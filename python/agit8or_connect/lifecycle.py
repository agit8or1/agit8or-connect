"""Connection lifecycle, failure classes, reconnect ladder / circuit breaker and health hysteresis
(CONNECTION_HEALTH.md §1–2, AUTO_RECONNECT.md §1–3). Local host behaviour; nothing here is on the wire.

The rules this module enforces:

- `active` is entered only from `testing`, and never while the kill switch is engaged.
- Security failures move an active connection to `security_blocked` at once and never retry by themselves.
- Availability failures follow the backoff ladder with CSPRNG jitter; at offline the circuit opens and only the
  scheduled probe runs (event deliveries short-circuit without spending attempts).
- No reconnect from `suspended`, `revoked`, `security_blocked`, `failed`, or while the kill switch is engaged.
- Releasing the kill switch resumes nothing; `resume` goes through `testing`.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Optional

from .errors import ConnectError

PENDING_PAIRING = 'pending_pairing'
AWAITING_REMOTE = 'awaiting_remote_approval'
AWAITING_LOCAL = 'awaiting_local_approval'
AWAITING_SECOND = 'awaiting_second_approval'
AWAITING_NETWORK = 'awaiting_network'
TESTING = 'testing'
ACTIVE = 'active'
SECURITY_BLOCKED = 'security_blocked'
SUSPENDED = 'suspended'
REVOKED = 'revoked'
FAILED = 'failed'
STATES = (PENDING_PAIRING, AWAITING_REMOTE, AWAITING_LOCAL, AWAITING_SECOND, AWAITING_NETWORK, TESTING, ACTIVE,
          SECURITY_BLOCKED, SUSPENDED, REVOKED, FAILED)
TERMINAL = {REVOKED, FAILED}

TRANSITIONS = {
    PENDING_PAIRING: {AWAITING_REMOTE, AWAITING_LOCAL, FAILED},
    AWAITING_REMOTE: {AWAITING_LOCAL, AWAITING_NETWORK, FAILED},
    AWAITING_LOCAL: {AWAITING_SECOND, AWAITING_NETWORK, FAILED},
    AWAITING_SECOND: {AWAITING_NETWORK, FAILED},
    AWAITING_NETWORK: {TESTING, FAILED},
    TESTING: {ACTIVE, AWAITING_NETWORK, FAILED, SECURITY_BLOCKED},
    ACTIVE: {SECURITY_BLOCKED, SUSPENDED, REVOKED},
    SUSPENDED: {TESTING, REVOKED},
    SECURITY_BLOCKED: {TESTING, REVOKED},
    REVOKED: set(),
    FAILED: set(),
}

INVALID_TRANSITION = 'invalid_transition'


def transition(current: str, new: str, *, kill_switch: bool = False, test_passed: bool = False) -> str:
    """Validate one state change; returns `new` or raises. `active` needs a passing connection test in the same
    commit (`test_passed=True`) and a released kill switch."""
    if current not in TRANSITIONS or new not in TRANSITIONS:
        raise ConnectError(INVALID_TRANSITION, f'unknown state {current!r} -> {new!r}', 409)
    if new not in TRANSITIONS[current]:
        raise ConnectError(INVALID_TRANSITION, f'{current} cannot become {new}', 409)
    if new == ACTIVE:
        if kill_switch:
            raise ConnectError('kill_switch', 'activation is blocked while the kill switch is engaged', 503)
        if not test_passed:
            raise ConnectError(INVALID_TRANSITION, 'active only after a passing connection test', 409)
    if new == TESTING and kill_switch:
        raise ConnectError('kill_switch', 'resume is blocked while the kill switch is engaged', 503)
    return new


# --- failure classes ---------------------------------------------------------------------------------

SECURITY_CODES = frozenset({
    'destination_changed', 'security_blocked', 'certificate_invalid', 'certificate_name_mismatch', 'spki_mismatch',
    'identity_changed', 'invalid_signature', 'peer_revoked', 'key_revoked', 'source_not_authorised',
    'scope_withdrawn', 'binding_mismatch', 'blocked_destination',
})
AVAILABILITY_CODES = frozenset({
    'transport_error', 'deadline_exceeded', 'rate_limited', 'server_error', 'unavailable', 'kill_switch_remote',
    'replay_store_unavailable', 'rate_limit_unavailable',
})
SECURITY, AVAILABILITY, PERMANENT, LOCAL = 'security', 'availability', 'permanent', 'local'


def classify_failure(code: str = '', http_status: Optional[int] = None) -> str:
    """security -> block, never retry; availability -> ladder; permanent -> do not retry this request;
    local -> our own configuration (destination policy, keys) is unavailable: alert, do not hammer the peer."""
    if code in SECURITY_CODES:
        return SECURITY
    if code in ('destination_policy_unavailable', 'key_unavailable', 'key_corrupt'):
        return LOCAL
    if code in AVAILABILITY_CODES:
        return AVAILABILITY
    if http_status is not None:
        if http_status >= 500 or http_status in (408, 429):
            return AVAILABILITY
        if 400 <= http_status < 500:
            return PERMANENT
    return AVAILABILITY if not code else PERMANENT


# --- reconnect ladder and circuit breaker ------------------------------------------------------------

LADDER = (10, 30, 60, 120, 300, 600, 900)
CLOSED, OPEN, HALF_OPEN = 'closed', 'open', 'half_open'


def jittered(seconds: float, spread: float = 0.2) -> float:
    """±spread jitter from the OS CSPRNG."""
    r = secrets.randbelow(2 ** 32) / 2 ** 32
    return seconds * (1 - spread + 2 * spread * r)


@dataclass
class Circuit:
    state: str = CLOSED
    step: int = -1
    consecutive_failures: int = 0
    next_attempt_at: float = 0.0
    blocked: bool = False             # set by a security failure; only an administrator clears it

    def as_dict(self) -> dict:
        return {'state': self.state, 'step': self.step, 'consecutive_failures': self.consecutive_failures,
                'next_attempt_at': self.next_attempt_at, 'blocked': self.blocked}


@dataclass
class ReconnectPolicy:
    ladder: tuple = LADDER
    open_after: int = 3               # consecutive availability failures before the circuit opens (offline)
    jitter: float = 0.2

    def may_call(self, c: Circuit, now: float, *, connection_state: str = ACTIVE, kill_switch: bool = False,
                 probe: bool = False) -> bool:
        """May we contact the peer now? Ordinary calls only with a closed circuit; probes when due."""
        if c.blocked or kill_switch or connection_state != ACTIVE:
            return False
        if c.state == CLOSED:
            return True
        if probe and now >= c.next_attempt_at:
            c.state = HALF_OPEN
            return True
        return False

    def on_success(self, c: Circuit) -> Circuit:
        if not c.blocked:
            c.state, c.step, c.consecutive_failures, c.next_attempt_at = CLOSED, -1, 0, 0.0
        return c

    def on_failure(self, c: Circuit, now: float, code: str = '', http_status: Optional[int] = None) -> str:
        """Record a failure; returns its class. A security failure blocks the circuit for good."""
        kind = classify_failure(code, http_status)
        if kind == SECURITY:
            c.blocked, c.state = True, OPEN
            c.next_attempt_at = float('inf')
            return kind
        if kind != AVAILABILITY:
            return kind
        c.consecutive_failures += 1
        c.step = min(c.step + 1, len(self.ladder) - 1)
        delay = jittered(self.ladder[c.step], self.jitter)
        c.next_attempt_at = now + delay
        if c.state == HALF_OPEN or c.consecutive_failures >= self.open_after:
            c.state = OPEN
        return kind


# --- health hysteresis -------------------------------------------------------------------------------

CONNECTED, DEGRADED, OFFLINE = 'connected', 'degraded', 'offline'


@dataclass
class Health:
    status: str = CONNECTED
    transport_failures: int = 0
    other_failures: int = 0
    passes: int = 0
    last_success_at: float = 0.0
    history: list = field(default_factory=list)

    def record(self, now: float, *, ok: bool, transport: bool = False, full_pass: bool = True,
               offline_after: float = 300) -> str:
        """One check result. transport=True for DNS/TCP/TLS/timeouts; full_pass when every check passed."""
        if ok:
            self.transport_failures = self.other_failures = 0
            self.last_success_at = now
            self.passes = self.passes + 1 if full_pass else 0
            if self.status != CONNECTED and self.passes >= 2:
                self._set(CONNECTED, now)
            elif self.status == OFFLINE and not full_pass:
                self._set(DEGRADED, now)
            return self.status
        self.passes = 0
        if transport:
            self.transport_failures += 1
            if self.transport_failures >= 3 or (self.last_success_at and now - self.last_success_at >= offline_after):
                self._set(OFFLINE, now)
        else:
            self.other_failures += 1
            if self.status == CONNECTED and self.other_failures >= 2:
                self._set(DEGRADED, now)
            elif self.status == OFFLINE:
                self._set(DEGRADED, now)
        return self.status

    def _set(self, s, now):
        if s != self.status:
            self.history = (self.history + [(int(now), self.status, s)])[-100:]
            self.status = s
