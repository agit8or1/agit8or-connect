"""Shared rate limits (THREAT_MODEL.md §5, PROTOCOL.md §5.1).

Limits are counted in a store shared by every worker (storage.SqlRateLimitStore on SQLite/PostgreSQL;
MemoryRateLimitStore only for a single process or tests), so N workers do not multiply a limit by N.

    limiter = RateLimiter(SqlRateLimitStore(backend))
    limiter.check('pairing.address', source)        # counts and raises rate_limited (429) when over
    limiter.ensure_below('token.failure', conn, src) # refuses early if a failure counter is exhausted
    limiter.hit('token.failure', conn, src)         # ... and counts a failure after it happened

Failure policy — FAIL CLOSED: if the store cannot be read or written, `check`, `ensure_below` and `hit`
raise `rate_limit_unavailable` (503) and the caller refuses the request. Every rule below protects a
security decision, so there is no fail-open mode.

Keys and shared NAT: limits on unauthenticated endpoints are keyed by source address (and a global
ceiling); limits that could lock out a connection are keyed by (connection, source address) so an
attacker behind the same NAT as a legitimate peer — or anywhere else — exhausts only its own bucket.
Per-connection ceilings exist only for successful use (API abuse by a key holder), never for failures
an outsider can cause.

Windows are sliding (the previous fixed window is weighted by its remaining overlap), so a burst at a
window boundary cannot double the limit.
"""
from __future__ import annotations

import hashlib
import math
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional, Protocol, Tuple

from .errors import ConnectError, RATE_LIMITED

RATE_LIMIT_UNAVAILABLE = 'rate_limit_unavailable'


@dataclass(frozen=True)
class Rule:
    limit: int
    window: int          # seconds
    description: str = ''


# Defaults: what each counts, keyed by what. Hosts may pass their own table (same names).
DEFAULT_RULES: Dict[str, Rule] = {
    'pairing.address': Rule(10, 600, 'pairing submissions per source address'),
    'pairing.global': Rule(100, 600, 'pairing submissions, all sources'),
    'pairing.failed_code.address': Rule(10, 3600, 'wrong pairing codes per source address'),
    'qc.review.admin': Rule(20, 3600, 'Quick Connect invitations reviewed per administrator'),
    'qc.exchange.address': Rule(20, 600, 'Quick Connect exchanges per source address'),
    'token.connection': Rule(120, 60, 'tokens issued per connection (successful requests)'),
    'token.failure': Rule(20, 300, 'failed token requests per (connection, source)'),
    'auth.failure': Rule(30, 300, 'failed resource authentications per (connection, source)'),
    'auth.failure.address': Rule(200, 300, 'failed authentications per source address, all connections'),
    'signature.invalid': Rule(20, 300, 'invalid event / message signatures per (connection, source)'),
    'api.connection': Rule(600, 60, 'authenticated API calls per connection'),
    'admin.approval': Rule(30, 3600, 'approvals and destination changes per administrator'),
}


class RateLimitStore(Protocol):
    def hit(self, bucket: str, window_start: int, window: int, amount: int = 1) -> int: ...

    def get(self, bucket: str, window_start: int) -> int: ...


class MemoryRateLimitStore:
    """Single-process store (tests, development). Bounded: expired windows are dropped as time moves."""

    def __init__(self):
        self._c: Dict[Tuple[str, int], int] = {}
        self._lock = threading.Lock()
        self._last_sweep = 0

    def hit(self, bucket, window_start, window, amount=1):
        with self._lock:
            if window_start - self._last_sweep > 60:
                self._c = {k: v for k, v in self._c.items() if k[1] >= window_start - 2 * 86400}
                self._last_sweep = window_start
            k = (bucket, window_start)
            self._c[k] = self._c.get(k, 0) + amount
            return self._c[k]

    def get(self, bucket, window_start):
        with self._lock:
            return self._c.get((bucket, window_start), 0)


def bucket_key(rule: str, *parts: str) -> str:
    """Bucket name; parts are hashed so addresses and ids are not stored in clear and keys stay short."""
    digest = hashlib.sha256('\x1f'.join(str(p) for p in parts).encode('utf-8')).hexdigest()[:32]
    return f'{rule}:{digest}'


@dataclass(frozen=True)
class Decision:
    allowed: bool
    count: float
    limit: int
    retry_after: int


class RateLimiter:
    def __init__(self, store: RateLimitStore, rules: Optional[Dict[str, Rule]] = None,
                 clock: Callable[[], float] = time.time):
        self.store = store
        self.rules = dict(DEFAULT_RULES if rules is None else rules)
        self.clock = clock

    def _rule(self, name: str) -> Rule:
        try:
            return self.rules[name]
        except KeyError:
            raise ConnectError(RATE_LIMIT_UNAVAILABLE, f'no rate-limit rule {name}', 503) from None

    def _estimate(self, rule: Rule, bucket: str, now: float, add: int) -> Tuple[float, int]:
        w = rule.window
        start = int(now) - int(now) % w
        try:
            cur = self.store.hit(bucket, start, w, add) if add else self.store.get(bucket, start)
            prev = self.store.get(bucket, start - w)
        except ConnectError as e:
            if e.code == RATE_LIMIT_UNAVAILABLE:
                raise
            raise ConnectError(RATE_LIMIT_UNAVAILABLE, 'rate-limit store unavailable', 503) from e
        except Exception as e:  # noqa: BLE001 — fail closed on any store failure
            raise ConnectError(RATE_LIMIT_UNAVAILABLE, 'rate-limit store unavailable', 503) from e
        elapsed = now - start
        weight = max(0.0, (w - elapsed) / w)
        return cur + prev * weight, int(math.ceil(w - elapsed)) or 1

    def peek(self, name: str, *parts: str) -> Decision:
        rule = self._rule(name)
        est, retry = self._estimate(rule, bucket_key(name, *parts), self.clock(), 0)
        return Decision(est < rule.limit, est, rule.limit, retry)

    def hit(self, name: str, *parts: str, amount: int = 1) -> Decision:
        rule = self._rule(name)
        est, retry = self._estimate(rule, bucket_key(name, *parts), self.clock(), amount)
        return Decision(est <= rule.limit, est, rule.limit, retry)

    def check(self, name: str, *parts: str) -> Decision:
        """Count one use and refuse when the rule is exceeded."""
        d = self.hit(name, *parts)
        if not d.allowed:
            raise limited(d, self._rule(name))
        return d

    def ensure_below(self, name: str, *parts: str) -> Decision:
        """Refuse when a failure counter is already exhausted (does not count)."""
        d = self.peek(name, *parts)
        if not d.allowed:
            raise limited(d, self._rule(name))
        return d


def limited(d: Decision, rule: Rule) -> ConnectError:
    e = ConnectError(RATE_LIMITED, 'too many requests; try again later', 429)
    e.retry_after = d.retry_after
    return e
