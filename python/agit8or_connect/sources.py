"""Inbound source policy for Connect endpoints (IP_ALLOWLIST_AND_BOOTSTRAP.md §1).

Two layers, both must allow: the installation layer (who may reach Connect at all) and the connection layer
(who may act for the connection a request names). Each is an allowlist plus explicit denies; deny wins; an
empty list denies everything; there is no open mode. Every refusal is the same `403 source_not_authorised`,
so the policy reveals nothing about connection ids.

    policy = SourcePolicy(version=7, rules=[...])
    d = policy.evaluate('203.0.113.10', route='token', connection_id='c1', now=now)
    if not d.allowed: refuse 403 (log d.reason to the folded refusal log, not the audit chain)
    ... authenticate ...
    check_binding(d, authenticated_connection_id)   # step 11

Changes go through `preview_change(old, new, observed)`: it lists the connections a new policy would lock out
(by their recently observed sources), the networks it newly admits, whether it widens anything, and whether a
second administrator is required (private networks or widening). Rollback must only narrow.
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from . import addresses
from .canonical import canonical_json, sha256_hex
from .errors import ConnectError

SOURCE_NOT_AUTHORISED = 'source_not_authorised'
SOURCE_POLICY_UNAVAILABLE = 'source_policy_unavailable'
INSTALLATION, CONNECTION = 'installation', 'connection'
ALLOW, DENY = 'allow', 'deny'
PAIRING_PURPOSE = 'pairing'
MIN_PREFIX = {4: 16, 6: 32}
MAX_RULES = 2000

# Route -> how the connection layer is chosen (§1.4)
ROUTES_UNNAMED = {'discovery', 'health'}     # union of active connections' rules + temporary pairing rules
ROUTES_PAIRING = {'pairing'}                 # union of temporary pairing rules
ROUTES_NAMED = {'pairing_status', 'qc_exchange', 'token', 'jwks', 'events', 'capabilities', 'test', 'resource',
                'qc_probe', 'remote_actions'}


def _bad(msg: str) -> ConnectError:
    return ConnectError('invalid_source_rule', msg, 400)


@dataclass(frozen=True)
class SourceRule:
    net: str
    layer: str = CONNECTION
    action: str = ALLOW
    connection_id: Optional[str] = None      # connection layer: whose rule (None only for pairing rules)
    private: bool = False                    # an administrator marked this private network explicitly
    temporary: bool = False
    purpose: str = ''                        # 'pairing' or a Quick Connect attempt id for temporary rules
    expires_at: Optional[int] = None
    note: str = ''

    def network(self):
        return ipaddress.ip_network(self.net, strict=True)

    def live(self, now: int) -> bool:
        return self.expires_at is None or now < self.expires_at

    def as_dict(self) -> dict:
        d = {'net': self.net, 'layer': self.layer, 'action': self.action, 'private': self.private,
             'temporary': self.temporary}
        for k in ('connection_id', 'purpose', 'expires_at', 'note'):
            v = getattr(self, k)
            if v not in (None, ''):
                d[k] = v
        return d

    @classmethod
    def from_dict(cls, d: Mapping) -> 'SourceRule':
        return cls(net=d['net'], layer=d.get('layer', CONNECTION), action=d.get('action', ALLOW),
                   connection_id=d.get('connection_id'), private=bool(d.get('private', False)),
                   temporary=bool(d.get('temporary', False)), purpose=d.get('purpose', ''),
                   expires_at=d.get('expires_at'), note=d.get('note', ''))


def validate_rule(r: SourceRule) -> SourceRule:
    try:
        n = r.network()
    except (ValueError, TypeError):
        raise _bad('rule network malformed or not canonical')
    if str(n) != r.net:
        raise _bad('rule network is not canonical')
    if r.layer not in (INSTALLATION, CONNECTION) or r.action not in (ALLOW, DENY):
        raise _bad('rule layer or action unknown')
    if r.action == ALLOW:
        if n.prefixlen < MIN_PREFIX[n.version]:
            raise _bad('allow rule too broad (IPv4 at least /16, IPv6 at least /32)')
        cat = addresses.network_category(str(n))
        if cat in ('metadata', 'multicast', 'unspecified', 'broadcast', 'reserved'):
            raise _bad(f'{r.net} is a {cat} network and cannot be allowed')
        if cat in ('private', 'loopback', 'link_local') and not r.private:
            raise _bad(f'{r.net} is {cat}: it must be marked private explicitly')
    if r.layer == CONNECTION and not r.connection_id and r.purpose != PAIRING_PURPOSE:
        raise _bad('a connection-layer rule names its connection (or is a temporary pairing rule)')
    if r.layer == INSTALLATION and r.connection_id:
        raise _bad('an installation-layer rule names no connection')
    if r.temporary and r.expires_at is None:
        raise _bad('temporary rules expire')
    if len(r.note) > 100:
        raise _bad('rule note too long')
    return r


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    step: int
    connection_id: Optional[str] = None
    source: str = ''

    def raise_if_refused(self):
        if not self.allowed:
            raise ConnectError(SOURCE_NOT_AUTHORISED, 'source not authorised', 403)


def _match(rules: Iterable[SourceRule], a) -> Tuple[bool, bool]:
    allow = deny = False
    for r in rules:
        n = r.network()
        if n.version == a.version and a in n:
            if r.action == DENY:
                deny = True
            else:
                allow = True
    return allow, deny


@dataclass
class SourcePolicy:
    version: int
    rules: Sequence[SourceRule] = ()

    def __post_init__(self):
        if len(self.rules) > MAX_RULES:
            raise _bad('too many source rules')
        for r in self.rules:
            validate_rule(r)

    def digest(self) -> str:
        return sha256_hex(canonical_json({'version': self.version,
                                          'rules': sorted((r.as_dict() for r in self.rules), key=canonical_json)}))

    def _live(self, now):
        return [r for r in self.rules if r.live(now)]

    def evaluate(self, source: str, *, route: str, connection_id: Optional[str] = None,
                 active_connections: Iterable[str] = (), now: Optional[int] = None) -> Decision:
        now = int(time.time() if now is None else now)
        a = addresses.parse(source)
        if a is None:
            return Decision(False, 'source unreadable', 1)
        if a.version == 6 and a.ipv4_mapped is not None:
            a = a.ipv4_mapped
        src = str(a)
        rules = self._live(now)
        inst = [r for r in rules if r.layer == INSTALLATION]
        allow, deny = _match(inst, a)
        if deny:
            return Decision(False, 'installation deny', 3, source=src)
        if not allow:
            return Decision(False, 'installation allowlist', 4, source=src)
        conn_rules = [r for r in rules if r.layer == CONNECTION]
        pairing_rules = [r for r in conn_rules if r.temporary and r.purpose == PAIRING_PURPOSE]
        if route in ROUTES_UNNAMED:
            active = set(active_connections)
            layer = [r for r in conn_rules if r.connection_id in active] + pairing_rules
            named = None
        elif route in ROUTES_PAIRING:
            layer, named = pairing_rules, None
        elif route in ROUTES_NAMED:
            if not connection_id:
                return Decision(False, 'no connection named', 5, source=src)
            layer, named = [r for r in conn_rules if r.connection_id == connection_id], connection_id
        else:
            return Decision(False, 'unknown route', 5, source=src)
        if not layer:
            return Decision(False, 'no connection rules', 5, named, src)
        allow, deny = _match(layer, a)
        if deny:
            return Decision(False, 'connection deny', 6, named, src)
        if not allow:
            return Decision(False, 'connection allowlist', 7, named, src)
        return Decision(True, 'allowed', 7, named, src)


def check_binding(decision: Decision, authenticated_connection_id: str):
    """Step 11: the connection proven by authentication MUST be the one whose rules admitted the source."""
    if decision.connection_id is not None and decision.connection_id != authenticated_connection_id:
        raise ConnectError(SOURCE_NOT_AUTHORISED, 'source not authorised', 403)


# --- change preview --------------------------------------------------------------------------------

@dataclass
class ChangePreview:
    locked_out: List[Tuple[str, str]] = field(default_factory=list)   # (connection id, observed source)
    newly_allowed: List[str] = field(default_factory=list)            # networks allowed now that were not
    removed: List[str] = field(default_factory=list)
    widens: bool = False
    adds_private: bool = False
    needs_second_admin: bool = False

    def as_dict(self) -> dict:
        return {'locked_out': [list(x) for x in self.locked_out], 'newly_allowed': self.newly_allowed,
                'removed': self.removed, 'widens': self.widens, 'adds_private': self.adds_private,
                'needs_second_admin': self.needs_second_admin}


def _allow_set(p: SourcePolicy):
    return {(r.layer, r.connection_id, r.net) for r in p.rules if r.action == ALLOW}


def _covered(net, others) -> bool:
    return any(o.version == net.version and net.subnet_of(o) for o in others)


def preview_change(old: SourcePolicy, new: SourcePolicy, observed: Mapping[str, Iterable[str]], *,
                   now: Optional[int] = None) -> ChangePreview:
    """`observed`: connection id -> sources seen for it recently (for example the last 30 days)."""
    now = int(time.time() if now is None else now)
    p = ChangePreview()
    for cid, sources in observed.items():
        for s in sources:
            route = 'token'
            before = old.evaluate(s, route=route, connection_id=cid, now=now).allowed
            after = new.evaluate(s, route=route, connection_id=cid, now=now).allowed
            if before and not after:
                p.locked_out.append((cid, addresses.normalize(s) or s))
    old_allow, new_allow = _allow_set(old), _allow_set(new)
    for layer, cid, net in sorted(new_allow - old_allow, key=str):
        n = ipaddress.ip_network(net)
        same_scope = [ipaddress.ip_network(x[2]) for x in old_allow if x[0] == layer and x[1] == cid]
        if not _covered(n, same_scope):
            p.newly_allowed.append(net)
            p.widens = True
        if addresses.network_category(str(n)) in ('private', 'loopback', 'link_local'):
            p.adds_private = True
    p.removed = sorted({x[2] for x in old_allow - new_allow})
    p.needs_second_admin = p.widens or p.adds_private
    return p


def check_rollback(current: SourcePolicy, target: SourcePolicy) -> None:
    """A rollback may only narrow: every allow rule of the target must already be covered now."""
    cur = {}
    for layer, cid, net in _allow_set(current):
        cur.setdefault((layer, cid), []).append(ipaddress.ip_network(net))
    for layer, cid, net in _allow_set(target):
        if not _covered(ipaddress.ip_network(net), cur.get((layer, cid), [])):
            raise ConnectError('invalid_request', 'a rollback may only narrow the source policy', 400)


# --- fail-closed cache -----------------------------------------------------------------------------

class PolicyCache:
    """Per-process cache keyed by policy version. The loader is the source of truth: if it fails and the last
    good copy is older than `max_stale` seconds, evaluate() refuses (source_policy_unavailable -> 403)."""

    def __init__(self, loader: Callable[[], SourcePolicy], *, max_stale: int = 60, refresh: int = 5,
                 clock: Callable[[], float] = time.time):
        self.loader, self.max_stale, self.refresh, self.clock = loader, max_stale, refresh, clock
        self._policy: Optional[SourcePolicy] = None
        self._loaded_at = 0.0
        self._checked_at = -1e18

    def get(self) -> SourcePolicy:
        now = self.clock()
        if self._policy is not None and now - self._checked_at < self.refresh:
            return self._policy
        self._checked_at = now
        try:
            p = self.loader()
            if not isinstance(p, SourcePolicy):
                raise TypeError('loader returned no policy')
            if self._policy is None or p.version >= self._policy.version:
                self._policy = p
            self._loaded_at = now
        except Exception:
            if self._policy is None or now - self._loaded_at > self.max_stale:
                raise ConnectError(SOURCE_POLICY_UNAVAILABLE, 'source policy unavailable', 403)
        return self._policy
