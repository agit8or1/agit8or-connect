"""Elevated-grant approval (PROTOCOL.md §7.3) and per-action approval (`action-approval/1`).

Elevated grants
---------------
`high_risk` and `admin` scopes are never activated by an ordinary approval. The host:

  1. computes the immutable request fingerprint (`grant_fingerprint`) over everything the approval covers:
     connection, peer installation and key, inbound scopes, tenant grants;
  2. `propose(...)` by administrator P, who has re-authenticated within `reauth_max_age`;
  3. `approve(...)` by a DIFFERENT administrator Q, also freshly re-authenticated, against the CURRENT
     fingerprint — any change to scopes, tenants, peer or key changes the fingerprint and the proposal no
     longer matches (it is invalidated, never carried over);
  4. activates only when `is_authorized(connection, fingerprint, scopes)` is true, and checks it again
     at every token issue and every use, so revocation (`revoke`) takes effect immediately.

A host that does not implement this (`ElevatedGrantPolicy(enabled=False)`, the default for
`ElevatedGrantPolicy.disabled()`) refuses every elevated scope: they stay unavailable. There is no
single-administrator override. (A break-glass design is described, not implemented, in
docs/SECURITY_ARCHITECTURE.md §6 and needs its own review.)

Per-action approval (`action-approval/1`)
-----------------------------------------
Holding a `high_risk` scope is not enough to act: each operation needs its own approval at the
receiving installation (the one whose customer is affected).

  * The caller sends the operation. Without an approval the receiver creates a pending `ActionRequest`
    — exact target, action type, SHA-256 of the canonical parameters, the operator (delegated actor when
    present), tenant, required scope, expiry — and answers `403 action_approval_required` with its id.
  * An administrator of the receiver (never the operator) approves or denies it.
  * The caller repeats the SAME operation with `Agit8or-Action-Approval: <id>`. The receiver consumes the
    approval in one conditional write that also compares connection, tenant, target, action type and
    parameter digest: single use, and any change to the parameters after approval is refused.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

from .canonical import canonical_json, sha256_hex
from .errors import ACTION_APPROVAL_REQUIRED, ConnectError, INVALID_SCOPE, KILL_SWITCH
from .scopes import Catalog, ELEVATED_RISKS

SECOND_ADMIN_REQUIRED = 'second_admin_required'
REAUTHENTICATION_REQUIRED = 'reauthentication_required'
APPROVAL_MISMATCH = 'approval_mismatch'
ACTION_APPROVAL_HEADER = 'Agit8or-Action-Approval'
ACTION_APPROVAL_EXTENSION = 'action-approval'

REAUTH_MAX_AGE = 300
PROPOSAL_TTL = 86400
ACTION_TTL = 900


@dataclass(frozen=True)
class AdminAuth:
    """Who acts and when they last re-authenticated (host-verified; the SDK only checks freshness)."""
    admin_id: str
    reauthenticated_at: int


def classify_scopes(catalog: Catalog, scopes: Iterable[str]) -> Tuple[List[str], List[str]]:
    """(ordinary, elevated). Unknown or unavailable scopes are refused (never granted)."""
    ordinary, elevated = [], []
    for name in sorted(set(scopes)):
        s = catalog.get(name)
        if s is None:
            raise ConnectError(INVALID_SCOPE, f'unknown scope {name}', 400)
        if not s.available:
            raise ConnectError(INVALID_SCOPE, f'scope {name} is not available on this installation', 400)
        (elevated if s.risk in ELEVATED_RISKS else ordinary).append(name)
    return ordinary, elevated


def grant_fingerprint(*, connection_id: str, remote_installation: str, remote_key_thumbprints: Sequence[str],
                      inbound_scopes: Iterable[str], tenant_grants: Iterable[dict]) -> str:
    """SHA-256 over the canonical form of everything an elevated approval covers."""
    grants = sorted(({'remote_tenant': str(g['remote_tenant']), 'local_tenant': str(g['local_tenant']),
                      'scopes': sorted(set(g.get('scopes') or ()))} for g in tenant_grants),
                    key=lambda g: (g['remote_tenant'], g['local_tenant']))
    return sha256_hex(canonical_json({'v': 'agit8or-connect elevated-grant v1', 'connection_id': connection_id,
                                      'remote_installation': remote_installation,
                                      'remote_keys': sorted(set(remote_key_thumbprints)),
                                      'scopes': sorted(set(inbound_scopes)), 'tenant_grants': grants}))


class GrantApprovalStore(Protocol):
    def create(self, proposal: dict) -> None: ...

    def get(self, proposal_id: str) -> Optional[dict]: ...

    def approve(self, proposal_id: str, *, approver: str, approver_auth_at: int, fingerprint: str,
                now: int) -> bool: ...

    def set_status(self, proposal_id: str, status: str, *, only_from: str = 'pending') -> bool: ...

    def find_approved(self, connection_id: str, fingerprint: str) -> Optional[dict]: ...

    def invalidate(self, connection_id: str, *, keep_fingerprint: Optional[str] = None,
                   status: str = 'invalidated') -> int: ...


class MemoryGrantApprovalStore:
    def __init__(self):
        self.rows: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, p):
        with self._lock:
            self.rows[p['id']] = dict(p, status='pending', approver=None, approved_at=None, approver_auth_at=None)

    def get(self, pid):
        with self._lock:
            r = self.rows.get(pid)
            return dict(r) if r else None

    def approve(self, pid, *, approver, approver_auth_at, fingerprint, now):
        with self._lock:
            r = self.rows.get(pid)
            if not r or r['status'] != 'pending' or r['proposer'] == approver or r['fingerprint'] != fingerprint \
                    or r['expires_at'] <= now:
                return False
            r.update(status='approved', approver=approver, approved_at=now, approver_auth_at=approver_auth_at)
            return True

    def set_status(self, pid, status, *, only_from='pending'):
        with self._lock:
            r = self.rows.get(pid)
            if not r or r['status'] != only_from:
                return False
            r['status'] = status
            return True

    def find_approved(self, connection_id, fingerprint):
        with self._lock:
            hits = [r for r in self.rows.values() if r['connection_id'] == connection_id
                    and r['fingerprint'] == fingerprint and r['status'] == 'approved']
            return dict(max(hits, key=lambda r: r['approved_at'])) if hits else None

    def invalidate(self, connection_id, *, keep_fingerprint=None, status='invalidated'):
        n = 0
        with self._lock:
            for r in self.rows.values():
                if r['connection_id'] == connection_id and r['status'] in ('pending', 'approved') and \
                        r['fingerprint'] != (keep_fingerprint or ''):
                    r['status'] = status
                    n += 1
        return n


class ElevatedGrantPolicy:
    def __init__(self, store: GrantApprovalStore, catalog: Catalog, *, enabled: bool = True,
                 reauth_max_age: int = REAUTH_MAX_AGE, proposal_ttl: int = PROPOSAL_TTL,
                 clock: Callable[[], float] = time.time, kill_switch: Callable[[], bool] = lambda: False):
        self.store = store
        self.catalog = catalog
        self.enabled = enabled
        self.reauth_max_age = reauth_max_age
        self.proposal_ttl = proposal_ttl
        self.clock = clock
        self.kill_switch = kill_switch

    @classmethod
    def disabled(cls, catalog: Catalog) -> 'ElevatedGrantPolicy':
        return cls(MemoryGrantApprovalStore(), catalog, enabled=False)

    def _now(self) -> int:
        return int(self.clock())

    def _fresh(self, auth: AdminAuth) -> None:
        if not isinstance(auth, AdminAuth) or not auth.admin_id:
            raise ConnectError(REAUTHENTICATION_REQUIRED, 'an authenticated administrator is required', 403)
        age = self._now() - int(auth.reauthenticated_at)
        if age < -60 or age > self.reauth_max_age:
            raise ConnectError(REAUTHENTICATION_REQUIRED, 'sign in again to approve elevated permissions', 403)

    def classify(self, scopes: Iterable[str]) -> Tuple[List[str], List[str]]:
        ordinary, elevated = classify_scopes(self.catalog, scopes)
        if elevated and not self.enabled:
            raise ConnectError(INVALID_SCOPE, f'scope {elevated[0]} needs elevated approval, which this '
                                              'installation does not offer', 400)
        return ordinary, elevated

    def propose(self, *, connection_id: str, fingerprint: str, scopes: Iterable[str], proposer: AdminAuth) -> str:
        if self.kill_switch():
            raise ConnectError(KILL_SWITCH, 'approvals are blocked while the kill switch is engaged', 503)
        _, elevated = self.classify(scopes)
        if not elevated:
            raise ConnectError('invalid_request', 'nothing elevated to approve', 400)
        self._fresh(proposer)
        # Any earlier proposal for another version of this connection's request is void.
        self.store.invalidate(connection_id, keep_fingerprint=fingerprint)
        pid = str(uuid.uuid4())
        now = self._now()
        self.store.create({'id': pid, 'connection_id': connection_id, 'fingerprint': fingerprint,
                           'scopes': sorted(set(scopes)), 'proposer': proposer.admin_id, 'proposed_at': now,
                           'proposer_auth_at': int(proposer.reauthenticated_at), 'expires_at': now + self.proposal_ttl})
        return pid

    def approve(self, proposal_id: str, *, approver: AdminAuth, current_fingerprint: str) -> dict:
        if self.kill_switch():
            raise ConnectError(KILL_SWITCH, 'approvals are blocked while the kill switch is engaged', 503)
        self._fresh(approver)
        p = self.store.get(proposal_id)
        if p is None or p['status'] != 'pending':
            raise ConnectError('not_found', 'no pending elevated approval', 404)
        if p['proposer'] == approver.admin_id:
            raise ConnectError(SECOND_ADMIN_REQUIRED, 'a different administrator must approve elevated '
                                                      'permissions', 403)
        if p['fingerprint'] != current_fingerprint:
            self.store.set_status(proposal_id, 'invalidated')
            raise ConnectError(APPROVAL_MISMATCH, 'the request changed since it was proposed; propose it again', 409)
        if not self.store.approve(proposal_id, approver=approver.admin_id,
                                  approver_auth_at=int(approver.reauthenticated_at),
                                  fingerprint=current_fingerprint, now=self._now()):
            raise ConnectError(APPROVAL_MISMATCH, 'the approval could not be recorded (expired, changed or decided '
                                                  'concurrently)', 409)
        return self.store.get(proposal_id)

    def is_authorized(self, connection_id: str, fingerprint: str, scopes: Iterable[str]) -> bool:
        """True when every elevated scope in `scopes` is covered by a two-administrator approval of exactly
        this fingerprint. Ordinary scopes need nothing here. Unknown scopes: False."""
        try:
            _, elevated = classify_scopes(self.catalog, scopes)
        except ConnectError:
            return False
        if not elevated:
            return True
        if not self.enabled:
            return False
        p = self.store.find_approved(connection_id, fingerprint)
        return bool(p) and p['proposer'] != p['approver'] and set(elevated) <= set(p['scopes'])

    def authorized_scopes(self, connection_id: str, fingerprint: str, scopes: Iterable[str]) -> List[str]:
        """`scopes` minus any elevated scope not currently covered (for token issue and every use)."""
        scopes = sorted(set(scopes))
        if self.is_authorized(connection_id, fingerprint, scopes):
            return scopes
        return [s for s in scopes if (self.catalog.get(s) and self.catalog.get(s).risk not in ELEVATED_RISKS)]

    def revoke(self, connection_id: str) -> int:
        return self.store.invalidate(connection_id, status='revoked')


# --- per-action approval -----------------------------------------------------------------------------

def action_params_digest(params) -> str:
    return sha256_hex(canonical_json(params if params is not None else {}))


@dataclass(frozen=True)
class ActionRequest:
    id: str
    connection_id: str
    tenant: str
    target: str
    action_type: str
    params_sha256: str
    operator: str
    required_scope: str
    requested_at: int
    expires_at: int


class ActionApprovalStore(Protocol):
    def create(self, request: dict) -> None: ...

    def get(self, request_id: str) -> Optional[dict]: ...

    def decide(self, request_id: str, *, approve: bool, admin: str, now: int) -> bool: ...

    def consume(self, request_id: str, *, connection_id: str, tenant: str, target: str, action_type: str,
                params_sha256: str, now: int) -> bool: ...


class MemoryActionApprovalStore:
    def __init__(self):
        self.rows: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def create(self, r):
        with self._lock:
            self.rows[r['id']] = dict(r, status='pending', decided_by=None, decided_at=None, consumed_at=None)

    def get(self, rid):
        with self._lock:
            r = self.rows.get(rid)
            return dict(r) if r else None

    def decide(self, rid, *, approve, admin, now):
        with self._lock:
            r = self.rows.get(rid)
            if not r or r['status'] != 'pending' or r['operator'] == admin or r['expires_at'] <= now:
                return False
            r.update(status='approved' if approve else 'denied', decided_by=admin, decided_at=now)
            return True

    def consume(self, rid, *, connection_id, tenant, target, action_type, params_sha256, now):
        with self._lock:
            r = self.rows.get(rid)
            if not r or r['status'] != 'approved' or r['expires_at'] <= now or \
                    (r['connection_id'], r['tenant'], r['target'], r['action_type'], r['params_sha256']) != \
                    (connection_id, tenant, target, action_type, params_sha256):
                return False
            r.update(status='consumed', consumed_at=now)
            return True


class ActionApprovals:
    def __init__(self, store: ActionApprovalStore, *, ttl: int = ACTION_TTL, reauth_max_age: int = REAUTH_MAX_AGE,
                 clock: Callable[[], float] = time.time, kill_switch: Callable[[], bool] = lambda: False):
        self.store = store
        self.ttl = ttl
        self.reauth_max_age = reauth_max_age
        self.clock = clock
        self.kill_switch = kill_switch

    def request(self, *, connection_id: str, tenant: str, target: str, action_type: str, params,
                operator: str, required_scope: str) -> ActionRequest:
        for name, v in (('tenant', tenant), ('target', target), ('action_type', action_type), ('operator', operator)):
            if not isinstance(v, str) or not v or len(v) > 256:
                raise ConnectError('invalid_request', f'{name} missing or malformed', 400)
        now = int(self.clock())
        r = ActionRequest(str(uuid.uuid4()), connection_id, tenant, target, action_type,
                          action_params_digest(params), operator, required_scope, now, now + self.ttl)
        self.store.create(dict(r.__dict__, record={'target': target, 'action_type': action_type}))
        return r

    def decide(self, request_id: str, *, approve: bool, admin: AdminAuth) -> None:
        if approve and self.kill_switch():
            raise ConnectError(KILL_SWITCH, 'approvals are blocked while the kill switch is engaged', 503)
        age = int(self.clock()) - int(admin.reauthenticated_at)
        if not admin.admin_id or age < -60 or age > self.reauth_max_age:
            raise ConnectError(REAUTHENTICATION_REQUIRED, 'sign in again to decide on this action', 403)
        r = self.store.get(request_id)
        if r is None:
            raise ConnectError('not_found', 'no such action request', 404)
        if r['operator'] == admin.admin_id:
            raise ConnectError(SECOND_ADMIN_REQUIRED, 'the operator cannot approve their own action', 403)
        if not self.store.decide(request_id, approve=approve, admin=admin.admin_id, now=int(self.clock())):
            raise ConnectError(APPROVAL_MISMATCH, 'the action request is no longer pending', 409)

    def consume(self, request_id: str, *, connection_id: str, tenant: str, target: str, action_type: str,
                params) -> None:
        """Single use. Raises action_approval_required (403) unless an approved, unexpired request with exactly
        these values exists."""
        if self.kill_switch():
            raise ConnectError(KILL_SWITCH, 'actions are blocked while the kill switch is engaged', 503)
        if not request_id or not self.store.consume(request_id, connection_id=connection_id, tenant=tenant,
                                                    target=target, action_type=action_type,
                                                    params_sha256=action_params_digest(params),
                                                    now=int(self.clock())):
            raise ConnectError(ACTION_APPROVAL_REQUIRED, 'this action needs an approval for exactly these '
                                                         'parameters', 403)
