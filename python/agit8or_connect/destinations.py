"""Approved outbound destinations (IP_ALLOWLIST_AND_BOOTSTRAP.md §4).

Every outbound Connect request of a connection goes to ONE approved destination: a host name (or IP
literal) and port, the set of addresses an administrator approved for it, the trust anchor (system CAs,
or only a private CA) and optional SPKI pins. `transport.GuardedTransport` enforces it on every request.

    ApprovedDestination        the policy record (immutable; validated)
    DestinationPolicy          the interface the transport reads (`get(connection_id)`)
    MemoryDestinationStore     in-memory implementation (tests, single process)
    storage.SqlDestinationStore   persistent implementation (SQLite / PostgreSQL)

Fail closed: a missing, unreadable, corrupt (digest mismatch) or inconsistent record refuses the request
with `destination_policy_unavailable`; a destination in `security_blocked` refuses with
`security_blocked`. There is no default destination and no "allow anything public" fallback.

Address changes never approve themselves (§4.1): the transport raises `destination_changed` with
evidence; a host records it with `block()`, and an administrator approves a change as a new record
(`propose_change` / `approve_change` on the stores), optionally keeping the old addresses for a bounded
overlap during a planned migration.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, List, Optional, Protocol, Sequence, Tuple

from . import addresses
from .canonical import canonical_json, sha256_hex
from .errors import ConnectError

DESTINATION_POLICY_UNAVAILABLE = 'destination_policy_unavailable'
SECURITY_BLOCKED = 'security_blocked'
INVALID_DESTINATION = 'invalid_destination'

ACTIVE, BLOCKED = 'active', 'security_blocked'
MAX_ADDRESSES = 16
# Narrowest ranges an administrator may approve for a peer behind rotating addresses.
MIN_RANGE_PREFIX = {4: 24, 6: 48}
MAX_OVERLAP = 7 * 86400
_HOST_RE = re.compile(r'^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$')
_PIN_RE = re.compile(r'^[A-Za-z0-9_-]{43}$')


def _bad(msg: str) -> ConnectError:
    return ConnectError(INVALID_DESTINATION, msg, 400)


def normalize_host(host: str) -> str:
    """Lower-case DNS name, or canonical IP literal (IPv6 without brackets)."""
    if not isinstance(host, str) or not host:
        raise _bad('destination host missing')
    h = host.strip().lower()
    if h.startswith('[') and h.endswith(']'):
        h = h[1:-1]
    ip = addresses.parse(h)
    if ip is not None:
        if addresses.classify(ip).via == 'mapped':
            raise _bad('IPv4-mapped host literal not accepted (use the IPv4 address)')
        return str(ip)
    if not h.isascii() or not _HOST_RE.match(h) or h == 'localhost' or h.endswith('.localhost'):
        raise _bad('destination host malformed or not allowed')
    return h


@dataclass(frozen=True)
class ApprovedAddress:
    net: str                         # canonical network text, e.g. 203.0.113.10/32 or 2001:db8::/48
    private: bool = False            # an administrator explicitly approved a private address
    not_before: Optional[int] = None
    not_after: Optional[int] = None  # set on the OLD addresses during an approved migration overlap
    note: str = ''

    def network(self):
        return ipaddress.ip_network(self.net, strict=True)

    def valid_at(self, now: int) -> bool:
        return (self.not_before is None or now >= self.not_before) and (self.not_after is None or now < self.not_after)

    def as_dict(self) -> dict:
        d = {'net': self.net, 'private': self.private}
        if self.not_before is not None:
            d['not_before'] = self.not_before
        if self.not_after is not None:
            d['not_after'] = self.not_after
        if self.note:
            d['note'] = self.note
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'ApprovedAddress':
        if not isinstance(d, dict) or not isinstance(d.get('net'), str):
            raise _bad('approved address malformed')
        return cls(d['net'], bool(d.get('private', False)), d.get('not_before'), d.get('not_after'),
                   str(d.get('note') or '')[:100])


def check_address(a: ApprovedAddress) -> ApprovedAddress:
    try:
        net = ipaddress.ip_network(a.net, strict=True)
    except (ValueError, TypeError) as e:
        raise _bad('approved address malformed') from e
    if net.with_prefixlen != a.net:
        raise _bad('approved address is not canonical')
    if net.num_addresses > 1 and net.prefixlen < MIN_RANGE_PREFIX[net.version]:
        raise _bad(f'approved range too broad (at most /{MIN_RANGE_PREFIX[net.version]})')
    cat = addresses.network_category(net)
    if cat in addresses.ALWAYS_REFUSED:
        raise _bad(f'{a.net} is a {cat} address and can never be a destination')
    if cat == addresses.PRIVATE and not a.private:
        raise _bad(f'{a.net} is private: it must be approved explicitly as a private address')
    if cat != addresses.PRIVATE and a.private:
        raise _bad(f'{a.net} is not private but is marked private (inconsistent record)')
    for t in (a.not_before, a.not_after):
        if t is not None and (isinstance(t, bool) or not isinstance(t, int) or t < 0):
            raise _bad('address validity times must be integers')
    if a.not_before is not None and a.not_after is not None and a.not_after <= a.not_before:
        raise _bad('address validity window is empty')
    return a


@dataclass(frozen=True)
class ApprovedDestination:
    connection_id: str
    host: str
    port: int
    addresses: Tuple[ApprovedAddress, ...]
    ca_pem: Optional[str] = None             # when set, REPLACES the system CAs for this destination
    spki_pins: Tuple[str, ...] = ()          # base64url SHA-256 of SubjectPublicKeyInfo DER
    expected_installation_id: str = ''
    state: str = ACTIVE
    version: int = 1
    approved_by: Tuple[str, ...] = ()
    approved_at: int = 0
    evidence: Optional[dict] = None          # last security-block evidence (sanitised)

    def validate(self) -> 'ApprovedDestination':
        if not isinstance(self.connection_id, str) or not self.connection_id or len(self.connection_id) > 128:
            raise _bad('destination connection id malformed')
        if normalize_host(self.host) != self.host:
            raise _bad('destination host is not normalised')
        if isinstance(self.port, bool) or not isinstance(self.port, int) or not 1 <= self.port <= 65535:
            raise _bad('destination port malformed')
        if not 1 <= len(self.addresses) <= MAX_ADDRESSES:
            raise _bad(f'a destination needs 1 to {MAX_ADDRESSES} approved addresses')
        seen = set()
        for a in self.addresses:
            check_address(a)
            if (a.net, a.not_before, a.not_after) in seen:
                raise _bad('approved address listed twice')
            seen.add((a.net, a.not_before, a.not_after))
        ip_host = addresses.parse(self.host)
        if ip_host is not None and not any(ip_host in a.network() for a in self.addresses):
            raise _bad('an IP-literal destination must be one of its approved addresses')
        for p in self.spki_pins:
            if not isinstance(p, str) or not _PIN_RE.match(p):
                raise _bad('SPKI pin malformed (base64url SHA-256)')
        if self.ca_pem is not None and (not isinstance(self.ca_pem, str) or 'BEGIN CERTIFICATE' not in self.ca_pem):
            raise _bad('private CA must be PEM certificates')
        if self.state not in (ACTIVE, BLOCKED):
            raise _bad('destination state unknown')
        if isinstance(self.version, bool) or not isinstance(self.version, int) or self.version < 1:
            raise _bad('destination version malformed')
        return self

    # -- matching -------------------------------------------------------------------------------
    def match(self, address: str, now: int) -> Optional[ApprovedAddress]:
        """The approved entry covering `address` at `now`, or None."""
        ip = addresses.parse(addresses.normalize(address) or '')
        if ip is None:
            return None
        for a in self.addresses:
            if a.valid_at(now) and ip.version == a.network().version and ip in a.network():
                return a
        return None

    # -- serialisation and integrity ------------------------------------------------------------
    def as_dict(self) -> dict:
        d = {'connection_id': self.connection_id, 'host': self.host, 'port': self.port,
             'addresses': [a.as_dict() for a in self.addresses], 'spki_pins': list(self.spki_pins),
             'expected_installation_id': self.expected_installation_id, 'state': self.state,
             'version': self.version, 'approved_by': list(self.approved_by), 'approved_at': self.approved_at}
        if self.ca_pem is not None:
            d['ca_pem'] = self.ca_pem
        if self.evidence is not None:
            d['evidence'] = self.evidence
        return d

    @classmethod
    def from_dict(cls, d: dict) -> 'ApprovedDestination':
        if not isinstance(d, dict):
            raise _bad('destination record malformed')
        try:
            return cls(connection_id=d['connection_id'], host=d['host'], port=d['port'],
                       addresses=tuple(ApprovedAddress.from_dict(a) for a in d['addresses']),
                       ca_pem=d.get('ca_pem'), spki_pins=tuple(d.get('spki_pins') or ()),
                       expected_installation_id=str(d.get('expected_installation_id') or ''),
                       state=d.get('state', ACTIVE), version=d.get('version', 1),
                       approved_by=tuple(d.get('approved_by') or ()), approved_at=int(d.get('approved_at') or 0),
                       evidence=d.get('evidence'))
        except (KeyError, TypeError, ValueError) as e:
            raise _bad('destination record malformed') from e

    def digest(self) -> str:
        """Integrity digest stored next to the record; a mismatch on load means the record was altered
        outside this code (or is corrupt) and the destination is refused."""
        return sha256_hex(canonical_json(self.as_dict()))


def new_destination(connection_id: str, host: str, port: int, approved: Iterable, *, ca_pem: Optional[str] = None,
                    spki_pins: Sequence[str] = (), expected_installation_id: str = '',
                    approved_by: Sequence[str] = (), now: Optional[int] = None) -> ApprovedDestination:
    """Build and validate a destination. `approved` holds ApprovedAddress objects, dicts, or address
    strings (an exact address becomes /32 or /128; a private address must be passed as an
    ApprovedAddress or dict with private=True — never inferred)."""
    entries = []
    for a in approved:
        if isinstance(a, ApprovedAddress):
            entries.append(a)
        elif isinstance(a, dict):
            entries.append(ApprovedAddress.from_dict(a))
        else:
            try:
                net = ipaddress.ip_network(str(a), strict=True)
            except ValueError as e:
                raise _bad('approved address malformed') from e
            entries.append(ApprovedAddress(net.with_prefixlen))
    return ApprovedDestination(connection_id, normalize_host(host), int(port), tuple(entries), ca_pem,
                               tuple(spki_pins), expected_installation_id, ACTIVE, 1, tuple(approved_by),
                               int(time.time() if now is None else now)).validate()


def with_migration(dest: ApprovedDestination, new_addresses: Iterable[ApprovedAddress], *, now: int,
                   overlap: int = 0, approved_by: Sequence[str] = ()) -> ApprovedDestination:
    """A new version for an approved address change. With `overlap` > 0 the old addresses stay valid until
    now + overlap (a planned migration), otherwise they are removed. The state returns to ACTIVE; the
    host keeps the connection in `testing` until a connection test passes."""
    if isinstance(overlap, bool) or not isinstance(overlap, int) or not 0 <= overlap <= MAX_OVERLAP:
        raise _bad(f'overlap must be 0..{MAX_OVERLAP} seconds')
    new = [replace(a, not_before=None) for a in new_addresses]
    old = []
    if overlap:
        new_nets = {a.net for a in new}
        old = [replace(a, not_after=min(a.not_after or now + overlap, now + overlap))
               for a in dest.addresses if a.net not in new_nets and a.valid_at(now)]
    return replace(dest, addresses=tuple(new + old), state=ACTIVE, version=dest.version + 1,
                   approved_by=tuple(approved_by), approved_at=now, evidence=None).validate()


class DestinationPolicy(Protocol):
    def get(self, connection_id: str) -> ApprovedDestination: ...


def unavailable(msg: str = 'approved destination unavailable') -> ConnectError:
    return ConnectError(DESTINATION_POLICY_UNAVAILABLE, msg, 503)


@dataclass
class _Change:
    id: str
    connection_id: str
    base_version: int
    addresses: Tuple[ApprovedAddress, ...]
    overlap: int
    proposer: str
    proposed_at: int
    evidence: Optional[dict] = None
    status: str = 'pending'
    approvers: List[str] = field(default_factory=list)


class MemoryDestinationStore:
    """In-memory DestinationPolicy with the same semantics as the SQL store (versioned records, integrity
    digest, block, two-step reviewed change). Process-local: use storage.SqlDestinationStore when more
    than one process sends requests."""

    def __init__(self, clock=time.time):
        self._rows: Dict[str, Tuple[dict, str]] = {}
        self._changes: Dict[str, _Change] = {}
        self._lock = threading.Lock()
        self._clock = clock

    def put(self, dest: ApprovedDestination, *, expected_version: Optional[int] = None) -> ApprovedDestination:
        dest.validate()
        with self._lock:
            cur = self._rows.get(dest.connection_id)
            cur_version = cur[0]['version'] if cur else None
            if expected_version is not None and cur_version != expected_version:
                raise ConnectError('conflict', 'destination changed concurrently', 409)
            self._rows[dest.connection_id] = (dest.as_dict(), dest.digest())
        return dest

    def get(self, connection_id: str) -> ApprovedDestination:
        with self._lock:
            row = self._rows.get(connection_id)
        if row is None:
            raise unavailable('no approved destination for this connection')
        return load_checked(row[0], row[1], connection_id)

    def block(self, connection_id: str, evidence: dict) -> ApprovedDestination:
        dest = self.get(connection_id)
        blocked = replace(dest, state=BLOCKED, version=dest.version + 1, evidence=sanitize_evidence(evidence))
        return self.put(blocked, expected_version=dest.version)

    def propose_change(self, connection_id: str, new_addresses: Iterable, *, proposer: str, overlap: int = 0,
                       evidence: Optional[dict] = None) -> str:
        import uuid
        dest = self.get(connection_id)
        addrs = tuple(a if isinstance(a, ApprovedAddress) else ApprovedAddress.from_dict(a) for a in new_addresses)
        for a in addrs:
            check_address(a)
        cid = str(uuid.uuid4())
        with self._lock:
            self._changes[cid] = _Change(cid, connection_id, dest.version, addrs, overlap, proposer,
                                         int(self._clock()), sanitize_evidence(evidence) if evidence else None)
        return cid

    def approve_change(self, change_id: str, *, approver: str) -> ApprovedDestination:
        with self._lock:
            ch = self._changes.get(change_id)
        if ch is None or ch.status != 'pending':
            raise ConnectError('not_found', 'no pending destination change', 404)
        dest = self.get(ch.connection_id)
        decision = change_decision(ch.addresses, ch.proposer, ch.approvers + [approver], dest.version,
                                   ch.base_version)
        with self._lock:
            ch.approvers.append(approver)
            if decision != 'apply':
                return dest
            ch.status = 'applied'
        new = with_migration(dest, ch.addresses, now=int(self._clock()), overlap=ch.overlap,
                             approved_by=[ch.proposer] + ch.approvers)
        return self.put(new, expected_version=dest.version)


def change_decision(new_addresses: Sequence[ApprovedAddress], proposer: str, approvers: Sequence[str],
                    current_version: int, base_version: int) -> str:
    """'apply' or 'wait'. A change proposed against an older version is void (the record moved on). The
    approver must differ from the proposer; a change that adds a private address needs two approvers
    other than the proposer (IP_ALLOWLIST_AND_BOOTSTRAP.md §4.1)."""
    if current_version != base_version:
        raise ConnectError('conflict', 'the destination changed since this change was proposed', 409)
    distinct = [a for a in dict.fromkeys(approvers) if a and a != proposer]
    if not distinct:
        raise ConnectError('second_admin_required', 'a different administrator must approve this change', 403)
    needed = 2 if any(a.private for a in new_addresses) else 1
    return 'apply' if len(distinct) >= needed else 'wait'


def load_checked(record: dict, digest: str, connection_id: str) -> ApprovedDestination:
    try:
        dest = ApprovedDestination.from_dict(record)
        dest.validate()
    except ConnectError as e:
        raise unavailable(f'approved destination record invalid: {e.message}') from e
    if dest.connection_id != connection_id:
        raise unavailable('approved destination record belongs to another connection')
    if dest.digest() != digest:
        raise unavailable('approved destination record failed its integrity check')
    return dest


_EVIDENCE_KEYS = ('code', 'host', 'port', 'approved', 'observed', 'connected', 'certificate', 'at', 'message')


def sanitize_evidence(evidence: Optional[dict]) -> dict:
    """Only allow-listed keys, bounded sizes; never request bodies, headers or secrets."""
    out = {}
    for k in _EVIDENCE_KEYS:
        v = (evidence or {}).get(k)
        if v is None:
            continue
        if isinstance(v, (list, tuple)):
            out[k] = [str(x)[:128] for x in list(v)[:32]]
        elif isinstance(v, dict):
            out[k] = {str(kk)[:64]: (vv if isinstance(vv, (int, bool)) else str(vv)[:256])
                      for kk, vv in list(v.items())[:16] if not isinstance(vv, (dict, list))}
            sans = v.get('sans')
            if isinstance(sans, list):
                out[k]['sans'] = [str(s)[:128] for s in sans[:32]]
        elif isinstance(v, (int, bool)):
            out[k] = v
        else:
            out[k] = str(v)[:256]
    return out
