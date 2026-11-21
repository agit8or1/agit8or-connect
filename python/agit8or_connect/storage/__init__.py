"""Persistent, multi-process stores on SQL (SQLite or PostgreSQL), behind the SDK's store interfaces.

    backend = SqliteBackend('/var/lib/app/connect.db')          # or PostgresBackend(dsn=...)
    backend.migrate()                                           # CREATE TABLE IF NOT EXISTS ...
    replay = SqlReplayStore(backend)                            # replay.ReplayStore
    limits = SqlRateLimitStore(backend)                         # ratelimit.RateLimitStore
    destinations = SqlDestinationStore(backend)                 # destinations.DestinationPolicy
    grants = SqlGrantApprovalStore(backend); actions = SqlActionApprovalStore(backend)

Guarantees (tested in python/agit8or_connect/tests/test_storage.py, against SQLite locally and against
PostgreSQL when AGIT8OR_CONNECT_TEST_POSTGRES_DSN is set — CI runs a PostgreSQL service for that):

* Single-use values: one INSERT … ON CONFLICT … DO UPDATE … WHERE <expired> statement; the database's
  unique key decides, so two workers (threads, processes or hosts sharing the database) racing on the
  same value cannot both win, and a restart forgets nothing.
* Counters: one atomic upsert per hit.
* Every failure to read or write raises ConnectError with a `*_unavailable` code (HTTP 503): callers
  refuse the request (fail closed). Nothing here ever answers "allowed" because storage failed.

`SqliteBackend` suits one host (several worker processes); WAL mode and synchronous=FULL are set. For
several hosts use PostgreSQL. The SQL is plain enough to port to other databases; a port must keep the
unique constraints and the single-statement conditional updates.
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
import threading
import time
import uuid
from typing import Callable, Iterator, Optional

from ..errors import ConnectError

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS connect_replay (
        namespace TEXT NOT NULL, key TEXT NOT NULL, expires_at BIGINT NOT NULL,
        PRIMARY KEY (namespace, key))""",
    "CREATE INDEX IF NOT EXISTS connect_replay_expiry ON connect_replay (expires_at)",
    """CREATE TABLE IF NOT EXISTS connect_ratelimit (
        bucket TEXT NOT NULL, window_start BIGINT NOT NULL, count BIGINT NOT NULL, expires_at BIGINT NOT NULL,
        PRIMARY KEY (bucket, window_start))""",
    "CREATE INDEX IF NOT EXISTS connect_ratelimit_expiry ON connect_ratelimit (expires_at)",
    """CREATE TABLE IF NOT EXISTS connect_destination (
        connection_id TEXT PRIMARY KEY, version BIGINT NOT NULL, record TEXT NOT NULL, digest TEXT NOT NULL,
        updated_at BIGINT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS connect_destination_change (
        id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, base_version BIGINT NOT NULL, addresses TEXT NOT NULL,
        overlap BIGINT NOT NULL, proposer TEXT NOT NULL, approvers TEXT NOT NULL, evidence TEXT,
        status TEXT NOT NULL, proposed_at BIGINT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS connect_grant_approval (
        id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, fingerprint TEXT NOT NULL, scopes TEXT NOT NULL,
        proposer TEXT NOT NULL, proposed_at BIGINT NOT NULL, proposer_auth_at BIGINT NOT NULL,
        approver TEXT, approved_at BIGINT, approver_auth_at BIGINT, status TEXT NOT NULL,
        expires_at BIGINT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS connect_grant_approval_conn ON connect_grant_approval (connection_id, status)",
    """CREATE TABLE IF NOT EXISTS connect_action_approval (
        id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, tenant TEXT NOT NULL, target TEXT NOT NULL,
        action_type TEXT NOT NULL, params_sha256 TEXT NOT NULL, operator TEXT NOT NULL,
        required_scope TEXT NOT NULL, requested_at BIGINT NOT NULL, expires_at BIGINT NOT NULL,
        status TEXT NOT NULL, decided_by TEXT, decided_at BIGINT, consumed_at BIGINT, record TEXT NOT NULL)""",
]


# Tables of optional modules (audit log, event queue, source policy) are appended here by those modules
# so `migrate()` creates everything a host uses.
EXTRA_SCHEMA: list = []


class SqlBackend:
    """Connection factory + dialect. Subclasses provide `_connect()` and the placeholder style."""

    placeholder = '?'
    name = 'sql'

    def sql(self, statement: str) -> str:
        return statement if self.placeholder == '?' else statement.replace('?', self.placeholder)

    def _connect(self):
        raise NotImplementedError

    def _begin(self, conn, write: bool):
        pass

    @contextlib.contextmanager
    def tx(self, write: bool = True, error_code: str = 'storage_unavailable') -> Iterator[object]:
        """A transaction; any database error becomes ConnectError(error_code, 503)."""
        conn = None
        try:
            conn = self._connect()
            self._begin(conn, write)
            cur = conn.cursor()
            yield _Cursor(cur, self)
            conn.commit()
        except ConnectError:
            if conn is not None:
                _quiet(conn.rollback)
            raise
        except Exception as e:  # noqa: BLE001 — every storage failure fails closed
            if conn is not None:
                _quiet(conn.rollback)
            raise ConnectError(error_code, f'storage unavailable ({e.__class__.__name__})', 503) from e
        finally:
            if conn is not None:
                _quiet(conn.close)

    def migrate(self) -> None:
        with self.tx(write=True) as cur:
            for stmt in SCHEMA + list(self.extra_schema()):
                cur.execute(stmt)

    def extra_schema(self):
        return list(EXTRA_SCHEMA)


def _quiet(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001
        pass


class _Cursor:
    def __init__(self, cur, backend: SqlBackend):
        self._cur = cur
        self._b = backend

    def execute(self, statement: str, params=()):
        self._cur.execute(self._b.sql(statement), tuple(params))
        return self

    @property
    def rowcount(self) -> int:
        return self._cur.rowcount

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()


class SqliteBackend(SqlBackend):
    name = 'sqlite'

    def __init__(self, path: str, *, busy_timeout_ms: int = 5000):
        if sqlite3.sqlite_version_info < (3, 35, 0):
            raise RuntimeError('SQLite >= 3.35 is required (RETURNING, upsert)')
        self.path = path
        self.busy_timeout_ms = busy_timeout_ms
        self._init_lock = threading.Lock()
        self._wal = False

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=self.busy_timeout_ms / 1000, isolation_level=None)
        conn.execute(f'PRAGMA busy_timeout={int(self.busy_timeout_ms)}')
        conn.execute('PRAGMA synchronous=FULL')
        if not self._wal:
            with self._init_lock:
                conn.execute('PRAGMA journal_mode=WAL')
                self._wal = True
        return conn

    def _begin(self, conn, write: bool):
        conn.execute('BEGIN IMMEDIATE' if write else 'BEGIN')


class PostgresBackend(SqlBackend):
    """psycopg 3 (`pip install psycopg`). Pass `connect` to use your own pool."""
    name = 'postgres'
    placeholder = '%s'

    def __init__(self, dsn: Optional[str] = None, *, connect: Optional[Callable[[], object]] = None):
        if connect is None:
            import psycopg  # imported lazily: optional dependency
            connect = lambda: psycopg.connect(dsn)  # noqa: E731
        self._factory = connect

    def _connect(self):
        return self._factory()


# --- replay -----------------------------------------------------------------------------------------

MAX_REPLAY_TTL = 8 * 86400
MAX_KEY = 512


class SqlReplayStore:
    """replay.ReplayStore on a UNIQUE (namespace, key). An expired row is reused atomically."""

    def __init__(self, backend: SqlBackend, clock: Callable[[], float] = time.time):
        self.backend = backend
        self.clock = clock

    def add(self, namespace: str, key: str, expires_at: int) -> bool:
        if not namespace or not key or len(namespace) > 64 or len(key) > MAX_KEY:
            raise ConnectError('invalid_request', 'replay key malformed', 400)
        now = int(self.clock())
        exp = min(int(expires_at), now + MAX_REPLAY_TTL)
        with self.backend.tx(error_code='replay_store_unavailable') as cur:
            cur.execute('INSERT INTO connect_replay (namespace, key, expires_at) VALUES (?, ?, ?) '
                        'ON CONFLICT (namespace, key) DO UPDATE SET expires_at = excluded.expires_at '
                        'WHERE connect_replay.expires_at <= ?', (namespace, key, exp, now))
            return cur.rowcount == 1

    def purge(self, limit: int = 10000) -> int:
        now = int(self.clock())
        with self.backend.tx(error_code='replay_store_unavailable') as cur:
            cur.execute('DELETE FROM connect_replay WHERE (namespace, key) IN (SELECT namespace, key FROM '
                        'connect_replay WHERE expires_at <= ? LIMIT ?)', (now, int(limit)))
            return cur.rowcount

    def count(self) -> int:
        with self.backend.tx(write=False, error_code='replay_store_unavailable') as cur:
            return cur.execute('SELECT COUNT(*) FROM connect_replay').fetchone()[0]


# --- rate limits ------------------------------------------------------------------------------------

class SqlRateLimitStore:
    """ratelimit.RateLimitStore: fixed windows, one atomic upsert per hit."""

    def __init__(self, backend: SqlBackend):
        self.backend = backend

    def hit(self, bucket: str, window_start: int, window: int, amount: int = 1) -> int:
        with self.backend.tx(error_code='rate_limit_unavailable') as cur:
            row = cur.execute('INSERT INTO connect_ratelimit (bucket, window_start, count, expires_at) '
                              'VALUES (?, ?, ?, ?) ON CONFLICT (bucket, window_start) DO UPDATE SET '
                              'count = connect_ratelimit.count + excluded.count RETURNING count',
                              (bucket, window_start, amount, window_start + 2 * window)).fetchone()
            return int(row[0])

    def get(self, bucket: str, window_start: int) -> int:
        with self.backend.tx(write=False, error_code='rate_limit_unavailable') as cur:
            row = cur.execute('SELECT count FROM connect_ratelimit WHERE bucket = ? AND window_start = ?',
                              (bucket, window_start)).fetchone()
            return int(row[0]) if row else 0

    def purge(self, now: int, limit: int = 10000) -> int:
        with self.backend.tx(error_code='rate_limit_unavailable') as cur:
            cur.execute('DELETE FROM connect_ratelimit WHERE (bucket, window_start) IN (SELECT bucket, '
                        'window_start FROM connect_ratelimit WHERE expires_at <= ? LIMIT ?)', (now, int(limit)))
            return cur.rowcount


# --- approved destinations --------------------------------------------------------------------------

class SqlDestinationStore:
    """destinations.DestinationPolicy with versioned compare-and-set writes, an integrity digest checked
    on every read, security blocks with evidence, and reviewed changes (destinations.change_decision)."""

    def __init__(self, backend: SqlBackend, clock: Callable[[], float] = time.time):
        self.backend = backend
        self.clock = clock

    def put(self, dest, *, expected_version: Optional[int] = None):
        dest.validate()
        rec = json.dumps(dest.as_dict(), sort_keys=True)
        now = int(self.clock())
        with self.backend.tx(error_code='destination_policy_unavailable') as cur:
            row = cur.execute('SELECT version FROM connect_destination WHERE connection_id = ?',
                              (dest.connection_id,)).fetchone()
            current = int(row[0]) if row else None
            if expected_version is not None and current != expected_version:
                raise ConnectError('conflict', 'destination changed concurrently', 409)
            if current is not None and dest.version <= current:
                raise ConnectError('conflict', 'destination version must increase', 409)
            if row:
                cur.execute('UPDATE connect_destination SET version = ?, record = ?, digest = ?, updated_at = ? '
                            'WHERE connection_id = ? AND version = ?',
                            (dest.version, rec, dest.digest(), now, dest.connection_id, current))
                if cur.rowcount != 1:
                    raise ConnectError('conflict', 'destination changed concurrently', 409)
            else:
                cur.execute('INSERT INTO connect_destination (connection_id, version, record, digest, updated_at) '
                            'VALUES (?, ?, ?, ?, ?)', (dest.connection_id, dest.version, rec, dest.digest(), now))
        return dest

    def get(self, connection_id: str):
        from ..destinations import load_checked, unavailable
        with self.backend.tx(write=False, error_code='destination_policy_unavailable') as cur:
            row = cur.execute('SELECT record, digest FROM connect_destination WHERE connection_id = ?',
                              (connection_id,)).fetchone()
        if row is None:
            raise unavailable('no approved destination for this connection')
        try:
            record = json.loads(row[0])
        except ValueError as e:
            raise unavailable('approved destination record is corrupt') from e
        return load_checked(record, row[1], connection_id)

    def block(self, connection_id: str, evidence: dict):
        from dataclasses import replace
        from ..destinations import BLOCKED, sanitize_evidence
        dest = self.get(connection_id)
        if dest.state == BLOCKED:
            return dest
        return self.put(replace(dest, state=BLOCKED, version=dest.version + 1, evidence=sanitize_evidence(evidence)),
                        expected_version=dest.version)

    def propose_change(self, connection_id: str, new_addresses, *, proposer: str, overlap: int = 0,
                       evidence: Optional[dict] = None) -> str:
        from ..destinations import ApprovedAddress, check_address, sanitize_evidence
        dest = self.get(connection_id)
        addrs = [a if isinstance(a, ApprovedAddress) else ApprovedAddress.from_dict(a) for a in new_addresses]
        for a in addrs:
            check_address(a)
        cid = str(uuid.uuid4())
        with self.backend.tx(error_code='destination_policy_unavailable') as cur:
            cur.execute('INSERT INTO connect_destination_change (id, connection_id, base_version, addresses, overlap, '
                        'proposer, approvers, evidence, status, proposed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (cid, connection_id, dest.version, json.dumps([a.as_dict() for a in addrs]), int(overlap),
                         proposer, '[]', json.dumps(sanitize_evidence(evidence)) if evidence else None, 'pending',
                         int(self.clock())))
        return cid

    def approve_change(self, change_id: str, *, approver: str):
        from ..destinations import ApprovedAddress, change_decision, with_migration
        with self.backend.tx(error_code='destination_policy_unavailable') as cur:
            row = cur.execute('SELECT connection_id, base_version, addresses, overlap, proposer, approvers, status '
                              'FROM connect_destination_change WHERE id = ?', (change_id,)).fetchone()
        if row is None or row[6] != 'pending':
            raise ConnectError('not_found', 'no pending destination change', 404)
        conn_id, base, addrs_json, overlap, proposer, approvers_json, _ = row
        addrs = [ApprovedAddress.from_dict(a) for a in json.loads(addrs_json)]
        approvers = json.loads(approvers_json) + [approver]
        dest = self.get(conn_id)
        decision = change_decision(addrs, proposer, approvers, dest.version, int(base))
        with self.backend.tx(error_code='destination_policy_unavailable') as cur:
            cur.execute('UPDATE connect_destination_change SET approvers = ?, status = ? WHERE id = ? AND '
                        "status = 'pending' AND approvers = ?",
                        (json.dumps(approvers), 'applied' if decision == 'apply' else 'pending', change_id,
                         approvers_json))
            if cur.rowcount != 1:
                raise ConnectError('conflict', 'the change was decided concurrently', 409)
        if decision != 'apply':
            return dest
        new = with_migration(dest, addrs, now=int(self.clock()), overlap=int(overlap),
                             approved_by=[proposer] + [a for a in approvers if a != proposer])
        return self.put(new, expected_version=dest.version)


# --- elevated-grant approvals and per-action approvals ---------------------------------------------

_GRANT_COLS = ('id', 'connection_id', 'fingerprint', 'scopes', 'proposer', 'proposed_at', 'proposer_auth_at',
               'approver', 'approved_at', 'approver_auth_at', 'status', 'expires_at')


def _grant_row(row) -> dict:
    d = dict(zip(_GRANT_COLS, row))
    d['scopes'] = json.loads(d['scopes'])
    return d


class SqlGrantApprovalStore:
    """approvals.GrantApprovalStore."""

    def __init__(self, backend: SqlBackend):
        self.backend = backend

    def create(self, p: dict) -> None:
        with self.backend.tx(error_code='approval_store_unavailable') as cur:
            cur.execute('INSERT INTO connect_grant_approval (id, connection_id, fingerprint, scopes, proposer, '
                        'proposed_at, proposer_auth_at, status, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (p['id'], p['connection_id'], p['fingerprint'], json.dumps(p['scopes']), p['proposer'],
                         p['proposed_at'], p['proposer_auth_at'], 'pending', p['expires_at']))

    def get(self, proposal_id: str) -> Optional[dict]:
        with self.backend.tx(write=False, error_code='approval_store_unavailable') as cur:
            row = cur.execute(f'SELECT {", ".join(_GRANT_COLS)} FROM connect_grant_approval WHERE id = ?',
                              (proposal_id,)).fetchone()
        return _grant_row(row) if row else None

    def approve(self, proposal_id: str, *, approver: str, approver_auth_at: int, fingerprint: str, now: int) -> bool:
        with self.backend.tx(error_code='approval_store_unavailable') as cur:
            cur.execute("UPDATE connect_grant_approval SET status = 'approved', approver = ?, approved_at = ?, "
                        "approver_auth_at = ? WHERE id = ? AND status = 'pending' AND proposer <> ? AND "
                        'fingerprint = ? AND expires_at > ?',
                        (approver, now, approver_auth_at, proposal_id, approver, fingerprint, now))
            return cur.rowcount == 1

    def set_status(self, proposal_id: str, status: str, *, only_from: str = 'pending') -> bool:
        with self.backend.tx(error_code='approval_store_unavailable') as cur:
            cur.execute('UPDATE connect_grant_approval SET status = ? WHERE id = ? AND status = ?',
                        (status, proposal_id, only_from))
            return cur.rowcount == 1

    def find_approved(self, connection_id: str, fingerprint: str) -> Optional[dict]:
        with self.backend.tx(write=False, error_code='approval_store_unavailable') as cur:
            row = cur.execute(f'SELECT {", ".join(_GRANT_COLS)} FROM connect_grant_approval WHERE connection_id = ? '
                              "AND fingerprint = ? AND status = 'approved' ORDER BY approved_at DESC LIMIT 1",
                              (connection_id, fingerprint)).fetchone()
        return _grant_row(row) if row else None

    def invalidate(self, connection_id: str, *, keep_fingerprint: Optional[str] = None,
                   status: str = 'invalidated') -> int:
        with self.backend.tx(error_code='approval_store_unavailable') as cur:
            cur.execute("UPDATE connect_grant_approval SET status = ? WHERE connection_id = ? AND status IN "
                        "('pending', 'approved') AND fingerprint <> ?",
                        (status, connection_id, keep_fingerprint or ''))
            return cur.rowcount


_ACTION_COLS = ('id', 'connection_id', 'tenant', 'target', 'action_type', 'params_sha256', 'operator',
                'required_scope', 'requested_at', 'expires_at', 'status', 'decided_by', 'decided_at', 'consumed_at',
                'record')


def _action_row(row) -> dict:
    d = dict(zip(_ACTION_COLS, row))
    d['record'] = json.loads(d['record'])
    return d


class SqlActionApprovalStore:
    """approvals.ActionApprovalStore: consume() is a single conditional UPDATE, so an approval is used at
    most once even when several workers race on it."""

    def __init__(self, backend: SqlBackend):
        self.backend = backend

    def create(self, r: dict) -> None:
        with self.backend.tx(error_code='approval_store_unavailable') as cur:
            cur.execute('INSERT INTO connect_action_approval (id, connection_id, tenant, target, action_type, '
                        'params_sha256, operator, required_scope, requested_at, expires_at, status, record) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (r['id'], r['connection_id'], r['tenant'], r['target'], r['action_type'], r['params_sha256'],
                         r['operator'], r['required_scope'], r['requested_at'], r['expires_at'], 'pending',
                         json.dumps(r.get('record') or {}, sort_keys=True)))

    def get(self, request_id: str) -> Optional[dict]:
        with self.backend.tx(write=False, error_code='approval_store_unavailable') as cur:
            row = cur.execute(f'SELECT {", ".join(_ACTION_COLS)} FROM connect_action_approval WHERE id = ?',
                              (request_id,)).fetchone()
        return _action_row(row) if row else None

    def decide(self, request_id: str, *, approve: bool, admin: str, now: int) -> bool:
        with self.backend.tx(error_code='approval_store_unavailable') as cur:
            cur.execute("UPDATE connect_action_approval SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? "
                        "AND status = 'pending' AND operator <> ? AND expires_at > ?",
                        ('approved' if approve else 'denied', admin, now, request_id, admin, now))
            return cur.rowcount == 1

    def consume(self, request_id: str, *, connection_id: str, tenant: str, target: str, action_type: str,
                params_sha256: str, now: int) -> bool:
        with self.backend.tx(error_code='approval_store_unavailable') as cur:
            cur.execute("UPDATE connect_action_approval SET status = 'consumed', consumed_at = ? WHERE id = ? AND "
                        "status = 'approved' AND expires_at > ? AND connection_id = ? AND tenant = ? AND target = ? "
                        'AND action_type = ? AND params_sha256 = ?',
                        (now, request_id, now, connection_id, tenant, target, action_type, params_sha256))
            return cur.rowcount == 1

    def cancel_connection(self, connection_id: str) -> int:
        with self.backend.tx(error_code='approval_store_unavailable') as cur:
            cur.execute("UPDATE connect_action_approval SET status = 'cancelled' WHERE connection_id = ? AND status "
                        "IN ('pending', 'approved')", (connection_id,))
            return cur.rowcount


from .extra import SCHEMA_EXTRA as _SCHEMA_EXTRA  # noqa: E402
from .extra import SqlAuditLog, SqlEventQueue, SqlSourcePolicyStore  # noqa: E402,F401

SCHEMA.extend(_SCHEMA_EXTRA)
