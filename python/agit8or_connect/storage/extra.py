"""SQL stores for the P1 host modules: durable event queue (AUTO_RECONNECT.md §4), append-only audit log with
signed checkpoints (audit.py), and the versioned source policy (sources.py). Same backends and fail-closed
rule as the other stores: any storage error raises a `*_unavailable` ConnectError.
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Callable, List, Optional

from ..errors import ConnectError

SCHEMA_EXTRA = [
    """CREATE TABLE IF NOT EXISTS connect_event_queue (
        event_id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, seq BIGINT NOT NULL, event_type TEXT NOT NULL,
        tenant TEXT NOT NULL, body TEXT NOT NULL, created_at BIGINT NOT NULL, status TEXT NOT NULL,
        attempts BIGINT NOT NULL, reached_attempts BIGINT NOT NULL, next_attempt_at BIGINT NOT NULL,
        lease_owner TEXT, lease_until BIGINT, last_error TEXT, delivered_at BIGINT, requeued_from TEXT)""",
    "CREATE INDEX IF NOT EXISTS connect_event_queue_due ON connect_event_queue (connection_id, status, seq)",
    """CREATE TABLE IF NOT EXISTS connect_event_seq (connection_id TEXT PRIMARY KEY, seq BIGINT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS connect_audit (
        seq BIGINT PRIMARY KEY, record TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL,
        created_at BIGINT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS connect_audit_checkpoint (
        seq BIGINT PRIMARY KEY, hash TEXT NOT NULL, jws TEXT NOT NULL, created_at BIGINT NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS connect_source_policy (
        id TEXT PRIMARY KEY, version BIGINT NOT NULL, document TEXT NOT NULL, digest TEXT NOT NULL,
        updated_at BIGINT NOT NULL)""",
]

PENDING, DELIVERED, DEAD, CANCELLED = 'pending', 'delivered', 'dead', 'cancelled'
PERMANENT_STATUSES = {400, 401, 403, 404, 405, 409, 410, 413, 415, 422}


class SqlEventQueue:
    """Outbox of signed events per connection.

    - `claim(connection_id, worker, now)` leases the oldest due events (creation order) with one conditional
      UPDATE per row, so two workers never deliver the same row at the same time; a crashed worker's lease
      expires and the row is retried (the receiver deduplicates by event id: at-least-once, idempotent).
    - `record_failure(reached=False)` (circuit open, peer unreachable) does not spend an attempt.
    - Dead letter on a permanent status, on age above `max_age`, or after `max_reached` attempts that reached
      the peer. `requeue` brings a dead letter back with its ORIGINAL event id (audited by the caller).
    - `cancel_connection` (revocation) cancels queued rows but deletes nothing.
    """

    def __init__(self, backend, *, max_age: int = 7 * 86400, max_reached: int = 12, lease: int = 60,
                 clock: Callable[[], float] = time.time):
        self.backend, self.max_age, self.max_reached, self.lease, self.clock = backend, max_age, max_reached, lease, clock

    def _tx(self, write=True):
        return self.backend.tx(write=write, error_code='event_queue_unavailable')

    def enqueue(self, *, event_id: str, connection_id: str, event_type: str, tenant: str, body: bytes) -> int:
        now = int(self.clock())
        with self._tx() as cur:
            row = cur.execute('INSERT INTO connect_event_seq (connection_id, seq) VALUES (?, 1) ON CONFLICT '
                              '(connection_id) DO UPDATE SET seq = connect_event_seq.seq + 1 RETURNING seq',
                              (connection_id,)).fetchone()
            seq = int(row[0])
            cur.execute('INSERT INTO connect_event_queue (event_id, connection_id, seq, event_type, tenant, body, '
                        'created_at, status, attempts, reached_attempts, next_attempt_at) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)',
                        (event_id, connection_id, seq, event_type, tenant, body.decode('utf-8'), now, PENDING, now))
        return seq

    def claim(self, connection_id: str, worker: str, *, limit: int = 10) -> List[dict]:
        now = int(self.clock())
        out = []
        with self._tx() as cur:
            rows = cur.execute('SELECT event_id, seq, event_type, tenant, body, created_at, attempts, reached_attempts '
                               'FROM connect_event_queue WHERE connection_id = ? AND status = ? AND next_attempt_at <= ? '
                               'AND (lease_until IS NULL OR lease_until <= ?) ORDER BY seq LIMIT ?',
                               (connection_id, PENDING, now, now, int(limit))).fetchall()
            for r in rows:
                if now - int(r[5]) > self.max_age:
                    cur.execute('UPDATE connect_event_queue SET status = ?, last_error = ? WHERE event_id = ? AND '
                                'status = ?', (DEAD, 'too old', r[0], PENDING))
                    continue
                cur.execute('UPDATE connect_event_queue SET lease_owner = ?, lease_until = ? WHERE event_id = ? AND '
                            'status = ? AND (lease_until IS NULL OR lease_until <= ?)',
                            (worker, now + self.lease, r[0], PENDING, now))
                if cur.rowcount == 1:
                    out.append({'event_id': r[0], 'seq': int(r[1]), 'event_type': r[2], 'tenant': r[3],
                                'body': r[4].encode('utf-8'), 'created_at': int(r[5]), 'attempts': int(r[6]),
                                'reached_attempts': int(r[7])})
        return out

    def mark_delivered(self, event_id: str, worker: str) -> bool:
        with self._tx() as cur:
            cur.execute('UPDATE connect_event_queue SET status = ?, delivered_at = ?, lease_owner = NULL, '
                        'lease_until = NULL WHERE event_id = ? AND status = ? AND lease_owner = ?',
                        (DELIVERED, int(self.clock()), event_id, PENDING, worker))
            return cur.rowcount == 1

    def record_failure(self, event_id: str, worker: str, *, reached: bool, http_status: Optional[int] = None,
                       error: str = '', retry_at: Optional[float] = None) -> str:
        """Returns the row's new status. `retry_at` is the connection's next probe/attempt time."""
        now = int(self.clock())
        with self._tx() as cur:
            row = cur.execute('SELECT reached_attempts, attempts FROM connect_event_queue WHERE event_id = ? AND '
                              'status = ? AND lease_owner = ?', (event_id, PENDING, worker)).fetchone()
            if row is None:
                return 'not_leased'
            reached_n = int(row[0]) + (1 if reached else 0)
            attempts = int(row[1]) + (1 if reached else 0)
            dead = (reached and http_status in PERMANENT_STATUSES) or reached_n >= self.max_reached
            status = DEAD if dead else PENDING
            cur.execute('UPDATE connect_event_queue SET status = ?, attempts = ?, reached_attempts = ?, '
                        'next_attempt_at = ?, last_error = ?, lease_owner = NULL, lease_until = NULL '
                        'WHERE event_id = ? AND lease_owner = ?',
                        (status, attempts, reached_n, int(retry_at if retry_at is not None else now + 60),
                         (error or (str(http_status) if http_status else ''))[:200], event_id, worker))
            return status

    def requeue(self, event_id: str) -> bool:
        with self._tx() as cur:
            cur.execute('UPDATE connect_event_queue SET status = ?, reached_attempts = 0, next_attempt_at = ?, '
                        'created_at = ?, requeued_from = ? WHERE event_id = ? AND status = ?',
                        (PENDING, int(self.clock()), int(self.clock()), DEAD, event_id, DEAD))
            return cur.rowcount == 1

    def cancel_connection(self, connection_id: str) -> int:
        with self._tx() as cur:
            cur.execute('UPDATE connect_event_queue SET status = ? WHERE connection_id = ? AND status = ?',
                        (CANCELLED, connection_id, PENDING))
            return cur.rowcount

    def counts(self, connection_id: str) -> dict:
        with self._tx(write=False) as cur:
            rows = cur.execute('SELECT status, COUNT(*) FROM connect_event_queue WHERE connection_id = ? GROUP BY '
                               'status', (connection_id,)).fetchall()
        return {r[0]: int(r[1]) for r in rows}


class SqlAuditLog:
    """Append-only hash chain (audit.py). append() reads the head and inserts the next row in one write
    transaction; the primary key on seq makes a concurrent second writer fail instead of forking the chain."""

    def __init__(self, backend, clock: Callable[[], float] = time.time):
        self.backend, self.clock = backend, clock

    def _tx(self, write=True):
        return self.backend.tx(write=write, error_code='audit_unavailable')

    def append(self, record: dict) -> dict:
        from .. import audit
        rec = audit.redact(record)
        with self._tx() as cur:
            head = cur.execute('SELECT seq, hash FROM connect_audit ORDER BY seq DESC LIMIT 1').fetchone()
            seq, prev = (int(head[0]) + 1, head[1]) if head else (1, audit.GENESIS)
            h = audit.entry_hash(prev, rec)
            cur.execute('INSERT INTO connect_audit (seq, record, prev_hash, hash, created_at) VALUES (?, ?, ?, ?, ?)',
                        (seq, json.dumps(rec, sort_keys=True), prev, h, int(self.clock())))
        return {'seq': seq, 'prev_hash': prev, 'hash': h, 'record': rec}

    def entries(self, after_seq: int = 0, limit: int = 100000) -> List[dict]:
        with self._tx(write=False) as cur:
            rows = cur.execute('SELECT seq, record, prev_hash, hash FROM connect_audit WHERE seq > ? ORDER BY seq '
                               'LIMIT ?', (int(after_seq), int(limit))).fetchall()
        return [{'seq': int(r[0]), 'record': json.loads(r[1]), 'prev_hash': r[2], 'hash': r[3]} for r in rows]

    def head(self) -> Optional[dict]:
        with self._tx(write=False) as cur:
            r = cur.execute('SELECT seq, hash FROM connect_audit ORDER BY seq DESC LIMIT 1').fetchone()
        return {'seq': int(r[0]), 'hash': r[1]} if r else None

    def save_checkpoint(self, seq: int, h: str, jws: str) -> None:
        with self._tx() as cur:
            cur.execute('INSERT INTO connect_audit_checkpoint (seq, hash, jws, created_at) VALUES (?, ?, ?, ?)',
                        (int(seq), h, jws, int(self.clock())))

    def checkpoints(self) -> List[dict]:
        with self._tx(write=False) as cur:
            rows = cur.execute('SELECT seq, hash, jws FROM connect_audit_checkpoint ORDER BY seq').fetchall()
        return [{'seq': int(r[0]), 'hash': r[1], 'jws': r[2]} for r in rows]


class SqlSourcePolicyStore:
    """One versioned source-policy document with an integrity digest and compare-and-set on version."""

    def __init__(self, backend, policy_id: str = 'default', clock: Callable[[], float] = time.time):
        self.backend, self.policy_id, self.clock = backend, policy_id, clock

    def put(self, policy, *, expected_version: Optional[int]) -> None:
        from ..sources import SourcePolicy
        assert isinstance(policy, SourcePolicy)
        doc = json.dumps({'version': policy.version, 'rules': [r.as_dict() for r in policy.rules]}, sort_keys=True)
        with self.backend.tx(error_code='source_policy_unavailable') as cur:
            row = cur.execute('SELECT version FROM connect_source_policy WHERE id = ?', (self.policy_id,)).fetchone()
            cur_v = int(row[0]) if row else None
            if cur_v != expected_version:
                raise ConnectError('conflict', 'source policy changed concurrently', 409)
            if cur_v is not None and policy.version <= cur_v:
                raise ConnectError('conflict', 'source policy version must increase', 409)
            if row:
                cur.execute('UPDATE connect_source_policy SET version = ?, document = ?, digest = ?, updated_at = ? '
                            'WHERE id = ? AND version = ?', (policy.version, doc, policy.digest(), int(self.clock()),
                                                             self.policy_id, cur_v))
            else:
                cur.execute('INSERT INTO connect_source_policy (id, version, document, digest, updated_at) VALUES '
                            '(?, ?, ?, ?, ?)', (self.policy_id, policy.version, doc, policy.digest(), int(self.clock())))

    def get(self):
        from ..sources import SourcePolicy, SourceRule
        with self.backend.tx(write=False, error_code='source_policy_unavailable') as cur:
            row = cur.execute('SELECT document, digest FROM connect_source_policy WHERE id = ?',
                              (self.policy_id,)).fetchone()
        if not row:
            raise ConnectError('source_policy_unavailable', 'no source policy', 403)
        try:
            d = json.loads(row[0])
            p = SourcePolicy(int(d['version']), [SourceRule.from_dict(r) for r in d['rules']])
        except (ValueError, KeyError, TypeError, ConnectError):
            raise ConnectError('source_policy_unavailable', 'source policy record invalid', 403)
        if p.digest() != row[1]:
            raise ConnectError('source_policy_unavailable', 'source policy failed its integrity check', 403)
        return p


def new_event_id() -> str:
    return str(uuid.uuid4())
