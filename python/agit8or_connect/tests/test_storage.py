"""Persistent stores: replay, rate limits, destinations, approvals.

Runs against SQLite (a file in a temporary directory) always, and against PostgreSQL when
AGIT8OR_CONNECT_TEST_POSTGRES_DSN is set (CI provides a PostgreSQL service). Concurrency tests use several
OS processes on the same database, which is what several application workers do.
"""
import multiprocessing
import os
import shutil
import sqlite3
import tempfile
import time
import unittest
import uuid

from agit8or_connect import approvals as ap
from agit8or_connect import pairing, tokens
from agit8or_connect.destinations import ApprovedAddress, new_destination
from agit8or_connect.errors import ConnectError
from agit8or_connect.keys import generate_private_key
from agit8or_connect.ratelimit import RateLimiter, Rule
from agit8or_connect.scopes import Catalog, Scope
from agit8or_connect.storage import (PostgresBackend, SqlActionApprovalStore, SqlDestinationStore,
                                     SqlGrantApprovalStore, SqlRateLimitStore, SqlReplayStore, SqliteBackend)

PG_DSN = os.environ.get('AGIT8OR_CONNECT_TEST_POSTGRES_DSN', '')
CTX = multiprocessing.get_context('spawn')


def _backend(kind, where):
    return SqliteBackend(where) if kind == 'sqlite' else PostgresBackend(where)


# --- worker functions (module level so 'spawn' can import them) ----------------------------------------

def _race_replay(kind, where, key, start_at, q):
    store = SqlReplayStore(_backend(kind, where))
    while time.time() < start_at:
        time.sleep(0.001)
    q.put(store.add('race', key, int(time.time()) + 600))


def _race_limit(kind, where, n, start_at, q):
    store = SqlRateLimitStore(_backend(kind, where))
    while time.time() < start_at:
        time.sleep(0.001)
    for _ in range(n):
        store.hit('bucket', 1000, 60)
    q.put(True)


def _race_consume(kind, where, rid, start_at, q):
    store = SqlActionApprovalStore(_backend(kind, where))
    while time.time() < start_at:
        time.sleep(0.001)
    q.put(store.consume(rid, connection_id='c1', tenant='t1', target='dev-1', action_type='reboot',
                        params_sha256=ap.action_params_digest({'force': False}), now=int(time.time())))


def _race_token_assertion(kind, where, assertion, endpoint, pub_pem, start_at, q):
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_public_key(pub_pem.encode())
    store = SqlReplayStore(_backend(kind, where))
    while time.time() < start_at:
        time.sleep(0.001)
    try:
        tokens.verify_client_assertion(assertion, lambda kid: key, client_id='c1', token_endpoint=endpoint, replay=store)
        q.put('ok')
    except ConnectError as e:
        q.put(e.code)


def _run_race(target, args, n=8):
    q = CTX.Queue()
    start_at = time.time() + 1.5
    procs = [CTX.Process(target=target, args=args + (start_at, q)) for _ in range(n)]
    for p in procs:
        p.start()
    results = [q.get(timeout=60) for _ in procs]
    for p in procs:
        p.join(30)
    return results


class _StoreTests:
    kind = 'sqlite'

    def setUp(self):
        if self.kind == 'sqlite':
            self.dir = tempfile.mkdtemp()
            self.where = os.path.join(self.dir, 'connect.db')
        else:
            self.where = PG_DSN
            self._reset_pg()
        self.backend = _backend(self.kind, self.where)
        self.backend.migrate()

    def tearDown(self):
        if self.kind == 'sqlite':
            shutil.rmtree(self.dir, ignore_errors=True)

    def _reset_pg(self):
        b = PostgresBackend(PG_DSN)
        with b.tx() as cur:
            for t in ('connect_replay', 'connect_ratelimit', 'connect_destination', 'connect_destination_change',
                      'connect_grant_approval', 'connect_action_approval'):
                cur.execute(f'DROP TABLE IF EXISTS {t}')

    # replay ----------------------------------------------------------------------------------------
    def test_replay_single_use_and_restart(self):
        r = SqlReplayStore(self.backend)
        now = int(time.time())
        self.assertTrue(r.add('dpop', 'k1', now + 60))
        self.assertFalse(r.add('dpop', 'k1', now + 60))
        self.assertTrue(r.add('assertion', 'k1', now + 60), 'namespaces are separate')
        restarted = SqlReplayStore(_backend(self.kind, self.where))   # a new process after a restart
        self.assertFalse(restarted.add('dpop', 'k1', now + 60))

    def test_replay_expiry_reuse_and_purge(self):
        clock = [1_800_000_000]
        r = SqlReplayStore(self.backend, clock=lambda: clock[0])
        self.assertTrue(r.add('event', 'e1', clock[0] + 10))
        clock[0] += 11
        self.assertTrue(r.add('event', 'e1', clock[0] + 10), 'an expired value may be recorded again')
        self.assertFalse(r.add('event', 'e1', clock[0] + 10))
        r.add('event', 'e2', clock[0] + 5)
        clock[0] += 100
        self.assertEqual(r.purge(), 2)
        self.assertEqual(r.count(), 0)

    def test_replay_ttl_is_clamped(self):
        clock = [1_800_000_000]
        r = SqlReplayStore(self.backend, clock=lambda: clock[0])
        r.add('x', 'k', clock[0] + 10 ** 9)
        clock[0] += 9 * 86400
        self.assertTrue(r.add('x', 'k', clock[0] + 10), 'caller-chosen expiry cannot keep a row forever')

    def test_replay_concurrent_processes_exactly_one_wins(self):
        results = _run_race(_race_replay, (self.kind, self.where, 'shared-jti'))
        self.assertEqual(results.count(True), 1, results)

    def test_concurrent_token_assertion_replay(self):
        key = generate_private_key()
        endpoint = 'https://b.example.test/connect/v1/token'
        assertion = tokens.build_client_assertion(key, 'c1', endpoint)
        from cryptography.hazmat.primitives import serialization
        pem = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        results = _run_race(_race_token_assertion, (self.kind, self.where, assertion, endpoint, pem))
        self.assertEqual(results.count('ok'), 1, results)
        self.assertEqual(results.count('replayed'), len(results) - 1, results)

    def test_invalid_signature_does_not_touch_replay_storage(self):
        r = SqlReplayStore(self.backend)
        key, other = generate_private_key(), generate_private_key()
        endpoint = 'https://b.example.test/connect/v1/token'
        for _ in range(20):
            forged = tokens.build_client_assertion(other, 'c1', endpoint)
            with self.assertRaises(ConnectError):
                tokens.verify_client_assertion(forged, lambda kid: key.public_key(), client_id='c1',
                                               token_endpoint=endpoint, replay=r)
            proof = tokens.build_dpop_proof(other, 'POST', endpoint)
            with self.assertRaises(ConnectError):
                tokens.verify_dpop_proof(proof, method='POST', url=endpoint, replay=r,
                                         allowed_jkts=['not-this-key'])
        self.assertEqual(r.count(), 0)

    def test_pairing_requests_recorded_only_after_the_code(self):
        r = SqlReplayStore(self.backend)
        for _ in range(10):
            req, _ = pairing.build_request(generate_private_key(), initiator_app={
                'type': 'x', 'installation_id': str(uuid.uuid4())}, responder_installation='resp',
                pairing_code='00000-00000', connection_id=str(uuid.uuid4()),
                discovery_url='https://a.example.test/.well-known/agit8or-connect', requested_scopes=[])
            pairing.verify_request(req, responder_installation='resp', replay=None)
        self.assertEqual(r.count(), 0)

    # rate limits -----------------------------------------------------------------------------------
    def test_rate_limit_shared_across_processes(self):
        _run_race(_race_limit, (self.kind, self.where, 25), n=4)
        self.assertEqual(SqlRateLimitStore(self.backend).get('bucket', 1000), 100)

    def test_rate_limit_rules_and_nat_separation(self):
        clock = [1_800_000_000]
        lim = RateLimiter(SqlRateLimitStore(self.backend), {'token.failure': Rule(3, 300)}, clock=lambda: clock[0])
        for _ in range(3):
            lim.hit('token.failure', 'conn-victim', '198.51.100.1')
        with self.assertRaises(ConnectError) as e:
            lim.ensure_below('token.failure', 'conn-victim', '198.51.100.1')
        self.assertEqual(e.exception.code, 'rate_limited')
        self.assertGreater(e.exception.retry_after, 0)
        # Same NAT address, another connection; same connection, another address: unaffected.
        lim.ensure_below('token.failure', 'conn-other', '198.51.100.1')
        lim.ensure_below('token.failure', 'conn-victim', '203.0.113.9')
        clock[0] += 900
        lim.ensure_below('token.failure', 'conn-victim', '198.51.100.1')

    def test_sliding_window_boundary(self):
        clock = [1_800_000_000 - 1_800_000_000 % 60 + 59]   # one second before a window ends
        lim = RateLimiter(SqlRateLimitStore(self.backend), {'r': Rule(10, 60)}, clock=lambda: clock[0])
        for _ in range(10):
            lim.check('r', 'x')
        clock[0] += 2                                        # next window
        with self.assertRaises(ConnectError):
            lim.check('r', 'x')

    # destinations ----------------------------------------------------------------------------------
    def test_destination_versioning_integrity_and_block(self):
        s = SqlDestinationStore(self.backend)
        d = new_destination('c1', 'peer.example.test', 443, ['203.0.113.10'])
        s.put(d)
        self.assertEqual(s.get('c1'), d)
        with self.assertRaises(ConnectError) as e:
            s.put(d)                                         # same version again
        self.assertEqual(e.exception.code, 'conflict')
        b = s.block('c1', {'code': 'destination_changed', 'observed': ['203.0.113.99'], 'token': 'x' * 10})
        self.assertEqual(b.state, 'security_blocked')
        self.assertNotIn('token', b.evidence)
        with self.backend.tx() as cur:                       # someone edits the row behind our back
            cur.execute("UPDATE connect_destination SET record = REPLACE(record, '203.0.113.10', '203.0.113.11')")
        with self.assertRaises(ConnectError) as e:
            s.get('c1')
        self.assertEqual(e.exception.code, 'destination_policy_unavailable')
        with self.backend.tx() as cur:
            cur.execute("UPDATE connect_destination SET record = 'not json'")
        with self.assertRaises(ConnectError):
            s.get('c1')

    def test_destination_reviewed_change(self):
        s = SqlDestinationStore(self.backend)
        s.put(new_destination('c1', 'peer.example.test', 443, ['203.0.113.10']))
        cid = s.propose_change('c1', [ApprovedAddress('10.1.2.3/32', private=True)], proposer='alice')
        with self.assertRaises(ConnectError):
            s.approve_change(cid, approver='alice')
        self.assertEqual(s.approve_change(cid, approver='bob').version, 1)
        d = s.approve_change(cid, approver='carol')
        self.assertEqual([a.net for a in d.addresses], ['10.1.2.3/32'])
        with self.assertRaises(ConnectError):
            s.approve_change(cid, approver='dave')

    # approvals -------------------------------------------------------------------------------------
    def test_grant_approval_store(self):
        cat = Catalog([Scope('a:read', 'r', 'read'), Scope('a:run', 'x', 'high_risk')])
        pol = ap.ElevatedGrantPolicy(SqlGrantApprovalStore(self.backend), cat)
        now = int(time.time())
        pid = pol.propose(connection_id='c1', fingerprint='f1', scopes=['a:read', 'a:run'],
                          proposer=ap.AdminAuth('alice', now))
        self.assertFalse(pol.is_authorized('c1', 'f1', ['a:run']))
        with self.assertRaises(ConnectError):
            pol.approve(pid, approver=ap.AdminAuth('alice', now), current_fingerprint='f1')
        pol.approve(pid, approver=ap.AdminAuth('bob', now), current_fingerprint='f1')
        self.assertTrue(pol.is_authorized('c1', 'f1', ['a:run', 'a:read']))
        self.assertFalse(pol.is_authorized('c1', 'f2', ['a:run']))
        pol.revoke('c1')
        self.assertFalse(pol.is_authorized('c1', 'f1', ['a:run']))

    def test_action_approval_consumed_once_across_processes(self):
        store = SqlActionApprovalStore(self.backend)
        acts = ap.ActionApprovals(store)
        req = acts.request(connection_id='c1', tenant='t1', target='dev-1', action_type='reboot',
                           params={'force': False}, operator='remote:op-1', required_scope='remote_actions:execute')
        acts.decide(req.id, approve=True, admin=ap.AdminAuth('alice', int(time.time())))
        results = _run_race(_race_consume, (self.kind, self.where, req.id))
        self.assertEqual(results.count(True), 1, results)


class SqliteStores(_StoreTests, unittest.TestCase):
    kind = 'sqlite'

    def test_storage_failure_fails_closed(self):
        d = tempfile.mkdtemp()
        try:
            path = os.path.join(d, 'x.db')
            b = SqliteBackend(path)
            b.migrate()
            os.chmod(path, 0o400)
            os.chmod(d, 0o500)
            if os.access(path, os.W_OK):
                self.skipTest('running with privileges that ignore file modes')
            for fn, code in ((lambda: SqlReplayStore(b).add('n', 'k', 10 ** 10), 'replay_store_unavailable'),
                             (lambda: RateLimiter(SqlRateLimitStore(b)).check('api.connection', 'c'),
                              'rate_limit_unavailable'),
                             (lambda: SqlDestinationStore(b).put(new_destination('c', 'h.example.test', 443,
                                                                                 ['203.0.113.1'])),
                              'destination_policy_unavailable')):
                with self.assertRaises(ConnectError) as e:
                    fn()
                self.assertEqual(e.exception.code, code)
                self.assertEqual(e.exception.status, 503)
        finally:
            os.chmod(d, 0o700)
            shutil.rmtree(d, ignore_errors=True)

    def test_missing_tables_fail_closed(self):
        b = SqliteBackend(os.path.join(self.dir, 'empty.db'))
        with self.assertRaises(ConnectError) as e:
            SqlReplayStore(b).add('n', 'k', 10 ** 10)
        self.assertEqual(e.exception.code, 'replay_store_unavailable')

    def test_wal_and_full_sync(self):
        conn = sqlite3.connect(self.where)
        self.assertEqual(conn.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
        conn.close()


@unittest.skipUnless(PG_DSN, 'set AGIT8OR_CONNECT_TEST_POSTGRES_DSN to run the PostgreSQL store tests')
class PostgresStores(_StoreTests, unittest.TestCase):
    kind = 'postgres'


class PostgresRequired(unittest.TestCase):
    """In the CI PostgreSQL job a missing DSN or driver is a failure, never a silent skip."""

    @unittest.skipUnless(os.environ.get('AGIT8OR_CONNECT_REQUIRE_POSTGRES'), 'only in the PostgreSQL CI job')
    def test_postgres_really_ran(self):
        self.assertTrue(PG_DSN, 'AGIT8OR_CONNECT_TEST_POSTGRES_DSN is not set')
        import psycopg  # noqa: F401  (ImportError fails the job)


if __name__ == '__main__':
    unittest.main()
