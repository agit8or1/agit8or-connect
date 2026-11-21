"""P1 host modules: trusted proxy, source policy, lifecycle / reconnect / health, durable event queue, audit
checkpoints and exports, and the dpop-nonce/1 and actor/1 extensions (unit + reference-peer interop)."""
import json
import multiprocessing
import os
import tempfile
import unittest

from agit8or_connect import audit, keys
from agit8or_connect import extensions as ext
from agit8or_connect import lifecycle as lc
from agit8or_connect.errors import ConnectError
from agit8or_connect.proxy import TrustedProxyResolver, resolve_client_address
from agit8or_connect.reference_peer import API, Network, ReferencePeer
from agit8or_connect.sources import (PolicyCache, SourcePolicy, SourceRule, check_binding, check_rollback,
                                     preview_change)
from agit8or_connect.storage import SqlAuditLog, SqlEventQueue, SqliteBackend, SqlSourcePolicyStore
from agit8or_connect.tests.test_reference_peer import Clock


def code_of(fn):
    try:
        fn()
        return 'ok'
    except ConnectError as e:
        return e.code


class TrustedProxy(unittest.TestCase):
    def setUp(self):
        self.r = TrustedProxyResolver(['10.0.0.0/24'])

    def test_direct_peer_ignores_headers(self):
        self.assertEqual(self.r.resolve('203.0.113.9', {'X-Forwarded-For': '198.51.100.1'}), '203.0.113.9')
        self.assertEqual(resolve_client_address('::ffff:203.0.113.9', {'X-Forwarded-For': '1.2.3.4'}), '203.0.113.9')

    def test_right_to_left_through_trusted_proxies(self):
        h = {'X-Forwarded-For': '198.51.100.66, 203.0.113.5, 10.0.0.7'}   # client spoofed the left-most value
        self.assertEqual(self.r.resolve('10.0.0.5', h), '203.0.113.5')
        self.assertEqual(self.r.resolve('10.0.0.5', {'x-forwarded-for': '[2001:db8::1]:443'}), '2001:db8::1')

    def test_refusals(self):
        for h in ({}, {'X-Forwarded-For': ''}, {'X-Forwarded-For': 'example.test'}, {'X-Forwarded-For': '10.0.0.9'},
                  {'X-Forwarded-For': ','.join(['203.0.113.1'] * 9)}, {'X-Forwarded-For': '203.0.113.1,,'},
                  {'X-Forwarded-For': 'fe80::1%eth0'}):
            self.assertEqual(code_of(lambda: self.r.resolve('10.0.0.5', h)), 'source_unresolved', h)
        with self.assertRaises(ValueError):
            TrustedProxyResolver(['0.0.0.0/0'])

    def test_forwarded_header(self):
        r = TrustedProxyResolver(['10.0.0.0/24'], header='forwarded')
        self.assertEqual(r.resolve('10.0.0.5', {'Forwarded': 'for=198.51.100.66, for="[2001:db8::5]";proto=https'}),
                         '2001:db8::5')
        self.assertEqual(code_of(lambda: r.resolve('10.0.0.5', {'Forwarded': 'by=10.0.0.5'})), 'source_unresolved')


def rule(net, **kw):
    return SourceRule(net=net, **kw)


INSTALL = rule('203.0.113.0/24', layer='installation')


class Sources(unittest.TestCase):
    def policy(self, *extra, version=1):
        return SourcePolicy(version, [INSTALL, rule('198.51.100.0/24', layer='installation'), *extra])

    def test_two_layers_deny_wins_and_binding(self):
        p = self.policy(rule('203.0.113.10/32', connection_id='c1'), rule('203.0.113.11/32', connection_id='c2'),
                        rule('203.0.113.12/32', connection_id='c1', action='deny'))
        self.assertTrue(p.evaluate('203.0.113.10', route='token', connection_id='c1').allowed)
        self.assertFalse(p.evaluate('203.0.113.11', route='token', connection_id='c1').allowed)
        self.assertFalse(p.evaluate('203.0.113.12', route='token', connection_id='c1').allowed)
        self.assertFalse(p.evaluate('192.0.2.1', route='token', connection_id='c1').allowed, 'installation layer')
        self.assertFalse(p.evaluate('203.0.113.10', route='token', connection_id='nope').allowed)
        self.assertFalse(p.evaluate('203.0.113.10', route='token').allowed, 'named route without a connection')
        d = p.evaluate('203.0.113.10', route='discovery', active_connections=['c1'])
        self.assertTrue(d.allowed)
        self.assertTrue(p.evaluate('::ffff:203.0.113.10', route='token', connection_id='c1').allowed)
        ok = p.evaluate('203.0.113.10', route='token', connection_id='c1')
        check_binding(ok, 'c1')
        self.assertEqual(code_of(lambda: check_binding(ok, 'c2')), 'source_not_authorised')

    def test_temporary_pairing_rule_expires(self):
        p = self.policy(rule('198.51.100.7/32', temporary=True, purpose='pairing', expires_at=1000))
        self.assertTrue(p.evaluate('198.51.100.7', route='pairing', now=999).allowed)
        self.assertFalse(p.evaluate('198.51.100.7', route='pairing', now=1000).allowed)
        self.assertFalse(p.evaluate('198.51.100.7', route='token', connection_id='c1', now=999).allowed)

    def test_rule_validation(self):
        for bad in (rule('0.0.0.0/0', layer='installation'), rule('10.0.0.0/8', layer='installation', private=True),
                    rule('10.1.0.0/16', layer='installation'), rule('169.254.169.254/32', connection_id='c', private=True),
                    rule('203.0.113.1/32'), rule('203.0.113.1/32', layer='installation', connection_id='c'),
                    rule('203.0.113.1/32', connection_id='c', temporary=True), rule('203.0.113.1/24', connection_id='c')):
            self.assertEqual(code_of(lambda: SourcePolicy(1, [bad])), 'invalid_source_rule', bad)
        SourcePolicy(1, [rule('10.1.0.0/16', layer='installation', private=True)])

    def test_preview_lockout_widening_and_rollback(self):
        old = self.policy(rule('203.0.113.10/32', connection_id='c1'), rule('198.51.100.20/32', connection_id='c2'))
        new = self.policy(rule('203.0.113.0/28', connection_id='c1'), rule('10.9.0.0/16', layer='installation',
                                                                            private=True), version=2)
        prev = preview_change(old, new, {'c1': ['203.0.113.10'], 'c2': ['198.51.100.20']})
        self.assertEqual(prev.locked_out, [('c2', '198.51.100.20')])
        self.assertIn('203.0.113.0/28', prev.newly_allowed)
        self.assertTrue(prev.widens and prev.adds_private and prev.needs_second_admin)
        narrow = self.policy(rule('203.0.113.10/32', connection_id='c1'), version=3)
        self.assertFalse(preview_change(old, narrow, {}).needs_second_admin)
        check_rollback(old, narrow)
        self.assertEqual(code_of(lambda: check_rollback(narrow, old)), 'invalid_request')

    def test_cache_fails_closed_and_store_integrity(self):
        t = [1000.0]
        state = {'p': self.policy(), 'fail': False}

        def loader():
            if state['fail']:
                raise OSError('db down')
            return state['p']
        cache = PolicyCache(loader, max_stale=60, refresh=0, clock=lambda: t[0])
        self.assertEqual(cache.get().version, 1)
        state['fail'] = True
        t[0] += 30
        self.assertEqual(cache.get().version, 1, 'last good copy within a minute')
        t[0] += 31
        self.assertEqual(code_of(cache.get), 'source_policy_unavailable')
        d = tempfile.mkdtemp()
        b = SqliteBackend(os.path.join(d, 's.db'))
        b.migrate()
        st = SqlSourcePolicyStore(b)
        self.assertEqual(code_of(st.get), 'source_policy_unavailable')
        st.put(self.policy(), expected_version=None)
        self.assertEqual(st.get().version, 1)
        self.assertEqual(code_of(lambda: st.put(self.policy(version=2), expected_version=5)), 'conflict')
        with b.tx() as cur:
            cur.execute("UPDATE connect_source_policy SET document = replace(document, '203.0.113.0/24', '203.0.0.0/16')")
        self.assertEqual(code_of(st.get), 'source_policy_unavailable', 'tampered policy refused')


class Lifecycle(unittest.TestCase):
    def test_active_only_from_testing_with_a_passing_test(self):
        self.assertEqual(code_of(lambda: lc.transition('awaiting_network', 'active', test_passed=True)),
                         'invalid_transition')
        self.assertEqual(code_of(lambda: lc.transition('testing', 'active')), 'invalid_transition')
        self.assertEqual(code_of(lambda: lc.transition('testing', 'active', test_passed=True, kill_switch=True)),
                         'kill_switch')
        self.assertEqual(lc.transition('testing', 'active', test_passed=True), 'active')
        self.assertEqual(code_of(lambda: lc.transition('security_blocked', 'active', test_passed=True)),
                         'invalid_transition')
        self.assertEqual(code_of(lambda: lc.transition('suspended', 'testing', kill_switch=True)), 'kill_switch')
        self.assertEqual(code_of(lambda: lc.transition('revoked', 'testing')), 'invalid_transition')

    def test_failure_classes(self):
        for c in ('destination_changed', 'spki_mismatch', 'certificate_name_mismatch', 'invalid_signature'):
            self.assertEqual(lc.classify_failure(c), lc.SECURITY, c)
        self.assertEqual(lc.classify_failure('transport_error'), lc.AVAILABILITY)
        self.assertEqual(lc.classify_failure(http_status=503), lc.AVAILABILITY)
        self.assertEqual(lc.classify_failure(http_status=404), lc.PERMANENT)
        self.assertEqual(lc.classify_failure('destination_policy_unavailable'), lc.LOCAL)

    def test_ladder_circuit_and_security_block(self):
        pol, c = lc.ReconnectPolicy(), lc.Circuit()
        now = 1000.0
        delays = []
        for _ in range(9):
            pol.on_failure(c, now, 'transport_error')
            delays.append(c.next_attempt_at - now)
        self.assertEqual(c.state, lc.OPEN)
        for d, base in zip(delays, list(lc.LADDER) + [900, 900]):
            self.assertTrue(base * 0.8 <= d <= base * 1.2, (d, base))
        self.assertFalse(pol.may_call(c, now), 'open circuit short-circuits calls')
        self.assertTrue(pol.may_call(c, c.next_attempt_at, probe=True))
        self.assertEqual(c.state, lc.HALF_OPEN)
        pol.on_success(c)
        self.assertEqual((c.state, c.step), (lc.CLOSED, -1))
        self.assertFalse(pol.may_call(c, now, connection_state='suspended'))
        self.assertFalse(pol.may_call(c, now, kill_switch=True))
        pol.on_failure(c, now, 'spki_mismatch')
        self.assertTrue(c.blocked)
        pol.on_success(c)
        self.assertTrue(c.blocked and not pol.may_call(c, 10 ** 12, probe=True), 'security failures never reconnect')

    def test_health_hysteresis(self):
        h = lc.Health()
        h.record(0, ok=True)
        h.record(10, ok=False)
        self.assertEqual(h.status, 'connected')
        h.record(20, ok=False)
        self.assertEqual(h.status, 'degraded')
        for t in (30, 40, 50):
            h.record(t, ok=False, transport=True)
        self.assertEqual(h.status, 'offline')
        h.record(60, ok=True)
        self.assertEqual(h.status, 'offline', 'one pass is not enough')
        h.record(70, ok=True)
        self.assertEqual(h.status, 'connected')


def _claim_worker(args):
    path, worker = args
    q = SqlEventQueue(SqliteBackend(path))
    got = []
    for _ in range(20):
        rows = q.claim('c1', worker, limit=3)
        for r in rows:
            got.append(r['event_id'])
            q.mark_delivered(r['event_id'], worker)
    return got


class EventQueue(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, 'q.db')
        self.t = [1_800_000_000.0]
        b = SqliteBackend(self.path)
        b.migrate()
        self.q = SqlEventQueue(b, clock=lambda: self.t[0])

    def put(self, n, conn='c1'):
        ids = []
        for i in range(n):
            eid = f'{conn}-ev-{i:03d}'
            self.q.enqueue(event_id=eid, connection_id=conn, event_type='alert.raised', tenant='org-1', body=b'{}')
            ids.append(eid)
        return ids

    def test_order_unreached_failures_and_dead_letter(self):
        ids = self.put(3)
        rows = self.q.claim('c1', 'w1')
        self.assertEqual([r['event_id'] for r in rows], ids)
        self.assertEqual(self.q.claim('c1', 'w2'), [], 'leased rows are not handed out twice')
        self.assertEqual(self.q.record_failure(ids[0], 'w1', reached=False, retry_at=self.t[0]), 'pending')
        self.assertEqual(self.q.record_failure(ids[1], 'w1', reached=True, http_status=403), 'dead')
        self.assertTrue(self.q.mark_delivered(ids[2], 'w1'))
        again = self.q.claim('c1', 'w1')
        self.assertEqual([r['event_id'] for r in again], [ids[0]])
        self.assertEqual(again[0]['attempts'], 0, 'unreachable peer spends no attempts')
        self.assertTrue(self.q.requeue(ids[1]))
        self.assertIn(ids[1], [r['event_id'] for r in self.q.claim('c1', 'w3')], 'requeued with the original id')

    def test_age_limit_and_cancel(self):
        self.put(2)
        self.t[0] += 8 * 86400
        self.assertEqual(self.q.claim('c1', 'w1'), [])
        self.assertEqual(self.q.counts('c1'), {'dead': 2})
        self.put(1, conn='c2')
        self.assertEqual(self.q.cancel_connection('c2'), 1)
        self.assertEqual(self.q.counts('c2'), {'cancelled': 1}, 'cancelled, not deleted')

    def test_lease_expiry_redelivers(self):
        ids = self.put(1)
        self.q.claim('c1', 'crashed')
        self.t[0] += 61
        self.assertEqual([r['event_id'] for r in self.q.claim('c1', 'w2')], ids)

    def test_workers_never_deliver_the_same_row(self):
        import time
        self.t[0] = time.time() - 1          # the workers use the real clock
        self.put(30)
        ctx = multiprocessing.get_context('spawn')
        with ctx.Pool(3) as pool:
            results = pool.map(_claim_worker, [(self.path, f'w{i}') for i in range(3)])
        flat = [e for r in results for e in r]
        self.assertEqual(len(flat), 30)
        self.assertEqual(len(set(flat)), 30)


class AuditAnchors(unittest.TestCase):
    def setUp(self):
        d = tempfile.mkdtemp()
        self.b = SqliteBackend(os.path.join(d, 'a.db'))
        self.b.migrate()
        self.log = SqlAuditLog(self.b)
        self.key = keys.generate_private_key()

    def test_redaction(self):
        r = audit.redact({'op': 'token.issued', 'access_token': 'aaa.bbb.ccc', 'connection_id': 'c1',
                          'detail': {'code': '12345-67890', 'note': 'word ' * 100,
                                     'blob': 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlc2lnbmF0dXJl'},
                          'key_thumbprint': 'A' * 43})
        self.assertTrue(r['access_token'].startswith('redacted:'))
        self.assertTrue(r['detail']['code'].startswith('redacted:'))
        self.assertTrue(r['detail']['blob'].startswith('redacted:'))
        self.assertEqual(len(r['detail']['note']), audit.MAX_AUDIT_STRING)
        self.assertEqual(r['key_thumbprint'], 'A' * 43, 'identifiers kept')
        self.assertEqual(r['connection_id'], 'c1')

    def test_checkpoint_export_and_rewrite_detection(self):
        for i in range(5):
            self.log.append({'op': 'event', 'n': i})
        head = self.log.head()
        cp = audit.sign_checkpoint(self.key, issuer='inst-1', seq=head['seq'], head_hash=head['hash'])
        self.log.save_checkpoint(head['seq'], head['hash'], cp)
        bundle = audit.export_bundle(self.log.entries(), cp, issuer='inst-1')
        pub = self.key.public_key()
        self.assertEqual(audit.verify_export(bundle, pub, issuer='inst-1')['count'], 5)
        # A database writer rewrites history and re-signs with a stolen audit key: published checkpoints catch it.
        published = [{'seq': 3, 'hash': self.log.entries()[2]['hash']}]
        forged = json.loads(json.dumps(bundle))
        forged['entries'][1]['record']['n'] = 99
        prev = audit.GENESIS
        for e in forged['entries']:
            e['prev_hash'] = prev
            e['hash'] = prev = audit.entry_hash(prev, e['record'])
        forged['checkpoint'] = audit.sign_checkpoint(self.key, issuer='inst-1', seq=5, head_hash=prev)
        audit.verify_export(forged, pub, issuer='inst-1')          # self-consistent without an anchor ...
        self.assertEqual(code_of(lambda: audit.verify_export(forged, pub, issuer='inst-1',
                                                              known_checkpoints=published)), 'audit_invalid')
        tampered = json.loads(json.dumps(bundle))
        tampered['entries'][2]['record']['n'] = 7
        self.assertEqual(code_of(lambda: audit.verify_export(tampered, pub, issuer='inst-1')), 'audit_invalid')
        other = keys.generate_private_key().public_key()
        self.assertEqual(code_of(lambda: audit.verify_export(bundle, other, issuer='inst-1')), 'audit_invalid')
        short = json.loads(json.dumps(bundle))
        short['entries'] = short['entries'][:-1]
        self.assertEqual(code_of(lambda: audit.verify_export(short, pub, issuer='inst-1')), 'audit_invalid',
                         'truncated export refused')

    def test_records_are_redacted_on_append(self):
        e = self.log.append({'op': 'pairing', 'pairing_code': '12345-67890'})
        self.assertTrue(e['record']['pairing_code'].startswith('redacted:'))


class NonceAndActor(unittest.TestCase):
    def test_nonce_issuer(self):
        t = [1_800_000_000.0]
        n = ext.NonceIssuer(b'k' * 32, clock=lambda: t[0])
        a = n.issue('token:c1')
        self.assertTrue(n.valid(a, 'token:c1'))
        self.assertFalse(n.valid(a, 'token:c2'), 'bound to its context')
        t[0] += 300
        self.assertTrue(n.valid(a, 'token:c1'), 'previous window accepted')
        t[0] += 300
        self.assertFalse(n.valid(a, 'token:c1'))
        with self.assertRaises(ConnectError) as e:
            n.check(a, 'token:c1')
        self.assertEqual(e.exception.code, 'use_dpop_nonce')
        self.assertTrue(n.valid(e.exception.dpop_nonce, 'token:c1'))
        for bad in (None, '', 'x' * 40, a[:-1] + ('A' if a[-1] != 'A' else 'B')):
            self.assertFalse(n.valid(bad, 'token:c1'))

    def test_actor_validation(self):
        self.assertEqual(ext.validate_actor('user:42'), 'user:42')
        for bad in ('', 'alice@example.test', 'a b', 'x' * 129, None):
            self.assertEqual(code_of(lambda: ext.validate_actor(bad)), 'invalid_actor')
        self.assertIsNone(ext.actor_of({}, {}))
        self.assertEqual(code_of(lambda: ext.actor_of({'act': {'sub': 'u1'}}, {})), 'invalid_token')
        self.assertEqual(code_of(lambda: ext.actor_of({'act': {'sub': 'u1', 'act': {'sub': 'u2'}}}, {'actor': 1})),
                         'invalid_token')

    def pair(self, a_ext, b_ext):
        clock, net = Clock(), Network()
        a = ReferencePeer('https://msp-a.example.test', net, clock=clock, extensions=a_ext)
        b = ReferencePeer('https://rmm-b.example.test', net, clock=clock, extensions=b_ext)
        code = b.create_invitation()
        conn = a.start_pairing(b.base, code, requested_scopes=['connection:read'])
        b.approve(conn.request_id, scopes=['connection:read'], tenant_grants=[])
        a.poll(conn.id)
        a.accept(conn.id)
        return a, b, conn, net

    def test_negotiated_nonce_and_actor_end_to_end(self):
        a, b, conn, net = self.pair(ext.HARDENING_EXTENSIONS, ext.HARDENING_EXTENSIONS)
        bconn = b.connections[b.requests[conn.request_id]]
        self.assertEqual(conn.negotiated, {'action-approval': 1, 'actor': 1, 'dpop-nonce': 1})
        self.assertEqual(bconn.negotiated, conn.negotiated)
        tok = a.get_token(conn.id, actor='user:42')          # first try answered use_dpop_nonce, retried
        self.assertTrue(conn.dpop_nonce)
        from agit8or_connect.jws import unverified_payload
        self.assertEqual(unverified_payload(tok['access_token'])['act'], {'sub': 'user:42'})
        r = a.call(conn.id, 'GET', b.url(f'{API}/test'), token=tok['access_token'])
        self.assertEqual(r.status, 200)
        # A proof without a nonce is refused with a fresh nonce in the header
        from agit8or_connect import tokens
        _, key = conn.active_key()
        url = b.url(f'{API}/test')
        h = {'Authorization': f'DPoP {tok["access_token"]}',
             'DPoP': tokens.build_dpop_proof(key, 'GET', url, now=a.now(), access_token=tok['access_token'])}
        r = net.request('GET', url, h)
        self.assertEqual(r.status, 401)
        self.assertIn('use_dpop_nonce', r.header('WWW-Authenticate'))
        self.assertTrue(r.header('DPoP-Nonce'))

    def test_old_peers_are_unaffected(self):
        a, b, conn, net = self.pair(ext.HARDENING_EXTENSIONS, None)
        self.assertEqual(conn.negotiated, {})
        self.assertNotIn('extensions', b.document())
        tok = a.get_token(conn.id)
        self.assertEqual(conn.dpop_nonce, '')
        self.assertEqual(a.call(conn.id, 'GET', b.url(f'{API}/test'), token=tok['access_token']).status, 200)
        with self.assertRaises(ConnectError):
            a.get_token(conn.id, actor='user:42')             # not negotiated: refused, never silently dropped


if __name__ == '__main__':
    unittest.main()


class P1Vectors(unittest.TestCase):
    def test_extension_vectors(self):
        from agit8or_connect import tokens
        from agit8or_connect.replay import MemoryReplayStore
        from agit8or_connect.tests.test_vectors import load
        v = load('extensions.json')
        n = v['dpop_nonce']
        iss = ext.NonceIssuer(bytes.fromhex(n['secret_hex']), clock=lambda: n['now'])
        self.assertEqual(iss.issue(n['context']), n['nonce'])
        self.assertFalse(iss.valid(n['nonce'], n['wrong_context']))
        late = ext.NonceIssuer(bytes.fromhex(n['secret_hex']), clock=lambda: n['valid_until_exclusive'])
        self.assertFalse(late.valid(n['nonce'], n['context']))
        jkt, claims = tokens.verify_dpop_proof(n['proof'], method=n['proof_method'], url=n['proof_url'],
                                               replay=MemoryReplayStore(), now=n['now'],
                                               nonce_check=lambda x: iss.check(x, n['context']))
        self.assertEqual(claims['nonce'], n['nonce'])
        self.assertEqual(jkt, v['keys']['A']['thumbprint'])
        b = keys.private_key_from_seed(bytes.fromhex(v['keys']['B']['seed_hex']))
        c = tokens.verify_access_token(v['actor']['access_token'], {keys.thumbprint(b): b.public_key()},
                                       issuer=v['actor']['issuer'], now=v['actor']['now'])
        self.assertEqual(ext.actor_of(c, {'actor': 1}), v['actor']['actor'])
        for bad in v['actor']['invalid_actors']:
            self.assertEqual(code_of(lambda: ext.validate_actor(bad)), 'invalid_actor')

    def test_checkpoint_vectors(self):
        from agit8or_connect.tests.test_vectors import load
        v = load('audit-checkpoint.json')
        pub = keys.public_key_from_jwk(v['key']['public_jwk'])
        self.assertEqual(audit.verify_export(v['export'], pub, issuer='inst-audit'), dict(v['head'], count=3))
        for neg in v['negative']:
            b = dict(v['export'], entries=neg.get('entries', v['export']['entries']))
            self.assertEqual(code_of(lambda: audit.verify_export(b, pub, issuer='inst-audit',
                                                                  known_checkpoints=neg.get('known_checkpoints', ()))),
                             neg['error'], neg['case'])
