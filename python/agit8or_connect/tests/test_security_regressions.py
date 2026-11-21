"""Regression tests for the findings in docs/SECURITY_AND_READINESS_AUDIT.md (reference peer and SDK), plus
elevated-grant approval, per-action approval, kill switch and private-key protection."""
import json
import os
import stat
import tempfile
import unittest

from agit8or_connect import keys, tokens
from agit8or_connect.approvals import (ActionApprovals, AdminAuth, ElevatedGrantPolicy, MemoryActionApprovalStore,
                                       MemoryGrantApprovalStore, classify_scopes, grant_fingerprint)
from agit8or_connect.errors import ConnectError
from agit8or_connect.keystore import (EnvMasterKeys, FileMasterKeys, PrivateKeyCipher, StaticMasterKeys,
                                      generate_master_key, redacted_key_repr, row_aad, secret_tempfile)
from agit8or_connect.reference_peer import API, REFERENCE_CATALOG, Network, ReferencePeer
from agit8or_connect.tests.test_reference_peer import Clock
from agit8or_connect.tests.test_vectors import load

ELEVATED = ['connection:read', 'remote_actions:execute']


def pair(requested=('connection:read', 'customers:read', 'remote_actions:execute'), clock=None):
    clock = clock or Clock()
    net = Network()
    a = ReferencePeer('https://msp-a.example.test', net, clock=clock, tenants={'org-1': 'A customer'})
    b = ReferencePeer('https://rmm-b.example.test', net, clock=clock)
    code = b.create_invitation()
    conn = a.start_pairing(b.base, code, requested_scopes=list(requested), proposed_tenants=[{'id': 'org-1'}])
    return a, b, conn, net, clock


class ElevatedScopes(unittest.TestCase):
    """F-01 / F-02."""

    def test_single_administrator_cannot_activate_elevated_scopes(self):
        a, b, conn, net, clock = pair()
        bconn = b.approve(conn.request_id, scopes=ELEVATED, tenant_grants=[
            {'remote_tenant': 'org-1', 'local_tenant': 'cust-1', 'scopes': ELEVATED}],
            admin=AdminAuth('alice', clock()))
        self.assertEqual(bconn.state, 'awaiting_second_approval')
        self.assertEqual(a.poll(conn.id), 'pending', 'the peer sees pending until the second approval')
        with self.assertRaises(ConnectError) as e:
            b.second_approve(conn.request_id, admin=AdminAuth('alice', clock()))
        self.assertEqual(e.exception.code, 'second_admin_required')
        with self.assertRaises(ConnectError) as e:
            b.second_approve(conn.request_id, admin=AdminAuth('bob', clock() - 3600))
        self.assertEqual(e.exception.code, 'reauthentication_required')
        b.second_approve(conn.request_id, admin=AdminAuth('bob', clock()))
        self.assertEqual(bconn.state, 'active')
        self.assertEqual(a.poll(conn.id), 'approved')
        a.accept(conn.id)
        self.assertIn('remote_actions:execute', a.get_token(conn.id)['scope'].split())

    def test_changed_request_invalidates_the_proposal(self):
        a, b, conn, net, clock = pair()
        b.approve(conn.request_id, scopes=ELEVATED, tenant_grants=[], admin=AdminAuth('alice', clock()))
        bconn = b.connections[b.requests[conn.request_id]]
        bconn.pending['tenant_grants'] = [{'remote_tenant': 'org-1', 'local_tenant': 'cust-2', 'scopes': ELEVATED}]
        with self.assertRaises(ConnectError) as e:
            b.second_approve(conn.request_id, admin=AdminAuth('bob', clock()))
        self.assertEqual(e.exception.code, 'approval_mismatch')
        self.assertNotEqual(bconn.state, 'active')

    def test_unknown_and_unavailable_scopes_never_granted(self):
        a, b, conn, net, clock = pair(requested=('connection:read', 'bogus:scope'))
        with self.assertRaises(ConnectError) as e:
            b.approve(conn.request_id, scopes=['connection:read', 'bogus:scope'], tenant_grants=[])
        self.assertEqual(e.exception.code, 'invalid_scope')
        from agit8or_connect.scopes import Catalog, Scope
        cat = Catalog([Scope('x:read', 'r', 'read', available=False)])
        with self.assertRaises(ConnectError):
            classify_scopes(cat, ['x:read'])

    def test_disabled_policy_keeps_elevated_scopes_unavailable(self):
        pol = ElevatedGrantPolicy.disabled(REFERENCE_CATALOG)
        with self.assertRaises(ConnectError):
            pol.classify(['remote_actions:execute'])
        self.assertFalse(pol.is_authorized('c', 'f', ['remote_actions:execute']))
        self.assertEqual(pol.authorized_scopes('c', 'f', ['connection:read', 'connection:admin']),
                         ['connection:read'])

    def test_revoking_elevated_grant_is_immediate(self):
        a, b, conn, net, clock = self._active_elevated()
        tok = a.get_token(conn.id)['access_token']
        bconn = b.connections[b.requests[conn.request_id]]
        b.revoke_elevated(bconn.id)
        r = a.call(conn.id, 'POST', b.url(f'{API}/remote-actions'), tenant='org-1', token=tok,
                   body=json.dumps({'target': 'dev-1', 'action': 'reboot'}).encode())
        self.assertEqual(r.status, 401)          # token predates the revocation
        with self.assertRaises(ConnectError):
            a.get_token(conn.id, ['remote_actions:execute'])

    def test_token_scope_cannot_exceed_live_approval(self):
        a, b, conn, net, clock = self._active_elevated()
        bconn = b.connections[b.requests[conn.request_id]]
        b.elevated.revoke(bconn.id)              # approval withdrawn in the store only
        with self.assertRaises(ConnectError) as e:
            a.get_token(conn.id, ['remote_actions:execute'])
        self.assertEqual(e.exception.code, 'invalid_scope')
        self.assertNotIn('remote_actions:execute', a.get_token(conn.id)['scope'].split())

    def _active_elevated(self):
        a, b, conn, net, clock = pair()
        b.approve(conn.request_id, scopes=ELEVATED, tenant_grants=[
            {'remote_tenant': 'org-1', 'local_tenant': 'cust-1', 'scopes': ELEVATED}],
            admin=AdminAuth('alice', clock()))
        b.second_approve(conn.request_id, admin=AdminAuth('bob', clock()))
        a.poll(conn.id)
        a.accept(conn.id)
        return a, b, conn, net, clock

    def test_fingerprint_covers_scopes_tenants_and_keys(self):
        base = dict(connection_id='c', remote_installation='i', remote_key_thumbprints=['k1'],
                    inbound_scopes=['a:read'], tenant_grants=[{'remote_tenant': 'r', 'local_tenant': 'l',
                                                               'scopes': ['a:read']}])
        fp = grant_fingerprint(**base)
        for change in ({'remote_key_thumbprints': ['k2']}, {'inbound_scopes': ['a:read', 'a:run']},
                       {'tenant_grants': [{'remote_tenant': 'r', 'local_tenant': 'l2', 'scopes': ['a:read']}]},
                       {'remote_installation': 'j'}):
            self.assertNotEqual(grant_fingerprint(**dict(base, **change)), fp, change)


class PerActionApproval(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.conn, self.net, self.clock = ElevatedScopes()._active_elevated()
        self.url = self.b.url(f'{API}/remote-actions')

    def call(self, body, approval=None):
        h_extra = {}
        tok = self.a.get_token(self.conn.id)['access_token']
        _, key = self.conn.active_key()
        h = {'Authorization': f'DPoP {tok}', 'Agit8or-Tenant': 'org-1',
             'DPoP': tokens.build_dpop_proof(key, 'POST', self.url, now=self.clock(), access_token=tok)}
        if approval:
            h['Agit8or-Action-Approval'] = approval
        h.update(h_extra)
        return self.net.request('POST', self.url, h, json.dumps(body).encode())

    def test_action_needs_its_own_approval_single_use_and_unchanged(self):
        body = {'target': 'dev-1', 'action': 'reboot', 'params': {'force': False}}
        r = self.call(body)
        self.assertEqual(r.status, 403)
        err = json.loads(r.body)['error']
        self.assertEqual(err['code'], 'action_approval_required')
        aid = err['approval_id']
        self.assertEqual(self.call(body, aid).status, 403, 'pending is not approved')
        with self.assertRaises(ConnectError):
            self.b.decide_action(aid, approve=True, admin=AdminAuth('bob', self.clock() - 9999))
        self.b.decide_action(aid, approve=True, admin=AdminAuth('bob', self.clock()))
        tampered = dict(body, params={'force': True})
        self.assertEqual(self.call(tampered, aid).status, 403, 'parameters changed after approval')
        self.assertEqual(self.call(dict(body, target='dev-2'), aid).status, 403, 'target changed')
        self.assertEqual(self.call(body, aid).status, 200)
        self.assertEqual(self.call(body, aid).status, 403, 'single use')

    def test_operator_cannot_approve_own_action(self):
        acts = ActionApprovals(MemoryActionApprovalStore())
        req = acts.request(connection_id='c', tenant='t', target='x', action_type='script', params={},
                           operator='alice', required_scope='remote_actions:execute')
        with self.assertRaises(ConnectError) as e:
            acts.decide(req.id, approve=True, admin=AdminAuth('alice', int(__import__('time').time())))
        self.assertEqual(e.exception.code, 'second_admin_required')

    def test_denied_and_expired(self):
        clock = [1_800_000_000]
        acts = ActionApprovals(MemoryActionApprovalStore(), ttl=60, clock=lambda: clock[0])
        req = acts.request(connection_id='c', tenant='t', target='x', action_type='script', params={'a': 1},
                           operator='op', required_scope='s')
        acts.decide(req.id, approve=False, admin=AdminAuth('adm', clock[0]))
        with self.assertRaises(ConnectError):
            acts.consume(req.id, connection_id='c', tenant='t', target='x', action_type='script', params={'a': 1})
        req2 = acts.request(connection_id='c', tenant='t', target='x', action_type='script', params={'a': 1},
                            operator='op', required_scope='s')
        acts.decide(req2.id, approve=True, admin=AdminAuth('adm', clock[0]))
        clock[0] += 61
        with self.assertRaises(ConnectError):
            acts.consume(req2.id, connection_id='c', tenant='t', target='x', action_type='script', params={'a': 1})


class KillSwitch(unittest.TestCase):
    def test_kill_switch_blocks_api_and_approvals_and_resumes_nothing(self):
        a, b, conn, net, clock = pair(requested=('connection:read',))
        b.set_kill_switch(True)
        with self.assertRaises(ConnectError) as e:
            b.approve(conn.request_id, scopes=['connection:read'], tenant_grants=[])
        self.assertEqual(e.exception.code, 'kill_switch')
        r = net.request('POST', b.url(f'{API}/token'), {}, b'')
        self.assertEqual(r.status, 503)
        self.assertEqual(net.request('GET', b.url('/.well-known/agit8or-connect')).status, 200)
        b.set_kill_switch(False)
        b.approve(conn.request_id, scopes=['connection:read'], tenant_grants=[])
        a.poll(conn.id)
        a.accept(conn.id)
        bconn = b.connections[b.requests[conn.request_id]]
        b.set_kill_switch(True)
        self.assertEqual(bconn.state, 'suspended')
        b.set_kill_switch(False)
        self.assertEqual(bconn.state, 'suspended', 'releasing the kill switch resumes nothing')


class ReferencePeerFindings(unittest.TestCase):
    def test_f05_retired_key_refused_after_overlap(self):
        a, b, conn, net, clock = pair(requested=('connection:read',))
        b.approve(conn.request_id, scopes=['connection:read'], tenant_grants=[])
        a.poll(conn.id)
        a.accept(conn.id)
        old_kid, old_key = conn.active_key()
        self.assertTrue(a.rotate(conn.id, overlap=10))
        self.assertEqual(a.get_token(conn.id, key=old_key)['token_type'], 'DPoP', 'retiring key valid in overlap')
        clock.t += 7200                         # overlap over; endorsement of B's cached ring expired too
        a.retire_due(conn.id)
        self.assertIsNone(conn.keys[old_kid]['private'], 'retired private half wiped')
        with self.assertRaises(ConnectError) as e:
            a.get_token(conn.id, key=old_key)
        self.assertEqual(e.exception.code, 'invalid_client')
        self.assertEqual(a.get_token(conn.id)['token_type'], 'DPoP')

    def test_f06_no_fetch_before_administrator_acts(self):
        a, b, conn, net, clock = pair(requested=('connection:read',))
        fetched = [u for _, u in net.log if 'msp-a.example.test/.well-known' in u]
        self.assertEqual(fetched, [])
        b.approve(conn.request_id, scopes=['connection:read'], tenant_grants=[])
        fetched = [u for _, u in net.log if 'msp-a.example.test/.well-known' in u]
        self.assertEqual(len(fetched), 1)

    def test_f12_wrong_codes_leave_no_replay_rows(self):
        net, clock = Network(), Clock()
        b = ReferencePeer('https://rmm.example.test', net, clock=clock)
        a = ReferencePeer('https://msp.example.test', net, clock=clock)
        b.create_invitation()
        before = len(b.replay._seen)
        for _ in range(3):
            with self.assertRaises(ConnectError):
                a.start_pairing(b.base, '00000-00000', requested_scopes=['connection:read'])
        self.assertEqual(len(b.replay._seen), before)

    def test_f07_pairing_rate_limited_per_source(self):
        net, clock = Network(), Clock()
        net.default_source = '198.51.100.20'
        b = ReferencePeer('https://rmm.example.test', net, clock=clock)
        a = ReferencePeer('https://msp.example.test', net, clock=clock)
        codes = []
        for _ in range(12):
            b.create_invitation()
            try:
                a.start_pairing(b.base, '00000-00000', requested_scopes=['connection:read'])
            except ConnectError as e:
                codes.append(e.code)
        self.assertIn('rate_limited', codes)

    def test_f15_refused_event_does_not_consume_its_id(self):
        a, b, conn, net, clock = pair(requested=('connection:read', 'events:publish'))
        bconn = b.approve(conn.request_id, scopes=['connection:read', 'events:publish'], tenant_grants=[])
        a.poll(conn.id)
        a.accept(conn.id)
        eid = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        r = a.send_event(conn.id, 'alert.raised', 'org-1', {}, event_id=eid)
        self.assertEqual(r.status, 403)          # tenant not granted yet
        from agit8or_connect.tenants import TenantGrant
        b.grants.add(TenantGrant(bconn.id, 'org-1', 'cust-1', ('events:publish',)))
        r = a.send_event(conn.id, 'alert.raised', 'org-1', {}, event_id=eid)
        self.assertEqual(json.loads(r.body)['status'], 'accepted')
        r = a.send_event(conn.id, 'secret.exfiltrated', 'org-1', {})
        self.assertEqual(json.loads(r.body)['error']['code'], 'event_type_not_allowed')

    def test_f20_unknown_and_inactive_clients_look_the_same(self):
        a, b, conn, net, clock = pair(requested=('connection:read',))
        r1 = net.request('POST', b.url(f'{API}/token'), {}, b'grant_type=client_credentials&client_id=nope&'
                         b'client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer')
        bconn_id = b.requests[conn.request_id]
        r2 = net.request('POST', b.url(f'{API}/token'), {}, ('grant_type=client_credentials&client_id=' + bconn_id +
                         '&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer')
                         .encode())
        self.assertEqual(json.loads(r1.body), json.loads(r2.body))

    def test_f18_mapped_source_matches_ipv4_declaration(self):
        from agit8or_connect import quick_connect as qc
        self.assertTrue(qc.source_in_egress('::ffff:203.0.113.10', [{'net': '203.0.113.10/32'}]))
        self.assertFalse(qc.source_in_egress('::ffff:203.0.113.11', [{'net': '203.0.113.10/32'}]))

    def test_f21_health_and_www_authenticate(self):
        a, b, conn, net, clock = pair(requested=('connection:read',))
        h = json.loads(net.request('GET', b.url(f'{API}/health')).body)
        self.assertEqual(h['installation_id'], b.installation_id)
        r = net.request('POST', b.url(f'{API}/test'), {'Authorization': 'DPoP x.y.z', 'DPoP': 'a.b.c'})
        self.assertEqual(r.status, 401)
        self.assertTrue(r.header('WWW-Authenticate').startswith('DPoP error='))


class KeyProtection(unittest.TestCase):
    def setUp(self):
        self.mk = StaticMasterKeys({'mk1': os.urandom(32)}, 'mk1')
        self.cipher = PrivateKeyCipher(self.mk)
        self.key = keys.generate_private_key()
        self.aad = row_aad('connect_key', 'private_key', 'row-1')

    def test_roundtrip_and_row_binding(self):
        blob = self.cipher.encrypt(self.key, self.aad)
        self.assertEqual(keys.thumbprint(self.cipher.decrypt(blob, self.aad)), keys.thumbprint(self.key))
        for other in (row_aad('connect_key', 'private_key', 'row-2'), row_aad('other', 'private_key', 'row-1')):
            with self.assertRaises(ConnectError) as e:
                self.cipher.decrypt(blob, other)
            self.assertEqual(e.exception.code, 'key_corrupt')

    def test_rotation_and_unavailable_key(self):
        blob = self.cipher.encrypt(self.key, self.aad)
        rotated = StaticMasterKeys({'mk1': self.mk.get('mk1'), 'mk2': os.urandom(32)}, 'mk2')
        c2 = PrivateKeyCipher(rotated)
        self.assertTrue(c2.needs_rewrap(blob))
        new = c2.rewrap(blob, self.aad)
        self.assertFalse(c2.needs_rewrap(new))
        only_new = PrivateKeyCipher(StaticMasterKeys({'mk2': rotated.get('mk2')}, 'mk2'))
        self.assertEqual(keys.thumbprint(only_new.decrypt(new, self.aad)), keys.thumbprint(self.key))
        with self.assertRaises(ConnectError) as e:
            only_new.decrypt(blob, self.aad)
        self.assertEqual(e.exception.code, 'key_unavailable')

    def test_errors_and_logs_carry_no_key_material(self):
        blob = self.cipher.encrypt(self.key, self.aad)
        try:
            self.cipher.decrypt(blob, b'x')
        except ConnectError as e:
            self.assertNotIn(blob.split('.')[3][:16], str(e))
        self.assertEqual(redacted_key_repr(blob), '<encrypted key, master key mk1>')

    def test_key_file_permissions(self):
        d = tempfile.mkdtemp()
        path = os.path.join(d, 'keys.json')
        with open(path, 'w') as f:
            json.dump({'current': 'k', 'keys': {'k': generate_master_key()}}, f)
        os.chmod(path, 0o640)    # any group or other bit is refused; group-read is enough to prove it
        with self.assertRaises(ConnectError) as e:
            FileMasterKeys(path)
        self.assertEqual(e.exception.code, 'key_unavailable')
        os.chmod(path, 0o600)
        self.assertEqual(FileMasterKeys(path).current()[0], 'k')
        os.remove(path)
        os.rmdir(d)

    def test_env_keys_and_missing(self):
        os.environ['A8C_TEST_KEYS'] = json.dumps({'current': 'e1', 'keys': {'e1': generate_master_key()}})
        try:
            self.assertEqual(EnvMasterKeys('A8C_TEST_KEYS').current()[0], 'e1')
        finally:
            del os.environ['A8C_TEST_KEYS']
        with self.assertRaises(ConnectError):
            EnvMasterKeys('A8C_TEST_KEYS')
        with self.assertRaises(ConnectError):
            StaticMasterKeys({'k': b'short'}, 'k')

    def test_secret_tempfile(self):
        with secret_tempfile(b'-----BEGIN PRIVATE KEY-----') as path:
            with open(path, 'rb') as f:
                self.assertTrue(f.read().startswith(b'-----BEGIN'))
            if not path.startswith('/proc/'):
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertFalse(os.path.exists(path) and not path.startswith('/proc/'))

    def test_vector(self):
        v = load('key-envelope.json')
        import base64
        dec = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))  # noqa: E731
        mks = StaticMasterKeys({k: dec(x) for k, x in v['master_keys'].items()}, 'test-mk-1')
        c = PrivateKeyCipher(mks)
        self.assertEqual(c.decrypt_bytes(v['envelope'], v['row_aad'].encode()).hex(), v['plaintext_seed_hex'])
        self.assertEqual(c.encrypt_bytes(bytes.fromhex(v['plaintext_seed_hex']), v['row_aad'].encode(),
                                         _nonce=dec(v['nonce_b64url'])), v['envelope'])
        for n in v['negative']:
            with self.assertRaises(ConnectError) as e:
                c.decrypt_bytes(n.get('envelope', v['envelope']), n['row_aad'].encode())
            self.assertEqual(e.exception.code, n['error'], n['case'])


if __name__ == '__main__':
    unittest.main()
