"""GuardedTransport over real TLS (local listener, test-only CA) and the approved-destination policy.

Evidence level: real TCP + TLS 1.2/1.3 handshakes, certificate chain and name verification, on 127.0.0.1;
DNS answers come from a test resolver and validated documentation addresses are mapped to the local
listener by a test dialer (tls_support.mapped_dialer). Nothing here uses the public network.
"""
import json
import os
import unittest
from dataclasses import replace

from agit8or_connect import addresses
from agit8or_connect.destinations import (ApprovedAddress, MemoryDestinationStore, new_destination)
from agit8or_connect.errors import ConnectError
from agit8or_connect.transport import GuardedTransport, preview_destination
from agit8or_connect.tests.tls_support import TestPKI, TlsServer, mapped_dialer, resolver_for, spki_of

HOST = 'peer.example.test'
IP1, IP2, PRIV = '203.0.113.10', '203.0.113.20', '10.20.30.40'


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = TestPKI()
        cert, key = cls.pki.leaf((HOST,))
        cls.cert = cert
        cls.server = TlsServer(cls.pki.server_context(cert, key))
        other_cert, other_key = cls.pki.leaf(('someone-else.example.test',))
        cls.wrong_name = TlsServer(cls.pki.server_context(other_cert, other_key))
        foreign = TestPKI('Another TEST-ONLY CA')
        fc, fk = foreign.leaf((HOST,))
        cls.foreign = TlsServer(foreign.server_context(fc, fk))
        ec, ek = cls.pki.leaf((HOST,), days=-1, not_before_days=10)
        cls.expired = TlsServer(cls.pki.server_context(ec, ek))
        sc, sk = cls.pki.leaf((HOST,), days=5)
        cls.soon = TlsServer(cls.pki.server_context(sc, sk))
        ipc, ipk = cls.pki.leaf((), ips=('2001:db8::10',))
        cls.ipserver = TlsServer(cls.pki.server_context(ipc, ipk))

    @classmethod
    def tearDownClass(cls):
        for s in (cls.server, cls.wrong_name, cls.foreign, cls.expired, cls.soon, cls.ipserver):
            s.close()

    def setUp(self):
        self.store = MemoryDestinationStore()
        self.dns = {HOST: [IP1]}
        self.store.put(new_destination('c1', HOST, 443, [IP1], ca_pem=self.pki.ca_pem))

    def transport(self, port=None, **kw):
        port = port or self.server.port
        mapping = kw.pop('mapping', {IP1: port, IP2: port, PRIV: port})
        return GuardedTransport(self.store, 'c1', resolver=resolver_for(self.dns),
                                _dialer=mapped_dialer(mapping, kw.pop('report_peer', None)), **kw)

    def refused(self, code, fn, *a, **kw):
        with self.assertRaises(ConnectError) as e:
            fn(*a, **kw)
        self.assertEqual(e.exception.code, code, e.exception.message)
        return e.exception


class HappyPath(_Base):
    def test_request_over_verified_tls(self):
        r = self.transport().request('GET', f'https://{HOST}/ok')
        self.assertEqual(r.status, 200)
        self.assertEqual(json.loads(r.body)['host'], HOST)
        self.assertEqual(r.peer_address, IP1)
        self.assertEqual(r.certificate['spki_sha256'], spki_of(self.cert))
        self.assertIn(HOST, r.certificate['sans'])
        self.assertEqual(r.warnings, [])

    def test_post_body_and_request_limit(self):
        t = self.transport(max_request_bytes=10)
        self.assertEqual(json.loads(t.request('POST', f'https://{HOST}/e', {}, b'0123456789').body)['received'], 10)
        self.refused('too_large', t.request, 'POST', f'https://{HOST}/e', {}, b'01234567890')

    def test_spki_pin_match_and_mismatch(self):
        dest = self.store.get('c1')
        self.store.put(replace(dest, spki_pins=(spki_of(self.cert),), version=2))
        self.assertEqual(self.transport().request('GET', f'https://{HOST}/ok').status, 200)
        self.store.put(replace(dest, spki_pins=('A' * 43,), version=3))
        before = len(self.server.seen)
        self.refused('spki_mismatch', self.transport().request, 'GET', f'https://{HOST}/ok')
        self.assertEqual(len(self.server.seen), before, 'no request byte may be sent before the pin check')

    def test_expiry_warning(self):
        seen = []
        t = self.transport(self.soon.port, on_warning=lambda c, w: seen.append((c, w)))
        r = t.request('GET', f'https://{HOST}/ok')
        self.assertTrue(r.warnings and r.warnings[0].startswith('certificate_expiring'))
        self.assertEqual(seen[0][0], 'c1')

    def test_ip_literal_destination_with_ip_san(self):
        self.store.put(new_destination('c1', '[2001:db8::10]', 443, ['2001:db8::10/128'], ca_pem=self.pki.ca_pem),
                       expected_version=1)
        t = GuardedTransport(self.store, 'c1', _dialer=mapped_dialer({'2001:db8::10': self.ipserver.port}))
        self.assertEqual(t.request('GET', 'https://[2001:db8::10]/ok').status, 200)

    def test_proxy_environment_is_ignored(self):
        old = {k: os.environ.get(k) for k in ('HTTPS_PROXY', 'https_proxy', 'ALL_PROXY')}
        try:
            for k in old:
                os.environ[k] = 'http://192.0.2.99:9'
            self.assertEqual(self.transport().request('GET', f'https://{HOST}/ok').status, 200)
        finally:
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


class DestinationEnforcement(_Base):
    def test_dns_change_between_requests_is_refused_with_evidence(self):
        t = self.transport()
        self.assertEqual(t.request('GET', f'https://{HOST}/ok').status, 200)
        self.dns[HOST] = [IP2]          # the name now points somewhere else (public, valid certificate)
        e = self.refused('destination_changed', t.request, 'GET', f'https://{HOST}/ok')
        self.assertEqual(e.evidence['observed'], [IP2])
        self.assertEqual(e.evidence['approved'], [IP1 + '/32'])
        blocked = self.store.block('c1', e.evidence)
        self.assertEqual(blocked.state, 'security_blocked')
        self.dns[HOST] = [IP1]          # even back on the old address: blocked until reviewed
        self.refused('security_blocked', t.request, 'GET', f'https://{HOST}/ok')

    def test_mixed_answers_refuse_the_whole_request(self):
        self.dns[HOST] = [IP1, IP2]
        self.refused('destination_changed', self.transport().request, 'GET', f'https://{HOST}/ok')
        self.dns[HOST] = [IP1, PRIV]
        self.refused('destination_changed', self.transport().request, 'GET', f'https://{HOST}/ok')
        self.dns[HOST] = [IP1, '127.0.0.1']
        self.refused('blocked_destination', self.transport().request, 'GET', f'https://{HOST}/ok')

    def test_always_refused_classes(self):
        for ip in ('127.0.0.1', '169.254.169.254', '::1', 'fe80::1', '0.0.0.0', '224.0.0.1', '::ffff:127.0.0.1',
                   '64:ff9b::a9fe:a9fe', 'fec0::1', '2002:7f00:1::1'):
            self.dns[HOST] = [ip]
            self.refused('blocked_destination', self.transport().request, 'GET', f'https://{HOST}/ok')

    def test_private_address_only_when_approved_as_private(self):
        self.dns[HOST] = [PRIV]
        self.refused('destination_changed', self.transport().request, 'GET', f'https://{HOST}/ok')
        with self.assertRaises(ConnectError):           # cannot approve a private address implicitly
            new_destination('c1', HOST, 443, [PRIV], ca_pem=self.pki.ca_pem)
        self.store.put(new_destination('c1', HOST, 443, [ApprovedAddress(PRIV + '/32', private=True)],
                                       ca_pem=self.pki.ca_pem), expected_version=1)
        self.assertEqual(self.transport().request('GET', f'https://{HOST}/ok').status, 200)

    def test_host_port_and_url_must_match(self):
        t = self.transport()
        self.refused('blocked_destination', t.request, 'GET', 'https://other.example.test/ok')
        self.refused('blocked_destination', t.request, 'GET', f'https://{HOST}:8443/ok')
        self.refused('blocked_destination', t.request, 'GET', f'http://{HOST}/ok')
        self.refused('blocked_destination', t.request, 'GET', f'https://u:p@{HOST}/ok')
        self.refused('blocked_destination', t.request, 'GET', f'https://{HOST}/ok', {'Host': 'other.example.test'})

    def test_redirect_is_not_followed(self):
        t = self.transport()
        n = len(self.server.seen)
        r = t.request('GET', f'https://{HOST}/redirect')
        self.assertEqual(r.status, 302)
        self.assertEqual(len(self.server.seen), n + 1)
        self.refused('blocked_destination', t.request, 'GET', r.header('Location'))

    def test_connected_peer_must_be_the_validated_address(self):
        t = self.transport(report_peer=IP2)
        self.refused('blocked_destination', t.request, 'GET', f'https://{HOST}/ok')

    def test_migration_overlap_then_old_address_expires(self):
        clock = [1_800_000_000]
        store = MemoryDestinationStore(clock=lambda: clock[0])
        store.put(new_destination('c1', HOST, 443, [IP1], ca_pem=self.pki.ca_pem, now=clock[0]))
        cid = store.propose_change('c1', [ApprovedAddress(IP2 + '/32')], proposer='alice', overlap=3600)
        with self.assertRaises(ConnectError) as e:
            store.approve_change(cid, approver='alice')
        self.assertEqual(e.exception.code, 'second_admin_required')
        dest = store.approve_change(cid, approver='bob')
        self.assertEqual(dest.version, 2)
        t = GuardedTransport(store, 'c1', resolver=resolver_for(self.dns), clock=lambda: clock[0],
                             _dialer=mapped_dialer({IP1: self.server.port, IP2: self.server.port}))
        self.dns[HOST] = [IP1]
        self.assertEqual(t.request('GET', f'https://{HOST}/ok').status, 200)   # old address inside the overlap
        self.dns[HOST] = [IP2]
        self.assertEqual(t.request('GET', f'https://{HOST}/ok').status, 200)
        clock[0] += 3601
        self.dns[HOST] = [IP1]
        self.refused('destination_changed', t.request, 'GET', f'https://{HOST}/ok')

    def test_private_change_needs_two_other_administrators(self):
        cid = self.store.propose_change('c1', [ApprovedAddress(PRIV + '/32', private=True)], proposer='alice')
        self.assertEqual(self.store.approve_change(cid, approver='bob').version, 1)   # waits for a second one
        self.assertEqual(self.store.approve_change(cid, approver='carol').version, 2)

    def test_stale_change_is_void(self):
        cid = self.store.propose_change('c1', [ApprovedAddress(IP2 + '/32')], proposer='alice')
        self.store.block('c1', {'code': 'destination_changed'})
        self.refused('conflict', self.store.approve_change, cid, approver='bob')


class FailClosed(_Base):
    def test_missing_corrupt_and_inconsistent_policy(self):
        t = GuardedTransport(self.store, 'unknown', resolver=resolver_for(self.dns))
        self.refused('destination_policy_unavailable', t.request, 'GET', f'https://{HOST}/ok')
        rec, digest = self.store._rows['c1']
        tampered = dict(rec, addresses=[{'net': IP2 + '/32', 'private': False}])
        self.store._rows['c1'] = (tampered, digest)
        self.refused('destination_policy_unavailable', self.transport().request, 'GET', f'https://{HOST}/ok')
        bad = dict(rec, addresses=[{'net': '127.0.0.1/32', 'private': True}])
        from agit8or_connect.destinations import ApprovedDestination
        self.store._rows['c1'] = (bad, ApprovedDestination.from_dict(bad).digest())
        self.refused('destination_policy_unavailable', self.transport().request, 'GET', f'https://{HOST}/ok')

    def test_policy_backend_error(self):
        class Broken:
            def get(self, cid):
                raise OSError('disk gone')
        t = GuardedTransport(Broken(), 'c1', resolver=resolver_for(self.dns))
        self.refused('destination_policy_unavailable', t.request, 'GET', f'https://{HOST}/ok')

    def test_constructor_requires_a_policy(self):
        with self.assertRaises(ValueError):
            GuardedTransport(None, 'c1')


class TlsFailures(_Base):
    def test_wrong_name(self):
        self.refused('certificate_name_mismatch', self.transport(self.wrong_name.port).request, 'GET',
                     f'https://{HOST}/ok')

    def test_untrusted_ca(self):
        self.refused('certificate_invalid', self.transport(self.foreign.port).request, 'GET', f'https://{HOST}/ok')

    def test_expired(self):
        self.refused('certificate_invalid', self.transport(self.expired.port).request, 'GET', f'https://{HOST}/ok')

    def test_private_ca_replaces_system_store(self):
        # Without the private CA the system store does not know the test CA.
        dest = self.store.get('c1')
        self.store.put(replace(dest, ca_pem=None, version=2))
        self.refused('certificate_invalid', self.transport().request, 'GET', f'https://{HOST}/ok')

    def test_no_verification_switch_exists(self):
        import ssl
        t = self.transport()
        ctx = t._context(self.store.get('c1'))
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(ctx.check_hostname)
        self.assertGreaterEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_2)
        import inspect
        from agit8or_connect import transport as mod
        src = inspect.getsource(mod)
        for forbidden in ('CERT_NONE', 'check_hostname = False', '_create_unverified_context', 'verify=False'):
            self.assertNotIn(forbidden, src)


class Limits(_Base):
    def test_response_size_cap(self):
        self.refused('too_large', self.transport(max_response_bytes=1024 * 1024).request, 'GET', f'https://{HOST}/big')

    def test_total_deadline_against_a_dripping_peer(self):
        import time
        t = self.transport(total_timeout=1.0)
        start = time.monotonic()
        self.refused('deadline_exceeded', t.request, 'GET', f'https://{HOST}/slow')
        self.assertLess(time.monotonic() - start, 3)


class Preview(_Base):
    def test_preview_reports_addresses_and_certificate(self):
        self.dns[HOST] = [IP1, PRIV]
        p = preview_destination(f'https://{HOST}', ca_pem=self.pki.ca_pem, resolver=resolver_for(self.dns),
                                _dialer=mapped_dialer({IP1: self.server.port, PRIV: self.server.port}))
        self.assertEqual([a['address'] for a in p.addresses], [IP1, PRIV])
        self.assertEqual([a['private'] for a in p.addresses], [False, True])
        self.assertEqual(p.certificate['spki_sha256'], spki_of(self.cert))

    def test_preview_never_contacts_refused_addresses(self):
        self.dns[HOST] = [IP1, '169.254.169.254']
        with self.assertRaises(ConnectError) as e:
            preview_destination(f'https://{HOST}', ca_pem=self.pki.ca_pem, resolver=resolver_for(self.dns),
                                _dialer=mapped_dialer({}))
        self.assertEqual(e.exception.code, 'blocked_destination')

    def test_preview_requires_a_verifying_certificate(self):
        with self.assertRaises(ConnectError) as e:
            preview_destination(f'https://{HOST}', ca_pem=self.pki.ca_pem, resolver=resolver_for(self.dns),
                                _dialer=mapped_dialer({IP1: self.wrong_name.port}))
        self.assertEqual(e.exception.code, 'certificate_name_mismatch')


class AddressVectors(unittest.TestCase):
    def test_classification_vectors(self):
        from agit8or_connect.tests.test_vectors import load
        v = load('addresses.json')
        for c in v['addresses']:
            info = addresses.classify(c['input'])
            self.assertEqual((info.category, info.via, info.refused), (c['category'], c['via'], c['outbound_refused']),
                             c['input'])
            self.assertEqual(addresses.normalize(c['input']), c['normalized'], c['input'])
        from agit8or_connect.destinations import check_address
        for c in v['approved_networks']:
            if c['valid']:
                check_address(ApprovedAddress(c['net'], c['private']))
            else:
                with self.assertRaises((ConnectError, ValueError)):
                    check_address(ApprovedAddress(c['net'], c['private']))

    def test_legacy_ip_allowed_is_version_independent(self):
        from agit8or_connect.http import ip_allowed
        self.assertFalse(ip_allowed('fec0::1', True))         # was True on Python 3.12 (F-11)
        self.assertFalse(ip_allowed('2002:7f00:1::1', True))
        self.assertTrue(ip_allowed('93.184.216.34', False))


if __name__ == '__main__':
    unittest.main()
