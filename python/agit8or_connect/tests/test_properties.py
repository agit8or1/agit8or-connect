"""Property tests (hypothesis). Skipped when hypothesis is not installed; CI installs it."""
import ipaddress
import os
import unittest

try:
    from hypothesis import given, settings, strategies as st
except ImportError:          # pragma: no cover
    given = None

from agit8or_connect import addresses
from agit8or_connect.errors import ConnectError

if given is not None:
    v4 = st.integers(0, 2 ** 32 - 1).map(lambda n: str(ipaddress.IPv4Address(n)))
    v6 = st.integers(0, 2 ** 128 - 1).map(lambda n: str(ipaddress.IPv6Address(n)))
    any_ip = st.one_of(v4, v6)

    @unittest.skipIf(given is None, 'hypothesis not installed')
    class AddressProperties(unittest.TestCase):
        @settings(max_examples=2000, deadline=None)
        @given(any_ip)
        def test_classification_total_and_normalisation_idempotent(self, ip):
            info = addresses.classify(ip)
            self.assertIn(info.category, addresses.CATEGORIES)
            n = addresses.normalize(ip)
            self.assertEqual(addresses.normalize(n), n)
            self.assertEqual(addresses.classify(n).category, info.category)

        @settings(max_examples=2000, deadline=None)
        @given(v4)
        def test_mapped_and_nat64_forms_never_escape_their_ipv4_class(self, ip):
            cat = addresses.classify(ip).category
            mapped = '::ffff:' + ip
            self.assertEqual(addresses.classify(mapped).category, cat)
            nat64 = str(ipaddress.IPv6Address(int(ipaddress.IPv6Address('64:ff9b::')) + int(ipaddress.IPv4Address(ip))))
            self.assertEqual(addresses.classify(nat64).category, cat)

        @settings(max_examples=1000, deadline=None)
        @given(st.integers(0, 2 ** 32 - 1), st.integers(24, 32))
        def test_network_category_is_at_least_as_strict_as_any_member(self, n, prefix):
            net = ipaddress.IPv4Network((n, prefix), strict=False)
            cat = addresses.network_category(str(net))
            order = ['metadata', 'loopback', 'link_local', 'unspecified', 'broadcast', 'multicast', 'reserved',
                     'private', 'documentation', 'public']
            for member in (net.network_address, net.broadcast_address, net.network_address + (net.num_addresses // 2)):
                self.assertLessEqual(order.index(cat), order.index(addresses.classify(str(member)).category),
                                     (str(net), str(member)))

        @settings(max_examples=300, deadline=None)
        @given(st.text(max_size=80))
        def test_arbitrary_text_never_crashes_and_non_addresses_are_refused(self, s):
            info = addresses.classify(s)
            if addresses.parse(s) is None:
                self.assertTrue(info.refused)

    @unittest.skipIf(given is None, 'hypothesis not installed')
    class EnvelopeProperties(unittest.TestCase):
        @settings(max_examples=200, deadline=None)
        @given(st.binary(min_size=1, max_size=256), st.text(min_size=1, max_size=40).filter(lambda s: '#' not in s and '\n' not in s))
        def test_roundtrip_and_any_bit_flip_detected(self, data, row):
            from agit8or_connect.keystore import PrivateKeyCipher, StaticMasterKeys, row_aad
            c = PrivateKeyCipher(StaticMasterKeys({'k': os.urandom(32)}, 'k'))
            aad = row_aad('t', 'c', row)
            blob = c.encrypt_bytes(data, aad)
            self.assertEqual(c.decrypt_bytes(blob, aad), data)
            parts = blob.split('.')
            ct = bytearray(parts[3].encode())
            ct[len(ct) // 2] = ord('A') if ct[len(ct) // 2] != ord('A') else ord('B')
            with self.assertRaises(ConnectError):
                c.decrypt_bytes('.'.join(parts[:3] + [ct.decode()]), aad)

    @unittest.skipIf(given is None, 'hypothesis not installed')
    class RateLimitProperties(unittest.TestCase):
        @settings(max_examples=200, deadline=None)
        @given(st.integers(1, 20), st.lists(st.floats(0, 5, allow_nan=False), min_size=1, max_size=60))
        def test_never_more_than_limit_per_window(self, limit, gaps):
            from agit8or_connect.ratelimit import MemoryRateLimitStore, RateLimiter, Rule
            t = [1_800_000_000.0]
            rl = RateLimiter(MemoryRateLimitStore(), {'x': Rule(limit, 60)}, clock=lambda: t[0])
            allowed = []
            for g in gaps:
                t[0] += g
                try:
                    rl.check('x', 'k')
                    allowed.append(t[0])
                except ConnectError as e:
                    self.assertEqual(e.code, 'rate_limited')
            for i, start in enumerate(allowed):     # any 60 s span holds at most 2*limit (sliding estimate bound)
                self.assertLessEqual(sum(1 for x in allowed[i:] if x < start + 60), 2 * limit)
            self.assertLessEqual(len([x for x in allowed if x < allowed[0] + 1e-9 + 0]), limit)


if given is not None:
    token_like = st.one_of(st.text(max_size=300), st.lists(st.text(alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_', max_size=80), min_size=1, max_size=5).map('.'.join))

    @unittest.skipIf(given is None, 'hypothesis not installed')
    class ParserFuzz(unittest.TestCase):
        """Untrusted inputs: parsers and verifiers fail with ConnectError, never another exception."""

        @settings(max_examples=400, deadline=None)
        @given(token_like)
        def test_token_verifiers_only_raise_connect_errors(self, t):
            from agit8or_connect import jws, keys, tokens
            from agit8or_connect.replay import MemoryReplayStore
            k = keys.generate_private_key()
            for fn in (lambda: jws.unverified_header(t), lambda: jws.unverified_payload(t),
                       lambda: tokens.verify_access_token(t, {keys.thumbprint(k): k.public_key()}, issuer='i'),
                       lambda: tokens.verify_dpop_proof(t, method='GET', url='https://x.example.test/',
                                                        replay=MemoryReplayStore()),
                       lambda: tokens.verify_client_assertion(t, lambda kid: k.public_key(), client_id='c',
                                                              token_endpoint='https://x.example.test/t',
                                                              replay=MemoryReplayStore())):
                try:
                    fn()
                except ConnectError:
                    pass

        @settings(max_examples=300, deadline=None)
        @given(st.dictionaries(st.text(max_size=20), st.text(max_size=40), max_size=6))
        def test_proxy_and_source_inputs(self, headers):
            from agit8or_connect.proxy import TrustedProxyResolver
            from agit8or_connect.sources import SourcePolicy, SourceRule
            r = TrustedProxyResolver(['10.0.0.0/24'])
            p = SourcePolicy(1, [SourceRule('203.0.113.0/24', layer='installation')])
            for peer in ('10.0.0.5', '203.0.113.7'):
                try:
                    src = r.resolve(peer, headers)
                    p.evaluate(src, route='token', connection_id='c')
                except ConnectError:
                    pass


if __name__ == '__main__':
    unittest.main()
