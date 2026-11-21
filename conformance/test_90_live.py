"""Black-box checks against a running installation (optional).

Skipped unless AGIT8OR_CONNECT_TARGET is set to the installation's public base
URL (https only). Read-only and unauthenticated: it fetches discovery and
health and sends empty, unauthenticated POSTs to the 1.1 routes. It never
pairs, never sends a pairing code, and never stores anything.

    AGIT8OR_CONNECT_TARGET=https://connect.example.com python -m unittest test_90_live -v

Options:
  AGIT8OR_CONNECT_TARGET_PRIVATE=1   allow a private (RFC 1918 / ULA / CGNAT) address
  AGIT8OR_CONNECT_TARGET_CA=path     PEM bundle that REPLACES the system CAs (private CA)

Every Connect route of an installation that enforces source policy may answer
`403 source_not_authorised` to this machine; that answer is accepted as
conformant (QUICK_CONNECT_SPECIFICATION.md §7.3) and the checks that need a
readable document are skipped. Requests go through the SDK's guarded
transport: TLS verified, no redirects, no proxies, loopback / link-local /
metadata addresses refused."""
import json
import os
import unittest

from _support import load_schema, schema_errors
from agit8or_connect import discovery, quick_connect as qc
from agit8or_connect.http import MinimalGuardedTransport

TARGET = (os.environ.get('AGIT8OR_CONNECT_TARGET') or '').rstrip('/')


def transport():
    ca = os.environ.get('AGIT8OR_CONNECT_TARGET_CA')
    pem = open(ca, encoding='utf-8').read() if ca else None
    return MinimalGuardedTransport(allow_private=os.environ.get('AGIT8OR_CONNECT_TARGET_PRIVATE') == '1',
                                   ca_pem=pem)


@unittest.skipUnless(TARGET, 'set AGIT8OR_CONNECT_TARGET to run the live checks')
class LiveInstallation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = transport()
        cls.url = discovery.discovery_url(TARGET)
        r = cls.t.request('GET', cls.url, {'Accept': 'application/json'})
        cls.status = r.status
        cls.body = json.loads(r.body or b'null') if r.body else None

    def assert_error_body(self, body, code=None):
        self.assertEqual(schema_errors(load_schema('Error'), body), [], body)
        if code:
            self.assertEqual(body['error']['code'], code)

    def doc_or_skip(self):
        if self.status == 403:
            self.assert_error_body(self.body, 'source_not_authorised')
            self.skipTest('this source is not authorised at the target (403 source_not_authorised)')
        self.assertEqual(self.status, 200, self.body)
        return self.body

    def test_discovery_shape_and_same_origin(self):
        doc = self.doc_or_skip()
        self.assertEqual(schema_errors(load_schema('Discovery'), doc), [])
        info = discovery.parse_document(doc, self.url)   # refuses cross-origin endpoints
        self.assertEqual(info.version, '1')
        self.assertIn('1', doc['versions'])

    def test_1_1_additions_consistent(self):
        doc = self.doc_or_skip()
        adv = qc.advertised_extensions(doc, self.url)
        if 'extensions' in doc:
            self.assertEqual(schema_errors(load_schema('QcExtensions'), doc['extensions']), [])
        if qc.EXT_BOOTSTRAP in adv:
            self.assertIn(qc.EXT_SOURCE_BINDING, adv, 'qc-bootstrap/1 requires qc-source-binding/1')

    def test_health(self):
        r = self.t.request('GET', TARGET + '/connect/v1/health')
        body = json.loads(r.body or b'{}')
        if r.status == 403:
            return self.assert_error_body(body, 'source_not_authorised')
        self.assertEqual(r.status, 200, body)
        self.assertEqual(body.get('protocol'), 'agit8or-connect/1')

    def test_probe_unauthenticated_or_absent(self):
        doc = self.doc_or_skip()
        adv = qc.advertised_extensions(doc, self.url)
        probe = doc['endpoints'].get('qc_probe') if qc.EXT_DIAGNOSTICS in adv else TARGET + qc.PROBE_PATH
        r = self.t.request('POST', probe, {'Content-Type': 'application/json'}, b'{}')
        body = json.loads(r.body or b'{}')
        if qc.EXT_DIAGNOSTICS in adv:
            self.assertIn(r.status, (401, 403), 'an unauthenticated probe must be refused')
        else:
            self.assertIn(r.status, (403, 404), 'a peer without qc-diagnostics/1 answers 404 (or 403 by source)')
        self.assert_error_body(body)

    def test_exchange_refuses_an_unknown_code(self):
        doc = self.doc_or_skip()
        if qc.EXT_BOOTSTRAP not in qc.advertised_extensions(doc, self.url):
            self.skipTest('target does not advertise qc-bootstrap/1')
        r = self.t.request('POST', doc['endpoints']['qc_exchange'], {'Content-Type': 'application/json'},
                           b'{"exchange": "x.y.z"}')
        self.assertEqual(r.status, 403, 'no temporary rule names this request: source_not_authorised first')
        self.assert_error_body(json.loads(r.body or b'{}'), 'source_not_authorised')


if __name__ == '__main__':
    unittest.main()
