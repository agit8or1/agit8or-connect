"""qc-diagnostics/1: the probe answer's shape, its authentication, and the
fallback against a peer without the extension.

Fallback rule (docs/CONNECTION_HEALTH.md): a caller probes only when the
peer's discovery advertises qc-diagnostics/1. Against a peer that does not
(a 1.0 peer, or one that answers the probe route with 404) the
reverse-connectivity diagnostic is `not_tested`. It is never a failure and
never changes the connection's health."""
import json
import unittest

from _support import load_schema, schema_errors, vector
from agit8or_connect import quick_connect as qc
from agit8or_connect.errors import ConnectError

from test_30_interop import SCOPES, approve_both, code_flow, make


def reverse_step(peer, conn_id, nonce=None):
    """Conformance model of the reverse-connectivity diagnostic step."""
    conn = peer.connections[conn_id]
    base = conn.remote_endpoints['api_base'].rsplit('/connect/v1', 1)[0]
    url = base + '/.well-known/agit8or-connect'
    doc = json.loads(peer.network.request('GET', url).body)
    if qc.EXT_DIAGNOSTICS not in qc.advertised_extensions(doc, url):
        return 'not_tested', None
    try:
        return 'pass', peer.qc_probe(conn_id, nonce=nonce)
    except ConnectError as e:
        if e.status == 404:
            return 'not_tested', None
        return 'fail', e.code


class ProbeResponseShape(unittest.TestCase):
    def test_vector_response_valid(self):
        d = vector('qc-diagnostics.json')
        nonce = d['request']['body'].get('nonce')
        self.assertEqual(qc.validate_probe_response(d['response'], nonce=nonce), d['response'])
        self.assertEqual(schema_errors(load_schema('QcProbeResponse'), d['response']), [])

    def test_vector_invalid_responses_refused(self):
        d = vector('qc-diagnostics.json')
        nonce = d['request']['body'].get('nonce')
        self.assertGreaterEqual(len(d['response_invalid']), 5)
        for bad in d['response_invalid']:
            with self.assertRaises(ConnectError, msg=json.dumps(bad)) as e:
                qc.validate_probe_response(bad, nonce=nonce)
            self.assertEqual(e.exception.code, 'invalid_request')

    def test_built_response_round_trips(self):
        r = qc.build_probe_response(observed_source='2001:db8::1', server_time=1767225600,
                                    connection_state='active', source_check='not_enforced', nonce='n' * 22)
        self.assertEqual(r['observed_source'], '2001:db8::1')
        self.assertEqual(schema_errors(load_schema('QcProbeResponse'), r), [])
        with self.assertRaises(ConnectError):
            qc.validate_probe_response(r, nonce='m' * 22)       # nonce must be echoed


class ProbeOnTheWire(unittest.TestCase):
    def test_both_1_1_probe_passes_and_reports_observed_source(self):
        a, b, *_ = make(True, True)
        url = a.qc_start(b.base, requested_scopes=SCOPES)
        conn = a.qc_callback(b.qc_authorize(b.qc_review(url)), proposed_tenants=[{'id': 'org-1'}])
        bconn = approve_both(a, b, conn)
        status, resp = reverse_step(a, conn.id, nonce='n' * 22)
        self.assertEqual(status, 'pass')
        self.assertEqual(resp['observed_source'], '203.0.113.10')
        self.assertEqual(reverse_step(b, bconn.id)[1]['observed_source'], '198.51.100.7')

    def test_probe_needs_a_dpop_token(self):
        a, b, net, _ = make(True, True)
        r = net.request('POST', b.url(qc.PROBE_PATH), {'Content-Type': 'application/json'}, b'{}',
                        source='203.0.113.10')
        self.assertIn(r.status, (401, 403), r.body)
        self.assertEqual(schema_errors(load_schema('Error'), json.loads(r.body)), [])

    def test_v1_peer_reverse_step_not_tested_without_a_request(self):
        a, b, net, _ = make(True, False)
        conn, _ = code_flow(a, b)
        before = len(net.log)
        self.assertEqual(reverse_step(a, conn.id), ('not_tested', None))
        self.assertFalse(any(u.endswith(qc.PROBE_PATH) for _, u in net.log[before:]))

    def test_probe_route_404_is_not_tested(self):
        a, b, net, _ = make(True, False)
        conn, _ = code_flow(a, b)
        r = net.request('POST', b.url(qc.PROBE_PATH), {}, b'{}', source='203.0.113.10')
        self.assertEqual(r.status, 404)
        self.assertEqual(schema_errors(load_schema('Error'), json.loads(r.body)), [])
        with self.assertRaises(ConnectError) as e:
            a.qc_probe(conn.id)
        self.assertEqual(e.exception.status, 404)
        # A peer that advertises the extension but has no route behaves like a 1.0 peer for this step.
        b.qc_advertise = True
        self.assertEqual(reverse_step(a, conn.id), ('not_tested', None))


if __name__ == '__main__':
    unittest.main()
