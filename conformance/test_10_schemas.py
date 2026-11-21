"""Every positive message in the vectors validates against its JSON Schema in
schemas/, and the schemas are in step with openapi/openapi.yaml.

Schema validation is a shape check only. It never replaces the verification
order of the specification; the vector tests check that."""
import json
import os
import subprocess
import sys
import unittest

from _support import ROOT, jws_parts, load_schema, schema_errors, vector


class SchemasUpToDate(unittest.TestCase):
    def test_schemas_match_openapi(self):
        try:
            import yaml  # noqa: F401
        except ImportError:
            self.skipTest('PyYAML not installed (CI installs it)')
        r = subprocess.run([sys.executable, os.path.join(ROOT, 'tools', 'build_schemas.py'), '--check'],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


class VectorsMatchSchemas(unittest.TestCase):
    def check(self, schema, obj, label):
        errs = schema_errors(load_schema(schema), obj)
        self.assertEqual(errs, [], f'{label} vs {schema}')

    def check_jws(self, schema, token, typ, label):
        header, payload = jws_parts(token)
        self.assertEqual(header['typ'], typ, label)
        self.assertEqual(load_schema(schema)['x-jws-typ'], typ)
        self.check(schema, payload, label)
        if 'jwk' in header:
            self.check('OkpJwk', header['jwk'], label + ' header jwk')

    def test_v1_pairing_messages(self):
        p = vector('pairing.json')
        self.check_jws('PairingRequestClaims', p['request']['jws'], 'agit8or-pairing-request+jwt', 'request')
        self.check_jws('PairingAckClaims', p['ack']['jws'], 'agit8or-pairing-ack+jwt', 'ack')
        self.check_jws('PairingPollClaims', p['poll']['jws'], 'agit8or-pairing-poll+jwt', 'poll')
        self.check_jws('PairingResultClaims', p['result']['jws'], 'agit8or-pairing-result+jwt', 'result')

    def test_v1_token_messages(self):
        t = vector('tokens.json')
        self.check_jws('ClientAssertionClaims', t['client_assertion']['jws'], 'client-authentication+jwt', 'assertion')
        self.check_jws('AccessTokenClaims', t['access_token']['jws'], 'at+jwt', 'access token')
        self.check_jws('DpopProofClaims', t['dpop']['token_request']['jws'], 'dpop+jwt', 'dpop token')
        self.check_jws('DpopProofClaims', t['dpop']['resource_request']['jws'], 'dpop+jwt', 'dpop resource')

    def test_v1_jwks_and_events(self):
        j = vector('jwks.json')
        self.check('EndorsedJwks', j['document'], 'jwks')
        self.check_jws('JwksEndorsementClaims', j['document']['endorsement'], 'agit8or-jwks+jwt', 'endorsement')
        w = vector('webhooks.json')
        self.check('EventEnvelope', json.loads(w['body_utf8']), 'event')
        for name, k in vector('keys.json')['keys'].items():
            self.check('OkpJwk', k['public_jwk'], 'key ' + name)

    def test_1_1_messages(self):
        inv = vector('qc-invitation.json')
        self.check_jws('QcInvitationClaims', inv['invitation']['jws'], 'agit8or-qc-invitation+jwt', 'invitation')
        self.check('QcInvitationClaims', inv['invitation']['claims'], 'invitation claims')
        ex = vector('qc-exchange.json')
        self.check_jws('QcAcceptClaims', ex['accept']['jws'], 'agit8or-qc-accept+jwt', 'accept')
        self.check_jws('QcExchangeClaims', ex['exchange']['jws'], 'agit8or-qc-exchange+jwt', 'exchange')
        self.check_jws('PairingAckClaims', ex['ack']['jws'], 'agit8or-pairing-ack+jwt', '1.1 ack is v1')
        for e in inv['invitation']['claims']['egress'] + ex['accept']['claims']['egress']:
            self.check('EgressEntry', e, 'egress')

    def test_1_1_diagnostics_and_errors(self):
        d = vector('qc-diagnostics.json')
        self.check('QcProbeResponse', d['response'], 'probe response')
        self.check('Error', d['source_not_authorised_error']['body'], 'source_not_authorised body')
        self.assertEqual(d['source_not_authorised_error']['status'], 403)

    def test_reference_discovery_documents(self):
        from agit8or_connect.reference_peer import Network, ReferencePeer
        for qc in (False, True):
            doc = ReferencePeer('https://responder.example.test', Network(), quick_connect=qc).document()
            self.check('Discovery', doc, f'discovery quick_connect={qc}')
            if qc:
                self.check('QcDiscoveryAdditions', doc, 'discovery 1.1 additions')

    def test_schema_validator_refuses_bad_shapes(self):
        d = vector('qc-diagnostics.json')
        bad = dict(d['response'], protocol='agit8or-connect/1')
        self.assertTrue(schema_errors(load_schema('QcProbeResponse'), bad))
        bad = {k: v for k, v in d['response'].items() if k != 'checks'}
        self.assertTrue(schema_errors(load_schema('QcProbeResponse'), bad))


if __name__ == '__main__':
    unittest.main()
