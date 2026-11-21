"""
Build schemas/*.schema.json (JSON Schema 2020-12), one file per message.

    python tools/build_schemas.py           # write
    python tools/build_schemas.py --check   # exit 1 if schemas/ differs (CI)

Two sources:

* every `components.schemas` entry of openapi/openapi.yaml (needs PyYAML), with
  `#/components/schemas/X` references rewritten to `X.schema.json`;
* the JWS claim sets of agit8or-connect/1 (docs/PROTOCOL.md §5-§6, §9), which
  the OpenAPI document does not describe because they travel inside JWS
  values. They are defined below.

The schemas are descriptive. They never replace the verification order of the
specification (signature first, then claims); a message that validates against
its schema can still be refused. Unknown members MUST be ignored by receivers
(PROTOCOL.md §3), so `additionalProperties` is never false on a v1 message.
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
OUT = os.path.join(ROOT, 'schemas')
OPENAPI = os.path.join(ROOT, 'openapi', 'openapi.yaml')
BASE_ID = 'https://github.com/agit8or1/agit8or-connect/schemas/'
DIALECT = 'https://json-schema.org/draft/2020-12/schema'

UUID = {'type': 'string', 'pattern': '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'}
INT = {'type': 'integer'}
JTI = {'type': 'string', 'minLength': 1, 'maxLength': 128}
B64URL = {'type': 'string', 'pattern': '^[A-Za-z0-9_-]+$'}
SCOPES = {'type': 'array', 'items': {'type': 'string'}}
V1 = {'type': 'string', 'const': 'agit8or-connect/1'}
APP = {'type': 'object', 'required': ['type', 'version', 'display_name', 'installation_id'],
       'properties': {'type': {'type': 'string'}, 'version': {'type': 'string'},
                      'display_name': {'type': 'string'}, 'installation_id': UUID}}
JWK = {'$ref': 'OkpJwk.schema.json'}


# JWS `typ` of the openapi-derived claim schemas (QUICK_CONNECT_SPECIFICATION.md §4.2).
OPENAPI_JWS_TYP = {'QcInvitationClaims': 'agit8or-qc-invitation+jwt', 'QcAcceptClaims': 'agit8or-qc-accept+jwt',
                   'QcExchangeClaims': 'agit8or-qc-exchange+jwt'}


def claims(title, required, props, typ):
    return {'title': title, 'description': f'Payload of a JWS with header typ "{typ}".',
            'x-jws-typ': typ, 'type': 'object', 'required': sorted(required), 'properties': props}


V1_SCHEMAS = {
    'PairingRequestClaims': claims(
        'Pairing request (PROTOCOL.md §5.2)',
        ['protocol', 'iss', 'aud', 'iat', 'exp', 'jti', 'pairing_code', 'app', 'connection_id', 'discovery_url',
         'connection_key', 'requested_scopes', 'proposed_tenants'],
        {'protocol': V1, 'iss': UUID, 'aud': UUID, 'iat': INT, 'exp': INT, 'jti': JTI,
         'pairing_code': {'type': 'string'}, 'app': APP, 'connection_id': UUID,
         'discovery_url': {'type': 'string', 'pattern': '^https://'}, 'connection_key': JWK,
         'requested_scopes': SCOPES,
         'proposed_tenants': {'type': 'array', 'items': {
             'type': 'object', 'required': ['id'],
             'properties': {'id': {'type': 'string'}, 'label': {'type': 'string'}}}}},
        'agit8or-pairing-request+jwt'),
    'PairingAckClaims': claims(
        'Pairing ack (PROTOCOL.md §5.2)',
        ['protocol', 'iss', 'aud', 'iat', 'exp', 'request_id', 'request_jti', 'connection_id', 'app',
         'connection_key', 'status'],
        {'protocol': V1, 'iss': UUID, 'aud': UUID, 'iat': INT, 'exp': INT, 'request_id': {'type': 'string'},
         'request_jti': JTI, 'connection_id': UUID, 'app': APP, 'connection_key': JWK,
         'status': {'type': 'string', 'const': 'pending_approval'}},
        'agit8or-pairing-ack+jwt'),
    'PairingPollClaims': claims(
        'Pairing status poll proof (PROTOCOL.md §5.2)',
        ['iss', 'aud', 'iat', 'exp', 'jti', 'request_id'],
        {'iss': UUID, 'aud': UUID, 'iat': INT, 'exp': INT, 'jti': JTI, 'request_id': {'type': 'string'}},
        'agit8or-pairing-poll+jwt'),
    'PairingResultClaims': claims(
        'Pairing result (PROTOCOL.md §5.2)',
        ['protocol', 'iss', 'aud', 'iat', 'exp', 'status', 'request_id', 'request_jti', 'connection_id'],
        {'protocol': V1, 'iss': UUID, 'aud': UUID, 'iat': INT, 'exp': INT,
         'status': {'type': 'string', 'enum': ['approved', 'rejected']}, 'request_id': {'type': 'string'},
         'request_jti': JTI, 'connection_id': UUID, 'granted_scopes': SCOPES, 'requested_scopes': SCOPES,
         'tenant_grants': {'type': 'array', 'items': {
             'type': 'object', 'required': ['remote_tenant', 'scopes'],
             'properties': {'remote_tenant': {'type': 'string'}, 'tenant': {'type': 'string'},
                            'local_tenant': {'type': 'string'}, 'label': {'type': 'string'},
                            'scopes': SCOPES}}},
         'endpoints': {'type': 'object', 'additionalProperties': {'type': 'string'}}},
        'agit8or-pairing-result+jwt'),
    'ClientAssertionClaims': claims(
        'Client assertion, private_key_jwt (PROTOCOL.md §6.1, RFC 7523)',
        ['iss', 'sub', 'aud', 'iat', 'exp', 'jti'],
        {'iss': UUID, 'sub': UUID, 'aud': {'type': 'string', 'pattern': '^https://'}, 'iat': INT, 'exp': INT,
         'jti': JTI},
        'client-authentication+jwt'),
    'AccessTokenClaims': claims(
        'DPoP-bound access token (PROTOCOL.md §6.2)',
        ['iss', 'aud', 'sub', 'client_id', 'scope', 'iat', 'exp', 'jti', 'cnf'],
        {'iss': UUID, 'aud': UUID, 'sub': UUID, 'client_id': UUID, 'scope': {'type': 'string'}, 'iat': INT,
         'nbf': INT, 'exp': INT, 'jti': JTI,
         'cnf': {'type': 'object', 'required': ['jkt'], 'properties': {'jkt': B64URL}},
         'act': {'description': 'actor/1 only (PROTOCOL.md §18.2): the person the call is made for.',
                 'type': 'object', 'required': ['sub'], 'additionalProperties': False,
                 'properties': {'sub': {'type': 'string', 'pattern': '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'}}}},
        'at+jwt'),
    'DpopProofClaims': claims(
        'DPoP proof (PROTOCOL.md §6.3, RFC 9449); header carries the public jwk',
        ['htm', 'htu', 'iat', 'jti'],
        {'htm': {'type': 'string', 'pattern': '^[A-Z]+$'}, 'htu': {'type': 'string', 'pattern': '^https://'},
         'iat': INT, 'jti': JTI, 'ath': B64URL,
         'nonce': {'description': 'dpop-nonce/1 only (PROTOCOL.md §18.1)', 'type': 'string',
                   'pattern': '^[A-Za-z0-9_-]{32,64}$'}},
        'dpop+jwt'),
    'AuditCheckpointClaims': claims(
        'Signed audit checkpoint (PROTOCOL.md §14.1); local, exchanged only when an operator publishes it',
        ['iss', 'seq', 'hash', 'iat'],
        {'iss': {'type': 'string'}, 'seq': {'type': 'integer', 'minimum': 1},
         'hash': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'}, 'iat': INT},
        'audit-checkpoint+jwt'),
    'JwksEndorsementClaims': claims(
        'JWKS endorsement (PROTOCOL.md §6.4)',
        ['iss', 'sub', 'keys_sha256', 'iat', 'exp'],
        {'iss': UUID, 'sub': UUID, 'keys_sha256': {'type': 'string', 'pattern': '^[0-9a-f]{64}$'},
         'iat': INT, 'exp': INT},
        'agit8or-jwks+jwt'),
    'EndorsedJwks': {
        'title': 'Endorsed JWKS document (PROTOCOL.md §6.4)', 'type': 'object', 'required': ['keys', 'endorsement'],
        'properties': {'keys': {'type': 'array', 'items': JWK}, 'endorsement': {'type': 'string'}}},
    'TokenResponse': {
        'title': 'Token endpoint answer (PROTOCOL.md §6.1)', 'type': 'object',
        'required': ['access_token', 'token_type', 'expires_in', 'scope'],
        'properties': {'access_token': {'type': 'string'}, 'token_type': {'type': 'string', 'const': 'DPoP'},
                       'expires_in': {'type': 'integer', 'minimum': 1, 'maximum': 300},
                       'scope': {'type': 'string'}}},
}


def _rewrite(o):
    if isinstance(o, dict):
        out = {}
        for k, v in o.items():
            if k == '$ref' and isinstance(v, str) and v.startswith('#/components/schemas/'):
                out[k] = v.rsplit('/', 1)[1] + '.schema.json'
            else:
                out[k] = _rewrite(v)
        return out
    if isinstance(o, list):
        return [_rewrite(x) for x in o]
    return o


def build() -> dict:
    import yaml  # only the builder needs PyYAML; the conformance suite reads the JSON output
    with open(OPENAPI, encoding='utf-8') as f:
        components = yaml.safe_load(f)['components']['schemas']
    files = {}
    for name, schema in list(components.items()) + list(V1_SCHEMAS.items()):
        body = {'$schema': DIALECT, '$id': BASE_ID + name + '.schema.json'}
        if name in components:
            body['x-source'] = 'openapi/openapi.yaml#/components/schemas/' + name
            if name in OPENAPI_JWS_TYP:
                body['x-jws-typ'] = OPENAPI_JWS_TYP[name]
        body.update(_rewrite(schema))
        files[name + '.schema.json'] = json.dumps(body, indent=2, ensure_ascii=False, sort_keys=False) + '\n'
    return files


def main(argv) -> int:
    files = build()
    if '--check' in argv:
        on_disk = sorted(n for n in os.listdir(OUT) if n.endswith('.schema.json')) if os.path.isdir(OUT) else []
        bad = sorted(set(on_disk) ^ set(files))
        for name, text in files.items():
            p = os.path.join(OUT, name)
            if os.path.exists(p) and open(p, encoding='utf-8').read() != text:
                bad.append(name)
        if bad:
            print('schemas/ out of date:', ', '.join(sorted(set(bad))))
            return 1
        print(f'{len(files)} schemas up to date')
        return 0
    os.makedirs(OUT, exist_ok=True)
    for name, text in files.items():
        with open(os.path.join(OUT, name), 'w', encoding='utf-8') as f:
            f.write(text)
    print(f'wrote {len(files)} schemas')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
