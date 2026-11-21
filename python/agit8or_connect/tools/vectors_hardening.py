"""New vector files added by the hardening work (existing files are never changed).

    addresses.json       address classification shared by both SDKs (outbound policy, source policy)
    key-envelope.json    private-key encryption at rest: AES-256-GCM envelope with row-bound associated data
"""
from __future__ import annotations

import hashlib

from .. import addresses
from ..destinations import ApprovedAddress, check_address
from ..errors import ConnectError
from ..keystore import PrivateKeyCipher, StaticMasterKeys, row_aad

NOTICE = 'TEST-ONLY KEYS. Published seeds; never use outside conformance tests.'

ADDRESS_CASES = [
    '93.184.216.34', '8.8.8.8', '2606:4700::1111', '203.0.113.10', '198.51.100.7', '192.0.2.1', '2001:db8::10',
    '3fff::1', '10.0.0.5', '172.16.1.1', '172.31.255.255', '172.32.0.1', '192.168.1.1', '100.64.0.1',
    '100.127.255.255', '100.128.0.1', 'fd12:3456::1', 'fc00::1', '64:ff9b:1::a00:1', '127.0.0.1', '127.255.255.254',
    '::1', '0.0.0.0', '0.1.2.3', '::', '169.254.1.1', 'fe80::1', '169.254.169.254', '169.254.170.2',
    '169.254.170.23', '100.100.100.200', '192.0.0.192', 'fd00:ec2::254', '224.0.0.1', '239.255.255.250', 'ff02::1',
    '255.255.255.255', '240.0.0.1', '192.0.0.170', '198.18.0.1', '192.88.99.1', '::ffff:127.0.0.1',
    '::ffff:10.0.0.1', '::ffff:93.184.216.34', '64:ff9b::7f00:1', '64:ff9b::a9fe:a9fe', '64:ff9b::5db8:d822',
    '::127.0.0.1', '2001::1', '2001:20::1', '2002:7f00:1::1', '2002:5db8:d822::1', 'fec0::1', '5f00::1', '100::1',
    '4000::1', 'fe80::1%eth0', '1.2.3', '256.1.1.1', 'example.test',
]

NETWORK_CASES = [
    ('203.0.113.10/32', False), ('203.0.113.0/24', False), ('203.0.112.0/23', False), ('10.0.0.5/32', False),
    ('10.0.0.5/32', True), ('10.0.0.0/24', True), ('93.184.216.34/32', True), ('127.0.0.1/32', True),
    ('169.254.169.254/32', False), ('2001:db8::/48', False), ('2001:db8::/47', False), ('fd12:3456::/48', True),
    ('fe80::/64', True), ('64:ff9b::/96', False), ('::ffff:0:0/96', False), ('0.0.0.0/0', False),
    ('203.0.113.1/24', False),
]


def address_vectors():
    cases = []
    for a in ADDRESS_CASES:
        info = addresses.classify(a)
        cases.append({'input': a, 'normalized': addresses.normalize(a), 'category': info.category, 'via': info.via,
                      'outbound_refused': info.refused})
    nets = []
    for net, private in NETWORK_CASES:
        try:
            check_address(ApprovedAddress(net, private))
            nets.append({'net': net, 'private': private, 'valid': True})
        except ConnectError as e:
            nets.append({'net': net, 'private': private, 'valid': False, 'error': e.code})
        except ValueError:
            nets.append({'net': net, 'private': private, 'valid': False, 'error': 'invalid_destination'})
    from .. import destinations
    d = destinations.new_destination('conn-vector-1', 'peer.example.test', 443,
                                      ['203.0.113.0/24', destinations.ApprovedAddress('10.20.30.40/32', private=True,
                                                                                    note='site link')],
                                      spki_pins=['A' * 43], approved_by=['admin-1', 'admin-2'], now=1800000000)
    dest = {'record': d.as_dict(), 'digest': d.digest()}
    return {'notice': NOTICE, 'destination': dest, 'description': 'Address classification (python/agit8or_connect/addresses.py) and '
            'approved-destination address validation (destinations.check_address). Categories: '
            + ', '.join(addresses.CATEGORIES) + '.', 'addresses': cases, 'approved_networks': nets}


def key_envelope_vectors():
    mk = hashlib.sha256(b'agit8or-connect TEST-ONLY master key 1').digest()
    mk2 = hashlib.sha256(b'agit8or-connect TEST-ONLY master key 2').digest()
    seed = hashlib.sha256(b'agit8or-connect/1 TEST-ONLY key A').digest()
    nonce = hashlib.sha256(b'agit8or-connect TEST-ONLY nonce').digest()[:12]
    aad = row_aad('connect_key', 'private_key', '7d1f5c9a-0b7e-4c2e-9c55-0d6f3a1b2c3d')
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.from_private_bytes(seed)
    blob = PrivateKeyCipher(StaticMasterKeys({'test-mk-1': mk}, 'test-mk-1')).encrypt_bytes(seed, aad, _nonce=nonce)
    import base64
    b64 = lambda b: base64.urlsafe_b64encode(b).decode().rstrip('=')  # noqa: E731
    return {'notice': NOTICE, 'description': 'Private-key envelope a8ck1.<key id>.<nonce>.<AES-256-GCM ct+tag>; '
            'associated data = "agit8or-connect key-v1\\n" + key id + "\\n" + row aad.',
            'master_keys': {'test-mk-1': b64(mk), 'test-mk-2': b64(mk2)},
            'row_aad': aad.decode(), 'nonce_b64url': b64(nonce), 'plaintext_seed_hex': seed.hex(),
            'public_key_thumbprint': __import__('agit8or_connect.keys', fromlist=['thumbprint']).thumbprint(key),
            'envelope': blob,
            'negative': [
                {'case': 'other row', 'row_aad': 'connect_key.private_key#00000000-0000-4000-8000-000000000000',
                 'error': 'key_corrupt'},
                {'case': 'relabelled key id', 'envelope': blob.replace('test-mk-1', 'test-mk-2'),
                 'row_aad': aad.decode(), 'error': 'key_corrupt'},
                {'case': 'unknown key id', 'envelope': blob.replace('test-mk-1', 'test-mk-9'), 'row_aad': aad.decode(),
                 'error': 'key_unavailable'},
            ]}


def hardening_files():
    return {'addresses.json': address_vectors(), 'key-envelope.json': key_envelope_vectors()}
