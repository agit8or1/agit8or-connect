"""Write the TEST-ONLY TLS fixtures used by typescript/test/transport.test.ts.

Node cannot issue X.509 certificates, so the TypeScript transport tests load fixed PEM files. They are
published, test-only keys for 127.0.0.1 listeners and must never be trusted anywhere else.
Run: python tools/make_tls_fixtures.py   (needs the `cryptography` package)
"""
import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = os.path.join(os.path.dirname(__file__), '..', 'typescript', 'test', 'fixtures', 'tls')
UTC = datetime.timezone.utc
START, END = datetime.datetime(2026, 1, 1, tzinfo=UTC), datetime.datetime(2046, 1, 1, tzinfo=UTC)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem(obj):
    if hasattr(obj, 'private_bytes'):
        return obj.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
    return obj.public_bytes(serialization.Encoding.PEM)


def ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(START).not_valid_after(END)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return cert, key


def leaf(issuer, names, start=START, end=END):
    cert_ca, key_ca = issuer
    key = ec.generate_private_key(ec.SECP256R1())
    sans = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]
    cert = (x509.CertificateBuilder().subject_name(name(names[0])).issuer_name(cert_ca.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(start).not_valid_after(end)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(key_ca, hashes.SHA256()))
    return cert, key


def main():
    os.makedirs(OUT, exist_ok=True)
    root, other = ca('Agit8or Connect TEST-ONLY CA'), ca('Agit8or Connect TEST-ONLY other CA')
    files = {'ca.pem': pem(root[0]), 'other-ca.pem': pem(other[0])}
    for label, (cert, key) in {
        'peer': leaf(root, ['peer.example.test']),
        'wrong-name': leaf(root, ['someone-else.example.test']),
        'expired': leaf(root, ['peer.example.test'], datetime.datetime(2020, 1, 1, tzinfo=UTC),
                        datetime.datetime(2021, 1, 1, tzinfo=UTC)),
        'other-ca': leaf(other, ['peer.example.test']),
    }.items():
        files[f'{label}.crt'] = pem(cert)
        files[f'{label}.key'] = pem(key)
    files['README.md'] = (b'TEST-ONLY certificates and private keys for the TypeScript transport tests (127.0.0.1 '
                          b'listeners). Published on purpose; never trust them anywhere else. Regenerate with '
                          b'`python tools/make_tls_fixtures.py`.\n')
    for n, data in files.items():
        with open(os.path.join(OUT, n), 'wb') as f:
            f.write(data)
    print('wrote', len(files), 'files to', os.path.normpath(OUT))


if __name__ == '__main__':
    main()
