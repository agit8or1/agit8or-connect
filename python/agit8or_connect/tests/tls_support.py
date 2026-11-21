"""Test-only PKI and HTTPS server on 127.0.0.1 (never used outside tests).

`TestPKI` makes a private CA and leaf certificates; `TlsServer` serves a few behaviours over real TLS on an
ephemeral 127.0.0.1 port. Transports reach it through `mapped_dialer`, which connects a VALIDATED
documentation address (for example 203.0.113.10) to the local listener: everything above the socket —
address policy, TLS verification, host-name checks, pinning, limits — runs unchanged.
"""
from __future__ import annotations

import datetime
import ipaddress
import json
import socket
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


class TestPKI:
    def __init__(self, cn='Agit8or Connect TEST-ONLY CA'):
        self.key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        self.cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn))
                     .public_key(self.key.public_key()).serial_number(x509.random_serial_number())
                     .not_valid_before(now - datetime.timedelta(days=1)).not_valid_after(now + datetime.timedelta(days=30))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                     .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                                  content_commitment=False, key_encipherment=False,
                                                  data_encipherment=False, key_agreement=False, encipher_only=False,
                                                  decipher_only=False), critical=True)
                     .sign(self.key, hashes.SHA256()))

    @property
    def ca_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    def leaf(self, names=('peer.example.test',), ips=(), days=30, not_before_days=1):
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)
        sans = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
        cert = (x509.CertificateBuilder().subject_name(_name((list(names) or list(ips))[0]))
                .issuer_name(self.cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(days=not_before_days))
                .not_valid_after(now + datetime.timedelta(days=days))
                .add_extension(x509.SubjectAlternativeName(sans), critical=False)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(self.key, hashes.SHA256()))
        return cert, key

    def server_context(self, cert, key) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with tempfile.NamedTemporaryFile('wb', suffix='.pem', delete=False) as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
            path = f.name
        ctx.load_cert_chain(path)
        import os
        os.remove(path)
        return ctx


def spki_of(cert) -> str:
    import base64
    import hashlib
    der = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(hashlib.sha256(der).digest()).decode().rstrip('=')


class _Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def _send(self, status, body=b'', headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.seen.append(('GET', self.path, dict(self.headers)))
        if self.path == '/redirect':
            return self._send(302, b'', {'Location': 'https://other.example.test/'})
        if self.path == '/big':
            return self._send(200, b'x' * (3 * 1024 * 1024))
        if self.path == '/slow':
            self.send_response(200)
            self.send_header('Content-Length', '100')
            self.end_headers()
            for _ in range(100):
                self.wfile.write(b'x')
                self.wfile.flush()
                time.sleep(0.2)
            return
        return self._send(200, json.dumps({'ok': True, 'host': self.headers.get('Host')}).encode(),
                          {'Content-Type': 'application/json'})

    def do_POST(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n)
        self.server.seen.append(('POST', self.path, dict(self.headers)))
        return self._send(200, json.dumps({'received': len(body)}).encode())


class _QuietServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass   # clients that give up early (size and deadline tests) are expected


class TlsServer:
    def __init__(self, ctx: ssl.SSLContext):
        self.httpd = _QuietServer(('127.0.0.1', 0), _Handler)
        self.httpd.seen = []
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def seen(self):
        return self.httpd.seen

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def mapped_dialer(mapping, report_peer=None):
    """{validated address: local port} -> a dialer. `report_peer` overrides the reported peer address (to test
    the connected-address check)."""
    def dial(ip, port, timeout, source_address=None):
        if ip not in mapping:
            raise ConnectionRefusedError(f'no test listener for {ip}')
        sock = socket.create_connection(('127.0.0.1', mapping[ip]), timeout=timeout)
        return sock, (report_peer if report_peer is not None else ip)
    return dial


def resolver_for(answers: dict):
    """A getaddrinfo stand-in: {host: [addresses]} (mutable, so a test can change DNS between requests)."""
    def resolve(host, port, *a):
        if host not in answers:
            raise socket.gaierror(socket.EAI_NONAME, 'not found')
        out = []
        for ip in answers[host]:
            fam = socket.AF_INET6 if ':' in ip else socket.AF_INET
            out.append((fam, socket.SOCK_STREAM, 6, '', (ip, port) if fam == socket.AF_INET else (ip, port, 0, 0)))
        return out
    return resolve
