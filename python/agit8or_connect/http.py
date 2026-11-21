"""Transport interface, the Response type, and the legacy address-class-only transport.

For connection traffic use `transport.GuardedTransport`: it enforces the connection's APPROVED
DESTINATION (host, port, addresses, CA, SPKI pins). `MinimalGuardedTransport` below only decides whether
an address CLASS is acceptable; it does not pin a connection to its approved addresses and is kept for
backward compatibility and for read-only checks (it is not sufficient for a production host).

The SDK never opens a socket except through a Transport:

    transport.request(method, url, headers=dict, body=bytes|None) -> Response

`default_transport()` returns MinimalGuardedTransport. A host application
can pass its own Transport (for example one backed by its existing guarded
HTTP client) wherever the SDK takes one. MinimalGuardedTransport:

  * accepts https only,
  * resolves the host ONCE, refuses if ANY address is not allowed, and
    connects to the validated IP literal so DNS cannot rebind between check
    and connect. Loopback, link-local, unspecified, metadata and
    non-unicast addresses are ALWAYS refused (PROTOCOL.md §4); private
    ranges (RFC1918, CGNAT, IPv6 ULA) only when the operator explicitly
    allowed private networks for the connection. (``allow_loopback_http``
    is accepted for compatibility and no longer permits anything.)
  * verifies TLS (system store or a configured private CA bundle; minimum
    TLS 1.2; hostname checked) — there is no switch to turn it off,
  * never follows redirects, ignores proxies, caps the body and the time.
"""
from __future__ import annotations

import http.client
import socket
import time
import ssl
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol
from urllib.parse import urlsplit

from . import addresses
from .errors import BLOCKED_DESTINATION, ConnectError, TOO_LARGE, TRANSPORT

DEFAULT_MAX_BYTES = 2 * 1024 * 1024
DEFAULT_TIMEOUT = 10.0

@dataclass
class Response:
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b''
    peer_address: str = ''                       # set by GuardedTransport
    certificate: Optional[dict] = None           # sanitised peer certificate details (GuardedTransport)
    warnings: List[str] = field(default_factory=list)

    def header(self, name: str) -> str:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return ''


class Transport(Protocol):
    def request(self, method: str, url: str, headers: Optional[dict] = None,
                body: Optional[bytes] = None) -> Response: ...


def ip_allowed(ip: str, allow_private: bool) -> bool:
    """Address-class check (addresses.py tables, identical on every Python version): public addresses
    are allowed; private ones (RFC 1918, CGNAT, ULA, local-use NAT64) only with `allow_private`;
    loopback, link-local, metadata, multicast, unspecified, broadcast, reserved and documentation
    addresses never. IPv4-mapped and NAT64 addresses are judged by the IPv4 address they carry."""
    info = addresses.classify(ip)
    if info.category == addresses.PUBLIC:
        return True
    return bool(allow_private) and info.category == addresses.PRIVATE


class MinimalGuardedTransport:
    def __init__(self, *, allow_private: bool = False, ca_pem: Optional[str] = None,
                 max_bytes: int = DEFAULT_MAX_BYTES, timeout: float = DEFAULT_TIMEOUT,
                 allow_loopback_http: bool = False, resolver=socket.getaddrinfo,
                 max_request_bytes: int = 1024 * 1024, total_timeout: Optional[float] = None):
        self.allow_private = allow_private
        self.max_request_bytes = max_request_bytes
        # One deadline over the whole request (default 3 x the per-operation timeout), so a peer that
        # drips one byte per socket timeout cannot hold a worker indefinitely.
        self.total_timeout = total_timeout if total_timeout is not None else 3 * timeout
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.allow_loopback_http = allow_loopback_http
        self.resolver = resolver
        ctx = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        self.context = ctx

    def _resolve(self, host: str, port: int):
        try:
            infos = self.resolver(host, port, 0, socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise ConnectError(TRANSPORT, f'{host} did not resolve', 502) from e
        ips = []
        for info in infos:
            ip = info[4][0]
            if not ip_allowed(ip, self.allow_private):
                raise ConnectError(BLOCKED_DESTINATION, f'{host} resolves to an address this connection may not '
                                                        'use (enable private networks for this connection to '
                                                        'reach an internal address)', 502)
            if ip not in ips:
                ips.append(ip)
        if not ips:
            raise ConnectError(TRANSPORT, f'{host} did not resolve', 502)
        return ips

    def request(self, method, url, headers=None, body=None) -> Response:
        p = urlsplit(url)
        host = p.hostname or ''
        if p.username or p.password or not host:
            raise ConnectError(BLOCKED_DESTINATION, 'URL must have a host and no credentials', 400)
        if p.scheme == 'https':
            port = p.port or 443
        else:
            raise ConnectError(BLOCKED_DESTINATION, 'only https is allowed', 400)
        if body is not None and len(body) > self.max_request_bytes:
            raise ConnectError(TOO_LARGE, 'request body too large', 413)
        end = time.monotonic() + self.total_timeout
        ips = self._resolve(host, port)
        path = (p.path or '/') + (f'?{p.query}' if p.query else '')
        transport = self
        opened = []

        class _Conn(http.client.HTTPSConnection if p.scheme == 'https' else http.client.HTTPConnection):
            def connect(self_inner):
                sock = socket.create_connection((ips[0], port), transport.timeout)
                peer = sock.getpeername()[0]
                if peer not in ips:
                    sock.close()
                    raise ConnectError(BLOCKED_DESTINATION, 'connected peer is not the validated address', 502)
                if p.scheme == 'https':
                    sock = transport.context.wrap_socket(sock, server_hostname=host)
                opened.append(sock)
                self_inner.sock = sock

        kwargs = {'timeout': self.timeout}
        if p.scheme == 'https':
            kwargs['context'] = self.context
        conn = _Conn(host, port, **kwargs)
        try:
            conn.request(method, path, body=body, headers=dict(headers or {}))
            r = conn.getresponse()
            chunks, total = [], 0
            while True:
                left = end - time.monotonic()
                if left <= 0:
                    raise ConnectError(TRANSPORT, f'{host} did not answer in time', 504)
                opened[0].settimeout(min(self.timeout, left))
                chunk = r.read1(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_bytes:
                    raise ConnectError(TOO_LARGE, 'response too large', 502)
                chunks.append(chunk)
            return Response(r.status, {k: v for k, v in r.getheaders()}, b''.join(chunks))
        except ConnectError:
            raise
        except ssl.SSLError as e:
            raise ConnectError(TRANSPORT, f'TLS verification failed for {host} ({e.__class__.__name__})', 502) from e
        except (OSError, http.client.HTTPException) as e:
            raise ConnectError(TRANSPORT, f'{host} could not be reached ({e.__class__.__name__})', 502) from e
        finally:
            conn.close()


def default_transport(**kwargs) -> Transport:
    return MinimalGuardedTransport(**kwargs)
