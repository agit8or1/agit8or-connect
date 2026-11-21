"""GuardedTransport: the outbound HTTPS client every Connect request of a connection goes through.

    transport = GuardedTransport(destination_store, connection_id)
    response = transport.request('POST', url, headers, body)

For every request, in this order (IP_ALLOWLIST_AND_BOOTSTRAP.md §4):

  1. Load the connection's ApprovedDestination from the policy. Missing, unreadable, corrupt or
     inconsistent -> `destination_policy_unavailable` (503). `security_blocked` -> refused.
  2. The URL: https only, no user info, no fragment; host and port EQUAL to the approved destination.
  3. Resolve the host once (bounded time). Every answer is classified (addresses.py): loopback,
     link-local, metadata, multicast, unspecified, broadcast and reserved addresses are refused
     (`blocked_destination`) whatever the policy says; every answer must be covered by an approved
     entry valid now, and a private answer only by an entry approved as private. One answer outside
     the policy refuses the whole request (`destination_changed`, with evidence) — mixed public/private
     answers and DNS changes between requests are caught here.
  4. Connect to a validated address (never re-resolving), then check the socket's actual peer address
     is that address.
  5. TLS >= 1.2, certificate chain and host name (or IP SAN) always verified against the system CAs or,
     when the destination has one, ONLY its private CA. There is no switch to turn this off.
  6. After the handshake and before any request byte: SPKI pins (when configured) -> `spki_mismatch`;
     certificate expiry inside the warning window -> a warning on the response and `on_warning`.
  7. Send; no redirects are followed (a 3xx is returned as is); no proxy is used and proxy environment
     variables are ignored (the socket is opened by this code); request and response bodies are capped;
     one deadline covers resolution, connect, handshake, send and the whole response.

`preview_destination()` performs steps 3–6 without an HTTP request and without a policy, for the
administrator's "approve destination" screen; its result is the input to `destinations.new_destination`.
"""
from __future__ import annotations

import base64
import concurrent.futures
import datetime
import hashlib
import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import addresses
from .destinations import (ApprovedDestination, BLOCKED, DestinationPolicy, SECURITY_BLOCKED, normalize_host,
                           unavailable)
from .errors import (BLOCKED_DESTINATION, CERT_NAME_MISMATCH, ConnectError, DESTINATION_CHANGED, SPKI_MISMATCH,
                     TOO_LARGE, TRANSPORT)
from .http import Response

CERTIFICATE_INVALID = 'certificate_invalid'
DEADLINE_EXCEEDED = 'deadline_exceeded'
DEFAULT_MAX_RESPONSE = 2 * 1024 * 1024
DEFAULT_MAX_REQUEST = 1024 * 1024
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_TOTAL_TIMEOUT = 15.0
EXPIRY_WARNING_DAYS = 21
_FORBIDDEN_HEADERS = {'host', 'proxy-authorization', 'proxy-connection', 'transfer-encoding', 'connection',
                      'content-length'}
_RESOLVER_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix='agit8or-dns')


def spki_sha256(cert_der: bytes) -> str:
    """base64url SHA-256 of the certificate's SubjectPublicKeyInfo (the SPKI pin format)."""
    cert = x509.load_der_x509_certificate(cert_der)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.urlsafe_b64encode(hashlib.sha256(spki).digest()).decode('ascii').rstrip('=')


def certificate_details(cert_der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(cert_der)
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(v) for v in san.get_values_for_type(x509.DNSName)] + \
            [str(v) for v in san.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []
    not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else \
        cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return {'subject': cert.subject.rfc4514_string()[:256], 'issuer': cert.issuer.rfc4514_string()[:256],
            'sans': sans[:32], 'not_after': int(not_after.timestamp()), 'spki_sha256': spki_sha256(cert_der),
            'serial': format(cert.serial_number, 'x')[:64]}


def _tls_context(ca_pem: Optional[str]) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=ca_pem) if ca_pem else \
        ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.options |= ssl.OP_NO_COMPRESSION
    return ctx


def default_dialer(ip: str, port: int, timeout: float, source_address: Optional[str] = None):
    """Open a TCP connection to exactly `ip`; return (socket, the peer address the kernel reports)."""
    src = (source_address, 0) if source_address else None
    sock = socket.create_connection((ip, port), timeout=timeout, source_address=src)
    return sock, sock.getpeername()[0]


class _Deadline:
    def __init__(self, seconds: float, clock=time.monotonic):
        self.clock = clock
        self.end = clock() + seconds

    def left(self) -> float:
        r = self.end - self.clock()
        if r <= 0:
            raise ConnectError(DEADLINE_EXCEEDED, 'the request did not complete in time', 504)
        return r


def _resolve(resolver, host: str, port: int, deadline: _Deadline) -> List[str]:
    ip = addresses.parse(host)
    if ip is not None:
        return [str(ip)]
    fut = _RESOLVER_POOL.submit(resolver, host, port, 0, socket.SOCK_STREAM)
    try:
        infos = fut.result(timeout=deadline.left())
    except concurrent.futures.TimeoutError as e:
        raise ConnectError(TRANSPORT, f'{host} did not resolve in time', 504) from e
    except (socket.gaierror, OSError) as e:
        raise ConnectError(TRANSPORT, f'{host} did not resolve', 502) from e
    out: List[str] = []
    for info in infos:
        a = addresses.normalize(info[4][0])
        if a is None:
            raise ConnectError(BLOCKED_DESTINATION, f'{host} resolved to a malformed address', 502)
        if a not in out:
            out.append(a)
    if not out:
        raise ConnectError(TRANSPORT, f'{host} did not resolve', 502)
    return out


def _tls_error(e: Exception, host: str) -> ConnectError:
    if isinstance(e, ssl.SSLCertVerificationError):
        msg = (getattr(e, 'verify_message', '') or str(e)).lower()
        if getattr(e, 'verify_code', None) == 62 or 'hostname mismatch' in msg or "doesn't match" in msg or \
                'ip address mismatch' in msg:
            return ConnectError(CERT_NAME_MISMATCH, f'the certificate is not valid for {host}', 502)
        return ConnectError(CERTIFICATE_INVALID, f'the certificate of {host} did not verify', 502)
    return ConnectError(TRANSPORT, f'TLS handshake with {host} failed ({e.__class__.__name__})', 502)


@dataclass
class _Connected:
    sock: ssl.SSLSocket
    address: str
    certificate: dict
    warnings: List[str] = field(default_factory=list)


def _connect(*, host: str, port: int, candidates: List[str], ctx: ssl.SSLContext, deadline: _Deadline,
             connect_timeout: float, dialer, source_address: Optional[str], pins: Tuple[str, ...],
             now: float, warn_days: int) -> _Connected:
    last: Optional[Exception] = None
    for ip in candidates:
        try:
            raw, peer = dialer(ip, port, min(connect_timeout, deadline.left()), source_address)
        except ConnectError:
            raise
        except OSError as e:
            last = e
            continue
        if addresses.normalize(peer) != ip:
            raw.close()
            raise ConnectError(BLOCKED_DESTINATION, 'the connected peer is not the validated address', 502)
        try:
            raw.settimeout(deadline.left())
            tls = ctx.wrap_socket(raw, server_hostname=host)
        except (ssl.SSLError, ssl.CertificateError) as e:
            raw.close()
            raise _tls_error(e, host) from e
        except OSError as e:
            raw.close()
            last = e
            continue
        der = tls.getpeercert(binary_form=True)
        if not der:
            tls.close()
            raise ConnectError(CERTIFICATE_INVALID, 'no peer certificate', 502)
        details = certificate_details(der)
        if pins and details['spki_sha256'] not in pins:
            tls.close()
            raise ConnectError(SPKI_MISMATCH, f'the certificate key of {host} is not one of the pinned keys', 502)
        warnings = []
        if details['not_after'] - now < warn_days * 86400:
            days = max(0, int((details['not_after'] - now) // 86400))
            warnings.append(f'certificate_expiring: the certificate of {host} expires in {days} day(s)')
        return _Connected(tls, ip, details, warnings)
    if isinstance(last, socket.timeout):
        raise ConnectError(TRANSPORT, f'{host} did not accept a connection in time', 504) from last
    raise ConnectError(TRANSPORT, f'{host} could not be reached ({last.__class__.__name__ if last else "no address"})',
                       502) from last


class GuardedTransport:
    """See the module docstring. One instance per connection; safe to reuse across requests (it keeps
    no connection open and re-reads the policy on every request)."""

    def __init__(self, policy: DestinationPolicy, connection_id: str, *,
                 max_response_bytes: int = DEFAULT_MAX_RESPONSE, max_request_bytes: int = DEFAULT_MAX_REQUEST,
                 connect_timeout: float = DEFAULT_CONNECT_TIMEOUT, total_timeout: float = DEFAULT_TOTAL_TIMEOUT,
                 resolver=socket.getaddrinfo, clock: Callable[[], float] = time.time,
                 expiry_warning_days: int = EXPIRY_WARNING_DAYS, source_address: Optional[str] = None,
                 on_warning: Optional[Callable[[str, str], None]] = None, _dialer=None):
        if policy is None or not connection_id:
            raise ValueError('GuardedTransport needs a destination policy and a connection id')
        self.policy = policy
        self.connection_id = connection_id
        self.max_response_bytes = max_response_bytes
        self.max_request_bytes = max_request_bytes
        self.connect_timeout = connect_timeout
        self.total_timeout = total_timeout
        self.resolver = resolver
        self.clock = clock
        self.expiry_warning_days = expiry_warning_days
        self.source_address = source_address
        self.on_warning = on_warning
        # Test seam only: maps a validated address to a socket (the integration harness maps documentation
        # addresses to local listeners). The validation above it is unchanged.
        self._dialer = _dialer or default_dialer
        self._contexts: Dict[str, ssl.SSLContext] = {}

    def _destination(self) -> ApprovedDestination:
        try:
            dest = self.policy.get(self.connection_id)
        except ConnectError:
            raise
        except Exception as e:  # noqa: BLE001 — any storage failure fails closed
            raise unavailable(f'approved destination could not be loaded ({e.__class__.__name__})') from e
        if not isinstance(dest, ApprovedDestination):
            raise unavailable('approved destination policy returned no record')
        try:
            dest.validate()
        except ConnectError as e:
            raise unavailable(f'approved destination invalid: {e.message}') from e
        if dest.connection_id != self.connection_id:
            raise unavailable('approved destination belongs to another connection')
        if dest.state == BLOCKED:
            raise ConnectError(SECURITY_BLOCKED, 'this connection is security blocked: an administrator must '
                                                 'review the destination change', 403)
        return dest

    def _context(self, dest: ApprovedDestination) -> ssl.SSLContext:
        key = hashlib.sha256((dest.ca_pem or '').encode()).hexdigest()
        if key not in self._contexts:
            try:
                self._contexts[key] = _tls_context(dest.ca_pem)
            except ssl.SSLError as e:
                raise unavailable('the private CA of this destination could not be loaded') from e
        return self._contexts[key]

    def check_addresses(self, dest: ApprovedDestination, resolved: List[str], now: int) -> List[str]:
        """Validate every resolved address; refuse the whole set if any one is not acceptable."""
        out = []
        for a in resolved:
            info = addresses.classify(a)
            if info.refused:
                raise ConnectError(BLOCKED_DESTINATION, f'{dest.host} resolves to a {info.category} address, '
                                                        'which is never allowed', 502)
            dial = addresses.normalize(a) or info.address   # NAT64 stays IPv6 on the wire; mapped -> IPv4
            entry = dest.match(dial, now) or dest.match(info.address, now)
            if entry is None or (info.private and not entry.private):
                err = ConnectError(DESTINATION_CHANGED, f'{dest.host} resolves to an address that is not approved '
                                                        'for this connection', 502)
                err.evidence = {'code': DESTINATION_CHANGED, 'host': dest.host, 'port': dest.port,
                                'approved': [x.net for x in dest.addresses if x.valid_at(now)],
                                'observed': resolved, 'at': now}
                raise err
            out.append(dial)
        return out

    def request(self, method: str, url: str, headers: Optional[dict] = None,
                body: Optional[bytes] = None) -> Response:
        deadline = _Deadline(self.total_timeout)
        dest = self._destination()
        p = urlsplit(url)
        if p.scheme != 'https':
            raise ConnectError(BLOCKED_DESTINATION, 'only https is allowed', 400)
        if p.username is not None or p.password is not None or p.fragment:
            raise ConnectError(BLOCKED_DESTINATION, 'URL must not carry user info or a fragment', 400)
        try:
            host = normalize_host(p.hostname or '')
            port = p.port or 443
        except (ConnectError, ValueError) as e:
            raise ConnectError(BLOCKED_DESTINATION, 'URL host or port malformed', 400) from e
        if host != dest.host or port != dest.port:
            raise ConnectError(BLOCKED_DESTINATION, 'URL is not on the approved destination of this connection', 400)
        if body is not None and len(body) > self.max_request_bytes:
            raise ConnectError(TOO_LARGE, 'request body too large', 413)
        hdrs = {}
        for k, v in (headers or {}).items():
            if k.lower() in _FORBIDDEN_HEADERS or '\n' in str(k) + str(v) or '\r' in str(k) + str(v):
                raise ConnectError(BLOCKED_DESTINATION, f'header {k} may not be set', 400)
            hdrs[k] = v
        now = self.clock()
        candidates = self.check_addresses(dest, _resolve(self.resolver, host, port, deadline), int(now))
        conn = _connect(host=host, port=port, candidates=candidates, ctx=self._context(dest), deadline=deadline,
                        connect_timeout=self.connect_timeout, dialer=self._dialer,
                        source_address=self.source_address, pins=dest.spki_pins, now=now,
                        warn_days=self.expiry_warning_days)
        for w in conn.warnings:
            if self.on_warning:
                try:
                    self.on_warning(self.connection_id, w)
                except Exception:  # noqa: BLE001 — a warning hook never breaks a request
                    pass
        return self._exchange(conn, method, host, port, p, hdrs, body, deadline)

    def _exchange(self, conn: _Connected, method, host, port, p, headers, body, deadline) -> Response:
        path = (p.path or '/') + (f'?{p.query}' if p.query else '')
        hc = http.client.HTTPSConnection(f'[{host}]' if ':' in host else host, port, timeout=deadline.left())
        hc.sock = _KeepOpen(conn.sock)   # connected, verified and pinned; http.client never reconnects it
        try:
            conn.sock.settimeout(deadline.left())
            hc.putrequest(method.upper(), path, skip_accept_encoding=True)
            for k, v in headers.items():
                hc.putheader(k, v)
            hc.putheader('Connection', 'close')
            if body is not None:
                hc.putheader('Content-Length', str(len(body)))
            hc.endheaders(body)
            conn.sock.settimeout(deadline.left())
            r = hc.getresponse()
            chunks, total = [], 0
            while True:
                conn.sock.settimeout(deadline.left())
                chunk = r.read1(65536)        # one receive at most, so the deadline is checked in between
                if not chunk:
                    break
                total += len(chunk)
                if total > self.max_response_bytes:
                    raise ConnectError(TOO_LARGE, 'response too large', 502)
                chunks.append(chunk)
            resp = Response(r.status, {k: v for k, v in r.getheaders()}, b''.join(chunks))
            resp.peer_address = conn.address
            resp.certificate = conn.certificate
            resp.warnings = list(conn.warnings)
            return resp
        except ConnectError:
            raise
        except socket.timeout as e:
            raise ConnectError(DEADLINE_EXCEEDED, 'the request did not complete in time', 504) from e
        except (OSError, http.client.HTTPException) as e:
            raise ConnectError(TRANSPORT, f'{host} could not be reached ({e.__class__.__name__})', 502) from e
        finally:
            hc.close()
            try:
                conn.sock.close()
            except OSError:
                pass


class _KeepOpen:
    """http.client closes its socket as soon as a `Connection: close` response starts; the body is still to
    be read under our deadline, so the real socket is closed by GuardedTransport, not by http.client."""

    def __init__(self, sock):
        self._sock = sock

    def close(self):
        pass

    def __getattr__(self, name):
        return getattr(self._sock, name)


@dataclass
class DestinationPreview:
    host: str
    port: int
    addresses: List[dict]
    certificate: dict
    warnings: List[str]

    def as_dict(self) -> dict:
        return {'host': self.host, 'port': self.port, 'addresses': self.addresses, 'certificate': self.certificate,
                'warnings': self.warnings}


def preview_destination(url: str, *, ca_pem: Optional[str] = None, resolver=socket.getaddrinfo,
                        timeout: float = DEFAULT_TOTAL_TIMEOUT, clock=time.time, _dialer=None) -> DestinationPreview:
    """Resolve and TLS-handshake (no HTTP request) for the administrator's approval screen. Refused
    address classes are never contacted. Every address is handshaken; a certificate that does not verify
    for the host is an error, not a preview. Approving private addresses stays an explicit decision."""
    p = urlsplit(url)
    if p.scheme != 'https' or p.username or p.password or not p.hostname:
        raise ConnectError(BLOCKED_DESTINATION, 'an https URL with a host is required', 400)
    host = normalize_host(p.hostname)
    port = p.port or 443
    deadline = _Deadline(timeout)
    resolved = _resolve(resolver, host, port, deadline)
    infos = [addresses.classify(a) for a in resolved]
    refused = [i for i in infos if i.refused]
    if refused:
        raise ConnectError(BLOCKED_DESTINATION, f'{host} resolves to a {refused[0].category} address, which is '
                                                'never allowed', 502)
    ctx = _tls_context(ca_pem)
    certs, warnings = [], []
    for i in infos:
        c = _connect(host=host, port=port, candidates=[i.address], ctx=ctx, deadline=deadline,
                     connect_timeout=DEFAULT_CONNECT_TIMEOUT, dialer=_dialer or default_dialer, source_address=None,
                     pins=(), now=clock(), warn_days=EXPIRY_WARNING_DAYS)
        c.sock.close()
        certs.append(c.certificate)
        warnings.extend(w for w in c.warnings if w not in warnings)
    spkis = {c['spki_sha256'] for c in certs}
    if len(spkis) > 1:
        warnings.append('different_certificates: the addresses present different certificate keys')
    return DestinationPreview(host, port, [{'address': i.address, 'category': i.category,
                                            'private': i.private} for i in infos], certs[0], warnings)
