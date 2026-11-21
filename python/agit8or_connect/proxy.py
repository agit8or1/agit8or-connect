"""Trusted-proxy client-address resolution (IP_ALLOWLIST_AND_BOOTSTRAP.md §1.3 step 1).

The client address a Connect endpoint checks is the TCP peer address, unless that peer is one of the
configured reverse proxies; only then are forwarding headers read, right to left, skipping further trusted
proxies. The first address that is not a trusted proxy is the client. Anything malformed, ambiguous or too long
refuses (`source_unresolved`, answered as 403 source_not_authorised) — it never falls back to "the left-most
header value" (which any client can set) or to the proxy's own address.

    resolver = TrustedProxyResolver(['10.0.0.5/32'], header='x-forwarded-for')
    client = resolver.resolve(peer_address, headers)

Configure exactly one header family: `x-forwarded-for` (with optional `x-real-ip` refused) or RFC 7239
`forwarded`. The proxy MUST overwrite or append to that header, never pass a client's value through unchanged
as the only entry (see docs/PRODUCTION_DEPLOYMENT.md for proxy snippets).
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Iterable, List, Mapping, Optional, Sequence

from . import addresses
from .errors import ConnectError

SOURCE_UNRESOLVED = 'source_unresolved'
HEADERS = ('x-forwarded-for', 'forwarded')
MAX_HOPS = 8
MAX_HEADER = 2048
_FORWARDED_FOR = re.compile(r'(?i)(?:^|;)\s*for=("?)(\[?[0-9A-Fa-f:.]+\]?(?::\d{1,5})?)\1\s*(?=;|$)')


def _err(msg: str) -> ConnectError:
    return ConnectError(SOURCE_UNRESOLVED, msg, 403)


def _addr(text: str):
    """One address from a header element: brackets and a port are allowed, zone ids and names are not."""
    t = text.strip().strip('"')
    if t.startswith('['):
        end = t.find(']')
        if end < 0:
            raise _err('malformed forwarded address')
        t = t[1:end]
    elif t.count(':') == 1:                 # IPv4 with port
        t = t.split(':', 1)[0]
    a = addresses.parse(t)
    if a is None:
        raise _err('forwarded element is not an IP address')
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return a


@dataclass
class TrustedProxyResolver:
    trusted: Sequence[str] = ()
    header: str = 'x-forwarded-for'
    max_hops: int = MAX_HOPS

    def __post_init__(self):
        if self.header not in HEADERS:
            raise ValueError(f'header must be one of {HEADERS}')
        nets = []
        for t in self.trusted:
            n = ipaddress.ip_network(t, strict=True)
            if n.prefixlen < (16 if n.version == 4 else 32):
                raise ValueError(f'trusted proxy range {t} is too broad')
            nets.append(n)
        self._nets = nets

    def is_trusted(self, a) -> bool:
        return any(a.version == n.version and a in n for n in self._nets)

    def _chain(self, headers: Mapping[str, str]) -> List:
        lower = {k.lower(): v for k, v in headers.items()}
        raw = lower.get(self.header)
        if raw is None:
            return []
        if isinstance(raw, (list, tuple)):
            raw = ','.join(raw)
        if len(raw) > MAX_HEADER:
            raise _err('forwarding header too long')
        elements = [e for e in raw.split(',')]
        if len(elements) > self.max_hops:
            raise _err('too many forwarding hops')
        out = []
        for e in elements:
            if not e.strip():
                raise _err('empty forwarding element')
            if self.header == 'forwarded':
                m = _FORWARDED_FOR.search(e.strip())
                if not m:
                    raise _err('Forwarded element without a usable for= address')
                out.append(_addr(m.group(2)))
            else:
                out.append(_addr(e))
        return out

    def resolve(self, peer_address: str, headers: Mapping[str, str]) -> str:
        peer = addresses.parse(peer_address)
        if peer is None:
            raise _err('peer address unreadable')
        if peer.version == 6 and peer.ipv4_mapped is not None:
            peer = peer.ipv4_mapped
        if not self.is_trusted(peer):
            return str(peer)                 # direct client: headers are ignored, whatever they say
        chain = self._chain(headers)
        if not chain:
            raise _err('request came through a trusted proxy without a forwarding header')
        for a in reversed(chain):
            if not self.is_trusted(a):
                return str(a)
        raise _err('every forwarded address is a trusted proxy')


def resolve_client_address(peer_address: str, headers: Mapping[str, str],
                           resolver: Optional[TrustedProxyResolver] = None) -> str:
    """Without a resolver the TCP peer address is the client address (no header is ever read)."""
    if resolver is None:
        a = addresses.normalize(peer_address)
        if a is None:
            raise _err('peer address unreadable')
        return a
    return resolver.resolve(peer_address, headers)
