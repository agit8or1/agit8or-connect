"""Address classification shared by the outbound transport, the source policy and Quick Connect.

The tables below are explicit (IANA special-purpose registries, cloud metadata endpoints) so the result
does not depend on the Python version: `ipaddress.is_global` / `is_private` changed between 3.11 and
3.13, and the SDK must classify an address the same way everywhere (and the same way as the TypeScript
SDK, which carries the same tables; `test-vectors/addresses.json` pins both).

Categories
----------
public          globally routable unicast
private         RFC 1918, CGNAT 100.64/10, IPv6 ULA fc00::/7, local-use NAT64 64:ff9b:1::/48 —
                reachable only as an explicit, administrator-approved private entry
documentation   192.0.2/24, 198.51.100/24, 203.0.113/24, 2001:db8::/32, 3fff::/20 — not routable; treated
                like public for approval (they appear in tests and examples)
loopback, link_local, metadata, multicast, unspecified, broadcast, reserved
                ALWAYS refused for outbound Connect traffic, whatever any setting says

IPv4-mapped (::ffff:a.b.c.d) and well-known NAT64 (64:ff9b::/96) addresses are classified by the IPv4
address they carry. 6to4 (2002::/16), Teredo (2001::/32), IPv4-compatible (::/96), site-local
(fec0::/10) and SRv6 SIDs (5f00::/16) are `reserved`: they are deprecated or tunnel encodings whose real
destination is not the address itself.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional, Union

PUBLIC, PRIVATE, DOCUMENTATION = 'public', 'private', 'documentation'
LOOPBACK, LINK_LOCAL, METADATA, MULTICAST = 'loopback', 'link_local', 'metadata', 'multicast'
UNSPECIFIED, BROADCAST, RESERVED = 'unspecified', 'broadcast', 'reserved'
CATEGORIES = (PUBLIC, PRIVATE, DOCUMENTATION, LOOPBACK, LINK_LOCAL, METADATA, MULTICAST, UNSPECIFIED,
              BROADCAST, RESERVED)
# Never a destination for Connect traffic.
ALWAYS_REFUSED = frozenset((LOOPBACK, LINK_LOCAL, METADATA, MULTICAST, UNSPECIFIED, BROADCAST, RESERVED))

_N = ipaddress.ip_network

# Order matters: the first matching (most specific) entry wins.
_V4 = (
    (_N('169.254.169.254/32'), METADATA), (_N('169.254.170.2/32'), METADATA),
    (_N('169.254.170.23/32'), METADATA), (_N('100.100.100.200/32'), METADATA),
    (_N('192.0.0.192/32'), METADATA),
    (_N('255.255.255.255/32'), BROADCAST),
    (_N('0.0.0.0/8'), UNSPECIFIED),
    (_N('127.0.0.0/8'), LOOPBACK),
    (_N('169.254.0.0/16'), LINK_LOCAL),
    (_N('224.0.0.0/4'), MULTICAST),
    (_N('240.0.0.0/4'), RESERVED),
    (_N('192.0.0.0/24'), RESERVED),
    (_N('192.88.99.0/24'), RESERVED),
    (_N('198.18.0.0/15'), RESERVED),
    (_N('192.0.2.0/24'), DOCUMENTATION), (_N('198.51.100.0/24'), DOCUMENTATION),
    (_N('203.0.113.0/24'), DOCUMENTATION),
    (_N('10.0.0.0/8'), PRIVATE), (_N('172.16.0.0/12'), PRIVATE), (_N('192.168.0.0/16'), PRIVATE),
    (_N('100.64.0.0/10'), PRIVATE),
)
_V6 = (
    (_N('fd00:ec2::254/128'), METADATA),
    (_N('::/128'), UNSPECIFIED),
    (_N('::1/128'), LOOPBACK),
    (_N('::/96'), RESERVED),                 # IPv4-compatible (deprecated)
    (_N('100::/64'), RESERVED),              # discard-only
    (_N('64:ff9b:1::/48'), PRIVATE),         # local-use NAT64
    (_N('2001::/32'), RESERVED),             # Teredo
    (_N('2001:db8::/32'), DOCUMENTATION),
    (_N('2001::/23'), RESERVED),             # IETF protocol assignments
    (_N('2002::/16'), RESERVED),             # 6to4 (deprecated)
    (_N('3fff::/20'), DOCUMENTATION),
    (_N('5f00::/16'), RESERVED),             # SRv6 SIDs
    (_N('fc00::/7'), PRIVATE),
    (_N('fe80::/10'), LINK_LOCAL),
    (_N('fec0::/10'), RESERVED),             # site-local (deprecated)
    (_N('ff00::/8'), MULTICAST),
)
_MAPPED = _N('::ffff:0:0/96')
_NAT64 = _N('64:ff9b::/96')
_GLOBAL_UNICAST_V6 = _N('2000::/3')

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass(frozen=True)
class AddressInfo:
    address: str            # normalised text (IPv4-mapped shown as the IPv4 address)
    category: str
    via: str = ''           # 'mapped' or 'nat64' when classified through an embedded IPv4 address

    @property
    def refused(self) -> bool:
        return self.category in ALWAYS_REFUSED

    @property
    def private(self) -> bool:
        return self.category == PRIVATE


def parse(value) -> Optional[IPAddress]:
    """An address object, or None. Zone ids (fe80::1%eth0) are refused."""
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        addr = value
    else:
        if not isinstance(value, str) or '%' in value or len(value) > 64:
            return None
        try:
            addr = ipaddress.ip_address(value.strip('[]'))
        except ValueError:
            return None
    if addr.version == 6 and addr.scope_id:
        return None
    return addr


def normalize(value) -> Optional[str]:
    """Canonical text; an IPv4-mapped IPv6 address becomes the IPv4 address it carries (dual-stack
    sockets report IPv4 peers that way)."""
    addr = parse(value)
    if addr is None:
        return None
    if addr.version == 6 and addr in _MAPPED:
        return str(addr.ipv4_mapped)
    return str(addr)


def classify(value) -> AddressInfo:
    addr = parse(value)
    if addr is None:
        return AddressInfo(str(value)[:64], RESERVED)
    via = ''
    if addr.version == 6 and addr in _MAPPED:
        addr, via = addr.ipv4_mapped, 'mapped'
    elif addr.version == 6 and addr in _NAT64:
        addr, via = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF), 'nat64'
    table = _V4 if addr.version == 4 else _V6
    for net, cat in table:
        if addr in net:
            return AddressInfo(str(addr), cat, via)
    if addr.version == 6 and addr not in _GLOBAL_UNICAST_V6:
        return AddressInfo(str(addr), RESERVED, via)
    return AddressInfo(str(addr), PUBLIC, via)


def network_category(net) -> str:
    """The most restrictive category any address of `net` can have: a network that overlaps a refused
    range is refused, one that overlaps a private range is private."""
    n = net if isinstance(net, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else \
        ipaddress.ip_network(net, strict=False)
    if n.num_addresses == 1:
        return classify(n.network_address).category
    table = _V4 if n.version == 4 else _V6
    hits = {cat for rng, cat in table if rng.overlaps(n)}
    if n.version == 6:
        if n.overlaps(_MAPPED) or n.overlaps(_NAT64):
            hits.add(RESERVED)       # a range spanning embedded-IPv4 encodings is never acceptable
        if not n.subnet_of(_GLOBAL_UNICAST_V6) and not any(n.subnet_of(rng) for rng, _ in table):
            hits.add(RESERVED)
    for cat in (METADATA, LOOPBACK, LINK_LOCAL, UNSPECIFIED, BROADCAST, MULTICAST, RESERVED, PRIVATE):
        if cat in hits:
            return cat
    if any(c == DOCUMENTATION and n.subnet_of(rng) for rng, c in table):
        return DOCUMENTATION
    return PUBLIC


def is_refused(value) -> bool:
    return classify(value).refused
