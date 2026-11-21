/**
 * Address classification — the same explicit tables as python/agit8or_connect/addresses.py, pinned for both
 * SDKs by test-vectors/addresses.json. Loopback, link-local, metadata, multicast, unspecified, broadcast and
 * reserved addresses are never a destination for Connect traffic.
 */
import { _ip } from './index.ts';

export const PUBLIC = 'public', PRIVATE = 'private', DOCUMENTATION = 'documentation';
export const ADDRESS_CATEGORIES = ['public', 'private', 'documentation', 'loopback', 'link_local', 'metadata', 'multicast',
  'unspecified', 'broadcast', 'reserved'];
export const ALWAYS_REFUSED = new Set(['loopback', 'link_local', 'metadata', 'multicast', 'unspecified', 'broadcast', 'reserved']);

export interface Addr { v: 4 | 6; addr: bigint; prefix: number }
export interface AddressInfo { address: string; category: string; via: string; refused: boolean; private: boolean }

const V4 = [
  ['169.254.169.254/32', 'metadata'], ['169.254.170.2/32', 'metadata'], ['169.254.170.23/32', 'metadata'],
  ['100.100.100.200/32', 'metadata'], ['192.0.0.192/32', 'metadata'], ['255.255.255.255/32', 'broadcast'],
  ['0.0.0.0/8', 'unspecified'], ['127.0.0.0/8', 'loopback'], ['169.254.0.0/16', 'link_local'], ['224.0.0.0/4', 'multicast'],
  ['240.0.0.0/4', 'reserved'], ['192.0.0.0/24', 'reserved'], ['192.88.99.0/24', 'reserved'], ['198.18.0.0/15', 'reserved'],
  ['192.0.2.0/24', 'documentation'], ['198.51.100.0/24', 'documentation'], ['203.0.113.0/24', 'documentation'],
  ['10.0.0.0/8', 'private'], ['172.16.0.0/12', 'private'], ['192.168.0.0/16', 'private'], ['100.64.0.0/10', 'private'],
];
const V6 = [
  ['fd00:ec2::254/128', 'metadata'], ['::/128', 'unspecified'], ['::1/128', 'loopback'], ['::/96', 'reserved'],
  ['100::/64', 'reserved'], ['64:ff9b:1::/48', 'private'], ['2001::/32', 'reserved'], ['2001:db8::/32', 'documentation'],
  ['2001::/23', 'reserved'], ['2002::/16', 'reserved'], ['3fff::/20', 'documentation'], ['5f00::/16', 'reserved'],
  ['fc00::/7', 'private'], ['fe80::/10', 'link_local'], ['fec0::/10', 'reserved'], ['ff00::/8', 'multicast'],
];

let tables: { v4: [Addr, string][]; v6: [Addr, string][]; mapped: Addr; nat64: Addr; gua: Addr } | null = null;
function t() {   // built lazily: index.ts and this module import each other
  if (!tables) {
    const n = (x: string[]): [Addr, string] => [_ip.netOf(x[0]) as Addr, x[1]];
    tables = { v4: V4.map(n), v6: V6.map(n), mapped: _ip.netOf('::ffff:0:0/96') as Addr, nat64: _ip.netOf('64:ff9b::/96') as Addr,
      gua: _ip.netOf('2000::/3') as Addr };
  }
  return tables;
}

const inNet = (a: Addr, n: Addr) => a.v === n.v && n.prefix <= a.prefix && _ip.overlaps(a, n);
const subnetOf = (a: Addr, n: Addr) => a.v === n.v && n.prefix <= a.prefix && _ip.overlaps(a, n);

/** Parse an address (brackets allowed, zone ids refused). */
export function parseAddress(value: unknown): Addr | null {
  if (typeof value !== 'string' || value.includes('%') || value.length > 64) return null;
  const s = value.replace(/^\[(.*)\]$/, '$1');
  if (!/^[0-9A-Fa-f:.]+$/.test(s)) return null;
  const v = (s.includes(':') ? 6 : 4) as 4 | 6;
  const a = v === 4 ? _ip.parseV4(s) : _ip.parseV6(s);
  return a === null ? null : { v, addr: a, prefix: v === 4 ? 32 : 128 };
}

const fmt = (a: Addr) => (a.v === 4 ? _ip.formatV4(a.addr) : _ip.formatV6(a.addr));
const v4of = (a: Addr): Addr => ({ v: 4, addr: a.addr & 0xffffffffn, prefix: 32 });

/** Canonical text; an IPv4-mapped IPv6 address becomes its IPv4 address. */
export function normalizeAddress(value: unknown): string | null {
  const a = parseAddress(value);
  if (!a) return null;
  return fmt(a.v === 6 && inNet(a, t().mapped) ? v4of(a) : a);
}

export function classifyAddress(value: unknown): AddressInfo {
  let a = parseAddress(value);
  const mk = (address: string, category: string, via = ''): AddressInfo =>
    ({ address, category, via, refused: ALWAYS_REFUSED.has(category), private: category === PRIVATE });
  if (!a) return mk(String(value).slice(0, 64), 'reserved');
  let via = '';
  if (a.v === 6 && inNet(a, t().mapped)) { a = v4of(a); via = 'mapped'; } else if (a.v === 6 && inNet(a, t().nat64)) { a = v4of(a); via = 'nat64'; }
  for (const [n, cat] of a.v === 4 ? t().v4 : t().v6) if (inNet(a, n)) return mk(fmt(a), cat, via);
  if (a.v === 6 && !inNet(a, t().gua)) return mk(fmt(a), 'reserved', via);
  return mk(fmt(a), PUBLIC, via);
}

/** The most restrictive category any address of `net` (canonical CIDR) can have. */
export function networkCategory(net: string): string {
  const n = _ip.netOf(net) as Addr;
  if (n.prefix === _ip.bits(n.v)) return classifyAddress(fmt(n)).category;
  const table = n.v === 4 ? t().v4 : t().v6;
  const hits = new Set(table.filter(([r]) => _ip.overlaps(r, n)).map(([, c]) => c));
  if (n.v === 6) {
    if (_ip.overlaps(n, t().mapped) || _ip.overlaps(n, t().nat64)) hits.add('reserved');
    if (!subnetOf(n, t().gua) && !table.some(([r]) => subnetOf(n, r))) hits.add('reserved');
  }
  for (const c of ['metadata', 'loopback', 'link_local', 'unspecified', 'broadcast', 'multicast', 'reserved', 'private']) if (hits.has(c)) return c;
  if (table.some(([r, c]) => c === DOCUMENTATION && subnetOf(n, r))) return DOCUMENTATION;
  return PUBLIC;
}

export function addressInNet(address: string, net: string): boolean {
  const a = parseAddress(address);
  return !!a && inNet(a, _ip.netOf(net) as Addr);
}
