/**
 * Approved outbound destinations — mirrors python/agit8or_connect/destinations.py. The record serialises to
 * the same canonical JSON, so both SDKs compute the same integrity digest for the same record and can share
 * one `connect_destination` table (SqliteDestinationStore in stores.ts).
 *
 * Fail closed: a missing, corrupt (digest mismatch) or inconsistent record refuses with
 * `destination_policy_unavailable` (503); a `security_blocked` destination refuses with `security_blocked`.
 */
import { ConnectError, canonicalJson, sha256Hex, _ip } from './index.ts';
import { ALWAYS_REFUSED, classifyAddress, networkCategory, normalizeAddress, parseAddress, addressInNet } from './addresses.ts';

export const DESTINATION_POLICY_UNAVAILABLE = 'destination_policy_unavailable';
export const SECURITY_BLOCKED = 'security_blocked';
export const MAX_DESTINATION_ADDRESSES = 16;
export const MIN_RANGE_PREFIX = { 4: 24, 6: 48 } as const;
export const MAX_MIGRATION_OVERLAP = 7 * 86400;
const HOST_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const PIN_RE = /^[A-Za-z0-9_-]{43}$/;

export interface ApprovedAddress { net: string; private?: boolean; not_before?: number; not_after?: number; note?: string }
export interface ApprovedDestination {
  connection_id: string; host: string; port: number; addresses: ApprovedAddress[]; ca_pem?: string; spki_pins?: string[];
  expected_installation_id?: string; state?: 'active' | 'security_blocked'; version?: number; approved_by?: string[];
  approved_at?: number; evidence?: Record<string, unknown>;
}
export interface DestinationPolicy { get(connectionId: string): ApprovedDestination | Promise<ApprovedDestination> }

const bad = (msg: string) => new ConnectError('invalid_destination', msg, 400);
export const destinationUnavailable = (msg = 'approved destination unavailable') => new ConnectError(DESTINATION_POLICY_UNAVAILABLE, msg, 503);

export function normalizeHost(host: string): string {
  if (typeof host !== 'string' || !host) throw bad('destination host missing');
  let h = host.trim().toLowerCase();
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1);
  const ip = parseAddress(h);
  if (ip) {
    if (ip.v === 6 && classifyAddress(h).via === 'mapped') throw bad('IPv4-mapped host literal not accepted');
    return ip.v === 4 ? _ip.formatV4(ip.addr) : _ip.formatV6(ip.addr);
  }
  if (!/^[\x00-\x7f]*$/.test(h) || !HOST_RE.test(h) || h === 'localhost' || h.endsWith('.localhost')) throw bad('destination host malformed or not allowed');
  return h;
}

const isInt = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v);

export function checkApprovedAddress(a: ApprovedAddress): ApprovedAddress {
  let n;
  try { n = _ip.netOf(a.net); } catch { throw bad('approved address malformed'); }
  const canon = `${n.v === 4 ? _ip.formatV4(n.addr) : _ip.formatV6(n.addr)}/${n.prefix}`;
  if (canon !== a.net) throw bad('approved address is not canonical');
  if (n.prefix < _ip.bits(n.v) && n.prefix < MIN_RANGE_PREFIX[n.v]) throw bad(`approved range too broad (at most /${MIN_RANGE_PREFIX[n.v]})`);
  const cat = networkCategory(a.net);
  if (ALWAYS_REFUSED.has(cat)) throw bad(`${a.net} is a ${cat} address and can never be a destination`);
  if (cat === 'private' && !a.private) throw bad(`${a.net} is private: it must be approved explicitly as a private address`);
  if (cat !== 'private' && a.private) throw bad(`${a.net} is not private but is marked private (inconsistent record)`);
  for (const x of [a.not_before, a.not_after]) if (x !== undefined && x !== null && (!isInt(x) || x < 0)) throw bad('address validity times must be integers');
  if (isInt(a.not_before) && isInt(a.not_after) && a.not_after <= a.not_before) throw bad('address validity window is empty');
  return a;
}

export function validateDestination(d: ApprovedDestination): ApprovedDestination {
  if (!d || typeof d.connection_id !== 'string' || !d.connection_id || d.connection_id.length > 128) throw bad('destination connection id malformed');
  if (normalizeHost(d.host) !== d.host) throw bad('destination host is not normalised');
  if (!isInt(d.port) || d.port < 1 || d.port > 65535) throw bad('destination port malformed');
  if (!Array.isArray(d.addresses) || d.addresses.length < 1 || d.addresses.length > MAX_DESTINATION_ADDRESSES) throw bad('a destination needs 1 to 16 approved addresses');
  const seen = new Set<string>();
  for (const a of d.addresses) {
    checkApprovedAddress(a);
    const k = `${a.net}|${a.not_before ?? ''}|${a.not_after ?? ''}`;
    if (seen.has(k)) throw bad('approved address listed twice');
    seen.add(k);
  }
  if (parseAddress(d.host) && !d.addresses.some((a) => addressInNet(d.host, a.net))) throw bad('an IP-literal destination must be one of its approved addresses');
  for (const p of d.spki_pins ?? []) if (typeof p !== 'string' || !PIN_RE.test(p)) throw bad('SPKI pin malformed (base64url SHA-256)');
  if (d.ca_pem !== undefined && d.ca_pem !== null && (typeof d.ca_pem !== 'string' || !d.ca_pem.includes('BEGIN CERTIFICATE'))) throw bad('private CA must be PEM certificates');
  if (![undefined, 'active', 'security_blocked'].includes(d.state)) throw bad('destination state unknown');
  if (d.version !== undefined && (!isInt(d.version) || d.version < 1)) throw bad('destination version malformed');
  return d;
}

/** The record as Python's ApprovedDestination.as_dict() writes it (for the shared digest). */
export function destinationRecord(d: ApprovedDestination): Record<string, unknown> {
  const out: Record<string, unknown> = {
    connection_id: d.connection_id, host: d.host, port: d.port,
    addresses: d.addresses.map((a) => {
      const x: Record<string, unknown> = { net: a.net, private: !!a.private };
      if (a.not_before !== undefined && a.not_before !== null) x.not_before = a.not_before;
      if (a.not_after !== undefined && a.not_after !== null) x.not_after = a.not_after;
      if (a.note) x.note = a.note;
      return x;
    }),
    spki_pins: [...(d.spki_pins ?? [])], expected_installation_id: d.expected_installation_id ?? '', state: d.state ?? 'active',
    version: d.version ?? 1, approved_by: [...(d.approved_by ?? [])], approved_at: d.approved_at ?? 0,
  };
  if (d.ca_pem !== undefined && d.ca_pem !== null) out.ca_pem = d.ca_pem;
  if (d.evidence !== undefined && d.evidence !== null) out.evidence = d.evidence;
  return out;
}

export const destinationDigest = (d: ApprovedDestination) => sha256Hex(canonicalJson(destinationRecord(d)));

export function newDestination(connectionId: string, host: string, port: number, approved: (string | ApprovedAddress)[],
  o: { caPem?: string; spkiPins?: string[]; expectedInstallationId?: string; approvedBy?: string[]; now?: number } = {}): ApprovedDestination {
  const addresses = approved.map((a) => {
    if (typeof a !== 'string') return { ...a };
    const n = _ip.netOf(a);
    return { net: `${n.v === 4 ? _ip.formatV4(n.addr) : _ip.formatV6(n.addr)}/${n.prefix}`, private: false };
  });
  return validateDestination({
    connection_id: connectionId, host: normalizeHost(host), port, addresses, ca_pem: o.caPem, spki_pins: o.spkiPins ?? [],
    expected_installation_id: o.expectedInstallationId ?? '', state: 'active', version: 1, approved_by: o.approvedBy ?? [],
    approved_at: Math.floor(o.now ?? Date.now() / 1000),
  });
}

/** The approved entry covering `address` at `now`, or null. */
export function matchDestination(d: ApprovedDestination, address: string, now: number): ApprovedAddress | null {
  const norm = normalizeAddress(address);
  if (!norm) return null;
  for (const a of d.addresses) {
    const valid = (a.not_before === undefined || a.not_before === null || now >= a.not_before) && (a.not_after === undefined || a.not_after === null || now < a.not_after);
    if (valid && addressInNet(norm, a.net)) return a;
  }
  return null;
}

export function loadCheckedDestination(record: unknown, digest: string, connectionId: string): ApprovedDestination {
  let d: ApprovedDestination;
  try { d = validateDestination(record as ApprovedDestination); } catch (e) {
    throw destinationUnavailable(`approved destination record invalid: ${(e as Error).message}`);
  }
  if (d.connection_id !== connectionId) throw destinationUnavailable('approved destination record belongs to another connection');
  if (destinationDigest(d) !== digest) throw destinationUnavailable('approved destination record failed its integrity check');
  return d;
}

const EVIDENCE_KEYS = ['code', 'host', 'port', 'approved', 'observed', 'connected', 'certificate', 'at', 'message'];
export function sanitizeEvidence(e: Record<string, unknown> | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of EVIDENCE_KEYS) {
    const v = e?.[k];
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) out[k] = v.slice(0, 32).map((x) => String(x).slice(0, 128));
    else if (typeof v === 'number' || typeof v === 'boolean') out[k] = v;
    else if (typeof v === 'object') {
      const o: Record<string, unknown> = {};
      for (const [kk, vv] of Object.entries(v as Record<string, unknown>).slice(0, 16)) {
        if (Array.isArray(vv)) { if (kk === 'sans') o.sans = vv.slice(0, 32).map((s) => String(s).slice(0, 128)); }
        else if (vv === null || typeof vv !== 'object') o[kk.slice(0, 64)] = typeof vv === 'number' || typeof vv === 'boolean' ? vv : String(vv).slice(0, 256);
      }
      out[k] = o;
    } else out[k] = String(v).slice(0, 256);
  }
  return out;
}

export class MemoryDestinationStore implements DestinationPolicy {
  rows = new Map<string, { record: Record<string, unknown>; digest: string }>();
  put(d: ApprovedDestination, expectedVersion?: number): ApprovedDestination {
    validateDestination(d);
    const cur = this.rows.get(d.connection_id);
    if (expectedVersion !== undefined && (cur?.record.version ?? undefined) !== expectedVersion) throw new ConnectError('conflict', 'destination changed concurrently', 409);
    this.rows.set(d.connection_id, { record: destinationRecord(d), digest: destinationDigest(d) });
    return d;
  }
  get(connectionId: string): ApprovedDestination {
    const r = this.rows.get(connectionId);
    if (!r) throw destinationUnavailable('no approved destination for this connection');
    return loadCheckedDestination(structuredClone(r.record), r.digest, connectionId);
  }
  block(connectionId: string, evidence: Record<string, unknown>): ApprovedDestination {
    const d = this.get(connectionId);
    return this.put({ ...d, state: 'security_blocked', version: (d.version ?? 1) + 1, evidence: sanitizeEvidence(evidence) }, d.version);
  }
}
