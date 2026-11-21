/**
 * P1 host helpers, mirroring Python: trusted-proxy client address (proxy.py), dpop-nonce/1 and actor/1
 * (extensions.py), audit checkpoints and export verification (audit.py). Pinned by
 * test-vectors/extensions.json and test-vectors/audit-checkpoint.json.
 */
import { createHmac, timingSafeEqual, type KeyObject } from 'node:crypto';
import { ConnectError, GENESIS, verifyChain, verifyCompact } from './index.ts';
import { normalizeAddress, addressInNet } from './addresses.ts';
import { _ip } from './index.ts';

// --- trusted proxy -------------------------------------------------------------------------------------

const unresolved = (m: string) => new ConnectError('source_unresolved', m, 403);

function fwdAddr(text: string): string {
  let t = text.trim().replace(/^"|"$/g, '');
  if (t.startsWith('[')) { const end = t.indexOf(']'); if (end < 0) throw unresolved('malformed forwarded address'); t = t.slice(1, end); }
  else if ((t.match(/:/g) ?? []).length === 1) t = t.split(':')[0];
  const n = normalizeAddress(t);
  if (!n || t.includes('%')) throw unresolved('forwarded element is not an IP address');
  return n;
}

export class TrustedProxyResolver {
  nets: string[]; header: 'x-forwarded-for' | 'forwarded'; maxHops: number;
  constructor(trusted: string[], header: 'x-forwarded-for' | 'forwarded' = 'x-forwarded-for', maxHops = 8) {
    for (const t of trusted) {
      const n = _ip.netOf(t);
      if (n.prefix < (n.v === 4 ? 16 : 32)) throw new Error(`trusted proxy range ${t} is too broad`);
    }
    this.nets = trusted; this.header = header; this.maxHops = maxHops;
  }
  isTrusted(a: string): boolean { return this.nets.some((n) => addressInNet(a, n)); }
  resolve(peerAddress: string, headers: Record<string, string | string[] | undefined>): string {
    const peer = normalizeAddress(peerAddress);
    if (!peer) throw unresolved('peer address unreadable');
    if (!this.isTrusted(peer)) return peer;
    const entry = Object.entries(headers).find(([k]) => k.toLowerCase() === this.header);
    const raw = entry ? (Array.isArray(entry[1]) ? entry[1].join(',') : String(entry[1] ?? '')) : undefined;
    if (raw === undefined) throw unresolved('request came through a trusted proxy without a forwarding header');
    if (raw.length > 2048) throw unresolved('forwarding header too long');
    const els = raw.split(',');
    if (els.length > this.maxHops) throw unresolved('too many forwarding hops');
    const chain = els.map((e) => {
      if (!e.trim()) throw unresolved('empty forwarding element');
      if (this.header === 'forwarded') {
        const m = /(?:^|;)\s*for=("?)(\[?[0-9A-Fa-f:.]+\]?(?::\d{1,5})?)\1\s*(?=;|$)/i.exec(e.trim());
        if (!m) throw unresolved('Forwarded element without a usable for= address');
        return fwdAddr(m[2]);
      }
      return fwdAddr(e);
    });
    for (let i = chain.length - 1; i >= 0; i--) if (!this.isTrusted(chain[i])) return chain[i];
    throw unresolved('every forwarded address is a trusted proxy');
  }
}

// --- dpop-nonce/1 -------------------------------------------------------------------------------------

export const USE_DPOP_NONCE = 'use_dpop_nonce';
export const DPOP_NONCE_HEADER = 'DPoP-Nonce';
export const HARDENING_EXTENSIONS: Record<string, number[]> = { 'dpop-nonce': [1], actor: [1], 'action-approval': [1] };

export class NonceIssuer {
  secret: Buffer; window: number; clock: () => number;
  constructor(secret: Buffer, o: { window?: number; clock?: () => number } = {}) {
    if (secret.length < 32) throw new Error('nonce secret must be at least 32 bytes');
    this.secret = secret; this.window = o.window ?? 300; this.clock = o.clock ?? (() => Date.now() / 1000);
  }
  private mac(context: string, index: bigint): Buffer {
    const idx = Buffer.alloc(8); idx.writeBigUInt64BE(index);
    return createHmac('sha256', this.secret).update(Buffer.concat([Buffer.from(`dpop-nonce/1\n${context}\n`), idx])).digest().subarray(0, 16);
  }
  issue(context: string): string {
    const index = BigInt(Math.floor(Math.floor(this.clock()) / this.window));
    const idx = Buffer.alloc(8); idx.writeBigUInt64BE(index);
    return Buffer.concat([idx, this.mac(context, index)]).toString('base64url');
  }
  valid(nonce: unknown, context: string): boolean {
    if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{32,64}$/.test(nonce)) return false;
    const raw = Buffer.from(nonce, 'base64url');
    if (raw.length !== 24) return false;
    const index = raw.readBigUInt64BE(0);
    const now = BigInt(Math.floor(Math.floor(this.clock()) / this.window));
    if (index !== now && index !== now - 1n) return false;
    return timingSafeEqual(raw.subarray(8), this.mac(context, index));
  }
  check(nonce: unknown, context: string): void {
    if (!this.valid(nonce, context)) {
      const e = new ConnectError(USE_DPOP_NONCE, 'a fresh DPoP nonce is required', 401) as ConnectError & { dpopNonce?: string };
      e.dpopNonce = this.issue(context);
      throw e;
    }
  }
}

// --- actor/1 -------------------------------------------------------------------------------------------

const ACTOR_RE = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
export function validateActor(sub: unknown): string {
  if (typeof sub !== 'string' || !ACTOR_RE.test(sub)) throw new ConnectError('invalid_actor', 'actor must be an opaque id of 1-128 characters [A-Za-z0-9._:-]', 400);
  return sub;
}
export function actorOf(claims: Record<string, unknown>, negotiated: Record<string, number>): string | null {
  const act = claims.act as Record<string, unknown> | undefined;
  if (act === undefined || act === null) return null;
  if (negotiated.actor !== 1) throw new ConnectError('invalid_token', 'actor tokens were not negotiated for this connection', 401);
  if (typeof act !== 'object' || Object.keys(act).some((k) => k !== 'sub')) throw new ConnectError('invalid_token', 'actor claim malformed', 401);
  try { return validateActor(act.sub); } catch { throw new ConnectError('invalid_token', 'actor claim malformed', 401); }
}

// --- audit checkpoints and exports ----------------------------------------------------------------

export const TYP_CHECKPOINT = 'audit-checkpoint+jwt';
const HEX64 = /^[0-9a-f]{64}$/;

export function verifyCheckpoint(token: string, key: KeyObject, issuer: string): { iss: string; seq: number; hash: string; iat: number } {
  const c = verifyCompact(token, key, { typ: TYP_CHECKPOINT, issuer, required: ['iss', 'seq', 'hash', 'iat'] }) as any;
  if (!Number.isInteger(c.seq) || c.seq < 1 || !HEX64.test(String(c.hash))) throw new ConnectError('invalid_request', 'checkpoint claims malformed', 400);
  return c;
}

export interface AuditEntry { seq: number; record: unknown; prev_hash: string; hash: string }
export function verifyAuditExport(bundle: any, key: KeyObject, issuer: string, knownCheckpoints: { seq: number; hash: string }[] = []): { seq: number; hash: string; count: number } {
  const bad = (m: string) => new ConnectError('audit_invalid', m, 400);
  if (!bundle || bundle.format !== 'agit8or-connect-audit-export/1') throw bad('not an audit export');
  if (bundle.issuer !== issuer) throw bad('export from another installation');
  const entries: AuditEntry[] = bundle.entries ?? [];
  if (!entries.length) throw bad('empty export');
  const seq0 = bundle.start_seq;
  if (!Number.isInteger(seq0) || seq0 < 1) throw bad('start_seq malformed');
  const startPrev = bundle.start_prev ?? GENESIS;
  if (seq0 === 1 && startPrev !== GENESIS) throw bad('an export from the start must begin at the genesis hash');
  entries.forEach((e, i) => { if (e.seq !== seq0 + i) throw bad(`entry ${i} out of sequence`); });
  const broken = verifyChain(entries, startPrev);
  if (broken !== null) throw bad(`chain broken at seq ${seq0 + broken}`);
  let cp;
  try { cp = verifyCheckpoint(bundle.checkpoint ?? '', key, issuer); } catch { throw bad('checkpoint does not verify'); }
  const last = entries[entries.length - 1];
  if (cp.seq !== last.seq || cp.hash !== last.hash) throw bad('export does not end at its signed checkpoint');
  const bySeq = new Map(entries.map((e) => [e.seq, e.hash]));
  for (const k of knownCheckpoints) {
    if (bySeq.has(k.seq) && bySeq.get(k.seq) !== k.hash) throw bad(`history differs from the published checkpoint at seq ${k.seq}`);
    if (seq0 - 1 === k.seq && startPrev !== k.hash) throw bad('export does not continue from the published checkpoint');
  }
  return { seq: last.seq, hash: last.hash, count: entries.length };
}

