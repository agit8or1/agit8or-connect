/**
 * Server-side helpers missing from the original TypeScript SDK (audit F-13): the scope catalog with risk
 * tiers and authenticateResourceRequest (DPoP-bound access token + proof for one API call), mirroring
 * python/agit8or_connect/scopes.py and tokens.authenticate_resource_request.
 */
import { ConnectError, verifyAccessToken, verifyDpopProof, unverifiedPayload, type ReplayStore, type KeyRing } from './index.ts';
import { type KeyObject } from 'node:crypto';

export const RISKS = ['read', 'write', 'high_risk', 'admin'];
const SCOPE_RE = /^[a-z][a-z0-9_]{0,31}:[a-z][a-z0-9_]{0,31}$/;
export interface Scope { name: string; description: string; risk: string; available?: boolean; events?: string[] }

export class Catalog {
  byName: Map<string, Scope>;
  scopes: Scope[];
  constructor(scopes: Scope[]) {
    this.scopes = scopes;
    for (const s of scopes) {
      if (!SCOPE_RE.test(s.name)) throw new Error(`bad scope name ${s.name}`);
      if (!RISKS.includes(s.risk)) throw new Error(`bad risk ${s.risk}`);
    }
    this.byName = new Map(scopes.map((s) => [s.name, s]));
  }
  get(name: string): Scope | undefined { return this.byName.get(name); }
  elevated(names: Iterable<string>): string[] { return [...new Set(names)].filter((n) => { const s = this.byName.get(n); return s && (s.risk === 'high_risk' || s.risk === 'admin'); }).sort(); }
  defaultSet(): string[] { return this.scopes.filter((s) => s.available !== false && s.risk === 'read').map((s) => s.name); }
  checkKnown(names: Iterable<string>): string[] {
    const ns = [...new Set(names)].sort();
    const unknown = ns.find((n) => !this.byName.has(n));
    if (unknown) throw new ConnectError('invalid_scope', `unknown scope ${unknown}`, 400);
    return ns;
  }
  asList() { return this.scopes.map((s) => ({ scope: s.name, description: s.description, risk: s.risk, available: s.available !== false, ...(s.events?.length ? { events: s.events } : {}) })); }
}

type KeySource = KeyRing | ((kid: string) => KeyObject | undefined);

/** Authenticate one API call (`Authorization: DPoP <token>` + `DPoP: <proof>`). `tokenKeysFor(clientId)` returns
 * OUR keys that may have signed tokens for that connection, or an empty ring for an unknown / inactive one.
 * The caller then checks the connection is active, tokens_not_before, and intersects scopes with what is granted NOW. */
export function authenticateResourceRequest(o: { authorization: string; dpop: string; method: string; url: string; issuer: string;
  tokenKeysFor: (clientId: string) => KeySource | undefined; replay: ReplayStore; now?: number }): { claims: Record<string, unknown>; clientId: string } {
  const [scheme, token] = (o.authorization ?? '').split(' ', 2);
  if (scheme !== 'DPoP' || !token) {
    if (scheme === 'Bearer') throw new ConnectError('invalid_token', 'bearer tokens are not accepted; use DPoP', 401);
    throw new ConnectError('invalid_token', 'missing access token', 401);
  }
  let clientId = '';
  try { clientId = String(unverifiedPayload(token).client_id ?? ''); } catch { /* */ }
  if (!clientId) throw new ConnectError('invalid_token', 'malformed access token', 401);
  const claims = verifyAccessToken(token, o.tokenKeysFor(clientId) ?? new Map(), { issuer: o.issuer, now: o.now });
  verifyDpopProof(o.dpop, { method: o.method, url: o.url, replay: o.replay, now: o.now, accessToken: token, expectedJkt: (claims.cnf as { jkt: string }).jkt });
  return { claims, clientId };
}
