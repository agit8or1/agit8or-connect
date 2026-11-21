/**
 * Elevated-grant approval (two distinct, freshly re-authenticated administrators bound to an immutable
 * request fingerprint) and per-action approval (`action-approval/1`) — mirrors python/agit8or_connect/approvals.py.
 * There is no single-administrator override. With `enabled: false` elevated scopes stay unavailable.
 */
import { randomUUID } from 'node:crypto';
import { ConnectError, canonicalJson, sha256Hex } from './index.ts';
import { type Catalog } from './server.ts';
import { type SqliteDatabase } from './stores.ts';

export const ACTION_APPROVAL_HEADER = 'Agit8or-Action-Approval';
export const REAUTH_MAX_AGE = 300;
export interface AdminAuth { adminId: string; reauthenticatedAt: number }
const nowS = () => Math.floor(Date.now() / 1000);
const ELEVATED = new Set(['high_risk', 'admin']);

export function classifyScopes(catalog: Catalog, scopes: Iterable<string>): { ordinary: string[]; elevated: string[] } {
  const ordinary: string[] = [], elevated: string[] = [];
  for (const name of [...new Set(scopes)].sort()) {
    const s = catalog.get(name);
    if (!s) throw new ConnectError('invalid_scope', `unknown scope ${name}`, 400);
    if (s.available === false) throw new ConnectError('invalid_scope', `scope ${name} is not available on this installation`, 400);
    (ELEVATED.has(s.risk) ? elevated : ordinary).push(name);
  }
  return { ordinary, elevated };
}

export function grantFingerprint(o: { connectionId: string; remoteInstallation: string; remoteKeyThumbprints: string[]; inboundScopes: string[];
  tenantGrants: { remote_tenant: string; local_tenant: string; scopes?: string[] }[] }): string {
  const grants = o.tenantGrants.map((g) => ({ remote_tenant: String(g.remote_tenant), local_tenant: String(g.local_tenant), scopes: [...new Set(g.scopes ?? [])].sort() }))
    .sort((a, b) => (a.remote_tenant + '\0' + a.local_tenant < b.remote_tenant + '\0' + b.local_tenant ? -1 : 1));
  return sha256Hex(canonicalJson({ v: 'agit8or-connect elevated-grant v1', connection_id: o.connectionId, remote_installation: o.remoteInstallation,
    remote_keys: [...new Set(o.remoteKeyThumbprints)].sort(), scopes: [...new Set(o.inboundScopes)].sort(), tenant_grants: grants }));
}

export interface GrantProposal { id: string; connection_id: string; fingerprint: string; scopes: string[]; proposer: string; proposed_at: number;
  proposer_auth_at: number; approver?: string | null; approved_at?: number | null; status: string; expires_at: number }

export class MemoryGrantApprovalStore {
  rows = new Map<string, GrantProposal>();
  create(p: GrantProposal) { this.rows.set(p.id, { ...p, status: 'pending' }); }
  get(id: string) { const r = this.rows.get(id); return r ? { ...r } : null; }
  approve(id: string, approver: string, fingerprint: string, now: number): boolean {
    const r = this.rows.get(id);
    if (!r || r.status !== 'pending' || r.proposer === approver || r.fingerprint !== fingerprint || r.expires_at <= now) return false;
    Object.assign(r, { status: 'approved', approver, approved_at: now }); return true;
  }
  setStatus(id: string, status: string) { const r = this.rows.get(id); if (r && r.status === 'pending') r.status = status; }
  findApproved(connectionId: string, fingerprint: string) {
    return [...this.rows.values()].filter((r) => r.connection_id === connectionId && r.fingerprint === fingerprint && r.status === 'approved')
      .sort((a, b) => (b.approved_at ?? 0) - (a.approved_at ?? 0))[0] ?? null;
  }
  invalidate(connectionId: string, keepFingerprint = '', status = 'invalidated') {
    for (const r of this.rows.values()) if (r.connection_id === connectionId && ['pending', 'approved'].includes(r.status) && r.fingerprint !== keepFingerprint) r.status = status;
  }
}

export class ElevatedGrantPolicy {
  store: MemoryGrantApprovalStore; catalog: Catalog; o: { enabled?: boolean; reauthMaxAge?: number; proposalTtl?: number; clock?: () => number; killSwitch?: () => boolean };
  constructor(store: MemoryGrantApprovalStore, catalog: Catalog, o: { enabled?: boolean; reauthMaxAge?: number; proposalTtl?: number;
    clock?: () => number; killSwitch?: () => boolean } = {}) { this.store = store; this.catalog = catalog; this.o = o; }
  private now() { return Math.floor((this.o.clock ?? nowS)()); }
  private fresh(a: AdminAuth) {
    const age = this.now() - a.reauthenticatedAt;
    if (!a.adminId || age < -60 || age > (this.o.reauthMaxAge ?? REAUTH_MAX_AGE)) throw new ConnectError('reauthentication_required', 'sign in again to approve elevated permissions', 403);
  }
  classify(scopes: Iterable<string>) {
    const r = classifyScopes(this.catalog, scopes);
    if (r.elevated.length && this.o.enabled === false) throw new ConnectError('invalid_scope', `scope ${r.elevated[0]} needs elevated approval, which this installation does not offer`, 400);
    return r;
  }
  propose(o: { connectionId: string; fingerprint: string; scopes: string[]; proposer: AdminAuth }): string {
    if (this.o.killSwitch?.()) throw new ConnectError('kill_switch', 'approvals are blocked while the kill switch is engaged', 503);
    if (!this.classify(o.scopes).elevated.length) throw new ConnectError('invalid_request', 'nothing elevated to approve', 400);
    this.fresh(o.proposer);
    this.store.invalidate(o.connectionId, o.fingerprint);
    const id = randomUUID(), now = this.now();
    this.store.create({ id, connection_id: o.connectionId, fingerprint: o.fingerprint, scopes: [...new Set(o.scopes)].sort(), proposer: o.proposer.adminId,
      proposed_at: now, proposer_auth_at: o.proposer.reauthenticatedAt, status: 'pending', expires_at: now + (this.o.proposalTtl ?? 86400) });
    return id;
  }
  approve(id: string, approver: AdminAuth, currentFingerprint: string): GrantProposal {
    if (this.o.killSwitch?.()) throw new ConnectError('kill_switch', 'approvals are blocked while the kill switch is engaged', 503);
    this.fresh(approver);
    const p = this.store.get(id);
    if (!p || p.status !== 'pending') throw new ConnectError('not_found', 'no pending elevated approval', 404);
    if (p.proposer === approver.adminId) throw new ConnectError('second_admin_required', 'a different administrator must approve elevated permissions', 403);
    if (p.fingerprint !== currentFingerprint) { this.store.setStatus(id, 'invalidated'); throw new ConnectError('approval_mismatch', 'the request changed since it was proposed; propose it again', 409); }
    if (!this.store.approve(id, approver.adminId, currentFingerprint, this.now())) throw new ConnectError('approval_mismatch', 'the approval could not be recorded', 409);
    return this.store.get(id)!;
  }
  isAuthorized(connectionId: string, fingerprint: string, scopes: string[]): boolean {
    let elevated: string[];
    try { elevated = classifyScopes(this.catalog, scopes).elevated; } catch { return false; }
    if (!elevated.length) return true;
    if (this.o.enabled === false) return false;
    const p = this.store.findApproved(connectionId, fingerprint);
    return !!p && p.proposer !== p.approver && elevated.every((s) => p.scopes.includes(s));
  }
  authorizedScopes(connectionId: string, fingerprint: string, scopes: string[]): string[] {
    const s = [...new Set(scopes)].sort();
    if (this.isAuthorized(connectionId, fingerprint, s)) return s;
    return s.filter((n) => { const sc = this.catalog.get(n); return sc && !ELEVATED.has(sc.risk); });
  }
  revoke(connectionId: string) { this.store.invalidate(connectionId, '', 'revoked'); }
}

// --- per-action approval ------------------------------------------------------------------------------

export const actionParamsDigest = (params: unknown) => sha256Hex(canonicalJson(params ?? {}));
export interface ActionRequest { id: string; connection_id: string; tenant: string; target: string; action_type: string; params_sha256: string;
  operator: string; required_scope: string; requested_at: number; expires_at: number }

export interface ActionApprovalStore {
  create(r: ActionRequest): void; get(id: string): (ActionRequest & { status: string }) | null;
  decide(id: string, approve: boolean, admin: string, now: number): boolean;
  consume(id: string, m: { connection_id: string; tenant: string; target: string; action_type: string; params_sha256: string }, now: number): boolean;
}

export class MemoryActionApprovalStore implements ActionApprovalStore {
  rows = new Map<string, ActionRequest & { status: string }>();
  create(r: ActionRequest) { this.rows.set(r.id, { ...r, status: 'pending' }); }
  get(id: string) { const r = this.rows.get(id); return r ? { ...r } : null; }
  decide(id: string, approve: boolean, admin: string, now: number) {
    const r = this.rows.get(id);
    if (!r || r.status !== 'pending' || r.operator === admin || r.expires_at <= now) return false;
    r.status = approve ? 'approved' : 'denied'; return true;
  }
  consume(id: string, m: { connection_id: string; tenant: string; target: string; action_type: string; params_sha256: string }, now: number) {
    const r = this.rows.get(id);
    if (!r || r.status !== 'approved' || r.expires_at <= now || r.connection_id !== m.connection_id || r.tenant !== m.tenant || r.target !== m.target
      || r.action_type !== m.action_type || r.params_sha256 !== m.params_sha256) return false;
    r.status = 'consumed'; return true;
  }
}

/** Same table as the Python SqlActionApprovalStore; consume() is one conditional UPDATE (single use across workers). */
export class SqliteActionApprovalStore implements ActionApprovalStore {
  s: SqliteDatabase;
  constructor(s: SqliteDatabase) { this.s = s; }
  create(r: ActionRequest) {
    this.s.tx('approval_store_unavailable', (db) => db.prepare('INSERT INTO connect_action_approval (id, connection_id, tenant, target, action_type, params_sha256, operator, required_scope, requested_at, expires_at, status, record) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(r.id, r.connection_id, r.tenant, r.target, r.action_type, r.params_sha256, r.operator, r.required_scope, r.requested_at, r.expires_at, 'pending', JSON.stringify({ target: r.target, action_type: r.action_type })));
  }
  get(id: string) { return this.s.tx('approval_store_unavailable', (db) => db.prepare('SELECT * FROM connect_action_approval WHERE id = ?').get(id) ?? null); }
  decide(id: string, approve: boolean, admin: string, now: number) {
    return this.s.tx('approval_store_unavailable', (db) => Number(db.prepare("UPDATE connect_action_approval SET status = ?, decided_by = ?, decided_at = ? WHERE id = ? AND status = 'pending' AND operator <> ? AND expires_at > ?")
      .run(approve ? 'approved' : 'denied', admin, now, id, admin, now).changes) === 1);
  }
  consume(id: string, m: { connection_id: string; tenant: string; target: string; action_type: string; params_sha256: string }, now: number) {
    return this.s.tx('approval_store_unavailable', (db) => Number(db.prepare("UPDATE connect_action_approval SET status = 'consumed', consumed_at = ? WHERE id = ? AND status = 'approved' AND expires_at > ? AND connection_id = ? AND tenant = ? AND target = ? AND action_type = ? AND params_sha256 = ?")
      .run(now, id, now, m.connection_id, m.tenant, m.target, m.action_type, m.params_sha256).changes) === 1);
  }
}

export class ActionApprovals {
  store: ActionApprovalStore; o: { ttl?: number; reauthMaxAge?: number; clock?: () => number; killSwitch?: () => boolean };
  constructor(store: ActionApprovalStore, o: { ttl?: number; reauthMaxAge?: number; clock?: () => number; killSwitch?: () => boolean } = {}) { this.store = store; this.o = o; }
  private now() { return Math.floor((this.o.clock ?? nowS)()); }
  request(o: { connectionId: string; tenant: string; target: string; actionType: string; params: unknown; operator: string; requiredScope: string }): ActionRequest {
    for (const [n, v] of [['tenant', o.tenant], ['target', o.target], ['action_type', o.actionType], ['operator', o.operator]] as const) {
      if (typeof v !== 'string' || !v || v.length > 256) throw new ConnectError('invalid_request', `${n} missing or malformed`, 400);
    }
    const now = this.now();
    const r: ActionRequest = { id: randomUUID(), connection_id: o.connectionId, tenant: o.tenant, target: o.target, action_type: o.actionType,
      params_sha256: actionParamsDigest(o.params), operator: o.operator, required_scope: o.requiredScope, requested_at: now, expires_at: now + (this.o.ttl ?? 900) };
    this.store.create(r);
    return r;
  }
  decide(id: string, approve: boolean, admin: AdminAuth) {
    if (approve && this.o.killSwitch?.()) throw new ConnectError('kill_switch', 'approvals are blocked while the kill switch is engaged', 503);
    const age = this.now() - admin.reauthenticatedAt;
    if (!admin.adminId || age < -60 || age > (this.o.reauthMaxAge ?? REAUTH_MAX_AGE)) throw new ConnectError('reauthentication_required', 'sign in again to decide on this action', 403);
    const r = this.store.get(id);
    if (!r) throw new ConnectError('not_found', 'no such action request', 404);
    if (r.operator === admin.adminId) throw new ConnectError('second_admin_required', 'the operator cannot approve their own action', 403);
    if (!this.store.decide(id, approve, admin.adminId, this.now())) throw new ConnectError('approval_mismatch', 'the action request is no longer pending', 409);
  }
  consume(id: string, o: { connectionId: string; tenant: string; target: string; actionType: string; params: unknown }) {
    if (this.o.killSwitch?.()) throw new ConnectError('kill_switch', 'actions are blocked while the kill switch is engaged', 503);
    if (!id || !this.store.consume(id, { connection_id: o.connectionId, tenant: o.tenant, target: o.target, action_type: o.actionType,
      params_sha256: actionParamsDigest(o.params) }, this.now())) throw new ConnectError('action_approval_required', 'this action needs an approval for exactly these parameters', 403);
  }
}
