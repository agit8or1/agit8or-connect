/**
 * Persistent stores on SQLite (node:sqlite, built into Node >= 22.13; no npm dependency) and shared rate
 * limits. The tables and statements are the same as python/agit8or_connect/storage, so a Python and a
 * TypeScript worker can share one database file. For several hosts use PostgreSQL with the same SQL (see
 * the Python PostgresBackend); this SDK takes any object implementing the store interfaces.
 *
 * Every storage failure throws a `*_unavailable` ConnectError (503): callers refuse the request.
 */
import { createHash } from 'node:crypto';
import { ConnectError, type ReplayStore } from './index.ts';
import { type ApprovedDestination, type DestinationPolicy, destinationDigest, destinationRecord, destinationUnavailable,
  loadCheckedDestination, sanitizeEvidence, validateDestination } from './destinations.ts';

export const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS connect_replay (namespace TEXT NOT NULL, key TEXT NOT NULL, expires_at BIGINT NOT NULL, PRIMARY KEY (namespace, key))',
  'CREATE INDEX IF NOT EXISTS connect_replay_expiry ON connect_replay (expires_at)',
  'CREATE TABLE IF NOT EXISTS connect_ratelimit (bucket TEXT NOT NULL, window_start BIGINT NOT NULL, count BIGINT NOT NULL, expires_at BIGINT NOT NULL, PRIMARY KEY (bucket, window_start))',
  'CREATE TABLE IF NOT EXISTS connect_destination (connection_id TEXT PRIMARY KEY, version BIGINT NOT NULL, record TEXT NOT NULL, digest TEXT NOT NULL, updated_at BIGINT NOT NULL)',
  'CREATE TABLE IF NOT EXISTS connect_action_approval (id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, tenant TEXT NOT NULL, target TEXT NOT NULL, action_type TEXT NOT NULL, params_sha256 TEXT NOT NULL, operator TEXT NOT NULL, required_scope TEXT NOT NULL, requested_at BIGINT NOT NULL, expires_at BIGINT NOT NULL, status TEXT NOT NULL, decided_by TEXT, decided_at BIGINT, consumed_at BIGINT, record TEXT NOT NULL)',
];

type Db = { exec(sql: string): void; prepare(sql: string): { run(...a: unknown[]): { changes: number | bigint }; get(...a: unknown[]): any; all(...a: unknown[]): any[] }; close(): void };

/** One SQLite database (WAL, synchronous=FULL, busy timeout). */
export class SqliteDatabase {
  db: Db;
  constructor(path: string, busyTimeoutMs = 5000) {
    const { DatabaseSync } = (process as any).getBuiltinModule('node:sqlite');
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA busy_timeout=${Math.floor(busyTimeoutMs)}`);
    this.db.exec('PRAGMA journal_mode=WAL');
    this.db.exec('PRAGMA synchronous=FULL');
  }
  migrate(): void { for (const s of SCHEMA) this.db.exec(s); }
  tx<T>(code: string, fn: (db: Db) => T): T {
    try {
      this.db.exec('BEGIN IMMEDIATE');
      try { const r = fn(this.db); this.db.exec('COMMIT'); return r; } catch (e) { try { this.db.exec('ROLLBACK'); } catch { /* */ } throw e; }
    } catch (e) {
      if (e instanceof ConnectError) throw e;
      throw new ConnectError(code, `storage unavailable (${(e as Error).name})`, 503);
    }
  }
  close(): void { this.db.close(); }
}

export const MAX_REPLAY_TTL = 8 * 86400;
const nowS = () => Math.floor(Date.now() / 1000);

export class SqliteReplayStore implements ReplayStore {
  s: SqliteDatabase; clock: () => number;
  constructor(s: SqliteDatabase, clock: () => number = nowS) { this.s = s; this.clock = clock; }
  add(namespace: string, key: string, expiresAt: number): boolean {
    if (!namespace || !key || namespace.length > 64 || key.length > 512) throw new ConnectError('invalid_request', 'replay key malformed', 400);
    const now = Math.floor(this.clock());
    const exp = Math.min(Math.floor(expiresAt), now + MAX_REPLAY_TTL);
    return this.s.tx('replay_store_unavailable', (db) => Number(db.prepare('INSERT INTO connect_replay (namespace, key, expires_at) VALUES (?, ?, ?) ' +
      'ON CONFLICT (namespace, key) DO UPDATE SET expires_at = excluded.expires_at WHERE connect_replay.expires_at <= ?').run(namespace, key, exp, now).changes) === 1);
  }
  purge(limit = 10000): number {
    const now = Math.floor(this.clock());
    return this.s.tx('replay_store_unavailable', (db) => Number(db.prepare('DELETE FROM connect_replay WHERE (namespace, key) IN (SELECT namespace, key FROM connect_replay WHERE expires_at <= ? LIMIT ?)').run(now, limit).changes));
  }
}

/** Bounded in-memory replay store for one process (tests, development). Pruned as time passes. */
export class BoundedMemoryReplayStore implements ReplayStore {
  seen = new Map<string, number>(); last = 0;
  clock: () => number; maxEntries: number;
  constructor(clock: () => number = nowS, maxEntries = 100000) { this.clock = clock; this.maxEntries = maxEntries; }
  add(namespace: string, key: string, expiresAt: number): boolean {
    const now = this.clock();
    if (now - this.last > 60 || this.seen.size > this.maxEntries) {
      for (const [k, v] of this.seen) if (v <= now) this.seen.delete(k);
      this.last = now;
      if (this.seen.size > this.maxEntries) throw new ConnectError('replay_store_unavailable', 'replay store full', 503);
    }
    const k = `${namespace}\u0000${key}`;
    const prev = this.seen.get(k);
    if (prev !== undefined && prev > now) return false;
    this.seen.set(k, Math.min(expiresAt, now + MAX_REPLAY_TTL));
    return true;
  }
}

// --- rate limits ------------------------------------------------------------------------------------

export interface RateLimitStore { hit(bucket: string, windowStart: number, window: number, amount?: number): number; get(bucket: string, windowStart: number): number }

export class MemoryRateLimitStore implements RateLimitStore {
  c = new Map<string, number>();
  hit(b: string, w: number, _win: number, amount = 1) { const k = `${b}|${w}`; const n = (this.c.get(k) ?? 0) + amount; this.c.set(k, n); return n; }
  get(b: string, w: number) { return this.c.get(`${b}|${w}`) ?? 0; }
}

export class SqliteRateLimitStore implements RateLimitStore {
  s: SqliteDatabase;
  constructor(s: SqliteDatabase) { this.s = s; }
  hit(bucket: string, windowStart: number, window: number, amount = 1): number {
    return this.s.tx('rate_limit_unavailable', (db) => Number(db.prepare('INSERT INTO connect_ratelimit (bucket, window_start, count, expires_at) VALUES (?, ?, ?, ?) ' +
      'ON CONFLICT (bucket, window_start) DO UPDATE SET count = connect_ratelimit.count + excluded.count RETURNING count').get(bucket, windowStart, amount, windowStart + 2 * window).count));
  }
  get(bucket: string, windowStart: number): number {
    return this.s.tx('rate_limit_unavailable', (db) => Number(db.prepare('SELECT count FROM connect_ratelimit WHERE bucket = ? AND window_start = ?').get(bucket, windowStart)?.count ?? 0));
  }
}

export interface RateRule { limit: number; window: number; description?: string }
export const DEFAULT_RATE_RULES: Record<string, RateRule> = {
  'pairing.address': { limit: 10, window: 600 }, 'pairing.global': { limit: 100, window: 600 },
  'pairing.failed_code.address': { limit: 10, window: 3600 }, 'qc.review.admin': { limit: 20, window: 3600 },
  'qc.exchange.address': { limit: 20, window: 600 }, 'token.connection': { limit: 120, window: 60 },
  'token.failure': { limit: 20, window: 300 }, 'auth.failure': { limit: 30, window: 300 },
  'auth.failure.address': { limit: 200, window: 300 }, 'signature.invalid': { limit: 20, window: 300 },
  'api.connection': { limit: 600, window: 60 }, 'admin.approval': { limit: 30, window: 3600 },
};

export const bucketKey = (rule: string, ...parts: string[]) => `${rule}:${createHash('sha256').update(parts.join('\x1f')).digest('hex').slice(0, 32)}`;

/** Shared, sliding-window limits. FAIL CLOSED: a store failure throws rate_limit_unavailable (503). */
export class RateLimiter {
  rules: Record<string, RateRule>;
  store: RateLimitStore; clock: () => number;
  constructor(store: RateLimitStore, rules?: Record<string, RateRule>, clock: () => number = () => Date.now() / 1000) { this.store = store; this.clock = clock; this.rules = { ...(rules ?? DEFAULT_RATE_RULES) }; }
  private estimate(name: string, parts: string[], add: number) {
    const rule = this.rules[name];
    if (!rule) throw new ConnectError('rate_limit_unavailable', `no rate-limit rule ${name}`, 503);
    const now = this.clock(), w = rule.window, start = Math.floor(now) - (Math.floor(now) % w), b = bucketKey(name, ...parts);
    let cur: number, prev: number;
    try { cur = add ? this.store.hit(b, start, w, add) : this.store.get(b, start); prev = this.store.get(b, start - w); } catch {
      throw new ConnectError('rate_limit_unavailable', 'rate-limit store unavailable', 503);
    }
    const est = cur + prev * Math.max(0, (w - (now - start)) / w);
    return { est, rule, retryAfter: Math.max(1, Math.ceil(w - (now - start))) };
  }
  private limited(retryAfter: number) { const e = new ConnectError('rate_limited', 'too many requests; try again later', 429) as ConnectError & { retryAfter?: number }; e.retryAfter = retryAfter; return e; }
  hit(name: string, ...parts: string[]) { const r = this.estimate(name, parts, 1); return { allowed: r.est <= r.rule.limit, count: r.est, retryAfter: r.retryAfter }; }
  check(name: string, ...parts: string[]) { const r = this.estimate(name, parts, 1); if (r.est > r.rule.limit) throw this.limited(r.retryAfter); return r.est; }
  ensureBelow(name: string, ...parts: string[]) { const r = this.estimate(name, parts, 0); if (r.est >= r.rule.limit) throw this.limited(r.retryAfter); return r.est; }
}

// --- approved destinations --------------------------------------------------------------------------

export class SqliteDestinationStore implements DestinationPolicy {
  s: SqliteDatabase;
  constructor(s: SqliteDatabase) { this.s = s; }
  put(d: ApprovedDestination, expectedVersion?: number): ApprovedDestination {
    validateDestination(d);
    const rec = JSON.stringify(destinationRecord(d));
    return this.s.tx('destination_policy_unavailable', (db) => {
      const row = db.prepare('SELECT version FROM connect_destination WHERE connection_id = ?').get(d.connection_id);
      const cur = row ? Number(row.version) : undefined;
      if (expectedVersion !== undefined && cur !== expectedVersion) throw new ConnectError('conflict', 'destination changed concurrently', 409);
      if (cur !== undefined && (d.version ?? 1) <= cur) throw new ConnectError('conflict', 'destination version must increase', 409);
      if (row) db.prepare('UPDATE connect_destination SET version = ?, record = ?, digest = ?, updated_at = ? WHERE connection_id = ? AND version = ?').run(d.version ?? 1, rec, destinationDigest(d), nowS(), d.connection_id, cur);
      else db.prepare('INSERT INTO connect_destination (connection_id, version, record, digest, updated_at) VALUES (?, ?, ?, ?, ?)').run(d.connection_id, d.version ?? 1, rec, destinationDigest(d), nowS());
      return d;
    });
  }
  get(connectionId: string): ApprovedDestination {
    const row = this.s.tx('destination_policy_unavailable', (db) => db.prepare('SELECT record, digest FROM connect_destination WHERE connection_id = ?').get(connectionId));
    if (!row) throw destinationUnavailable('no approved destination for this connection');
    let rec: unknown;
    try { rec = JSON.parse(row.record); } catch { throw destinationUnavailable('approved destination record is corrupt'); }
    return loadCheckedDestination(rec, row.digest, connectionId);
  }
  block(connectionId: string, evidence: Record<string, unknown>): ApprovedDestination {
    const d = this.get(connectionId);
    if (d.state === 'security_blocked') return d;
    return this.put({ ...d, state: 'security_blocked', version: (d.version ?? 1) + 1, evidence: sanitizeEvidence(evidence) }, d.version);
  }
}
