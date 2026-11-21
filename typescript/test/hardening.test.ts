// Hardening modules: address vectors, approved destinations, the guarded transport over real TLS on
// 127.0.0.1 (test-only CA in test/fixtures/tls), SQLite stores, rate limits, approvals, key envelope.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { createServer, type Server } from 'node:https';
import { X509Certificate } from 'node:crypto';
import type { AddressInfo as NetAddressInfo } from 'node:net';
import * as c from '../src/index.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const DIR = process.env.AGIT8OR_CONNECT_VECTORS ?? join(HERE, '..', '..', 'test-vectors');
const load = (n: string) => JSON.parse(readFileSync(join(DIR, n), 'utf8'));
const fx = (n: string) => readFileSync(join(HERE, 'fixtures', 'tls', n), 'utf8');
const codeOf = async (fn: () => unknown) => { try { await fn(); return 'ok'; } catch (e) { if (e instanceof c.ConnectError) return e.code; throw e; } };

test('addresses: vectors shared with the Python SDK', () => {
  const v = load('addresses.json');
  for (const a of v.addresses) {
    const info = c.classifyAddress(a.input);
    assert.equal(info.category, a.category, a.input);
    assert.equal(info.refused, a.outbound_refused, a.input);
    assert.equal(info.via, a.via, a.input);
    assert.equal(c.normalizeAddress(a.input), a.normalized, a.input);
  }
  for (const n of v.approved_networks) {
    const r = (() => { try { c.checkApprovedAddress({ net: n.net, private: n.private }); return true; } catch (e) { return (e as c.ConnectError).code; } })();
    assert.equal(r === true, n.valid, n.net);
    if (!n.valid) assert.equal(r, n.error, n.net);
  }
});

test('F-18: IPv4-mapped sources match IPv4 declarations', () => {
  assert.ok(c.sourceInEgress('::ffff:203.0.113.10', [{ net: '203.0.113.10/32' }]));
  assert.ok(c.sourceInEgress('::ffff:cb00:710a', [{ net: '203.0.113.0/24' }]));
  assert.ok(!c.sourceInEgress('::ffff:203.0.113.11', [{ net: '203.0.113.10/32' }]));
});

test('destinations: digest matches Python, tampering fails closed', () => {
  const vec = load('addresses.json').destination;
  assert.equal(c.destinationDigest(c.validateDestination(vec.record)), vec.digest, 'same digest as the Python SDK');
  const rebuilt = c.newDestination('conn-vector-1', 'peer.example.test', 443, ['203.0.113.0/24', { net: '10.20.30.40/32', private: true, note: 'site link' }],
    { spkiPins: ['A'.repeat(43)], approvedBy: ['admin-1', 'admin-2'], now: 1800000000 });
  assert.equal(c.destinationDigest(rebuilt), vec.digest);
  const d = c.newDestination('conn-1', 'Peer.Example.Test', 443, ['203.0.113.10/32'], { now: 1_800_000_000, approvedBy: ['a', 'b'] });
  assert.equal(d.host, 'peer.example.test');
  const store = new c.MemoryDestinationStore();
  store.put(d);
  assert.equal(store.get('conn-1').host, 'peer.example.test');
  store.rows.get('conn-1')!.record.port = 8443;
  assert.equal((() => { try { store.get('conn-1'); return 'ok'; } catch (e) { return (e as c.ConnectError).code; } })(), 'destination_policy_unavailable');
  for (const bad of ['localhost', 'a..b', '::ffff:203.0.113.1', 'xn--é.test']) assert.throws(() => c.normalizeHost(bad), bad);
  assert.throws(() => c.newDestination('c', 'p.example.test', 443, ['10.0.0.0/8']));
  assert.throws(() => c.newDestination('c', 'p.example.test', 443, [{ net: '10.1.2.3/32' }]), 'private needs the explicit flag');
  assert.ok(c.newDestination('c', 'p.example.test', 443, [{ net: '10.1.2.3/32', private: true }]));
  assert.throws(() => c.newDestination('c', 'p.example.test', 443, [{ net: '169.254.169.254/32' }]));
});

// --- real TLS on 127.0.0.1 ---------------------------------------------------------------------------

async function server(cert: string, key: string, handler?: (req: any, res: any) => void): Promise<{ srv: Server; port: number }> {
  const srv = createServer({ cert: fx(cert), key: fx(key) }, handler ?? ((req, res) => {
    if (req.url === '/redirect') { res.writeHead(302, { Location: 'https://elsewhere.example.test/' }); res.end(); return; }
    if (req.url === '/big') { res.end(Buffer.alloc(64 * 1024, 120)); return; }
    if (req.url === '/slow') { res.write('a'); setTimeout(() => res.end('b'), 3000); return; }
    let body = ''; req.on('data', (d: Buffer) => { body += d; }); req.on('end', () => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ method: req.method, host: req.headers.host, body })); });
  }));
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  return { srv, port: (srv.address() as NetAddressInfo).port };
}

const DOC_IP = '203.0.113.10';
function transport(port: number, o: Partial<c.ApprovedDestination> = {}, t: c.GuardedTransportOptions = {}) {
  const store = new c.MemoryDestinationStore();
  store.put({ ...c.newDestination('conn-1', 'peer.example.test', 443, ['203.0.113.0/24'], { caPem: fx('ca.pem') }), ...o });
  const tr = new c.GuardedTransport(store, 'conn-1', {
    resolver: async () => [DOC_IP], _dialer: () => ({ host: '127.0.0.1', port, expectRemote: '127.0.0.1' }), totalTimeoutMs: 2000, ...t,
  });
  return { tr, store };
}

test('transport: verified TLS to an approved address, SPKI pins, expiry warning', async () => {
  const { srv, port } = await server('peer.crt', 'peer.key');
  try {
    const { tr } = transport(port);
    const r = await tr.request('POST', 'https://peer.example.test/x', { 'Content-Type': 'application/json' }, '{"a":1}');
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(r.body.toString()), { method: 'POST', host: 'peer.example.test', body: '{"a":1}' });
    assert.equal(r.peerAddress, DOC_IP);
    const spki = c.spkiSha256(new X509Certificate(fx('peer.crt')));
    assert.equal(r.certificate.spki_sha256, spki);
    assert.equal((await transport(port, { spki_pins: [spki] }).tr.request('GET', 'https://peer.example.test/')).status, 200);
    assert.equal(await codeOf(() => transport(port, { spki_pins: ['A'.repeat(43)] }).tr.request('GET', 'https://peer.example.test/')), 'spki_mismatch');
    const notAfter = new Date(new X509Certificate(fx('peer.crt')).validTo).getTime() / 1000;
    const warned: string[] = [];
    const w = transport(port, {}, { clock: () => notAfter - 5 * 86400, onWarning: (_c, m) => warned.push(m) });
    const r2 = await w.tr.request('GET', 'https://peer.example.test/');
    assert.match(r2.warnings[0], /^certificate_expiring/);
    assert.equal(warned.length, 1);
  } finally { srv.close(); }
});

test('transport: certificate failures', async () => {
  for (const [cert, code] of [['wrong-name', 'certificate_name_mismatch'], ['expired', 'certificate_invalid'], ['other-ca', 'certificate_invalid']] as const) {
    const { srv, port } = await server(`${cert}.crt`, `${cert}.key`);
    try { assert.equal(await codeOf(() => transport(port).tr.request('GET', 'https://peer.example.test/')), code, cert); } finally { srv.close(); }
  }
  const { srv, port } = await server('peer.crt', 'peer.key');
  try {   // no private CA configured: the system store does not know the test CA
    assert.equal(await codeOf(() => transport(port, { ca_pem: undefined }).tr.request('GET', 'https://peer.example.test/')), 'certificate_invalid');
  } finally { srv.close(); }
});

test('transport: destination policy, DNS changes and refused addresses', async () => {
  const { srv, port } = await server('peer.crt', 'peer.key');
  try {
    const { tr, store } = transport(port, {}, { resolver: async () => ['198.51.100.7'] });
    const e = await tr.request('GET', 'https://peer.example.test/').catch((x) => x);
    assert.equal(e.code, 'destination_changed');
    assert.deepEqual(e.evidence.observed, ['198.51.100.7']);
    store.block('conn-1', e.evidence);
    assert.equal(await codeOf(() => tr.request('GET', 'https://peer.example.test/')), 'security_blocked');
    for (const ip of ['127.0.0.1', '169.254.169.254', '::1', 'fe80::1', '::ffff:127.0.0.1', '64:ff9b::7f00:1', 'fec0::1']) {
      assert.equal(await codeOf(() => transport(port, {}, { resolver: async () => [ip] }).tr.request('GET', 'https://peer.example.test/')), 'blocked_destination', ip);
    }
    assert.equal(await codeOf(() => transport(port, {}, { resolver: async () => [DOC_IP, '198.51.100.7'] }).tr.request('GET', 'https://peer.example.test/')), 'destination_changed', 'every answer must be approved');
    const missing = new c.GuardedTransport(new c.MemoryDestinationStore(), 'conn-1');
    assert.equal(await codeOf(() => missing.request('GET', 'https://peer.example.test/')), 'destination_policy_unavailable');
    const broken = new c.GuardedTransport({ get: () => { throw new Error('db down'); } }, 'conn-1');
    assert.equal(await codeOf(() => broken.request('GET', 'https://peer.example.test/')), 'destination_policy_unavailable');
    const t2 = transport(port).tr;
    for (const url of ['http://peer.example.test/', 'https://other.example.test/', 'https://peer.example.test:8443/', 'https://u:p@peer.example.test/']) {
      assert.equal(await codeOf(() => t2.request('GET', url)), 'blocked_destination', url);
    }
    for (const h of ['Host', 'Proxy-Authorization', 'Transfer-Encoding', 'Connection']) {
      assert.equal(await codeOf(() => t2.request('GET', 'https://peer.example.test/', { [h]: 'x' })), 'blocked_destination', h);
    }
    const wrongPeer = transport(port, {}, { _dialer: () => ({ host: '127.0.0.1', port, expectRemote: '127.0.0.2' }) }).tr;
    assert.equal(await codeOf(() => wrongPeer.request('GET', 'https://peer.example.test/')), 'blocked_destination', 'connected address verified');
  } finally { srv.close(); }
});

test('transport: no redirects, size caps, deadline', async () => {
  const { srv, port } = await server('peer.crt', 'peer.key');
  try {
    const r = await transport(port).tr.request('GET', 'https://peer.example.test/redirect');
    assert.equal(r.status, 302, 'redirect returned, never followed');
    assert.equal(await codeOf(() => transport(port, {}, { maxResponseBytes: 1024 }).tr.request('GET', 'https://peer.example.test/big')), 'too_large');
    assert.equal(await codeOf(() => transport(port, {}, { maxRequestBytes: 4 }).tr.request('POST', 'https://peer.example.test/', {}, '12345')), 'too_large');
    const t0 = Date.now();
    assert.equal(await codeOf(() => transport(port, {}, { totalTimeoutMs: 500 }).tr.request('GET', 'https://peer.example.test/slow')), 'deadline_exceeded');
    assert.ok(Date.now() - t0 < 2000);
  } finally { srv.closeAllConnections?.(); srv.close(); }
});

// --- SQLite stores, shared between "workers" (two connections to one file) ------------------------------

test('sqlite: replay, rate limits and destinations persist and are shared', () => {
  const dir = mkdtempSync(join(tmpdir(), 'a8c-'));
  try {
    const path = join(dir, 'connect.db');
    const w1 = new c.SqliteDatabase(path); w1.migrate();
    const w2 = new c.SqliteDatabase(path);
    const now = 1_800_000_000;
    const r1 = new c.SqliteReplayStore(w1, () => now), r2 = new c.SqliteReplayStore(w2, () => now);
    assert.equal(r1.add('dpop', 'j1', now + 60), true);
    assert.equal(r2.add('dpop', 'j1', now + 60), false, 'seen by another worker');
    w1.close();
    const w3 = new c.SqliteDatabase(path);
    assert.equal(new c.SqliteReplayStore(w3, () => now).add('dpop', 'j1', now + 60), false, 'survives restart');
    assert.equal(new c.SqliteReplayStore(w3, () => now + 61).add('dpop', 'j1', now + 200), true, 'expired key reusable');

    const rl1 = new c.RateLimiter(new c.SqliteRateLimitStore(w2), { x: { limit: 3, window: 60 } }, () => now);
    const rl2 = new c.RateLimiter(new c.SqliteRateLimitStore(w3), { x: { limit: 3, window: 60 } }, () => now);
    rl1.check('x', 'a'); rl2.check('x', 'a'); rl1.check('x', 'a');
    assert.equal((() => { try { rl2.check('x', 'a'); return 'ok'; } catch (e) { return (e as c.ConnectError).code; } })(), 'rate_limited');
    rl2.check('x', 'b');
    const failing = new c.RateLimiter({ hit: () => { throw new Error('down'); }, get: () => 0 }, { x: { limit: 3, window: 60 } });
    assert.throws(() => failing.check('x', 'a'), (e: c.ConnectError) => e.code === 'rate_limit_unavailable' && e.status === 503);

    const ds = new c.SqliteDestinationStore(w2);
    const d = c.newDestination('conn-9', 'peer.example.test', 443, ['203.0.113.0/24'], { now });
    ds.put(d);
    assert.equal(new c.SqliteDestinationStore(w3).get('conn-9').port, 443);
    assert.equal((() => { try { ds.put({ ...d, version: 2 }, 5); return 'ok'; } catch (e) { return (e as c.ConnectError).code; } })(), 'conflict');
    w3.db.prepare("UPDATE connect_destination SET record = replace(record, '443', '444')").run();
    assert.equal((() => { try { ds.get('conn-9'); return 'ok'; } catch (e) { return (e as c.ConnectError).code; } })(), 'destination_policy_unavailable');
    w2.close(); w3.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- approvals --------------------------------------------------------------------------------------

const CAT = new c.Catalog([
  { name: 'connection:read', description: 'r', risk: 'read' }, { name: 'remote_actions:execute', description: 'x', risk: 'high_risk' },
  { name: 'connection:admin', description: 'a', risk: 'admin' }, { name: 'future:read', description: 'f', risk: 'read', available: false },
]);

test('elevated grants need two fresh administrators and an unchanged fingerprint', () => {
  const now = 1_800_000_000;
  const pol = new c.ElevatedGrantPolicy(new c.MemoryGrantApprovalStore(), CAT, { clock: () => now });
  const fp = c.grantFingerprint({ connectionId: 'c', remoteInstallation: 'i', remoteKeyThumbprints: ['k'], inboundScopes: ['remote_actions:execute'], tenantGrants: [] });
  const id = pol.propose({ connectionId: 'c', fingerprint: fp, scopes: ['remote_actions:execute'], proposer: { adminId: 'alice', reauthenticatedAt: now } });
  assert.equal(pol.isAuthorized('c', fp, ['remote_actions:execute']), false);
  assert.throws(() => pol.approve(id, { adminId: 'alice', reauthenticatedAt: now }, fp), (e: c.ConnectError) => e.code === 'second_admin_required');
  assert.throws(() => pol.approve(id, { adminId: 'bob', reauthenticatedAt: now - 3600 }, fp), (e: c.ConnectError) => e.code === 'reauthentication_required');
  assert.throws(() => pol.approve(id, { adminId: 'bob', reauthenticatedAt: now }, fp + 'x'), (e: c.ConnectError) => e.code === 'approval_mismatch');
  const id2 = pol.propose({ connectionId: 'c', fingerprint: fp, scopes: ['remote_actions:execute'], proposer: { adminId: 'alice', reauthenticatedAt: now } });
  pol.approve(id2, { adminId: 'bob', reauthenticatedAt: now }, fp);
  assert.equal(pol.isAuthorized('c', fp, ['remote_actions:execute', 'connection:read']), true);
  assert.deepEqual(pol.authorizedScopes('c', 'other', ['connection:read', 'remote_actions:execute']), ['connection:read']);
  pol.revoke('c');
  assert.equal(pol.isAuthorized('c', fp, ['remote_actions:execute']), false);
  assert.throws(() => c.classifyScopes(CAT, ['bogus:scope']), (e: c.ConnectError) => e.code === 'invalid_scope');
  assert.throws(() => c.classifyScopes(CAT, ['future:read']), (e: c.ConnectError) => e.code === 'invalid_scope');
  const off = new c.ElevatedGrantPolicy(new c.MemoryGrantApprovalStore(), CAT, { enabled: false });
  assert.throws(() => off.classify(['connection:admin']));
});

test('per-action approval is single use and bound to the parameters (memory and SQLite)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'a8c-'));
  try {
    const db = new c.SqliteDatabase(join(dir, 'a.db')); db.migrate();
    for (const store of [new c.MemoryActionApprovalStore(), new c.SqliteActionApprovalStore(db)]) {
      let now = 1_800_000_000;
      const acts = new c.ActionApprovals(store, { clock: () => now, ttl: 60 });
      const m = { connectionId: 'c', tenant: 't', target: 'dev-1', actionType: 'reboot', params: { force: false } };
      const req = acts.request({ ...m, operator: 'op', requiredScope: 'remote_actions:execute' });
      assert.throws(() => acts.consume(req.id, m), (e: c.ConnectError) => e.code === 'action_approval_required');
      assert.throws(() => acts.decide(req.id, true, { adminId: 'op', reauthenticatedAt: now }), (e: c.ConnectError) => e.code === 'second_admin_required');
      acts.decide(req.id, true, { adminId: 'adm', reauthenticatedAt: now });
      assert.throws(() => acts.consume(req.id, { ...m, params: { force: true } }));
      acts.consume(req.id, m);
      assert.throws(() => acts.consume(req.id, m), 'single use');
      const late = acts.request({ ...m, operator: 'op', requiredScope: 's' });
      acts.decide(late.id, true, { adminId: 'adm', reauthenticatedAt: now });
      now += 61;
      assert.throws(() => acts.consume(late.id, m), 'expired');
    }
    db.close();
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

// --- keystore ---------------------------------------------------------------------------------------

test('key envelope: vector shared with Python, row binding, rotation, file permissions', () => {
  const v = load('key-envelope.json');
  const mks = new c.StaticMasterKeys(Object.fromEntries(Object.entries<string>(v.master_keys).map(([k, x]) => [k, Buffer.from(x, 'base64url')])), 'test-mk-1');
  const cipher = new c.PrivateKeyCipher(mks);
  const aad = Buffer.from(v.row_aad);
  assert.equal(cipher.decryptBytes(v.envelope, aad).toString('hex'), v.plaintext_seed_hex);
  assert.equal(cipher.encryptBytes(Buffer.from(v.plaintext_seed_hex, 'hex'), aad, Buffer.from(v.nonce_b64url, 'base64url')), v.envelope);
  assert.equal(c.thumbprint(cipher.decryptPrivateKey(v.envelope, aad)), v.public_key_thumbprint);
  for (const n of v.negative) {
    assert.throws(() => cipher.decryptBytes(n.envelope ?? v.envelope, Buffer.from(n.row_aad)), (e: c.ConnectError) => e.code === n.error, n.case);
  }
  const key = c.generatePrivateKey();
  const blob = cipher.encryptPrivateKey(key, c.rowAad('connect_key', 'private_key', 'r1'));
  assert.equal(c.thumbprint(cipher.decryptPrivateKey(blob, c.rowAad('connect_key', 'private_key', 'r1'))), c.thumbprint(key));
  assert.throws(() => cipher.decryptBytes(blob, c.rowAad('connect_key', 'private_key', 'r2')), (e: c.ConnectError) => e.code === 'key_corrupt');
  const dir = mkdtempSync(join(tmpdir(), 'a8c-'));
  try {
    const p = join(dir, 'keys.json');
    writeFileSync(p, JSON.stringify({ current: 'k', keys: { k: Buffer.alloc(32, 7).toString('base64url') } }));
    chmodSync(p, 0o644);
    assert.throws(() => c.fileMasterKeys(p), (e: c.ConnectError) => e.code === 'key_unavailable');
    chmodSync(p, 0o600);
    assert.equal(c.fileMasterKeys(p).current()[0], 'k');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('authenticateResourceRequest: DPoP-bound token, replay and Bearer refusal', () => {
  const now = 1_800_000_000;
  const issuerKey = c.generatePrivateKey(), clientKey = c.generatePrivateKey();
  const issuer = 'https://rmm.example.test';
  const { token } = c.issueAccessToken(issuerKey, { issuer, clientId: 'conn-1', scopes: ['connection:read'], jkt: c.thumbprint(clientKey), now });
  const url = `${issuer}/connect/v1/test`;
  const replay = new c.BoundedMemoryReplayStore(() => now);
  const ring = new Map([[c.thumbprint(issuerKey), c.publicKeyFromJwk(c.publicJwk(issuerKey))]]);
  const proof = c.buildDpopProof(clientKey, 'GET', url, { now, accessToken: token });
  const r = c.authenticateResourceRequest({ authorization: `DPoP ${token}`, dpop: proof, method: 'GET', url, issuer, tokenKeysFor: (id) => (id === 'conn-1' ? ring : undefined), replay, now });
  assert.equal(r.clientId, 'conn-1');
  assert.throws(() => c.authenticateResourceRequest({ authorization: `DPoP ${token}`, dpop: proof, method: 'GET', url, issuer, tokenKeysFor: () => ring, replay, now }));
  assert.throws(() => c.authenticateResourceRequest({ authorization: `Bearer ${token}`, dpop: proof, method: 'GET', url, issuer, tokenKeysFor: () => ring, replay, now }), (e: c.ConnectError) => e.code === 'invalid_token');
  const other = c.buildDpopProof(c.generatePrivateKey(), 'GET', url, { now, accessToken: token });
  assert.throws(() => c.authenticateResourceRequest({ authorization: `DPoP ${token}`, dpop: other, method: 'GET', url, issuer, tokenKeysFor: () => ring, replay, now }), (e: c.ConnectError) => e.code === 'invalid_dpop_proof');
  assert.throws(() => c.authenticateResourceRequest({ authorization: `DPoP ${token}`, dpop: proof, method: 'GET', url, issuer, tokenKeysFor: () => undefined, replay, now }), (e: c.ConnectError) => e.code === 'invalid_token');
});
