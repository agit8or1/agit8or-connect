// P1 helpers: trusted proxy, dpop-nonce/1, actor/1, audit export verification (vectors shared with Python).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import * as c from '../src/index.ts';

const DIR = process.env.AGIT8OR_CONNECT_VECTORS ?? join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'test-vectors');
const load = (n: string) => JSON.parse(readFileSync(join(DIR, n), 'utf8'));
const code = (fn: () => unknown) => { try { fn(); return 'ok'; } catch (e) { return (e as c.ConnectError).code ?? String(e); } };

test('trusted proxy: headers only from trusted peers, right to left, refusals', () => {
  const r = new c.TrustedProxyResolver(['10.0.0.0/24']);
  assert.equal(r.resolve('203.0.113.9', { 'X-Forwarded-For': '198.51.100.1' }), '203.0.113.9');
  assert.equal(r.resolve('10.0.0.5', { 'x-forwarded-for': '198.51.100.66, 203.0.113.5, 10.0.0.7' }), '203.0.113.5');
  assert.equal(r.resolve('::ffff:10.0.0.5', { 'X-Forwarded-For': '[2001:db8::1]:443' }), '2001:db8::1');
  for (const h of [{}, { 'X-Forwarded-For': '' }, { 'X-Forwarded-For': 'example.test' }, { 'X-Forwarded-For': '10.0.0.9' },
    { 'X-Forwarded-For': Array(9).fill('203.0.113.1').join(',') }, { 'X-Forwarded-For': 'fe80::1%eth0' }]) {
    assert.equal(code(() => r.resolve('10.0.0.5', h)), 'source_unresolved', JSON.stringify(h));
  }
  const f = new c.TrustedProxyResolver(['10.0.0.0/24'], 'forwarded');
  assert.equal(f.resolve('10.0.0.5', { Forwarded: 'for=198.51.100.66, for="[2001:db8::5]";proto=https' }), '2001:db8::5');
  assert.throws(() => new c.TrustedProxyResolver(['0.0.0.0/0']));
});

test('dpop-nonce/1 and actor/1 vectors', () => {
  const v = load('extensions.json');
  const n = v.dpop_nonce;
  const iss = new c.NonceIssuer(Buffer.from(n.secret_hex, 'hex'), { clock: () => n.now });
  assert.equal(iss.issue(n.context), n.nonce);
  assert.equal(iss.valid(n.nonce, n.wrong_context), false);
  assert.equal(new c.NonceIssuer(Buffer.from(n.secret_hex, 'hex'), { clock: () => n.valid_until_exclusive }).valid(n.nonce, n.context), false);
  const r = c.verifyDpopProof(n.proof, { method: n.proof_method, url: n.proof_url, replay: new c.MemoryReplayStore(), now: n.now, nonceCheck: (x) => iss.check(x, n.context) });
  assert.equal(r.jkt, v.keys.A.thumbprint);
  const stale = new c.NonceIssuer(Buffer.alloc(32, 9), { clock: () => n.now });
  assert.equal(code(() => c.verifyDpopProof(n.proof, { method: n.proof_method, url: n.proof_url, replay: new c.MemoryReplayStore(), now: n.now, nonceCheck: (x) => stale.check(x, n.context) })), 'use_dpop_nonce');
  const b = c.privateKeyFromSeed(Buffer.from(v.keys.B.seed_hex, 'hex'));
  const claims = c.verifyAccessToken(v.actor.access_token, new Map([[c.thumbprint(b), c.publicKeyFromJwk(c.publicJwk(b))]]), { issuer: v.actor.issuer, now: v.actor.now });
  assert.equal(c.actorOf(claims, { actor: 1 }), v.actor.actor);
  assert.equal(code(() => c.actorOf(claims, {})), 'invalid_token', 'not negotiated');
  for (const bad of v.actor.invalid_actors) assert.equal(code(() => c.validateActor(bad)), 'invalid_actor');
  const proof = c.buildDpopProof(b, 'GET', 'https://x.example.test/a', { nonce: n.nonce, now: n.now });
  assert.equal((c.unverifiedPayload(proof) as any).nonce, n.nonce);
});

test('audit checkpoint vectors', () => {
  const v = load('audit-checkpoint.json');
  const key = c.publicKeyFromJwk(v.key.public_jwk);
  assert.deepEqual(c.verifyAuditExport(v.export, key, 'inst-audit'), { ...v.head, count: 3 });
  for (const neg of v.negative) {
    const b = { ...v.export, entries: neg.entries ?? v.export.entries };
    assert.equal(code(() => c.verifyAuditExport(b, key, 'inst-audit', neg.known_checkpoints ?? [])), neg.error, neg.case);
  }
  assert.equal(code(() => c.verifyAuditExport(v.export, c.publicKeyFromJwk(c.publicJwk(c.generatePrivateKey())), 'inst-audit')), 'audit_invalid');
  assert.equal(code(() => c.verifyAuditExport(v.export, key, 'other')), 'audit_invalid');
});
