// Second implementation in the HTTPS harness (python/agit8or_connect/tests/test_harness.py runs it):
// the TypeScript SDK acts as the calling side of an established connection against Python workers over real
// TLS on 127.0.0.1, through the TypeScript GuardedTransport. Prints one JSON line with what happened.
//   node test/harness_client.ts CONFIG.json
import { readFileSync } from 'node:fs';
import { createPrivateKey, randomUUID } from 'node:crypto';
import * as c from '../src/index.ts';

const cfg = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const key = createPrivateKey(cfg.private_key_pem);
const store = new c.MemoryDestinationStore();
const u = new URL(cfg.endpoints.token);
store.put(c.newDestination('peer', u.hostname, Number(u.port || 443), [`${cfg.doc_ip}/32`], { caPem: cfg.ca_pem }));
const tr = new c.GuardedTransport(store, 'peer', {
  resolver: async () => [cfg.doc_ip], _dialer: () => ({ host: '127.0.0.1', port: cfg.dial_port, expectRemote: '127.0.0.1' }),
});
const nonceOn = cfg.negotiated?.['dpop-nonce'] === 1;
const out: Record<string, unknown> = { workers: [] as string[] };

async function token(): Promise<string> {
  let nonce: string | undefined;
  for (let attempt = 0; attempt < 2; attempt++) {
    const form = new URLSearchParams({ grant_type: 'client_credentials', client_id: cfg.client_id,
      client_assertion_type: c.CLIENT_ASSERTION_TYPE, client_assertion: c.buildClientAssertion(key, cfg.client_id, cfg.endpoints.token) });
    const r = await tr.request('POST', cfg.endpoints.token, { 'Content-Type': 'application/x-www-form-urlencoded', DPoP: c.buildDpopProof(key, 'POST', cfg.endpoints.token, { nonce }) }, form.toString());
    (out.workers as string[]).push(r.header('agit8or-harness-worker'));
    const body = JSON.parse(r.body.toString());
    if (r.status === 200) return body.access_token;
    if (nonceOn && attempt === 0 && body.error === c.USE_DPOP_NONCE && r.header(c.DPOP_NONCE_HEADER)) { nonce = r.header(c.DPOP_NONCE_HEADER); out.token_nonce_retry = true; continue; }
    throw new Error(`token ${r.status} ${body.error}`);
  }
  throw new Error('token: no nonce');
}

async function api(method: string, url: string, at: string, nonce?: string) {
  const proof = c.buildDpopProof(key, method, url, { accessToken: at, nonce });
  const h = { Authorization: `DPoP ${at}`, DPoP: proof };
  const r = await tr.request(method, url, h);
  (out.workers as string[]).push(r.header('agit8or-harness-worker'));
  return { r, h };
}

const at = await token();
out.token = 'ok';
const testUrl = cfg.endpoints.test;
let { r, h } = await api('GET', testUrl, at);
if (nonceOn && r.status === 401 && r.header('www-authenticate').includes('use_dpop_nonce')) {
  out.api_nonce_retry = true;
  ({ r, h } = await api('GET', testUrl, at, r.header(c.DPOP_NONCE_HEADER)));
}
out.test_status = r.status;
out.test_body = JSON.parse(r.body.toString());
const replay = await tr.request('GET', testUrl, h);       // identical proof again, any worker
out.replay_status = replay.status;
out.replay_error = JSON.parse(replay.body.toString()).error?.code;

const eventId = randomUUID();
const body = Buffer.from(c.canonicalJson({ id: eventId, type: 'connect.test', version: 1, tenant: '', data: { from: 'typescript' },
  sender: cfg.installation_id, origin: cfg.installation_id, correlation_id: eventId, causation_id: '', hops: 0,
  idempotency_key: eventId, occurred_at: Math.floor(Date.now() / 1000) }));
const sendEvent = async () => {
  const eh = c.signEvent(key, { connectionId: cfg.client_id, eventId, sender: cfg.installation_id, receiver: cfg.remote_installation, body });
  const er = await tr.request('POST', cfg.endpoints.events, { ...eh, 'Content-Type': 'application/json' }, body);
  return JSON.parse(er.body.toString());
};
out.event = await sendEvent();
out.event_again = await sendEvent();
out.event_id = eventId;
console.log(JSON.stringify(out));
