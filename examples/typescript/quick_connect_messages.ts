// Minimal TypeScript peer: both sides of a Quick Connect bootstrap
// (qc-bootstrap/1 + qc-source-binding/1), in one process, with the reference SDK.
//
//   node examples/typescript/quick_connect_messages.ts        (Node >= 22.18, from the repo root)
//
// It builds and verifies the four messages in the order a real initiator (A)
// and responder (B) would, and prints the SAS both administrators compare.
// No network: a real peer sends the invitation and accept through the
// administrator's browser and the exchange as an HTTPS POST (with the DPoP
// proof) from A's declared egress address. Example only; not production code.
import { randomUUID } from 'node:crypto';
import * as c from '../../typescript/src/index.ts';

const A_BASE = 'https://initiator.example.test';
const B_BASE = 'https://responder.example.test';
const A_APP = { type: 'example-app', version: '1.0.0', display_name: 'Initiator', installation_id: randomUUID() };
const B_APP = { type: 'example-app', version: '1.0.0', display_name: 'Responder', installation_id: randomUUID() };

// --- A: start an attempt ------------------------------------------------------------------
const kA = c.generatePrivateKey();                 // becomes A's connection key
const verifier = c.generatePkceVerifier();         // stays on A's server
const state = c.qcGenerateState();                 // bound to A's administrator session
const attempt = randomUUID();
const invitation = c.buildInvitation(kA, {
  initiatorApp: A_APP, responderOrigin: B_BASE, attempt, base: A_BASE, redirectUri: `${A_BASE}/qc/callback`,
  egress: ['203.0.113.10'], requestedScopes: ['connection:read', 'customers:read'],
  codeChallenge: c.pkceChallenge(verifier), nonce: c.qcGenerateNonce(),
});
const browserUrl = c.authorizationUrl(`${B_BASE}/agit8or-connect/qc-authorize`, invitation.jws, state);
console.log('A -> browser:', browserUrl.slice(0, 80) + '...');

// --- B: the administrator, signed in to B's own UI, reviews and approves -------------------
const replayB = new c.MemoryReplayStore();
const { claims: inv, jwk: invJwk } = c.verifyInvitation(invitation.jws, { responderOrigin: B_BASE, replay: replayB });
console.log('B reviews: from', inv.base, 'egress', JSON.stringify(inv.egress), 'scopes', JSON.stringify(inv.requested_scopes));
const kB = c.generatePrivateKey();
const code = c.qcGenerateCode();                   // B stores only sha256(code); valid 120 s, single use
const codeIssuedAt = Math.floor(Date.now() / 1000);
const acceptJws = c.buildAccept(kB, {
  responderApp: B_APP, invitation: inv, invitationJws: invitation.jws, connectionId: randomUUID(), base: B_BASE,
  egress: ['198.51.100.7'], code,
});
// B also creates a temporary source rule for inv.egress (<= 15 min) before redirecting.
const callback = c.authorizationResponseUrl(inv.redirect_uri as string, { state, code, accept: acceptJws });

// --- A: callback in the administrator's session --------------------------------------------
const back = c.parseAuthorizationResponse(callback, state);
const { claims: acc } = c.verifyAccept(back.accept, { invitation: invitation.claims, invitationJws: invitation.jws, code: back.code });
// (A now reads B's discovery through the approved destination: checkDiscoveredIdentity + checkNoDowngrade.)
const exchangeUrl = `${B_BASE}/connect/v1/qc/exchange`;
const exchange = c.buildExchange(kA, {
  invitation: invitation.claims, accept: acc, acceptJws: back.accept, code: back.code, codeVerifier: verifier,
  initiatorApp: A_APP, discoveryUrl: `${A_BASE}/.well-known/agit8or-connect`, requestedScopes: ['connection:read', 'customers:read'],
});
const dpop = c.buildDpopProof(kA, 'POST', exchangeUrl);

// --- B: POST qc_exchange (after the source-address check) ------------------------------------
const ex = c.verifyExchange(exchange.jws, {
  dpop, url: exchangeUrl, invitation: inv, invitationJwk: invJwk, acceptJws, codeSha256: c.sha256Hex(code),
  codeExpiresAt: codeIssuedAt + 120, responderInstallation: B_APP.installation_id, replay: replayB,
});
console.log('B accepted the exchange for connection', ex.connection_id);

// --- both: transcript and SAS (then v1: ack, poll, result, both administrators approve) -------
const sasA = c.qcSas(c.qcTranscriptFromMessages(invitation.jws, back.accept, exchange.jws));
const sasB = c.qcSas(c.qcTranscriptFromMessages(invitation.jws, acceptJws, exchange.jws));
console.log('SAS at A:', sasA, ' SAS at B:', sasB, sasA === sasB ? '(match)' : '(MISMATCH)');
if (sasA !== sasB) process.exit(1);
