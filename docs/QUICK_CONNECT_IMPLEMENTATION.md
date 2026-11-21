# Implementing Agit8or Connect (v1 and Quick Connect 1.1)

This guide is for teams adding Agit8or Connect to an application. The normative text is
[PROTOCOL.md](PROTOCOL.md) (`agit8or-connect/1`) and [QUICK_CONNECT_SPECIFICATION.md](QUICK_CONNECT_SPECIFICATION.md)
(revision 1.1). The HTTP surface is [`openapi/openapi.yaml`](../openapi/openapi.yaml); message shapes are in
[`schemas/`](../schemas/). Where this guide and the specifications disagree, the specifications win.

> Status: draft, not yet independently security-reviewed. Do not describe an implementation as production
> secure on the strength of this repository.

## 1. Use an SDK, or match the vectors

| Language | Package | Notes |
|---|---|---|
| Python ≥ 3.10 | [`python/`](../python/) (`agit8or_connect`) | `cryptography` + `PyJWT` only; includes `MinimalGuardedTransport` and an in-memory `reference_peer` |
| TypeScript / Node ≥ 22.18 | [`typescript/`](../typescript/) | `node:crypto` only, no dependencies; **no HTTP transport** (bring your own guarded client) |

If you write your own implementation, it MUST reproduce every file in [`test-vectors/`](../test-vectors/) byte for
byte: canonical JSON, thumbprints, JWS, tokens, DPoP proofs, the pairing transcript and SAS, webhook signatures,
the audit chain, the endorsed JWKS, and every `qc-*.json` message and expected error code. The seeds in the vectors
are **published TEST-ONLY keys** and must never be used for anything else. Then run the
[conformance suite](../conformance/README.md).

Implement version 1 first. Revision 1.1 is optional and negotiated through discovery `extensions`; a 1.1
implementation still pairs with a 1.0 peer over the v1 code flow (QUICK_CONNECT_SPECIFICATION.md §2).

## 2. What your application stores

| Record | Fields (minimum) |
|---|---|
| Installation identity | `installation_id` (UUID, generated once), display name, public base URL (required setting), declared egress addresses, kill-switch flag |
| Connection | your UUID; remote installation id, app type, display name; base URL; remote endpoints; remote connection id (= your `client_id` at the peer); lifecycle state and health; inbound scopes (what the peer may do with you); outbound scopes (what you may do with the peer); per-connection TLS options; `tokens_not_before`; rotation schedule |
| Connection key | kid (thumbprint), state (`staged`/`active`/`retiring`/`retired`/`failed`), public JWK, **encrypted** private key (AEAD, associated data bound to the row) |
| Remote keys | the peer's endorsed JWKS and when it was fetched |
| Approved destination | host, port, approved addresses (exact, or small ranges), trust anchor (system CAs or only a private CA), optional SPKI pins, expected installation id |
| Source rules | installation layer and per-connection layer; allow/deny; network; purpose (`pairing`, `discovery`, normal); expiry for temporary rules; first/last observed |
| Pairing invitation (v1) | HMAC of the code, expiry, attempts, used/burned, the peer address it is valid from |
| Quick Connect attempt (initiator) | connection id, K_A (encrypted), PKCE verifier, `state` bound to the administrator session, invitation JWS, approved destination, deadline |
| Quick Connect grant (responder) | verified invitation and K_A public key, **SHA-256 of the code** (never the code), code expiry, accept JWS, K_B (encrypted), temporary rule, observed source of the exchange |
| Pairing request | public request id, connection, status, the result JWS once decided |
| Tenant grant | connection, your tenant, the peer's tenant id, scopes, active, revoked by/at |
| Replay record | namespace + key, **unique**, expiry |
| Outbound event / attempt | envelope, status, attempts, next attempt, created at |
| Inbound event | (connection, event id) unique, data |
| Audit event | hash-chained record (PROTOCOL.md §14) |

## 3. Endpoints to serve

Serve every route in `openapi.yaml`, under any prefix, as long as discovery lists it on the same origin. Rules
that are easy to get wrong:

1. Gate the whole surface behind a setting that is **off by default**; answer 404 while it is off.
2. Refuse every source address by default on all Connect endpoints, **before authentication** (discovery, health
   and pairing included), with an installation-wide list and a per-connection list that must both allow, deny
   winning. See [IP_ALLOWLIST_AND_BOOTSTRAP.md](IP_ALLOWLIST_AND_BOOTSTRAP.md). Answer `403 source_not_authorised`.
3. After authentication, check that the connection the credentials prove is the connection whose rule matched the
   address (binding check).
4. Don't fetch anything from a pairing request's `discovery_url` or an invitation's `base` until your administrator
   acts with a deliberate action (a POST, never on opening a review page).
5. Count wrong pairing codes **in the database**, not only in a cache, and burn every open invitation at 5.
6. Store replay ids (assertion, DPoP, poll, pairing, invitation, exchange and code) with an expiry, and use a unique
   constraint as the check. Record them **last**, in one transaction with your own state change.
7. Resolve `Agit8or-Tenant` only through **this connection's** active grants. Never accept your own tenant id
   directly.
8. Check `tokens_not_before` and connection state on every request, not only at token issue.
9. Never put tokens, assertions, codes, PKCE verifiers, signatures, DPoP proofs or keys in logs, audit detail,
   error messages, exports or admin pages.
10. Outbound HTTP: see [IP_ALLOWLIST_AND_BOOTSTRAP.md §4](IP_ALLOWLIST_AND_BOOTSTRAP.md#4-outbound-approved-destinations).
11. Put only absolute https URLs in what you send (`discovery_url`, `endpoints`, `base`, `redirect_uri`): make the
    public base URL a required setting rather than deriving it from a request's `Host` header.
12. Don't let an approval or activation happen while your kill switch is engaged. Releasing the kill switch
    activates nothing.
13. Warn, and require a second administrator, when an inbound request or invitation claims the installation id of
    a peer that is already connected.
14. Don't write a permanent audit record for every unauthenticated refusal: count them and summarise.

## 4. Quick Connect responder (B): checks in order

Wire-level verification of the invitation and the exchange is normative in QUICK_CONNECT_SPECIFICATION.md §5.3 and
§5.6 (`verify_invitation` / `verifyInvitation`, `verify_exchange` / `verifyExchange`). Around them the host adds:

1. Serve the conventional browser entry point `/agit8or-connect/qc-authorize` (or a `303` to your real page on the
   same origin). It is a web page behind your normal sign-in, second factor and site firewall, not a Connect API
   route.
2. Verify the invitation (spec §5.3). Never redirect a refusal unless steps 2–10 passed.
3. Check `base` against your **outbound** policy statically (syntax, not loopback/link-local/metadata, port 443
   unless an administrator allowed another). Do not fetch it yet.
4. Show the egress entries; flag private ones. Show the claimed installation id; if it already belongs to an active
   connection, warn and require a second administrator.
5. List unknown or unavailable scopes; never grant them.
6. Require the administrator's permission to manage connections and a fresh re-authentication.
7. Rate-limit reviews per administrator and per installation (counted durably).
8. On approval: create K_B, the code (store only its hash), the accept, and a **temporary rule** admitting exactly
   the invitation's egress to `qc_exchange` (and `pairing_status` for this request), for at most 15 minutes. Then
   `303` to `redirect_uri?accept=…&code=…&state=…`.
9. On `POST qc_exchange`: the source check runs first, keyed by the code hash read from the *unverified* payload.
   Unknown code, expired rule or another address → `403 source_not_authorised`, nothing recorded. Then verify (spec
   §5.6), consume the code, invitation and grant in one transaction, record the observed source, and answer the v1
   `202` with the ack signed by K_B.
10. When your administrator acts, fetch A's discovery (through your outbound policy) and check that its
    `installation_id` equals the invitation `iss`.
11. Any failure before both administrators approve: remove the temporary rule, retire the attempt keys, mark the
    attempt failed. Rollback only ever **removes** access.

## 5. Quick Connect initiator (A): steps

1. Approve the destination first (DNS + TLS preview, no HTTP request), then create the attempt: K_A, PKCE verifier,
   `state` bound to the administrator's session, nonce.
2. If you can read B's discovery and negotiation does not yield `qc-bootstrap/1`, do not send the invitation:
   offer the v1 code flow (`extension_not_negotiated`).
3. `303` the browser to `qc_authorize` (or the conventional entry point) with the invitation and `state`.
4. On the callback: compare `state` in constant time, process a callback at most once, verify the accept (spec
   §5.5), then read B's discovery and check identity and downgrade (spec §5.9).
5. POST the exchange with a DPoP proof by K_A, from your declared egress. Verify the v1 ack and that its key equals
   the accept key (`check_ack_key`).
6. Show the SAS; continue with v1 polling and approval.
7. Approve B's egress (from the signed accept) for your own endpoints during your approval step.

## 6. Administrator UI checklist

- A wizard: select application → destination (URL; show resolved addresses and certificate) → verify identity →
  pair (Quick Connect, or code / QR) → approve permissions (grouped by risk) → select customers → network
  (addresses in both directions) → test → complete. Keep TLS, private CA, private network and rotation under
  **Advanced**.
- Show the **SAS** prominently on both sides; approve only when they match.
- `high_risk`/`admin` scopes go through a second-administrator approval.
- A connection page: key fingerprints and states, rotation dates, destination and source rules, health and the
  last diagnostic run, recent activity.
- Actions: test, rotate now, suspend/resume (resume re-tests), disconnect (notify, then revoke), revoke, per-customer
  revoke, approve a changed address, kill switch.
- Error messages say what to do next. Never show a stack trace or a raw secret.

## 7. Multi-installation receivers

If your application can be connected to several installations (for example several service providers), every
lookup must include the connection. Different installations will reuse the same tenant ids (`org-1`). The
conformance suite has a test with two initiators using identical tenant ids.

## 8. Interop testing

[`python/agit8or_connect/reference_peer.py`](../python/agit8or_connect/reference_peer.py) is a complete in-memory
implementation of both roles (`quick_connect=True` for 1.1). It talks to any transport callable
`(method, url, headers, body) → Response`, so you can point it at your application's test client and use it as "the
other application" in your own end-to-end tests. For a running instance, use the live checks of the conformance
suite (`AGIT8OR_CONNECT_TARGET`).
