# Threat model

Covers `agit8or-connect/1` ([PROTOCOL.md](PROTOCOL.md) §16), the Quick Connect revision 1.1
([QUICK_CONNECT_SPECIFICATION.md](QUICK_CONNECT_SPECIFICATION.md) §11) and the recommended host controls
([IP_ALLOWLIST_AND_BOOTSTRAP.md](IP_ALLOWLIST_AND_BOOTSTRAP.md), [AUTO_RECONNECT.md](AUTO_RECONNECT.md)).

> This is the authors' model. It has **not** been independently reviewed. See [SECURITY.md](../SECURITY.md) to
> report a problem.

## 1. Assets and actors

- **Assets:** each installation's connection keys; access tokens; customer data reachable through tenant grants;
  events in transit and in queues; the audit chain; the administrators' sessions.
- **Trusted:** each installation's own server and its administrators (two-person approval for elevated actions).
- **Untrusted:** the network, DNS, any party holding a pairing code or an invitation link, the administrator's
  browser as a transport, the peer's claims until verified, any address seen in a request.
- **Out of scope:** a fully compromised administrator account (mitigated, not prevented, by two-person approval
  and the SAS), compromise of a host's master key or server, TLS library or CPU flaws.

## 2. Protocol threats (v1)

| Threat | Mitigation |
|---|---|
| Guessing a pairing code | 50-bit code, 10 min, single use, 5 failures burn all open codes, per-address and global rate limits, HMAC-peppered storage |
| Man in the middle at pairing | TLS + discovery identity + request signed by the announced key + SAS compared by both administrators |
| Rogue code holder pairs | Needs both administrators' approval; nothing is reachable without explicit grants |
| SSRF via discovery / endpoints | Same-origin endpoints, connect-time IP checks, metadata always blocked, no redirects or proxies, discovery only on an administrator action |
| Stolen access token | 300 s lifetime, DPoP binding, `tokens_not_before` |
| Replay (assertion, DPoP, poll, pairing request, event) | `jti` / event-id stores with expiry and a database-enforced unique key, shared by all workers and surviving restarts (`storage.SqlReplayStore`: SQLite or PostgreSQL); a store failure refuses the request (`replay_store_unavailable`, 503); pairing requests are recorded only after the code matches; events are recorded only after authorisation; events idempotent |
| Cross-tenant access within a connection | Grants per connection, resolution in the caller's namespace, scope ∩ grant scope |
| Cross-installation confusion | Everything keyed by connection; tokens bound to `client_id` and `cnf.jkt` |
| Key compromise | Rotation (the retiring key stops being accepted after the overlap, and its private half is wiped), revoke (private keys wiped), kill switch; private keys MUST be encrypted at rest with row-bound associated data (`keystore.PrivateKeyCipher`), master key outside the database |
| Privilege escalation | High-risk / admin scopes need two **distinct**, freshly re-authenticated administrators bound to a fingerprint of the exact request (scopes, tenant grants, keys, installation); approval re-checked at token issue and at every use; unknown and unavailable scopes refused; tokens never broader than grants; optional per-action approval (`action-approval/1`): single use, bound to target, action and a parameter digest, operator cannot approve their own action |
| Event loops | `origin` and `hops` guard |
| Audit tampering | Hash chain, append-only storage, verify command (detects, cannot prevent) |
| Secret leakage | Audit detail scrubbing; tests scan logs, responses and pages for codes, tokens and keys |
| Disabled TLS | No code path turns verification off |
| Algorithm / version downgrade | EdDSA only; `typ` checked for every JWS; only version 1 offered |

## 3. Quick Connect threats (1.1)

| Threat | Mitigation |
|---|---|
| Password phishing / credential relay between applications | No password grant, no password field: each administrator signs in only to their own application |
| Forged invitation shown to a phished responder administrator | The invitation grants nothing; the review shows the initiator's host, claimed id, egress and scopes; the temporary rule reaches only pairing endpoints for ≤ 15 min; final approval is v1 (both administrators, SAS) and the responder reads the initiator's discovery over TLS for its name |
| Stolen redirect / authorisation code | Useless alone: PKCE verifier (only the initiator's server has it), exchange signed by the invitation key, DPoP proof by the same key, request admitted only from the declared egress; 120 s, single use; `code_sha256` binds code ↔ accept |
| Invitation replay | `jti` single use, ≤ 10 min, `aud` = responder origin |
| Mix-and-match across attempts | `invitation_sha256`, `accept_sha256`, `attempt`, invitation `jti` and `code_sha256` chain every message to one attempt |
| Key or address substitution | The transcript binds both keys, both egress lists and the destination; administrators compare the SAS |
| Downgrade to the code flow or fewer extensions | Signed `extensions` in invitation and accept, checked against discovery after the callback; distinct `typ` + `protocol` claim prevent cross-protocol use |
| Open redirect via `redirect_uri` | Signed; same origin as `base`; canonical grammar; redirect only after the invitation verified |
| SSRF via `base` | Canonical grammar, refused literals, allowed ports; nothing fetched before an administrator acts; outbound through the approved-destination policy |
| Spoofed or shared source address | Address is a second factor only; TCP spoofing cannot complete TLS; installations behind one NAT separated by their keys (binding check) |
| Browser address used as trust | Never: egress comes only from administrator declarations and signed messages |

## 4. Host-level threats

| Threat | Mitigation |
|---|---|
| Connect endpoints exposed to the whole Internet | Default-deny two-layer source allowlist before authentication, independent of any general API policy |
| Unauthenticated growth of the audit chain / write-lock contention | Refusals go to a folded, prunable log; at most one aggregated chain record per minute |
| Brute force and floods (pairing, Quick Connect, token, authentication, signatures) | Shared sliding-window limits keyed by connection and source (`ratelimit.RateLimiter` over a shared store); a store failure refuses (`rate_limit_unavailable`); `Retry-After` on 429 |
| Pairing denial of service with wrong codes | Codes usable only from the address the invitation was created for; wrong codes count only against those invitations |
| DNS hijack + mis-issued certificate redirecting events | Approved-destination pin on every resolved and connected address, optional SPKI pin; change → Security Blocked, never silent |
| Lockout of a legitimate peer by a rule change | Preview against every active connection's observed source; rollback narrows only; server-side recovery path for the owner |
| A connection marked active before it works | `active` only after a passing connection test, in one commit |
| Approvals during an incident | Kill switch blocks approvals and activation; releasing it activates nothing |
| A general "allow private addresses" switch reaching loopback / metadata | Connect's outbound policy never inherits it; loopback, link-local, metadata always refused |
| Plaintext TLS client keys on disk | Load from memory (anonymous memory files where the platform allows), private temp directory otherwise, cleanup sweep |
| Relative URLs / Host-header-derived audiences | Public base URL is a required setting; only absolute https URLs are sent |
| State-changing GET (prefetchers, link previews) | Outbound lookups only on a POST by an administrator |
| Duplicate installation id claimed by a newcomer | Warning plus a second administrator |
| Stale cached tokens after suspend/revoke in another process | Re-read connection state from the database before every outbound call |
| Monitor job crash leaving connections unchecked | Per-connection exception isolation, bounded run time, stale-run alert |
| Events lost during a long outage | Attempts not counted while the peer is unreachable; age-based dead letter; ordered drain; requeue with the original id |

## 5. Residual risks and open items

- Rate limits are only shared if the host gives every worker the same store (SQL store); the in-memory store is per process.
- PostgreSQL behaviour is tested in CI only (service container); SQLite locally.
- The transport tests run against local TLS servers on 127.0.0.1 with a test-only CA; DNS answers for real hosts are not tested.
- An unauthenticated request naming an unknown key id can make a host fetch the peer's JWKS (bounded to once a
  minute per connection).
- Discovery and unauthenticated health reveal the application type, version and installation id to anyone the
  source policy admits; keep the source policy tight.
- Event bodies are signed, not encrypted; their confidentiality rests on TLS.
- SPKI pins are compared after the handshake (before any request bytes).
- Audit anchoring detects rewriting only up to the last checkpoint a verifier holds; entries after it can be
  dropped by someone who controls the database. Publish checkpoints off-host and often (`audit.sign_checkpoint`).
- `dpop-nonce/1` and `actor/1` protect only connections where both installations negotiated them; a 1.0 / 1.1
  peer still relies on `iat` windows and the jti replay store. The actor `sub` is the issuing installation's
  claim about its own user; the receiving side cannot verify the person, only attribute and limit.
- The TypeScript SDK and the Python SDK share an author; they are two implementations, not independent ones.
  No independent security review exists yet.
