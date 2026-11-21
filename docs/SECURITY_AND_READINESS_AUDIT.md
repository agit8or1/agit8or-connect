# Security and readiness audit — Agit8or Connect 1.1.0

Scope: everything in this repository at commit `26a7b56` (release 1.1.0): the specifications in `docs/`, the
OpenAPI description, the JSON Schemas, the test vectors, the Python SDK and in-memory reference peer, the
TypeScript SDK, the conformance suite, the examples and the GitHub Actions workflow.

> This is a self-review by the maintainers' tooling, written before the hardening work that follows it. It is
> **not** an independent security review, and nothing in it is a certification. Findings were checked against the
> code and, where marked *confirmed*, reproduced by running it. *Potential* findings are risks that need more
> testing or depend on how a host uses the SDK.

Section 12 records how each finding was handled by the hardening programme; the rest of this document describes
the state of 1.1.0 as found.

## 1. Method

1. Read every document listed above, the whole Python SDK (≈ 3 300 lines plus ≈ 1 000 lines of tests), the TypeScript SDK (≈ 1 200 lines), the
   conformance suite and the workflow.
2. Ran the baseline (Python 3.12, `cryptography` 50, PyJWT 2.15, Node 22.21):

   | Suite | Command | Result |
   |---|---|---|
   | Python SDK | `cd python && python -m unittest discover` | `Ran 62 tests … OK` |
   | Vector generator | `python -m agit8or_connect.tools.generate_vectors --check` | no differences |
   | TypeScript SDK | `cd typescript && npm test` | `# tests 19 # pass 19 # fail 0` |
   | Vector digests | `cd test-vectors && sha256sum -c ../conformance/VECTORS.sha256` | 12 × OK |
   | Conformance | `cd conformance && CONFORMANCE_REQUIRE_NODE=1 python -m unittest discover` | `Ran 64 tests … OK (skipped=5)` (the 5 live checks) |
   | Schemas | `python tools/build_schemas.py --check` | `23 schemas up to date` |

3. Reproduced the suspected defects with small scripts that drive the reference peer and the transport directly
   (results quoted in the findings).

## 2. Verified implementation status (1.1.0 as found)

| Area | Python SDK | TypeScript SDK | Evidence |
|---|---|---|---|
| Canonical JSON, base64url, thumbprints, compact JWS (EdDSA only, `typ` checked, `crit` refused) | implemented, vector-tested | implemented, vector-tested | `test_vectors.py`, `vectors.test.ts`, conformance 20 |
| Pairing messages, transcript, SAS, code hashing | implemented, vector-tested | implemented, vector-tested | `pairing.json` |
| Client assertion, access token, DPoP proof build/verify | implemented, vector-tested | implemented, vector-tested | `tokens.json` |
| `authenticate_resource_request` (Bearer refusal, token + proof) | implemented | **missing** | — |
| Endorsed JWKS | implemented | implemented | `jwks.json` |
| Signed events, envelope validation, backoff | implemented | sign/verify only (no envelope validation) | `webhooks.json` |
| Audit hash chain | `entry_hash`, `verify_chain` only | same | `audit-chain.json` |
| Discovery build/parse/fetch with same-origin check | implemented | **missing** (1.1 helpers only) | — |
| Scopes catalog, risk tiers, tenant authorisation | implemented | **missing** | — |
| Quick Connect 1.1 messages and checks | implemented, vector-tested | implemented, vector-tested | `qc-*.json` |
| Replay store | interface + in-memory only | interface + in-memory only | — |
| Outbound transport | `MinimalGuardedTransport`: https, address class, TLS verify, no redirect/proxy, size cap; **no approved destination, no SPKI pin, no overall deadline, no request-body cap** | **none** | `test_reference_peer.Transport` (mocked resolver; no real TLS test) |
| Rate limiting, source policy, trusted proxy, key encryption, lifecycle/health, event queue, approvals | **specification and guides only** | same | — |
| Reference peer | in-memory, both roles, v1 + 1.1 | none | interop tests (in-memory `Network`, no sockets) |

## 3. Differences between documented and implemented behaviour

| # | Document says | Implementation does | Finding |
|---|---|---|---|
| D-1 | PROTOCOL §5.2: the responder MUST NOT fetch `discovery_url` when the request arrives | the reference peer fetches it inside `_pairing_submit` | F-06 |
| D-2 | PROTOCOL §5.3, §7.3: `high_risk` / `admin` need a second administrator; connection waits in `awaiting_second_approval` | reference `approve()` / `accept()` activate at once | F-01 |
| D-3 | PROTOCOL §3, §7.2: unknown scopes are never granted; `available: false` refused at approval | reference `approve()` grants any scope the peer requested, catalogued or not | F-02 |
| D-4 | PROTOCOL §11: a peer accepts active and retiring keys; retired keys stop | reference peer only ever adds keys from a fetched JWKS; nothing is removed | F-05 |
| D-5 | CONNECTION_HEALTH §1: `active` only after a passing connection test; kill switch blocks activation | reference peer: `active` immediately on approval; no kill switch, no suspended state | F-10 |
| D-6 | PROTOCOL §3/§9: unknown event types answered `403 event_type_not_allowed` | reference peer accepts any well-formed type | F-15 |
| D-7 | PROTOCOL §10: unauthenticated health includes `installation_id` | reference peer omits it | F-21 |
| D-8 | PROTOCOL §13: 401 responses carry `WWW-Authenticate: DPoP …` | reference peer omits it | F-21 |
| D-9 | OpenAPI lists `GET /connect/v1/customers` | reference peer does not serve it | F-21 |
| D-10 | PROTOCOL §2: private-key encryption at rest **SHOULD**; CLAUDE_INTEGRATION_GUIDE §3 and THREAT_MODEL present it as **MUST** / an existing mitigation | no helper in either SDK; `private_key_to_pem` writes unencrypted PKCS#8 | F-08 |
| D-11 | PROTOCOL §5.1, THREAT_MODEL: pairing rate-limited per IP and globally | no rate limiter anywhere | F-07 |
| D-12 | IP_ALLOWLIST §4: approved-destination pin on every resolved and connected address, SPKI pins | not in either SDK (documented as a known limitation) | F-03 |
| D-13 | README errata: discovery capability entries are keyed `scope` | verified consistent: PROTOCOL §4 example, OpenAPI `Scope`, `schemas/Scope.schema.json`, both SDKs | none (consistent) |

## 4. Findings

Severity is the impact on a host that follows this repository, taking into account that the reference peer is
labelled test code. "Reference" means the defect is in `reference_peer.py`, which the guides present as the most
compact worked example and which hosts are told to use as "the other application" in their own tests.

### Critical

None found. No defect was found that lets an unauthenticated party obtain tokens, forge signatures or reach a
tenant without a grant in the SDK verification functions; the signature, `typ`, audience, issuer, lifetime and
replay checks behave as specified on every vector and on the negative tests tried.

### High

**F-01 — Reference peer activates elevated scopes with one approval** (*confirmed*, reference).
`ReferencePeer.approve(scopes=['remote_actions:execute', 'connection:admin', …])` set the connection to `active`
and the next token carried both elevated scopes. No second administrator, no re-authentication, no fingerprint.
Reproduction: `F2 B state after single approve with elevated+unknown scopes: active [...]`,
`F3 token scope issued: bogus:scope connection:admin connection:read remote_actions:execute`.

**F-02 — Reference peer grants scopes that are not in its catalog** (*confirmed*, reference). `approve()` checks
only that the scopes were requested by the peer, not that they exist, are available, or what tier they are.
`bogus:scope` above was granted and issued.

**F-03 — No approved-destination enforcement; no TypeScript transport** (*confirmed*, SDK). Python
`MinimalGuardedTransport` decides only whether an address *class* is allowed (public, or private when
`allow_private`). A DNS change to any other public address — or a hijack plus a mis-issued certificate — is
accepted. The TypeScript SDK has no transport at all, so every TypeScript host writes its own SSRF and TLS logic.

**F-04 — Replay protection is in-memory only** (*confirmed*, SDK). The only `ReplayStore` implementations are
process-local dictionaries. A host running several workers, or restarting, accepts a client assertion, DPoP
proof, pairing request, invitation, exchange or event id a second time. The interface is correct; a persistent,
atomic implementation and its tests were missing.

**F-05 — A rotated-out key is accepted by the peer forever** (*confirmed*, reference; SDK API invites it).
`_refresh_remote_keys` does `remote_keys.update(ring)`. A key that the owner retired (for example after a
suspected compromise) stays valid at the peer until the connection is revoked. Reproduction: after rotation and
100 000 s, `F4 retired key still accepted by peer after overlap: True`. The SDK's `verify_endorsed_jwks` returns
the full current ring, so the fix is to *replace* the ring; the SDK documentation did not say so.

### Medium

**F-06 — Responder fetches the initiator's discovery URL on an unauthenticated request** (*confirmed*,
reference). Contradicts PROTOCOL §5.2 and gives any code holder a server-side request primitive. Reproduction:
`F1 B fetched A discovery on submit (before admin action): True`.

**F-07 — No rate limiting anywhere; documented limits are per process** (*confirmed*). Pairing, token and event
endpoints of the reference peer are unlimited; THREAT_MODEL §5 already notes that per-process caches multiply by
worker count. The 5-wrong-codes burn rule is implemented (per invitation, in memory).

**F-08 — Private-key protection is inconsistent and unsupported** (*confirmed*, spec + SDK). See D-10. No AEAD
helper, no master-key interface, no rotation or backup guidance.

**F-09 — Transport gaps beyond F-03** (*confirmed*, SDK). `MinimalGuardedTransport` has per-operation socket
timeouts but no overall deadline (a server that drips one byte per timeout keeps a worker for a long time), no
request-body limit, no SPKI pinning and no certificate-expiry signal; the error codes `spki_mismatch`,
`certificate_name_mismatch` and `destination_changed` are defined but never raised. There was no test that
opened a real TLS connection.

**F-10 — Reference peer lifecycle is simpler than the documented one** (*confirmed*, reference). See D-5. No
`testing`, `security_blocked`, `suspended` states; no kill switch.

**F-11 — Address classification depends on the Python patch version** (*confirmed*, SDK). `ip_allowed` falls
back on `ipaddress.is_global`, whose tables changed in Python 3.11–3.13. On Python 3.12.3 the deprecated IPv6
site-local range `fec0::/10` is classified public and allowed (`ip_allowed('fec0::1', False) is True`). CI tests
3.10 and 3.12, so results can differ between the two matrix entries.

**F-12 — Pairing requests consume replay storage before the code is checked** (*confirmed*, SDK + reference).
A pairing request is signed with a key carried in its own header, so "record after the signature verified" does
not authenticate anything: any client can create unlimited valid requests and `verify_request` records each `jti`
before the code is compared. Without rate limiting (F-07) this grows replay storage without bound.

**F-13 — TypeScript SDK lacks server-side helpers present in Python** (*confirmed*). No resource-request
authentication (Bearer refusal + token + proof binding), no discovery parsing with the same-origin rule, no scope
catalog or tenant authorisation. TypeScript hosts must re-implement security checks that Python hosts get.

**F-14 — Audit chain has no anchor** (*confirmed*, design). `verify_chain` detects a changed, removed or
reordered entry only when the verifier has an independent copy of some later hash. An attacker who can rewrite
the whole table can recompute every hash. The documents say "detects, cannot prevent" but offer no checkpoint,
signature or external anchor, no export verification and no redaction helper.

**F-16 — No trusted-proxy client-address resolver** (*confirmed*, missing). Every document requires
"trusted-proxy logic only"; neither SDK provides it, and source policy is only as good as the address it is fed.

### Low

**F-15 — Event receiver order and type checks** (*confirmed*, reference). The event id is recorded before the
tenant/scope authorisation, so a refused event's id is consumed and a later legitimate redelivery is reported as
`duplicate`; no event-type allow-list (D-6).

**F-17 — Unbounded or quadratic in-memory replay stores** (*confirmed*). TypeScript `MemoryReplayStore` never
prunes; Python prunes the whole dictionary on every insert once it holds more than 10 000 entries.

**F-18 — IPv4-mapped sources not normalised** (*confirmed*). `source_in_egress('::ffff:203.0.113.10', …)` is false
for an IPv4 declaration; dual-stack servers report mapped addresses. Fails closed (usability, not a bypass).

**F-19 — Reference rotation never retires** (*confirmed*, reference). `to_retire` is never called; retiring keys
are never moved to `retired` or wiped. `_pairing_status` assumes exactly one remote key and raises an unhandled
`ValueError` otherwise.

**F-20 — Token endpoint distinguishes unknown and inactive clients** (*confirmed*, reference). "unknown client" vs
"connection is not active" lets a caller probe connection ids. Minor.

**F-22 — CI supply chain** (*confirmed*). Actions are pinned by SHA (good) but Python dependencies are open ranges
installed without hashes; no SAST, dependency audit, secret scan, OpenAPI validation, schema-compatibility check,
property-based tests, SBOM, Dependabot or release automation.

### Informational

**F-21 — Minor document/implementation differences** D-7, D-8, D-9.

**F-23 — DPoP server nonces not supported.** RFC 9449 §8 nonces are optional; without them a proof can be
pre-computed up to 120 s ahead. Single-use `jti` still prevents replay.

**F-24 — Delegated-user (actor) claims and per-action approval are design notes only** (PROTOCOL §17), while the
`remote_actions:execute` scope is in the example catalog. The tier text says every use needs per-action approval,
but there was no message or helper for it.

**F-25 — Live conformance checks are read-only and unauthenticated** (by design); there is no black-box test that
completes pairing and authorisation against a running installation, and no second implementation.

## 5. Missing authorisation enforcement (summary)

F-01, F-02 (elevated and unknown scopes), F-05 (retired keys), F-06 (unauthenticated fetch), F-15 (authorisation
after dedup). In the SDK verification functions, tenant resolution (`tenants.authorize`) correctly intersects
token scope with grant scope and keys every lookup by connection; cross-installation and cross-tenant tests pass.

## 6. Error handling

- SDK errors carry stable codes and messages without secrets (spot-checked every `ConnectError` message).
- `discovery.fetch` maps non-200 to `transport_error` without distinguishing `source_not_authorised` (F-21 class).
- Reference peer: `ValueError` paths in `_pairing_status` (F-19); JSON decode errors of request bodies surface as
  500-style exceptions in a real server.

## 7. Missing production functionality

Persistent replay (F-04), shared rate limiting (F-07), approved destinations and TypeScript transport (F-03),
private-key encryption (F-08), trusted proxy (F-16), source-policy engine, lifecycle/health/reconnect engine,
durable event queue, audit anchoring (F-14), elevated-grant and per-action approval (F-01, F-24), a persistent
reference host and a multi-process integration test (F-25).

## 8. Test coverage gaps

No real sockets or TLS anywhere; no multi-process or restart tests; no concurrency tests for single-use values; no
property-based or fuzz tests for canonical JSON, JWS parsing, address and URL grammars; no tests for the
transport's timeout or size limits; no TypeScript tests beyond vectors and Quick Connect messages.

## 9. Code duplication

- Special-address tables exist three times with different contents: `http._ALWAYS_BLOCKED` (relies on stdlib
  flags for loopback/link-local), `quick_connect._REFUSED_NETS`, and the TypeScript copy.
- `_now` helpers and scope/tenant list parsing repeated across modules (harmless).

## 10. Unnecessary complexity

None significant. The reference peer mixes both roles, both pairing flows and resource handling in one 730-line
class; acceptable for a worked example but it should stay a test fixture, with production patterns in separate,
reusable modules.

## 11. Compatibility concerns

- The 1.0 ↔ 1.1 matrix is covered by `conformance/test_30_interop.py` (four combinations).
- Vector files are pinned; nothing in the hardening work may change them.
- Fixes to F-01/F-02/F-05/F-06 change reference-peer behaviour only (local policy), not wire messages.
- DPoP nonces, delegated actors and per-action approval are new wire behaviour and must be negotiated extensions
  in discovery `extensions`, never required of a 1.0/1.1 peer.

## 12. Resolution status

Updated as the hardening work lands. "Open" means not addressed in this repository yet.

| Finding | Severity | Status |
|---|---|---|
| F-01 | High | Fixed (P0): two distinct re-authenticated administrators bound to a request fingerprint; re-checked at token issue and every use; tests `test_security_regressions.ElevatedScopes`, TS `hardening.test.ts` |
| F-02 | High | Fixed (P0): unknown and unavailable scopes refused at approval (`invalid_scope`) |
| F-03 | High | Fixed (P0): approved-destination `GuardedTransport` in both SDKs; local TLS tests (`test_transport`, TS `hardening.test.ts`) |
| F-04 | High | Fixed (P0): `storage.SqlReplayStore` (SQLite locally; PostgreSQL in the CI service job only) |
| F-05 | High | Fixed (P0): retiring keys refused after the overlap, private half wiped; remote key ring refreshed on expiry |
| F-06 | Medium | Fixed (P0): no discovery fetch at pairing submit; read when an administrator approves |
| F-07 | Medium | Fixed (P0): shared fail-closed `RateLimiter` on pairing, token, authentication and signature failures |
| F-08 | Medium | Fixed (P0): PROTOCOL §2 now MUST; `keystore.PrivateKeyCipher` in both SDKs with a shared vector |
| F-09 | Medium | Fixed (P0): one deadline, request cap, SPKI pins, expiry warning, distinct certificate errors (new transport); legacy transport gained deadline and request cap |
| F-10 | Medium | Fixed (P1): `lifecycle` enforces the documented state machine (active only from testing with a passing test, kill switch), failure classes, reconnect ladder / circuit, health hysteresis; the in-memory reference peer still uses a simplified subset |
| F-11 | Medium | Fixed (P0): explicit address tables independent of the runtime, pinned by `addresses.json` |
| F-12 | Medium | Fixed (P0): pairing request recorded for replay only after the code matches |
| F-13 | Medium | Partial (P0): TS `authenticateResourceRequest`, scope `Catalog`, stores, approvals, keystore; discovery parsing and tenant authorisation helpers still Python-only |
| F-14 | Medium | Fixed (P1): signed checkpoints, export verification against published checkpoints, redaction (`audit`, `SqlAuditLog`; TS verification); vector `audit-checkpoint.json` |
| F-16 | Medium | Fixed (P1): `proxy.TrustedProxyResolver` (both SDKs); deployment examples in PRODUCTION_DEPLOYMENT.md |
| F-15 | Low | Fixed (P0): event-type allowlist and authorisation before the event id is recorded |
| F-17 | Low | Fixed (P0): both in-memory stores pruned over time and bounded; documented as single-process |
| F-18 | Low | Fixed (P0): IPv4-mapped sources compared as IPv4 in both SDKs |
| F-19 | Low | Fixed (P0): `retire_due` runs on token use; `_pairing_status` uses the request key |
| F-20 | Low | Fixed (P0): one error for unknown and inactive clients |
| F-22 | Low | Open (P2 CI supply chain) |
| F-21 | Info | Partial (P0): D-7 and D-8 fixed; D-9 (`/customers` in the reference peer) open |
| F-23 | Info | Fixed (P1): negotiated `dpop-nonce/1` (PROTOCOL §18.1), both SDKs and the reference peer; vector `extensions.json` |
| F-24 | Info | Fixed (P0/P1): `action-approval/1` (§7.4) and `actor/1` (§18.2) |
| F-25 | Info | Partial (P1): multi-process HTTPS harness with restart, DNS change and the TypeScript SDK as a second caller (`tests/test_harness.py`); live conformance checks remain read-only |
