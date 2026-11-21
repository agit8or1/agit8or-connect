# Guide for AI coding assistants implementing an Agit8or Connect peer

This file is written for an AI coding assistant (Claude or any other) asked to add Agit8or Connect to an
application, and for the people reviewing its work. Read it completely before writing code. The key words MUST,
MUST NOT, SHOULD and MAY are used as in RFC 2119.

> Status: the protocol, SDKs and this guide are a **draft that has not been independently security-reviewed**.
> Do not tell users that the result is "production secure", "audited" or "certified". Say what was implemented
> and which conformance checks pass.

## 1. Read these, in this order

1. [PROTOCOL.md](PROTOCOL.md) — `agit8or-connect/1`, the base protocol. Normative.
2. [QUICK_CONNECT_SPECIFICATION.md](QUICK_CONNECT_SPECIFICATION.md) — revision 1.1, optional extensions. Normative.
   §13 is the implementer checklist (repeated in §6 below).
3. [QUICK_CONNECT_IMPLEMENTATION.md](QUICK_CONNECT_IMPLEMENTATION.md) — what to store, endpoints, host checks.
4. [IP_ALLOWLIST_AND_BOOTSTRAP.md](IP_ALLOWLIST_AND_BOOTSTRAP.md), [CONNECTION_HEALTH.md](CONNECTION_HEALTH.md),
   [AUTO_RECONNECT.md](AUTO_RECONNECT.md), [THREAT_MODEL.md](THREAT_MODEL.md).
5. [`openapi/openapi.yaml`](../openapi/openapi.yaml) and [`schemas/`](../schemas/) for shapes;
   [`test-vectors/`](../test-vectors/) for exact bytes.
6. [`python/agit8or_connect/reference_peer.py`](../python/agit8or_connect/reference_peer.py) — a complete worked
   example of both roles.

When documents disagree: the specifications win over the guides; the vectors win over prose for byte-level
questions. Report the disagreement; do not silently pick one.

## 2. Ground rules

- **Use a reference SDK** (Python `agit8or_connect`, TypeScript `typescript/src/index.ts`) or reproduce every vector.
  Do not hand-roll JWS, canonical JSON, thumbprints, DPoP or the SAS.
- **Do not invent protocol.** No new claims, headers, error codes, endpoints or algorithms. Unknown members you
  receive MUST be ignored (except JWS `crit`, which MUST be refused).
- **Do not weaken a check to make a test pass.** If a vector fails, the implementation is wrong.
- **Do not change files in `test-vectors/`.** They are pinned by SHA-256 (`conformance/VECTORS.sha256`).
- **Never use the vector keys** outside tests. They are published, TEST-ONLY seeds.
- Keep the feature **off by default** behind a setting, and make the public base URL a required setting.
- Ask the human before: exposing Connect routes publicly, choosing the egress address, granting `high_risk` or
  `admin` scopes, or relaxing any rule in §3.

## 3. MUST / MUST NOT

### Cryptography and messages

- MUST accept only Ed25519 (`alg: EdDSA`). MUST refuse `none`, HMAC and every other algorithm.
- MUST check the JWS `typ` of every message against the one expected at that step.
- MUST produce canonical JSON for every signed or hashed JSON value.
- MUST verify in the order the specification gives and return the listed error code for each failure.
- MUST record single-use values (jti, codes, event ids) **after** verification passes, using a unique constraint,
  in one transaction with the state change.
- MUST compare secrets (state, code hashes) in constant time.
- MUST NOT log, audit, display or export tokens, assertions, DPoP proofs, codes, PKCE verifiers, signatures or
  private keys.
- MUST encrypt private keys at rest, with associated data bound to the row.

### Network

- MUST refuse every source address by default on all Connect routes, before authentication, with an installation
  layer and a connection layer that both must allow. MUST answer `403 source_not_authorised`.
- MUST read the client address only through trusted-proxy logic. MUST NOT trust `X-Forwarded-For` from anyone else.
- MUST bind an authenticated request to the connection whose source rule matched.
- MUST NOT derive any source rule from the address of a browser request.
- Outbound: MUST use HTTPS, TLS ≥ 1.2 with certificate and hostname verification; MUST NOT follow redirects or use
  proxies; MUST check every resolved address and the connected address against the approved destination; MUST
  always refuse loopback, link-local, unspecified, multicast and metadata addresses.
- MUST NOT fetch a peer's `discovery_url` or `base` until an administrator performs a deliberate action (POST).

### Quick Connect

- MUST use the conventional browser entry point `/agit8or-connect/qc-authorize` (or a `303` to the real page on the
  same origin) as a page behind the normal sign-in — not a Connect API route.
- MUST NOT add a password grant or any field that could carry a password.
- MUST put the source-address check before anything else on `qc_exchange`.
- MUST check for downgrade after the callback and fall back to the v1 code flow whenever negotiation does not yield
  `qc-bootstrap/1`.
- MUST show the SAS on both sides and require both administrators' approval.
- MUST remove the temporary rule and retire attempt keys on any failure before both approvals. Rollback MUST only
  remove access.

### Lifecycle

- MUST make a connection `active` only after a passing connection test.
- MUST NOT auto-reconnect after a security failure (changed destination, certificate, identity or key; peer
  revocation; `source_not_authorised` from the peer). Block and show the evidence.
- MUST refuse approvals and activation while the kill switch is engaged.
- MUST probe (`qc_probe`) only peers that advertise `qc-diagnostics/1`; a 404 or a 1.0 peer is `not_tested`, never a
  failure.

## 4. Suggested work plan

1. Data model (QUICK_CONNECT_IMPLEMENTATION.md §2) with migrations.
2. Discovery + health + the inbound source policy (with tests that an unlisted address gets `403` on every route).
3. v1 pairing (code flow), tokens, JWKS, resources, events — using the SDK.
4. Outbound guarded client with approved destinations.
5. Lifecycle, connection test, health, reconnect.
6. Optional: Quick Connect (1.1), then `qc_probe`.
7. Administrator UI.
8. Run the SDK vector tests, the conformance suite, and your own end-to-end tests against the reference peer.

## 5. How to run conformance

From a checkout of this repository (Python ≥ 3.10 with `cryptography` and `PyJWT`; Node ≥ 22.18 for the
TypeScript part; `PyYAML` optional):

```bash
cd python && python -m unittest discover && python -m agit8or_connect.tools.generate_vectors --check && cd ..
cd typescript && npm test && cd ..
cd conformance && python -m unittest discover -v && cd ..
```

Against your running installation (read-only, unauthenticated, from an address you have allowed or not):

```bash
cd conformance
AGIT8OR_CONNECT_TARGET=https://your-installation.example python -m unittest test_90_live -v
# private address: AGIT8OR_CONNECT_TARGET_PRIVATE=1   private CA: AGIT8OR_CONNECT_TARGET_CA=/path/ca.pem
```

If your implementation keeps its own copy of the vectors, prove it is identical:
`cd your/vectors && sha256sum -c /path/to/agit8or-connect/conformance/VECTORS.sha256`, or run the suite with
`AGIT8OR_CONNECT_VECTORS=/path/to/your/vectors`.

For end-to-end tests inside your application, wire `ReferencePeer` to your test client as "the other application"
(see QUICK_CONNECT_IMPLEMENTATION.md §8).

## 6. Implementer checklist (QUICK_CONNECT_SPECIFICATION.md §13, extended)

1. Implement 1.0 first; pass every v1 vector.
2. Add discovery members only for extensions you implement; keep `versions: ["1"]`.
3. Serve `/agit8or-connect/qc-authorize` (browser) if you implement `qc-bootstrap/1` as a responder.
4. Verify in the order given; return the listed code for each failure; record single-use values last, in one
   transaction with your state change.
5. Put the source-address check before anything else on `qc_exchange`.
6. Show the SAS on both sides and require both administrators' approval (v1).
7. Fall back to the v1 code flow whenever negotiation does not yield `qc-bootstrap/1`.
8. Reproduce `test-vectors/qc-*.json` byte for byte.
9. Default-deny every Connect route by source address, two layers, binding check after authentication.
10. Pin outbound requests to approved destinations; security failures block, never reconnect.
11. `active` only after a passing connection test; kill switch blocks approvals.
12. No secrets in logs, audit, errors, pages or exports — add a test that scans for them.
13. The conformance suite passes, including the live checks against your instance.

## 7. What to report back to the human

- Which roles (initiator / responder) and extensions you implemented.
- The exact commands you ran and their final lines.
- Every rule from §3 you could not follow, and why.
- Every disagreement you found between documents, schemas and vectors.
- That the result is **not independently security-reviewed**.
