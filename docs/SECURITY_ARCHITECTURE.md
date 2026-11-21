# Security architecture

How the protections of Agit8or Connect fit together, which layer enforces each, and which module implements it.
Normative rules are in [PROTOCOL.md](PROTOCOL.md) and [QUICK_CONNECT_SPECIFICATION.md](QUICK_CONNECT_SPECIFICATION.md);
threats and residual risks in [THREAT_MODEL.md](THREAT_MODEL.md). This document has not been independently reviewed.

## 1. Request path (inbound)

Every request to a Connect route passes these gates in order. A gate that cannot reach its store refuses
(`*_unavailable`, 503); none of them fails open.

| # | Gate | Refusal | Module (Python / TypeScript) |
|---|---|---|---|
| 1 | Kill switch | `503 kill_switch` | host flag; reference peer |
| 2 | Client address through trusted proxies only | `403 source_unresolved` | `proxy` / `TrustedProxyResolver` |
| 3 | Source policy, installation layer then connection layer, deny wins | `403 source_not_authorised` | `sources.SourcePolicy` + `PolicyCache` (Python) |
| 4 | Rate limit (per route, source, connection, administrator), shared store | `429 rate_limited` | `ratelimit` / `stores.ts` |
| 5 | Client authentication: `private_key_jwt` assertion, Ed25519 only, `typ`, audience, times | `401 invalid_client` | `tokens` / `index.ts` |
| 6 | DPoP proof: key binding (`cnf.jkt`), `htm`/`htu`, `ath`, optional nonce (`dpop-nonce/1`) | `401 invalid_dpop_proof` / `use_dpop_nonce` | `tokens`, `extensions` / `index.ts`, `extensions.ts` |
| 7 | Replay: jti / code / event id recorded after verification, unique constraint | `401 replayed` | `replay`, `storage.SqlReplayStore` |
| 8 | Binding: the authenticated connection is the one whose source rule matched | `403 source_not_authorised` | `sources.check_binding` |
| 9 | Scope and tenant: token scopes, per-customer grants | `403 insufficient_scope` / `tenant_not_granted` | `scopes`, `tenants` |
| 10 | Elevated scopes: grant approved by two administrators, fingerprint-bound | `403 second_admin_required` | `approvals.ElevatedGrantPolicy` |
| 11 | Per-action approval (`action-approval/1`) for listed operations | `403 action_approval_required` | `approvals.ActionApprovals` |
| 12 | Audit (redacted) | — | `audit`, `storage.SqlAuditLog` |

## 2. Request path (outbound)

`transport.GuardedTransport` (both SDKs) is the only way the SDKs reach a peer:

1. The connection's **approved destination** is loaded and its integrity digest checked
   (`destinations.DestinationPolicy`, `storage.SqlDestinationStore`); missing or tampered → refuse.
2. The name is resolved; every address is classified (`addresses`, explicit tables); loopback, link-local,
   unspecified, multicast, metadata and mapped/NAT64 forms of them are always refused; each address must be in the
   approved set. An unapproved address → `destination_changed` and the connection becomes `security_blocked`.
3. TCP to the checked address (no second resolution), TLS ≥ 1.2, certificate and hostname verification against
   the system store or the connection's private CA (which then *replaces* the system store), optional SPKI pins.
4. One request, no redirects, no proxies, forbidden hop-by-hop headers refused, one overall deadline, bounded
   response size.

## 3. Trust establishment

- Pairing (v1 code flow or Quick Connect `qc-bootstrap/1`) exchanges Ed25519 keys and installation ids; both
  administrators compare the **SAS** derived from the transcript and approve.
- Quick Connect adds a signed invitation, PKCE, a DPoP-bound exchange, a temporary 15-minute source rule for
  exactly the declared egress, and a downgrade check against discovery.
- `active` is reachable only from `testing` with a passing connection test and the kill switch released
  (`lifecycle.transition`).

## 4. Keys and secrets

- Private keys at rest: `keystore.PrivateKeyCipher`, envelope `a8ck1.<kid>.<nonce>.<ct>` (AES-256-GCM, associated
  data bound to table, column and row). Master keys outside the database, rotatable with rewrap.
- Key rotation for connection keys: `rotation` (overlap, endorsed JWKS).
- No secret appears in logs, errors, audit or exports; `audit.redact` strips known secret fields and token-shaped
  values.

## 5. Availability vs security failures

`lifecycle.classify_failure` sorts every failure into **security** (block, never retry), **availability** (retry
on the ladder 10 s → 15 min with jitter, circuit breaker), **permanent** (stop, needs an administrator) or
**local** (fix configuration). Events go through the durable outbox (`storage.SqlEventQueue`) so an outage loses
nothing.

## 6. Evidence and anchoring

- Audit entries form a hash chain; `audit.sign_checkpoint` signs the head with a separate audit key; exports
  (`agit8or-connect-audit-export/1`) verify against previously published checkpoints.
- Destination changes, grant approvals and action approvals are stored as history, never deleted.

## 7. Compatibility as a security property

New wire behaviour arrives only as negotiated extensions (`dpop-nonce/1`, `actor/1`, `action-approval/1`,
Quick Connect's `qc-*`). An extension is used only when both installations advertised it; a downgrade attempt on
Quick Connect is detected (`downgrade_detected`). Existing test vectors never change
(`tools/check_schema_compat.py` enforces it in CI).

## 8. Supply chain

- Python dependencies are hash-locked (`requirements/*.txt`, installed with `--require-hashes`); the TypeScript
  SDK has no npm dependencies (checked in CI).
- CI: CodeQL (Python, TypeScript, workflows), secret scanning, `pip-audit`, dependency review on pull requests,
  OpenAPI validation, schema / vector compatibility, SBOM (CycloneDX). Actions are pinned by commit SHA.
- Releases: a tag pushed by the owner builds the packages, SBOM and checksums into a **draft** release.
