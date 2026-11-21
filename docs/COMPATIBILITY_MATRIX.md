# Compatibility matrix

What works between installations at different protocol revisions and with different optional extensions. All
combinations use protocol major version `agit8or-connect/1`. An extension is used only when **both** discovery
documents advertise it; otherwise behaviour is exactly that of the lower side.

## 1. Revisions

| Initiator ↓ / Responder → | 1.0 | 1.1 (no hardening extensions) | 1.1 + hardening extensions |
|---|---|---|---|
| **1.0** | v1 code flow | v1 code flow | v1 code flow; no nonce, no `act`, no action approval |
| **1.1** | v1 code flow (Quick Connect not offered: `extension_not_negotiated`) | Quick Connect or code flow | Quick Connect or code flow; hardening extensions unused |
| **1.1 + hardening** | v1 code flow; extensions unused | Quick Connect or code flow; extensions unused | Quick Connect or code flow; negotiated extensions active |

"Hardening extensions" = `dpop-nonce/1`, `actor/1`, `action-approval/1` (PROTOCOL.md §7.4, §18).

## 2. Per extension

| Extension | Advertised in | Effect when negotiated | Effect when one side lacks it |
|---|---|---|---|
| `qc-bootstrap/1` | discovery `extensions` | browser-mediated pairing | v1 code flow |
| `qc-source-binding/1` | discovery | signed egress declarations, temporary rule | source rules entered by administrators |
| `qc-diagnostics/1` | discovery | `qc_probe` | probe step reported `not_tested` (never a failure) |
| `dpop-nonce/1` | discovery | server nonces in DPoP proofs, `use_dpop_nonce` + one retry | `iat` window + jti replay store only |
| `actor/1` | discovery | `act.sub` in access tokens, attributed actions | no actor; actions attributed to the connection |
| `action-approval/1` | discovery | listed operations wait for an administrator (`action_approval_required`) | operations governed by scopes only |

A peer that receives an unknown extension name ignores it. An access token carrying `act` on a connection that
did not negotiate `actor/1` is refused (`invalid_token`); a DPoP `nonce` claim on a connection without
`dpop-nonce/1` is ignored, as RFC 9449 allows.

## 3. SDK coverage

| Capability | Python SDK | TypeScript SDK |
|---|---|---|
| v1 messages, tokens, DPoP, pairing, events, JWKS, audit chain | yes | yes |
| Quick Connect 1.1 messages and checks | yes | yes |
| Guarded transport, approved destinations, address tables | yes | yes |
| Replay / rate-limit / approval stores (SQL) | SQLite + PostgreSQL | in-memory interfaces (host provides SQL) |
| Key envelope (`a8ck1`) | yes | yes |
| Trusted proxy resolver | yes | yes |
| Source policy engine, change preview | yes | no (planned) |
| Lifecycle state machine, reconnect policy | yes | `backoffSeconds` only (planned) |
| Event outbox, audit log store | yes (SQL) | no (planned) |
| `dpop-nonce/1`, `actor/1` | yes | yes |
| Audit checkpoints | sign + verify | verify |
| Reference peer (both roles) | yes (test code) | no |

## 4. Data and wire stability

- The 12 original vector files are frozen (`conformance/VECTORS.sha256`). New behaviour adds new vector files.
- Schemas change only additively within the major version; `tools/check_schema_compat.py` rejects removed
  properties, newly required properties, changed types and lost enum values.
- SQL tables are created with `IF NOT EXISTS`; new tables are additive. Hosts that ran the P0 schema need no data
  migration for P1 (new tables only).
