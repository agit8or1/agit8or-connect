# Integration checklist

A checklist for a team adding Agit8or Connect to an application. Tick every item or write down why it does not
apply. Detailed rules: [QUICK_CONNECT_IMPLEMENTATION.md](QUICK_CONNECT_IMPLEMENTATION.md),
[PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md), [QUICK_CONNECT_UI.md](QUICK_CONNECT_UI.md).

## Before writing code

- [ ] Decide the roles (initiator, responder, both) and which extensions to advertise.
- [ ] Choose the public base URL and the egress address(es); confirm they are stable.
- [ ] Decide the tenant model (customers / organisations) and how grants map to it.
- [ ] Identify which operations need per-action approval and which scopes are `high_risk` / `admin`.

## Data and storage

- [ ] Connection, key, destination, source-rule, approval, event-outbox and audit tables (or the SDK's `storage`
      schema) created by a migration.
- [ ] Shared SQL stores for replay, rate limits, approvals and destinations; no in-memory store in production.
- [ ] Private keys encrypted with `PrivateKeyCipher`; master key outside the database; rotation tested.
- [ ] Single-use values recorded after verification, in one transaction with the state change.

## Inbound

- [ ] Kill switch checked first.
- [ ] Trusted proxy resolver configured with the exact proxy addresses; a direct request's forwarding headers are
      ignored (test it).
- [ ] Default-deny source policy on **every** Connect route, two layers; `403 source_not_authorised` before
      authentication; binding check after authentication.
- [ ] Rate limits per route, source and connection from a shared store.
- [ ] Token endpoint: `private_key_jwt`, Ed25519 only, DPoP-bound tokens, short lifetimes.
- [ ] Scope and tenant checks on every resource; elevated scopes need two administrators.

## Outbound

- [ ] All peer requests through `GuardedTransport` with the approved destination; no other HTTP client touches a
      peer URL.
- [ ] A destination change goes to `security_blocked` and the Security Blocked review; nothing reconnects by itself.
- [ ] Private CA and SPKI pins, if used, configured per connection under Advanced settings.

## Lifecycle and operations

- [ ] `active` only after a passing connection test; kill switch blocks approvals.
- [ ] Scheduler job (one instance) for health, reconnect and the outbox.
- [ ] Audit redaction on; checkpoints signed by a separate key and published off-host.
- [ ] Monitoring for the signals in PRODUCTION_DEPLOYMENT.md §9.

## UI

- [ ] Wizard, SAS on both sides, second-administrator screen, Security Blocked review (QUICK_CONNECT_UI.md).
- [ ] The UI renders `allowed_actions` from the backend and never shows secrets.

## Tests

- [ ] SDK vector tests and `generate_vectors --check` pass; your own vector copy matches `VECTORS.sha256`.
- [ ] End-to-end tests against the reference peer: pairing, token, API call, event, rotation, revoke, kill switch.
- [ ] Negative tests: unlisted source on every route, replayed proof, wrong `htu`, expired token, unknown scope,
      changed destination address, store unavailable.
- [ ] A test that scans logs, errors, audit and pages for secrets.
- [ ] Conformance suite, including the live read-only checks against a staging installation.

## Release

- [ ] Feature off by default behind a setting.
- [ ] Documentation states what was implemented and tested, without claims of certification or independent
      review.
