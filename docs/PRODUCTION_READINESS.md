# Production readiness

An honest statement of what this repository provides, what the tests prove, and what is still missing. It is a
self-assessment by the maintainers' tooling, **not** an independent audit or a certification. Findings and their
resolution are tracked in [SECURITY_AND_READINESS_AUDIT.md](SECURITY_AND_READINESS_AUDIT.md) §12.

Evidence labels used below:

- **unit**: in-process tests with mocked or in-memory collaborators;
- **local network**: real TLS / HTTP between processes on 127.0.0.1 with a test-only CA (names resolved by the
  test harness, not by real DNS);
- **CI service**: the PostgreSQL service container in GitHub Actions;
- **none**: not tested.

## 1. Feature status

| Feature | Status | Python | TypeScript | Evidence |
|---|---|---|---|---|
| v1 pairing (code flow), SAS, approvals | implemented | yes | yes | unit, vectors, local network |
| Quick Connect 1.1 (`qc-bootstrap/1`, `qc-source-binding/1`, `qc-diagnostics/1`) | implemented | yes | yes | unit, vectors |
| `private_key_jwt` + DPoP-bound tokens | implemented | yes | yes | unit, vectors, local network |
| Endorsed JWKS rotation | implemented | yes | yes | unit, local network |
| Signed events, replay / duplicate detection | implemented | yes | yes | unit, local network |
| Approved-destination transport (address tables, pins, private CA) | implemented | yes | yes | unit, local network (TLS) |
| Persistent replay / rate-limit / approval / destination stores | implemented | SQLite, PostgreSQL | interfaces + memory | unit (SQLite), multi-process (SQLite), CI service (PostgreSQL) |
| Two-administrator elevated grants | implemented | yes | yes | unit |
| Per-action approval (`action-approval/1`) | implemented (optional) | yes | yes | unit |
| Private-key envelope encryption | implemented | yes | yes | unit, vectors |
| Trusted proxy resolver | implemented | yes | yes | unit, property tests |
| Source policy engine, change preview, rollback check | implemented | yes | planned | unit, property tests |
| Lifecycle state machine, reconnect ladder, circuit breaker | implemented | yes | planned | unit |
| Durable event outbox | implemented | yes | planned | unit, multi-process (SQLite) |
| Audit redaction, signed checkpoints, export verification | implemented | yes | verify only | unit, vectors |
| `dpop-nonce/1`, `actor/1` | implemented (optional) | yes | yes | unit, vectors, local network (nonce) |
| Reference peer | test code | yes | no | unit, local network |
| Event forwarding across more than two applications | design note | — | — | none |
| Administrator UI | specification only ([QUICK_CONNECT_UI.md](QUICK_CONNECT_UI.md)) | — | — | none |
| Live interop between two independent products | not done | — | — | none |

## 2. What the tests prove

- Byte-level agreement of both SDKs on every vector (16 files, pinned by SHA-256).
- Fail-closed behaviour of every store and the transport when a dependency is missing or tampered with.
- Multi-worker correctness of replay, rate limits and the event outbox with several OS processes sharing SQLite.
- PostgreSQL store behaviour in CI (the job fails if PostgreSQL did not actually run).
- A full lifecycle across two installations × two worker processes over HTTPS on 127.0.0.1, including restart,
  DNS change → `security_blocked`, kill switch, and the TypeScript SDK as the calling side.
- Parsers and verifiers fail with protocol errors on random input (property-based fuzz tests).

## 3. What the tests do not prove

- Behaviour on a real network with real DNS, real certificates and real proxies.
- Interoperability with an implementation written by another team.
- PostgreSQL under concurrent load from many hosts (only functional tests in CI).
- Side channels, denial-of-service resistance beyond the documented limits, and the host application's own
  security (sign-in, second factor, administrator permissions) on which approvals depend.
- Any UI.

## 4. Assessment

The protocol design and the SDK security primitives are in a state where a host application can build on them
for a **controlled rollout**: feature off by default, a small number of known peers, administrators who review
every pairing, and monitoring as in [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md). Before a broad rollout
the items in §5 should be closed, above all an independent security review and a second independent
implementation.

| Area | Grade | Reason |
|---|---|---|
| Protocol architecture | B+ | Sound key binding, negotiated extensions, downgrade checks; delegation and multi-hop forwarding still design notes |
| SDK completeness | B | Python complete for host needs; TypeScript lacks source policy, lifecycle, outbox, SQL stores |
| Transport security | A- | Approved destinations, explicit address tables, pins, fail closed; tested on loopback only |
| Authentication / authorisation | B+ | `private_key_jwt` + DPoP, two-administrator elevation, action approval; depends on host re-authentication |
| Tenant isolation | B+ | Per-connection grants enforced on every resource and event; tested in unit and reference-peer tests |
| Operational reliability | B | Durable stores, outbox, reconnect policy; scheduler and monitoring are host responsibilities |
| Test coverage | B+ | Unit, vectors, property, multi-process, local HTTPS harness, PostgreSQL in CI; no real-network tests |
| Developer integration experience | B | Guides, checklist, UI contract, reference peer; no packaged server or published packages yet |
| Production readiness | C+ | Suitable for a controlled rollout by a host that follows the deployment guide; not reviewed independently |

## 5. Roadmap (planned, not implemented)

1. Independent security review of the protocol and both SDKs.
2. TypeScript parity: source policy engine, lifecycle, event outbox, SQL store adapters.
3. A conformance mode that drives a running installation through pairing with the reference peer over the network
   (opt-in, against a staging host).
4. Interoperability tests with a second implementation by another team.
5. Published packages (PyPI, npm) from the draft release workflow, with provenance attestations.
6. Event forwarding across more than two applications (PROTOCOL §17), as a negotiated extension.
7. Load tests of the PostgreSQL stores.
