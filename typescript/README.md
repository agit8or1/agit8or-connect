# @agit8or/connect (TypeScript reference SDK)

> Draft. Not yet independently security-reviewed. Do not describe or deploy it as production secure.

Sign / verify / token / webhook functions of the Agit8or Connect protocol
`agit8or-connect/1` (see [`../docs/PROTOCOL.md`](../docs/PROTOCOL.md)), written with
`node:crypto` only — no npm dependencies. The source uses erasable TypeScript
syntax only, so Node 22.18+ runs it directly (type stripping); a project can also
compile it with its normal `tsc` build.

    npm test            # = node --test test/*.test.ts

The tests verify the shared vectors in [`../test-vectors/`](../test-vectors/),
the same files the Python SDK verifies. Passing them is the interop proof. Set
`AGIT8OR_CONNECT_VECTORS=/path/to/test-vectors` to run against another copy.

Protocol revision 1.1 ([`../docs/QUICK_CONNECT_SPECIFICATION.md`](../docs/QUICK_CONNECT_SPECIFICATION.md),
optional Quick Connect extensions) is in the same file, after the v1 functions:
`buildInvitation` / `verifyInvitation`, `buildAccept` / `verifyAccept`,
`buildExchange` / `verifyExchange`, `qcTranscriptHash` / `qcSas`,
`negotiateExtensions` / `checkNoDowngrade`, `normalizeNet` / `checkNet`,
`checkBase` / `checkRedirectUri`, `buildProbeResponse` /
`validateProbeResponse`. `test/qc.test.ts` verifies `test-vectors/qc-*.json`.

## Not included: an outbound HTTP transport

Unlike the Python SDK (`agit8or_connect.http.MinimalGuardedTransport`), this SDK
does **not** ship a guarded HTTP client. It builds and verifies messages; sending
them is up to the host. Whatever client you use MUST follow the outbound rules of
[`../docs/IP_ALLOWLIST_AND_BOOTSTRAP.md`](../docs/IP_ALLOWLIST_AND_BOOTSTRAP.md)
(HTTPS only, TLS ≥ 1.2 with verification, no redirects, no proxies, destination
address checked at connect time after DNS resolution, loopback / link-local /
metadata always refused). A guarded TypeScript transport is planned.
