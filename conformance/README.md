# Conformance suite

```bash
cd conformance
python -m unittest discover -v                 # everything below except the live checks
CONFORMANCE_REQUIRE_NODE=1 python -m unittest discover   # fail (not skip) when Node is missing — CI uses this
```

Needs Python ≥ 3.10 with `cryptography` and `PyJWT`; Node ≥ 22.18 for the TypeScript part; `PyYAML` only for the
schema/OpenAPI sync check (skipped without it). No network access.

| Module | Proves |
|---|---|
| `test_00_vectors.py` | Every file in `test-vectors/` has the SHA-256 pinned in `VECTORS.sha256` (no file added or missing), files with keys are labelled TEST-ONLY, and the Python generator reproduces every byte |
| `test_10_schemas.py` | Every positive vector message (v1 pairing, tokens, DPoP, JWKS, events; 1.1 invitation, accept, exchange, probe, `source_not_authorised`) and the reference discovery documents validate against `schemas/`; the schemas are in step with `openapi/openapi.yaml` |
| `test_20_sdk_vectors.py` | The Python SDK's vector tests and the TypeScript SDK's `node --test` both pass on the vectors in use |
| `test_30_interop.py` | Two independent in-memory reference peers pair and work in all four 1.0/1.1 combinations (Quick Connect only when both are 1.1; otherwise the v1 code flow); SAS equal on both sides; `source_not_authorised` before anything is recorded; denial; downgrade detection; single-use codes; tenant isolation between installations with identical tenant ids; revocation |
| `test_40_probe.py` | `qc_probe` answer shape (vectors, schema, nonce echo), authentication required, and the fallback: against a peer without `qc-diagnostics/1` (or whose probe route answers 404) the reverse-connectivity step is `not_tested`, with no request sent when not advertised |
| `test_90_live.py` | **Optional**, skipped unless `AGIT8OR_CONNECT_TARGET` is set: read-only, unauthenticated checks against a running installation (discovery shape and same-origin endpoints, extension consistency, health, probe refused or 404, `qc_exchange` refusing an unknown code with `source_not_authorised`). `403 source_not_authorised` from the target is accepted as conformant |

## Testing your own implementation

- **Your vectors:** `AGIT8OR_CONNECT_VECTORS=/path/to/copy python -m unittest discover` (or
  `sha256sum -c VECTORS.sha256` inside your copy).
- **Your SDK in Python:** `AGIT8OR_CONNECT_SDK=/path/containing/agit8or_connect` runs the suite against another
  checkout of the package.
- **Your running server:** `AGIT8OR_CONNECT_TARGET=https://host python -m unittest test_90_live -v`
  (`AGIT8OR_CONNECT_TARGET_PRIVATE=1` for a private address, `AGIT8OR_CONNECT_TARGET_CA=/path/ca.pem` for a private CA).
  The live checks never pair, never send a pairing code and never authenticate; a full black-box pairing run needs
  an administrator on both sides and is out of scope for an automated suite.
- **Your application in its own tests:** use `agit8or_connect.reference_peer.ReferencePeer` as "the other
  application" through your test client.

Passing this suite shows interoperability with the reference SDKs on the published vectors. It is **not** a
security certification.
