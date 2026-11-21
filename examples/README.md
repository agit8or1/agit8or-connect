# Examples

Minimal, in-process peers. They show the order of operations; they are not production code
(no persistence, no real network, no administrator UI).

| File | What it shows | Run |
|---|---|---|
| `python/quick_connect_peers.py` | Two in-memory installations (`ReferencePeer`) pair with Quick Connect, finish with the v1 approval, make an authorised call, send a signed event and run the probe. | `cd python && python ../examples/python/quick_connect_peers.py` |
| `typescript/quick_connect_messages.ts` | The four Quick Connect messages (invitation, accept, exchange + DPoP) built and verified with the TypeScript SDK in the order A and B use them, then the SAS on both sides. | `node examples/typescript/quick_connect_messages.ts` (Node ≥ 22.18) |

Every key in the examples is generated at run time. The keys in `test-vectors/` are
published, TEST-ONLY keys and must never be used anywhere else.
