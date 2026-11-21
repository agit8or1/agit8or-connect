# Source allowlists, approved destinations and bootstrap

How an installation decides **who may reach its Connect endpoints** (inbound, by source address) and **where it
may send Connect requests** (outbound, approved destinations), and how Quick Connect creates the first rules
without anyone typing a shared secret into two screens.

The wire parts are normative in [QUICK_CONNECT_SPECIFICATION.md](QUICK_CONNECT_SPECIFICATION.md) §4.4 and §7
(`qc-source-binding/1`) and [PROTOCOL.md](PROTOCOL.md) §4. The rest of this document is recommended host behaviour.

> An address is a **second factor**, never the only one. Every request still needs the connection's keys (signed
> messages, DPoP-bound tokens). Source rules shrink the attack surface; they do not replace authentication.

## 1. Inbound: default-deny for Connect endpoints

### 1.1 Scope

Every Connect route: `/.well-known/agit8or-connect` and everything under the Connect API prefix (pairing, token,
JWKS, events, capabilities, test, resources, `qc_exchange`, `qc_probe`). Not the administrator's web pages
(including the `qc_authorize` browser page); those keep the site's sign-in, second factor and firewall.

### 1.2 Two layers, both must allow

- **Installation layer:** addresses allowed to reach Connect at all.
- **Connection layer:** addresses allowed for the connection the request names.

Each layer is an allowlist (empty = deny all) plus explicit denies (deny wins). There is no "open" mode.

### 1.3 Evaluation order (per request)

```
0. Connect disabled                                   → 404
1. Client address via trusted-proxy logic only        → unreadable → 403 source_not_authorised
2. Load the source policy                             → load error → 403 (fail closed)
3. Installation layer: explicit deny                  → 403
4. Installation layer: allowlist                      → not matched → 403
5. Identify the connection the request names (§1.4)   → unknown → no connection rules → 403
6. Connection layer: explicit deny                    → 403
7. Connection layer: allowlist                        → not matched → 403
8. Rate limits, keyed by address AND connection
9. Body cap, kill switch
10. Protocol authentication (signature / assertion / DPoP)
11. Binding: the connection proven in step 10 MUST equal the one used in steps 5–7
    → mismatch → 403 source_not_authorised + security event
```

A valid token never skips steps 1–7. There is no exception for discovery, health or pairing.

### 1.4 Which connection a request names (before authentication)

| Route | Named by | Rules consulted at the connection layer |
|---|---|---|
| discovery, health | none | union of all active connections' rules, plus temporary `pairing` rules |
| `pairing` (v1 code flow) | none | union of temporary `pairing` rules (created with the invitation code) |
| `pairing_status` | the pairing request's connection | that connection's temporary + active rules |
| `qc_exchange` | `sha256(code)` from the unverified exchange payload → grant → attempt | that attempt's temporary rule |
| `token` | `client_id` form field | that connection's rules |
| `jwks` | path connection id | that connection's rules |
| `events` | `Agit8or-Connection` header | that connection's rules |
| `capabilities`, `test`, resources, `qc_probe` | `client_id` of the (still unverified) access token | that connection's rules; re-checked at step 11 |

Naming a connection that does not exist, or one that is revoked or failed, gives the same `403` as a non-matching
address, so the policy reveals nothing about connection ids.

### 1.5 Rule validation

- Refuse `0.0.0.0/0`, `::/0`, IPv4 prefixes shorter than `/16` and IPv6 prefixes shorter than `/32`.
- Private, loopback and link-local networks only as explicit entries an administrator marks as private. No
  implicit trust for "local" traffic; a site-wide LAN exemption must not apply to Connect.
- Widening a rule is a reviewed change (preview against every active connection's observed source; a second
  administrator for private addresses or ranges). Rollback only narrows.

### 1.6 Failure behaviour and logging

- Fail closed: if the policy cannot be loaded and the last good copy is older than about a minute, refuse.
- Cache the compiled policy per process keyed by a version number bumped on every change; the cache is never the
  source of truth.
- Log refusals to a folded, prunable log (per source, reason and minute), **not** to the tamper-evident audit chain;
  summarise security-relevant refusals into the chain at most once a minute.

### 1.7 What is never trusted implicitly

- A private or loopback source address.
- A source shared with another connection (NAT): the address passes for the connection whose rules list it, and the
  binding check (step 11) ties the request to that connection's key holder. Two installations behind one NAT
  address are told apart only by their keys.
- The same vendor or application type.
- An address seen in a browser request.

## 2. Where egress addresses come from

- **Own egress:** declared by the installation's administrator. A host MAY suggest a value (for example the
  `observed_source` a peer reported through `qc_probe`), but the administrator confirms it. Never derived from the
  administrator's browser address.
- **Peer egress:** only from the signed invitation (initiator) or accept (responder), proven by the exchange
  arriving from that address, and confirmed by the receiving administrator.
- **Observed vs declared:** after the first authorised exchange or probe, show both. If they differ, the request
  was already refused; nothing is added automatically. The administrator can approve a corrected address as a new
  reviewed change.

Declarations follow QUICK_CONNECT_SPECIFICATION.md §4.4: canonical form only, 1–8 entries, IPv4 `/16`–`/32`, IPv6
`/32`–`/128`, refused special-purpose networks, private networks flagged by the receiver.

## 3. Bootstrap: creating the first rules

### 3.1 Quick Connect (`qc-bootstrap/1`)

```
A admin: approve destination B (DNS + TLS preview), declare A's egress
A → browser → B's own admin UI: signed invitation (egress_A inside)
B admin (signed in to B): approve → temporary rule for egress_A on qc_exchange (+ pairing_status), ≤ 15 min
B → browser → A: accept (egress_B inside) + single-use code (120 s)
A → B (from egress_A): discovery, then qc_exchange (K_A signature + PKCE + DPoP)
both: SAS → v1 approval → each side approves the other's egress for its own endpoints
```

An exchange arriving from an address outside `egress_A` is refused by the source layer before any verification,
and recorded nothing. Rollback before both approvals removes the temporary rule and retires the attempt keys.

### 3.2 v1 code flow with the same protections

When the peer does not advertise `qc-bootstrap/1`:

- The responder's invitation page also asks for the peer's egress address(es) and creates a temporary `pairing`
  rule together with the code. Once source policy is enforced, a code without an address is not offered.
- Wrong-code floods can then only come from the authorised address; wrong codes count only against invitations
  that address was allowed for.
- The initiator approves the destination before pairing, exactly as in Quick Connect.

### 3.3 Reverse direction

Each side approves the other side's source address for its own endpoints as its own reviewed change. A connection
used in one direction only still needs the responder's discovery of the initiator to pass (identity bound to the
initiator's TLS name); the initiator then admits the responder's egress with purpose `discovery` only.

## 4. Outbound: approved destinations

Every outbound Connect request (discovery, pairing, token, JWKS, events, resources, probe) goes through a guarded
client pinned to the connection's **approved destination**:

- HTTPS only; TLS 1.2 or newer; certificate always verified (system CAs, or **only** the connection's private CA when
  configured); hostname verification on; an IP-literal destination accepted only if the certificate names that IP.
- No redirects, no proxies, no proxy environment variables; response size and time capped.
- DNS resolved once per request; **every** resolved address and the connected peer address must be in the approved
  set, else nothing is sent (`destination_changed`).
- Loopback, link-local, unspecified, multicast and cloud-metadata addresses are always refused, whatever a general
  "allow private addresses" switch in the host says. Private ranges only as explicit approved entries.
- Port 443, or the explicit port of the approved base URL.
- Optional SPKI pins compared after the handshake, before any request bytes (`spki_mismatch`).
- Keep TLS client keys out of plaintext files (load from memory where the TLS library allows it).

Both SDKs implement these rules in `GuardedTransport` (`python/agit8or_connect/transport.py`,
`typescript/src/transport.ts`), driven by a `DestinationPolicy`:

- The policy returns the connection's approved record (host, port, approved addresses with an explicit
  `private` flag and optional validity window, private CA, SPKI pins, expected installation id, state, version).
  Records carry a SHA-256 integrity digest over their canonical JSON; a missing, unreadable, inconsistent or
  tampered record refuses the request with `destination_policy_unavailable` (503). There is no fallback to the
  system resolver or to "any public address".
- Address classes come from explicit tables that do not depend on the language runtime
  (`test-vectors/addresses.json` pins them for both SDKs). IPv4-mapped and NAT64 forms are classified by the
  IPv4 address they carry; 6to4, Teredo, site-local (`fec0::/10`) and other special ranges are refused.
- Certificate failures are distinguished: `certificate_invalid`, `certificate_name_mismatch`, `spki_mismatch`.
  A certificate expiring within 21 days (configurable) produces a `certificate_expiring` warning on the response.
- One deadline covers resolution, connection, handshake and the whole response; `deadline_exceeded` (504).
- The headers `Host`, `Proxy-*`, `Connection`, `Transfer-Encoding` and `Content-Length` cannot be set by callers.
- `preview_destination` (Python) reads what an address change would look like (resolved addresses, certificate
  names, SPKI) without sending any request, for the review screen.

Stores: `MemoryDestinationStore` (tests), `SqlDestinationStore` (SQLite or PostgreSQL, Python) and
`SqliteDestinationStore` (TypeScript), all with compare-and-set on `version`. The older Python
`MinimalGuardedTransport` remains for compatibility; it applies only the address-class rules.

### 4.1 Changes of address (dynamic IP, CDN)

- A resolved address outside the pin: the request fails with `destination_changed` and its `evidence`
  (host, approved and observed addresses, time). The host calls `block(connection_id, evidence)`: the record moves
  to `security_blocked` (a new version; evidence is sanitised and size-capped) and every later request fails with
  `security_blocked` until a reviewed change.
- An administrator proposes the change; a **different** administrator approves it (`propose_change` /
  `approve_change`; a private address needs two approvers, neither of them the proposer). Old and new addresses
  can overlap for at most 7 days (`with_migration`). The connection is retested and returns to active only when
  the test passes. There is no single-administrator override.
- Peers behind rotating addresses can be approved as a range (at most IPv4 `/24`, IPv6 `/48`).

See [AUTO_RECONNECT.md](AUTO_RECONNECT.md) for why these failures never reconnect automatically.
