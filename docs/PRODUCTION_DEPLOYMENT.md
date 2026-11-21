# Production deployment

How to run a host application that implements Agit8or Connect with the reference SDKs. This is guidance for
hosts; the SDKs are libraries, not a server. What is and is not proven by tests is listed in
[PRODUCTION_READINESS.md](PRODUCTION_READINESS.md); the design in [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md).

## 1. Components a production host needs

| Concern | Use | Never in production |
|---|---|---|
| Replay (assertions, DPoP, pairing, events) | `storage.SqlReplayStore` on the host's database (PostgreSQL for several hosts) | `MemoryReplayStore` (per process, lost on restart) |
| Rate limits | `ratelimit.RateLimiter` over `storage.SqlRateLimitStore` | per-process limits with several workers |
| Outbound calls | `transport.GuardedTransport` with a `DestinationPolicy` (`storage.SqlDestinationStore`) | `MinimalGuardedTransport`, a general HTTP client, proxies |
| Inbound source checks | `proxy.TrustedProxyResolver` + `sources.SourcePolicy` via `sources.PolicyCache` | reading `X-Forwarded-For` from any peer |
| Elevated grants | `approvals.ElevatedGrantPolicy` over `storage.SqlGrantApprovalStore`, administrator re-authentication wired to the host's login | a single-administrator override |
| Per-action approval | `approvals.ActionApprovals` over `storage.SqlActionApprovalStore` | approving inside the request that asks |
| Private keys | `keystore.PrivateKeyCipher` with a master key outside the database (`FileMasterKeys`, `EnvMasterKeys` or a KMS-backed provider) | plaintext PEM in the database or on disk |
| Events out | `storage.SqlEventQueue` (outbox) | sending inline and forgetting on failure |
| Audit | `storage.SqlAuditLog` + periodic `audit.sign_checkpoint`, published off-host | a mutable log with no anchor |

Every store raises a `*_unavailable` error (HTTP 503) when it cannot answer; let that refuse the request. Do not
catch it and continue.

## 2. Database

- **PostgreSQL** for anything with more than one host or container. The stores use single-statement upserts and
  conditional updates, so correctness does not depend on isolation level beyond PostgreSQL's default
  `READ COMMITTED`. Give the application role `SELECT, INSERT, UPDATE, DELETE` on the `connect_*` tables only;
  run `migrate()` (or the equivalent DDL from `storage.SCHEMA`) with a separate migration role.
- **SQLite** is fine for a single host: WAL mode, `synchronous=FULL`, `BEGIN IMMEDIATE`, a busy timeout. All
  worker processes must use the same file on a local disk (not a network file system).
- Purge expired rows periodically: `SqlReplayStore.purge()`, `SqlRateLimitStore.purge(now)`. Replay rows expire
  after at most 8 days. Never delete approval, destination-change, audit or event-queue rows as part of
  "cleanup"; they are history.
- Back up the database **and** the master-key file separately. A database backup without the master key cannot
  decrypt private keys (by design); a lost master key means re-pairing.

## 3. Keys

- Generate the master key with `keystore.generate_master_key()`; store it as
  `{"current": "<id>", "keys": {"<id>": "<base64url 32 bytes>"}}` in a file with mode `0600`, owned by the service
  user (`FileMasterKeys` refuses anything else), or in an environment variable injected by the platform's secret
  store (`EnvMasterKeys`).
- Rotate: add a new key id, make it `current`, then rewrap every stored private key (`PrivateKeyCipher.rewrap`,
  `needs_rewrap`). Keep the old key until no row uses it.
- TLS client keys, if any, go through `keystore.secret_tempfile` (anonymous memory file where available).
- Keep a separate Ed25519 **audit key** for checkpoints; the web process that writes the audit table should not
  be able to read it (run checkpoint signing in a separate job or service account).

## 4. Reverse proxy and client addresses

The Connect endpoints check the **client address** before authentication. Behind a reverse proxy the TCP peer
is the proxy, so the host must be told which proxies to trust:

```python
resolver = TrustedProxyResolver(['10.20.0.5/32'], header='x-forwarded-for')   # exact proxy addresses
client = resolver.resolve(peer_address, request_headers)                         # raises source_unresolved
```

Rules: list only the proxies' own addresses (no broad ranges; `/16` IPv4 and `/32` IPv6 at most, and narrower
is better); configure exactly one header; the proxy must **replace or append** to that header. A direct client's
headers are ignored.

nginx (replace the client's header with the TCP peer address):

```nginx
location /connect/ {
    proxy_set_header X-Forwarded-For $remote_addr;   # replace, do not use $proxy_add_x_forwarded_for
    proxy_set_header Host $host;
    proxy_pass https://connect_app;
}
location = /.well-known/agit8or-connect {
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_pass https://connect_app;
}
```

Caddy:

```
handle /connect/* {
    reverse_proxy connect_app:8443 {
        header_up X-Forwarded-For {remote_host}
    }
}
```

HAProxy:

```
http-request set-header X-Forwarded-For %[src]
```

With a chain of proxies (CDN → load balancer → app), list every hop the application can see as trusted and let
each append; the resolver walks the header right to left and stops at the first untrusted address. A CDN's
published ranges are broad: prefer a CDN feature that sends a signed or dedicated client-address header, and
restrict the origin to the CDN at the network level.

## 5. Outbound traffic

- Every request to a peer goes through `GuardedTransport` with that connection's approved destination. Do not set
  `HTTPS_PROXY` for the service; the transport opens its own sockets and ignores proxy environment variables, and an
  egress proxy would hide the address the transport must check.
- The server's egress address(es) are what peers allowlist. Keep them stable (NAT gateway with a fixed address)
  and declare them to the peer; a change of egress needs coordination (the peer sees `source_not_authorised`).
- Certificate expiry warnings come back on every response (`Response.warnings`); feed them to monitoring.

## 6. Workers, scheduling, restarts

- Any number of web workers can serve Connect endpoints as long as they share the database stores above.
- Run one scheduler job (every minute) for health checks, reconnect probes and the event outbox; give it a lock so
  only one instance runs (AUTO_RECONNECT.md §3). The outbox's leases also make concurrent drains safe.
- Restarts lose nothing that matters: replay records, limits, approvals, destinations and queued events are in the
  database; tokens are short-lived and re-issued.

## 7. Secrets in logs

- Do not log request bodies, `Authorization`, `DPoP`, `client_assertion`, pairing codes or keys. Audit records go
  through `audit.redact`.
- Error responses carry codes and short messages only; the SDKs never put key material or tokens in exceptions.

## 8. Kill switch and incident response

- Offer the kill switch in the administrator UI **and** from the server command line. While engaged every Connect
  API call is answered `503 kill_switch`, approvals are refused, active connections become `suspended`. Releasing
  it resumes nothing; each connection is re-tested before it is active again.
- After a suspected key compromise: engage the kill switch, revoke the affected connections (private keys are
  wiped), rotate the master key and rewrap, then pair again.

## 9. What to monitor

- 401/403/429 rates per connection and per source; `security_blocked` transitions; `*_unavailable` errors (these
  mean a store is down and requests are being refused); certificate-expiry warnings; dead-lettered events;
  checkpoint publication succeeding.

## 10. Repository settings the owner should consider

Recommendations only; this repository does not change its own settings:

- Protect `main`: require pull requests, the CI checks (`test (3.10)`, `test (3.12)`, `postgres`, and the security
  workflow), and linear history; disallow force-pushes.
- Require signed tags for releases; enable private vulnerability reporting and Dependabot security updates.
