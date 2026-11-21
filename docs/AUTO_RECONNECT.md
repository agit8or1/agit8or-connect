# Automatic reconnection and event recovery

Recommended host behaviour, local to each installation (nothing here is on the wire). It decides **when an
installation retries by itself and when it must stop and ask an administrator**.

The principle: **availability failures retry; security failures block.** A connection never "fixes" a changed
address, certificate, identity or key on its own.

Reference implementation (Python): `lifecycle.classify_failure`, `lifecycle.ReconnectPolicy` / `Circuit` (ladder,
CSPRNG jitter, open / half-open, permanent block on a security failure) and `storage.SqlEventQueue` (durable
outbox with leases, creation-order drain, unreached attempts not counted, dead letter, requeue with the original
id, cancel without delete). The scheduler loop of §3 is left to the host.

## 1. Security failures never reconnect

These move `active` → `security_blocked` immediately, keep their evidence, and never retry by themselves:

| Code | Cause |
|---|---|
| `destination_changed` | the peer's name resolves to (or the socket reached) an address outside the approved set |
| `certificate_invalid`, `certificate_name_mismatch`, `spki_mismatch` | TLS identity changed |
| `identity_changed` | the discovery `installation_id` differs from the stored one |
| `invalid_signature` | a response from the peer did not verify |
| `peer_revoked` | the peer answered `invalid_client` / revoked for a connection it should know (a signed `connect.connection.revoked` event revokes instead) |
| `key_revoked` | our key is refused after a completed rotation |
| `source_not_authorised` (from the peer) | our egress changed; update and coordinate with the peer's administrator |
| `scope_withdrawn` | a token was granted with fewer scopes than committed |
| binding mismatch | an inbound request authenticated as a different connection than its source rule matched |

Recovery: an administrator reviews the evidence and approves the change (for example a new address, as a reviewed
change), then the connection goes through `testing` and returns to `active` only when the test passes.

## 2. Availability failures: backoff ladder and circuit breaker

Transport failures (DNS timeout, TCP refused/reset, TLS timeout, HTTP 5xx, 429) drive health and the retry ladder:

- Ladder: `10 s, 30 s, 1 min, 2 min, 5 min, 10 min, 15 min`, then stays at 15 min.
- Jitter ±20 %, from a CSPRNG.
- First failure: circuit stays `closed`, step 0.
- At **Offline** the circuit opens: only the scheduled probe is attempted; event deliveries and other calls to that
  peer are short-circuited **without spending attempts**.
- When a probe is due the circuit is `half_open`: one probe. Success → `closed`, step reset, a full diagnostic, then
  the event queue drains. Failure → `open`, next step.
- The ladder belongs to the connection, not to each event.
- No reconnect at all from `suspended`, `revoked`, `security_blocked`, or while the kill switch is engaged.

## 3. Scheduling without a daemon

One periodic job (for example every minute) that:

1. Reaps expired Quick Connect attempts and temporary source rules (rules also carry their own expiry, so a late
   reaper never re-opens anything).
2. Loops for a bounded wall time (for example 50 s): picks connections whose `next_check_at` is due (oldest first,
   a small batch), checks them, sleeps until the next due time, and exits early when nothing is due. This gives the
   10 s and 30 s steps on top of a one-minute scheduler.
3. Delivers due events.

Safety:

- One runner per job (a claim/lock), and a compare-and-set on `next_check_at` per connection before its check, so a
  manual re-test at the same time cannot double-run it.
- Exceptions are caught per connection and recorded; the job always returns.
- Everything is in the database, so a restart resumes from `next_check_at`.

## 4. Durable event queue and recovery

- While the circuit is open, events wait: their attempt counter does not move and their next attempt follows the
  connection's probe time.
- Dead letter only on (1) a permanent status (400, 403, 404, 410, 413 …), (2) age above a limit (for example 7
  days, configurable), or (3) a number of attempts that actually **reached** the peer and got a non-permanent error
  (PROTOCOL.md §9: 12).
- On recovery the queue drains in creation order, in small batches. The receiver deduplicates by event id, so a
  crash between send and mark is safe: at-least-once delivery, idempotent receiver.
- An administrator can requeue a dead letter with its **original** id (audited); the peer still deduplicates.
- Revocation cancels queued events but keeps the rows; nothing in the queue, attempts, inbound events or
  security-block evidence is deleted by the reconnect logic. Delivered history may be pruned after a retention
  period.

## 5. Resume

`resume` after a suspension goes through `testing`, never straight to `active`. Releasing the kill switch resumes
nothing.
