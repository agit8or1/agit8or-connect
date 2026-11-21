# Quick Connect: administrator UI specification and workflow contract

Recommended host behaviour (local, not on the wire). It turns QUICK_CONNECT_SPECIFICATION.md (protocol),
QUICK_CONNECT_IMPLEMENTATION.md §4–6 (host checks) and CONNECTION_HEALTH.md (lifecycle) into screens, and defines a
**workflow contract**: the state object a host's backend gives its UI, so that every UI shows the same facts, offers
only the actions that are safe in the current state, and maps every error code to a next step.

The key words MUST, SHOULD and MAY are used as in RFC 2119.

## 1. Principles

- The UI never decides security. It renders the workflow state and posts actions; the backend re-checks every
  precondition (state, permissions, re-authentication, kill switch) on every action.
- Every step that contacts the other installation is a deliberate **POST** by an administrator. Opening or
  refreshing a page never sends a request to a peer.
- The **SAS** (short authentication string) is shown on both sides, large, in the same grouping, and the approve
  button stays disabled until the administrator confirms it matches.
- Elevated permissions (`high_risk`, `admin`) are visually separated, never pre-selected, and need a second
  administrator. No screen offers a single-administrator override.
- No secret is ever displayed after creation: pairing codes are shown once; tokens, keys, PKCE values and
  assertions are never displayed.
- Error text says what happened and what to do next; never a stack trace, never a raw protocol payload.

## 2. Initiator (A) wizard

| # | Screen | Shows | Action (POST) | Backend preconditions | Next |
|---|---|---|---|---|---|
| A1 | Choose application | catalog of known application types; free URL entry | — | Connect enabled; administrator may manage connections | A2 |
| A2 | Destination | normalised URL; **preview**: resolved addresses with their class (public / private / documentation), certificate subject, SANs, issuer, expiry, SPKI; warnings (private address, certificate expiring, name mismatch) | `approve_destination` | fresh re-authentication; private address needs explicit tick (+ second administrator if the policy says so); preview is not older than 10 min | A3 |
| A3 | Identity | discovery identity *after* the administrator asks for it: display name, application type, installation id, supported extensions; a warning if the installation id is already connected | `read_discovery` | destination approved | A4 (Quick Connect) or A4c (code flow) |
| A4 | Quick Connect | requested permissions grouped by tier; customers to propose; own egress addresses (declared, editable only via settings) | `start_quick_connect` → browser `303` to B | `qc-bootstrap/1` negotiated; egress declared | B screens, then A5 |
| A4c | Code flow | input for the pairing code from B (or QR) | `submit_code` | — | A5 |
| A5 | Verify | **SAS** (both sides must show the same); B's display name, installation id, key fingerprint; B's egress from the signed accept | `confirm_sas` | callback verified, downgrade check passed | A6 |
| A6 | Approve | granted permissions per tier; customer mapping; B's egress → A's source rules (preview against active connections) | `approve` | SAS confirmed; kill switch released | A7 (waits for B) |
| A7 | Waiting | B's status (`pending`, `awaiting_second_approval`) | `poll` (automatic, rate-limited) | — | A8 |
| A8 | Test | diagnostic steps with pass / fail / not tested | `run_test` | both sides approved | A9 or back to A2/A6 with the failing step highlighted |
| A9 | Done | connection page | — | test passed (`active` committed) | — |

## 3. Responder (B) screens

| # | Screen | Shows | Action | Preconditions |
|---|---|---|---|---|
| B1 | Review invitation (behind normal sign-in at `/agit8or-connect/qc-authorize`) | initiator host, claimed installation id, egress (private flagged), requested permissions by tier with unknown / unavailable ones marked "will not be granted", expiry countdown | `accept_invitation` / `decline` | invitation verified; administrator permission; fresh re-authentication; review rate limit |
| B2 | Verify | SAS; A's display name and installation id **from A's discovery** (read on this POST) | `confirm_sas` | exchange arrived from A's declared egress |
| B3 | Approve | permissions to grant (elevated ones in a separate box with "needs a second administrator"); customers; A's egress → B's source rules | `approve` | SAS confirmed; kill switch released |
| B3b | Second approval (another administrator) | the exact request: scopes, customers, keys, installation id, proposer, proposal time; a notice if anything changed since the proposal | `second_approve` / `reject` | different account from the proposer; fresh re-authentication; fingerprint unchanged |
| B4 | Test and done | as A8–A9 | `run_test` | — |

## 4. Connection page (both sides)

- Header: display name, application type, state badge (§6), health (`connected` / `degraded` / `offline`).
- Identity: remote installation id, key fingerprints with states (active, retiring until …, retired), rotation dates.
- Network: approved destination (host, port, addresses with validity windows, private CA yes/no, SPKI pins);
  inbound source rules; last observed source.
- Permissions: granted scopes by tier, per customer; elevated approvals with both administrators and times.
- Activity: last token, last event in/out, queue counts (pending / dead), recent refusals (folded), audit link.
- Actions (only those in `allowed_actions`): test, rotate now, suspend, resume (re-tests), revoke elevated,
  revoke, approve address change, requeue dead letters, export audit.

## 5. Security Blocked review

Shown when a connection enters `security_blocked` (destination change, certificate / SPKI change, identity change,
binding mismatch …):

- What changed, from the stored **evidence**: approved vs observed addresses, certificate subject / SANs / issuer /
  SPKI, time, code. Never a raw response body.
- Choices: **propose change** (opens a destination change with the observed values pre-filled; the proposer cannot
  approve it), **keep blocked**, **revoke**. A private address or a widened range requires two approvers other
  than the proposer. An approved change can overlap old and new addresses for at most 7 days.
- After approval the connection goes to `testing`; it becomes `active` only when the test passes.

## 6. Workflow contract

The backend exposes one state object per attempt or connection (for example
`GET /admin/connect/workflows/{id}`). UIs render only from it and send actions as
`POST /admin/connect/workflows/{id}/actions/{action}` with the `version` they rendered (optimistic concurrency:
a stale version is answered `409 conflict` and the UI reloads).

```json
{
  "id": "8d0f…",
  "kind": "quick_connect_initiator",
  "version": 7,
  "step": "verify_sas",
  "state": "awaiting_local_approval",
  "health": null,
  "expires_at": 1767226500,
  "kill_switch": false,
  "allowed_actions": ["confirm_sas", "cancel"],
  "requires": {"reauthentication": true, "second_administrator": false},
  "display": {
    "peer": {"display_name": "RMM B", "app_type": "rmm", "installation_id": "6c0d…",
             "already_connected": false},
    "sas": "4821 0937 5510",
    "destination": {"host": "rmm.example.com", "port": 443,
                    "addresses": [{"net": "203.0.113.10/32", "private": false}],
                    "certificate": {"subject": "CN=rmm.example.com", "sans": ["rmm.example.com"],
                                    "issuer": "CN=Example CA", "not_after": 1790000000, "spki_sha256": "…"}},
    "scopes": {"read": ["connection:read"], "write": [], "high_risk": [], "admin": [],
               "refused": [{"scope": "bogus:scope", "reason": "unknown"}]},
    "egress": {"ours": ["198.51.100.20/32"], "theirs": ["203.0.113.10/32"]},
    "diagnostics": null
  },
  "warnings": [{"code": "certificate_expiring", "message": "The certificate expires in 12 days."}],
  "error": null
}
```

Rules:

- `allowed_actions` is computed by the backend from the state machine (CONNECTION_HEALTH.md §1,
  QUICK_CONNECT_SPECIFICATION.md §6), the kill switch and the viewer's permissions. The UI MUST NOT show other
  actions; the backend MUST refuse them anyway.
- `display` holds only values the backend verified (signed messages, discovery read on a POST, the transport's
  preview). It never contains codes, tokens, keys or PKCE values. The pairing code is returned once, by the action
  that creates it, and not stored in the state object.
- `error` is `{code, message, next}` with `next` one of the actions in `allowed_actions` (or `null`).
- Times are Unix seconds; the UI renders local time and a countdown for `expires_at`.

### 6.1 Error codes → message and next step

| Code | Message (example) | Next |
|---|---|---|
| `destination_changed` | The other installation's address changed. Review the new address before continuing. | `review_block` |
| `security_blocked` | This connection is blocked until an administrator reviews a security change. | `review_block` |
| `certificate_invalid` / `certificate_name_mismatch` / `spki_mismatch` | The other installation's certificate did not verify / does not match. | `review_block` |
| `destination_policy_unavailable` | The approved destination could not be loaded. Nothing was sent. | `retry` |
| `source_not_authorised` | The other installation refused our address. Check the egress address you declared and ask their administrator. | `edit_egress` |
| `rate_limited` | Too many attempts. Try again in N minutes (from `Retry-After`). | `retry` (disabled until then) |
| `kill_switch` | Agit8or Connect is stopped on this installation. | none |
| `second_admin_required` | Another administrator must approve this. | `request_second_approval` |
| `reauthentication_required` | Sign in again to continue. | `reauthenticate` |
| `approval_mismatch` | The request changed since it was proposed. Review it again. | `propose_again` |
| `extension_not_negotiated` / `downgrade_detected` | Quick Connect is not available with this installation; use a pairing code. | `use_code_flow` |
| `invalid_pairing_code` / `pairing_locked` | The code is wrong or expired / too many wrong codes; ask for a new code. | `enter_code` |
| `invalid_scope` | A requested permission is unknown or not available and was not granted. | `edit_scopes` |
| `action_approval_required` | This action needs approval by an administrator of the other installation. | `wait` |
| `*_unavailable` (stores) | A required service is unavailable; the request was refused safely. | `retry` |

### 6.2 Accessibility and wording

- The SAS is rendered in a monospaced font, grouped in fours, with an accessible label that reads digits
  separately. A copy-to-clipboard control is not offered for the SAS (it must be compared, not pasted).
- Risk tiers use text labels as well as colour.
- Wording describes what the product does; it does not claim certification or independent review.

## 7. Conformance of a UI

A host can test its UI against this contract by driving the backend with the reference peer as the other
application (QUICK_CONNECT_IMPLEMENTATION.md §8) and asserting, for each state: the actions offered equal
`allowed_actions`, no secret appears in rendered pages or the state object, and every error code above is
rendered with a next step.
