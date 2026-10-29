# Open calls by peer

`GET /api/v1/calls?peer=<node-id>` is an owner-scoped, read-only view of the
node's durable call state. It requires a valid owner-subject bearer token with
`read` scope (including an owner's paired app with that scope). Missing or
invalid authentication returns 401; a different subject or missing scope
returns 403.

`peer` is required and must decode as a 32-byte hex node id. Missing, duplicate,
or malformed peer parameters return HTTP 400 with fixed JSON error text:
`{"error":"invalid peer id","code":400}` (the numeric `code` is the generic
bad-request marker; typed refusals such as `not_dispatched` carry a string
`code` instead). Input is never echoed. A valid unknown peer returns `[]`.

The response is an array of at most **4** entries (the per-peer open-call
admission bound), with unresolved reservations first, then call id order.
The bound also applies if the stored data exceeds the admission bound.

```json
[
  {
    "id": "0123456789abcdef0123456789abcdef",
    "state": "ended",
    "direction": "outgoing",
    "unresolved_paid_admission": true,
    "created": 1790000000000,
    "op_id": "9a6b9c52-f45b-400d-8891-080fb382dcad",
    "paid_until_ms": null,
    "next_block_seq": 0,
    "next_block_due_ms": null
  }
]
```

- `id`: the call id, scoped to the requested peer.
- `state`: `reserved`, `awaiting_device`, `ringing`, `live`, or `ended`, aged at read time.
- `direction`: `outgoing` (this node offered) or `incoming` (the peer offered).
- `unresolved_paid_admission`: boolean; conservatively true whenever the call
  retains a pending signal reservation. The read does not reconcile payment
  evidence or release reservations, even when a journal appears terminal.
- `created`: nullable integer, Unix milliseconds. When a pending offer is bound
  to a matching operation journal entry, this is that operation's stored
  `created_at`. Otherwise it is `null`: `call_state` has no creation timestamp,
  and an answer/hangup timestamp is not the call's creation time.
- `paid_until_ms`: nullable Unix-millisecond boundary of the last settled 60-second block; null until block zero settles.
- `next_block_seq`: next required block sequence, starting at zero.
- `next_block_due_ms`: Unix-millisecond renewal time (20 seconds before the paid boundary), or the answer time for block zero; null when ended or when all blocks allowed by the duration cap have been paid.
- `op_id`: nullable string, the stored pending signal's operation id, or `null`
  once no operation binding remains in call state. It can refer to an answer
  or hangup rather than an offer. No placeholder strings are returned.
- `reservation`: present for an outgoing call backed by a paired app's spend
  grant. Contains `reserved_msat`, `spent_msat`, `remaining_msat`,
  `per_block_msat`, `per_block_fee_msat`, `max_call_minutes`, `released_msat`, and `closed`.
  `spent_msat` includes settled block principal and known routing fees.
  `remaining_msat` includes unresolved payment liabilities and excludes released
  funds. It is an observation, never new payment authority. The original
  reservation amount and per-block ceilings stay fixed for the call.

Open means an unexpired reserved/awaiting-device/ringing/live call **or any call with a pending
signal**, including calls whose ringing/live deadline and replay tombstone
have expired. Ended/expired calls without a pending signal are omitted.

**The client must fail closed per peer when `unresolved_paid_admission` is
true:** keep blocking re-admission/new paid admission to that peer, even if
`state` is `ended` or metadata is `null`. Expiry does not prove nonpayment.
Only normal operation recovery/settlement can resolve the reservation; GET
never does so. This blocker applies to the requested peer, not unrelated
peers. An empty response is a snapshot, not authorization to bypass the normal
compose/admission checks.

The endpoint reads the durable call state, including paid interval fields from migration 035. It does not request
prices, pay, dispatch signals, emit call events, sweep rows, or mutate the
operation journal. See [call protocol and recovery](CALLS-PROTOTYPE.md).

## Paired-app call spending (M6 N3)

The owner sets the outgoing paid-duration cap in node configuration:

```toml
[calls]
max_call_minutes = 60
```

The default is **60 minutes**; only integers from **1 through 240** are accepted.
Restart the node to apply a config change. A paired-app reservation pins its
cap when created, so a config change never resizes an existing hold. Holds
created before this setting existed retain their original 240-minute cap.
Owner-authorized calls without a grant use the current node setting.

Before a caller's offer is dispatched, the node reserves `max_call_minutes`
60-second blocks at the callee's current kind-404 price, plus the enforced
routing-fee ceiling for each block. The existing minimum invoice amount also
applies. Already-answered calls without a hold may reserve at block zero.
The total must fit the approved grant's total, per-call, recipient, envelope,
allowlist and spend-velocity limits. This block bundle counts as one breaker
entry; the separate ringing fee and other signaling retain their ordinary
metering. Blocks draw from the bundle without another breaker entry or the
generic messaging per-payment ceiling. Thus the per-block limit comes from the
grant limits divided across the reserved minutes, not the 6-sat messaging cap;
raising the grant's velocity/total limits or reducing reserved minutes permits
a higher per-block price.

### Caller consent on an offer

`POST /api/v1/messages/compose` accepts two optional top-level integer fields
for a kind-400 offer, in msat:

- `max_block_msat`: the maximum payable price of one 60-second kind-404 block.
  The node asks the callee for its current price, rather than trusting its
  advert. A nonzero quote below 1,000 msat uses the existing 1,000-msat minimum;
  a zero quote stays free.
- `max_hold_msat`: the maximum complete block reservation. The node computes
  `max_call_minutes × (payable block price + per-block routing-fee ceiling)`.
  `max_routing_fee_msat` bounds that per-block fee under the existing routing
  policy. This hold excludes the separately metered offer/signaling fees;
  `max_total_msat` still caps the offer payment itself.

Both limits are inclusive: equality succeeds if the ordinary grant, liquidity,
and call checks pass. Either field may be omitted independently; an absent or
null field adds no consent limit, preserving previous clients' behavior. Zero
is a real ceiling. The checks also apply to owner-authenticated offers when
supplied, although those calls do not create a paired-app hold. Other kinds
do not use these offer fields.

For example, with the default 60-minute cap:

```json
{
  "operation_id": "9a6b9c52-f45b-400d-8891-080fb382dcad",
  "recipient": "<callee-node-id>",
  "kind": 400,
  "plaintext": "{\"v\":1,\"call_id\":\"0123456789abcdef0123456789abcdef\",\"sdp\":\"<offer>\",\"media\":\"audio\"}",
  "max_block_msat": 7000,
  "max_routing_fee_msat": 500,
  "max_hold_msat": 450000
}
```

A price above consent returns HTTP 400 with `code: "not_dispatched"` and
`reason: "call_price_above_consent"`. An excessive computed hold returns the
same status/code with `reason: "call_hold_above_consent"`. Both checks precede
reservation creation, invoice/payment dispatch, and offer delivery: a refused
new offer creates no hold and spends nothing. A retry with an existing hold
must also cover its pinned price and original amount; it cannot silently
resize that hold. Replaying an already-paid operation returns its existing
receipt without spending again; new limits cannot undo that payment.

### Settlement and release

After the final allowed block, `next_block_due_ms` is null and a new block is
refused with `reason: "call_duration_cap"`. The one-second maintenance sweep
ends the call at the final paid boundary, without renewal grace, records
`duration_cap`, and attempts a paid kind-403 notification with that reason.
Notification failure cannot extend the call. A peer predating this reason may
ignore the notification and ends through its ordinary unpaid expiry instead.
The cap counts paid media intervals from the answer, not ringing time.

One active channel's known spendable outbound capacity must cover the hold,
less all other held call funds. Unknown capacity fails closed. This is a
conservative local-channel preflight, not a guarantee of remote routing
liquidity throughout the call. No liquidity purchase is implied.
`call_liquidity_insufficient` identifies insufficient capacity;
`call_liquidity_unavailable` identifies a failed capacity query.

The hold and its child debit references are written atomically in the existing
pairing ledger. Child payments use the existing outbox reconciliation journal.
Hangup, Unpaid, failure and timeout release unallocated funds once; ambiguous
payments remain held until their outcome and fees are known. Startup and the
one-second call maintenance sweep repair interrupted releases. A closed hold
cannot fund a retried offer; use a new call id. A block price above the reserved
price ends the call with `call_price_changed`. Later requests may tighten the
original routing ceiling but cannot widen it; blocks cannot pay re-admission.

Validation and transient invoice refusals leave a live call retryable. Definite
payment failure or a price above the reserved ceiling ends it; ambiguous
payments remain journaled and the ordinary expiry deadline still applies.
If an Unpaid call has a pending block, its unused hold stays reserved through
the 60-second resume window. Settlement inside that window reopens the call
and draws once from the original reservation. After the window, unused funds
are released and only unresolved payment liabilities remain held. A later
settlement is still charged once and delivered for the callee's overpayment
audit; it does not reopen the call or create another hold. A block invoice
refused near the deadline spends nothing and returns its unused draw to the
open hold (or releases it if the hold has closed).

A locally settled block can still be awaiting the callee's delivery grant.
For that case the node checks the paid delivery queue or durable settlement
recovery evidence and the call/sequence binding before retaining the unused
hold. Older rows recover their binding from encrypted plaintext; a settled
legacy row awaiting materialization conservatively keeps the peer's allowance
until recovery identifies it. The allowance ends
at most 130 seconds after the local Unpaid deadline (60 seconds to resume,
one 60-second granted interval, and 10 seconds of grace). Receipt or terminal
rejection ends this allowance; it cannot retain a hold indefinitely. This
lets a delayed usable grant reopen the call with its original reservation.

Declined/unanswered holds with zero settled spend are neutral to the failure
breaker; confirmed first-block payment failures still count, including a failure
resolved after hangup. Cleanup errors are logged and retried; they never replace a successful
compose response or prevent unrelated expiry notifications.

Finished holds become small receipts without paid-block lists. At most 256
finished receipts per grant are retained, for at most 24 hours after completion;
oldest receipts are removed first under count pressure. Open holds and unresolved
child payments are never pruned. Call-row tombstones continue to protect call
ids after a spend receipt is removed.

**Downgrade:** a pre-#460 binary rejects the ledger's `call_reservations` field.
Downgrade is unsupported while any hold, unresolved draw, or finished receipt
remains. End calls, let operation reconciliation finish, then leave the new
binary running for at least 24 hours after the last hold finishes so maintenance
can prune the receipts. With no retained calls the field is omitted and the
ledger has the previous schema again. Remove `calls.max_call_minutes` from the
config before starting an older binary. Never delete the ledger or edit out
holds to bypass the restriction: that can discard payment liabilities. Retained
`duration_cap` reasons in call rows require a binary that recognizes that reason;
allow those call tombstones to expire as well before downgrading.

This slice adds no SQL migration. Any new migration needs the owner's GO.

## Incoming invite device wait

On the callee node an admitted kind-400 invite starts as `awaiting_device`.
Its device deadline is 15 seconds after local arrival. The first fetch by a
currently paired app through message GET, plaintext GET, or message listing,
or the first successful authorized paired WebSocket write, changes it to
`ringing` with a deadline 60 seconds after that delivery. Further devices do
not restart the clock. Internal broadcast subscribers and resync enqueue alone
do not count; resync can start ringing only through an actual device stream.

An expired row is aged to `ended` before classification. A late fetch or
resend cannot revive it. The node retains ordinary replay tombstones, bounds
device waits with the existing call limits, and expires them in the call-state
sweep. Startup ends awaiting calls rather than binding retained old invites to
them. No database migration is required.

The invite's existing `MessageAck` is delayed until device delivery. The
background control writer sends it within its 100 ms sweep cadence, without
peer I/O on the device request. A resend during the wait remains pending and
receives the same eventual outcome; it is never decrypted or forwarded twice.
The 15-second wait is below the sender's 60-second periodic resend scan.

A wait with no device delivery ends with the existing `MessageReject` frame,
using the new stable reason string **`call_not_reachable`** and the invite's
message ID. Apps can display this as the person's device being offline.
Callers that do not recognize the reason use their existing generic rejection
handling. The refused envelope and cached plaintext are withdrawn; its payment
hash and nonce remain spent. Pending, fetched, and not-reachable outcomes use
the existing payment receipt, without a new table or migration. An authenticated
resend matching its immutable receipt receives the same ACK or refusal after
withdrawal, content retention, or restart, without new pricing or settlement.
Startup withdraws pending device waits and retains a not-reachable refusal;
it must finish this recovery before serving devices or receiving messages.
The refusal uses the existing paid-but-refused path, with no extra caller
charge. There is no additional payment, invoice, caller
timer anchoring, or new wire acknowledgment field.

## Contract goldens (app–node)

The responses the app consumes for calls and for the owner-only STUN fields
are pinned as JSON fixtures under
`crates/konsensus-api/tests/fixtures/contract/`, rendered by the live
handlers with fixed inputs and compared field by field by
`crates/konsensus-api/tests/contract_goldens.rs`. The app repo will consume the
same fixtures, so a field added, removed, renamed, retyped or made nullable
on either side fails there and here before it reaches a user.

| Fixture | Request | Status | Contract |
|---|---|---|---|
| `status_stun_own.json` | `GET /api/v1/status` | 200 | Own STUN responder (`[calls] stun_listen`) at a dialable advertised host: `stun_port`, `stun_url` (`stun:<peer host>:<stun_port>`), `stun_source` `own`, `peer_endpoint`, `peer_endpoint_source` `advertised`. |
| `status_stun_configured.json` | `GET /api/v1/status` | 200 | Own responder without a dialable host but a valid `[network] stun_server`: `stun_port`, `stun_url` from the configured server, `stun_source` `configured`, `peer_endpoint_reason` `no_dialable_endpoint`. |
| `status_stun_absent.json` | `GET /api/v1/status` | 200 | No responder, no dialable host, no configured server: `stun_port`, `stun_url`, `stun_source`, `peer_endpoint` and `peer_endpoint_source` are absent; `peer_endpoint_reason` `no_dialable_endpoint`. |
| `peer_call_price.json` | `GET /api/v1/pricing/peers/:id/call` | 200 | The callee's live call price: `peer_id`, `offer_msat` (kind 400, asked of the callee), `signal_msat` (kind 401). |
| `call_invite_accepted.json` | `POST /api/v1/messages/compose` (kind 400, `wait_ack_ms: 0`) | 200 | A paid, dispatched invite: `operation_id` (echoed), `state` `sent`, `accepted` `false` (no acceptance receipt was awaited), `payment_hash`, `retry_allowed`, `max_routing_fee_msat`, `message_id`, `delivered`, `amount_msat`. See [exactly-once operations](EXACTLY-ONCE-OPERATIONS.md). |
| `call_invite_refused_call_id_used.json` | `POST /api/v1/messages/compose` (kind 400) | 400 | A new operation reusing a call id: `error`, `code` `not_dispatched`, `reason` `call_id_used` (see the refusal table in [CALLS-PROTOTYPE.md](CALLS-PROTOTYPE.md)). |
| `calls_open_by_peer.json` | `GET /api/v1/calls?peer=<node-id>` | 200 | Three open calls: an `ended` outgoing call with an unresolved paid admission bound to its journal row (`created` set, `op_id` set) first, then a `ringing` outgoing and a `live` incoming call in id order, both with `created` and `op_id` `null`. |
| `calls_open_by_peer_empty.json` | `GET /api/v1/calls?peer=<node-id>` | 200 | A valid peer with no open calls: `[]`. |
| `calls_invalid_peer.json` | `GET /api/v1/calls?peer=not-a-node-id` | 400 | `{"error":"invalid peer id","code":400}`: the fixed text, with the generic numeric bad-request `code`. |

Each fixture is one envelope:

```json
{ "request": "GET /api/v1/status", "status": 200, "body": { "...": "..." } }
```

`body` is the handler's JSON exactly as served (keys sorted), except for the
masked fields below. Absent optional fields are absent in the fixture too;
`null` stays `null`, so nullability is part of the contract.

### Mask

Node-generated ids and timestamps vary per run, so the test replaces them
with a typed placeholder **after checking their shape**; a mask never hides a
missing field, a `null` that became a value, or a value of another type.
Client-supplied ids (operation ids, call ids) are fixed test inputs and are
kept literally.

| Path (JSON pointer, `*` = every element) | Check | Placeholder |
|---|---|---|
| `/body/node_id`, `/body/connected_peer_ids/*`, `/body/peer_id` | 64 lower-case hex chars | `<hex64>` |
| `/body/lightning_node_pubkey` | 66 lower-case hex chars | `<hex66>` |
| `/body/message_id`, `/body/payment_hash` | 64 lower-case hex chars | `<hex64>` |
| `/body/uptime_secs` | non-negative integer | `<uint>` |
| `/body/*/next_block_due_ms` | non-negative integer ≥ 10^12 (Unix milliseconds) | `<unix_ms>` |
| `/body/*/created` | non-negative integer ≥ 10^12 (Unix milliseconds) | `<unix_ms>` |

### Regenerating

```sh
UPDATE_GOLDENS=1 cargo test -p konsensus-api --test contract_goldens
```

rewrites the fixtures from the live handlers. Review the diff as an API
change, update the table above, and tell the app side: a regenerated fixture
is the contract changing, not the test being wrong.
