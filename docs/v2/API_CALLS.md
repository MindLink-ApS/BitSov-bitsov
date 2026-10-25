# Open calls by peer

`GET /api/v1/calls?peer=<node-id>` is an owner-scoped, read-only view of the
node's durable call state. It requires a valid owner-subject bearer token with
`read` scope (including an owner's paired app with that scope). Missing or
invalid authentication returns 401; a different subject or missing scope
returns 403.

`peer` is required and must decode as a 32-byte hex node id. Missing, duplicate,
or malformed peer parameters return HTTP 400 with fixed JSON error text:
`{"error":"invalid peer id"}`. Input is never echoed. A valid
unknown peer returns `[]`.

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
    "op_id": "9a6b9c52-f45b-400d-8891-080fb382dcad"
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
- `op_id`: nullable string, the stored pending signal's operation id, or `null`
  once no operation binding remains in call state. It can refer to an answer
  or hangup rather than an offer. No placeholder strings are returned.

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

The endpoint uses existing tables without a migration. It does not request
prices, pay, dispatch signals, emit call events, sweep rows, or mutate the
operation journal. See [call protocol and recovery](CALLS-PROTOTYPE.md).

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
