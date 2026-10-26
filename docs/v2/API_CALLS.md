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
    "op_id": "9a6b9c52-f45b-400d-8891-080fb382dcad",
    "paid_until_ms": null,
    "next_block_seq": 0,
    "next_block_due_ms": null
  }
]
```

- `id`: the call id, scoped to the requested peer.
- `state`: `reserved`, `ringing`, `live`, or `ended`, aged at read time.
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
- `next_block_due_ms`: Unix-millisecond renewal time (20 seconds before the paid boundary), or the answer time for block zero; null when ended or at the four-hour cap.
- `op_id`: nullable string, the stored pending signal's operation id, or `null`
  once no operation binding remains in call state. It can refer to an answer
  or hangup rather than an offer. No placeholder strings are returned.

Open means an unexpired reserved/ringing/live call **or any call with a pending
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
