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
- `state`: `reserved`, `ringing`, `live`, or `ended`, aged at read time.
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

The endpoint uses existing tables without a migration. It does not request
prices, pay, dispatch signals, emit call events, sweep rows, or mutate the
operation journal. See [call protocol and recovery](CALLS-PROTOTYPE.md).

# Owner media socket (M6 N2)

`GET /api/v1/calls/<call-id>/media?peer=<node-id>` upgrades to the binary
WebSocket that carries a node-routed call's media between the owner's app and
its own node. Media flows app → own node → peer node → peer app; apps never
send media to each other. The JWT is sent as the `bitsov.jwt.<token>`
subprotocol, as on `/api/v1/ws` (the `?token=` query form is for local tooling).

The socket opens only for a **paired device** (a token with a live pairing
binding; the owner's own key-proof token gets 403) that holds the `spend`
scope and whose subject is this node. `call-id` must be the 32-hex call id and
`peer` the call's counterparty (400 otherwise). The node's call media router
must admit `(peer, call-id)`: until N1 lands that means the stored call is
live (answered, not ended, not expired); N1 tightens it to paid-until. A call
that is not admitted gets 403, a second socket on the same call 409, a peer
that is not connected or does not advertise `call_media_v1` 503. Pairing and
scope are re-checked while the socket is open; revocation closes it.

Every binary message is one packet: `seq` (u32, big-endian) followed by the
codec payload, at most 4096 bytes. Packets from the app are forwarded to the
peer node as `CallMedia` frames on the existing Noise link; the peer's packets
arrive on the same socket in the same form. Each direction is capped at 100
packets and 64 KiB per second; queues are bounded and drop the oldest packet
rather than block, and a packet that cannot be written to the peer within
200 ms (a bulk frame holds the writer) is dropped rather than queued. The
socket closes when the call stops being admitted. Malformed or oversize app
packets are dropped and counted; the socket stays open.
