# Organism reads: energy (N1) and membrane (N2)

Two local reads of the node's own ledger, used by the app's Body panel (O1 v2).
Both require a current paired token with `read` scope and a loopback connection.
Missing connection metadata, remote clients, and unpaired tokens are refused.
The shared `/api/v1/ws` stream uses the same policy; revocation/epoch/identity
changes are checked again before each event is sent. Neither is gossiped, and neither describes anyone
else's traffic: there is no network map and no export route. `/status` lists
`energy_v1` and `membrane_v1` in `api_capabilities` when a node serves them.

## `GET /api/v1/energy?window=1h|24h|7d`

Sats in and out, summed from this node's stored paid messages (inbound ones
passed the payment gate; outbound ones this node paid for). Default `24h`.

```json
{ "window": "24h", "as_of_ms": 0, "since_ms": 0, "bucket_ms": 3600000,
  "buckets": [ { "start_ms": 0, "in_msat": 0, "out_msat": 0 } ],
  "counterparties": [ { "counterparty": "<node hex | room uuid>", "counterparty_kind": "node",
                        "in_msat": 0, "out_msat": 0, "in_count": 0, "out_count": 0 } ],
  "totals": { "in_msat": 0, "out_msat": 0, "in_count": 0, "out_count": 0 },
  "truncated": false, "source": "…" }
```

- Buckets: 12 × 5 min (`1h`), 24 × 1 h (`24h`), 7 × 1 day (`7d`). A bucket with
  nothing in it is **omitted**, so a client draws a gap, not a zero.
- A room message from another member counts as energy in from the room.
- Reads metadata columns only (`Storage::energy_rows_since`): no ciphertext,
  payment hash or preimage. Messages removed by retention are no longer counted.
- `truncated: true` means the 100 000-row read limit was hit; totals are a floor.

## Membrane: `/ws` `membrane` events and `GET /api/v1/membrane?since=&limit=`

Every admission decision at the payment gate, including paid relay controls and
admissions followed by storage failure, plus our own sends refused before
payment dispatch. `admitted` means the gate passed, not that storage or delivery
succeeded. A room member with an unknown payment outcome is never called refused. One event:

```json
{ "type": "membrane", "seq": 12, "at": 0, "direction": "inbound", "verdict": "refused",
  "code": "unpaid", "kind": 0, "first_contact": false, "required_msat": 20000, "paid_msat": 0 }
```

| Field | Notes |
|---|---|
| `direction` | `inbound` (a peer at our gate) or `outbound` (our send refused before any payment). |
| `verdict` | `admitted` or `refused`. |
| `code` | Admitted: `settled`. Refused, inbound: `unpaid`, `insufficient_payment`, `not_settled`, `settlement_mismatch`, `settlement_unavailable`, `proof_reused`, `replay`, `stale`, `bad_signature`, `invalid_envelope`, `invite_only`, `not_priceable`, `node_error`. Refused, outbound: `price_cap_exceeded`, `budget_exceeded` (G1, including file, room-member, and direct-payment refusals). Admitted, outbound: `readmission` (we paid a contact's admission again after a reconnect; `paid_msat` from its signed quote, `cap_msat` the contact's budget cap when paid from a budget grant). |
| `counterparty` | Inbound: set **only if the gate verified the sender's signature before deciding** (admissions, and refusals from `replay` onward). A refusal decided earlier (`invalid_envelope`, `invite_only`, `stale`, `bad_signature`) names no one. Outbound: a canonical node or room ID, or omitted when invalid/unknown. Direct-payment events omit invoice/payee data. |
| `first_contact` | Admitted from a sender who is not a contact. The sender is not added. |
| `required_msat` | The price the gate stated (insufficient or unpaid). |
| `paid_msat` | The amount the envelope carried; settled when admitted. |
| `cap_msat` | Outbound: the cap the client confirmed. |

`GET /api/v1/membrane` returns `{ capacity, totals, events, pre_payment_refusals }`,
with events newest first.
`limit` defaults to 100 and is capped at the ring. `since` keeps events with
`at > since`. The ring holds 500 events in memory, and `totals` counts since
start. Nothing is written to disk: the audit log (`message.rejected`) is still
the only persistent record. An event never carries plaintext, ciphertext,
signatures, nonces, payment hashes or preimages
(`membrane::tests::events_never_carry_payment_secrets_or_payload`).

Pre-handshake doorway refusals (rate limit, cookie, IP guard) are not events.

All event strings are fixed enum labels or canonical IDs (at most 64 bytes).
There is no arbitrary reason text, recipient input, invoice or payment proof in
an event. Energy filters timestamps to `[since_ms, as_of_ms]`, omitting future
clock-skew rows until they enter the window.

### Pre-payment refusals (DEMO-3 Body gap)

N2 (#82) counted message-gate decisions, not the control frames dropped before
payment. `GET /api/v1/membrane` now also returns:

```json
{ "pre_payment_refusals": {
  "bucket_ms": 3600000,
  "capacity": 24,
  "effective_hour_start_ms": 1790553600000,
  "buckets": [
    { "start_ms": 1790553600000,
      "counts": { "session_before_payment": 2, "price_before_payment": 1,
                  "admission_required": 1 } }
  ]
} }
```

Each count is a refused control frame/request, **not a unique stranger, message,
connection, or payment**. A single connection can contribute several refusals.
The Body can sum the counts for the displayed hours, separately from message-gate
`totals.refused`; adding a UI consumer is an app-side change.

- `session_before_payment`: PrekeyOffer, SessionInit, SessionAck, RatchetInit.
- `delivery_before_payment`: MessageAck, MessageReject.
- `price_before_payment`: PriceTable, PriceQuery, PriceResponse.
- `peer_exchange_before_payment`: PeerExchange request or response.
- `lightning_info_before_payment`: LightningInfo.
- `gossip_before_payment`: Gossip.
- `invoice_error_before_payment`: InvoiceError rejected as unprivileged and
  unbound; replies to our own bound requests remain allowed and uncounted.
- `admission_required`: a non-admission invoice request on an unprivileged
  connection. Counted even when its refusal reply is rate-limited. This replaces
  the former per-peer, 10-second `admission_required` event telemetry.

Only nonzero reason counts and nonempty buckets are returned, oldest first.
Buckets are UTC hours: the current hour plus 23 preceding hours. Counts expire
on reads as well as writes; restart clears them. `since` and `limit` apply only
to the event ring, **not** these buckets. Reads neither consume nor reset counts.
Counters saturate at `u64::MAX`. On clock rollback, counts stay in the most recent
observed hour until the clock catches up; expired hours cannot reappear.

`effective_hour_start_ms` is the node's effective current UTC-hour start in Unix
milliseconds after that rollback clamp. It advances on reads as well as writes,
including reads during quiet hours, and is returned even when `buckets` is empty.
Use it to select the current-hour bucket and the inclusive preceding 23 hours;
missing buckets/reasons in that window mean zero. A quiet read at hour 101 after
a refusal at hour 100 pins this anchor to hour 101 even if the clock rolls back
to hour 99. The newest nonempty bucket alone cannot establish the current hour.
This field is additive: older consumers can ignore it. Older nodes omit it;
consumers can still sum all returned buckets for the retained 24-hour total, but
must treat the exact current-hour count/anchor as unavailable.

Doctrine: an unpaid stranger must not buy stored state about themselves. Even a
bounded event ring or identity-indexed cooldown would retain individual unpaid
encounters and let an attacker churn identities into telemetry state. The only
acceptable observation here is an aggregate: a fixed 24 × 8 array of counters,
coarse hour starts, and fixed enum reason labels. It accepts no sender ID, IP,
request ID, payload, invoice, or free-text reason. There is no per-event timestamp,
sequence, disk write, or WebSocket event. The previous per-peer refusal telemetry
map has been removed; pre-existing transport/reply abuse limits remain enforcement
state, not telemetry. No new storage is allocated per stranger.

Coverage is the session/control membrane after the Noise handshake. Connecting,
allowed bootstrap admission quotes, quote-service failures, and pre-handshake
rate/cookie/IP refusals are not counted. Message-gate events retain their existing
semantics. Read access retains the paired, loopback, `read`-scope policy of N2.
