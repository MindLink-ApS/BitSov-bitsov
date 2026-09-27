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
| `code` | Admitted: `settled`. Refused, inbound: `unpaid`, `insufficient_payment`, `not_settled`, `settlement_mismatch`, `settlement_unavailable`, `proof_reused`, `replay`, `stale`, `bad_signature`, `invalid_envelope`, `invite_only`, `not_priceable`, `node_error`. Refused, outbound: `price_cap_exceeded`, `budget_exceeded` (G1, including file, room-member, and direct-payment refusals). |
| `counterparty` | Inbound: set **only if the gate verified the sender's signature before deciding** (admissions, and refusals from `replay` onward). A refusal decided earlier (`invalid_envelope`, `invite_only`, `stale`, `bad_signature`) names no one. Outbound: a canonical node or room ID, or omitted when invalid/unknown. Direct-payment events omit invoice/payee data. |
| `first_contact` | Admitted from a sender who is not a contact. The sender is not added. |
| `required_msat` | The price the gate stated (insufficient or unpaid). |
| `paid_msat` | The amount the envelope carried; settled when admitted. |
| `cap_msat` | Outbound: the cap the client confirmed. |

`GET /api/v1/membrane` returns `{ capacity, totals, events }`, newest first.
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
