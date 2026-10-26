# Node-routed calls and paid blocks (M6)

Calls route media **app → own node → peer node → peer app**. Both media
paths terminate at the participating nodes. There is no app-to-app media
path, direct WebRTC bypass, or unpaid media relay. The separate media-frame
implementation must consult the call admission hook before forwarding frames.

## Signalling and money

All signals use the normal authenticated `POST /api/v1/messages/compose`
path: encryption, recipient payment, signing, gate verification, durable
operation recovery, and application admission. Each call is scoped to exactly
one `(peer, call_id)`. A `call_id` is 32 lowercase hexadecimal characters.
Signals 400–403 carry `v: 1`; 404 accepts the minimal payload below (and
optionally `v: 1`). Unknown fields and fields from another kind are refused.
SDP/ICE fields are retained for signalling compatibility; M6 media uses
the existing TCP Noise peer link, with no UDP or STUN on the call path.
Only one node must be reachable; the other dials out and holds the connection.
The initial media transport is encrypted hop by hop: each owner's own node
can hear it. App-to-app end-to-end media encryption is a separate milestone.

| Kind | Payload fields beyond version and call id | Price at receiver |
| --- | --- | --- |
| 400 offer | `media`, `sdp`, optional `meeting` | `call_msat` |
| 401 answer | `sdp` | `realtime_signal_msat` |
| 402 transport candidate | `candidate`, optional `sdp_mid`, `sdp_mline_index` | `realtime_signal_msat` |
| 403 hangup | optional `reason`, including `unpaid` | `realtime_signal_msat` |
| 404 CALL_BLOCK | `seq` | **callee's `call_block_msat`** |

```json
{"call_id":"0123456789abcdef0123456789abcdef","seq":0}
```

The offer fee pays for ringing, not ongoing media or a live admission grant.
The caller pays every block to the callee. The callee's `[pricing]
call_block_msat` defaults to 10 000 msat and must be positive. It is a
per-kind override and appears as `kind:404` in price adverts whenever it
differs from the realtime category, following `call_msat` / `kind:400`.
Chain pricing and trust discounts apply through the existing pricing engine
and gate, including the gate's admission floor.

Before paying 400 or 404, the caller node asks the recipient for that exact
kind (`PriceQuery` / `PriceResponse`). Only a fresh answer after that query
counts; another kind's answer cannot satisfy it. Queries are coalesced per
peer and kind for two seconds, in a bounded cache. There is **no fallback to
the caller's tariff** for these payments. Without the callee's answer,
compose refuses `call_price_unknown` before paying.

## Paid interval state machine

An offer rings for 60 seconds. A callee's paid answer (401) starts the call's
clock and a thirty-second initial payment window. The answer itself grants no
media. On receiving 401 the caller app requests block 0 through its own
node's authenticated compose endpoint, using its existing spend grant and
payment caps. The node refuses a block sent by the callee or for an unknown,
unanswered, or ended call.

Block 0 purchases `[answer, answer + 60 seconds]`. Only its settled payment
admits media. The caller app requests block `k + 1` **20 seconds before**
block `k` ends, again through compose. `GET /api/v1/calls?peer=…` exposes
`paid_until_ms`, `next_block_seq`, and `next_block_due_ms` to resume scheduling.
The node never manufactures caller spend authority for background renewals.
Stopping the app or losing its spend grant therefore stops renewals.

Only the next sequence is accepted, beginning at zero. Duplicates, replays,
gaps, excessive sequences and renewals before their due time are refused.
A late payment within ten seconds of the previous boundary extends that
boundary by exactly 60 seconds; it never buys extra time by moving the
anchor to its arrival. The grace endpoint is inclusive: media stops when
`now > paid_until_ms + 10 seconds`. With no block zero, media remains refused
and the initial window expires thirty seconds after answer. The receiver checks
block admission before consuming its payment proof and holds that decision
through acceptance, so crossing a deadline cannot consume a proof and then
refuse the block. Late refusals emit `message.rejected` audit records.
If the subsequent call-state write fails after paid acceptance, no media is
granted and the receipt remains stored. A `call.block_commit_failed` audit
record links its message id to the call id, sequence and amount for operator
reconciliation; it contains no payment preimage or decrypted payload. This
records the failure for manual reconciliation, not automatic retry or refund.

Calls are capped at 240 blocks (four hours). No payment revives an expired
or ended call. Expiry changes the durable phase to `ended`, records
`HangupReason::Unpaid`, and keeps the replay tombstone and any pending
payment evidence. After local `Unpaid` expiry, the caller admits only one
403 `reason: "unpaid"` from the callee, without changing the tombstone.
A durable notice flag suppresses further distinct envelopes as well as
ordinary envelope replays. Only the callee can reserve that notification;
a pending retry is idempotent, definite nonpayment releases it, and a paid
commit keeps the flag consumed across restarts.
A one-second maintenance timer ages calls independently
of connected apps; only the callee then attempts a 403 `reason: "unpaid"` through normal paid
compose with at most eight concurrent notifications, a five-second attempt deadline,
a 1 000 msat total cap, zero routing fees, and no peer re-admission. Excess
notifications are dropped rather than blocking expiry. The notification
is best effort; transport, wallet, or process failure never extends media
admission. An operation already dispatched retains ordinary journal recovery.

## Media admission interface

The media-frame path calls:

```rust,ignore
konsensus_api::calls::call_media_admitted(storage, peer, call_id, now_ms).await
```

Time is Unix milliseconds. The result is true only for a live call with a
settled block and a paid boundary whose grace has not elapsed. Unknown peer,
unknown call, ringing, ended, unpaid first block and storage errors all fail
closed. The pure `CallEntry::media_admitted(now_ms)` uses the same rule. No
unpaid timeout notification or outstanding reservation can authorize media.

## Persistence, recovery and bounds

`call_state` stores side, phase, effective deadline, replay deadline,
`paid_until_ms`, next sequence, end reason, the Unpaid notice flag and any outgoing reservation.
Migration 036 adds the notice flag for SQLite and PostgreSQL.
Migration 035 adds paid intervals in SQLite and PostgreSQL; versions 033/034
are reserved by the schema-parity and call-invite changes. Existing live
rows with no block proof are ended while retaining their entire replay
window. New calls and paid intervals survive restarts.

Outgoing signals reserve under a canonical operation id and exact request
hash before any quote or payment. Settlement commits before envelope
publication. Definite nonpayment releases the reservation; ambiguous payment
keeps it for same-operation recovery. A block reservation does not advance
the sequence until payment settles. A recovered payment cannot revive an
expired call. Before every new block charge, including after a failed-payment
retry and after invoice response, the call is revalidated. After journal
writes, phase, sequence and deadline are checked again under the call
transition lock, held through the first wallet poll. A new wallet dispatch
requires at least five seconds before the local deadline to allow for the
callee's earlier answer time and payment/delivery latency. Already-dispatched
payments retain normal settlement recovery, even if they settle after expiry. One operation cannot settle or release another request.

Incoming call envelopes are held before paid acceptance. Only a
payment-gate-accepted, decrypted, valid transition is released to the app.
Refusals withdraw message and plaintext, mark the receipt application-rejected,
and retain the burned payment hash and nonce. Startup and periodic sweeps
withdraw abandoned holds. Freshly paying a duplicate sequence does not buy
another interval.

Open calls remain bounded at four per peer and 4 096 globally, including
unsettled reservations; none are evicted. Burned ids have separate bounds
of 256 per peer and 65 536 globally. Pressure may evict the oldest ids only
after at least one hour of replay protection; otherwise tombstones remain
for 24 hours after ending. Expired tombstones are swept in bounded batches;
pending payment evidence is never swept as unpaid.

Mesh meetings remain sets of ordinary pairwise calls with at most four
participants. The earlier participant in the fixed roster places and pays
each leg, including its blocks. The `call_meeting_v1` capability guards
meeting offers. Every leg uses both nodes for media and the same paid
admission rule; no meeting-level grant bypasses it.

Calls require an existing E2EE contact. First-contact admission stays on the
ordinary owner-approved chat path. Existing operation idempotency, budget
grants, recipient and aggregate caps, routing-fee limits, and reconnect
admission rules apply to calls as to other paid messages.
