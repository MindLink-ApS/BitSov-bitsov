# 1:1 calls (prototype, regtest)

Status: prototype behind no flag; proven on regtest only (29 Sep 2026 overnight
defaults). Mainnet only after review.

## Shape

- **Media** never touches the node. The two apps open a direct WebRTC path
  (STUN only; no TURN relay, so no third party carries or bills media).
- **Signalling** is four paid UKM kinds through the ordinary payment gate:
  `400` offer, `401` answer, `402` ICE candidate, `403` hangup. Payload:
  `konsensus_core::payloads::call::CallSignal` (JSON, `v: 1`, `call_id` =
  32 lowercase hex; offer carries `media` + `sdp`, answer `sdp`, ICE
  `candidate`, hangup `reason`). Unknown fields are refused.

## Money

- The offer is the **per-call admission**, paid once at the callee's
  `[pricing] call_msat` (default 10 000 msat; must be > 0). It is advertised
  as the per-kind price-table entry `kind:400` and the kind is a category
  override, so a realtime category offer never covers it.
- Before paying an offer, the caller's node asks the callee now
  (`PriceQuery {kind: 400}` → `PriceResponse`). It never falls back to its own
  tariff: no fresh answer, nothing is paid (`call_price_unknown`).
  `GET /api/v1/pricing/peers/:id/call` exposes the same answer to the app.
- Answer, ICE and hangup pay `realtime_signal_msat` (the app floors every
  payment at 1 sat). No per-minute payment for direct media.

## Call state (durable, `call_state`, migration 027)

Per `(peer, call_id)`: side, phase, deadline, replay deadline and any pending
signal of ours. Stored in the node database, so a restart keeps used ids,
live calls and reservations. Pure rules: `konsensus_core::payloads::call`.

| Signal | Accepted only when | Effect |
|---|---|---|
| 400 offer | the id was never used with that peer (or its replay protection ended) | ringing, 60 s |
| 401 answer | ringing, and sent by the callee | live, 4 h cap |
| 402 ICE | ringing or live | — |
| 403 hangup | ringing or live | ended; id burned for 24 h |

**Our own signals are transactional.** Compose *reserves* the signal under its
operation id (generated if absent) before any quote or payment; a reserved
offer rings nobody and accepts no answer. The transition is *committed* right
after the payment settles, before the envelope is dispatched. After compose
returns, the operation journal decides: paid → commit, `prepared`/`released`
(definitely unpaid) → release (an unsent offer is forgotten, so its id is
free), `paying`/`payment_unknown` → keep, so a retry of the same operation
recovers without a second charge. At startup, before the receive loop and the
outbox resend, `calls::recover` applies the same rule to every reservation a
crash left.

**Incoming signals are held until admitted.** Before its paid acceptance an
incoming call signal is held (`call_admission_hold`): history, resync and
duplicate ACKs treat it as absent until its admission is final. Admitted, the
hold is lifted before the app sees it; refused, message, plaintext, receipt and
hold are withdrawn in one transaction. A hold that outlives its handler (the
withdrawal failed, or the node crashed) is withdrawn at startup, before the
receive loop runs, and by the periodic sweep after 5 minutes: fail closed.

**Incoming refusals are withdrawn.** A paid signal refused by the call rules
(after the gate and decryption) is answered with `MessageReject`, its message
row and cached plaintext are deleted, and its receipt is marked
application-rejected (`accepted = -1`): history, resync and a resend never
present it as delivered, and its payment hash and nonce stay burned.

**Bounds.** Open calls (reserved, ringing, live, or with a signal of ours
being paid) are bounded at 16 per peer and 4 096 in total and are never
evicted; a new call beyond that is refused (`call_busy`). Burned ids (ended
calls under replay protection) are bounded separately, 256 per peer and 65 536
in total, so ended calls never block new ones for the whole tombstone: past a
bound, the oldest ids burned for at least 1 hour make room; an id burned less
than 1 hour ago is never dropped, and if those alone fill a bound the call is
refused. Otherwise an id stays burned for 24 h. Expired rows are swept every 5
minutes (never one with a pending signal).

**One operation, one signal.** Operation ids are canonicalized (lowercase
UUIDv4) before the reservation, which is bound to the exact request (the
journal's request hash, kind and recipient). An operation id reused for
another call id or another payload is refused (`operation_mismatch`) before
any reservation and never commits or releases the first request's; a retry of an operation
that already paid is answered from the journal. The background operation
reconciler and a same-operation retry that finds the payment settled both
commit the call reservation before any resend, so an offer whose payment resolved later rings the callee
and accepts the answer.

**Pricing freshness is per kind.** The caller asks the callee (`PriceQuery`
400) and accepts only a kind-400 answer that arrived after that query; an
unrelated price update never counts. Queries to one peer are sent at most every
2 s; concurrent callers share the answer.

**Admission.** A call never pays first-contact admission: a contact without an
E2EE session is refused (`call_needs_contact`, nothing paid). After a
reconnect, re-admission follows the existing non-chat rule: an uncapped
(owner) call re-admits once, reported separately as `readmission_msat`, then
pays the call (verified on real LDK); a capped (paired app) call refuses
re-admission before any quote, as files do (#127), and re-admission happens on
the chat path under the owner's quoted approval. If the callee does not answer
the price query at all, the call is refused before paying
(`call_price_unknown`) and its reservation released.

Calls are 1:1: a room compose of 400-403 is refused (`call_room`).

## Evidence

- `msg_handler::tests::paid_call_signalling_is_single_use_and_forwarded_only_for_a_live_call`
  (two Noise transports, real receive loop): underpaid, paid, duplicate,
  replayed id, wrong-side answer, ICE for live/unknown call, hangup.
- `regtest_e2e::real_ldk_regtest_calls` (real Core + electrs + LDK, A–C–B):
  live price query, paid offer, local refusals, answer/ICE/hangup both ways,
  msat-exact channel and budget reconciliation, and a call after reconnect
  refused before paying with its id released.
- `konsensus-api/tests/call_state_tests.rs`: the #131 review probes as
  regressions (unpaid offer/answer, capacity, unrelated price response,
  refused signal via resync), restart, recovery and price-query rate limit.
