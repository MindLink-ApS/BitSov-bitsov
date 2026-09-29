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

## Call state (`CallRegistry`)

Per node, per `(peer, call_id)`, bounded (4 096 tracked):

| Signal | Accepted only when | Effect |
|---|---|---|
| 400 offer | the id was never used with that peer | ringing, 60 s |
| 401 answer | ringing, and sent by the callee | live, 4 h cap |
| 402 ICE | ringing or live | — |
| 403 hangup | ringing or live | ended; id burned for 24 h |

Outgoing signals are checked in `compose` **before any quote or payment**
(`call_id_used`, `call_not_live`, `call_signal_invalid`). Incoming signals are
checked after the gate and decryption; a refused one is answered with
`MessageReject` and **never reaches the WebSocket**. Replays of the same
envelope stay the gate's job (duplicate ACK, nonce and payment-hash reuse).

Calls are 1:1: a room compose of 400-403 is refused (`call_room`).

## Evidence

- `msg_handler::tests::paid_call_signalling_is_single_use_and_forwarded_only_for_a_live_call`
  (two Noise transports, real receive loop): underpaid, paid, duplicate,
  replayed id, wrong-side answer, ICE for live/unknown call, hangup.
- `regtest_e2e::real_ldk_regtest_calls` (real Core + electrs + LDK, A–C–B):
  live price query, paid offer, local refusals, answer/ICE/hangup both ways,
  msat-exact channel and budget reconciliation.
