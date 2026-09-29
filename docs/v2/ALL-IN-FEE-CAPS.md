# All-in Lightning debit caps (FEE-CAP)

`max_total_msat`, per-recipient message caps, and G1 grants authorize wallet
debit: principal plus the approved routing fee ceiling. A 1,000 msat message
therefore needs a 6,000 msat cap under the default policy. A caller can instead
request `max_routing_fee_msat: 0` and authorize only a zero-fee route.

Ordinary invoice, keysend, compose, and file requests accept an optional
`max_routing_fee_msat`. It tightens the node policy; it cannot widen it.
The default is `min(max(5000, floor(principal / 100)), 10000)` msat per
payment. Zero-price messages create no payment and reserve no fee. LDK always
receives `RouteParametersConfig.max_total_routing_fee_msat`, including bound
keysend and internal callers using the ordinary provider methods. Unsupported
fee-limited provider methods refuse before dispatch.

LDK and LND nodes configure the policy in `konsensus.toml`:

```toml
[routing_fees]
minimum_msat = 5000
proportional_millionths = 10000
maximum_msat = 10000
```

Sponsor gifts retain their separately approved explicit fee ceiling. Their
G1 reservations, like the sponsor purse, cover gift plus maximum fee.

A first-contact quote includes both admission and message fee ceilings in
`total_msat`. A room reserves the sum of individual all-in payments before
fanout. Reconnect re-admission needs a fresh signed quote: a capped
**single-recipient chat** request pays only when that quote's all-in admission +
message fit the caller cap (and any grant), reserved before dispatch. Rooms,
files, and other non-chat kinds refuse a capped reconnect before any quote. No
quote or a non-fitting quote is refused before payment. An uncapped request may
use existing admission authority, but G1 still reserves its all-in amount and
applies the caller's tighter routing limit.

G1 reserves before dispatch and reconciles principal plus actual fee after
settlement. Missing fees and ambiguous outcomes retain the full reservation;
confirmed failures and positive non-dispatch release it. Admission recovery
uses the original durable reservation and never releases fees as if they were
zero. Existing persisted reservations remain conservative and are not expanded
into new dispatch authority.

Responses and payment/cap errors report `max_routing_fee_msat`; compose/file
responses sum the authorized message and admission ceilings. `amount_msat`
and payment proofs still describe principal, so fees are never presented as
value received by the peer. The ceiling is an authorization, not a prediction
of the route's actual fee. Stable cap and budget refusal codes are preserved.

The 5,000-msat floor allows several forwarding hops with base fees around one
sat each, while the 10,000-msat absolute maximum limits ordinary fee exposure.
This is a routing allowance, not a promise that a route exists. A small message
can cost more in fees than principal; callers can tighten the fee allowance.

LND sends the exact ceiling as REST `fee_limit_msat`, including zero ([LND
SendPaymentV2](https://lightning.engineering/api-docs/api/lnd/router/send-payment-v2/)).
LNbits has no supported portable per-payment fee contract here. Selecting
`lightning.backend = "lnbits"` fails configuration/startup with `not_supported`
before provider initialization. Use LDK or LND; this is not a per-payment refusal.

LDK's initial route failure (`PaymentSendingFailed`, including the underlying
`RouteNotFound`) proves no dispatch: reservations release and keysend may fall
back to an invoice. It does not disable wallet capability. Persistence errors
can occur after dispatch and remain unresolved. Invoice hashes are single-use
for capped payments: even a failed attempt requires a fresh invoice; increasing
the fee allowance and resubmitting the same hash is refused. Reconcile by hash.
LND checks exact outgoing history with `TrackPaymentV2` and remembers possible
dispatches until restart; it also refuses existing failed hashes. This requires
exclusive payment-writing ownership of that LND wallet: REST offers no atomic
freshness exclusion against independent wallet clients. Backend history must
not be deleted while operations remain unresolved.

App migration: `max_total_msat` and `FirstContactGrant.max_total_msat` now bound
principal **plus fees**. Show `quote.max_routing_fee_msat` alongside admission
and message principal; confirm `quote.total_msat`, which already includes both
fee ceilings. Clients constructing totals themselves must add the aggregate
routing ceiling once. Do not add it again to `quote.total_msat`. Old principal-
only confirmations fail closed. Calendar event/update/RSVP replies include
`max_routing_fee_msat`; fanout replies sum individual authorized ceilings.

The stock mock now issues signed regtest BOLT11 invoices. Their mock-only
metadata carries the simulated preimage for cross-instance testing; these
invoices never represent real funds. Synthetic or unrelated invoice strings
are rejected. Mock settlement and fee-limit enforcement remain active.

## Channel open fee and announcement (#101)

On-chain channel opens are outside Lightning routing-fee caps. For
`POST /payments/open-channel` (and the LDK opener):

- An explicit per-channel funding `fee_rate_sat_per_vb` (sat/vB) is **refused
  before dispatch** (`PaymentNotDispatched`: LDK cannot enforce that ceiling).
  Omit the override and use the node's fee estimator.
- `announce: true` is refused before dispatch when the node cannot honour
  announcement prerequisites (no alias / listening addresses) —
  `announce_unavailable`. Private opens (`announce: false`) remain the
  supported path for BitSov nodes without an alias.
- A successful open return means initiation, not confirmed usable capacity;
  wait for confirmations and both ends reporting the channel active.
