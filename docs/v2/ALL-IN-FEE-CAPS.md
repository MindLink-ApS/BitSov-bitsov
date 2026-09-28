# All-in Lightning debit caps (FEE-CAP)

`max_total_msat`, per-recipient message caps, and G1 grants authorize wallet
debit: principal plus the approved routing fee ceiling. A 1,000 msat message
therefore needs a 2,000 msat cap under the default policy. A caller can instead
request `max_routing_fee_msat: 0` and authorize only a zero-fee route.

Ordinary invoice, keysend, compose, and file requests accept an optional
`max_routing_fee_msat`. It tightens the node policy; it cannot widen it.
The default is `min(max(1000, floor(principal / 100)), 10000)` msat per
payment. Zero-price messages create no payment and reserve no fee. LDK always
receives `RouteParametersConfig.max_total_routing_fee_msat`, including bound
keysend and internal callers using the ordinary provider methods. Unsupported
fee-limited provider methods refuse before dispatch.

Embedded LDK nodes configure the policy in `konsensus.toml`:

```toml
[routing_fees]
minimum_msat = 1000
proportional_millionths = 10000
maximum_msat = 10000
```

Sponsor gifts retain their separately approved explicit fee ceiling. Their
G1 reservations, like the sponsor purse, cover gift plus maximum fee.

A first-contact quote includes both admission and message fee ceilings in
`total_msat`. A room reserves the sum of individual all-in payments before
fanout. Reconnect admission is an additional payment: a request with a total
or recipient cap refuses that unquoted payment. An uncapped request may use
the existing admission authority, but G1 still reserves its all-in amount and
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
