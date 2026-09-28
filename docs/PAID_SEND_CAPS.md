# Paid-send caps and room outcomes

`GET /api/v1/status` advertises `api_capabilities` containing
`paid_send_caps_v1` and `room_terminal_outcomes_v1`.

`POST /api/v1/messages`, `/messages/compose`, and `/files/:id/send` accept
optional `max_total_msat`. Message endpoints also accept optional
`max_recipient_msat`, an object mapping canonical lowercase node IDs to caps.
For room compose, the map must match every current non-self member exactly. A joined
or removed member therefore requires a fresh quote before any payment.

The cap covers all-in wallet debit: recipient principal (including the 1-sat
minimum for nonzero prices) plus the approved maximum routing fee. The default
fee ceiling is `min(max(5000, floor(P / 100)), 10000)` msat; an optional
`max_routing_fee_msat` tightens it. Zero-price proofs reserve no fee. The raw
`/messages` endpoint receives an already-paid proof; it checks that proof's
amount before storage/delivery and does not create or pay an invoice itself.
It cannot undo a payment the caller made before submitting the proof.

Compose captures the current prices once, checks the full total and each
recipient cap before any invoice request or payment, then pays those captured
amounts. Concurrent pricing updates cannot increase the dispatched amount.
An invoice response must still match the exact amount requested. Cap refusal
returns HTTP 409 with `{"code":"price_cap_exceeded","error":"…"}` and no
invoice or payment dispatch. Existing errors retain their numeric HTTP code.
Omitting total/recipient caps leaves principal uncapped; the routing policy still applies.

First-contact compose checks the aggregate admission/message principal and
both fee ceilings against the confirmed cap. The app confirms `quote.total_msat`
and displays `quote.max_routing_fee_msat` separately (already included in total).
A capped reconnect re-admission is allowed only when the payee returns a fresh
signed quote whose admission, message, and both fee ceilings fit that same
caller cap (and any grant); the all-in amount is reserved before dispatch.
No quote, or a quote that does not fit, is refused before payment. An uncapped
authorized request may reserve and pay that additional all-in admission under
existing G1 admission authority.

Room compose returns `member_outcomes` for every non-self recipient, including
when no message could be stored. Each row has `recipient`, `status`,
`amount_msat`, nullable `message_id`, and nullable `reason`:

- `settled`: payment is confirmed; amount is the settled principal. A missing
  message ID means payment succeeded but proof construction/storage failed;
  this is not a queued or delivered message.
- `refused`: nothing was dispatched, or the payment was confirmed failed or
  expired. Amount is zero.
- `unknown`: payment may be in flight or its terminal state cannot be verified.
  The response amount describes attempted principal. The held liability includes
  that principal plus the approved fee ceiling and is not released for retry.

Top-level `amount_msat` sums settled amounts plus the reserved principal of
unknown members. An unknown row does not establish settlement.
Top-level `message_id` is one stored member envelope, or the empty string if none was stored.
`delivered` means at least one envelope reached a connected member; HTTP 200
and a canonical message ID do not establish every member's success.

Clients must validate all rows against the confirmed member set, preserve an
ambiguity fence for any missing/unknown/inconsistent row, and never infer room
settlement from one canonical message. This API does not provide aggregate
reconciliation for a completely lost room reply. A terminal partial result
must still disclose refused or paid-but-unstored members; retrying the whole
room message may duplicate payments to successful members.

Keysend fallback requires `LightningError::PaymentNotDispatched`: a typed
provider guarantee that dispatch never began (for example, unsupported keysend
or rejected local key validation). Generic connection/backend/payment errors,
including response read/parse failures and timeouts, are unknown; they never
trigger an invoice request or a second payment. Even generic connection errors
are conservative unless the provider can positively prove pre-dispatch failure.
A room member with such an error remains unknown with its checked price reserved.

`amount_msat` always describes principal. `max_routing_fee_msat` reports the
aggregate authorized fee ceiling, including paid or unresolved file errors and
calendar fanout/RSVP. Known settlement reconciles actual principal plus actual
fees; unknown outcomes or missing fee records retain the all-in reservation.
Capped invoice payments require a fresh hash, including after a route miss;
request a new invoice to try a wider fee allowance. See
[all-in fee policy and backend support](v2/ALL-IN-FEE-CAPS.md).
