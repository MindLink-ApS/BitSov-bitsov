# Paid-send caps and room outcomes

`GET /api/v1/status` advertises `api_capabilities` containing
`paid_send_caps_v1` and `room_terminal_outcomes_v1`.

`POST /api/v1/messages`, `/messages/compose`, and `/files/:id/send` accept
optional `max_total_msat`. Message endpoints also accept optional
`max_recipient_msat`, an object mapping canonical lowercase node IDs to caps.
For room compose, the map must match every current non-self member exactly. A joined
or removed member therefore requires a fresh quote before any payment.

The cap covers recipient payment principal, including the 1-sat minimum for
nonzero prices. A zero-price proof stays zero. Lightning routing fees remain
provider-controlled and are not included in this principal cap. The raw
`/messages` endpoint receives an already-paid proof; it checks that proof's
amount before storage/delivery and does not create or pay an invoice itself.
It cannot undo a payment the caller made before submitting the proof.

Compose captures the current prices once, checks the full total and each
recipient cap before any invoice request or payment, then pays those captured
amounts. Concurrent pricing updates cannot increase the dispatched amount.
An invoice response must still match the exact amount requested. Cap refusal
returns HTTP 409 with `{"code":"price_cap_exceeded","error":"…"}` and no
invoice or payment dispatch. Existing errors retain their numeric HTTP code.
Omitting caps preserves the uncapped principal behavior for existing clients.

Capped first-contact compose refuses before requesting an admission invoice
when no session exists: admission has a separate recipient-set price that is
not included in the message quote. Establish admission separately before a
capped send. An uncapped client retains the existing paid-admission behavior.

Room compose returns `member_outcomes` for every non-self recipient, including
when no message could be stored. Each row has `recipient`, `status`,
`amount_msat`, nullable `message_id`, and nullable `reason`:

- `settled`: payment is confirmed; amount is the settled principal. A missing
  message ID means payment succeeded but proof construction/storage failed;
  this is not a queued or delivered message.
- `refused`: nothing was dispatched, or the payment was confirmed failed or
  expired. Amount is zero.
- `unknown`: payment may be in flight or its terminal state cannot be verified.
  Amount is zero because no settled amount is proven; it is not proof of no spend.

Top-level `amount_msat` sums known settled amounts. Top-level `message_id` is
one stored member envelope, or the empty string if none was stored.
`delivered` means at least one envelope reached a connected member; HTTP 200
and a canonical message ID do not establish every member's success.

Clients must validate all rows against the confirmed member set, preserve an
ambiguity fence for any missing/unknown/inconsistent row, and never infer room
settlement from one canonical message. This API does not provide aggregate
reconciliation for a completely lost room reply. A terminal partial result
must still disclose refused or paid-but-unstored members; retrying the whole
room message may duplicate payments to successful members.
