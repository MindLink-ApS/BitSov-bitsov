# Capped first contact and paired file staging (F1)

A connected stranger can call `POST /api/v1/messages/compose` with
`max_total_msat`. Admission and message delivery are two separately settled,
single-use acts. At a 2,000-msat admission price and 2,000-msat message price,
the call needs a 4,000-msat cap. The response's `amount_msat` includes both
principals. Routing fees remain outside the principal cap, as in #80.

First contact is restricted to `KIND_CHAT` (`konsensus:admission:0`). The
requester sends an amount hint that the target ignores. The target reads the
chat admission/message price from its own pricing engine and
puts the message price and request nonce in the signed admission invoice's
description. The requester checks the authenticated Noise responder, invoice
hash, expiry, amount, signed quote, and aggregate/recipient caps before paying.
If the recipient's Lightning pubkey is already known, the invoice payee must
also match it. On first contact the authenticated recipient endorses the
invoice; the receiving payment gate independently requires incoming settlement
in that recipient's backend. The admission invoice must remain within the
existing 100,000-msat protocol ceiling. An uncapped first-contact request also
uses 100,000 msat as its aggregate safety ceiling.

Positive sub-satoshi message quotes are normalized to the backend's 1,000-msat
minimum before checking the aggregate. A malicious signed `message=1` quote
cannot authorize 1,000 msat outside the caller's cap. Invoice fallback continues
to require explicit `PaymentNotDispatched` from keysend; ambiguous dispatch
never tries another payment path. The message invoice's responding peer, hash,
settled amount/direction, and preimage must also match. Ordinary message invoice
fallback now also verifies the known recipient Lightning pubkey before payment;
a third-party payee is refused even when the authenticated responder supplies it.

Before admission dispatch, a private journal in the node's data directory
records the payment hash, amount, and quote. Writes and directory updates are
synced. Cancellation, response loss, backend unavailability, and restart keep
the original attempt reserved. Retries reconcile that hash or resend the saved
proof. Unknown attempts never expire; `PaymentNotFound` is not proof of failure.
Explicit non-dispatch and a matching terminal failure release the attempt.
Known settled admissions retain the existing 15-minute lifetime, including
across restart. The journal is payment-recovery state; it does not authorize
admission or bypass the receiver's single-use settlement gate.

Paid operational failures return HTTP 502 with
`code: "payment_settled_send_incomplete"` and the principal newly settled by
that call in `amount_msat`. Reconciled prior admissions are not charged to the
retry again. If a retry pays nothing new and is refused by its cap or grant, it
retains the cap/budget refusal code and emits the corresponding N2 event. Unknown
outcomes remain HTTP 502; clients must retain their full confirmed cap until reconciliation, as in #80. The endpoint is not a general
message-idempotency API: clients must not blindly retry a lost send response.

## Stranger payment preparation and the whitepaper floor

The whitepaper's irreducible floor permits only the work needed to determine
whether inbound contact is paid. Its membrane section describes a bounded,
unprivileged quarantine before promotion; the 2026-07-01 keystone specifically
has the target re-price and the requester pay the target's invoice. This change
implements that narrow invoice-payment preparation step. It does not interpret
the floor as permission for a general unpaid price/invoice service. The literal
"no invoice" clause and an invoice-first keystone cannot both apply without
this exception: here the floor includes only the bounded payment-preparation
quote needed to offer that payment. This is an explicit protocol clarification,
not a claim that creating an invoice is already settled work.

The stranger path returns a signed invoice and its chat price (the signed
message-price field), or the fixed `stateless_quote_unsupported` refusal. It never
returns a price table, prekeys, peer information, session, file quote, arbitrary
invoice, or application response. Even signed unpaid UKMs
receive no detailed rejection or corrective price table. Durable nonce records
are written only after price and settlement checks; rejected strangers do not
create application audit records.

Quote request IDs bind the authenticated Noise sender, target NodeId, issuance
second and fresh nonce. The invoice signs that ID and price, pays the target's
Lightning backend, and expires within 60 seconds of the attempt. One ID can
issue at most one invoice, including after restart: attempts timestamped at or
before this process's startup second are rejected. New quotes can therefore be
unavailable during the first startup second. Synchronized clocks are required:
future-dated attempts and attempts older than the 60-second window are rejected. Lightning settlement and the durable payment-hash
replay gate make the paid proof single-use. A spent or expired quote cannot
promote a second contact.

Issuance is limited to one attempt per actual TCP source IP per 10 seconds and
16 globally per 10-second window. IPv4-mapped IPv6 addresses share the same
source bucket. Rotating Noise identities does not reset a source limit. Live
replay/rate guards are bounded and refused rather than evicted. Pricing and
invoice creation each have five-second deadlines; failures consume their quota
and produce no fallback service.

**Stateless backend requirement:** before settlement there are no BitSov peer,
contact, session, message, nonce, quote or pending-invoice records, including in
Lightning payment storage. The membrane retains only its transient connection
and bounded volatile source counters/request-ID digests. Operator transport logs
are not admission records. The requester’s own authorized payment-recovery journal
is separate from target-side stranger state.

Production first-contact quotes are **LDK-only**. The vendored LDK Node 0.7.0
extension calls `ChannelManager::create_bolt11_invoice` with `payment_hash=None`,
which uses `create_inbound_payment`: the hash/secret use the node's expanded inbound
key, so the preimage is reconstructible on HTLC receipt without a pending record.
The ordinary `receive` API is not used. Required BOLT11 payment metadata carries a
node-signed version, absolute expiry and quoted amount, bound to the payment hash
and secret. `PaymentClaimable` validates it against the local node key and wall
clock before claiming, including after restart; LDK's block-time grace period
cannot extend the short quote deadline. Missing or modified metadata fails closed. The event handler inserts an incoming
successful receipt only on `PaymentClaimed`, before exposing `PaymentReceived`.
LDK's necessary channel/HTLC safety persistence is unchanged. Unknown stateless
BOLT11 payments have no fee-skimming allowance, and duplicate attempts cannot
change the successful receipt or reopen it.

LND, LNbits and other backends without this capability fail closed without an
invoice RPC or payment. The rate-limited quote refusal carries
`stateless_quote_unsupported`; the sender's compose API returns HTTP 503 with
that code. It authenticates the recipient before accepting a refusal. There is
no fallback to ordinary stateful invoice creation. Established-peer invoice
payments continue to use the normal backend API.

The explicitly configured shared mock models the same storage invariant:
quotes are signed without a row; its atomic payment transaction first inserts
an already-settled receipt. Unpaid/failed quotes leave no row, and settled
replays cannot debit twice. This remains a no-funds local test backend, not a
production Lightning implementation.

## Temporary file staging

`POST /api/v1/files` accepts a currently valid paired spend grant or local owner
capability (Spend/Admin); read/receive-only and revoked clients cannot upload.
Staging is volatile memory, never a persistent file/storage record: 4 MiB per
file, 8 MiB per grant/owner, 16 MiB globally and 64 entries. Filename, MIME,
encoded-size and decoded-size checks precede insertion. Staging transfers no
Lightning principal and grants no file-management authority; deletion remains
Admin-only and another grant cannot read or send the staged file. Paired entries
carry the creating grant operation ID as well as client, epoch and identity;
replacement or regrant never revives the old grant's uploads.

Entries expire after five minutes. Access and a 15-second background sweep
remove idle entries whose exact creating grant expired, was revoked or was
replaced; startup begins with an empty store, so no staged bytes survive restart. A send rechecks the live grant, owns its quota
through all awaits, and consumes the blob on success, error or cancellation.
A cap refusal before dispatch leaves it available within its existing expiry.
In-flight sends end at the earlier of stage expiry and 60 seconds. An ambiguous
payment timeout returns HTTP 502 with an explicit unresolved-outcome message;
deleting staging never means the
payment failed, and clients must retain their reservation and not auto-retry.
Received files remain durable and retain the existing access controls.

## G1 and N2 integration

Main through `6dd70976` is merged, including G1 budget grants and N2 membrane
observations. Compose and file send use `MeteredSpend`; paired staging uses
`AuthUser` with an explicit spend capability check and retains no permanent blob.
Price-cap and budget refusals both feed N2's outbound membrane observations.

Paired first contact reserves one effective aggregate cap before requesting any
invoice. Requests without an explicit cap fail closed. The same `Debit` guards
admission invoice requests, admission payment and message payment, revalidating
the original grant at each dispatch poll. The signed target quote determines
both prices within the cap. Owner requests still obey the price caps.

Each durable reservation has a unique id and outstanding recipient map. Resolving
one recipient consumes that entry once, atomically with the adjusted tally, so
retries and restarts cannot release it twice. Outstanding reservations are bounded
at 1,024 per grant; unknown outcomes are retained rather than evicted.

The admission journal records the original reservation before dispatch. Recovery
can reconcile confirmed admission settlement/failure against that original grant,
including when a different caller retries. It never restores spend authority. A
retry that merely polls an old unknown payment releases its own unused reservation.
Before starting the message payment the journal durably marks that second leg as
possibly dispatched. Cancellation in that window keeps the original aggregate
reserved; admission settlement alone cannot release an uncertain message debit.

Per-peer serialization covers the full compose operation. Every known result
resolves its aggregate reservation once; unknown/currently cancelled payments
remain reserved. File cap/budget refusals preserve staging, and an abandoned Noise
write shuts down the connection so later traffic cannot reuse partial framing or
an unmatched encryption nonce. Post-payment file failures report settled principal.

Combined regressions cover aggregate budget refusal before quote, target cap
refusal, both payments under one reservation, revocation during quote retrieval,
unknown retry/restart, original-grant reconciliation, exactly-once resolution,
paired staging, and N2 refusal events. The existing G1 cancellation, expiry,
rotation, fanout and fallback tests run on the combined tree.

**On top of that (#85):** the aggregate cap alone never lets a budget pay a
stranger. A paired first contact also needs the owner's one-time first-contact
grant for exactly that recipient, which bounds the cap
(`docs/SPEND_BUDGET_GRANTS.md`, "First contact"). After a reconnect, a contact
the grant budgets is admitted again from the budget without a prompt, at its
signed quote and within its cap. Anyone else needs that one-time confirmation
("Re-admission after a reconnect").

## Local proof and limits

`bitsov-app` PR #46's `scripts/two-node-mock-harness.sh` uses two fresh local
identities, loopback-only macOS sandboxing, and `shared_mock`. The shared mock
issues valid signed regtest invoices and atomically settles them in a local
SQLite ledger. Only the recipient sees the corresponding incoming settlement;
re-paying an invoice cannot debit it twice. It has no channels or real funds.

The harness covers strict first contact, encrypted peer and A+B room delivery,
paired upload/file delivery, aggregate cap refusals, and a withheld real HTTP
response. A separate stock-mock phase retains the generic backend-error
regression. Every request/response and remaining limitation is recorded in its
private evidence directory. No owner upload fixture or disabled settlement
check is used for the successful admission/file flows.

This does not prove LND/LDK routing, liquidity, fees, HTLC timing, a room with two
remote recipients, or the live Tauri UI. A peer price table can remain unknown
immediately after admission, and existing startup ratchet repair can delay
readiness; the harness records both rather than claiming those are fixed.

The first-contact approval endpoint requires the independent owner's credential,
plus the target paired `client_id` and exact budget `grant_op_id`. Paired spend
tokens can fetch quotes and send within approved terms, but cannot mint owner
approval. Cached quotes remain chat-only and expire at the signed BOLT11 expiry,
which may be earlier than the admission request deadline.
