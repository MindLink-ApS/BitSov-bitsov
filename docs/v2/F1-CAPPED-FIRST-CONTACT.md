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
retry again. Unknown outcomes remain HTTP 502; clients must retain their full
confirmed cap until reconciliation, as in #80. The endpoint is not a general
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

The stranger path returns only a signed invoice and its chat price (the signed
message-price field), never a price table, prekeys, peer information, session,
file quote, arbitrary invoice, or application response. Even signed unpaid UKMs
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

**Meaning of stateless:** before settlement there are no BitSov peer, contact,
session, application message, nonce, or stored quote records. The membrane
necessarily retains the transient connection plus bounded volatile source
counters and request-ID digests. A standard Lightning backend necessarily
creates its own pending invoice bookkeeping; expiry limits payment validity,
not historical backend record retention. This is the explicit, rate-bounded
payment-preparation exception required by the invoice keystone. Zero records
inside the Lightning backend itself would require a different backend contract.
Operator transport logs/counters are not peer admission. The requester’s own
payment-recovery journal is separate from target-side stranger state.

## Temporary file staging

`POST /api/v1/files` accepts a currently valid paired spend grant or local owner
capability (Spend/Admin); read/receive-only and revoked clients cannot upload.
Staging is volatile memory, never a persistent file/storage record: 4 MiB per
file, 8 MiB per grant/owner, 16 MiB globally and 64 entries. Filename, MIME,
encoded-size and decoded-size checks precede insertion. Staging transfers no
Lightning principal and grants no file-management authority; deletion remains
Admin-only and another grant cannot read or send the staged file.

Entries expire after five minutes. Access and a 15-second background sweep
remove expired/revoked idle entries; startup begins with an empty store, so no
staged bytes survive restart. A send rechecks the live grant, owns its quota
through all awaits, and consumes the blob on success, error or cancellation.
A cap refusal before dispatch leaves it available within its existing expiry.
In-flight sends end at the earlier of stage expiry and 60 seconds. An ambiguous
payment timeout returns HTTP 502 with an explicit unresolved-outcome message;
deleting staging never means the
payment failed, and clients must retain their reservation and not auto-retry.
Received files remain durable and retain the existing access controls.

## G1 integration contract

Reviewed against PR #81, `feat/g1-budget-scoped-grant` at
`fec318395e5b49ab52d42198f62630d865180ba7`, then its dispatch-validity update
`942b68a698552a5b4e571fa2463f2344fedcaa4f`. F1 is based on main `f2f17695`;
it does not merge, rewrite, or replace G1's grant implementation.

When rebasing G1, retain `MeteredSpend` on compose and file send. File staging
must use `AuthUser` plus the explicit capability check: G1 deliberately rejects
paired clients on the unmetered `ScopedAuth<Spend>` extractor, even though
staging itself transfers no money.

For paired first contact, reserve **one call** against the effective aggregate
cap before requesting an invoice. Keep `refuse_unpriced` for a paired request
without an explicit aggregate bound. The signed invoice determines the actual
admission/message split within that reservation. Do not remove G1's refusal
and leave a message-only debit: that would allow admission to bypass the grant.
At `942b68a`, G1 debits before encryption and releases on encryption failure.
The first-contact `NoSession` branch must keep the aggregate debit while it
continues admission, not release it and continue using a released reservation.
Until this integration is made, retain G1's fail-closed first-contact refusal.

Carry the same aggregate `Debit` through admission's invoice frame using
`Debit::request_invoice`, admission payment using `Debit::dispatch`, and the
message using `create_metered_payment_proof`. That last helper is essential:
G1's public `create_payment_proof` now wraps an **unmetered** debit. Preserve
G1's per-poll grant validity checks across revocation/expiry while a provider is
pending, and across keysend-to-invoice fallback. A reservation alone is not
permission to dispatch after the grant has been revoked.

Resolve the same-recipient reservation exactly once at the outer compose
result, using the aggregate receipt or `FirstContactCharge` outcome. Two calls
to `Debit::settled` for the two legs subtract against the same original
reservation twice. Ordinary failures after settlement must not release the
paid admission. Unknown/cancelled outcomes retain the reservation. A resumed
admission belongs to the original grant/reservation, not the retry's grant;
associate that reservation with the journal before allowing automatic budget
reconciliation across retries or restart. Owner calls remain subject to caps.

Required combined regressions: aggregate per-call grant refusal before invoice
request; admission paid then session/proof/delivery failure; admission unknown
then retry/restart; admission settled/message failed; same-recipient resolution
once; cancellation; and bounded paired upload without management privileges.

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
