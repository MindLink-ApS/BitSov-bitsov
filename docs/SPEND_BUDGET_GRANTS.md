# Budget-scoped spend grants (G1)

`GET /api/v1/status` advertises `spend_budget_grant_v1` in `api_capabilities`.

A paired client's `spend` now comes only from a **budget grant**: an absolute
expiry (at most 24 h), a total budget, optional per-recipient budgets and a
per-call maximum. The 30-day unmetered grant is gone. A pre-G1 grant without a
budget is dropped when the pairing store is opened and is never honoured. The
store is now version 2, so an older node refuses to open it rather than read a
metered grant as an unmetered one.

## Owner flow (one command per budget window)

1. The app asks: `POST /api/v1/pair/elevation-request` with
   `{"scopes":["spend"],"budget":{"budget_msat":2000000}}`. The `budget`
   object is optional and is only a proposal. Its fields are `budget_msat`,
   optional `per_call_max_msat`, `per_recipient_msat` (map of lowercase hex
   node id or Lightning pubkey to msat) and `ttl_secs` (default and maximum
   86400). A proposal the node cannot enforce is a 400, and nothing is left
   pending.
2. The owner runs `konsensus grant --op <id> [--budget <sats>] [--for 24h]
   [--per-call <sats>] [--recipient <key>=<sats> ...]`. Each flag overrides the
   proposal. With neither a proposal nor `--budget`, the command refuses. The
   CLI prints the request and the exact terms being granted, asks
   `Grant these terms? [y/N]` (`--yes` skips only this question), then asks
   for the confirmation code from the owner node's console, as before.
3. The app re-issues its token. `GET /api/v1/pair/grant` returns the live
   grant (`budget_msat`, `used_msat`, `remaining_msat`, `per_call_max_msat`,
   `per_recipient_msat`, `used_by_recipient`, `granted_at`, `expires_at`), or
   `{"grant": null}`.

Revoke now: `konsensus grant-revoke --client-id <id>` (or `--all`). The pairing
stays with read+receive. Revoking, bumping or deleting a pairing, rotating its
key, or rebinding the identity also removes the grant. Every authenticated
request recomputes the pairing's scopes, so a token that still claims `spend`
gets a 401 on its next request. `konsensus pair-status` lists live grants with
what is left. Requests already waiting for an invoice and queued room members
also recheck their original grant before dispatch. Revocation, rotation,
replacement or expiry stops those undispatched payments; it cannot recall a
payment already handed to the Lightning backend.

## What is debited, and when

| Route | Recipient key | Amount reserved |
|---|---|---|
| `POST /messages/compose` (peer) | node id | quoted price (1-sat minimum) |
| `POST /messages/compose` (room) | each member's node id | every member's quoted price, as **one** call |
| `POST /files/:id/send` | node id | file price (1-sat minimum) |
| `POST /payments/pay` | invoice payee pubkey | invoice amount |
| `POST /payments/keysend` | `dest_pubkey` | `amount_msat` |

The debit happens under the pairing store's mutex and is persisted **before**
any ratchet is advanced, invoice is requested or payment is dispatched. The
original reservation is checked under that same mutex before starting an invoice
request and on every poll of payment futures, including fallback and room-member
operations. A started invoice-request frame is allowed to finish its write to
keep the shared encrypted connection intact; its later payment is checked again.
No mutex is held across an async suspension. If a provider has already been
polled when its grant becomes invalid, its outcome is conservatively unknown:
it may have handed the payment to the backend before suspending.

A budget or price-cap refusal precedes encryption. An encryption failure
before dispatch releases the reservation. A budget refusal is HTTP 409:

```json
{"code":"budget_exceeded","reason":"total","remaining_msat":500,"error":"…"}
```

`reason` is one of `no_grant`, `per_call`, `total`, `recipient`, `unpriced`
(an amountless invoice, whose price is not known before paying),
`first_contact` (a first contact without the owner's one-time confirmation for
that contact; see below) or `ledger` (the ledger could not be written). Nothing
was reserved and nothing was paid.

Outcomes follow the #80 rules. A settled payment is charged the amount the
provider reported. A refusal before dispatch or a confirmed failure is
released. An unknown outcome (transport loss, still in flight, a crash in
between) stays reserved. For rooms, `settled` / `refused` / `unknown` members
resolve the same way. The tally can over-count, never under-count. Routing
fees are provider-controlled and, as with the #80 caps, are not principal.

`POST /messages` (a pre-encrypted message carrying a proof the caller already
paid) accepts a budget grant but debits nothing: it requests no invoice and
dispatches no payment. A proof paid through `/payments/pay` or `keysend` was
debited there.

Routes that move value but are not metered (`send-onchain`, `open-channel`,
`close-channel`, calendar fan-out) refuse a paired caller with 403, whatever
its budget. Only the owner's own key-proof token reaches them. A structural
test fails if a `MeteredSpend` handler can pay before it debits.

## Persistence

The budget, what has been used and the absolute expiry live in
`pairing/clients.json` (0600, write-then-rename). A restart keeps the tally and
cannot extend the window. Store reads and writes purge expired grants under
one mutex. Opening the store must finish the purge before startup can proceed.
The API checks again before binding its listener, covering expiry during startup;
failed cleanup prevents the API from serving any request.
Startup also deletes abandoned `clients.json.tmp` files from interrupted writes;
these uncommitted records are never promoted over the authoritative file.
The running node schedules cleanup for the earliest absolute expiry, waking
when grants change; it also rechecks the wall clock at least once a second.
A hand-edited expiry more than 24 h after `granted_at` is treated as expired.
Granting a new window for a client replaces its previous grant and tally.

Expiry is rechecked after synchronizing a temporary file and after publishing
it. If a write crosses a deadline, the expired grant is removed and the write
is repeated before success is returned. Reads never expose expired records;
a fallible disk read reports a cleanup failure instead of returning stale data.
Failed deletions stay queued and the scheduler retries them once a second.
Revocation removes spend authority immediately but keeps an inert, budgetless
record in memory until its deletion is durable. A failed write therefore cannot
make reads, sweeps or shutdown forget the deletion, even before the original
expiry. The same rule applies to pairing revocation, epoch/key changes, identity
rebind and grant replacement. A failed revocation still reports an error: if the
process crashes before a retry succeeds, only the previously durable state can
be recovered; startup always removes records whose absolute expiry has passed.

Graceful shutdown purges expired grants when the scheduler stops and again after
the API and backend tasks drain. The node waits for the scheduler and reports a
failed final purge as a shutdown error. Live grants keep their original expiry
and tallies across shutdown and restart.

Deletion requires a running process and writable storage. While the process is
stopped, suspended, or unable to write, physical bytes can remain on disk;
they confer no authority. Restart purges them before opening the service, and
read/scheduler retries finish cleanup once storage recovers. Deadline scheduling
is not a guarantee of physical erasure while the process cannot execute.
The expiry gate is that a grant is never honored at or after its absolute expiry
and is purged at the next opportunity: sweep, graceful shutdown, or startup before
API access. A record left while powered off at expiry is acceptable only because
it remains inert and startup purges it before serving requests.

An expiry that occurs while the debit is persisted refuses dispatch rather than
returning a reservation that was pruned. Failed expiry deletions remain in
memory until a successful write, so a later sweep retries after an I/O failure.

## First contact: one confirmation per new contact

A budget never pays a first contact on its own. Reaching a stranger (a
`price_open` node with no session yet) means paying its admission, and the owner
decides that once per contact. The app asks in its own window, and the node
backs that one answer with a short, single-use **first-contact grant**.
`GET /api/v1/status` advertises `first_contact_grant_v1`.

1. **Quote.** `POST /api/v1/messages/first-contact/quote {"recipient"}` asks the
   connected stranger for its signed admission quote. This is F1's bounded
   payment preparation (`docs/v2/F1-CAPPED-FIRST-CONTACT.md`). The node
   validates the quote as a send would and returns `admission_msat`,
   `message_msat`, `total_msat` and `expires_at` (≤ 60 s). It pays and
   reserves nothing, and needs a live budget grant. The node keeps the quote for
   its validity, so the send pays exactly this invoice and the stranger is never
   asked for a second one. For a stranger, it returns 409 if a first contact is
   already paid or in flight. For a contact that needs admission again after a
   reconnect (see below), it returns that contact's quote, reusing one the node
   already holds.
2. **Confirm.** `POST /api/v1/pair/first-contact-grant {"recipient",
   "max_total_msat", "contact_budget_msat"?}` is sent after the owner confirms in
   the app.
   - `contact_budget_msat` is the contact's budget the owner chose on the door
     card. If the budget grant has no cap for this contact yet, it becomes one
     (bounded by the grant's total). This only narrows the grant, and it makes
     the contact *budgeted* (next section).
   - It needs a live budget grant, and the amount must fit it: per-call maximum,
     what is left of the budget, and the recipient's budget if set. It is at most
     100,000 msat (F1's first-contact ceiling).
   - Nothing is reserved yet.
   - The grant expires after 120 s, or with the budget grant if that is sooner.
   - It is single use and for exactly this recipient. A new confirmation replaces
     an unused one.
   - It is held in memory only: never written down, and dropped on restart,
     revocation, rotation or replacement of the budget grant.
3. **Send.** `POST /api/v1/messages/compose` to that stranger consumes the grant.
   - The grant's amount caps the whole first contact: admission plus first
     message, together with any `max_total_msat`.
   - The node reserves that cap **once** against the budget grant before
     requesting the admission invoice.
   - The same reservation is carried through the invoice request
     (`Debit::request_invoice`), the admission payment (`Debit::dispatch`,
     re-checked on every poll) and the message (`create_metered_payment_proof`).
   - It is resolved **once** from the aggregate outcome: settled is charged what
     settled in this call; unknown stays reserved; a call that moved nothing is
     released.
   - A paid admission whose session or message then fails stays charged for the
     admission only.

Without a matching grant, a paired first contact is refused with
`budget_exceeded` / `first_contact` before anything is asked of the stranger. The
owner's own key is not metered; the #80 caps still bound it.

## Re-admission after a reconnect: paid from the budget for a budgeted contact

Admission is per connection; there is no durable admission object. After a
reconnect the recipient holds the connection as unpaid and refuses a message
invoice with `admission_required` (an N2 event on its side). The sender then
pays admission again on the normal paid path: the recipient's signed quote
(F1), the admission payment and its signed proof, then the message.

CoS decision (2026-09-27): **a budget may pay that re-admission for a contact
the owner already budgeted**, without a prompt.

- *Budgeted* means the live budget grant has a cap for this contact: set when
  the owner granted the budget, or by `contact_budget_msat` on the contact's
  first-contact confirmation.
- The node first asks for the recipient's signed quote, then reserves exactly
  the quoted admission against the grant before paying anything. The
  reservation must fit the contact's cap, the per-call maximum and what is left.
  The message is its own reservation, as for every send.
- The payment is resolved once (settled, released if never dispatched, kept
  reserved if unknown). The sender records it as an outbound N2 membrane event
  `readmission`, with the amount and the contact's cap.
- A contact the grant does not budget is refused with `budget_exceeded` /
  `first_contact` before the recipient is asked for anything. The owner's
  one-time confirmation for exactly that contact (steps 1 and 2 above) then
  covers the re-admission, is consumed by it, and bounds its amount. Never for a
  stranger without it.
- A confirmed `max_total_msat` covers the message only. The compose reply's
  `amount_msat` stays the message principal, and the re-admission is reported
  apart as `readmission_msat`. For a paired client the grant bounds it; the
  owner's own key has no such bound, so a capped owner send is refused
  (`price_cap_exceeded`) and an uncapped one pays.

That the owner, not a program, confirmed is the app's contract, the same as for
every budgeted send. The node enforces the rest: an explicit call per contact,
exact recipient, bounded amount, single use, short life, and inside a budget the
owner granted at the node.

