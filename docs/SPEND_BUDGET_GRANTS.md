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
(an amountless invoice, or first-contact admission, whose price is not known
before paying) or `ledger` (the ledger could not be written). Nothing was
reserved and nothing was paid.

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
cannot extend the window. Expired grants are removed on every store write, at
open, and by a 60-second sweep. A hand-edited expiry more than 24 h after
`granted_at` is treated as expired. Granting a new window for a client replaces
its previous grant and tally.

An expiry that occurs while the debit is persisted refuses dispatch rather than
returning a reservation that was pruned. Failed expiry deletions remain in
memory until a successful write, so a later sweep retries after an I/O failure.
