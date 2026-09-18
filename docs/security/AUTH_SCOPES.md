# Route → scope matrix (genome #72, ticket 1)

Today every authenticated route is equivalent: `Claims {sub, iat, exp}`, `AuthUser {node_id}`,
and `POST /auth/local` mints that token for **any process that can reach loopback**. Reading a
balance and spending the balance are the same grant.

This document is the contract for ticket 1: **constrained issuance + enforcement**. Pairing,
hardware-bound keys and anything touching protocol admission are out of scope.

## Why the app requesting less is not enough

Scopes only reduce risk if the **issuer** is constrained. A malicious local process does not
politely request `read` — it requests everything. So the fix is not "the app asks for a weaker
token"; it is that **`/auth/local` is structurally incapable of minting the dangerous scopes.**

## Scopes

| scope | meaning |
|---|---|
| `read` | observe state: status, identity, balances, history, peers, rooms, pricing |
| `receive` | create the means to be paid: funding address, invoice |
| `spend` | move value: pay, keysend, on-chain send, channel open/close — **and paid messaging**, which settles a payment per message |
| `admin` | change node configuration and relationships: peers, pricing, gossip, invites, content |
| `identity` | key material and identity replacement: reveal mnemonic, restore, verify mnemonic |
| `credential` | mint credentials at least as strong as one's own |

`spend` includes message send/compose deliberately. Under "payment IS the connection", sending a
message *is* spending; treating it as messaging rather than spending would reopen the hole by
another door.

## Issuance

| issuer | proof required | scopes granted |
|---|---|---|
| `POST /auth/local` | loopback presence only | **`read` + `receive`** |
| `POST /auth/token` | Ed25519 signature over a single-use challenge, verified against the node's own identity key | **all scopes** — preserved deliberately, see below |

Loopback presence grants **no** `spend`, `admin`, `identity` or `credential`. Not "should not
request" — *cannot obtain*.

`/auth/token` keeps full authority **explicitly**. Both issuers currently call the same
`create_token(node_id, jwt_secret)`, so a change there would silently alter the key-proof path
too. Ticket 1 makes each issuer name its own scope set at the call site, so neither can drift
into the other by accident.

Note what the key-proof flow is and is not: it proves possession of the node's identity key.
That is not by itself a recovery flow, and it is not usable by a local UI that deliberately never
holds the key — which is why pairing (ticket 2) exists.

## Matrix

### read
Observation only. Every authenticated handler not listed under another scope requires `read`:
status, chain status, identity display, payment history/balance/channels/price, peers list,
pricing, rooms list/get/members, sessions list/status/prekey, routing, gossip status,
onboarding state, invites list/capabilities, message get/list/search/plaintext, content
list/read/manifest, file download/list, hosting contracts list + ledger, calendar event list.

`read` includes **message plaintext** (`/messages/:id/plaintext`) and message search. That is
deliberate and is the main residual exposure of loopback issuance — see the closing section.

### receive
`GET /payments/funding-address` · `POST /payments/invoice` ·
`POST /onboarding/start` with `tier: "full"`

`/onboarding/start` is scoped per tier, because one route carries two different
operations. `full` asks the Lightning backend for a funding address and records the amount
expected — that is "create the means to be paid", which is `receive`, and it is the path
the shipped app uses. `light` records an inviter and an invite, which begins a
relationship, so it still requires `admin`. The extractor states the `receive` floor and
the administrative branch raises it, because the tier is only known from the body.

### spend
`POST /payments/pay` · `/payments/keysend` · `/payments/send-onchain` · `/payments/open-channel` ·
`/payments/close-channel` · `/messages` · `/messages/compose` · `/files/:id/send`

### admin
Anything that changes configuration, relationships, or stored content:

`POST /peers` (add) · `PUT /peers/:id` · `DELETE /peers/:id` · `POST /peers/:node_id/connect` ·
`/peers/:node_id/discover` · `/peers/import` · `GET /peers/export` · `GET /export/bundle` ·
`POST /gossip/publish` · `/invite` · `/invite/redeem` · `/invites` · `/invites/accept` ·
`DELETE` an invite (revoke) · `POST /rooms` (create) · `DELETE /rooms/:id` ·
`POST /rooms/:id/members` · `DELETE` a room member · calendar event create/update/delete +
`/calendar/events/:id/rsvp` ·  `POST|PUT|DELETE /content/pages/*` ·
`POST /files` (upload) · `DELETE` a file · `/messages/resync` · `DELETE` a message ·
hosting contract creation · session initiate/accept.

`/peers/export` and `/export/bundle` are `admin` rather than `read`: they emit the user's
relationship graph in bulk, which is a different exposure from reading one record.

Session initiate/accept are `admin` rather than `read` because they establish durable
relationship state with a peer. This is the local owner API, not the wire admission path —
inbound packets remain governed by settled payment at the gate, unchanged by this ticket.

### spend, additionally

Three calendar handlers require `spend` **as well as** `admin`: event create, event update,
and RSVP. Each calls `create_payment_proof`, which at a nonzero price dispatches a keysend
or an invoice payment. Admin is the mutation; spend is the money. Requiring only the first
would let a token that cannot spend move value.

### identity
`POST /identity/mnemonic` (reveal) · `/identity/restore` · `/identity/verify-mnemonic`

### WebSocket

`GET /ws` requires `read`, checked before the upgrade, for both the subprotocol and the
legacy query-parameter form. The socket subscribes immediately to plaintext message and
delivery broadcasts, so admitting a token the REST routes would refuse would hand it the
message stream. This endpoint authenticates itself rather than using the extractor, which
is exactly why it was missed on the first pass.

### unauthenticated (unchanged)
`GET /auth/challenge` · `POST /auth/local` · `POST /auth/token` · `GET /livez` · `/metrics`

## Migration: tokens minted before scopes

A token with no scope claim is **rejected** with a clear error telling the caller to
re-authenticate. It is *not* treated as full access, and *not* silently downgraded to `read` to
keep a screen working. Tokens live 24h and the app mints on demand, so the cost is one re-auth.

No hidden fallback. If something breaks, it breaks visibly.

## Migration consequence for the app — stated, not hidden

**"Restore an existing identity" stops working from a loopback token.** `/identity/restore`
requires `identity`, which `/auth/local` will not grant.

That is the correct outcome: restoring an identity from a seed phrase is precisely the operation
that must not be available to any process that happens to be running on the machine. But it is a
visible regression in the shipped UI and must not be papered over. Until pairing exists, restore
needs an explicit operator action; the button should say so rather than fail opaquely.

The funding flow the app actually ships — identity display, funding address, balance polling —
continues to work on `read` + `receive`.

## Enforcement is exhaustive, not listed

`scope_coverage_tests::no_handler_accepts_an_unscoped_token` fails if **any** handler takes a
bare `AuthUser`. A bare `AuthUser` authenticates but does not authorize: it accepts any valid
token, loopback included.

This matters because the hand-written lists were repeatedly insufficient. A first pass
missed three spend routes whose parameter happened to be named `_user`. A second missed
every handler declared `pub(super) async fn` — 45 authenticated handlers still took an
unscoped token while the targeted tests were green. Review then found three more classes
the guard could not see at all:

| defect | why the guard missed it | invariant that now catches it |
|---|---|---|
| `/ws` upgraded any valid token | the guard walked only `src/handlers`; `/ws` authenticates itself | `self_authenticating_endpoints_also_check_scope`, and the walk now covers all of `src/` |
| three calendar handlers could pay with `admin` alone | the spend list did not name them | `every_function_that_can_pay_demands_spend` — any function reaching `create_payment_proof` must demand `spend` |
| `/onboarding/start` demanded `admin`, breaking the app's funding flow | nothing checked that the *preserved* paths still worked | a behavioural test posting the app's exact body, asserting the funding address and the state it then polls |

The pattern in all three: a rule stated as a list of names proves only what someone
remembered to list. Each is now stated as an invariant over the source instead.

## What the tests can and cannot show

Negative tests can prove **a specific token is refused specific operations**. That is the claim
this ticket makes.

They cannot prove that local malware "can only read the balance". Any process can still call
`/auth/local` and obtain `read` + `receive` — which means reading history and generating
addresses. The blast radius is reduced; it is not eliminated, and nobody should describe it as
eliminated until pairing constrains *who* may obtain a token at all.
