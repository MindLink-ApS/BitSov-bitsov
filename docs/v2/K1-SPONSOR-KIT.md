# K1 slice 2: capped sponsor sats in the introduction kit

Spec: `MindLink-Private/pm/projects/bitsov/research/K1-FIRST-CONTACT-KIT-SPEC.md`. Builds on slice 1 (#89, signed introductions).

One person funds another. The inviter's node pays a small, capped gift of its own bitcoin into the newcomer's own node. The newcomer then pays for first contact and every message like anyone else.

## What the gift is not

- **Not admission.** The gift's invoice hash is written to the gate's durable receipt table (`payment_receipts`) on the newcomer's node *before the invoice leaves that node*. An envelope proving payment with that hash is refused as a reused payment, even from the sponsor, who learns the preimage by paying. This holds across restarts, on every backend, with or without settlement checks.
- **Not credit.** It is ordinary balance in the newcomer's wallet. The newcomer can keep it, spend it or withdraw it. Nothing refills it, and received messages never top up the sponsor's purse.
- **Not authority.** Sponsoring grants no power over the newcomer's wallet, and the newcomer's funding request grants nothing to anyone.

## Flow

| Step | Who | Route | Scope | What happens |
|---|---|---|---|---|
| 1 | owner | node config `[sponsor]` | — | Turns sponsoring on. Off by default; see caps below. |
| 2 | sponsor | `POST /api/v1/sponsor/offer` | spend (metered) | Signs a fresh introduction card plus a `SponsorOffer` for that card's `intro_id` only. Link: `bitsov://introduce#<card>.<offer>`. Opens the one active kit. Moves nothing. |
| 3 | newcomer | `POST /api/v1/sponsor/request {link}` | receive | Verifies the card and offer (same key, same `intro_id`, network, expiry, strict Ed25519). Creates one invoice of exactly the offered gift, registers its hash as funding-only (fails closed), and signs a `FundingRequest`. Returns `bitsov://sponsor-request#…` and a six-digit code. |
| 4 | in person | — | — | The newcomer shows the request as a QR; both people compare the six digits. |
| 5 | sponsor | `POST /api/v1/sponsor/candidate {request}` | spend (metered) | Verifies the signature, that the request is for this sponsor, and that the invoice pays the bound Lightning key the exact amount with the exact hash. Freezes the request as the kit's only candidate; a different one is refused, not swapped in. |
| 6 | sponsor | `POST /api/v1/sponsor/approve {intro_id, code}` | spend (metered) | Wrong code: nothing paid. Re-checks the purse and daily count, reserves gift + fee ceiling, and **persists that before dispatch**. A paired app is also debited against its G1 grant. |
| 7 | newcomer | `GET /api/v1/sponsor/request/:hash` | read | `waiting` or `received`. |

- **Outcomes of step 6:** settled → `funded`. Failed or not dispatched → `failed`: the kit closes and both holds are released. Anything else → `unknown`: both holds stay until `POST /api/v1/sponsor/kits/:id/reconcile` finds a definitive outgoing record.
- **Cancelling:** `POST /api/v1/sponsor/kits/:id/cancel` withdraws an offer or candidate before dispatch.
- **Status:** `GET /api/v1/sponsor` (read) shows the policy, the rolling purse and the recent kits, without invoices.

The funding request travels in person rather than over the peer transport. That keeps this slice from adding a pre-payment network handler. A transport frame for it is a later option; the record and checks would not change.

## Caps (node-enforced; config may only lower them)

| Cap | Spec default | Where |
|---|---|---|
| Gift + fee per kit | ≤ 50,000 sats (gift default 20,000, fee ceiling 100) | `SponsorPolicy::new`, config load |
| Rolling 24 h purse, including fees and unresolved reservations | ≤ 100,000 sats | ledger `purse_used` |
| Approved kits per rolling 24 h | ≤ 2 | ledger `kits_today` |
| Open kits (offered, candidate, paying or unknown) | 1 | ledger `active` |
| Offer and dispatch window | 10 min | `SponsorOffer`, kit `expires_at` |

- **Clock rollback:** it cannot refresh the purse. A reservation dated after the node's current clock still counts.
- **Failed approvals:** a failed approval still used one of the day's kits.
- **Consumed introductions:** a consumed `intro_id` never pays twice.
- **The ledger:** `<data_dir>/sponsor/kits.json` (0600, atomic replace, versioned).

## Records

Both records are compact binary behind base64url and use strict Ed25519 (weak and non-canonical keys are refused). Domains: `bitsov-sponsor-offer/v1\0` and `bitsov-sponsor-request/v1\0`. The code is BLAKE3 over `bitsov-sponsor-code/v1\0`, the intro id, both keys and the invoice hash, reduced to six digits.

- `SponsorOffer`: network, `intro_id`, sponsor key, `gift_msat`, `expires_at`, signature.
- `FundingRequest`: network, `intro_id`, sponsor key, newcomer key, newcomer Lightning key, `amount_msat`, `payment_hash`, `expires_at`, bolt11, signature by the newcomer.

## Not in this slice

- On-chain reserve gifts (the 25,000-sat anchor reserve) and JIT/LSPS2 funding of the gift. The pilot pays an ordinary invoice.
- A newcomer-side messaging grant scoped to the inviter. The newcomer's existing G1 budget and first-contact OK apply.
- A transport frame for the request, and the anti-amplification challenge on a public door.
