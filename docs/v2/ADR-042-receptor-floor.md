# ADR-042: The receptor — a stateless one-act quote inside the floor

**Status:** Proposed (owner-approved direction; whitepaper text pending merge)
**Date:** 2026-09-28
**Decided by:** Rasmus (owner), option A, 28 Sep 2026
**Scope:** Whitepaper doctrine floor, F1 first-contact quotes, future per-act
doors (including x402 `exact`/`lnbtc`)

## Problem

The whitepaper floor and its Line 2 conflict when the payment rail needs a
recipient invoice.

- Floor: with no settled payment there is no "packet, service, stored state,
  topology disclosure, prekey, invoice, peer record, or carrier beyond that
  floor."
- Line 2: "You do not need permission to offer payment to it."

Lightning BOLT11 requires the recipient to issue an invoice before anyone can
pay. Read literally, a stranger cannot pay, so Line 2 fails. F1 already
resolved this for first-contact chat with a narrow, chat-only exception
(`F1-CAPPED-FIRST-CONTACT.md`, "Stranger payment preparation and the
whitepaper floor"). The x402 spike (O3) found the same wall for any agent or
service act: anonymous unpaid invoice generation exceeds the floor unless the
exception is widened explicitly.

Owner principle: pay-per-request is the rule for every act, whether the
requester is a human peer or an AI model.

## Options

| Option | Description | Doctrine check | Cost / risk | Result |
|---|---|---|---|---|
| A | Name F1's stateless one-act quote the **receptor** and make it part of the floor for every act, same for human and agent requesters. | Keeps "no service without settlement". The receptor is payment preparation, not service. Resolves Line 2 for invoice rails. | Low. F1 code path exists (LDK `create_inbound_payment`). Needs generalizing beyond chat. Minting cost and invoice topology remain (open questions). | **Approved** |
| B | Keysend: the payer pushes a spontaneous payment with no invoice. Propose as an x402 upstream scheme. | Purest fit: the node sends nothing before settlement. | Keysend is not in x402 today; needs an upstream spec. Payer must already know a route to the node. Weaker proof-of-payment binding than a signed invoice. | Roadmap |
| C | BOLT12 offers / blinded paths as a variant of A. | Same as A, and reduces topology disclosure. | Implementation support in LDK and wallets is still uneven. Not in x402 `lnbtc`. | Roadmap |
| D | Paid bootstrap or session: pay once, get a session that can then quote. | Fails Line 3: creates a durable admission object not re-proven per act. | Adds a second paid act and recovery rules. | Rejected |
| E | External invoicing gateway issues invoices for the node. | Moves the wall off the node; custodial or trusted third party. | Violates the Charter's sovereignty scope. | Rejected |

## Decision

Adopt option A. The floor contains exactly one outbound act before
settlement: the **receptor**, a quote for one act.

### Review test

A quote is floor, not service, if and only if it is:

1. **Stateless until settlement** — no peer, contact, session, quote, nonce or
   pending-invoice record, including in Lightning payment storage. Only
   bounded volatile rate counters and request-ID digests.
2. **Node-signed** — the node's key binds the price, expiry and request.
3. **Short-lived** — expiry of 60 seconds or less.
4. **One per request** — one request ID yields at most one invoice.
5. **Rate-capped** — per source and globally (F1: 1 per source IP per 10 s,
   16 global per 10 s).
6. **Discloses only that act's price** — no price table, prekeys, peer data,
   session, other invoice or application response. Otherwise a fixed refusal.
7. **Identical for human and agent requesters** — the same rule, limits and
   refusal for a Noise peer and an HTTP/x402 client.

Any quote that fails one item is service and needs settlement first.

## Consequences

- Whitepaper: the floor paragraph names the receptor
  (`WHITEPAPER-AMENDMENT-receptor.md`). "No service without settlement" is
  unchanged.
- F1: its chat-only exception becomes the first instance of the receptor rule.
  No behavior change.
- x402 `exact`/`lnbtc` door: unblocked at the doctrine level, provided its
  challenge invoice passes the review test. It stays behind a default-off flag.
- Backends that cannot mint stateless invoices (LND, LNbits today) keep failing
  closed with `stateless_quote_unsupported`.

## Open questions

1. **Route-hint topology.** BOLT11 route hints for unannounced channels disclose
   channel peers and short channel IDs to an unpaid requester. The floor lists
   "topology disclosure". Does a receptor invoice need to omit hints, limit them
   to one LSP hint, or wait for option C?
2. **DoS / CPU cost of minting.** Each receptor costs a signature and an HMAC
   derivation. The F1 rate caps bound this for chat. Are the same caps right for
   all acts and for an HTTP door that may see more traffic?
3. **Supported networks.** x402 `lnbtc` specifies only mainnet and testnet.
   Regtest/signet receptors are test-only and must not be advertised as x402
   networks.
4. **Identical retries under x402.** x402 issues a fresh invoice per challenge,
   even for an identical request. The receptor's "one per request" needs a
   request ID that includes a fresh nonce, with rate caps bounding retries.
