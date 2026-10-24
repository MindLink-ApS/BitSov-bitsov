# Roadmap: doctrine follow-ups

Items that follow from decided doctrine but are not yet built. Each links to
its decision record.

## Receptor follow-ups (ADR-042, 28 Sep 2026)

### 1. Generalize the F1 quote path to any act type

Move the F1 stranger quote (LDK `create_inbound_payment`, signed metadata,
60 s expiry, one invoice per request ID, per-source and global rate caps) out of
the `KIND_CHAT` path into one receptor used by every act kind. Same review test
and fixed refusal for all. No new state before settlement.

### 2. x402 `exact`/`lnbtc` door behind a default-off flag

After item 1, serve the x402 challenge invoice through the receptor. The node is
its own facilitator and replay store. Mainnet/testnet identifiers only.
Spike: `X402-LNBTC-SPIKE` (O3). Flag stays off until reviewed.

### 3. Option B — keysend payer-push as an x402 upstream scheme

The payer sends a spontaneous payment with no invoice, so the node sends nothing
before settlement. This is the purest fit with the floor and needs no receptor.
Not built now because x402 has no keysend scheme (needs an upstream proposal),
the payer needs a route to the node without an invoice's hints, and binding the
payment to one request relies on custom TLV records rather than a signed
invoice.

### 4. Option C — BOLT12 / blinded-path receptor

Same rule as the receptor, with offers and blinded paths so the quote does not
reveal channel peers or short channel IDs. Addresses the route-hint topology
question in ADR-042. Not built now because LDK and wallet support is uneven and
x402 `lnbtc` is BOLT11-only.
