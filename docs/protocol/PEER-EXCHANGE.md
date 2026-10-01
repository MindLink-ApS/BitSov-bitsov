# Paid peer exchange (#162, T17 option a)

Peer exchange serves one owner-curated response for one settled payment. It is
off by default. Whitelist admission and payment promotion grant no discovery.

```toml
[privacy]
peer_exchange = "paid" # default: "off"
shareable_peers = ["<64-hex node key>"] # default: []
share_peer_labels = [] # separate explicit consent, only for shareable peers
```

The configured IDs select admitted registry entries. The response excludes the
requester and the serving node and contains at most 50 records. Unlisted records
and labels never enter the quote snapshot. Configuration takes effect on node
restart; outstanding quotes remain redeemable with the same node identity.

1. A caller sends `PeerExchangeQuoteRequest` over authenticated Noise. Off,
   no shareable records, invalid/oversized labels, and quota refusals happen
   before invoicing. Quotes are limited to one attempt per peer per 60 seconds
   and 256 peer attempts per window, including refusals.
2. `PeerExchangeQuote` contains the requester and recipient node keys, exact
   amount, expiry, an opaque encrypted snapshot, a stateless BOLT11 invoice and
   the recipient's Ed25519 signature. It expires after 60 seconds; the invoice
   has at most 55 seconds, reserving backend RPC time. No persistent unpaid
   invoice fallback is used. The invoice description commits only to the
   ciphertext hash; it contains no contacts or social graph.
3. Before paying, the caller must verify the node signature over
   `quote.signable_bytes()`, both endpoint keys, expiry, invoice signature,
   amount and description (`bitsov:peer-exchange:903:<blake3(snapshot)>`).
   It must have enough time to settle and deliver before the quote expires and
   explicitly authorize the amount and its routing-fee budget. Never pay after
   a refusal or without a valid quote.
4. Send `PeerExchangePaidRequest { quote, envelope }`. The signed UKM is kind
   903 (the existing control tariff, rounded up to 1,000 msat and the configured
   admission floor), addressed to the quote issuer. Its payload is exactly the
   quote's 64 signature bytes; its proof must match that quote's invoice hash
   and exact amount. The normal payment gate checks signature, freshness,
   recipient-bound incoming settlement and durable nonce/payment-hash replay.
   Ordinary UKM Message frames cannot consume a peer-exchange payment.
5. The returned `PeerExchangeResponse` completes that paid act. The caller must
   correlate it to its outstanding paid request on that authenticated connection.
   Neither registry edits, switching off, later prices, nor quote cooldowns
   change a valid quote's response. No policy check follows payment acceptance.
   Invalid/expired quotes and mismatched or replayed proofs are refused.

The snapshot uses AES-GCM with a separate key derived from the existing node
identity; it remains opaque until paid redemption and survives a process restart.
Its wire encoding is hex, capped at 24 KiB decoded; invoices are capped at 8 KiB.
These caps keep quotes and the canonical paid requests within a Noise record.
Oversized snapshots are refused before invoicing.

This change ships the receiving wire service. The node does not automatically
buy discovery or expose a spending-authorized HTTP buyer workflow. The legacy
`POST /api/v1/peers/:node_id/discover` endpoint explicitly refuses instead of
claiming it requested discovery. Legacy unpaid `PeerExchangeRequest` receives
`peer_exchange_requires_quote_and_payment`. Quotes/refusals carry no admission
or promotion authority. A future buyer workflow must bind responses to its own
paid request; connection privilege is insufficient.

Settlement cannot be refunded. Invalid unsolicited payments may already have
settled externally; quote validation happens before the application accepts or
consumes a payment proof. Correct callers only pay a valid quote and submit the
matching act while it is live. Network or storage failures are not a refund
mechanism, and payment-proof replay remains fail-closed.
