# Bounded LSPS2 funding pilot (L1)

A fresh embedded-LDK node can request a funding invoice through a configured
LSP, receive a JIT channel and spend the resulting usable Lightning balance.
Funding buys no communication rights: the first message and every later act
still need their own settled, recipient-bound, single-use payment.

This is an owner-initiated pilot, disabled by default. LDK Node 0.7.0 already
uses `lightning-liquidity` 0.2.0 (Cargo.lock); this change connects its fixed-amount
LSPS2 `get_info` / `buy` / `receive_via_jit_channel` flow to BitSov's fee authority.
No separate node, seed, wallet, provider service, or dependency fork is introduced.

## Operator configuration

Keep the existing network/Esplora settings. The protocol works on the configured
Bitcoin network (including signet and mainnet); the operator must select an LSP
actually serving that network. No public provider is silently chosen.

```toml
[lightning]
backend = "ldk"
network = "signet"
# Keep your existing esplora_url, listening_address, etc.

[lightning.liquidity]
enabled = true
selected_provider = "<lowercase compressed Lightning public key of LSP A>"

[[lightning.liquidity.providers]]
node_id = "<lowercase compressed Lightning public key of LSP A>"
address = "lsp-a.example:9735"
# token = "<provider-issued token, only if required>"

[[lightning.liquidity.providers]]
node_id = "<lowercase compressed Lightning public key of independent LSP B>"
address = "lsp-b.example:9735"
```

The placeholders are deliberately non-runnable. Validate provider keys and fees
out of band. Configured keys must be canonical and unique; there are at most 16.
Remove legacy `lsp_node_id`, `lsp_address`, `lsp_token` fields when migrating;
startup rejects these ambiguous old settings with a migration error.

LDK Node has **one active LSPS2 client**. The list is a local provider registry,
with explicit selection at startup. To switch, reconcile outstanding invoices
and HTLCs, stop the node, change `selected_provider`, restart using the same data
directory. Existing channels remain. This is provider portability, not live
per-invoice choice or automatic failover. Funded channels with independent peers
are needed for outage resilience; changing a name cannot move trapped liquidity.

## App/API contract

`/api/v1/status.api_capabilities` includes `lsps2_funding_quotes_v1` when the API
supports this contract. `GET /api/v1/payments/liquidity` (read scope) reports
`enabled`, configured provider keys, and the selection. Capability support does
not mean the LSP is online or that capacity is available. Tokens are never returned.

1. `POST /api/v1/payments/liquidity/quote` (receive scope):
   `{"gross_msat":100000000,"max_lsp_fee_msat":2000000}`.
   The ceiling is mandatory and below gross; gross is at most 1 BTC.
   LDK chooses an in-range offer under this ceiling, prepares an invoice and
   persists its `Bolt11Jit` purpose and maximum deduction. Negotiating does not
   transfer funds. The payable invoice remains private in a bounded in-memory
   store; one negotiation at a time, at most 16 outstanding previews, 120-second
   invoices. A cancelled request can finish negotiation but cannot publish.
2. Render the returned `quote_id`, `provider`, `gross_msat`, `max_fee_msat`,
   `min_net_msat`, `expires_at`. For the illustrative ceiling above, a 2,000,000
   msat fee on 100,000,000 msat gross leaves at least 98,000,000 msat. These are
   illustrative amounts, not an advertised provider offer. Display: "LSP fee
   deducted from incoming funds; payer routing fee and node reserve are separate."
3. After confirmation, `POST /api/v1/payments/liquidity/accept` (spend scope):
   `{"quote_id":"<id>","provider":"<displayed key>","max_lsp_fee_msat":2000000}`.
   The #80 cap checker rejects a lowered ceiling below the quoted fee or a changed
   provider before any fee debit. A quote belongs to its owner identity or exact
   paired client/epoch/fingerprint and is consumed once. The fee terms are immutable.
4. Only acceptance returns `{bolt11,payment_hash,amount_msat,description,expiry_secs,created_at}`.
   Give that invoice to a separate funding payer/sponsor. No spend is automatically
   initiated. Funding is real settlement, not credit, a free message, or admission.
5. Poll `GET /api/v1/payments/<hash>`. After settlement its `liquidity` field reports
   actual `gross_msat`, `lsp_fee_msat`, `net_received_msat`. The general amount is
   already net: do not subtract the fee twice. Before settlement this field is null.
   Check usable channels with `/payments/channels` and its node freshness headers;
   aggregate wallet balance includes on-chain funds and is not routing capacity.
6. Obtain the stranger's current quote and use the existing capped message send.
   The newly funded usable channel can route that separate payment. Existing
   principal caps, G1 message accounting and recipient binding remain in force.
   This pilot does not advertise an all-in route-fee cap on the later send; LDK's
   existing outgoing route policy is unchanged.

The vendored LDK receive handler enforces the fixed funding minimum **before
claiming any HTLC or releasing its preimage**. It reads the original gross and
negotiated maximum fee from the persisted `Bolt11Jit` record, requires aggregate
net received to be at least `gross - maximum fee`, and also enforces the skim
ceiling. An undersized payment is failed back to the payer. Failed attempts keep
the original amount/fee terms, including across restart. A successful receipt is
never downgraded by a duplicate attempt.

For multipart payments, LDK first assembles the sender's declared total. Individual
parts are not compared with the full funding minimum: a missing part remains
pending until completion or LDK's MPP timeout. The pre-claim guard checks the sum
of actual received parts, after any LSP deduction. A completed but undersized
multipart payment fails as a whole; no subset is claimed.

A quote without an invoice cannot be paid. LDK logs full JIT invoices at INFO;
LSPS2-enabled nodes therefore use a WARN-level LDK filesystem logger. No chat
text or contact names enter a funding memo. Neither pending nor funding-only
payments expose preimages through the generic payment list.

## Fee authority and recovery

Ordinary G1 grants cannot accept liquidity quotes. The owner must explicitly opt
in with `konsensus grant --op <id> --budget <sats> --for <duration>
--allow-liquidity-fees` (and optionally `--per-call`, `--recipient <LSP-key>=<sats>`).
The CLI never inherits this permission from an app proposal. Its confirmation
summary shows the authority. Control-socket terms carry `allow_liquidity_fees`;
old terms and stored grants default to false. Grant views expose this setting.

The LSP fee debits the **same** G1 total, per-call and per-recipient budget, under
the existing durable ledger mutex. It is not deducted twice from the wallet.
Dispatch revalidates the exact grant before publishing the invoice. Owner-key
calls have no G1 grant, but still require the mandatory per-operation fee cap.
No autonomous maintenance, on-chain spend or channel-opening grant is implied.

Publication creates possible future fee liability. The full ceiling stays counted
for the grant window on success, response loss, cancellation and unknown outcome.
A definite rejection before publication releases it. This conservative pilot does
not refund unused ceiling or expired invoices automatically: expiry cannot prove
an HTLC was not already in flight. Do not issue a replacement invoice on a timeout.
A new owner-approved grant is a new explicit allowance, not automatic renewal.

Unaccepted previews disappear on restart; previously published invoices may still
settle and their LDK fee ceilings remain. G1 reservations survive restart while
the grant is live. There is no invoice re-download after acceptance: save the
response/payment hash, or inspect payment status, and reconcile before repeating.

All `Bolt11Jit` records are permanently funding-only. The payment gate checks
purpose before settlement admission, including after an LDK store reload. Such
payments also produce no inbound admission stream proof. Funding preimages,
LSP tokens, quotes, and channels confer zero rights to send messages. No identity
or contact graph is written on-chain; no global provider graph is introduced.

## Trust and limits

- A no-channel wallet still needs funding and chain synchronization. LDK's default
  anchor emergency reserve (25,000 sats per applicable channel) is preserved.
  No `trusted_peers_no_reserve` waiver is enabled. An entirely empty wallet may
  reject the channel; this is not an unconditional minute-one onboarding claim.
- Selecting an LSPS2 peer opts into LDK's trusted zero-conf peer behavior. Until
  confirmation the LSP can withhold/double-spend funding. The LSP observes the
  client's Lightning key, connection address, timing, amounts and payment metadata.
  Use a verified compatible provider and small explicitly capped pilot exposure.
- LDK 0.7's wrapper does not expose the provider's trust-mode field or an operator
  mode selector. This implementation does not add a pre-funding-preimage release
  path or relax reserves. Qualify interoperability with each provider before use;
  a provider requiring an unsupported trust flow may stall/refuse. No production
  provider or mainnet qualification is claimed by mock tests.
- LSP disconnects, rejection, fee/amount mismatch, absent reserve, chain-sync failure
  or funding failure are failures/pending outcomes, not permission to widen caps,
  trust, or try another operator automatically. There is no live failover here.
- L1b work remains: concurrent multi-LSP selection upstream, full fee reconciliation,
  bounded outgoing route fees, real isolated network qualification and recovery drills.

Validation uses a mock LSP boundary (production preview store and HTTP/ledger),
LDK payment serialization for purpose/fee retention, and the actual payment gate.
The vendored LDK regression suite exercises its production receive handler with
disposable, unstarted objects and real in-memory multipart HTLC assembly:
`cargo test --manifest-path vendor/ldk-node/Cargo.toml --locked --lib bitsov_jit_tests`.
It covers below-minimum/exact-minimum funding, excessive skim, malformed fixed
terms, restart/retry, and multipart aggregates. These vendor tests are run
separately from the workspace because the vendor crate is excluded as a member.
The workspace suite does not require the optional downloaded-bitcoind integration
feature or any real funds. Mock success is not proof of channel-opening mainnet
compatibility or independent-provider availability.
