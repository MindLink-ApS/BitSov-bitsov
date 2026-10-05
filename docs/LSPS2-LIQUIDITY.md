# Bounded LSPS2 funding pilot (L1)

A fresh embedded-LDK node can request a funding invoice through a configured
LSP, receive a JIT channel and spend the resulting usable Lightning balance.
Funding buys no communication rights: the first message and every later act
still need their own settled, recipient-bound, single-use payment.

This is an owner-initiated pilot, disabled by default. LDK Node 0.7.0 already
uses `lightning-liquidity` 0.2.0 (Cargo.lock); this change connects its fixed-amount
LSPS2 `get_info` / `buy` / `receive_via_jit_channel` flow to BitSov's fee authority.
The client uses the same node, seed and wallet. An optional hub provider service is
described below; no dependency fork is introduced.

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
   After funding, use the normal capped compose/pay path (#99): quotes report
   `max_routing_fee_msat` and caps cover principal + routing fee. JIT funding
   fees remain a separate LSP skim.

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

## Hub provider pilot

A BitSov hub can serve the existing app client with the vendored LDK 0.7 LSPS2
service. This is **off by default** and mutually exclusive with
`lightning.liquidity.enabled` on the same node. Keep your chain settings and
add the following to the hub's LDK configuration; replace the token before use:

```toml
[lightning]
backend = "ldk"
network = "regtest" # use the same network as the apps and funding payer
listening_address = "0.0.0.0:9735"

[lightning.lsps2_service]
enabled = true
require_token = "<replace-with-private-per-hub-pilot-token>"
channel_opening_fee_ppm = 10000
min_channel_opening_fee_msat = 1000000
channel_over_provisioning_ppm = 1000000
min_channel_lifetime = 144
max_client_to_self_delay = 2016
min_payment_size_msat = 10000000
max_payment_size_msat = 1000000000
forwarding_fee_ppm = 500
forwarding_fee_base_msat = 1000
```

These are configurable pilot defaults, not a production pricing recommendation.
The token is a required nonempty shared pilot gate, compared as a string by LDK;
it is not user authentication. Protect the config file. Debug output redacts it.
Service advertising is always off. LDK's service role enables forwarding into
private channels even with `forward_to_private_channels = false`; no alias or
public channel is added. The service uses `client_trusts_lsp = false`, compatible
with our existing client waiting for the funding transaction before claiming.
Clients still explicitly trust this LSP for zero-conf channels.

On each app use the existing registry, pointing to this hub (no service block):

```toml
[lightning.liquidity]
enabled = true
selected_provider = "<hub-lowercase-compressed-Lightning-public-key>"

[[lightning.liquidity.providers]]
node_id = "<hub-lowercase-compressed-Lightning-public-key>"
address = "hub.example:9735"
token = "<same-private-per-hub-pilot-token>"
```

Startup requires opening ppm below 1,000,000, forwarding ppm at most 1,000,000,
and overprovisioning at most 10,000,000. The payment range must satisfy
`0 < min <= max <= 100000000000` msat, and the minimum opening fee must be below
the minimum payment. Lifetime must be positive; client delay is 1–65,535 blocks.
The forwarding base and ppm cannot both be zero. Unknown service fields fail
parsing. Omit the block or set `enabled = false` to leave the service inactive.

The opening fee is `max(min_fee_msat, ceil(gross_msat * opening_ppm / 1000000))`.
It is deducted only from the JIT **funding** payment. The example charges
1,000,000 msat from a 100,000,000-msat top-up and forwards 99,000,000 msat to the
app. Overprovisioning of 1,000,000 ppm adds another 99,000,000 msat of hub capital
to the channel, providing inbound capacity for later receipts, less reserves.
Hub on-chain funds, transaction fees and applicable anchor reserves are required;
app anchor reserves are not waived.

LDK initially creates service channels with zero forwarding fees. After
`ChannelReady`, BitSov applies the configured base and ppm with
`update_channel_config`, preserving other channel settings. It retries a failed
update before acknowledging that event and scans ready channels on restart.
LDK exposes no JIT-origin marker: while service mode is enabled, the scan targets
private outbound ready channels with **0 base / 0 ppm**. Normal BitSov manual
opens have a nonzero base and are untouched; externally configured free private
outbound channels also match this signature. Existing nonzero tariffs survive
restart unchanged; changes to these service tariff settings price new/unpriced
channels, not all existing channels.

Admission remains a separate, fresh stateless BOLT11 quote paid over the usable
channel. It receives its entire principal; it never uses the JIT intercept SCID
or pays an opening-fee skim. Forwarding fees are paid by the sender under the
unchanged ALL-IN allowance `min(max(5000, floor(principal * 1%)), 10000)` msat.
For a 2,001-msat admission, the example hub tariff is 1,001 msat, below the
5,000-msat allowance. Operators must price for their intended payment range;
an excessive tariff causes ordinary capped payments to fail, not wider caps.

The service is alpha upstream. Its channel opens still use LDK's legacy funding
path, **not the #190 priority/cap policy**. Insufficient hub funds, disconnection
or an upstream create-channel error can leave a top-up pending until timeout;
this change adds no retry for those upstream opening failures. Reconcile before
reissuing a top-up. No vendor code or admission policy is changed. A hub observes
both endpoints of payments routed between its own leaves, and is an availability
dependency; this pilot provides neither social-graph privacy nor automatic failover.

The real `regtest_e2e::three_node::lsps2_service::hub_jit_then_stateless_admission`
scenario runs in the [three-node paid suite](three-node-paid-e2e.md). It uses the
production hub constructor and client, asserts a disconnected-provider refusal,
then bounds negotiation/open/settlement to 60 seconds. It verifies opening-fee
accounting, overprovisioned inbound, tariff recovery after restart, and separate
stateless admission payments in both directions with exact principal and fees.
