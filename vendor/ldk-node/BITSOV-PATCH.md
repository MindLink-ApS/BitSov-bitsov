# BitSov stateless quote extension

Source: crates.io ldk-node 0.7.0, upstream https://github.com/lightningdevkit/ldk-node/tree/v0.7.0. Crates.io archive SHA-256: `d830ef2d6b00f089fb6e3ac845370ebf0f35f9d11ce81b3a097c1580d2dce358` (the pre-patch root lockfile checksum). Original licenses retained. Only production sources are vendored; standalone upstream integration test/bench targets and their unused dev dependencies are removed from the packaged Cargo manifest.

Local delta: expose Bolt11Payment::receive_stateless, delegating to ChannelManager::create_bolt11_invoice with payment_hash=None (which calls create_inbound_payment), without the payment-store insert or invoice log in receive_inner. On PaymentClaimed, insert an unknown stateless BOLT11 receipt as Succeeded before publishing PaymentReceived. Existing invoice APIs retain their behavior. No payment record is inserted on quote issuance or PaymentClaimable. LDK channel safety/HTLC persistence is unchanged.

Tests: konsensus-lightning/tests/stateless_quotes.rs checks an unstarted disposable regtest instance, including complete before/after disk snapshots. The shared mock and real loopback Noise regressions check no unpaid rows and settlement-only records.

Additional receive safety: reject fee skimming for unknown stateless BOLT11 payments, and retain Succeeded receipts on duplicate rejection. The upstream duplicate rejection changed Succeeded to Failed, which could reopen the single-use guard.

Production event regression (unstarted, fixed-seed regtest object with synthetic settlement events, no funds/network):

    cargo test --manifest-path vendor/ldk-node/Cargo.toml --locked --lib bitsov_stateless_tests

The vendor unit-test lock is separate; workspace dependencies remain pinned by the root Cargo.lock. The vendor manifest adds tempfile for these disposable storage tests. No upstream integration tests or real node daemons run.

## Fixed LSPS2 funding minimum

Before claiming a stored fixed-amount `Bolt11Jit` payment, `PaymentClaimable`
validates the aggregate net against the persisted gross minus the negotiated
maximum opening fee. An amount below that minimum, an excessive skim, or invalid
fixed-amount terms fails the whole payment backwards before the preimage is
released. Rejection preserves the original gross/fee terms for retries and
restart. Variable-amount JIT invoices retain their existing fee-only policy;
BitSov's pilot does not issue them.

The check runs after LDK has assembled MPP parts and before either automatic
claim or manual-claim notification. It never rejects an individual shard merely
because it is below the whole-payment minimum. Existing `Succeeded` duplicate
protection remains before this check because settled records contain net, not
the original gross.

    cargo test --manifest-path vendor/ldk-node/Cargo.toml --locked --lib bitsov_jit_tests

The regression invokes the production handler and uses LDK's existing in-memory
test channel managers to deliver multipart HTLCs. No node is started, no socket
is bound, and no real wallet or funds are used.

## Observed wallet sync health

`chain/sync_health.rs` records process-local success/failure observations in two
wallet slots. The first failure time survives retries; success clears only the
corresponding slot, and the oldest outstanding failure is exposed as
`NodeStatus.chain_sync_failure`. Bitcoind's combined listener synchronization and
polling use one slot; Esplora/Electrum record onchain and Lightning wallet results
separately. Remote error strings, credentials, URLs and paths are not retained.

The existing sync results are recorded and returned unchanged. Channel manager,
chain monitor, sweeper, broadcast and persistence behavior is unchanged. The
BitSov adapter exposes this only as the owner `/status` `chain_sync` diagnostic;
it does not change `money_ready`, payment dispatch or wallet freshness semantics.

    cargo test --offline --manifest-path vendor/ldk-node/Cargo.toml --locked --lib sync_health

The unit regression checks retry timestamps, independent wallet failures and
clearing on success. Workspace regressions cover owner-only status, unchanged
readiness/dispatch after failure, and failed Core synchronization with an isolated
process network guard permitting only the disposable RPC fixture.

## Closed-channel funding evidence

`Node::channel_funding_outpoint` exposes a monitor's funding outpoint even after
force-close. It is a local read, not proof of broadcast or confirmation. The
BitSov provider verifies removed-channel funding against the configured chain
source before counting the claim in either closing funds or its legacy total;
monitor persistence and recovery remain unchanged.

`LightningBalance::from_ldk_balance` selects the same on-close balance candidate
as LDK's `claimable_amount_satoshis`: the latest candidate when confirmed index
is zero, otherwise the confirmed candidate. Amount and transaction fee remain
paired. This keeps subtraction from the aggregate exact with pending splices.
The candidate remains an estimate, not proof of replacement funding confirmation.

    cargo test --offline --manifest-path vendor/ldk-node/Cargo.toml --lib bitsov_funding_tests

## Chain-sync retry resilience (2026-10-03)

Investigation of test #5 (Atlas run 2 item 13, and the repeat around 04:14 on
3 October), against ldk-node 0.7.0, esplora-client 0.12.3 and
lightning-transaction-sync 0.2.1:

- Ordinary Esplora errors and the existing inner wallet timeouts already return
  through the sync-status cleanup and retry on later background ticks. The HTTP
  client already has a 10-second per-request deadline; this patch retains it.
- A cancelled outer Esplora sync leaves `WalletSyncStatus::InProgress` behind.
  Subsequent subscribers wait without a deadline, blocking the shared sequential
  wallet/fee loop. An offline regression reproduces the stranded waiter before
  the fix. A drop guard now notifies subscribers and releases ownership; both
  owner work and subscriber waits have the existing wallet deadline (onchain
  20 seconds, Lightning 10 seconds). Subscriber timeout does not steal ownership
  from a still-running sync. Losing the last subscriber during notification is
  normal, not an assertion failure.
- **The production trigger remains unconfirmed.** Normal request errors/timeouts
  do not cancel the outer owner. No incident `ldk_node.log`, task dump or live
  transport evidence was available under the no-network constraint. This is a
  demonstrated cancellation fix and resilience hardening, not proof that beta's
  hours-long incident is resolved. Restart also clears process-local sync health.
- The absent journal error is explained by LDK's default filesystem logger.
  Background failures now additionally use the application's `log` facade
  (bridged by the node's tracing initialization), with only fixed operation and
  error categories plus a numeric delay:
  `chain_sync_failed operation=onchain|lightning|fees kind=sync_failed|timeout retry_in_secs=N`.
  No remote error text, URLs, credentials, transaction IDs or wallet data enters
  this message. Existing detailed file logging is unchanged.

Esplora/Electrum background wallet and fee workers now wait independently and
retry after 10, 20, 40, 80, 160, then at most 300 seconds, indefinitely. Every
failed background attempt emits one fixed error line, bounded to one per worker
per 10 seconds. Success restores the configured interval, measured from completion;
missed ticks never cause a catch-up burst. Fees retain their delayed first tick.
Shutdown interrupts retry sleep and lets an active attempt finish under its source
limits. These workers isolate asynchronous waits, not blocking persistence, mutex
operations or arbitrary panics. Bitcoin Core polling is unchanged.

`money_ready`, sync-health slots, successful-sync timestamp updates, settlement,
channel safety and custody semantics are unchanged. Failure never fabricates a
successful sync or resets another wallet's failure. The Esplora HTTP builder is
extracted only to permit injection of a never-resolving DNS implementation in the
request-timeout test; it preserves default retry behavior and custom headers.

Offline verification (no listeners, network connections or node starts):

    cargo test --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib
    cargo test --offline --locked -p konsensus-lightning --lib ldk::tests
    cargo clippy --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib --tests
    cargo clippy --offline --locked -p konsensus-lightning --lib -- -D warnings

The vendor suite includes all existing `bitsov_` settlement regressions and new
cancellation, source-error recovery, timeout, log, bounded-backoff, worker-isolation
and shutdown tests. Virtual time drives retry tests; the HTTP timeout test never
resolves an address. Verification passed 38 vendor tests and 49 LDK adapter tests. Downstream Clippy
passes with warnings denied. Vendor Clippy completes with 281 pre-existing
warnings (baseline: 282; no added warning categories); its strict `-D warnings`
run is not clean. No workspace tests that open sockets were run.

Doctrine: 1, 2, 5 and 6 hold: settlement/admission and custody remain unchanged;
Bitcoin remains chain evidence, never identity; diagnostics disclose no identifiers;
incident-resolution claims remain explicitly unverified. Lines 3 and 4 unchanged.
