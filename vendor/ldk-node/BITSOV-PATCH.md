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
