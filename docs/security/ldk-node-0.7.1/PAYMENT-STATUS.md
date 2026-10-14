# Payment-status follow-up

Stacked on reviewed base `d23eb420` (`fix/ldk-node-071-backports`), on
`fix/ldk-node-late-failure`. This follow-up retains ldk-node 0.7.0 and the
previous backports and local patches.

## Late failure after success

Exact release commit:
[`c43be1a3f9a1a5b66d527596c1591acb962761d1`](https://github.com/lightningdevkit/ldk-node/commit/c43be1a3f9a1a5b66d527596c1591acb962761d1),
backport of mainline
[`1bb6aa38641c30687dbf6509abac5c3a06820e5c`](https://github.com/lightningdevkit/ldk-node/commit/1bb6aa38641c30687dbf6509abac5c3a06820e5c).
Verified the actual Git commit and full diff, and ancestry in `v0.7.1`
(peeled commit `edc8916e289d39a4135b6eda66978a9f765396bb`).

The two production hunks are applied verbatim: an early `PaymentFailed` guard
in `src/event.rs`, and `PaymentKind::is_lightning_payment` in
`src/payment/store.rs`. An already-successful outbound Lightning payment keeps
its entire receipt and produces no contradictory application failure event.
Pending, failed and missing records still follow the old failure/event path,
including replay when a prior event-queue persistence attempt failed.

The release commit message retains the mainline description of an atomic
check/update. The **release implementation** actually uses `get` followed by
an early return; it does not introduce an atomic store transition. This
backport matches that release implementation, without claiming a general
concurrent-writer monotonicity guarantee.

`security_071_payment_status.rs` drives the real `PaymentSent` then
`PaymentFailed` handlers for all five Lightning payment kinds. It checks the
entire receipt (including hash, preimage, amount, fee and timestamp), absent
and conflicting event hashes, suppression of application failure events, and
persistence/replay after reopening the store. A control covers pending-to-failed,
already-failed replay and missing-record event delivery.

Before the fix, the success regression failed because status changed from
`Succeeded` to `Failed`; the replay control passed. Both pass with the backport.
They run under the existing `ldk-node-security` CI job's unfiltered vendored
`--lib` command. Full follow-up validation is recorded below.

## Circular inbound HTLC using an outbound hash

Exact release commit:
[`ad36b93c3567dfd8609c3fe662f45363eb850ca2`](https://github.com/lightningdevkit/ldk-node/commit/ad36b93c3567dfd8609c3fe662f45363eb850ca2),
backport of mainline
[`c49b86dd50214e3b4cb759fe48794d0144b6f92f`](https://github.com/lightningdevkit/ldk-node/commit/c49b86dd50214e3b4cb759fe48794d0144b6f92f)
(part of PR #1157). Verified the actual Git commit/diff and ancestry in the
same `v0.7.1` tag.

The single production hunk is applied verbatim: keep `fail_htlc_backwards`,
then return without touching the outbound payment. Matching an outbound hash
can be a loop or an unrelated HTLC using that hash; it does not prove that
the outbound payment failed. A genuine outbound failure remains handled by
`PaymentFailed`.

`security_071_circular.rs` drives the real `PaymentClaimable` handler for
pending and succeeded outbound records. It checks complete record equality,
absence of preimage claiming/application events, and persisted records after
restart. Before the fix it failed on the pending record becoming `Failed`;
after the fix it passes for both statuses. It uses the same existing CI job.
The synthetic event has no corresponding live ChannelManager HTLC; failure
propagation on a funded network is not exercised.


## Application settlement boundary

`crates/konsensus-lightning/src/tests/ldk_late_failure.rs` restores a successful
receipt and a stale application `PaymentFailed` notification into a real SQLite
store/queue. It runs the production drainer and consumer, subscribes through
`outgoing_payment_updates`, then calls the real `get_payment_status` on the hint.
For failures both with and without a payment hash, the result remains `Settled`
with the same preimage, amount, fee and complete underlying receipt.

This is complementary coverage: the vendor regression tests raw LDK
`PaymentSent` → `PaymentFailed` handling and fails without the backport; the
application regression pins the contract that an application event is only a
wake-up hint and the persisted record is authoritative. The application test
alone does not detect removing the vendor guard, and does not run
`konsensus-api`'s `await_settlement` loop. No test-only production API was added.

## BitSov `crates/` audit

No independent production transition from `Succeeded`/`Settled` to `Failed`
was found. No BitSov production code was changed.

- `konsensus-lightning/src/ldk.rs`: `spawn_event_drainer` broadcasts only a hash;
  `outgoing_update_hash` supplies that hint; `get_payment_status` reads node
  records; `convert_status` maps `Succeeded` to `Settled` and `Failed` to
  `Failed`. It does not mutate the record in response to application failure
  notifications. This is why fixing the vendor store mutation is essential.
- `konsensus-lightning/src/mock.rs`: the direct `Failed` assignment in
  `cancel_hodl_invoice` is guarded by `Pending` while holding the payment lock.
- LND, CLN and LNbits adapters map backend-reported states; they do not locally
  overwrite a previously successful stored LDK payment. They rely on their
  external backends' state reporting, which was not audited here.
- `konsensus-api/src/handlers/messages/compose.rs` returns on `Settled` rather
  than continuing to process hints; `operations.rs` prefers a stored settled
  proof and refuses to release a payment when a failure contradicts recorded
  settlement. `handlers/sponsor.rs::record_outcome` fences funded state against
  later failure results. Budget resolution removes pending reservations once,
  so repeat resolution cannot turn a completed debit into a refund.
- Storage/node consumers were checked for payment-status writes, success/failure
  variants and string-state assignments. Outbox `failed_paid` is a delivery
  failure that retains payment liability; it is not an unpaid payment status.

A separate read-only review confirmed the production diff, regression scope and
absence of an additional local success-to-failure write. This is a targeted
source audit, not a whole-repository security certification.

## Preservation

[payment-status-preservation.json](payment-status-preservation.json) compares
all tracked vendor files with `d23eb4202ee85ec00509a9186ad02953fb07be5e`:
232 existing files are byte-identical; only `event.rs`, `payment/store.rs` and
the existing event-test module change. The two production files were rebuilt
from base bytes plus the two original release patches in a temporary directory
and compared byte-for-byte to this tree. The existing test file is identical
after removing its two new module declarations. Two new vendor test files are
added. No manifests, locks, package versions, persistence formats, CI workflow
or other vendor patches changed. Earlier archive-relative inventories remain
historical snapshots, explicitly identified in README.

## Observed validation

Environment: macOS arm64, Rust/Cargo 1.91.1. All Cargo runs use
`CARGO_BUILD_JOBS=2 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`, with
`CARGO_TARGET_DIR=/tmp/ldk-security-vendor-target` for the vendor and
`/tmp/ldk-security-target` for the workspace crate. Dependencies were already
cached; `--locked --offline` prevents resolution/network changes.

| Command/check | Result |
|---|---|
| Before fixes: `cargo test --locked --offline --manifest-path vendor/ldk-node/Cargo.toml --lib payment_status` | 2 expected vulnerability failures; 1 replay control passed |
| Late-failure-only focused run after its fix | 2 passed |
| `cargo test --locked --offline --manifest-path vendor/ldk-node/Cargo.toml --lib` | 163 passed, 0 failed, 0 ignored |
| `cargo test --locked --offline -p konsensus-lightning --no-fail-fast` in restricted sandbox | 257 passed, 135 failed, 2 ignored; localhost bind permission errors, including secondary Mockito server errors |
| Same full konsensus-lightning command with local socket binds permitted | 392 passed, 0 failed, 2 ignored; exit 0 |
| `git diff --check d23eb420` | Passed |
| Reapply exact upstream patches to base and compare; all-vendor hash inventory | Passed |

The two ignored tests are `close_current_channel_restart_and_send_only_home`
and `recover_latest_hub_state_with_and_without_stale_backup`, which require a
local bitcoind and real regtest channels. No integration feature or live funds
were used. The first application-test compilation required correcting owned
`Vec<u8>` arguments for `KVStoreSync::write`; the subsequent full runs include
the corrected test. No production code changed to address sandbox failures.

[payment-status-results.json](payment-status-results.json) preserves all run
counts, failed target/test names from the sandbox and red runs, and SHA-256
hashes/paths of local raw logs. Those temporary logs are not portable artifacts.
The full workspace and hosted CI were not rerun for this follow-up. The existing
CI job will execute all 163 vendor lib tests. Upstream tag signing identity,
funded-network behavior and general concurrent-writer races are outside this
validation.
