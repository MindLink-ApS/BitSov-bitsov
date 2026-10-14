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
`--lib` command. Full follow-up validation is recorded below when completed.
