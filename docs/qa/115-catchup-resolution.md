# PR #115 catch-up resolution

Normal merge of `origin/main` at `c71dad3` (#113, exactly-once slice 2)
into `fix/pay-not-dispatched` at `9fb6ba4`. No rebase or force push.

## Conflict hunk notes

All three textual conflict hunks were independent EOF test additions in
`crates/konsensus-api/tests/budget_grant_tests.rs`. The resolved file keeps
main's tests together, followed by #115's direct-payment contract tests.

1. **Fee refusal versus operation journal/recovery tests** (original conflict
   begins after `invoice_fee_refusal_releases_message_reservation`): retained
   #115's `direct_send_fee_refusal_is_not_dispatched_and_releases_budget` and
   #113's operation insert/journal failure tests, `HoldPaidSend`, and
   `recovery_resolves_paid_commit_reservation_once_and_keeps_unknown_fees`.
   Kept complete function boundaries rather than interleaving their bodies.
2. **Unknown direct payment versus free-message/cancellation recovery**:
   retained `direct_send_unknown_keeps_502_and_full_reservation`,
   `recovery_free_message_resolves_recorded_admission_but_keeps_unknown_fee`,
   `ReadyPauseBeforeDebit`, and
   `cancel_before_reservation_attachment_does_not_leak_grant`.
   Unknown direct sends still return 502 and retain principal plus fee;
   operation recovery retains its cancellation and admission accounting checks.
3. **On-chain/channel refusal versus durable accounting intents**: retained
   `direct_send_onchain_and_channel_refusals_preserve_not_dispatched` and
   `accounting_intents_survive_prepared_released_and_ledger_write_failure`.
   Thus typed on-chain/channel refusal coverage and #113's independent,
   retryable budget-resolution intents both remain.

## Semantic integration

- Retained #115's generic `PaymentNotDispatched -> ApiError::NotDispatched`
  conversion and explicit on-chain mapping, including routing-fee wrappers.
- Retained #113's operation/outbox implementation, migrations, and accounting
  unchanged. Also retained its valid mock payment hash derived from the
  preimage, alongside #115's wallet refusal modes for on-chain/channel tests.
- `/payments/pay` and `/payments/keysend` use `MeteredSpend::debit`, not
  `debit_operation`: they create no compose/outbox operation. Their known
  non-dispatch path calls `resolve_payment` before returning the typed error.
  `Debit::released` resolves zero through the pairing ledger, consuming the
  reservation and any reservation link. Repeating resolution is a no-op once
  the recipient/reservation is gone. Unknown outcomes remain reserved.
- Strengthened the direct fee-refusal regression with real SQLite storage:
  both routes, owner/metered callers, and zero/nonzero fee caps. After refusal,
  restart plus repeated operation reconciliation must leave usage zero and
  pending reservations/operation links empty. An immediate successful retry
  must spend principal once, and repeated restart/reconciliation must preserve
  that charge rather than releasing it again. Direct calls must create no
  outbox operation.

## Review and regression evidence

- Read-only independent integration review found no critical or important
  blockers; the workspace checks remain the execution gate.
- Targeted direct-send tests passed (3 tests).
- `cargo test --workspace --locked`: 3,471 passed, 0 failed, 3 ignored
  across 110 suites. The first sandboxed run encountered four local socket
  permission failures; the full authorized rerun passed, including all 121
  budget-grant tests.
- `cargo clippy --workspace --locked -- -D warnings`: passed. Both Cargo
  commands emit the existing `sqlx-postgres 0.8.0` future-compatibility notice.
- Tests used Rust 1.91.1, two build jobs, no incremental compilation, and
  disabled dev/test debug symbols, with `CARGO_TARGET_DIR=/tmp/bitsov-target-a31`.
- Mutation check: temporarily removing `debit.released(recipient)` from the
  provider nondispatch branch made the strengthened refusal test fail with
  1,000 msat retained instead of zero. The original production code was
  restored before workspace validation.

Validation results and the final pushed merge SHA are recorded in the requested
`pm/_verdicts/115-catchup.txt` handoff.
