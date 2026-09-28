# Slice 2 direct PR review fixes

Atlas redirect supersedes the earlier delivery instructions: apply Fable commit 757912a to feat/exactly-once-s2 (cherry-picked as 35210e6), fix the four findings from pm/_verdicts/113-verdict.txt, and normally push #113. Leave fix/s2-followups unused and close draft #114; do not delete branches or merge. Final verdict overwrites pm/_verdicts/exactly-once-s2-fix.txt with FIXED <sha> and per-finding notes.

- [x] Reproduce supplied probes: cancellation before debit attachment leaks 1000 msat; admission operation write failure blocks an unpaid retry; message retry erases 1000 msat of readmission receipt.
- [x] Persist operation/execution/purpose linkage in the same atomic pairing ledger write as every compose, first-contact and re-admission reservation. Recover an unattached reservation from this link; do not hold a synchronous pairing lock over SQL awaits.
- [x] Persist independent resolution intents before clearing execution state; retry ledger failures and clear intents only after durable resolution. Include prepared/released and delivered/rejected operations. Unknown fees retain liability. Recover original parent and admission child separately.
- [x] Add known-undispatched admission handshake markers (legacy defaults to unknown), restore previous journals, and fence late cancelled SQL writes before clearing exact unpaid guards. Preserve positive non-dispatch before asynchronous cleanup.
- [x] Keep cumulative readmission amounts in admission settlement transitions, not per-attempt drafts.
- [x] Regressions: established/first-contact pre-attachment cancellation; existing paid/sent/acked/rejected budget recovery; prepared/released/acked intent snapshots with ledger write failure; failed admission writes and committed-write/new-operation restart snapshots; cumulative readmission after refused message invoice.
- [x] Complete workspace tests, all-target Clippy and independent re-review.
- Commit and normal push to #113 follow this verified tree; completion is recorded in the external verdict.
- Delivery completion is recorded in the requested verdict after the push, PR #114 closure and /tmp/bitsov-target-a27 cleanup.

Review refinements: queue known-zero child resolutions with admission_not_dispatched; invalidate the matching execution even when a cancelled admission_started SQL update has not become visible. Existing static scope coverage was extended to recognize the new debit_operation helper; its original check otherwise flagged the renamed debit path. Build/test logs are under /tmp/bitsov-s2-redirect-*.log outside the disposable target directory.

Final verification: `CARGO_TARGET_DIR=/tmp/bitsov-target-a27 cargo test --workspace --locked` exited 0: 3462 passed, 0 failed, 3 existing ignored tests across 110 test/doc-test groups. `CARGO_TARGET_DIR=/tmp/bitsov-target-a27 cargo clippy --workspace --all-targets --locked -- -D warnings` exited 0. PostgreSQL runtime, real Esplora and DBH1 tests remain ignored; no live PostgreSQL runtime claim is made. SQLx retains its existing future-compatibility notice. Independent final review found no blocking findings. Logs: `/tmp/bitsov-s2-redirect-workspace-final.log` and `/tmp/bitsov-s2-redirect-clippy.log`.
