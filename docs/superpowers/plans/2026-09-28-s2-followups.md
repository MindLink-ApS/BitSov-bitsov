# Slice 2 recovery follow-ups

Goal/spec: Atlas ticket and Fable review of #113; implement findings 3, 2, and 4 from a42754c on fix/s2-followups. Finding 1 (local keysend preimage) remains slice 3. Draft PR initially targets feat/exactly-once-s2, to be retargeted to main after #113 merges. Never push the base branch or merge.

Implementation: retain payment_unknown for incomplete settled proof/draft; re-query unusable cached proof; resolve the original pairing reservation from paid recovery evidence before delivery/backoff; persist a 15-second exponential offline delay capped at 300 seconds. Add serde defaults, no migration. Unknown fees retain liability.

- [x] Add regressions in outbox_operations.rs: absent/malformed/wrong preimage, cached incomplete settlement, missing drafts with/without envelope_ready, offline backoff/cap/restart/reconnect.
- [x] Add paid-commit cancellation regression in budget_grant_tests.rs: reopen SQLite and pairing ledger; known fee resolves once, unknown fee stays reserved even while offline.
- [x] Observe failures against a42754c: proof/draft became failed_paid; cached proof never refreshed; offline recovery sent; paid reservation stayed 1500 rather than 1100 msat.
- [x] Implement recovery changes in handlers/messages/operations.rs and document the contract and slice 3 deferral in docs/v2/EXACTLY-ONCE-OPERATIONS.md.
- [x] Run cargo test --workspace --locked and cargo clippy --workspace --all-targets --locked -- -D warnings with CARGO_TARGET_DIR=/tmp/bitsov-target-a27. Review the complete change.
- Delivery (completion recorded in the ticket verdict): commit, push fix/s2-followups, create draft PR, remove /tmp/bitsov-target-a27, write DONE <pr> <sha> to the ticket verdict. Do not merge.

Review focus: missing evidence never authorizes repayment; old recovery blobs deserialize; original reservation/grant binding and unknown fees; offline retry bookkeeping stays bounded across restart; connected resend preserves ACK/rejection behavior.

Verification notes: first broad sandbox run hit four existing local socket permission failures (expiry_api_start_purges_before_binding_listener, expiry_api_start_refuses_failed_cleanup_before_binding, owner_socket_first_contact_checks_tuple_and_consumes_once, owner_socket_gift_checks_every_field_and_refuses_replay). Full verification uses local socket access. Initial paid-crash test setup needed an explicit 500 msat fee ceiling to reach the paid commit; the corrected test then reproduced the intended 1500-versus-1100 accounting failure on the base implementation.

Independent review found and regressions reproduced three edge cases: cached settled/no-proof evidence with a zero receipt must survive a contradictory Failed lookup; send/ACK/reject can precede the debit tail; free messages lack a Lightning settlement record but may hold admission budget. Fixes preserve matching cached settled amounts, include post-payment receipts in both storage recovery scans (accounting only, no terminal resend), and resolve free-message admission evidence with known fees. This keeps schema compatibility at the cost of scanning retained completed receipts; resolution is idempotent and does not write already-resolved pairing entries.

Independent review recheck: clean after the three additional regressions/fixes. Clippy completed with exit 0 (`cargo clippy --workspace --all-targets --locked -- -D warnings`); only the existing sqlx-postgres future-compatibility notice remains. Final `cargo test --workspace --locked` completed with exit 0: 3458 passed, 0 failed, 3 ignored across 109 result groups. The three ignored tests are pre-existing (including PostgreSQL runtime coverage). `git diff --check` is clean. Logs are `/tmp/bitsov-s2-followups-workspace-final.log` and `/tmp/bitsov-s2-followups-clippy.log`, outside the disposable build cache.

Delivery redirected by Atlas after draft #114 was created: Fable changes were cherry-picked to feat/exactly-once-s2 as 35210e6. The direct #113 fix continues in 2026-09-28-s2-review-fixes.md. fix/s2-followups is left unused; the original DONE verdict is historical and superseded by exactly-once-s2-fix.txt.
