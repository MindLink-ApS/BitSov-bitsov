# Isolate timing flakes #374 implementation plan

**Goal:** Make all tests named in #374 and its 22 October comment independent of scheduler delays, using mock/regtest resources only.

**Architecture:** Keep production decisions unchanged. Inject a per-instance Unix clock into introduction/sponsor time reads, defaulting to the same system clock. Keep synchronization and fixture changes in tests. Preserve the production restart quarantine and state locks.

**Spec:** GitHub issue MindLink-ApS/BitSov-bitsov#374 and the user's execution request.

## Constraints

- Unique owned temporary directories and OS-assigned listener ports.
- No live wallets, secrets, or external chain services.
- No longer sleeps to mask races; explicitly advance expiry time and await events.
- Explicitly report every production seam for security review.
- Revised by the user on 22 October: retain the first four full-workspace attempts (originally reported as clean; see evidence correction below) and run four more `cargo test --workspace --no-fail-fast` passes at default concurrency, two additional runs with eight `yes > /dev/null` workers; record each named test's pass count across all eight. This supersedes the original 30-run/10-loaded-run requirement to avoid blocking the lane.
- Run `cargo clippy --workspace --all-targets -- -D warnings`; delete target, commit, push HEAD to test/isolate-timing-flakes-374; no PR.

## Tasks

- [x] Capture baseline workspace results and inspect every named fixture's time, port, directory and lock ownership.
- [x] Sponsor expiry: share a controllable clock between each pair's introduction settings; replace two-second races and three-second sleeps with explicit time advancement. Preserve expiry refusal, durable terminal expiry and rollback assertions. Add the smallest real-clock-default seam in introduction settings and route sponsor time reads through it.
- [x] Sponsor dispatch: notify when the mock reaches the paused dispatch and select against premature request completion. Retain reservation, reconciliation and restart assertions.
- [x] Reconnect: initialize an already-running recipient quote gate explicitly in test-only code; remove setup sleep and elapsed-performance assertion. Keep actual transport, quote, admission, budget and delivery checks.
- [x] Offline fee barrier: derive expected identity from the fixture mnemonic without acquiring the directory's state lock twice; use regtest and private backup/state paths.
- [x] CLI refusal: retain private directories, use P2P port zero and an owned OS-assigned API listener reservation (config rejects equal API/P2P ports), and await child completion after closing password input. Keep no-write/no-secret assertions.
- [x] Onchain disconnect: await wallet entry, cancel the HTTP request, release dispatch, and await the persisted receipt condition without a five-second scheduler deadline. Keep real SQLite storage and exactly-once dispatch checks.
- [x] Run targeted checks, inspect the complete diff, then execute and archive the revised eight-run stress proof and Clippy output (seven clean suites, one earlier interrupted attempt; see evidence correction).
- [x] Write root-cause, production-seam and per-test count report.
- Finalization: remove target, commit and push the requested branch; final commit/push outcome is reported in the completion response.

## Review focus

Expiry at the exact boundary; clock rollback cannot revive terminal state; notifications cannot be lost; early request refusal must fail rather than hang; cancelled HTTP must still produce a durable receipt; readiness fixture must not weaken production quarantine; unique paths must include backup and lock state.

## Production seams (need security review)

- `crates/konsensus-api/src/handlers/introduction.rs`: `UnixClock`/`IntroductionSettings.clock` routes card issuance and verification through a per-instance callable; both default and `fixed()` construction use the original `now_unix` implementation, preserving Unix seconds and the pre-epoch error, with no request/config clock override.
- `crates/konsensus-api/src/handlers/sponsor.rs`: all four wall-time reads use that same clock; its default implementation is identical to the removed helper, and read placement, ledger locking, durable time floor, expiry comparisons, authorization and payment decisions are unchanged.
- `crates/konsensus-node/src/admission_quotes.rs`: `started_at_for_test` is gated by `#[cfg(test)]`, so it is absent from production and leaves the real constructor, restart quarantine and admission checks unchanged.
- `crates/konsensus-node/src/main.rs`: node startup supplies `clock: Default::default()`, selecting the original real system clock with no new runtime configuration.

## Self-review

Summary: reviewed the complete source diff, fixture ownership, expiry boundary/rollback assertions, stored notification permits, cancellation/durable-receipt barrier and quote quarantine. Production behavior remains unchanged with the default clock; test fixtures own their clock, paths and listeners.

Findings: no blocking or important findings. The pure seams above remain explicitly flagged for independent security review; this self-review is not that sign-off. The CLI and dispatch waits now rely on the proof runner's suite watchdog for genuine hangs.

Verdict: approve for the requested verification and branch push; no PR or merge.

## Verification evidence correction

The earlier report contains three completed clean suites, not four. The fourth raw log shows all 28 #374 tests passing, followed by `wire_invoice_limits` being terminated by SIGTERM; Cargo continues through the remaining targets and reports one failed target. No assertion failure is recorded. At initial inspection `results.json` contained only runs 1–3; by final aggregation it also recorded run 4 with Cargo exit 101 and all eight CPU workers alive before cleanup. Retain this interrupted attempt in the eight-run per-test counts, but do not describe it as a clean full-workspace pass. The source diff SHA-256 matches the earlier proof exactly: `c9d02d3d3eaaea8566c5798f97a8982bddf3ddb1b8c8fd2a5f40b69a520af063`.

Execute exactly four additional suites as requested (two loaded, two unloaded), without restarting the superseded 30-run proof or adding replacement suites. No source changes were needed during self-review.

Environment note: an initial additional attempt was stopped after sandbox-denied TCP/Unix socket binds (`Operation not permitted`). Its runner cleaned up Cargo and all eight load workers. The four additional proof runs were restarted with local-socket permissions; the invalid sandbox attempt is preserved separately and excluded from the eight-run comparison.

## Final verification

- Four additional full `cargo test --workspace --no-fail-fast` runs passed at default concurrency: 635.256s and 596.914s with eight CPU workers, then 515.908s and 508.977s without added load.
- All 28 named tests passed 8/8 across the archived attempts; the full-workspace tally is seven clean passes and one earlier SIGTERM-interrupted attempt, not eight clean suites.
- `cargo clippy --workspace --all-targets -- -D warnings` exited 0. Existing dependency warnings remain in the raw log (including vendored `electrum-client` and the `sqlx-postgres` future-incompatibility notice); no workspace lint failure occurred.
- No `yes` processes remained after the loaded runs. Source patch hashes match the earlier proof; self-review required no source edits.
- Individual counts, run status and raw-log hashes: `docs/testing/issue-374/verification.md` and `verification.json`; compressed logs are stored alongside them.
