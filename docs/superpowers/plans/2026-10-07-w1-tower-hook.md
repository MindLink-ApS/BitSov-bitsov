# W1 tower hook implementation plan

**Goal:** Implement only W1 from the supplied watchtower design contract.
**Spec:** `../pa-w1-contract.md`, §§ F3–F9, 3.3–3.4, 7.
**Architecture:** An optional TowerPersister delegates all monitor persistence to the existing Persister. A configured TowerClient is a durable local candidate queue (no transport). Pending unsigned ladders and a per-channel wallet destination survive restarts; signed candidates remain available for W2.

## Constraints and review focus

- Offline only; no regtest/e2e, daemons, RPC, or 127.0.0.1:3141. Never push.
- Preserve disabled persistence calls, bytes, statuses, completed updates and archive behavior.
- Persist pending data before monitor acknowledgement; retain signed data before removing pending data. Never acknowledge tower storage errors as Completed.
- Retry secret-not-known on subsequent updates and startup; deduplicate replay; reject corrupt storage.
- Three fee tiers max(253, one-block estimate), 4x, 16x; fee at most half the protected output; exclude dust outputs.
- W2 crypto, networking, payment, configuration and acknowledgement/pruning are out of scope. Same-SHA Fable/Grok approval remains a separate money-path merge gate.

## Tasks

- [x] Add offline functional regressions using LDK's in-memory harness: initial/later commitments, script-valid signed ladder, below dust, restart mid-queue, disabled delegate parity, storage failure and fee caps. Observe failure before implementing.
- [x] Implement `tower_hook.rs`: serializable JusticeCandidate and pending channel record, durable local TowerClient, generic TowerPersister with optional fee/destination providers. Run hook tests and commit.
- [x] Wire explicit Builder opt-in, ChainMonitor type, module export; default remains off. Document every delta in BITSOV-PATCH.md. Check workspace and vendor clippy offline; commit.
- [x] Review final diff and report exact validation commands, results, commits and outstanding W2/review work.


## Execution record

Implemented inline in the supplied clone on `feat/w1-tower-hook`. No network,
regtest/e2e, daemon, RPC or push commands were executed.

- Core hook / initial seven offline tests: `f112e41`.
- Builder opt-in, crash reconciliation, exact fee adapter and ten-test coverage:
  `2992eab`.
- A separate read-only code review found the tower-ahead crash orphan and padded
  fee-estimate mismatch. Both were reproduced by failing regressions and fixed.
  Corrupt-record validation was also strengthened because accepting a malformed
  signed row could falsely represent protection. No review findings remain
  deferred. External Fable/Grok same-SHA approval has not been obtained.
- Pending records store unsigned ladders rather than complete commitments (F9),
  plus each entry's observation update ID. Failed tower writes stop before the
  wrapped monitor advances. Entries newer than a restored monitor are discarded
  as unacknowledged; signed candidates are retained. A full monitor AND manager
  reload regression makes/revokes a different transaction after this boundary.
- The hook uses the cached one-block estimate after exactly undoing LDK's
  protection margin, with the existing 8000 sat/kWU fallback if absent. No new
  fee queries or changes to LDK's own estimate. Overflowing ladder tiers are
  omitted instead of wrapping through LDK's internal u32 conversion.

Final verification, after code changes:

```text
cargo test --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib tower_hook
PASS: 10 passed, 0 failed (121 unrelated tests filtered out).

cargo check --offline --locked --workspace --all-targets
PASS: exit 0. Existing sqlx-postgres 0.8.0 future-incompatibility notice.

cargo clippy --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --all-targets
PASS: exit 0, 281 existing vendor warnings. No diagnostics in W1 hook or fee accessor.

cargo clippy --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --all-targets -- -D warnings
FAIL: existing vendor lint debt (strict warning policy), not a clean clippy gate.

git diff --check
PASS.
```

Test-first evidence: the initial delegating scaffold failed both candidate
checks. Added regressions subsequently reproduced fee overflow, monitor advance
after failed tower writes, tower-ahead startup entries, inflated one-block fees
and malformed signed records. All now pass in the ten-test suite. The crash and
malformed-record tests were additionally run by their exact test-name filters
while debugging; failures were resolved before the final suite.

Remaining scope: W2 crypto, network client, payment, configuration, ack/pruning;
W3/W4; real infrastructure testing; external money-path review. The hook covers
to_local only, cannot backfill states observed while disabled, and retains the
contract's stop-and-retry behavior on superseded-splice signing errors.
