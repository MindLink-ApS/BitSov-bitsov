# Newcomer Starter Implementation Plan

> Execute inline using executing-plans and test-driven-development; review the completed branch before pushing.

**Goal:** Deliver the owner-requested signet starter API and worker, including C3 and F4.
**Architecture:** Keep hub admission and open operations from PR-1. Persist newcomer operations in migration 031's existing table. Capture initial push in LDK channel persistence so verification remains sound after spending. A refusal can create a bounded successor; uncertainty can only replay its original operation.
**Tech Stack:** Rust, Tokio, Axum, SQLite/PostgreSQL, embedded LDK.
**Spec:** docs/design/N-M7A-STARTER-REQUEST.md and docs/ops/starter-hub.md.

## Global constraints

- Signet only in production; regtest for tests. Refuse mainnet, testnet, non-LDK, and allow_mainnet.
- No new SQL migrations; stop and report if required.
- POST requires receive scope and a verified pairing; GET requires read.
- Local channel evidence determines readiness. Never reopen on an uncertain outcome.
- Push the named branch, without opening a PR.

## Review focus

- Crash/restart between refusal and successor insertion: transaction and durable lineage tests.
- Delayed/spoofed status: configured peer and request binding, monotonic state tests.
- Spending before worker reconciliation: durable negotiated push, readiness and restart tests.
- Changed hub config and concurrent POST: durable binding and one-live-request tests.
- Malformed amounts and identifiers: checked bounds, no readiness on missing evidence.

### Task 1: Durable channel evidence

- [x] Add a failing LDK test: open with 10,000-sat push, spend, serialize/reload, retain initial push.
- [x] Add optional initial-push field in LDK persisted channel and detail mappings. Old records remain unknown.
- [x] Extend core ChannelInfo and map optional direction, privacy, readiness, reserve and push fields.
- [x] Run focused vendor and core tests.

### Task 2: Durable newcomer operations

- [x] Add failing SQLite concurrency and bounded-retry tests.
- [x] Implement newcomer storage operations in both SQL backends and encrypted wrapper using table 031.
- [x] Serialize create/retry transitions under the existing singleton lock. Retain refused operations; link successors using original_request_id.
- [x] Limit refusal successors to three, respecting hub retry time; timeouts retain their UUID.
- [x] Test storage and core verification boundaries.

### Task 3: API and worker integration

- [x] Add API authorization/idempotency tests and in-process PR-1 hub integration tests.
- [x] Add default-off config, runtime checks, routes, status capability and worker wiring.
- [x] Reconcile local evidence every 15 seconds, including after transmission exhaustion; send with persisted capped backoff.
- [x] Test retries, no duplicate opens, terminal refusals, adoption, late funding and push-before-spend evidence.
- [x] Document configuration, bounded retries, status and rollback.
- [x] Run cargo test for touched crates and cargo clippy --workspace -- -D warnings; review the implementation.

## Implementation decisions and review fixes

- C3 uses durable initial-push evidence, permitting verification after an ordinary
  spend; the previous current-balance heuristic was racy. Unknown old records
  remain unverified. LDK's normal readiness checks govern spending.
- F4 bounds each mesh connection to eight sends, rearming the same operation on
  reconnect or explicit POST. Three refusal successors remain the persistent
  limit, with 10/20/40-minute minimum backoff. This reconciles the user's bounded
  retry requirement with the design's late-funding/reconnect recovery.
- Independent review identified permanent exhaustion, refused-original adoption,
  and missing precondition error metadata. Fixes retain the operation ID on
  rearm, atomically adopt the exact authenticated original, and return reason and
  retry_allowed. Regression coverage is in newcomer, storage, and API tests.

- A transport regression test caught the Noise capability representation mismatch;
  the API now recognizes `Custom("starter_hub_v1")` as advertised by PR-1.

## Validation

- `cargo test -p konsensus-core -p konsensus-storage -p konsensus-lightning -p konsensus-api -p konsensus-node`: all 3,729 unit/integration tests passed (six ignored). Local socket tests required execution outside the filesystem sandbox. The final doctest stage encountered E0460 after an overlapping Cargo run replaced the shared LDK artifact; rerunning the same package selection with `--doc` in isolation passed.
- Final starter API tests: five passed; final newcomer/PR-1 integration tests: four passed, including retry bounds, no duplicate open, original-grant adoption and push verification.
- Vendored Lightning library: 1,221 passed, nine ignored; vendored ldk-node library: 169 passed. The strengthened push-before-ready/spend/restart regression also passed separately.
- `cargo clippy --workspace -- -D warnings`: passed. `git diff --check`: passed. No SQL migration changes.

Delivery: commit and push `HEAD:refs/heads/feat/n-m7a-newcomer-pr2`; do not open a PR.
