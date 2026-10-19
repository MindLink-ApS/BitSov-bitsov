# LDK security update implementation plan

> Execute inline with the executing-plans and verification-before-completion skills.

Goal: integrate the verified October LDK security fixes while retaining every local vendor patch.
Spec: the user's three-step security task, base `9fdb14806971879661bdb07bd72b414d33974bae`.

Constraints: no real nodes or networks during tests; no push, tag or PR. Commit logical steps.

- [x] Verify release tags, registry checksums, actual release-branch fix commits and reachable application paths.
- [x] Inventory both vendor trees against their original crates.io archives and record all vendor history.
- [x] Rebase `vendor/lightning` to 0.2.7 via three-way merge against the 0.2.2 archive. Preserve all local additions; resolve the formatting/background-event conflict by retaining the upstream handler.
- [x] Upgrade `lightning-liquidity` and `lightning-transaction-sync` to 0.2.7 in both root and standalone node locks, with required types 0.3.5 and compatible background-processor 0.2.3. Keep ldk-node 0.7.0, whose API is compatible with the release-branch fixes.
- [x] Verify the final local delta against the new archive; verify the node source tree is byte-identical to base. Record exact hashes and review commands.
- [x] Run upstream rollback regression, local Lightning regressions and vendored node tests, then cargo build and workspace tests or node crate suites with OS network denial. Record failures, skips and pass counts.
- [x] Obtain independent final review, resolve material findings, commit validation evidence and report SHAs/uncertainties.

Review focus: acknowledged rollback vs legitimate retransmission; LSPS2 inbound amount vs onion amount; already-queued LSPS2 state; Electrum registration/reorg selection; retention of close-consent, monitor-event visibility and diagnostic TLV 49.

## Execution record

- `99f5017`: verified source/tag/registry evidence and complete before-inventory.
- `0368086`: vendor rebase, dependency floors/locks and after-inventory.
- Validation: build passes; Lightning 1220 passed/9 ignored; node vendor 154 passed;
  LSPS2 final 18 passed; two regression guards independently demonstrated red/green.
- Workspace: 4188 passed, 386 network-denied failures, 7 ignored; every failed test
  is recorded in `docs/security/ldk-0.2.7/workspace-results.json`. Not a green run.
- Independent source and focused-regression reviews found no critical/important issue.
- No real node/network was accessed; no push, tag or PR. Old queued JIT amounts
  and unadopted node 0.7.1 hardening remain documented limitations.
