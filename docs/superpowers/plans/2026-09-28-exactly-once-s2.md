# Exactly-once slice 2 implementation plan

Goal: persist a client operation before budget debit and payment, recover paid messages after restart, and make repeated compose requests idempotent.

Spec: Atlas `PAID-DELIVERY-EXACTLY-ONCE-DESIGN.md`, slice 2, authorized by the ticket. The repository-facing API and recovery contract is in `docs/v2/EXACTLY-ONCE-OPERATIONS.md`.

Architecture: additive outbox operation records in SQLite/Postgres and the encrypted wrapper; compare-and-swap claims plus per-operation serialization; encrypted envelope draft persisted before dispatch; payment hash journaled before settlement polling; recovery uses status lookups only. Existing pending delivery acceptance, rejection and ACK transactions advance the operation. No plaintext is persisted in recovery data.

Constraints: preserve #99 principal plus routing ceilings, #100 reservation/connection generation binding, and #103 acceptance and ACK predicates. Rooms keep existing behavior; an explicit operation id for room fanout is rejected until slice 4. Migration 024 is additive because slice 1 already occupies 020–023. An untrackable dispatch remains blocked, never assumed failed. No rebase or merge of the PR.

- [x] Storage: add operation record, atomic insert/CAS/read/recovery scan, backend parity, encrypted recovery data, and transactional ACK/reject linkage. Test reopened SQLite, concurrent claims, ACK monotonicity, rollback, wrapper encryption.
- [x] Compose: validate/generate UUIDv4, hash canonical request, persist before preflight/debit, serialize duplicates, persist draft before dispatch and hash before polling, resume without ratchet/payment, expose status and receipt fields. Test request compatibility, mismatch, duplicate concurrent POST and deferred/failed settlement.
- [x] Recovery: startup and periodic status reconciliation, paid envelope materialization and pending insertion; no automatic payment. Test interruption at prepare, claim, dispatch, hash, settlement, paid, send and ACK boundaries against durable SQLite and payment counters.
- [x] Verification: targeted tests then `cargo test --workspace --locked`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, fresh independent whole-change review and necessary fixes. Use `/tmp/bitsov-target-a27`; delete it after checks.
- Delivery (completion recorded in the ticket verdict): commit and push `feat/exactly-once-s2`; draft PR against main; write `DONE <pr> <sha>` to requested verdict file; do not merge.

Review focus: cancellation before hash persistence; concurrent POST versus startup recovery; immediate ACK races; grant replacement during recovery; old clients and room compose compatibility.

## Review and verification ledger

- Storage insert/CAS regression: missing methods RED, then durable reopen and concurrent claim GREEN.
- API duplicate POST regression: unknown operation_id rejected RED, then same message ID and one backend payment GREEN.
- Crash matrix covers encrypted draft/dispatch/hash/settlement/message/pending/paid/sent boundaries, cancellation and restart, ACK persistence, unknown keysend and invoice response loss.
- Independent review found four issues: post-dispatch journal failure releasing a paired debit; legacy admission replay through migration; pre-dispatch cancellation permanently blocked; failed-paid receipt reporting zero. Each received a failing regression and a passing fix. The paired-budget regression specifically observed spent accounting 0 before the fix and 1000 after it.
- Additional receipt regression: a failed transport write reported sent; now it remains paid, while immediate ACK wins over later send bookkeeping.
- Ruling: use migration 024 because base slice 1 already occupies 020–023; changing a shipped checksum would break upgrades.
- Ruling: reject explicitly operation-tagged room requests until slice 4; existing room requests remain unchanged and are explicitly untracked. This avoids claiming single-payment retry guarantees for a fanout that does not yet implement them.
- Main integration: PR #103 merged to a97ab0e; performed a normal merge of origin/main, no rebase.
- All-target Clippy exposed three pre-existing test-only lints (numeric grouping, Copy clone, explicit mutex guard scope); fixed those mechanically.
- The existing reconnect latency probe uses wait_ack_ms=0 because its sender stub does not consume ACKs; the production default remains 5000 ms.
- No deferred review findings. PostgreSQL runtime coverage remains in the repository's dedicated CI job; the PostgreSQL integration test was not run locally because it requires a disposable server.

Final verification on the normally merged tree:
- `CARGO_TARGET_DIR=/tmp/bitsov-target-a27 cargo test --workspace --locked`: exit 0; 3,453 passed, 0 failed, 3 pre-existing ignored tests, 109 result groups including doctests.
- `CARGO_TARGET_DIR=/tmp/bitsov-target-a27 cargo clippy --workspace --all-targets --locked -- -D warnings`: exit 0.
- `git diff --check`: clean.
- Detailed logs are outside the build cache: `/tmp/bitsov-s2-workspace-final.log`, `/tmp/bitsov-s2-clippy-final.log`, and `/tmp/bitsov-s2-review-green.log`.
