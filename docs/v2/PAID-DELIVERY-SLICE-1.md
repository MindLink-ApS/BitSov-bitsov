# Paid delivery: durable acceptance and retry (slice 1)

A transport write does not prove recipient acceptance. Durable API outgoing paid message envelopes enter the durable pending queue before dispatch and remain there until an authenticated recipient ACK matches that dispatched entry and the local sender identity. Compose's existing `delivered` field still means transport write success; this slice adds no HTTP fields or endpoints.

The recipient validates integrity, freshness, signature, pricing, recipient binding and Lightning settlement on every attempt. Ordinary message acceptance then commits the nonce, permanent payment receipt and message in one SQLite/PostgreSQL transaction. Any storage failure rolls back both single-use keys. The encrypted storage wrapper preserves this transaction while encrypting ciphertext at rest.

A matching payment receipt **and stored envelope** produces `AlreadyAccepted`. Immutable sender, kind, recipient, nonce, proof, amount and references must match. Ciphertext identity was verified by the gate; this also works with randomized encryption at rest. A legacy receipt without a message can be healed only when its stored ID and sender match the fully gate-validated envelope. Migration 021 marks receipts backed by existing messages as accepted; new acceptance and legacy repair set that permanent marker in the same transaction. The marker survives deletion and retention, preventing an accepted message from being resurrected. Receipts already orphaned before upgrade cannot distinguish old storage failures from historical deletion; only that pre-upgrade ambiguity remains. A duplicate receives `MessageAck { duplicate: true }` without another admission event, promotion, decrypt, storage write or application broadcast. A hash reused for another envelope is rejected. ACK follows durable acceptance even when decryption fails.

Retries older than four minutes refresh only the signed timestamp and signature, preserving message ID, nonce, ciphertext, payment proof and references. The refreshed wrapper is persisted before dispatch. Admission proofs never enter the generic outbox or outgoing message history. Their resend branch renews only the ledger and journal, and uses #100’s `send_admission_proof` on the captured, marked connection generation. The generic flusher removes legacy admission sentinel rows without sending them. Expired or consumed proof handling stays with #100; refreshing a wrapper never itself pays another invoice.

After ten failed attempts, housekeeping marks a row `stalled`; it does not delete the row. Stalled deliveries retry on the sixty-second periodic scan, avoiding reconnect-driven retry storms. Retention cleanup protects pending envelopes, and session/ratchet resets retain them. An explicit owner message deletion still removes its queue entries.

ACKs and rejects may be processed from unprivileged peers only for matching dispatched outbox entries, including the paid payee replies enabled by #100. Their event stamps retain strict connection privilege. Before any storage lookup, unpaid confirmations share a budget of 32 frames per peer and 128 frames globally per one-second window; identity churn cannot exceed the global budget or grow its map beyond 128 entries. Reconnects do not reset these handler-owned limits. They advance delivery notifications without routing-weight updates or privilege changes. Consuming an ACK is atomic, so repeated ACKs cannot repeatedly update weights. Unknown IDs, wrong peers, inbound messages and never-dispatched entries are ignored.

For old peers, the exact legacy rejection `replay detected: nonce already used` on an own dispatched envelope is treated as delivery confirmation and audited as `acked_legacy`, without a routing-weight update. This compatibility receipt has a weaker guarantee: the old recipient's non-atomic implementation could have burned keys before a storage failure. Only upgrading the recipient closes that historical window.

Definitive gate rejections (`PaymentProofReused`, `InsufficientPayment`, `RecipientMismatch`, `InvalidSignature`) atomically retain the envelope in terminal `failed_paid` state, persist its reason and emit a `failed_paid` delivery status. No reconnect, periodic flush or housekeeping pass retries it. Other rejects count once per dispatch and retry after 60, 120, 240 seconds, increasing up to one hour; the deadline survives restart. Unknown reasons remain transient for compatibility. A delayed genuine ACK can still resolve a transient rejection.

Migration 020 is preserved byte-for-byte for checksum compatibility. Migration 021 resets its optimistic `dispatched=1` backfill: an old offline queue row has no ACK authority until a fresh dispatch intent is recorded. It also adds rejection state metadata and receipt acceptance markers. A test opens a real database migrated through the original 020, upgrades it, and verifies both dispatch authority and permanent receipt consumption.

Wire compatibility adds only the optional, default-false `duplicate` field to the existing `MessageAck` variant. False is omitted. There is no new Frame variant or Capability.

## Validation matrix

| Slice-1 case | Coverage |
| --- | --- |
| Storage failure after full gate, retry succeeds | Production Noise receive-loop test with a SQLite failure trigger; both replay keys remain usable |
| Recipient exits before transaction commit | Storage subprocess exits without destructors after replay-key inserts; restart accepts once |
| Lost ACK, resend | Production receive loop reconnects, returns duplicate ACK, no second promotion, N2 admission or application event; one readable message |
| Same hash, different ID | Storage binding tests and full-gate Noise receive-loop rejection |
| Queue six minutes | Flusher renews only timestamp/signature; verifies signature and preserves paid identity |
| Admission resend fourteen minutes | Actual compose recovery branch with a durable journal; renewal persists, passes full recipient gate, zero new money calls |
| Admission flap after sixteen minutes | Real two-node Noise, shared settlement ledger, compose and concurrent generic flusher; old legacy row is removed, only one fresh admission accepted on replacement connection, payer mark set |
| Definitive / transient paid rejects | All four terminal reasons stop resends; transient reasons increment attempts once per dispatch and persist increasing deadlines; encrypted terminal row survives restart and housekeeping |
| Legacy receipt limbo | Matching receipt heals after full gate; invalid signature, wrong ID/sender and transaction failures cannot heal; accepted deletion/retention cannot resurrect |
| Unpaid confirmation flood | Forged ACK/Reject IDs consume the pre-storage budget; peer churn stays globally bounded; window recovery handles legitimate ACK |
| Migration compatibility | Original migration checksums preserved, offline rows lose assumed dispatch authority, existing accepted receipts remain consumed after deletion |
| Eleven failed attempts | Stalled row survives; reconnect skips it, periodic flush delivers; only ACK removes it |
| Legacy replay rejection | Own dispatched row consumed; `acked_legacy` audit; no trust weight |
| Forged/unprivileged ACK or reject | Wrong peer, unknown and unsent IDs ignored; matching receipts handled once without unprivileged weights |
| Old wire shape | Duplicate ACK decodes using the legacy enum shape; old ACK decodes with duplicate=false |
| Regtest LDK settlement | Feature-gated existing `ldk_payment_e2e` test adds post-gate rollback/retry and duplicate acceptance with one payment record, unchanged retry balance and readable plaintext |

Run `CARGO_TARGET_DIR=/tmp/bitsov-target-a13 cargo test --workspace --locked` and `cargo clippy --workspace --locked -- -D warnings`. The real-wallet matrix additionally uses `cargo test -p konsensus-lightning --locked --features ldk-integration-test --test ldk_payment_e2e ldk_two_node_channel_payment_and_gate_verification` and requires the existing Bitcoin Core/electrs test binaries. PostgreSQL parity is compiled by the workspace; runtime storage fault tests use SQLite.

Existing synthetic profile and content-response sends are outside the durable API outbox. Operation IDs, idempotent repeated POSTs, crash recovery between Lightning dispatch and envelope creation, new operation-status APIs and app changes belong to subsequent slices. They are not provided by this delivery retry mechanism.

Rework validation results are recorded in `pm/_verdicts/exactly-once-s1-fix.txt` in the local PM library. The real-wallet regtest is optional and is not part of the required workspace command.
