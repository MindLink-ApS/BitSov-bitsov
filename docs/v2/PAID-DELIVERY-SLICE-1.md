# Paid delivery: durable acceptance and retry (slice 1)

A transport write does not prove recipient acceptance. Durable API outgoing paid envelopes now enter the durable pending queue before dispatch and remain there until an authenticated recipient ACK matches that dispatched entry and the local sender identity. Compose's existing `delivered` field still means transport write success; this slice adds no HTTP fields or endpoints.

The recipient validates integrity, freshness, signature, pricing, recipient binding and Lightning settlement on every attempt. Ordinary message acceptance then commits the nonce, permanent payment receipt and message in one SQLite/PostgreSQL transaction. Any storage failure rolls back both single-use keys. The encrypted storage wrapper preserves this transaction while encrypting ciphertext at rest.

A matching payment receipt **and stored envelope** produces `AlreadyAccepted`. Immutable sender, kind, recipient, nonce, proof, amount and references must match. Ciphertext identity was verified by the gate; this also works with randomized encryption at rest. An isolated legacy receipt does not prove durable message storage. A duplicate receives `MessageAck { duplicate: true }` without another admission event, promotion, decrypt, storage write or application broadcast. A hash reused for another envelope is rejected. ACK follows durable acceptance even when decryption fails.

Retries older than four minutes refresh only the signed timestamp and signature, preserving message ID, nonce, ciphertext, payment proof and references. The refreshed wrapper is persisted before dispatch. The admission resend branch applies the same renewal to its in-memory ledger, durable journal and stored message within the existing fifteen-minute proof lifetime. It never pays again merely to refresh a wrapper.

After ten failed attempts, housekeeping marks a row `stalled`; it does not delete the row. Stalled deliveries retry on the sixty-second periodic scan, avoiding reconnect-driven retry storms. Retention cleanup protects pending envelopes, and session/ratchet resets retain them. An explicit owner message deletion still removes its queue entries.

Until payer-side promotion is available, ACKs and rejects may be processed from unprivileged peers only for matching dispatched outbox entries. They advance delivery notifications without routing-weight updates or privilege changes. Consuming an ACK is atomic, so repeated ACKs cannot repeatedly update weights. Unknown IDs, wrong peers, inbound messages and never-dispatched entries are ignored.

For old peers, the exact legacy rejection `replay detected: nonce already used` on an own dispatched envelope is treated as delivery confirmation and audited as `acked_legacy`, without a routing-weight update. This compatibility receipt has a weaker guarantee: the old recipient's non-atomic implementation could have burned keys before a storage failure. Only upgrading the recipient closes that historical window.

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
| Eleven failed attempts | Stalled row survives; reconnect skips it, periodic flush delivers; only ACK removes it |
| Legacy replay rejection | Own dispatched row consumed; `acked_legacy` audit; no trust weight |
| Forged/unprivileged ACK or reject | Wrong peer, unknown and unsent IDs ignored; matching receipts handled once without unprivileged weights |
| Old wire shape | Duplicate ACK decodes using the legacy enum shape; old ACK decodes with duplicate=false |
| Regtest LDK settlement | Feature-gated existing `ldk_payment_e2e` test adds post-gate rollback/retry and duplicate acceptance with one payment record, unchanged retry balance and readable plaintext |

Run `CARGO_TARGET_DIR=/tmp/bitsov-target-a13 cargo test --workspace --locked` and `cargo clippy --workspace --locked -- -D warnings`. The real-wallet matrix additionally uses `cargo test -p konsensus-lightning --locked --features ldk-integration-test --test ldk_payment_e2e ldk_two_node_channel_payment_and_gate_verification` and requires the existing Bitcoin Core/electrs test binaries. PostgreSQL parity is compiled by the workspace; runtime storage fault tests use SQLite.

Existing synthetic profile and content-response sends are outside the durable API outbox. Operation IDs, idempotent repeated POSTs, crash recovery between Lightning dispatch and envelope creation, new operation-status APIs and app changes belong to subsequent slices. They are not provided by this delivery retry mechanism.

Validation on this branch: locked workspace suite passed (3,313 tests, zero failures, two existing ignored); clippy with `-D warnings` passed. The feature-gated two-node LDK regtest test also passed against local Bitcoin Core and electrs.
