# Durable message operations (slice 2)

Single-recipient `POST /api/v1/messages/compose` accepts `operation_id`, a client-generated UUIDv4. Generate it before the first request and retain it through timeouts and restarts. Repeating the same request with that ID returns the original receipt or resends its stored envelope without paying again. Changing recipient, kind, plaintext, or references returns `409 operation_mismatch` before debit or payment.

If omitted, the node generates an ID and returns it. `deny_unknown_fields` remains enabled: unsupported fields fail during JSON extraction before spending. The API advertises `message_operations_v1`. Room requests remain compatible without an operation ID; explicit room IDs are refused before spending until per-member operations are implemented.

Responses add `operation_id`, `state`, `accepted`, `payment_hash`, and `retry_allowed`. `delivered` retains its transport-write meaning; only `accepted: true` / `state: acked` is a recipient acceptance receipt. `wait_ack_ms` defaults to 5000, is capped at 30000, and accepts 0 for immediate transport results. GET `/api/v1/messages/operations/{operation_id}` requires read scope and returns the durable receipt without spending.

| State | Same POST |
| --- | --- |
| prepared | Resume an operation proven not to have dispatched payment; normal authorization and caps apply. |
| paying / payment_unknown | Reconcile the recorded hash. If still unresolved, return `409 payment_unresolved`; no new payment. |
| released | A backend-positive Failed/Expired result permits one new authorized attempt. |
| paid / sent / rejected_retryable | Resend the same encrypted envelope and proof, respecting rejection backoff; no payment or ratchet advance. |
| acked | Return the acceptance receipt. |
| failed_paid | Return a terminal conflict with paid state; no payment. |

Migration 024 adds `outbox_operations` for SQLite/PostgreSQL and the encrypted wrapper. A prepared row precedes budget debit and Lightning calls. Recovery data holds an encrypted message draft, stable nonce/id, dispatch identity, and the original budget reservation; it contains no message plaintext. Invoice hashes are saved before payment dispatch, and returned keysend hashes before settlement polling. The paid envelope, pending queue row and paid operation transition commit in one database transaction. ACK/reject changes use slice 1's existing peer, sender and dispatch predicates in the same transaction as the operation change.

Recovery runs on startup and every 15 seconds. It queries recorded payments and restores delivery, never invokes a fresh payment. Per-operation locks serialize local POST/recovery work; version CAS and execution identities fence stale workers. A keysend that dispatched without leaving a recoverable hash remains `payment_unknown`; elapsed time or a missing backend record is not failure evidence. Known admission payments retain their existing journal and connection-generation rules. Generic recovery refuses legacy admission sentinels.

Existing pending deliveries receive `legacy:<message_id>:<recipient_id>` status IDs. Their original plaintext request binding is unavailable, so these are GET receipts rather than compose retry IDs. Existing legacy recipient acceptance and ACK behavior is unchanged.

Regression coverage includes persistent SQLite reopen, concurrent duplicate POSTs, prepared/dispatch/hash/settlement/message/queue/paid/send/ACK interruption boundaries, invoice response loss, unresolved keysend, positive failure release, invalid settled proof, rejection backoff, immediate ACK, encrypted recovery data, and paired-budget liability after journal failure. PostgreSQL parity is exercised by the repository's ignored PostgreSQL integration test and its dedicated CI workflow.
