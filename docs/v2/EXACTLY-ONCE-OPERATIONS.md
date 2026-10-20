# Durable message operations (slice 2)

Single-recipient `POST /api/v1/messages/compose` accepts `operation_id`, a client-generated UUIDv4. Generate it before the first request and retain it through timeouts and restarts. Repeating the same request with that ID returns the original receipt or resends its stored envelope without paying again. Changing recipient, kind, plaintext, or references returns `409 operation_mismatch` before debit or payment, unless the ID is abandoned (always `409 operation_abandoned`).

If omitted, the node generates an ID and returns it. `deny_unknown_fields` remains enabled: unsupported fields fail during JSON extraction before spending. The API advertises `message_operations_v1`. Room requests remain compatible without an operation ID; explicit room IDs are refused before spending until per-member operations are implemented.

Responses add `operation_id`, `state`, `accepted`, `payment_hash`, and `retry_allowed`. `delivered` retains its transport-write meaning; only `accepted: true` / `state: acked` is a recipient acceptance receipt. `wait_ack_ms` defaults to 5000, is capped at 30000, and accepts 0 for immediate transport results. GET `/api/v1/messages/operations/{operation_id}` requires read scope and returns the durable receipt without spending.

| State | Same POST |
| --- | --- |
| abandoned | Always `409 operation_abandoned`, even for a different request. Use a new ID. |
| prepared | Resume an operation proven not to have dispatched payment; normal authorization and caps apply. |
| paying / payment_unknown | Reconcile the recorded hash. If still unresolved, return `409 payment_unresolved`; no new payment. |
| released | A backend-positive Failed/Expired result permits one new authorized attempt. |
| paid / sent / rejected_retryable | Resend the same encrypted envelope and proof, respecting rejection backoff; no payment or ratchet advance. |
| acked | Return the acceptance receipt. |
| failed_paid | Return a terminal conflict with paid state; no payment. |

Migration 024 adds `outbox_operations` for SQLite/PostgreSQL and the encrypted wrapper. A prepared row precedes budget debit and Lightning calls. Recovery data holds an encrypted message draft, stable nonce/id, dispatch identity, and the original budget reservation; it contains no message plaintext. Invoice hashes are saved before payment dispatch, and returned keysend hashes before settlement polling. The paid envelope, pending queue row and paid operation transition commit in one database transaction. ACK/reject changes use slice 1's existing peer, sender and dispatch predicates in the same transaction as the operation change.

Recovery runs on startup and every 15 seconds. It queries recorded payments and restores delivery, never invokes a fresh payment. Per-operation locks serialize local POST/recovery work; version CAS and execution identities fence stale workers. A keysend that dispatched without leaving a recoverable hash remains `payment_unknown`; elapsed time or a missing backend record is not failure evidence. Known admission payments retain their existing journal and connection-generation rules. Generic recovery refuses legacy admission sentinels.

A settled payment whose preimage is absent, malformed, or does not match its hash stays `payment_unknown`, with its settled amount retained. Recovery polls again for valid proof; a missing encrypted draft also stays unresolved until the draft is restored. Neither condition permits a fresh payment or becomes terminal `failed_paid`.

Accounting recovery in every operation state resolves the original paired caller's durable reservation from the recorded settlement before attempting delivery. This covers a crash between the paid commit and compose's in-process debit resolution. The recovery scan includes prepared/released rows and retained completed receipts only while accounting is pending, so a transition or ACK racing recovery cannot hide the liability; only `paid` operations are resent by this loop (slice 1 handles sent/transient-rejection retries). Zero-price messages resolve any recorded admission charge without requiring a message payment record. Resolution is idempotent and bound to the original grant/reservation; absent message or admission fee evidence keeps the liability reserved.

Offline paid operations skip transport sends and persist an exponential retry schedule: 15, 30, 60, 120, 240, then 300 seconds (capped). Restart preserves the deadline. Once a due check finds the peer connected, recovery resets the backoff and resends the stored envelope. Offline checks do not increment send attempts. Explicit client retries retain their existing behavior and rejection backoff; the independent pending-delivery flusher is unchanged.

Slice 3 follow-up (Fable #113 finding 1): generate the keysend preimage locally and persist its hash before dispatch. Slice 2 still receives keysend identity from the backend, so a crash after dispatch but before the hash is recorded leaves the operation `payment_unknown` indefinitely. Time passing is never evidence that repayment is safe.

Existing pending deliveries receive `legacy:<message_id>:<recipient_id>` status IDs. Their original plaintext request binding is unavailable, so these are GET receipts rather than compose retry IDs. Existing legacy recipient acceptance and ACK behavior is unchanged.

Regression coverage includes persistent SQLite reopen, concurrent duplicate POSTs, prepared/dispatch/hash/settlement/message/queue/paid/send/ACK interruption boundaries, invoice response loss, unresolved keysend, positive failure release, invalid settled proof, rejection backoff, immediate ACK, encrypted recovery data, and paired-budget liability after journal failure. PostgreSQL parity is exercised by the repository's ignored PostgreSQL integration test and its dedicated CI workflow.

## Abandoning an unused operation ID

Nodes advertising `message_operation_abandon_v1` in `/api/v1/status`
`api_capabilities` accept `POST /api/v1/messages/operations/{operation_id}/abandon`
with no request body. This requires the same `spend` scope and paired-caller
binding as compose. The ID must be a UUIDv4; legacy synthetic IDs are read-only.

The route takes the compose operation lock and returns the ordinary
`ComposeResponse` view:

- `200`, `state: abandoned`, `retry_allowed: false`: a permanent tombstone was
  inserted for a missing ID, or a `prepared`/`released` row was fenced. Such a
  row must have no dispatch, pending or paid admission, payment hash, settled
  message amount, or re-admission amount. The same unpaid-evidence check used
  by recovery also checks the admission journal (including retained attempts)
  and wallet; ambiguous or unreadable evidence cannot authorize abandonment.
  Missing-row tombstones have an empty request hash and no pending accounting.
- `409`: the current operation view, including amounts and payment hash. This
  includes a repeated abandon of an already abandoned ID. A live compose holds
  the lock until it finishes or is cancelled; abandon waits and then evaluates
  its durable result. Paying, unresolved and paid operations are never abandoned.

A GET returning `404`, `prepared`, or `released` alone cannot fence a late POST.
Before releasing an unpaid spending reservation, clients should obtain the
abandon result and classify its state and payment evidence. A `prepared` row can
already contain a paid first-contact admission. After a confirmed abandonment,
use a **new operation ID** for any new send. Repeating abandon after a lost reply
can confirm the tombstone through its `409` view. Transport failure is still an
unknown outcome. Clients must gate this protocol on the capability flag.

Recovery resolves proven-unpaid linked budget reservations to zero through the
durable accounting queue, including debits cancelled before attachment to the
operation row. The operation stays `abandoned` throughout recovery and restart.

Abandoning an operation also releases any pending call reservation keyed by its
ID, even if the call POST was cancelled before inserting the operation row.
A cleanup storage error leaves the tombstone intact and returns an error;
repeated abandon requests, periodic reconciliation and startup recovery retry
the release idempotently without reopening the operation.

Abandoned IDs survive restarts and payload compaction, cannot re-enter paying,
and are excluded from payment recovery. Pending budget or call reservations can
still bring them into a cleanup sweep without authorizing another payment.
Migration 029 adds the state constraint and retention index on both backends;
SQLite rebuilds the table transactionally while preserving all existing rows,
including encrypted recovery bytes and CAS versions. Older binaries cannot be
used to resume writes after this upgrade.

## Reservation and admission crash boundaries

The pairing ledger atomically records each reservation's operation ID, execution ID and purpose with the debit. This includes first contact and child re-admission debits. Recovery can therefore discover a reservation even if cancellation prevents its asynchronous attachment to the operation recovery blob. These references restore reconciliation identity, never dispatch authority.

Known accounting outcomes are saved as independent resolution intents before execution fields are cleared. Recovery retries each original reservation until the pairing ledger durably accepts the resolution, then clears that intent through the operation's version CAS. A crash after ledger persistence safely repeats an idempotent resolution. Unknown fees retain the full liability and its intent across new execution claims. Child re-admission and undispatched parent liabilities are reconciled separately.

Admission journals distinguish a known-undispatched operation-write handshake from a possibly dispatched payment. Legacy journals default to possibly dispatched. Failed writes and cancellation retain the former marker; cleanup fences the original SQL execution before restoring any earlier journal and removing the exact unpaid guard. Positive wallet non-dispatch is also checkpointed before asynchronous cleanup. No missing backend record or elapsed time permits repayment of a possibly dispatched attempt.

`readmission_msat` accumulates in the settlement transition, once while an admission attempt is pending. Drafting or retrying a message never overwrites that cumulative receipt.

## Bounded recovery and terminal retention (#113 follow-up)

Additive migration 025 adds `accounting_pending` and `recovery_compacted` to SQLite and PostgreSQL. Recovery selects the indexed union of accounting-pending rows and `paying`, `payment_unknown`, `paid`, `sent`, and `rejected_retryable` states. The accounting flag changes with the opaque recovery blob in the same version CAS, including the atomic paid-envelope commit. ACK/reject transitions preserve it. Reservations, admission intents and queued budget resolutions (including unknown fees) keep the flag set. Existing rows conservatively start pending and are classified by their first successful sweep; migration never parses potentially encrypted blobs. Do not run older writers after upgrading: they do not maintain the new metadata.

Each sweep snapshots the pairing ledger's unresolved operation links once and unions those operation IDs with the SQL result. This also discovers a late debit from a fenced execution after its row left the SQL index, including after terminal compaction. Attachment and resolution still use execution identity and the original reservation. Duplicate POST and ordinary reconciliation read durable row references without scanning grants or acquiring a pairing lock for resolved accounting; actual ledger resolutions retain their lock and persistence requirements. Sweep work is proportional to active recovery rows, unresolved links (plus traversing the current grant set), and a bounded maintenance batch, independent of resolved message history. SQLite pins the partial indexes so missing planner statistics cannot choose a terminal-history state scan.

After 30 days without a terminal/accounting update, at most 100 `acked`/`failed_paid`/`released`/`abandoned` rows per sweep have their bulky recovery draft, settlement and execution material compacted. Any unresolved accounting or discovered ledger link defers compaction. The version CAS protects concurrent changes. Operation IDs, request hashes, caller binding, state, message/payment IDs, amount/readmission/fee response fields and other scalar receipt metadata remain permanent tombstones; deleting those identities would let a duplicate POST pay again. This is payload retention, not a TTL on replay protection. Unknown-fee liabilities, retryable paid or unresolved operations and undelivered paid envelopes never qualify. Compacted released rows retain their existing retry semantics; abandoned IDs remain permanently refused.

Coordination with #103: compaction does not touch `payment_receipts`, its migration-022 immutable envelope bindings, nonces, pending deliveries or message content. Recipient duplicate ACK and proof-reuse decisions remain valid after sender recovery compaction and independent message-content retention. Paid-message retention continues to follow `PAID-DELIVERY-SLICE-1.md`.

Tests measure actual SQLite VM steps before/after 20,000 additional terminal rows, verify excluded encrypted blobs are never decrypted, exercise every state with/without accounting, upgrade a migration-024 database without checksum changes, and verify bounded encrypted retention, duplicate POST responses and #103 receipt binding after compaction/restart. Late unattached links are covered after fencing, a newer execution, and compaction; existing dispatch, settlement, budget-write failure and ACK crash-injection tests remain required.

## Channel opens (#331)

`POST /api/v1/payments/open-channel` accepts the same optional UUIDv4 `operation_id` (capability `channel_open_operations_v1`). It is recorded in `channel_open_operations` (migration 030) before dispatch; a retry with the same id and parameters returns the recorded channel (200, `replayed: true`) or its unresolved status (202 `pending`/`outcome_uncertain` with the peer's current channels) and never opens again. Different parameters return `409 operation_mismatch`; a proven non-dispatch frees the id. Omitting it keeps the previous behaviour. See [funding-fees.md](../ops/funding-fees.md#idempotent-opens-with-operation_id-331).
