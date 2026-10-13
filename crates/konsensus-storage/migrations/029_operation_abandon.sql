-- SQLite cannot extend a CHECK constraint in place. Rebuild transactionally,
-- preserving opaque recovery bytes, receipt metadata and CAS versions exactly.
CREATE TABLE outbox_operations_abandon (
    operation_id TEXT NOT NULL PRIMARY KEY,
    recipient TEXT NOT NULL,
    kind BIGINT NOT NULL,
    request_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared','paying','paid','sent','acked','released','payment_unknown','rejected_retryable','failed_paid','abandoned')),
    payment_hash TEXT,
    admission_payment_hash TEXT,
    message_id TEXT,
    settled_msat BIGINT NOT NULL,
    readmission_msat BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    last_sent_at BIGINT,
    attempts BIGINT NOT NULL,
    last_error TEXT,
    version BIGINT NOT NULL,
    recovery BLOB NOT NULL,
    accounting_pending BOOLEAN NOT NULL DEFAULT TRUE,
    recovery_compacted BOOLEAN NOT NULL DEFAULT FALSE
);
INSERT INTO outbox_operations_abandon (operation_id, recipient, kind, request_hash, state, payment_hash, admission_payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery, accounting_pending, recovery_compacted)
SELECT operation_id, recipient, kind, request_hash, state, payment_hash, admission_payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery, accounting_pending, recovery_compacted FROM outbox_operations;
DROP TABLE outbox_operations;
ALTER TABLE outbox_operations_abandon RENAME TO outbox_operations;
CREATE INDEX outbox_operations_message ON outbox_operations(message_id, recipient);
CREATE INDEX outbox_operations_state ON outbox_operations(state);
CREATE INDEX outbox_operations_recovery ON outbox_operations(created_at)
WHERE accounting_pending = TRUE OR state IN ('paying', 'payment_unknown', 'paid', 'sent', 'rejected_retryable');
CREATE INDEX outbox_operations_retention ON outbox_operations(updated_at)
WHERE accounting_pending = FALSE AND recovery_compacted = FALSE AND state IN ('acked', 'failed_paid', 'released', 'abandoned');
