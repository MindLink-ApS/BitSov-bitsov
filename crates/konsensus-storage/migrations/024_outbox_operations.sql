-- Durable sender identity; recovery contains only encrypted message material and budget references.
CREATE TABLE outbox_operations (
    operation_id TEXT NOT NULL PRIMARY KEY,
    recipient TEXT NOT NULL,
    kind BIGINT NOT NULL,
    request_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared','paying','paid','sent','acked','released','payment_unknown','rejected_retryable','failed_paid')),
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
    recovery BLOB NOT NULL
);
CREATE INDEX outbox_operations_message ON outbox_operations(message_id, recipient);
CREATE INDEX outbox_operations_state ON outbox_operations(state);

-- Existing paid deliveries retain a queryable synthetic receipt. They cannot
-- bind a new compose request because their original plaintext hash is unknown.
INSERT INTO outbox_operations (operation_id, recipient, kind, request_hash, state, payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery)
SELECT 'legacy:' || p.message_id || ':' || p.recipient_id, p.recipient_id, m.kind, '',
       CASE WHEN p.state = 'failed_paid' THEN 'failed_paid' WHEN p.dispatched = 1 THEN 'sent' ELSE 'paid' END,
       m.payment_hash, m.id, m.amount_msat, 0, CAST(strftime('%s', 'now') AS BIGINT) * 1000, CAST(strftime('%s', 'now') AS BIGINT) * 1000,
       CASE WHEN p.dispatched = 1 THEN CAST(strftime('%s', 'now') AS BIGINT) * 1000 ELSE NULL END, p.attempts, p.rejection_reason, 0, X''
FROM pending_deliveries p JOIN messages m ON m.id = p.message_id;
