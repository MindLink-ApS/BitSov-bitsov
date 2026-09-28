-- Keep old opaque (possibly encrypted) recovery blobs conservative until one
-- successful accounting sweep. Never inspect/decrypt application data in SQL.
ALTER TABLE outbox_operations ADD COLUMN accounting_pending BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE outbox_operations ADD COLUMN recovery_compacted BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX outbox_operations_recovery ON outbox_operations(created_at)
WHERE accounting_pending = TRUE OR state IN ('paying', 'payment_unknown', 'paid', 'sent', 'rejected_retryable');
CREATE INDEX outbox_operations_retention ON outbox_operations(updated_at)
WHERE accounting_pending = FALSE AND recovery_compacted = FALSE AND state IN ('acked', 'failed_paid');
