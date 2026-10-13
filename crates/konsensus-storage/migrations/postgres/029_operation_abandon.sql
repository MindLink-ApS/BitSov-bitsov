ALTER TABLE outbox_operations DROP CONSTRAINT outbox_operations_state_check;
ALTER TABLE outbox_operations ADD CONSTRAINT outbox_operations_state_check
CHECK (state IN ('prepared','paying','paid','sent','acked','released','payment_unknown','rejected_retryable','failed_paid','abandoned'));
DROP INDEX outbox_operations_retention;
CREATE INDEX outbox_operations_retention ON outbox_operations(updated_at)
WHERE accounting_pending = FALSE AND recovery_compacted = FALSE AND state IN ('acked', 'failed_paid', 'released', 'abandoned');
