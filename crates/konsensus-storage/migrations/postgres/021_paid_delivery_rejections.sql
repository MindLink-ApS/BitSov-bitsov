-- Keep migration 020 byte-identical for databases that already applied it.
-- Its dispatched=1 backfill cannot distinguish offline rows. Re-establish
-- dispatch authority on the next send; paid identity makes replay safe.
UPDATE pending_deliveries SET dispatched = 0;
ALTER TABLE pending_deliveries ADD COLUMN IF NOT EXISTS retry_after_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pending_deliveries ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

-- An acceptance tombstone survives message deletion/retention. Only orphaned
-- legacy receipts may heal; receipts already backed by messages are spent.
ALTER TABLE payment_receipts ADD COLUMN IF NOT EXISTS accepted INTEGER NOT NULL DEFAULT 0;
UPDATE payment_receipts SET accepted = 1 WHERE EXISTS (
    SELECT 1 FROM messages WHERE messages.id = payment_receipts.message_id
        AND messages.sender = payment_receipts.sender
        AND messages.payment_hash = payment_receipts.payment_hash
);
