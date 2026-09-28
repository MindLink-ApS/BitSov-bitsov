-- Durable acceptance evidence survives content retention for duplicate ACKs.
ALTER TABLE payment_receipts ADD COLUMN kind INTEGER;
ALTER TABLE payment_receipts ADD COLUMN recipient_type TEXT;
ALTER TABLE payment_receipts ADD COLUMN recipient_id TEXT;
ALTER TABLE payment_receipts ADD COLUMN preimage TEXT;
ALTER TABLE payment_receipts ADD COLUMN amount_msat BIGINT;
ALTER TABLE payment_receipts ADD COLUMN nonce TEXT;
ALTER TABLE payment_receipts ADD COLUMN references_json TEXT;
UPDATE payment_receipts SET (kind, recipient_type, recipient_id, preimage, amount_msat, nonce, references_json) = (SELECT m.kind, m.recipient_type, m.recipient_id, m.preimage, m.amount_msat, m.nonce, m.references_json FROM messages m WHERE m.id = payment_receipts.message_id AND m.sender = payment_receipts.sender AND m.payment_hash = payment_receipts.payment_hash) WHERE accepted = 1;
