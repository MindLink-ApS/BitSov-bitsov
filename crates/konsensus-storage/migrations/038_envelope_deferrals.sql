-- A deferred ciphertext never consumes its paid proof or nonce. A fresh
-- ciphertext may use that proof, while the old ID stays deferred on restart.
CREATE TABLE IF NOT EXISTS envelope_deferrals (
    message_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    payment_hash TEXT NOT NULL,
    recipient_type TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    amount_msat BIGINT NOT NULL CHECK (amount_msat >= 0)
);
CREATE INDEX IF NOT EXISTS idx_envelope_deferrals_payment
    ON envelope_deferrals(payment_hash);
CREATE INDEX IF NOT EXISTS idx_envelope_deferrals_repair
    ON envelope_deferrals(sender, recipient_type, recipient_id);
