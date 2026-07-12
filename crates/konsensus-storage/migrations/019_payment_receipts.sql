-- Accepted Lightning payment hashes for economic replay protection.
--
-- Nonces reject identical envelope replays. This table rejects a fresh envelope
-- that reuses the same settled Lightning payment proof with a different nonce.
CREATE TABLE IF NOT EXISTS payment_receipts (
    payment_hash TEXT PRIMARY KEY,
    message_id   TEXT NOT NULL,
    sender       TEXT NOT NULL,
    received_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_payment_receipts_sender
    ON payment_receipts(sender, received_at DESC);
