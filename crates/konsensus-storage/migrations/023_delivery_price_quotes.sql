-- Recipient-issued offers survive a receiver restart; sender timestamps cannot renew them.
CREATE TABLE IF NOT EXISTS delivery_price_quotes (
    sender TEXT NOT NULL,
    scope TEXT NOT NULL,
    amount_msat BIGINT NOT NULL CHECK(amount_msat > 0),
    excluded_kinds TEXT NOT NULL DEFAULT ',',
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY(sender, scope, amount_msat, issued_at, excluded_kinds)
);
CREATE INDEX IF NOT EXISTS idx_delivery_price_quotes_expiry ON delivery_price_quotes(expires_at);
