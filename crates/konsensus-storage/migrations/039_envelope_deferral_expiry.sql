-- Existing deferrals have no bounded lifetime and expire on upgrade.
ALTER TABLE envelope_deferrals ADD COLUMN expires_at_ms BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_envelope_deferrals_expiry
    ON envelope_deferrals(expires_at_ms);
