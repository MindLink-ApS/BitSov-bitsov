-- Daily fiat exchange-rate snapshots. Version 7 was never applied on Postgres;
-- existing databases pick this up on the next startup. CREATE is idempotent
-- so a hand-built table keeps its rows.

CREATE TABLE IF NOT EXISTS fiat_rate_snapshots (
    date       TEXT NOT NULL,
    currency   TEXT NOT NULL,
    rate       DOUBLE PRECISION NOT NULL,
    source     TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    PRIMARY KEY (date, currency)
);

ALTER TABLE fiat_rate_snapshots ADD COLUMN IF NOT EXISTS date TEXT;
ALTER TABLE fiat_rate_snapshots ADD COLUMN IF NOT EXISTS currency TEXT;
ALTER TABLE fiat_rate_snapshots ADD COLUMN IF NOT EXISTS rate DOUBLE PRECISION;
ALTER TABLE fiat_rate_snapshots ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE fiat_rate_snapshots ADD COLUMN IF NOT EXISTS created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');

-- float4 cannot decode into the f64 the storage API uses. Widening is lossless.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'fiat_rate_snapshots'
          AND column_name = 'rate'
          AND udt_name = 'float4'
    ) THEN
        ALTER TABLE fiat_rate_snapshots
            ALTER COLUMN rate TYPE DOUBLE PRECISION;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_fiat_rate_snapshots_date
    ON fiat_rate_snapshots (date DESC);
