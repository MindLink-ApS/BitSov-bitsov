-- Migration 007: daily fiat exchange-rate snapshots for tax reporting.
--
-- One row per (date, currency).  The background snapshot task writes at 00:00 UTC
-- using upsert semantics, so restarting the node on the same day is idempotent.
-- The tax-export handler reads this table to denominate Lightning payments in the
-- user's local currency on the transaction date.

CREATE TABLE IF NOT EXISTS fiat_rate_snapshots (
    date       TEXT NOT NULL,  -- ISO-8601 date, e.g. "2026-04-21"
    currency   TEXT NOT NULL,  -- ISO 4217 code, e.g. "USD"
    rate       REAL NOT NULL,  -- fiat units per 1 BTC (always positive)
    source     TEXT NOT NULL,  -- data provider name, e.g. "MempoolSpace"
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (date, currency)
);

CREATE INDEX IF NOT EXISTS idx_fiat_rate_snapshots_date
    ON fiat_rate_snapshots (date DESC);
