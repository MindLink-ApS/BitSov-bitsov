-- Path-3 on-chain session debit ledger (anti-replay + balance tracking).
-- recorded_at is supplied by the application so the same SQL runs on SQLite and Postgres.
CREATE TABLE IF NOT EXISTS blvm_session_debits (
    payment_request_id TEXT NOT NULL,
    tx_hash            TEXT NOT NULL,
    session_debit_seq  INTEGER NOT NULL,
    debit_msat         INTEGER NOT NULL,
    recorded_at        TEXT NOT NULL,
    PRIMARY KEY (tx_hash, session_debit_seq)
);

CREATE INDEX IF NOT EXISTS idx_blvm_session_debits_session
    ON blvm_session_debits (payment_request_id, tx_hash);
