-- Pending outbound path-3 debits (reserved at compose, committed on peer ACK).
-- recorded_at is supplied by the application so the same SQL runs on SQLite and Postgres.
CREATE TABLE IF NOT EXISTS blvm_pending_outbound_debits (
    message_id          TEXT NOT NULL PRIMARY KEY,
    recipient_node_id   TEXT NOT NULL,
    payment_request_id  TEXT NOT NULL,
    tx_hash             TEXT NOT NULL,
    session_debit_seq   INTEGER NOT NULL,
    debit_msat          INTEGER NOT NULL,
    recorded_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_blvm_pending_outbound_recipient
    ON blvm_pending_outbound_debits (recipient_node_id);
