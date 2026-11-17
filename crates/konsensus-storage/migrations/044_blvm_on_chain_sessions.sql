-- Outbound path-3 on-chain session state (sender-side prepay ledger).
CREATE TABLE IF NOT EXISTS blvm_on_chain_sessions (
    recipient_node_id  TEXT NOT NULL PRIMARY KEY,
    payment_request_id TEXT NOT NULL,
    tx_hash            TEXT NOT NULL,
    amount_sats        INTEGER NOT NULL,
    debit_counter      INTEGER NOT NULL DEFAULT 0,
    spent_msat         INTEGER NOT NULL DEFAULT 0,
    opened_at_ms       TEXT NOT NULL
);
