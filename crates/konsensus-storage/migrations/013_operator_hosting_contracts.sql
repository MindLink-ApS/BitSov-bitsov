-- Operator hosting contracts and payment ledger.
-- MANUAL: deploy only after operator review; this table tracks real hosting
-- payment state for cloud-tier nodes.

CREATE TABLE IF NOT EXISTS operator_hosting_contracts (
    id              TEXT PRIMARY KEY,
    tenant_pubkey   TEXT NOT NULL,
    operator_pubkey TEXT NOT NULL,
    sats_per_day    INTEGER NOT NULL CHECK (sats_per_day > 0),
    started_at      INTEGER NOT NULL,
    last_paid_at    INTEGER,
    state           TEXT NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'overdue', 'paused', 'stopped')),
    updated_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operator_hosting_contracts_tenant
    ON operator_hosting_contracts(tenant_pubkey);

CREATE INDEX IF NOT EXISTS idx_operator_hosting_contracts_state
    ON operator_hosting_contracts(state);

CREATE TABLE IF NOT EXISTS operator_hosting_payments (
    payment_hash    TEXT PRIMARY KEY,
    contract_id     TEXT NOT NULL,
    tenant_pubkey   TEXT NOT NULL,
    operator_pubkey TEXT NOT NULL,
    amount_msat     INTEGER NOT NULL CHECK (amount_msat > 0),
    paid_at         INTEGER NOT NULL,
    direction       TEXT NOT NULL CHECK (direction IN ('incoming', 'outgoing')),
    preimage        TEXT,
    memo            TEXT,
    created_at      INTEGER NOT NULL,
    FOREIGN KEY (contract_id) REFERENCES operator_hosting_contracts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_operator_hosting_payments_contract
    ON operator_hosting_payments(contract_id, paid_at DESC);

CREATE INDEX IF NOT EXISTS idx_operator_hosting_payments_tenant
    ON operator_hosting_payments(tenant_pubkey, paid_at DESC);
