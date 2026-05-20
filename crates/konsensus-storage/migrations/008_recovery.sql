-- Recovery support: schemes, trustees (outbound), and shards (inbound).
--
-- recovery_schemes   : a key-recovery configuration for this node (e.g. Shamir 2-of-3).
-- recovery_trustees  : trustees who hold shards of THIS node\'s key (outbound).
-- recovery_shards    : shards THIS node holds on behalf of other nodes (inbound).
--                      shard_ciphertext is AES-256-GCM encrypted at rest.

CREATE TABLE IF NOT EXISTS recovery_schemes (
    id            TEXT    PRIMARY KEY,
    scheme_type   TEXT    NOT NULL,
    threshold     INTEGER NOT NULL CHECK (threshold > 0),
    total_shares  INTEGER NOT NULL CHECK (total_shares >= threshold),
    metadata_json TEXT    NOT NULL DEFAULT '{}',
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_trustees (
    id               TEXT    PRIMARY KEY,
    scheme_id        TEXT    NOT NULL REFERENCES recovery_schemes(id) ON DELETE CASCADE,
    trustee_node_id  TEXT    NOT NULL,
    share_index      INTEGER NOT NULL,
    shard_commitment TEXT,
    delivered_at     TEXT,
    created_at       TEXT    NOT NULL,
    UNIQUE (scheme_id, trustee_node_id),
    UNIQUE (scheme_id, share_index)
);

CREATE INDEX IF NOT EXISTS idx_recovery_trustees_scheme ON recovery_trustees(scheme_id);
CREATE INDEX IF NOT EXISTS idx_recovery_trustees_node   ON recovery_trustees(trustee_node_id);

CREATE TABLE IF NOT EXISTS recovery_shards (
    id                   TEXT    PRIMARY KEY,
    owner_node_id        TEXT    NOT NULL,
    share_index          INTEGER NOT NULL,
    shard_ciphertext     BLOB    NOT NULL,
    scheme_metadata_json TEXT    NOT NULL DEFAULT '{}',
    received_at          TEXT    NOT NULL,
    UNIQUE (owner_node_id, share_index)
);

CREATE INDEX IF NOT EXISTS idx_recovery_shards_owner ON recovery_shards(owner_node_id);
