-- Recovery schemes, outbound trustees, and inbound shards.
-- Version 8 was never applied on Postgres.

CREATE TABLE IF NOT EXISTS recovery_schemes (
    id            TEXT PRIMARY KEY,
    scheme_type   TEXT NOT NULL,
    threshold     INTEGER NOT NULL CHECK (threshold > 0),
    total_shares  INTEGER NOT NULL CHECK (total_shares >= threshold),
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

ALTER TABLE recovery_schemes ADD COLUMN IF NOT EXISTS scheme_type TEXT;
ALTER TABLE recovery_schemes ADD COLUMN IF NOT EXISTS threshold INTEGER;
ALTER TABLE recovery_schemes ADD COLUMN IF NOT EXISTS total_shares INTEGER;
ALTER TABLE recovery_schemes ADD COLUMN IF NOT EXISTS metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE recovery_schemes ADD COLUMN IF NOT EXISTS created_at TEXT;
ALTER TABLE recovery_schemes ADD COLUMN IF NOT EXISTS updated_at TEXT;

CREATE TABLE IF NOT EXISTS recovery_trustees (
    id               TEXT PRIMARY KEY,
    scheme_id        TEXT NOT NULL REFERENCES recovery_schemes(id) ON DELETE CASCADE,
    trustee_node_id  TEXT NOT NULL,
    share_index      INTEGER NOT NULL,
    shard_commitment TEXT,
    delivered_at     TEXT,
    created_at       TEXT NOT NULL,
    UNIQUE (scheme_id, trustee_node_id),
    UNIQUE (scheme_id, share_index)
);

ALTER TABLE recovery_trustees ADD COLUMN IF NOT EXISTS scheme_id TEXT;
ALTER TABLE recovery_trustees ADD COLUMN IF NOT EXISTS trustee_node_id TEXT;
ALTER TABLE recovery_trustees ADD COLUMN IF NOT EXISTS share_index INTEGER;
ALTER TABLE recovery_trustees ADD COLUMN IF NOT EXISTS shard_commitment TEXT;
ALTER TABLE recovery_trustees ADD COLUMN IF NOT EXISTS delivered_at TEXT;
ALTER TABLE recovery_trustees ADD COLUMN IF NOT EXISTS created_at TEXT;

CREATE TABLE IF NOT EXISTS recovery_shards (
    id                   TEXT PRIMARY KEY,
    owner_node_id        TEXT NOT NULL,
    share_index          INTEGER NOT NULL,
    shard_ciphertext     BYTEA NOT NULL,
    scheme_metadata_json TEXT NOT NULL DEFAULT '{}',
    received_at          TEXT NOT NULL,
    UNIQUE (owner_node_id, share_index)
);

ALTER TABLE recovery_shards ADD COLUMN IF NOT EXISTS owner_node_id TEXT;
ALTER TABLE recovery_shards ADD COLUMN IF NOT EXISTS share_index INTEGER;
ALTER TABLE recovery_shards ADD COLUMN IF NOT EXISTS shard_ciphertext BYTEA;
ALTER TABLE recovery_shards ADD COLUMN IF NOT EXISTS scheme_metadata_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE recovery_shards ADD COLUMN IF NOT EXISTS received_at TEXT;

-- A hand-built table may already exist without the secondary unique indexes.
-- Skip creation when any unique index already covers the same columns so
-- ON CONFLICT inference stays unambiguous.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_index ix
        JOIN pg_class t ON t.oid = ix.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = current_schema()
          AND t.relname = 'recovery_trustees'
          AND ix.indisunique
          AND ix.indpred IS NULL
          AND (
              SELECT array_agg(a.attname::text ORDER BY a.attname::text)
              FROM pg_attribute a
              WHERE a.attrelid = t.oid
                AND a.attnum = ANY (ix.indkey)
                AND a.attnum > 0
          ) = ARRAY['scheme_id', 'trustee_node_id']::text[]
    ) THEN
        CREATE UNIQUE INDEX recovery_trustees_scheme_node_key
            ON recovery_trustees (scheme_id, trustee_node_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_index ix
        JOIN pg_class t ON t.oid = ix.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = current_schema()
          AND t.relname = 'recovery_trustees'
          AND ix.indisunique
          AND ix.indpred IS NULL
          AND (
              SELECT array_agg(a.attname::text ORDER BY a.attname::text)
              FROM pg_attribute a
              WHERE a.attrelid = t.oid
                AND a.attnum = ANY (ix.indkey)
                AND a.attnum > 0
          ) = ARRAY['scheme_id', 'share_index']::text[]
    ) THEN
        CREATE UNIQUE INDEX recovery_trustees_scheme_share_key
            ON recovery_trustees (scheme_id, share_index);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_index ix
        JOIN pg_class t ON t.oid = ix.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = current_schema()
          AND t.relname = 'recovery_shards'
          AND ix.indisunique
          AND ix.indpred IS NULL
          AND (
              SELECT array_agg(a.attname::text ORDER BY a.attname::text)
              FROM pg_attribute a
              WHERE a.attrelid = t.oid
                AND a.attnum = ANY (ix.indkey)
                AND a.attnum > 0
          ) = ARRAY['owner_node_id', 'share_index']::text[]
    ) THEN
        CREATE UNIQUE INDEX recovery_shards_owner_share_key
            ON recovery_shards (owner_node_id, share_index);
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'recovery_trustees'::regclass
          AND contype = 'f'
    ) THEN
        ALTER TABLE recovery_trustees
            ADD CONSTRAINT recovery_trustees_scheme_id_fkey
            FOREIGN KEY (scheme_id) REFERENCES recovery_schemes(id) ON DELETE CASCADE;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_recovery_trustees_scheme ON recovery_trustees(scheme_id);
CREATE INDEX IF NOT EXISTS idx_recovery_trustees_node ON recovery_trustees(trustee_node_id);
CREATE INDEX IF NOT EXISTS idx_recovery_shards_owner ON recovery_shards(owner_node_id);
