-- Forward-only schema parity. Never backfill old migration numbers: nodes
-- may already have recorded them. Keep all repairs in version 033, with
-- conditional DDL so existing tables and rows survive and replay is safe.

-- Daily fiat exchange-rate snapshots.
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

-- Recovery schemes, outbound trustees, and inbound shards.
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

-- Contact book. Boolean flags are converted to INTEGER 0/1.
CREATE TABLE IF NOT EXISTS contacts (
    node_id                  TEXT PRIMARY KEY,
    local_alias              TEXT,
    claimed_name             TEXT,
    profile_json             TEXT NOT NULL DEFAULT '{}',
    avatar_blake3            TEXT,
    verified_identities_json TEXT NOT NULL DEFAULT '[]',
    muted                    INTEGER NOT NULL DEFAULT 0 CHECK (muted IN (0, 1)),
    blocked                  INTEGER NOT NULL DEFAULT 0 CHECK (blocked IN (0, 1)),
    tags_json                TEXT NOT NULL DEFAULT '[]',
    notes                    TEXT,
    created_at               TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    updated_at               TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
);

ALTER TABLE contacts ADD COLUMN IF NOT EXISTS local_alias TEXT;
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS claimed_name TEXT;
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS profile_json TEXT NOT NULL DEFAULT '{}';
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS avatar_blake3 TEXT;
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS verified_identities_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS muted INTEGER NOT NULL DEFAULT 0;
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS blocked INTEGER NOT NULL DEFAULT 0;
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS tags_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS notes TEXT;
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS updated_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'contacts' AND column_name = 'muted' AND udt_name = 'bool'
    ) THEN
        ALTER TABLE contacts ALTER COLUMN muted DROP DEFAULT;
        ALTER TABLE contacts
            ALTER COLUMN muted TYPE INTEGER USING CASE WHEN muted THEN 1 ELSE 0 END;
        ALTER TABLE contacts ALTER COLUMN muted SET DEFAULT 0;
        ALTER TABLE contacts ALTER COLUMN muted SET NOT NULL;
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'contacts' AND column_name = 'blocked' AND udt_name = 'bool'
    ) THEN
        ALTER TABLE contacts ALTER COLUMN blocked DROP DEFAULT;
        ALTER TABLE contacts
            ALTER COLUMN blocked TYPE INTEGER USING CASE WHEN blocked THEN 1 ELSE 0 END;
        ALTER TABLE contacts ALTER COLUMN blocked SET DEFAULT 0;
        ALTER TABLE contacts ALTER COLUMN blocked SET NOT NULL;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'contacts_muted_check' AND conrelid = 'contacts'::regclass
    ) THEN
        ALTER TABLE contacts
            ADD CONSTRAINT contacts_muted_check CHECK (muted IN (0, 1));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'contacts_blocked_check' AND conrelid = 'contacts'::regclass
    ) THEN
        ALTER TABLE contacts
            ADD CONSTRAINT contacts_blocked_check CHECK (blocked IN (0, 1));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_contacts_blocked ON contacts(blocked);
CREATE INDEX IF NOT EXISTS idx_contacts_muted ON contacts(muted);
CREATE INDEX IF NOT EXISTS idx_contacts_updated ON contacts(updated_at DESC);

-- Calendar tables, invite nonce uniqueness, and onboarding funding width.
-- Applied once. Statements are conditional so a database that already has
-- some of these objects keeps its rows and does not gain a second unique index
-- (a second index makes Postgres ON CONFLICT inference ambiguous).

CREATE TABLE IF NOT EXISTS calendar_events (
    id              TEXT PRIMARY KEY,
    message_id      TEXT,
    organizer       TEXT NOT NULL,
    title           TEXT NOT NULL,
    description     TEXT,
    start_ms        BIGINT NOT NULL,
    end_ms          BIGINT NOT NULL,
    tz              TEXT NOT NULL,
    location        TEXT,
    attendees_json  TEXT NOT NULL,
    recurrence_json TEXT,
    color           TEXT,
    created_at      TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    parent_id       TEXT
);

ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS message_id TEXT;
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS organizer TEXT NOT NULL DEFAULT '';
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '';
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS start_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS end_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS tz TEXT NOT NULL DEFAULT 'UTC';
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS location TEXT;
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS attendees_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS recurrence_json TEXT;
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS color TEXT;
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS parent_id TEXT;

CREATE INDEX IF NOT EXISTS idx_calendar_events_start ON calendar_events (start_ms);

CREATE TABLE IF NOT EXISTS calendar_rsvps (
    id         TEXT PRIMARY KEY,
    event_id   TEXT NOT NULL,
    responder  TEXT NOT NULL,
    response   TEXT NOT NULL,
    comment    TEXT,
    created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
);

ALTER TABLE calendar_rsvps ADD COLUMN IF NOT EXISTS event_id TEXT NOT NULL DEFAULT '';
ALTER TABLE calendar_rsvps ADD COLUMN IF NOT EXISTS responder TEXT NOT NULL DEFAULT '';
ALTER TABLE calendar_rsvps ADD COLUMN IF NOT EXISTS response TEXT NOT NULL DEFAULT '';
ALTER TABLE calendar_rsvps ADD COLUMN IF NOT EXISTS comment TEXT;
ALTER TABLE calendar_rsvps ADD COLUMN IF NOT EXISTS created_at TEXT NOT NULL DEFAULT to_char(now() AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"');

CREATE INDEX IF NOT EXISTS idx_calendar_rsvps_event ON calendar_rsvps (event_id);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_index ix
        JOIN pg_class t ON t.oid = ix.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = current_schema()
          AND t.relname = 'calendar_rsvps'
          AND ix.indisunique
          AND ix.indpred IS NULL
          AND (
              SELECT array_agg(a.attname::text ORDER BY a.attname::text)
              FROM pg_attribute a
              WHERE a.attrelid = t.oid
                AND a.attnum = ANY (ix.indkey)
                AND a.attnum > 0
          ) = ARRAY['event_id', 'responder']::text[]
    ) THEN
        CREATE UNIQUE INDEX calendar_rsvps_event_responder_key
            ON calendar_rsvps (event_id, responder);
    END IF;
END
$$;

-- SQLite migration 016 rebuilt invites_issued with nonce UNIQUE. Postgres
-- recorded version 16 without that constraint. Refuse to drop duplicate rows.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM invites_issued GROUP BY nonce HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'invites_issued.nonce has duplicate values; refusing to delete rows';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM pg_index ix
        JOIN pg_class t ON t.oid = ix.indrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = current_schema()
          AND t.relname = 'invites_issued'
          AND ix.indisunique
          AND ix.indpred IS NULL
          AND (
              SELECT array_agg(a.attname::text ORDER BY a.attname::text)
              FROM pg_attribute a
              WHERE a.attrelid = t.oid
                AND a.attnum = ANY (ix.indkey)
                AND a.attnum > 0
          ) = ARRAY['nonce']::text[]
    ) THEN
        CREATE UNIQUE INDEX invites_issued_nonce_key ON invites_issued (nonce);
    END IF;
END
$$;

-- PostgreSQL INTEGER is signed 32-bit and rejects the top half of u32.
-- BIGINT keeps every existing value.
ALTER TABLE onboarding_state
    ALTER COLUMN funding_amount_sats_received TYPE BIGINT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'onboarding_state'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) ILIKE '%id = 1%'
    ) THEN
        IF EXISTS (SELECT 1 FROM onboarding_state WHERE id <> 1) THEN
            RAISE EXCEPTION 'onboarding_state has a row other than id = 1; refusing to delete it';
        END IF;
        ALTER TABLE onboarding_state
            ADD CONSTRAINT onboarding_state_id_singleton CHECK (id = 1);
    END IF;
END
$$;
