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
