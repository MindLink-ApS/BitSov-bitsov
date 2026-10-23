-- Contact book. Version 9 was never applied on Postgres.
-- muted/blocked are INTEGER 0/1, matching SQLite, so the same checks apply.
-- A hand-built boolean column is converted with true mapping to 1 and false to 0.

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
