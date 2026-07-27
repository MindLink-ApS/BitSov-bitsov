-- Contact book: known peers with local annotations, trust signals, and avatar dedup.
--
-- avatar_blake3 references files.blake3_hash for blob deduplication — avatars
-- are stored once in the files table and referenced by content-addressed hash.
--
-- Upsert semantics: updated_at guards stale writes.  A row is only updated when
-- the incoming updated_at is strictly greater than the stored value, preventing
-- out-of-order sync from overwriting newer local edits.

CREATE TABLE IF NOT EXISTS contacts (
    node_id                  TEXT PRIMARY KEY,
    local_alias              TEXT,
    claimed_name             TEXT,
    profile_json             TEXT NOT NULL DEFAULT '{}',
    -- blake3 hash of the avatar blob; blob lives in files.blake3_hash (dedup).
    avatar_blake3            TEXT,
    verified_identities_json TEXT NOT NULL DEFAULT '[]',
    muted                    INTEGER NOT NULL DEFAULT 0 CHECK(muted IN (0, 1)),
    blocked                  INTEGER NOT NULL DEFAULT 0 CHECK(blocked IN (0, 1)),
    tags_json                TEXT NOT NULL DEFAULT '[]',
    notes                    TEXT,
    created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_contacts_blocked    ON contacts(blocked);
CREATE INDEX IF NOT EXISTS idx_contacts_muted      ON contacts(muted);
CREATE INDEX IF NOT EXISTS idx_contacts_updated    ON contacts(updated_at DESC);
