-- File metadata and encrypted blob storage.
-- Files are E2EE encrypted before storage (same as message ciphertext).
-- The `data` column holds the encrypted file bytes (BLOB).
-- For the mesh network, files are transferred inline in UKM envelopes
-- (KIND_FILE_REF = 200) and stored by both sender and receiver.

CREATE TABLE IF NOT EXISTS files (
    id            TEXT PRIMARY KEY,
    filename      TEXT NOT NULL,
    mime_type     TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes    INTEGER NOT NULL,
    blake3_hash   TEXT NOT NULL,
    sender        TEXT NOT NULL,
    message_id    TEXT,
    data          BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_files_sender ON files(sender);
CREATE INDEX IF NOT EXISTS idx_files_message ON files(message_id);
CREATE INDEX IF NOT EXISTS idx_files_created ON files(created_at DESC);
