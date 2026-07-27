-- Konsensus v2 initial schema
-- Shared between SQLite and PostgreSQL (compatible subset)

-- UKM envelopes (E2EE ciphertext only — never plaintext, Principle 4)
CREATE TABLE IF NOT EXISTS messages (
    id            TEXT PRIMARY KEY,
    kind          INTEGER NOT NULL,
    sender        TEXT NOT NULL,
    recipient_type TEXT NOT NULL,
    recipient_id  TEXT NOT NULL,
    timestamp_ms  INTEGER NOT NULL,
    ciphertext    BLOB NOT NULL,
    payment_hash  TEXT NOT NULL,
    preimage      TEXT NOT NULL,
    amount_msat   INTEGER NOT NULL,
    signature     TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    references_json TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient
    ON messages(recipient_type, recipient_id, timestamp_ms DESC);

CREATE INDEX IF NOT EXISTS idx_messages_sender
    ON messages(sender, timestamp_ms DESC);

-- Group chat rooms
CREATE TABLE IF NOT EXISTS rooms (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

-- Room membership
CREATE TABLE IF NOT EXISTS room_members (
    room_id       TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    node_id       TEXT NOT NULL,
    joined_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    role          TEXT NOT NULL DEFAULT 'member',
    PRIMARY KEY (room_id, node_id)
);

-- Known peers
CREATE TABLE IF NOT EXISTS peers (
    node_id       TEXT PRIMARY KEY,
    address       TEXT,
    last_seen     TEXT,
    display_name  TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

-- Nonces for replay protection
CREATE TABLE IF NOT EXISTS nonces (
    nonce_hex     TEXT PRIMARY KEY,
    sender        TEXT NOT NULL,
    received_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_nonces_sender ON nonces(sender);
