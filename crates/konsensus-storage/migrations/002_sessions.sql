-- E2EE session state persistence
-- Stores serialized Double Ratchet state per peer, encrypted at rest.
-- Enables session resumption across node restarts without re-running X3DH.

CREATE TABLE IF NOT EXISTS sessions (
    peer_id       TEXT PRIMARY KEY,
    state_blob    BLOB NOT NULL,
    established_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
