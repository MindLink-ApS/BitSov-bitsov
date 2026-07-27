-- Add foreign key constraint: pending_deliveries.message_id → messages.id
-- with ON DELETE CASCADE so retention cleanup automatically removes
-- orphaned pending deliveries.
--
-- SQLite does not support ALTER TABLE ADD CONSTRAINT, so we recreate
-- the table. The PRAGMA foreign_keys = ON statement must be issued
-- per-connection (handled in the Rust connection setup).

CREATE TABLE IF NOT EXISTS pending_deliveries_new (
    message_id    TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    recipient_id  TEXT NOT NULL,
    queued_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    attempts      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (message_id, recipient_id)
);

INSERT OR IGNORE INTO pending_deliveries_new (message_id, recipient_id, queued_at, attempts)
    SELECT message_id, recipient_id, queued_at, attempts
    FROM pending_deliveries
    WHERE message_id IN (SELECT id FROM messages);

DROP TABLE IF EXISTS pending_deliveries;

ALTER TABLE pending_deliveries_new RENAME TO pending_deliveries;

CREATE INDEX IF NOT EXISTS idx_pending_recipient ON pending_deliveries(recipient_id);
