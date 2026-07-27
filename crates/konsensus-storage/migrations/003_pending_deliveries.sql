-- Pending message delivery queue.
-- Tracks messages that could not be delivered because the recipient peer
-- was offline. The node retries delivery when the peer reconnects.

CREATE TABLE IF NOT EXISTS pending_deliveries (
    message_id    TEXT NOT NULL,
    recipient_id  TEXT NOT NULL,
    queued_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    attempts      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (message_id, recipient_id)
);

CREATE INDEX IF NOT EXISTS idx_pending_recipient ON pending_deliveries(recipient_id);
