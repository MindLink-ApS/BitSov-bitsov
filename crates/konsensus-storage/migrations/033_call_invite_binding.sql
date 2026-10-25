-- Message id of an admitted or sent call invite, so a resend can be
-- classified without the plaintext cache. ring_anchored records that the
-- caller's 60s clock follows the ringing ack (or the callee's device fetch)
-- rather than payment time.
ALTER TABLE call_state ADD COLUMN ring_anchored INTEGER NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS call_invite_binding (
    message_id TEXT PRIMARY KEY,
    peer TEXT NOT NULL,
    call_id TEXT NOT NULL
);
