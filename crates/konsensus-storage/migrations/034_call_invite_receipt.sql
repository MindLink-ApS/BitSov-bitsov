-- The invite message this call row belongs to. A device fetch is a receipt
-- only when it is this message, so a reused call id cannot be rung by an
-- older retained invite.
ALTER TABLE call_state ADD COLUMN invite_message_id TEXT;

-- Survives call_state being swept. pending until a device fetches the invite
-- or the grace period ends with no device (fetched / unreachable).
ALTER TABLE call_invite_binding ADD COLUMN outcome TEXT NOT NULL DEFAULT 'pending';
