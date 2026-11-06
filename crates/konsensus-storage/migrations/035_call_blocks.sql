-- Paid call intervals, shared by SQLite and PostgreSQL.
-- Versions 033/034 are reserved by the schema-parity and call-invite PRs.
ALTER TABLE call_state ADD COLUMN paid_until_ms BIGINT;
ALTER TABLE call_state ADD COLUMN next_block_seq BIGINT NOT NULL DEFAULT 0;
ALTER TABLE call_state ADD COLUMN end_reason TEXT;
-- Legacy live calls have no paid interval. Retain their entire replay window
-- but fail closed for media rather than granting the old four-hour admission.
UPDATE call_state SET phase = 'ended', deadline_ms = replay_until_ms,
    end_reason = 'unpaid' WHERE phase = 'live';
