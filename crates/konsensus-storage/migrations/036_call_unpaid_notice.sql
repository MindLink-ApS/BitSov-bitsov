-- One paid Unpaid notice per call, durably consumed on either side.
ALTER TABLE call_state ADD COLUMN unpaid_notice_used BIGINT NOT NULL DEFAULT 0
    CHECK (unpaid_notice_used IN (0, 1));
