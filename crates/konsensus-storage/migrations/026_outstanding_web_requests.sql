-- Paid outbound page/manifest requests awaiting their bound reply (#129 R1).
-- A restart between paying the request and receiving the reply must not
-- forget the binding. One row per paid request hash; taken once.
CREATE TABLE IF NOT EXISTS outstanding_web_requests (
    payment_hash TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    peer TEXT NOT NULL,
    expected_reply_kind BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_outstanding_web_requests_expiry ON outstanding_web_requests(expires_at_ms);
