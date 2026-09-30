-- 1:1 calls, Codex delta2 (#131).
-- A reserved signal of ours is bound to the exact request that reserved it
-- (the operation journal's request hash), not only to its operation id.
ALTER TABLE call_state ADD COLUMN pending_request_hash TEXT;
-- An incoming call signal is held (invisible to history, resync and
-- duplicate ACKs) from before its paid acceptance until its admission is
-- finalized. A hold that outlives its handler (failed refusal cleanup, crash)
-- is withdrawn by the startup / periodic sweep: fail closed.
CREATE TABLE IF NOT EXISTS call_admission_hold (
    message_id TEXT PRIMARY KEY,
    sender TEXT NOT NULL,
    held_at_ms BIGINT NOT NULL
);
