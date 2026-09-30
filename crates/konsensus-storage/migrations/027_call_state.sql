-- 1:1 call state (kinds 400-403). Survives restarts: used call ids stay
-- burned until replay_until_ms, live calls keep their phase, and a signal of
-- ours reserved under an operation id is settled or released on recovery.
CREATE TABLE IF NOT EXISTS call_state (
    peer TEXT NOT NULL,
    call_id TEXT NOT NULL,
    side TEXT NOT NULL,
    phase TEXT NOT NULL,
    deadline_ms BIGINT NOT NULL,
    replay_until_ms BIGINT NOT NULL,
    pending_operation_id TEXT,
    pending_kind BIGINT,
    PRIMARY KEY (peer, call_id)
);
CREATE INDEX IF NOT EXISTS idx_call_state_replay ON call_state(replay_until_ms);
CREATE INDEX IF NOT EXISTS idx_call_state_pending ON call_state(pending_operation_id);
