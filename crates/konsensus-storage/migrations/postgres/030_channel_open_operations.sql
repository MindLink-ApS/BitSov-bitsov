-- open-channel idempotency (#331): the caller's operation_id is recorded before
-- dispatch, so a retry after a timeout never opens a second channel.
CREATE TABLE IF NOT EXISTS channel_open_operations (
    operation_id TEXT NOT NULL PRIMARY KEY,
    request_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','uncertain','opened')),
    request BYTEA NOT NULL,
    result BYTEA,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);
