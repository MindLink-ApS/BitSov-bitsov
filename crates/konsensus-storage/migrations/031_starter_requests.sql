-- N-M7a: no socket address or alias is retained in starter state.
CREATE TABLE starter_requests (
 request_id TEXT PRIMARY KEY, hub_node_id TEXT NOT NULL, hub_ln_pubkey TEXT NOT NULL,
 network TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('requested','opening','ready','refused')),
 detail TEXT, reason TEXT, retry_allowed INTEGER NOT NULL DEFAULT 0, retry_after_unix BIGINT,
 original_request_id TEXT, capacity_sats BIGINT, push_sats BIGINT, channel_id TEXT,
 user_channel_id TEXT, funding_txid TEXT, verified_at BIGINT, created_at BIGINT NOT NULL,
 updated_at BIGINT NOT NULL, last_sent_at BIGINT, send_attempts BIGINT NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX starter_requests_live ON starter_requests(hub_node_id) WHERE state <> 'refused';
CREATE TABLE starter_grants (
 request_id TEXT PRIMARY KEY, requester_node_id TEXT NOT NULL, ln_pubkey TEXT NOT NULL,
 network TEXT NOT NULL, invite_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('admitted','opening','ready','refused','resolved')),
 reason TEXT, retry_after_unix BIGINT, attempts BIGINT NOT NULL DEFAULT 0,
 capacity_sats BIGINT NOT NULL CHECK(capacity_sats > 0),
 push_sats BIGINT NOT NULL CHECK(push_sats >= 0 AND push_sats <= capacity_sats / 2),
 utc_day TEXT NOT NULL, open_operation_id TEXT NOT NULL,
 channel_id TEXT, user_channel_id TEXT, funding_txid TEXT,
 created_at BIGINT NOT NULL, updated_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX starter_grants_node ON starter_grants(requester_node_id) WHERE state <> 'refused';
CREATE UNIQUE INDEX starter_grants_ln ON starter_grants(ln_pubkey) WHERE state <> 'refused';
CREATE TABLE starter_hub_counters (
 id INTEGER PRIMARY KEY CHECK(id = 1), utc_day TEXT NOT NULL,
 day_count BIGINT NOT NULL CHECK(day_count >= 0),
 inflight_count BIGINT NOT NULL CHECK(inflight_count >= 0),
 committed_sats BIGINT NOT NULL CHECK(committed_sats >= 0)
);
INSERT INTO starter_hub_counters VALUES (1, '', 0, 0, 0);
