-- Frozen origin/main a745318 migrations through 032.
CREATE TABLE _konsensus_migrations (version INTEGER PRIMARY KEY, name TEXT NOT NULL);
-- Migration 1: initial

                CREATE TABLE IF NOT EXISTS messages (
                    id            TEXT PRIMARY KEY,
                    kind          INTEGER NOT NULL,
                    sender        TEXT NOT NULL,
                    recipient_type TEXT NOT NULL,
                    recipient_id  TEXT NOT NULL,
                    timestamp_ms  BIGINT NOT NULL,
                    ciphertext    BYTEA NOT NULL,
                    payment_hash  TEXT NOT NULL,
                    preimage      TEXT NOT NULL,
                    amount_msat   BIGINT NOT NULL,
                    signature     TEXT NOT NULL,
                    nonce         TEXT NOT NULL,
                    references_json TEXT NOT NULL DEFAULT '[]',
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_messages_recipient
                    ON messages(recipient_type, recipient_id, timestamp_ms DESC);
                CREATE INDEX IF NOT EXISTS idx_messages_sender
                    ON messages(sender, timestamp_ms DESC);

                CREATE TABLE IF NOT EXISTS rooms (
                    id            TEXT PRIMARY KEY,
                    name          TEXT NOT NULL,
                    created_by    TEXT NOT NULL,
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS room_members (
                    room_id       TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
                    node_id       TEXT NOT NULL,
                    joined_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    role          TEXT NOT NULL DEFAULT 'member',
                    PRIMARY KEY (room_id, node_id)
                );

                CREATE TABLE IF NOT EXISTS peers (
                    node_id       TEXT PRIMARY KEY,
                    address       TEXT,
                    last_seen     TIMESTAMPTZ,
                    display_name  TEXT,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS nonces (
                    nonce_hex     TEXT PRIMARY KEY,
                    sender        TEXT NOT NULL,
                    received_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_nonces_sender ON nonces(sender);

INSERT INTO _konsensus_migrations (version, name) VALUES (1, 'initial');
-- Migration 2: sessions

                CREATE TABLE IF NOT EXISTS sessions (
                    peer_id       TEXT PRIMARY KEY,
                    state_blob    BYTEA NOT NULL,
                    established_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );

INSERT INTO _konsensus_migrations (version, name) VALUES (2, 'sessions');
-- Migration 3: pending_deliveries

                CREATE TABLE IF NOT EXISTS pending_deliveries (
                    message_id    TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                    recipient_id  TEXT NOT NULL,
                    queued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    attempts      INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (message_id, recipient_id)
                );
                CREATE INDEX IF NOT EXISTS idx_pending_recipient
                    ON pending_deliveries(recipient_id);

INSERT INTO _konsensus_migrations (version, name) VALUES (3, 'pending_deliveries');
-- Migration 4: files

                CREATE TABLE IF NOT EXISTS files (
                    id            TEXT PRIMARY KEY,
                    filename      TEXT NOT NULL,
                    mime_type     TEXT NOT NULL DEFAULT 'application/octet-stream',
                    size_bytes    BIGINT NOT NULL,
                    blake3_hash   TEXT NOT NULL,
                    sender        TEXT NOT NULL,
                    message_id    TEXT,
                    data          BYTEA NOT NULL,
                    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_files_sender ON files(sender);
                CREATE INDEX IF NOT EXISTS idx_files_message ON files(message_id);
                CREATE INDEX IF NOT EXISTS idx_files_created ON files(created_at DESC);

INSERT INTO _konsensus_migrations (version, name) VALUES (4, 'files');
-- Migration 5: message_plaintext
ALTER TABLE messages ADD COLUMN IF NOT EXISTS plaintext_enc BYTEA;
INSERT INTO _konsensus_migrations (version, name) VALUES (5, 'message_plaintext');
-- Migration 6: pending_deliveries_fk

                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.table_constraints
                        WHERE constraint_type = 'FOREIGN KEY'
                        AND table_name = 'pending_deliveries'
                        AND constraint_name = 'pending_deliveries_message_id_fkey'
                    ) THEN
                        ALTER TABLE pending_deliveries
                            ADD CONSTRAINT pending_deliveries_message_id_fkey
                            FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE;
                    END IF;
                END
                $$;

INSERT INTO _konsensus_migrations (version, name) VALUES (6, 'pending_deliveries_fk');
-- Migration 10: invites_issued

                CREATE TABLE IF NOT EXISTS invites_issued (
                    id                          BYTEA   PRIMARY KEY,
                    invitee_pubkey              BYTEA   NOT NULL,
                    expiry_unix                 BIGINT  NOT NULL,
                    channel_size_hint_sats      BIGINT,
                    nonce                       BYTEA   NOT NULL,
                    state                       TEXT    NOT NULL DEFAULT 'pending'
                                                    CHECK(state IN ('pending','accepted','revoked')),
                    created_at                  BIGINT  NOT NULL,
                    accepted_at                 BIGINT,
                    revoked_at                  BIGINT
                );
                CREATE INDEX IF NOT EXISTS idx_invites_issued_invitee
                    ON invites_issued(invitee_pubkey);
                CREATE INDEX IF NOT EXISTS idx_invites_issued_state
                    ON invites_issued(state);

INSERT INTO _konsensus_migrations (version, name) VALUES (10, 'invites_issued');
-- Migration 11: accepted_invites

                CREATE TABLE IF NOT EXISTS accepted_invites (
                    nonce           BYTEA   PRIMARY KEY,
                    inviter_pubkey  BYTEA   NOT NULL,
                    expiry_unix     BIGINT  NOT NULL,
                    accepted_at     BIGINT  NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_accepted_invites_inviter
                    ON accepted_invites(inviter_pubkey);

INSERT INTO _konsensus_migrations (version, name) VALUES (11, 'accepted_invites');
-- Migration 12: onboarding_state

                CREATE TABLE IF NOT EXISTS onboarding_state (
                    id                              INTEGER PRIMARY KEY,
                    current_step                    TEXT    NOT NULL DEFAULT 'paste-invite',
                    tier                            TEXT,
                    funding_amount_sats             BIGINT,
                    funding_address                 TEXT,
                    funding_txid                    TEXT,
                    confirmations                   INTEGER NOT NULL DEFAULT 0,
                    updated_at                      BIGINT
                );
                INSERT INTO onboarding_state (id, current_step) VALUES (1, 'paste-invite')
                    ON CONFLICT (id) DO NOTHING;

INSERT INTO _konsensus_migrations (version, name) VALUES (12, 'onboarding_state');
-- Migration 13: operator_hosting_contracts

                CREATE TABLE IF NOT EXISTS operator_hosting_contracts (
                    id              TEXT PRIMARY KEY,
                    tenant_pubkey   TEXT NOT NULL,
                    operator_pubkey TEXT NOT NULL,
                    sats_per_day    BIGINT NOT NULL CHECK (sats_per_day > 0),
                    started_at      BIGINT NOT NULL,
                    last_paid_at    BIGINT,
                    state           TEXT NOT NULL DEFAULT 'active'
                                    CHECK (state IN ('active', 'overdue', 'paused', 'stopped')),
                    updated_at      BIGINT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_operator_hosting_contracts_tenant
                    ON operator_hosting_contracts(tenant_pubkey);
                CREATE INDEX IF NOT EXISTS idx_operator_hosting_contracts_state
                    ON operator_hosting_contracts(state);

                CREATE TABLE IF NOT EXISTS operator_hosting_payments (
                    payment_hash    TEXT PRIMARY KEY,
                    contract_id     TEXT NOT NULL REFERENCES operator_hosting_contracts(id) ON DELETE CASCADE,
                    tenant_pubkey   TEXT NOT NULL,
                    operator_pubkey TEXT NOT NULL,
                    amount_msat     BIGINT NOT NULL CHECK (amount_msat > 0),
                    paid_at         BIGINT NOT NULL,
                    direction       TEXT NOT NULL CHECK (direction IN ('incoming', 'outgoing')),
                    preimage        TEXT,
                    memo            TEXT,
                    created_at      BIGINT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_operator_hosting_payments_contract
                    ON operator_hosting_payments(contract_id, paid_at DESC);
                CREATE INDEX IF NOT EXISTS idx_operator_hosting_payments_tenant
                    ON operator_hosting_payments(tenant_pubkey, paid_at DESC);

INSERT INTO _konsensus_migrations (version, name) VALUES (13, 'operator_hosting_contracts');
-- Migration 14: invite_v2_fields

                ALTER TABLE invites_issued
                    ADD COLUMN IF NOT EXISTS addr TEXT NOT NULL DEFAULT '';
                ALTER TABLE invites_issued
                    ADD COLUMN IF NOT EXISTS max_fee_rate_sat_per_vb BIGINT;
                ALTER TABLE invites_issued
                    ADD COLUMN IF NOT EXISTS channel_open_intent_expiry_unix BIGINT;

INSERT INTO _konsensus_migrations (version, name) VALUES (14, 'invite_v2_fields');
-- Migration 15: invite_expired_state

                ALTER TABLE invites_issued
                    DROP CONSTRAINT IF EXISTS invites_issued_state_check;
                ALTER TABLE invites_issued
                    ADD CONSTRAINT invites_issued_state_check
                    CHECK(state IN ('pending','accepted','revoked','expired'));

INSERT INTO _konsensus_migrations (version, name) VALUES (15, 'invite_expired_state');
-- Migration 16: invite_opening_state

                ALTER TABLE invites_issued
                    DROP CONSTRAINT IF EXISTS invites_issued_state_check;
                ALTER TABLE invites_issued
                    ADD CONSTRAINT invites_issued_state_check
                    CHECK(state IN ('pending','accepted','opening','revoked','expired'));

INSERT INTO _konsensus_migrations (version, name) VALUES (16, 'invite_opening_state');
-- Migration 17: onboarding_state_funding_evidence

                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS funding_amount_sats_required BIGINT;
                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS funding_amount_sats_received INTEGER NOT NULL DEFAULT 0;
                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS last_poll_at BIGINT;
                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS funding_evidence TEXT;
                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS tier TEXT;

                UPDATE onboarding_state
                SET funding_amount_sats_required = COALESCE(funding_amount_sats_required, funding_amount_sats);

INSERT INTO _konsensus_migrations (version, name) VALUES (17, 'onboarding_state_funding_evidence');
-- Migration 18: onboarding_state_scope

                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS invite_id TEXT;
                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS inviter_pubkey BYTEA;
                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS inviter_ln_pubkey TEXT;

INSERT INTO _konsensus_migrations (version, name) VALUES (18, 'onboarding_state_scope');
-- Migration 19: payment_receipts

                CREATE TABLE IF NOT EXISTS payment_receipts (
                    payment_hash TEXT PRIMARY KEY,
                    message_id   TEXT NOT NULL,
                    sender       TEXT NOT NULL,
                    received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_payment_receipts_sender
                    ON payment_receipts(sender, received_at DESC);

INSERT INTO _konsensus_migrations (version, name) VALUES (19, 'payment_receipts');
-- Migration 20: pending_delivery_state
ALTER TABLE pending_deliveries ADD COLUMN IF NOT EXISTS state TEXT NOT NULL DEFAULT 'pending'; ALTER TABLE pending_deliveries ADD COLUMN IF NOT EXISTS dispatched INTEGER NOT NULL DEFAULT 0;
INSERT INTO _konsensus_migrations (version, name) VALUES (20, 'pending_delivery_state');
-- Migration 21: paid_delivery_rejections
-- Keep migration 020 byte-identical for databases that already applied it.
-- Its dispatched=1 backfill cannot distinguish offline rows. Re-establish
-- dispatch authority on the next send; paid identity makes replay safe.
UPDATE pending_deliveries SET dispatched = 0;
ALTER TABLE pending_deliveries ADD COLUMN IF NOT EXISTS retry_after_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pending_deliveries ADD COLUMN IF NOT EXISTS rejection_reason TEXT;

-- An acceptance tombstone survives message deletion/retention. Only orphaned
-- legacy receipts may heal; receipts already backed by messages are spent.
ALTER TABLE payment_receipts ADD COLUMN IF NOT EXISTS accepted INTEGER NOT NULL DEFAULT 0;
UPDATE payment_receipts SET accepted = 1 WHERE EXISTS (
    SELECT 1 FROM messages WHERE messages.id = payment_receipts.message_id
        AND messages.sender = payment_receipts.sender
        AND messages.payment_hash = payment_receipts.payment_hash
);

INSERT INTO _konsensus_migrations (version, name) VALUES (21, 'paid_delivery_rejections');
-- Migration 22: receipt bindings
-- Durable acceptance evidence survives content retention for duplicate ACKs.
ALTER TABLE payment_receipts ADD COLUMN kind INTEGER;
ALTER TABLE payment_receipts ADD COLUMN recipient_type TEXT;
ALTER TABLE payment_receipts ADD COLUMN recipient_id TEXT;
ALTER TABLE payment_receipts ADD COLUMN preimage TEXT;
ALTER TABLE payment_receipts ADD COLUMN amount_msat BIGINT;
ALTER TABLE payment_receipts ADD COLUMN nonce TEXT;
ALTER TABLE payment_receipts ADD COLUMN references_json TEXT;
UPDATE payment_receipts SET (kind, recipient_type, recipient_id, preimage, amount_msat, nonce, references_json) = (SELECT m.kind, m.recipient_type, m.recipient_id, m.preimage, m.amount_msat, m.nonce, m.references_json FROM messages m WHERE m.id = payment_receipts.message_id AND m.sender = payment_receipts.sender AND m.payment_hash = payment_receipts.payment_hash) WHERE accepted = 1;

INSERT INTO _konsensus_migrations (version, name) VALUES (22, 'receipt bindings');
-- Migration 23: delivery price quotes
-- Recipient-issued offers survive a receiver restart; sender timestamps cannot renew them.
CREATE TABLE IF NOT EXISTS delivery_price_quotes (
    sender TEXT NOT NULL,
    scope TEXT NOT NULL,
    amount_msat BIGINT NOT NULL CHECK(amount_msat > 0),
    excluded_kinds TEXT NOT NULL DEFAULT ',',
    issued_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    PRIMARY KEY(sender, scope, amount_msat, issued_at, excluded_kinds)
);
CREATE INDEX IF NOT EXISTS idx_delivery_price_quotes_expiry ON delivery_price_quotes(expires_at);

INSERT INTO _konsensus_migrations (version, name) VALUES (23, 'delivery price quotes');
-- Migration 24: outbox operations
-- Durable sender identity; recovery contains only encrypted message material and budget references.
CREATE TABLE outbox_operations (
    operation_id TEXT NOT NULL PRIMARY KEY,
    recipient TEXT NOT NULL,
    kind BIGINT NOT NULL,
    request_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared','paying','paid','sent','acked','released','payment_unknown','rejected_retryable','failed_paid')),
    payment_hash TEXT,
    admission_payment_hash TEXT,
    message_id TEXT,
    settled_msat BIGINT NOT NULL,
    readmission_msat BIGINT NOT NULL,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL,
    last_sent_at BIGINT,
    attempts BIGINT NOT NULL,
    last_error TEXT,
    version BIGINT NOT NULL,
    recovery BYTEA NOT NULL
);
CREATE INDEX outbox_operations_message ON outbox_operations(message_id, recipient);
CREATE INDEX outbox_operations_state ON outbox_operations(state);

-- Existing paid deliveries retain a queryable synthetic receipt. They cannot
-- bind a new compose request because their original plaintext hash is unknown.
INSERT INTO outbox_operations (operation_id, recipient, kind, request_hash, state, payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery)
SELECT 'legacy:' || p.message_id || ':' || p.recipient_id, p.recipient_id, m.kind, '',
       CASE WHEN p.state = 'failed_paid' THEN 'failed_paid' WHEN p.dispatched = 1 THEN 'sent' ELSE 'paid' END,
       m.payment_hash, m.id, m.amount_msat, 0, CAST(EXTRACT(EPOCH FROM NOW()) * 1000 AS BIGINT), CAST(EXTRACT(EPOCH FROM NOW()) * 1000 AS BIGINT),
       CASE WHEN p.dispatched = 1 THEN CAST(EXTRACT(EPOCH FROM NOW()) * 1000 AS BIGINT) ELSE NULL END, p.attempts, p.rejection_reason, 0, decode('', 'hex')
FROM pending_deliveries p JOIN messages m ON m.id = p.message_id;

INSERT INTO _konsensus_migrations (version, name) VALUES (24, 'outbox operations');
-- Migration 25: outbox recovery
-- Keep old opaque (possibly encrypted) recovery blobs conservative until one
-- successful accounting sweep. Never inspect/decrypt application data in SQL.
ALTER TABLE outbox_operations ADD COLUMN accounting_pending BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE outbox_operations ADD COLUMN recovery_compacted BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX outbox_operations_recovery ON outbox_operations(created_at)
WHERE accounting_pending = TRUE OR state IN ('paying', 'payment_unknown', 'paid', 'sent', 'rejected_retryable');
CREATE INDEX outbox_operations_retention ON outbox_operations(updated_at)
WHERE accounting_pending = FALSE AND recovery_compacted = FALSE AND state IN ('acked', 'failed_paid');

INSERT INTO _konsensus_migrations (version, name) VALUES (25, 'outbox recovery');
-- Migration 26: outstanding web requests
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

INSERT INTO _konsensus_migrations (version, name) VALUES (26, 'outstanding web requests');
-- Migration 27: call state
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

INSERT INTO _konsensus_migrations (version, name) VALUES (27, 'call state');
-- Migration 28: call request hold
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

INSERT INTO _konsensus_migrations (version, name) VALUES (28, 'call request hold');
-- Migration 29: operation abandon
ALTER TABLE outbox_operations DROP CONSTRAINT outbox_operations_state_check;
ALTER TABLE outbox_operations ADD CONSTRAINT outbox_operations_state_check
CHECK (state IN ('prepared','paying','paid','sent','acked','released','payment_unknown','rejected_retryable','failed_paid','abandoned'));
DROP INDEX outbox_operations_retention;
CREATE INDEX outbox_operations_retention ON outbox_operations(updated_at)
WHERE accounting_pending = FALSE AND recovery_compacted = FALSE AND state IN ('acked', 'failed_paid', 'released', 'abandoned');

INSERT INTO _konsensus_migrations (version, name) VALUES (29, 'operation abandon');
-- Migration 30: channel open operations
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

INSERT INTO _konsensus_migrations (version, name) VALUES (30, 'channel open operations');
-- Migration 31: starter requests
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

INSERT INTO _konsensus_migrations (version, name) VALUES (31, 'starter requests');
-- Migration 32: starter queries
-- Indexed request lookups, bounded recovery/status pages, and requester pruning.
CREATE INDEX starter_grants_requester_time ON starter_grants(requester_node_id, created_at DESC, request_id DESC);
CREATE INDEX starter_grants_work ON starter_grants(request_id) WHERE state IN ('admitted','opening','resolved');
CREATE INDEX starter_grants_invite ON starter_grants(invite_id);
CREATE INDEX starter_grants_recent ON starter_grants(updated_at, request_id);
CREATE INDEX starter_grants_inflight ON starter_grants(state) WHERE state IN ('admitted','opening');
CREATE INDEX starter_grants_committed ON starter_grants(capacity_sats) WHERE state <> 'refused';
CREATE INDEX starter_grants_day ON starter_grants(utc_day) WHERE state <> 'refused';
CREATE INDEX starter_invites_requester ON invites_issued(invitee_pubkey, state, created_at DESC);
CREATE INDEX starter_invites_unsettled ON invites_issued(state, id) WHERE state IN ('pending','opening');
-- Upgrade old installations too: keep only the newest refusal per requester.
DELETE FROM starter_grants WHERE request_id IN (
 SELECT request_id FROM (
  SELECT request_id, ROW_NUMBER() OVER (PARTITION BY requester_node_id ORDER BY created_at DESC, request_id DESC) AS rank
  FROM starter_grants WHERE state='refused'
 ) ranked WHERE rank > 1
);
-- A live reservation already supplies the throttle and replay response.
DELETE FROM starter_grants WHERE state='refused' AND requester_node_id IN (
 SELECT requester_node_id FROM starter_grants WHERE state<>'refused'
);

INSERT INTO _konsensus_migrations (version, name) VALUES (32, 'starter queries');
