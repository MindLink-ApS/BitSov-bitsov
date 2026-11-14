-- Frozen origin/main a745318ecfaff7ddb55df6e0fa6472c14c7b2e47 migrations through 032.

-- 001_initial.sql
-- Konsensus v2 initial schema
-- Shared between SQLite and PostgreSQL (compatible subset)

-- UKM envelopes (E2EE ciphertext only — never plaintext, Principle 4)
CREATE TABLE IF NOT EXISTS messages (
    id            TEXT PRIMARY KEY,
    kind          INTEGER NOT NULL,
    sender        TEXT NOT NULL,
    recipient_type TEXT NOT NULL,
    recipient_id  TEXT NOT NULL,
    timestamp_ms  INTEGER NOT NULL,
    ciphertext    BLOB NOT NULL,
    payment_hash  TEXT NOT NULL,
    preimage      TEXT NOT NULL,
    amount_msat   INTEGER NOT NULL,
    signature     TEXT NOT NULL,
    nonce         TEXT NOT NULL,
    references_json TEXT NOT NULL DEFAULT '[]',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient
    ON messages(recipient_type, recipient_id, timestamp_ms DESC);

CREATE INDEX IF NOT EXISTS idx_messages_sender
    ON messages(sender, timestamp_ms DESC);

-- Group chat rooms
CREATE TABLE IF NOT EXISTS rooms (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

-- Room membership
CREATE TABLE IF NOT EXISTS room_members (
    room_id       TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    node_id       TEXT NOT NULL,
    joined_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    role          TEXT NOT NULL DEFAULT 'member',
    PRIMARY KEY (room_id, node_id)
);

-- Known peers
CREATE TABLE IF NOT EXISTS peers (
    node_id       TEXT PRIMARY KEY,
    address       TEXT,
    last_seen     TEXT,
    display_name  TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

-- Nonces for replay protection
CREATE TABLE IF NOT EXISTS nonces (
    nonce_hex     TEXT PRIMARY KEY,
    sender        TEXT NOT NULL,
    received_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_nonces_sender ON nonces(sender);


-- 002_sessions.sql
-- E2EE session state persistence
-- Stores serialized Double Ratchet state per peer, encrypted at rest.
-- Enables session resumption across node restarts without re-running X3DH.

CREATE TABLE IF NOT EXISTS sessions (
    peer_id       TEXT PRIMARY KEY,
    state_blob    BLOB NOT NULL,
    established_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);


-- 003_pending_deliveries.sql
-- Pending message delivery queue.
-- Tracks messages that could not be delivered because the recipient peer
-- was offline. The node retries delivery when the peer reconnects.

CREATE TABLE IF NOT EXISTS pending_deliveries (
    message_id    TEXT NOT NULL,
    recipient_id  TEXT NOT NULL,
    queued_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    attempts      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (message_id, recipient_id)
);

CREATE INDEX IF NOT EXISTS idx_pending_recipient ON pending_deliveries(recipient_id);


-- 004_files.sql
-- File metadata and encrypted blob storage.
-- Files are E2EE encrypted before storage (same as message ciphertext).
-- The `data` column holds the encrypted file bytes (BLOB).
-- For the mesh network, files are transferred inline in UKM envelopes
-- (KIND_FILE_REF = 200) and stored by both sender and receiver.

CREATE TABLE IF NOT EXISTS files (
    id            TEXT PRIMARY KEY,
    filename      TEXT NOT NULL,
    mime_type     TEXT NOT NULL DEFAULT 'application/octet-stream',
    size_bytes    INTEGER NOT NULL,
    blake3_hash   TEXT NOT NULL,
    sender        TEXT NOT NULL,
    message_id    TEXT,
    data          BLOB NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_files_sender ON files(sender);
CREATE INDEX IF NOT EXISTS idx_files_message ON files(message_id);
CREATE INDEX IF NOT EXISTS idx_files_created ON files(created_at DESC);


-- 005_message_plaintext.sql
-- Migration 005: Add encrypted plaintext cache for decrypted messages.
-- The node decrypts incoming E2EE messages and caches the plaintext (AES-encrypted
-- at rest) so the local REST API can return it. This enables the sovereign browser
-- and other features that need to poll for decrypted content.
-- The plaintext_enc column stores AES-256-GCM encrypted data, never raw plaintext.

ALTER TABLE messages ADD COLUMN plaintext_enc BLOB;


-- 006_pending_deliveries_fk.sql
-- Add foreign key constraint: pending_deliveries.message_id → messages.id
-- with ON DELETE CASCADE so retention cleanup automatically removes
-- orphaned pending deliveries.
--
-- SQLite does not support ALTER TABLE ADD CONSTRAINT, so we recreate
-- the table. The PRAGMA foreign_keys = ON statement must be issued
-- per-connection (handled in the Rust connection setup).

CREATE TABLE IF NOT EXISTS pending_deliveries_new (
    message_id    TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    recipient_id  TEXT NOT NULL,
    queued_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    attempts      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (message_id, recipient_id)
);

INSERT OR IGNORE INTO pending_deliveries_new (message_id, recipient_id, queued_at, attempts)
    SELECT message_id, recipient_id, queued_at, attempts
    FROM pending_deliveries
    WHERE message_id IN (SELECT id FROM messages);

DROP TABLE IF EXISTS pending_deliveries;

ALTER TABLE pending_deliveries_new RENAME TO pending_deliveries;

CREATE INDEX IF NOT EXISTS idx_pending_recipient ON pending_deliveries(recipient_id);


-- 007_fiat_rate_snapshots.sql
-- Migration 007: daily fiat exchange-rate snapshots for tax reporting.
--
-- One row per (date, currency).  The background snapshot task writes at 00:00 UTC
-- using upsert semantics, so restarting the node on the same day is idempotent.
-- The tax-export handler reads this table to denominate Lightning payments in the
-- user's local currency on the transaction date.

CREATE TABLE IF NOT EXISTS fiat_rate_snapshots (
    date       TEXT NOT NULL,  -- ISO-8601 date, e.g. "2026-04-21"
    currency   TEXT NOT NULL,  -- ISO 4217 code, e.g. "USD"
    rate       REAL NOT NULL,  -- fiat units per 1 BTC (always positive)
    source     TEXT NOT NULL,  -- data provider name, e.g. "MempoolSpace"
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (date, currency)
);

CREATE INDEX IF NOT EXISTS idx_fiat_rate_snapshots_date
    ON fiat_rate_snapshots (date DESC);


-- 008_recovery.sql
-- Recovery support: schemes, trustees (outbound), and shards (inbound).
--
-- recovery_schemes   : a key-recovery configuration for this node (e.g. Shamir 2-of-3).
-- recovery_trustees  : trustees who hold shards of THIS node\'s key (outbound).
-- recovery_shards    : shards THIS node holds on behalf of other nodes (inbound).
--                      shard_ciphertext is AES-256-GCM encrypted at rest.

CREATE TABLE IF NOT EXISTS recovery_schemes (
    id            TEXT    PRIMARY KEY,
    scheme_type   TEXT    NOT NULL,
    threshold     INTEGER NOT NULL CHECK (threshold > 0),
    total_shares  INTEGER NOT NULL CHECK (total_shares >= threshold),
    metadata_json TEXT    NOT NULL DEFAULT '{}',
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_trustees (
    id               TEXT    PRIMARY KEY,
    scheme_id        TEXT    NOT NULL REFERENCES recovery_schemes(id) ON DELETE CASCADE,
    trustee_node_id  TEXT    NOT NULL,
    share_index      INTEGER NOT NULL,
    shard_commitment TEXT,
    delivered_at     TEXT,
    created_at       TEXT    NOT NULL,
    UNIQUE (scheme_id, trustee_node_id),
    UNIQUE (scheme_id, share_index)
);

CREATE INDEX IF NOT EXISTS idx_recovery_trustees_scheme ON recovery_trustees(scheme_id);
CREATE INDEX IF NOT EXISTS idx_recovery_trustees_node   ON recovery_trustees(trustee_node_id);

CREATE TABLE IF NOT EXISTS recovery_shards (
    id                   TEXT    PRIMARY KEY,
    owner_node_id        TEXT    NOT NULL,
    share_index          INTEGER NOT NULL,
    shard_ciphertext     BLOB    NOT NULL,
    scheme_metadata_json TEXT    NOT NULL DEFAULT '{}',
    received_at          TEXT    NOT NULL,
    UNIQUE (owner_node_id, share_index)
);

CREATE INDEX IF NOT EXISTS idx_recovery_shards_owner ON recovery_shards(owner_node_id);


-- 009_contacts.sql
-- Contact book: known peers with local annotations, trust signals, and avatar dedup.
--
-- avatar_blake3 references files.blake3_hash for blob deduplication — avatars
-- are stored once in the files table and referenced by content-addressed hash.
--
-- Upsert semantics: updated_at guards stale writes.  A row is only updated when
-- the incoming updated_at is strictly greater than the stored value, preventing
-- out-of-order sync from overwriting newer local edits.

CREATE TABLE IF NOT EXISTS contacts (
    node_id                  TEXT PRIMARY KEY,
    local_alias              TEXT,
    claimed_name             TEXT,
    profile_json             TEXT NOT NULL DEFAULT '{}',
    -- blake3 hash of the avatar blob; blob lives in files.blake3_hash (dedup).
    avatar_blake3            TEXT,
    verified_identities_json TEXT NOT NULL DEFAULT '[]',
    muted                    INTEGER NOT NULL DEFAULT 0 CHECK(muted IN (0, 1)),
    blocked                  INTEGER NOT NULL DEFAULT 0 CHECK(blocked IN (0, 1)),
    tags_json                TEXT NOT NULL DEFAULT '[]',
    notes                    TEXT,
    created_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at               TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_contacts_blocked    ON contacts(blocked);
CREATE INDEX IF NOT EXISTS idx_contacts_muted      ON contacts(muted);
CREATE INDEX IF NOT EXISTS idx_contacts_updated    ON contacts(updated_at DESC);


-- 010_invites_issued.sql
-- Track ON-B (Tier-2 onboarding) — invites the inviter has issued.
--
-- Each row represents a BitSovInvite produced by this node's
-- POST /api/v1/invites endpoint (ONB2). The runner stamps state='pending'
-- on issuance; the invitee's first Noise_XX handshake flips it to 'accepted'
-- via the auto-channel-open trigger (ONB5). Operator can revoke a pending
-- invite via DELETE /api/v1/invites/:id.
--
-- ADR: docs/v2/ADR-029-invite-token-scheme.md.
-- Code surface: crates/konsensus-core/src/invite.rs (BitSovInvite type),
-- crates/konsensus-api/src/handlers/invites.rs (handlers, ONB2/ONB4/ONB5).

CREATE TABLE IF NOT EXISTS invites_issued (
    -- UUID v4 in canonical 16-byte form (BLOB) for compact storage.
    id                          BLOB    PRIMARY KEY,

    -- The recipient pubkey this invite is bound to (Ed25519, 32 bytes raw).
    invitee_pubkey              BLOB    NOT NULL,

    -- Unix seconds after which the invite is invalid (verify() rejects).
    expiry_unix                 INTEGER NOT NULL,

    -- Inviter's hint for channel capacity if invitee chose Light tier.
    -- NULL = use operator default (currently 50_000 sats per ADR-029).
    channel_size_hint_sats      INTEGER,

    -- Per-invite 16-byte random nonce (BLOB) included in signed canonical
    -- bytes. Ensures unique signatures across re-issues to the same pubkey.
    nonce                       BLOB    NOT NULL,

    -- Lifecycle: 'pending' (issued, not yet redeemed)
    --           | 'accepted' (invitee connected, ON-B5 auto-channel-open fired)
    --           | 'revoked' (operator deleted before acceptance).
    state                       TEXT    NOT NULL DEFAULT 'pending'
                                          CHECK(state IN ('pending','accepted','revoked')),

    created_at                  INTEGER NOT NULL,
    accepted_at                 INTEGER,
    revoked_at                  INTEGER
);

-- Fast lookup by invitee_pubkey when the invitee comes online (ONB5).
CREATE INDEX IF NOT EXISTS idx_invites_issued_invitee
    ON invites_issued(invitee_pubkey);

-- Fast lookup by state for the operator's invite-management panel (ONB10).
CREATE INDEX IF NOT EXISTS idx_invites_issued_state
    ON invites_issued(state);


-- 011_accepted_invites.sql
-- Track ON-B (Tier-2 onboarding) — invites this node has accepted as invitee.
--
-- One row per redeemed BitSovInvite, indexed by the invite's nonce.
-- ONB3's POST /api/v1/invites/accept handler inserts a row before adding
-- the inviter to the whitelist; a second presentation of the same invite
-- hits the PRIMARY KEY constraint and is rejected with HTTP 409.
--
-- This is the replay-protection surface called out in BitSovInvite::verify()
-- docstring: "Replay protection (nonce single-use) is the caller's
-- responsibility; this function intentionally has no state."
--
-- ADR: docs/v2/ADR-029-invite-token-scheme.md "Single-use enforcement".

CREATE TABLE IF NOT EXISTS accepted_invites (
    -- 16-byte nonce from the redeemed BitSovInvite (BLOB).
    -- PRIMARY KEY → second redemption of the same invite is rejected.
    nonce               BLOB    PRIMARY KEY,

    -- Inviter's Ed25519 pubkey (32 bytes raw) — recorded so operator
    -- audits can answer "who invited me?" without parsing the original token.
    inviter_pubkey      BLOB    NOT NULL,

    -- Original expiry timestamp (Unix seconds) — for audit trail; verify()
    -- already rejected expired invites at acceptance time.
    expiry_unix         INTEGER NOT NULL,

    -- When the invitee accepted (Unix seconds).
    accepted_at         INTEGER NOT NULL
);

-- Audit lookup by inviter (useful when revoking a relationship).
CREATE INDEX IF NOT EXISTS idx_accepted_invites_inviter
    ON accepted_invites(inviter_pubkey);


-- 012_onboarding_state.sql
-- Track ON-B (Tier-2 onboarding) — single-row state machine for the
-- invitee-side onboarding flow.
--
-- ONB6's funding-poll service writes this row when the invitee chooses
-- Full tier; the frontend's OnboardingView (ONB7+) polls GET
-- /api/v1/onboarding/state for ceremony progress updates.
--
-- Single row enforced via PRIMARY KEY CHECK(id=1) — there is only one
-- ongoing onboarding per node.
--
-- ADR: docs/v2/ADR-029-invite-token-scheme.md "Funding ceremony".

CREATE TABLE IF NOT EXISTS onboarding_state (
    -- Always 1 — enforced single-row.
    id                              INTEGER PRIMARY KEY CHECK(id = 1),

    -- Steps: 'paste-invite' (invitee about to paste a token)
    --       | 'accepting' (token parsed, signature verified, whitelist added)
    --       | 'funding' (Full-tier: awaiting on-chain funding)
    --       | 'funding-confirmed' (1+ confirmations received)
    --       | 'connecting' (Noise_XX handshake to inviter in progress)
    --       | 'first-message' (channel open, send-first-message wizard)
    --       | 'complete' (done; frontend transitions to ChatView).
    current_step                    TEXT    NOT NULL DEFAULT 'paste-invite',

    -- Full-tier funding ceremony (NULL for Light tier).
    funding_address                 TEXT,
    funding_amount_sats_required    INTEGER,
    funding_amount_sats_received    INTEGER NOT NULL DEFAULT 0,

    -- Last time the chain-poll task checked the funding address (Unix seconds).
    -- NULL until the first poll completes.
    last_poll_at                    INTEGER
);

-- Seed the single row so handlers can UPDATE rather than INSERT-on-first-use.
INSERT INTO onboarding_state (id, current_step) VALUES (1, 'paste-invite')
    ON CONFLICT(id) DO NOTHING;


-- 013_operator_hosting_contracts.sql
-- Operator hosting contracts and payment ledger.
-- MANUAL: deploy only after operator review; this table tracks real hosting
-- payment state for cloud-tier nodes.

CREATE TABLE IF NOT EXISTS operator_hosting_contracts (
    id              TEXT PRIMARY KEY,
    tenant_pubkey   TEXT NOT NULL,
    operator_pubkey TEXT NOT NULL,
    sats_per_day    INTEGER NOT NULL CHECK (sats_per_day > 0),
    started_at      INTEGER NOT NULL,
    last_paid_at    INTEGER,
    state           TEXT NOT NULL DEFAULT 'active'
                    CHECK (state IN ('active', 'overdue', 'paused', 'stopped')),
    updated_at      INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_operator_hosting_contracts_tenant
    ON operator_hosting_contracts(tenant_pubkey);

CREATE INDEX IF NOT EXISTS idx_operator_hosting_contracts_state
    ON operator_hosting_contracts(state);

CREATE TABLE IF NOT EXISTS operator_hosting_payments (
    payment_hash    TEXT PRIMARY KEY,
    contract_id     TEXT NOT NULL,
    tenant_pubkey   TEXT NOT NULL,
    operator_pubkey TEXT NOT NULL,
    amount_msat     INTEGER NOT NULL CHECK (amount_msat > 0),
    paid_at         INTEGER NOT NULL,
    direction       TEXT NOT NULL CHECK (direction IN ('incoming', 'outgoing')),
    preimage        TEXT,
    memo            TEXT,
    created_at      INTEGER NOT NULL,
    FOREIGN KEY (contract_id) REFERENCES operator_hosting_contracts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_operator_hosting_payments_contract
    ON operator_hosting_payments(contract_id, paid_at DESC);

CREATE INDEX IF NOT EXISTS idx_operator_hosting_payments_tenant
    ON operator_hosting_payments(tenant_pubkey, paid_at DESC);


-- 014_invite_v2_fields.sql
-- ONB5a: BitSovInvite v2 signed dial target and channel-open bounds.
--
-- Existing rows were issued as v1 invites; defaults preserve backward
-- compatibility while new v2 rows populate all three fields.

ALTER TABLE invites_issued
    ADD COLUMN addr TEXT NOT NULL DEFAULT '';

ALTER TABLE invites_issued
    ADD COLUMN max_fee_rate_sat_per_vb INTEGER;

ALTER TABLE invites_issued
    ADD COLUMN channel_open_intent_expiry_unix INTEGER;


-- 015_invite_expired_state.sql
-- ONB5: add explicit terminal state for channel-open intents that expired
-- before the invitee came online.

CREATE TABLE invites_issued_onb5_new (
    id                                  BLOB    PRIMARY KEY,
    invitee_pubkey                      BLOB    NOT NULL,
    expiry_unix                         INTEGER NOT NULL,
    channel_size_hint_sats              INTEGER,
    addr                                TEXT    NOT NULL DEFAULT '',
    max_fee_rate_sat_per_vb             INTEGER,
    channel_open_intent_expiry_unix     INTEGER,
    nonce                               BLOB    NOT NULL,
    state                               TEXT    NOT NULL DEFAULT 'pending'
                                                  CHECK(state IN ('pending','accepted','revoked','expired')),
    created_at                          INTEGER NOT NULL,
    accepted_at                         INTEGER,
    revoked_at                          INTEGER
);

INSERT INTO invites_issued_onb5_new (
    id,
    invitee_pubkey,
    expiry_unix,
    channel_size_hint_sats,
    addr,
    max_fee_rate_sat_per_vb,
    channel_open_intent_expiry_unix,
    nonce,
    state,
    created_at,
    accepted_at,
    revoked_at
)
SELECT
    id,
    invitee_pubkey,
    expiry_unix,
    channel_size_hint_sats,
    addr,
    max_fee_rate_sat_per_vb,
    channel_open_intent_expiry_unix,
    nonce,
    state,
    created_at,
    accepted_at,
    revoked_at
FROM invites_issued;

DROP TABLE invites_issued;
ALTER TABLE invites_issued_onb5_new RENAME TO invites_issued;

CREATE INDEX IF NOT EXISTS idx_invites_issued_invitee
    ON invites_issued(invitee_pubkey);

CREATE INDEX IF NOT EXISTS idx_invites_issued_state
    ON invites_issued(state);


-- 016_invite_opening_state.sql
-- ONB5d: add in-flight state for idempotent auto-channel opens

CREATE TABLE invites_issued_onb5d_new (
    id                                BLOB PRIMARY KEY,
    invitee_pubkey                    BLOB NOT NULL,
    expiry_unix                       INTEGER NOT NULL,
    channel_size_hint_sats            INTEGER,
    addr                              TEXT NOT NULL DEFAULT '',
    max_fee_rate_sat_per_vb           INTEGER,
    channel_open_intent_expiry_unix   INTEGER,
    nonce                             BLOB NOT NULL UNIQUE,
    state                             TEXT NOT NULL DEFAULT 'pending'
                                      CHECK(state IN ('pending','accepted','opening','revoked','expired')),
    created_at                        INTEGER NOT NULL,
    accepted_at                       INTEGER,
    revoked_at                        INTEGER
);

INSERT INTO invites_issued_onb5d_new (
    id,
    invitee_pubkey,
    expiry_unix,
    channel_size_hint_sats,
    addr,
    max_fee_rate_sat_per_vb,
    channel_open_intent_expiry_unix,
    nonce,
    state,
    created_at,
    accepted_at,
    revoked_at
)
SELECT
    id,
    invitee_pubkey,
    expiry_unix,
    channel_size_hint_sats,
    addr,
    max_fee_rate_sat_per_vb,
    channel_open_intent_expiry_unix,
    nonce,
    state,
    created_at,
    accepted_at,
    revoked_at
FROM invites_issued;

DROP TABLE invites_issued;
ALTER TABLE invites_issued_onb5d_new RENAME TO invites_issued;

CREATE INDEX IF NOT EXISTS idx_invites_issued_invitee
    ON invites_issued(invitee_pubkey);

CREATE INDEX IF NOT EXISTS idx_invites_issued_state
    ON invites_issued(state);


-- 017_onboarding_state_funding_evidence.sql
-- ONB6 onboarding-state compatibility migration:
-- add tier/evidence fields and keep funding progress columns explicit.

ALTER TABLE onboarding_state
    ADD COLUMN tier TEXT;

ALTER TABLE onboarding_state
    ADD COLUMN funding_evidence TEXT;


-- 018_onboarding_state_scope.sql
-- ONB5f replayable progress scoping:
-- track which invite/peer the single-row onboarding state belongs to so
-- normal mesh reconnects cannot regress or advance an unrelated flow.

ALTER TABLE onboarding_state
    ADD COLUMN invite_id TEXT;

ALTER TABLE onboarding_state
    ADD COLUMN inviter_pubkey BLOB;

ALTER TABLE onboarding_state
    ADD COLUMN inviter_ln_pubkey TEXT;


-- 019_payment_receipts.sql
-- Accepted Lightning payment hashes for economic replay protection.
--
-- Nonces reject identical envelope replays. This table rejects a fresh envelope
-- that reuses the same settled Lightning payment proof with a different nonce.
CREATE TABLE IF NOT EXISTS payment_receipts (
    payment_hash TEXT PRIMARY KEY,
    message_id   TEXT NOT NULL,
    sender       TEXT NOT NULL,
    received_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_payment_receipts_sender
    ON payment_receipts(sender, received_at DESC);


-- 020_pending_delivery_state.sql
ALTER TABLE pending_deliveries ADD COLUMN state TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE pending_deliveries ADD COLUMN dispatched INTEGER NOT NULL DEFAULT 0;
-- Existing rows were queued by a previous send attempt.
UPDATE pending_deliveries SET dispatched = 1;


-- 021_paid_delivery_rejections.sql
-- Keep migration 020 byte-identical for databases that already applied it.
-- Its dispatched=1 backfill cannot distinguish offline rows. Re-establish
-- dispatch authority on the next send; paid identity makes replay safe.
UPDATE pending_deliveries SET dispatched = 0;
ALTER TABLE pending_deliveries ADD COLUMN retry_after_ms BIGINT NOT NULL DEFAULT 0;
ALTER TABLE pending_deliveries ADD COLUMN rejection_reason TEXT;

-- An acceptance tombstone survives message deletion/retention. Only orphaned
-- legacy receipts may heal; receipts already backed by messages are spent.
ALTER TABLE payment_receipts ADD COLUMN accepted INTEGER NOT NULL DEFAULT 0;
UPDATE payment_receipts SET accepted = 1 WHERE EXISTS (
    SELECT 1 FROM messages WHERE messages.id = payment_receipts.message_id
        AND messages.sender = payment_receipts.sender
        AND messages.payment_hash = payment_receipts.payment_hash
);


-- 022_receipt_bindings.sql
-- Durable acceptance evidence survives content retention for duplicate ACKs.
ALTER TABLE payment_receipts ADD COLUMN kind INTEGER;
ALTER TABLE payment_receipts ADD COLUMN recipient_type TEXT;
ALTER TABLE payment_receipts ADD COLUMN recipient_id TEXT;
ALTER TABLE payment_receipts ADD COLUMN preimage TEXT;
ALTER TABLE payment_receipts ADD COLUMN amount_msat BIGINT;
ALTER TABLE payment_receipts ADD COLUMN nonce TEXT;
ALTER TABLE payment_receipts ADD COLUMN references_json TEXT;
UPDATE payment_receipts SET (kind, recipient_type, recipient_id, preimage, amount_msat, nonce, references_json) = (SELECT m.kind, m.recipient_type, m.recipient_id, m.preimage, m.amount_msat, m.nonce, m.references_json FROM messages m WHERE m.id = payment_receipts.message_id AND m.sender = payment_receipts.sender AND m.payment_hash = payment_receipts.payment_hash) WHERE accepted = 1;


-- 023_delivery_price_quotes.sql
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


-- 024_outbox_operations.sql
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
    recovery BLOB NOT NULL
);
CREATE INDEX outbox_operations_message ON outbox_operations(message_id, recipient);
CREATE INDEX outbox_operations_state ON outbox_operations(state);

-- Existing paid deliveries retain a queryable synthetic receipt. They cannot
-- bind a new compose request because their original plaintext hash is unknown.
INSERT INTO outbox_operations (operation_id, recipient, kind, request_hash, state, payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery)
SELECT 'legacy:' || p.message_id || ':' || p.recipient_id, p.recipient_id, m.kind, '',
       CASE WHEN p.state = 'failed_paid' THEN 'failed_paid' WHEN p.dispatched = 1 THEN 'sent' ELSE 'paid' END,
       m.payment_hash, m.id, m.amount_msat, 0, CAST(strftime('%s', 'now') AS BIGINT) * 1000, CAST(strftime('%s', 'now') AS BIGINT) * 1000,
       CASE WHEN p.dispatched = 1 THEN CAST(strftime('%s', 'now') AS BIGINT) * 1000 ELSE NULL END, p.attempts, p.rejection_reason, 0, X''
FROM pending_deliveries p JOIN messages m ON m.id = p.message_id;


-- 025_outbox_recovery.sql
-- Keep old opaque (possibly encrypted) recovery blobs conservative until one
-- successful accounting sweep. Never inspect/decrypt application data in SQL.
ALTER TABLE outbox_operations ADD COLUMN accounting_pending BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE outbox_operations ADD COLUMN recovery_compacted BOOLEAN NOT NULL DEFAULT FALSE;
CREATE INDEX outbox_operations_recovery ON outbox_operations(created_at)
WHERE accounting_pending = TRUE OR state IN ('paying', 'payment_unknown', 'paid', 'sent', 'rejected_retryable');
CREATE INDEX outbox_operations_retention ON outbox_operations(updated_at)
WHERE accounting_pending = FALSE AND recovery_compacted = FALSE AND state IN ('acked', 'failed_paid');


-- 026_outstanding_web_requests.sql
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


-- 027_call_state.sql
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


-- 028_call_request_hold.sql
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


-- 029_operation_abandon.sql
-- SQLite cannot extend a CHECK constraint in place. Rebuild transactionally,
-- preserving opaque recovery bytes, receipt metadata and CAS versions exactly.
CREATE TABLE outbox_operations_abandon (
    operation_id TEXT NOT NULL PRIMARY KEY,
    recipient TEXT NOT NULL,
    kind BIGINT NOT NULL,
    request_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('prepared','paying','paid','sent','acked','released','payment_unknown','rejected_retryable','failed_paid','abandoned')),
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
    recovery BLOB NOT NULL,
    accounting_pending BOOLEAN NOT NULL DEFAULT TRUE,
    recovery_compacted BOOLEAN NOT NULL DEFAULT FALSE
);
INSERT INTO outbox_operations_abandon (operation_id, recipient, kind, request_hash, state, payment_hash, admission_payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery, accounting_pending, recovery_compacted)
SELECT operation_id, recipient, kind, request_hash, state, payment_hash, admission_payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery, accounting_pending, recovery_compacted FROM outbox_operations;
DROP TABLE outbox_operations;
ALTER TABLE outbox_operations_abandon RENAME TO outbox_operations;
CREATE INDEX outbox_operations_message ON outbox_operations(message_id, recipient);
CREATE INDEX outbox_operations_state ON outbox_operations(state);
CREATE INDEX outbox_operations_recovery ON outbox_operations(created_at)
WHERE accounting_pending = TRUE OR state IN ('paying', 'payment_unknown', 'paid', 'sent', 'rejected_retryable');
CREATE INDEX outbox_operations_retention ON outbox_operations(updated_at)
WHERE accounting_pending = FALSE AND recovery_compacted = FALSE AND state IN ('acked', 'failed_paid', 'released', 'abandoned');


-- 030_channel_open_operations.sql
-- open-channel idempotency (#331): the caller's operation_id is recorded before
-- dispatch, so a retry after a timeout never opens a second channel.
CREATE TABLE IF NOT EXISTS channel_open_operations (
    operation_id TEXT NOT NULL PRIMARY KEY,
    request_hash TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending','uncertain','opened')),
    request BLOB NOT NULL,
    result BLOB,
    last_error TEXT,
    created_at BIGINT NOT NULL,
    updated_at BIGINT NOT NULL
);


-- 031_starter_requests.sql
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


-- 032_starter_queries.sql
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
