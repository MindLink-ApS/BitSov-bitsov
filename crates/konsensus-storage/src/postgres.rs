//! PostgreSQL storage backend using sqlx.
//!
//! Same schema and trait implementation as SQLite, but uses PostgreSQL
//! for T2 Standard and above sovereignty tiers.

use async_trait::async_trait;
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::str::FromStr;

use konsensus_core::{
    HostingContractState, MessageId, NodeId, Nonce, OperatorHostingContract,
    OperatorHostingPayment, OperatorHostingPaymentDirection, PaymentProof, Recipient,
    RoomId, Signature, UkmEnvelope,
};

use crate::calendar::{CalendarEventRecord, RsvpRecord};
use crate::error::StorageError;
use crate::invites::{
    AcceptedInviteRecord, InviteIssuedRecord, InviteSchemaCapabilities, InviteState,
};
use crate::models::{FileMetadata, FileRecord, OnboardingStateRecord, Peer, Room};
use crate::traits::Storage;

/// PostgreSQL-backed storage for T2+ sovereignty tiers.
pub struct PostgresStorage {
    pool: PgPool,
}

impl PostgresStorage {
    /// Connect to a PostgreSQL database and run migrations.
    pub async fn connect(url: &str) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(url)
            .await?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    /// Run incremental, tracked migrations (PostgreSQL-compatible).
    ///
    /// Each migration runs exactly once, tracked in `_konsensus_migrations`.
    /// Migration numbers match the SQLite migration files for parity.
    async fn run_migrations(&self) -> Result<(), StorageError> {
        // Create migration tracking table
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS _konsensus_migrations (\
                 version INTEGER PRIMARY KEY, \
                 name TEXT NOT NULL, \
                 applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
             )",
        )
        .execute(&self.pool)
        .await?;

        // Detect existing databases upgraded from the old monolithic migration.
        // If tables exist but no migration records, seed versions 1-5 as applied.
        let applied: Vec<i32> =
            sqlx::query_scalar("SELECT version FROM _konsensus_migrations ORDER BY version")
                .fetch_all(&self.pool)
                .await?;

        if applied.is_empty() {
            // Check if this is an existing database (messages table already exists)
            let table_exists: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM information_schema.tables \
                 WHERE table_name = 'messages')",
            )
            .fetch_one(&self.pool)
            .await
            .unwrap_or(false);

            if table_exists {
                // Seed migrations 1-5 as already applied (old monolithic schema)
                for v in 1..=5 {
                    let name = Self::pg_migrations()
                        .iter()
                        .find(|(ver, _, _)| *ver == v)
                        .map(|(_, n, _)| *n)
                        .unwrap_or("unknown");
                    sqlx::query(
                        "INSERT INTO _konsensus_migrations (version, name) VALUES ($1, $2) \
                         ON CONFLICT DO NOTHING",
                    )
                    .bind(v)
                    .bind(name)
                    .execute(&self.pool)
                    .await?;
                }
                // Re-read applied versions after seeding
                let applied: Vec<i32> = sqlx::query_scalar(
                    "SELECT version FROM _konsensus_migrations ORDER BY version",
                )
                .fetch_all(&self.pool)
                .await?;
                return self.apply_pending_migrations(&applied).await;
            }
        }

        self.apply_pending_migrations(&applied).await
    }

    /// Apply any migrations not yet in the applied list.
    async fn apply_pending_migrations(&self, applied: &[i32]) -> Result<(), StorageError> {
        for (version, name, sql) in Self::pg_migrations() {
            if applied.contains(&version) {
                continue;
            }
            sqlx::query(sql).execute(&self.pool).await?;
            sqlx::query("INSERT INTO _konsensus_migrations (version, name) VALUES ($1, $2)")
                .bind(version)
                .bind(name)
                .execute(&self.pool)
                .await?;
        }

        Ok(())
    }

    /// Ordered list of PostgreSQL migrations: (version, name, sql).
    fn pg_migrations() -> Vec<(i32, &'static str, &'static str)> {
        vec![
            (
                1,
                "initial",
                r#"
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
                "#,
            ),
            (
                2,
                "sessions",
                r#"
                CREATE TABLE IF NOT EXISTS sessions (
                    peer_id       TEXT PRIMARY KEY,
                    state_blob    BYTEA NOT NULL,
                    established_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                "#,
            ),
            (
                3,
                "pending_deliveries",
                r#"
                CREATE TABLE IF NOT EXISTS pending_deliveries (
                    message_id    TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                    recipient_id  TEXT NOT NULL,
                    queued_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    attempts      INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (message_id, recipient_id)
                );
                CREATE INDEX IF NOT EXISTS idx_pending_recipient
                    ON pending_deliveries(recipient_id);
                "#,
            ),
            (
                4,
                "files",
                r#"
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
                "#,
            ),
            (
                5,
                "message_plaintext",
                "ALTER TABLE messages ADD COLUMN IF NOT EXISTS plaintext_enc BYTEA;",
            ),
            (
                6,
                "pending_deliveries_fk",
                // For PostgreSQL, the FK was added in migration 3 for new databases.
                // For existing databases that ran the old monolithic migration,
                // we add the constraint if it doesn't already exist.
                r#"
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
                "#,
            ),
            (
                10,
                "invites_issued",
                r#"
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
                "#,
            ),
            (
                11,
                "accepted_invites",
                r#"
                CREATE TABLE IF NOT EXISTS accepted_invites (
                    nonce           BYTEA   PRIMARY KEY,
                    inviter_pubkey  BYTEA   NOT NULL,
                    expiry_unix     BIGINT  NOT NULL,
                    accepted_at     BIGINT  NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_accepted_invites_inviter
                    ON accepted_invites(inviter_pubkey);
                "#,
            ),
            (
                12,
                "onboarding_state",
                r#"
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
                "#,
            ),
            (
                13,
                "operator_hosting_contracts",
                r#"
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
                "#,
            ),
            (
                14,
                "invite_v2_fields",
                r#"
                ALTER TABLE invites_issued
                    ADD COLUMN IF NOT EXISTS addr TEXT NOT NULL DEFAULT '';
                ALTER TABLE invites_issued
                    ADD COLUMN IF NOT EXISTS max_fee_rate_sat_per_vb BIGINT;
                ALTER TABLE invites_issued
                    ADD COLUMN IF NOT EXISTS channel_open_intent_expiry_unix BIGINT;
                "#,
            ),
            (
                15,
                "invite_expired_state",
                r#"
                ALTER TABLE invites_issued
                    DROP CONSTRAINT IF EXISTS invites_issued_state_check;
                ALTER TABLE invites_issued
                    ADD CONSTRAINT invites_issued_state_check
                    CHECK(state IN ('pending','accepted','revoked','expired'));
                "#,
            ),
            (
                16,
                "invite_opening_state",
                r#"
                ALTER TABLE invites_issued
                    DROP CONSTRAINT IF EXISTS invites_issued_state_check;
                ALTER TABLE invites_issued
                    ADD CONSTRAINT invites_issued_state_check
                    CHECK(state IN ('pending','accepted','opening','revoked','expired'));
                "#,
            ),
            (
                17,
                "onboarding_state_funding_evidence",
                r#"
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
                "#,
            ),
            (
                18,
                "onboarding_state_scope",
                r#"
                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS invite_id TEXT;
                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS inviter_pubkey BYTEA;
                ALTER TABLE onboarding_state
                    ADD COLUMN IF NOT EXISTS inviter_ln_pubkey TEXT;
                "#,
            ),
            (
                19,
                "payment_receipts",
                r#"
                CREATE TABLE IF NOT EXISTS payment_receipts (
                    payment_hash TEXT PRIMARY KEY,
                    message_id   TEXT NOT NULL,
                    sender       TEXT NOT NULL,
                    received_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
                CREATE INDEX IF NOT EXISTS idx_payment_receipts_sender
                    ON payment_receipts(sender, received_at DESC);
                "#,
            ),
        ]
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

// Reuse helpers from sqlite module via standalone functions
fn recipient_to_parts(r: &Recipient) -> (&'static str, String) {
    match r {
        Recipient::Node(id) => ("node", id.to_hex()),
        Recipient::Room(id) => ("room", id.to_string()),
        Recipient::Broadcast => ("broadcast", String::new()),
    }
}

fn recipient_from_parts(rtype: &str, rid: &str) -> Result<Recipient, StorageError> {
    match rtype {
        "node" => {
            let id = NodeId::from_hex(rid)
                .map_err(|e| StorageError::Conversion(format!("node id: {e}")))?;
            Ok(Recipient::Node(id))
        }
        "room" => {
            let id = RoomId::parse(rid)
                .map_err(|e| StorageError::Conversion(format!("room id: {e}")))?;
            Ok(Recipient::Room(id))
        }
        "broadcast" => Ok(Recipient::Broadcast),
        other => Err(StorageError::Conversion(format!(
            "unknown recipient type: {other}"
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
fn row_to_envelope(
    id: &str,
    kind: i64,
    sender: &str,
    recipient_type: &str,
    recipient_id: &str,
    timestamp_ms: i64,
    ciphertext: &[u8],
    payment_hash: &str,
    preimage: &str,
    amount_msat: i64,
    signature: &str,
    nonce: &str,
    references_json: &str,
) -> Result<UkmEnvelope, StorageError> {
    let sender_id =
        NodeId::from_hex(sender).map_err(|e| StorageError::Conversion(format!("sender: {e}")))?;
    let recipient = recipient_from_parts(recipient_type, recipient_id)?;

    let ph_bytes: [u8; 32] = hex::decode(payment_hash)
        .map_err(|e| StorageError::Conversion(format!("payment_hash: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("payment_hash: wrong length".into()))?;
    let pi_bytes: [u8; 32] = hex::decode(preimage)
        .map_err(|e| StorageError::Conversion(format!("preimage: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("preimage: wrong length".into()))?;
    let amount_u64 = u64::try_from(amount_msat)
        .map_err(|_| StorageError::Conversion(format!("amount_msat negative: {amount_msat}")))?;
    let proof = PaymentProof::new(ph_bytes, pi_bytes, amount_u64);

    let sig_bytes: [u8; 64] = hex::decode(signature)
        .map_err(|e| StorageError::Conversion(format!("signature: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("signature: wrong length".into()))?;
    let sig = Signature::from_bytes(sig_bytes);

    let nonce_bytes: [u8; 24] = hex::decode(nonce)
        .map_err(|e| StorageError::Conversion(format!("nonce: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("nonce: wrong length".into()))?;
    let nonce = Nonce::from_bytes(nonce_bytes);

    let refs: Vec<String> = serde_json::from_str(references_json)
        .map_err(|e| StorageError::Serialization(format!("references: {e}")))?;
    let references: Result<Vec<MessageId>, _> = refs.iter().map(|s| MessageId::from_hex(s)).collect();
    let references =
        references.map_err(|e| StorageError::Conversion(format!("reference id: {e}")))?;

    let stored_id = MessageId::from_hex(id)
        .map_err(|e| StorageError::Conversion(format!("message id: {e}")))?;

    let kind_u16 = u16::try_from(kind)
        .map_err(|_| StorageError::Conversion(format!("kind out of u16 range: {kind}")))?;
    let timestamp_u64 = u64::try_from(timestamp_ms)
        .map_err(|_| StorageError::Conversion(format!("timestamp negative: {timestamp_ms}")))?;

    Ok(UkmEnvelope {
        id: stored_id,
        kind: kind_u16,
        sender: sender_id,
        recipient,
        timestamp: timestamp_u64,
        ciphertext: ciphertext.to_vec(),
        payment_proof: proof,
        signature: sig,
        nonce,
        references,
    })
}

fn u64_to_i64(value: u64, field: &str) -> Result<i64, StorageError> {
    i64::try_from(value)
        .map_err(|_| StorageError::Conversion(format!("{field} overflows i64: {value}")))
}

fn i64_to_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::Conversion(format!("{field} negative: {value}")))
}

#[allow(clippy::too_many_arguments)]
fn row_to_hosting_contract(
    id: String,
    tenant_pubkey: String,
    operator_pubkey: String,
    sats_per_day: i64,
    started_at: i64,
    last_paid_at: Option<i64>,
    state: String,
) -> Result<OperatorHostingContract, StorageError> {
    let contract = OperatorHostingContract {
        id: uuid::Uuid::parse_str(&id)
            .map_err(|e| StorageError::Conversion(format!("hosting contract id: {e}")))?,
        tenant_pubkey: NodeId::from_hex(&tenant_pubkey)
            .map_err(|e| StorageError::Conversion(format!("tenant_pubkey: {e}")))?,
        operator_pubkey,
        sats_per_day: i64_to_u64(sats_per_day, "sats_per_day")?,
        started_at: i64_to_u64(started_at, "started_at")?,
        last_paid_at: last_paid_at
            .map(|ts| i64_to_u64(ts, "last_paid_at"))
            .transpose()?,
        state: HostingContractState::from_str(&state)
            .map_err(|e| StorageError::Conversion(e.to_string()))?,
    };
    contract
        .validate()
        .map_err(|e| StorageError::Conversion(e.to_string()))?;
    Ok(contract)
}

#[allow(clippy::too_many_arguments)]
fn row_to_hosting_payment(
    payment_hash: String,
    contract_id: String,
    tenant_pubkey: String,
    operator_pubkey: String,
    amount_msat: i64,
    paid_at: i64,
    direction: String,
    preimage: Option<String>,
    memo: Option<String>,
) -> Result<OperatorHostingPayment, StorageError> {
    Ok(OperatorHostingPayment {
        payment_hash,
        contract_id: uuid::Uuid::parse_str(&contract_id)
            .map_err(|e| StorageError::Conversion(format!("hosting contract id: {e}")))?,
        tenant_pubkey: NodeId::from_hex(&tenant_pubkey)
            .map_err(|e| StorageError::Conversion(format!("tenant_pubkey: {e}")))?,
        operator_pubkey,
        amount_msat: i64_to_u64(amount_msat, "amount_msat")?,
        paid_at: i64_to_u64(paid_at, "paid_at")?,
        direction: OperatorHostingPaymentDirection::from_str(&direction)
            .map_err(|e| StorageError::Conversion(e.to_string()))?,
        preimage,
        memo,
    })
}

/// Session-listing query for the Postgres backend. Returns ALL stored sessions —
/// deliberately **no `LIMIT`** (DBH2), mirroring the SQLite backend. `restore_sessions()`
/// reads this at boot to resume every E2EE session; a cap here silently drops the
/// overflow ratchet state (the old `LIMIT 1000` discarded the oldest by
/// `updated_at DESC`), a Principle-2 fail-open at scale. CI has no Postgres service,
/// so this path is guarded by code symmetry with SQLite plus the `dbh2_guard`
/// string-assertion test below — not a live query.
const SESSIONS_SELECT: &str = "SELECT peer_id FROM sessions ORDER BY updated_at DESC";

/// Distinct-recipient query for the Postgres backend. Returns EVERY peer with a
/// queued delivery — deliberately **no `LIMIT`** (DBH2), mirroring SQLite. A cap
/// here means a node with queued mail to more than the cap of distinct peers never
/// flushes the overflow recipients on reconnect, a Principle-2 fail-open. Guarded by
/// code symmetry with SQLite plus the `dbh2_guard` test below.
const PENDING_PEERS_SELECT: &str = "SELECT DISTINCT recipient_id FROM pending_deliveries";

/// Room-membership query for the Postgres backend. Returns ALL members of a room —
/// deliberately **no `LIMIT`** (DBH2), mirroring SQLite. The room message fan-out
/// reads this; a cap silently excludes the overflow members from delivery on a room
/// larger than the cap (old `LIMIT 10000`), a Principle-2 fail-open. Guarded by code
/// symmetry with SQLite plus the `dbh2_guard` test below.
const ROOM_MEMBERS_SELECT: &str =
    "SELECT node_id FROM room_members WHERE room_id = $1 ORDER BY joined_at";

// ── HARD-4 complete-set query constants (Postgres) ───────────────────────
//
// Mirror of the SQLite `*_SELECT` constants (see `sqlite.rs`). Same HARD-4
// classification (AUTHORITY / correctness-complete / WHERE-scoped read-surface):
// none of these queries may grow a bare `LIMIT`, which would re-create the
// DBH1/DBH2 silent fail-open. The `hard4_guard` test below asserts no `LIMIT`
// regresses in. Postgres has no `list_fiat_rate_snapshots` impl (it falls back
// to the trait default), so that constant lives only in `sqlite.rs`.

/// `get_pending_for_peer` — AUTHORITY. Per-peer outbound delivery queue; the
/// pending-delivery flusher must see the complete queue. WHERE-scoped to one
/// peer.
const PENDING_FOR_PEER_SELECT: &str =
    "SELECT message_id, attempts FROM pending_deliveries \
     WHERE recipient_id = $1 ORDER BY queued_at ASC";

/// `list_invites_issued` — AUTHORITY. Duplicate-pending-invite gate and
/// acceptance lookup; must be complete.
const INVITES_ISSUED_SELECT: &str =
    "SELECT id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at \
     FROM invites_issued ORDER BY created_at DESC";

/// `list_active_accepted_invites` — AUTHORITY. Replayed at node startup to
/// repopulate the in-memory admission whitelist. A `LIMIT` is a Principle-2
/// fail-open: it would omit active invites from the startup whitelist, so
/// validly-invited peers are rejected as `NotWhitelisted` after a restart; the
/// mnemonic-recovery / RV-RESTORE path also needs the complete active set. Must
/// be complete. The `accepted_invites_guard` unit test asserts no `LIMIT`.
const ACTIVE_ACCEPTED_INVITES_SELECT: &str =
    "SELECT nonce, inviter_pubkey, expiry_unix, accepted_at \
     FROM accepted_invites WHERE expiry_unix > $1 ORDER BY accepted_at ASC";

/// `list_recurring_master_events` — correctness-complete. All recurring masters
/// for occurrence expansion in the calendar view.
const RECURRING_MASTER_EVENTS_SELECT: &str =
    "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
            location, attendees_json, recurrence_json, color, created_at, parent_id
     FROM calendar_events
     WHERE recurrence_json IS NOT NULL AND parent_id IS NULL
     ORDER BY start_ms ASC";

/// `list_calendar_exceptions_in_range` — correctness-complete. Exceptions
/// suppress expanded occurrences; range-scoped, must be complete in range.
const CALENDAR_EXCEPTIONS_IN_RANGE_SELECT: &str =
    "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
            location, attendees_json, recurrence_json, color, created_at, parent_id
     FROM calendar_events
     WHERE parent_id IS NOT NULL AND start_ms < $2 AND end_ms > $1
     ORDER BY start_ms ASC";

/// `list_operator_hosting_contracts` — AUTHORITY (money-path). The daily payment
/// task iterates every contract; a cap silently skips paying tenants. If a
/// memory bound is ever needed it MUST be streaming/chunked, never a bare
/// `LIMIT`.
const OPERATOR_HOSTING_CONTRACTS_SELECT: &str =
    "SELECT id, tenant_pubkey, operator_pubkey, sats_per_day, started_at, last_paid_at, state
     FROM operator_hosting_contracts
     ORDER BY started_at ASC";

/// `list_operator_hosting_payments` — READ-SURFACE, scoped to one contract.
const OPERATOR_HOSTING_PAYMENTS_SELECT: &str =
    "SELECT payment_hash, contract_id, tenant_pubkey, operator_pubkey, amount_msat,
            paid_at, direction, preimage, memo
     FROM operator_hosting_payments
     WHERE contract_id = $1
     ORDER BY paid_at DESC";
/// Peer-listing query for the Postgres backend. Returns ALL peers — deliberately
/// **no `LIMIT`** (DBH1), mirroring the SQLite backend. The `peers` table is the
/// durable gate-whitelist authority (boot-loaded via `merge_persisted_peers`) and
/// the RV-RESTORE backup source; a cap here is a Principle-2 fail-open at scale.
/// CI has no Postgres service, so this path is guarded by code symmetry with
/// SQLite plus the `dbh1_guard` string-assertion test below — not a live query.
const PEERS_SELECT: &str =
    "SELECT node_id, address, last_seen, display_name, metadata_json FROM peers ORDER BY node_id";

#[async_trait]
impl Storage for PostgresStorage {
    async fn store_message(&self, envelope: &UkmEnvelope) -> Result<(), StorageError> {
        let id = envelope.id.to_hex();
        let kind = i64::from(envelope.kind);
        let sender = envelope.sender.to_hex();
        let (rtype, rid) = recipient_to_parts(&envelope.recipient);
        let ts = i64::try_from(envelope.timestamp)
            .map_err(|_| StorageError::Conversion(format!("timestamp overflows i64: {}", envelope.timestamp)))?;
        let ciphertext = &envelope.ciphertext;
        let ph = hex::encode(envelope.payment_proof.payment_hash);
        let pi = hex::encode(envelope.payment_proof.preimage);
        let amt = i64::try_from(envelope.payment_proof.amount_msat)
            .map_err(|_| StorageError::Conversion(format!("amount_msat overflows i64: {}", envelope.payment_proof.amount_msat)))?;
        let sig = hex::encode(envelope.signature.as_bytes());
        let nonce = hex::encode(envelope.nonce.as_bytes());
        let refs: Vec<String> = envelope.references.iter().map(|r| r.to_hex()).collect();
        let refs_json =
            serde_json::to_string(&refs).map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO messages (id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
             ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(&id)
        .bind(kind)
        .bind(&sender)
        .bind(rtype)
        .bind(&rid)
        .bind(ts)
        .bind(ciphertext)
        .bind(&ph)
        .bind(&pi)
        .bind(amt)
        .bind(&sig)
        .bind(&nonce)
        .bind(&refs_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_message(&self, id: &MessageId) -> Result<Option<UkmEnvelope>, StorageError> {
        let id_hex = id.to_hex();

        let row = sqlx::query_as::<_, (
            String, i64, String, String, String, i64, Vec<u8>, String, String, i64, String,
            String, String,
        )>(
            "SELECT id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
             ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json \
             FROM messages WHERE id = $1",
        )
        .bind(&id_hex)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let envelope = row_to_envelope(
                    &r.0, r.1, &r.2, &r.3, &r.4, r.5, &r.6, &r.7, &r.8, r.9, &r.10, &r.11,
                    &r.12,
                )?;
                Ok(Some(envelope))
            }
            None => Ok(None),
        }
    }

    async fn get_messages_for_recipient(
        &self,
        recipient: &Recipient,
        limit: u32,
        before_timestamp: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError> {
        let (rtype, rid) = recipient_to_parts(recipient);
        let before = before_timestamp.map_or(i64::MAX, |t| t.min(i64::MAX as u64) as i64);
        let lim = limit as i64;

        let rows = sqlx::query_as::<_, (
            String, i64, String, String, String, i64, Vec<u8>, String, String, i64, String,
            String, String,
        )>(
            "SELECT id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
             ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json \
             FROM messages WHERE recipient_type = $1 AND recipient_id = $2 AND timestamp_ms < $3 \
             ORDER BY timestamp_ms DESC LIMIT $4",
        )
        .bind(rtype)
        .bind(&rid)
        .bind(before)
        .bind(lim)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                row_to_envelope(
                    &r.0, r.1, &r.2, &r.3, &r.4, r.5, &r.6, &r.7, &r.8, r.9, &r.10, &r.11,
                    &r.12,
                )
            })
            .collect()
    }

    async fn get_conversation_messages(
        &self,
        my_node_id: &str,
        peer_or_room_id: &str,
        is_room: bool,
        limit: u32,
        before_timestamp: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError> {
        let before = before_timestamp.map_or(i64::MAX, |t| t.min(i64::MAX as u64) as i64);
        let lim = limit as i64;

        let rows = if is_room {
            sqlx::query_as::<_, (
                String, i64, String, String, String, i64, Vec<u8>, String, String, i64, String,
                String, String,
            )>(
                "SELECT id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
                 ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json \
                 FROM messages WHERE recipient_type = 'room' AND recipient_id = $1 AND timestamp_ms < $2 \
                 ORDER BY timestamp_ms DESC LIMIT $3",
            )
            .bind(peer_or_room_id)
            .bind(before)
            .bind(lim)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, (
                String, i64, String, String, String, i64, Vec<u8>, String, String, i64, String,
                String, String,
            )>(
                "SELECT id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
                 ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json \
                 FROM messages WHERE (\
                   (sender = $1 AND recipient_type = 'node' AND recipient_id = $2) \
                   OR (sender = $2 AND recipient_type = 'node' AND recipient_id = $1) \
                 ) AND timestamp_ms < $3 \
                 ORDER BY timestamp_ms DESC LIMIT $4",
            )
            .bind(peer_or_room_id)
            .bind(my_node_id)
            .bind(before)
            .bind(lim)
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter()
            .map(|r| {
                row_to_envelope(
                    &r.0, r.1, &r.2, &r.3, &r.4, r.5, &r.6, &r.7, &r.8, r.9, &r.10, &r.11,
                    &r.12,
                )
            })
            .collect()
    }

    async fn delete_message(&self, id: &MessageId) -> Result<bool, StorageError> {
        let id_hex = id.to_hex();
        // Clean up pending deliveries first (belt-and-suspenders with FK CASCADE)
        sqlx::query("DELETE FROM pending_deliveries WHERE message_id = $1")
            .bind(&id_hex)
            .execute(&self.pool)
            .await?;
        let result = sqlx::query("DELETE FROM messages WHERE id = $1")
            .bind(&id_hex)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_messages_older_than(&self, before_ms: u64) -> Result<u64, StorageError> {
        // Clean up pending deliveries for messages about to be deleted
        sqlx::query(
            "DELETE FROM pending_deliveries WHERE message_id IN \
             (SELECT id FROM messages WHERE timestamp_ms < $1)",
        )
        .bind(before_ms.min(i64::MAX as u64) as i64)
        .execute(&self.pool)
        .await?;
        let result = sqlx::query("DELETE FROM messages WHERE timestamp_ms < $1")
            .bind(before_ms.min(i64::MAX as u64) as i64)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn create_room(&self, room: &Room) -> Result<(), StorageError> {
        let id = room.id.to_string();
        let created_by = room.created_by.to_hex();
        let metadata = serde_json::to_string(&room.metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO rooms (id, name, created_by, created_at, metadata_json) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&id)
        .bind(&room.name)
        .bind(&created_by)
        .bind(&room.created_at)
        .bind(&metadata)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_room(&self, id: &RoomId) -> Result<Option<Room>, StorageError> {
        let id_str = id.to_string();

        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT id, name, created_by, created_at, metadata_json FROM rooms WHERE id = $1",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((id, name, created_by, created_at, metadata_json)) => {
                let room_id = RoomId::parse(&id)
                    .map_err(|e| StorageError::Conversion(format!("room id: {e}")))?;
                let creator = NodeId::from_hex(&created_by)
                    .map_err(|e| StorageError::Conversion(format!("created_by: {e}")))?;
                let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(Room {
                    id: room_id,
                    name,
                    created_by: creator,
                    created_at,
                    metadata,
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_rooms(&self) -> Result<Vec<Room>, StorageError> {
        let rows = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT id, name, created_by, created_at, metadata_json FROM rooms ORDER BY created_at DESC LIMIT 1000",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(id, name, created_by, created_at, metadata_json)| {
                let room_id = RoomId::parse(&id)
                    .map_err(|e| StorageError::Conversion(format!("room id: {e}")))?;
                let creator = NodeId::from_hex(&created_by)
                    .map_err(|e| StorageError::Conversion(format!("created_by: {e}")))?;
                let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Room {
                    id: room_id,
                    name,
                    created_by: creator,
                    created_at,
                    metadata,
                })
            })
            .collect()
    }

    async fn delete_room(&self, id: &RoomId) -> Result<bool, StorageError> {
        let rid = id.to_string();

        sqlx::query("DELETE FROM room_members WHERE room_id = $1")
            .bind(&rid)
            .execute(&self.pool)
            .await?;

        let result = sqlx::query("DELETE FROM rooms WHERE id = $1")
            .bind(&rid)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn add_room_member(&self, room_id: &RoomId, member: &NodeId) -> Result<(), StorageError> {
        let rid = room_id.to_string();
        let nid = member.to_hex();

        sqlx::query(
            "INSERT INTO room_members (room_id, node_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(&rid)
        .bind(&nid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn remove_room_member(
        &self,
        room_id: &RoomId,
        member: &NodeId,
    ) -> Result<(), StorageError> {
        let rid = room_id.to_string();
        let nid = member.to_hex();

        sqlx::query("DELETE FROM room_members WHERE room_id = $1 AND node_id = $2")
            .bind(&rid)
            .bind(&nid)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_room_members(&self, room_id: &RoomId) -> Result<Vec<NodeId>, StorageError> {
        let rid = room_id.to_string();

        let rows = sqlx::query_as::<_, (String,)>(ROOM_MEMBERS_SELECT)
        .bind(&rid)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(nid,)| {
                NodeId::from_hex(&nid)
                    .map_err(|e| StorageError::Conversion(format!("member node_id: {e}")))
            })
            .collect()
    }

    async fn upsert_peer(&self, peer: &Peer) -> Result<(), StorageError> {
        let nid = peer.node_id.to_hex();
        let metadata = serde_json::to_string(&peer.metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        // Single atomic UPSERT — no read-then-write. The `invite_ref` /
        // `whitelist_source` preservation that previously required a SELECT +
        // Rust-side merge is now expressed inside the `ON CONFLICT` clause so a
        // concurrent writer cannot interleave between the read and the write
        // (HARD-3 TOCTOU fix). Mirrors `merge_peer_metadata_preserving_invite_ref`:
        // for each preserved key, the existing row's value wins, falling back to
        // the incoming value when the existing row lacks it.
        //
        // The `jsonb_typeof(...) = 'object'` guard makes this safe for the
        // `EncryptedStorage` wrapper, where `metadata_json` is an opaque
        // encrypted *string scalar* rather than a JSON object: in that case we
        // overwrite wholesale (the wrapper merges plaintext metadata itself
        // before encrypting). `metadata_json` is a TEXT column, so we cast to
        // jsonb for the merge and back to text for storage.
        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT(node_id) DO UPDATE SET \
             address = COALESCE(EXCLUDED.address, peers.address), \
             last_seen = COALESCE(EXCLUDED.last_seen, peers.last_seen), \
             display_name = COALESCE(EXCLUDED.display_name, peers.display_name), \
             metadata_json = CASE \
               WHEN jsonb_typeof(EXCLUDED.metadata_json::jsonb) = 'object' \
                AND jsonb_typeof(peers.metadata_json::jsonb) = 'object' \
               THEN ( \
                 (EXCLUDED.metadata_json::jsonb) || jsonb_strip_nulls(jsonb_build_object( \
                   'invite_ref', COALESCE( \
                     peers.metadata_json::jsonb -> 'invite_ref', \
                     EXCLUDED.metadata_json::jsonb -> 'invite_ref'), \
                   'whitelist_source', COALESCE( \
                     peers.metadata_json::jsonb -> 'whitelist_source', \
                     EXCLUDED.metadata_json::jsonb -> 'whitelist_source')) \
                 ))::text \
               ELSE EXCLUDED.metadata_json \
             END",
        )
        .bind(&nid)
        .bind(&peer.address)
        .bind(&peer.last_seen)
        .bind(&peer.display_name)
        .bind(&metadata)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_peer(&self, id: &NodeId) -> Result<Option<Peer>, StorageError> {
        let nid = id.to_hex();

        let row = sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>, String)>(
            "SELECT node_id, address, last_seen, display_name, metadata_json FROM peers WHERE node_id = $1",
        )
        .bind(&nid)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((node_id, address, last_seen, display_name, metadata_json)) => {
                let nid = NodeId::from_hex(&node_id)
                    .map_err(|e| StorageError::Conversion(format!("peer node_id: {e}")))?;
                let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(Peer {
                    node_id: nid,
                    address,
                    last_seen,
                    display_name,
                    metadata,
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_peers(&self) -> Result<Vec<Peer>, StorageError> {
        let rows = sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>, String)>(
            PEERS_SELECT,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(node_id, address, last_seen, display_name, metadata_json)| {
                let nid = NodeId::from_hex(&node_id)
                    .map_err(|e| StorageError::Conversion(format!("peer node_id: {e}")))?;
                let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Peer {
                    node_id: nid,
                    address,
                    last_seen,
                    display_name,
                    metadata,
                })
            })
            .collect()
    }

    async fn delete_peer(&self, id: &NodeId) -> Result<bool, StorageError> {
        let nid = id.to_hex();
        let result = sqlx::query("DELETE FROM peers WHERE node_id = $1")
            .bind(&nid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn store_nonce(&self, nonce: &Nonce, sender: &NodeId) -> Result<bool, StorageError> {
        let nonce_hex = hex::encode(nonce.as_bytes());
        let sender_hex = sender.to_hex();

        let result = sqlx::query(
            "INSERT INTO nonces (nonce_hex, sender) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(&nonce_hex)
        .bind(&sender_hex)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn store_payment_receipt(
        &self,
        payment_hash: &[u8; 32],
        sender: &NodeId,
        message_id: &MessageId,
    ) -> Result<bool, StorageError> {
        let payment_hash_hex = hex::encode(payment_hash);
        let sender_hex = sender.to_hex();
        let message_id_hex = message_id.to_hex();

        let result = sqlx::query(
            "INSERT INTO payment_receipts (payment_hash, message_id, sender) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(&payment_hash_hex)
        .bind(&message_id_hex)
        .bind(&sender_hex)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn has_nonce(&self, nonce: &Nonce) -> Result<bool, StorageError> {
        let nonce_hex = hex::encode(nonce.as_bytes());

        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM nonces WHERE nonce_hex = $1",
        )
        .bind(&nonce_hex)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0 > 0)
    }

    async fn cleanup_expired_nonces(&self, max_age_secs: u64) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM nonces WHERE received_at < NOW() - make_interval(secs => $1::double precision)",
        )
        .bind(i64::try_from(max_age_secs.min(i64::MAX as u64)).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ── E2EE Sessions ──────────────────────────────────────────────────

    async fn store_session(
        &self,
        peer_id: &NodeId,
        state_blob: &[u8],
    ) -> Result<(), StorageError> {
        let pid = peer_id.to_hex();

        sqlx::query(
            "INSERT INTO sessions (peer_id, state_blob, updated_at) \
             VALUES ($1, $2, NOW()) \
             ON CONFLICT(peer_id) DO UPDATE SET \
             state_blob = EXCLUDED.state_blob, \
             updated_at = NOW()",
        )
        .bind(&pid)
        .bind(state_blob)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let pid = peer_id.to_hex();

        let row = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT state_blob FROM sessions WHERE peer_id = $1",
        )
        .bind(&pid)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(blob,)| blob))
    }

    async fn delete_session(&self, peer_id: &NodeId) -> Result<bool, StorageError> {
        let pid = peer_id.to_hex();
        let result = sqlx::query("DELETE FROM sessions WHERE peer_id = $1")
            .bind(&pid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_sessions(&self) -> Result<Vec<NodeId>, StorageError> {
        let rows = sqlx::query_as::<_, (String,)>(
            SESSIONS_SELECT,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(pid,)| {
                NodeId::from_hex(&pid)
                    .map_err(|e| StorageError::Conversion(format!("session peer_id: {e}")))
            })
            .collect()
    }

    // ── Pending Deliveries ──────────────────────────────────────────────

    async fn queue_pending_delivery(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError> {
        let mid = message_id.to_hex();
        let rid = recipient.to_hex();

        sqlx::query(
            "INSERT INTO pending_deliveries (message_id, recipient_id) VALUES ($1, $2) \
             ON CONFLICT DO NOTHING",
        )
        .bind(&mid)
        .bind(&rid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_pending_for_peer(
        &self,
        recipient: &NodeId,
    ) -> Result<Vec<(MessageId, u32)>, StorageError> {
        let rid = recipient.to_hex();

        let rows = sqlx::query_as::<_, (String, i32)>(PENDING_FOR_PEER_SELECT)
            .bind(&rid)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|(mid, attempts)| {
                let id = MessageId::from_hex(&mid)
                    .map_err(|e| StorageError::Conversion(format!("pending message_id: {e}")))?;
                let att = u32::try_from(attempts)
                    .map_err(|_| StorageError::Conversion(format!("attempts out of u32 range: {attempts}")))?;
                Ok((id, att))
            })
            .collect()
    }

    async fn remove_pending_delivery(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError> {
        let mid = message_id.to_hex();
        let rid = recipient.to_hex();

        sqlx::query(
            "DELETE FROM pending_deliveries WHERE message_id = $1 AND recipient_id = $2",
        )
        .bind(&mid)
        .bind(&rid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn increment_pending_attempts(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError> {
        let mid = message_id.to_hex();
        let rid = recipient.to_hex();

        sqlx::query(
            "UPDATE pending_deliveries SET attempts = attempts + 1 \
             WHERE message_id = $1 AND recipient_id = $2",
        )
        .bind(&mid)
        .bind(&rid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_pending_peers(&self) -> Result<Vec<NodeId>, StorageError> {
        let rows = sqlx::query_as::<_, (String,)>(
            PENDING_PEERS_SELECT,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(rid,)| {
                NodeId::from_hex(&rid)
                    .map_err(|e| StorageError::Conversion(format!("pending recipient_id: {e}")))
            })
            .collect()
    }

    async fn count_pending_deliveries(&self) -> Result<u64, StorageError> {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM pending_deliveries",
        )
        .fetch_one(&self.pool)
        .await?;

        // COUNT(*) is always non-negative; clamp for safety
        Ok(u64::try_from(row.0).unwrap_or(0))
    }

    async fn clear_pending_for_peer(&self, recipient: &NodeId) -> Result<u64, StorageError> {
        let recipient_hex = recipient.to_hex();
        let result = sqlx::query(
            "DELETE FROM pending_deliveries WHERE recipient_id = $1",
        )
        .bind(&recipient_hex)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    async fn cleanup_stale_pending(&self, max_attempts: u32) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM pending_deliveries WHERE attempts >= $1",
        )
        .bind(max_attempts as i64)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ── Files ──────────────────────────────────────────────────────────

    async fn store_file(&self, file: &FileRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO files (id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, data) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&file.id)
        .bind(&file.filename)
        .bind(&file.mime_type)
        .bind(i64::try_from(file.size_bytes)
            .map_err(|_| StorageError::Conversion(format!("file size overflows i64: {}", file.size_bytes)))?)
        .bind(&file.blake3_hash)
        .bind(&file.sender)
        .bind(&file.message_id)
        .bind(&file.data)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_file(&self, id: &str) -> Result<Option<FileRecord>, StorageError> {
        let row = sqlx::query_as::<_, (
            String, String, String, i64, String, String, Option<String>, Vec<u8>, String,
        )>(
            "SELECT id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, data, \
             to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
             FROM files WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, data, created_at)| {
            FileRecord {
                id,
                filename,
                mime_type,
                size_bytes: u64::try_from(size_bytes).unwrap_or_else(|_| {
                    tracing::warn!(size_bytes, "negative file size in DB, clamping to 0");
                    0
                }),
                blake3_hash,
                sender,
                message_id,
                data,
                created_at,
            }
        }))
    }

    async fn get_file_metadata(&self, id: &str) -> Result<Option<FileMetadata>, StorageError> {
        let row = sqlx::query_as::<_, (
            String, String, String, i64, String, String, Option<String>, String,
        )>(
            "SELECT id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, \
             to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
             FROM files WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at)| {
            FileMetadata {
                id,
                filename,
                mime_type,
                size_bytes: u64::try_from(size_bytes).unwrap_or_else(|_| {
                    tracing::warn!(size_bytes, "negative file size in DB, clamping to 0");
                    0
                }),
                blake3_hash,
                sender,
                message_id,
                created_at,
            }
        }))
    }

    async fn list_files(&self, limit: u32) -> Result<Vec<FileMetadata>, StorageError> {
        let lim = limit as i64;

        let rows = sqlx::query_as::<_, (
            String, String, String, i64, String, String, Option<String>, String,
        )>(
            "SELECT id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, \
             to_char(created_at, 'YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"') \
             FROM files ORDER BY created_at DESC LIMIT $1",
        )
        .bind(lim)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|(id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at)| {
            FileMetadata {
                id,
                filename,
                mime_type,
                size_bytes: u64::try_from(size_bytes).unwrap_or_else(|_| {
                    tracing::warn!(size_bytes, "negative file size in DB, clamping to 0");
                    0
                }),
                blake3_hash,
                sender,
                message_id,
                created_at,
            }
        }).collect())
    }

    async fn delete_file(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM files WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── Plaintext Cache ─────────────────────────────────────────────────

    async fn store_message_plaintext(
        &self,
        id: &MessageId,
        encrypted_plaintext: &[u8],
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE messages SET plaintext_enc = $1 WHERE id = $2")
            .bind(encrypted_plaintext)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_message_plaintext(
        &self,
        id: &MessageId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let row: Option<(Option<Vec<u8>>,)> =
            sqlx::query_as("SELECT plaintext_enc FROM messages WHERE id = $1")
                .bind(id.to_hex())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|(data,)| data))
    }

    async fn invite_schema_capabilities(
        &self,
    ) -> Result<InviteSchemaCapabilities, StorageError> {
        let columns: Vec<String> = sqlx::query_scalar(
            "SELECT column_name FROM information_schema.columns \
             WHERE table_schema = current_schema() AND table_name = 'invites_issued'",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(InviteSchemaCapabilities {
            addr_column: columns.iter().any(|name| name == "addr"),
            max_fee_rate_sat_per_vb_column: columns
                .iter()
                .any(|name| name == "max_fee_rate_sat_per_vb"),
            channel_open_intent_expiry_unix_column: columns
                .iter()
                .any(|name| name == "channel_open_intent_expiry_unix"),
        })
    }

    async fn add_invite_issued(&self, record: &InviteIssuedRecord) -> Result<(), StorageError> {
        let expiry_unix = i64::try_from(record.expiry_unix).map_err(|_| {
            StorageError::Conversion(format!("expiry_unix overflows i64: {}", record.expiry_unix))
        })?;
        let channel_size_hint_sats = record.channel_size_hint_sats.map(i64::from);
        let max_fee_rate_sat_per_vb = record.max_fee_rate_sat_per_vb.map(i64::from);
        let channel_open_intent_expiry_unix = record
            .channel_open_intent_expiry_unix
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("channel_open_intent_expiry_unix overflows i64".into()))?;
        let created_at = i64::try_from(record.created_at).map_err(|_| {
            StorageError::Conversion(format!("created_at overflows i64: {}", record.created_at))
        })?;
        let accepted_at = record
            .accepted_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("accepted_at overflows i64".into()))?;
        let revoked_at = record
            .revoked_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("revoked_at overflows i64".into()))?;

        sqlx::query(
            "INSERT INTO invites_issued \
             (id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(record.id.as_bytes().as_slice())
        .bind(record.invitee_pubkey.as_slice())
        .bind(expiry_unix)
        .bind(channel_size_hint_sats)
        .bind(&record.addr)
        .bind(max_fee_rate_sat_per_vb)
        .bind(channel_open_intent_expiry_unix)
        .bind(record.nonce.as_slice())
        .bind(record.state.to_string())
        .bind(created_at)
        .bind(accepted_at)
        .bind(revoked_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn add_invite_and_whitelist(
        &self,
        invite: &InviteIssuedRecord,
        peer_pubkey: [u8; 32],
    ) -> Result<(), StorageError> {
        let expiry_unix = i64::try_from(invite.expiry_unix).map_err(|_| {
            StorageError::Conversion(format!("expiry_unix overflows i64: {}", invite.expiry_unix))
        })?;
        let channel_size_hint_sats = invite.channel_size_hint_sats.map(i64::from);
        let max_fee_rate_sat_per_vb = invite.max_fee_rate_sat_per_vb.map(i64::from);
        let channel_open_intent_expiry_unix = invite
            .channel_open_intent_expiry_unix
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("channel_open_intent_expiry_unix overflows i64".into()))?;
        let created_at = i64::try_from(invite.created_at).map_err(|_| {
            StorageError::Conversion(format!("created_at overflows i64: {}", invite.created_at))
        })?;
        let accepted_at = invite
            .accepted_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("accepted_at overflows i64".into()))?;
        let revoked_at = invite
            .revoked_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("revoked_at overflows i64".into()))?;

        let node_id = NodeId::from_bytes(peer_pubkey).to_hex();
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO invites_issued \
             (id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(invite.id.as_bytes().as_slice())
        .bind(invite.invitee_pubkey.as_slice())
        .bind(expiry_unix)
        .bind(channel_size_hint_sats)
        .bind(&invite.addr)
        .bind(max_fee_rate_sat_per_vb)
        .bind(channel_open_intent_expiry_unix)
        .bind(invite.nonce.as_slice())
        .bind(invite.state.to_string())
        .bind(created_at)
        .bind(accepted_at)
        .bind(revoked_at)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::Database)?;

        let mut metadata = sqlx::query_as::<_, (String,)>(
            "SELECT metadata_json FROM peers WHERE node_id = $1",
        )
        .bind(&node_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(StorageError::Database)?
        .and_then(|(json,)| serde_json::from_str::<serde_json::Value>(&json).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));

        metadata["invite_ref"] = serde_json::Value::String(invite.id.to_string());
        metadata["whitelist_source"] = serde_json::Value::String("invite".to_string());
        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES ($1, NULL, NULL, NULL, $2) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = EXCLUDED.metadata_json",
        )
        .bind(&node_id)
        .bind(&metadata_json)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::Database)?;

        tx.commit().await.map_err(StorageError::Database)?;
        Ok(())
    }

    async fn add_invite_and_whitelist_with_peer_metadata(
        &self,
        invite: &InviteIssuedRecord,
        peer_pubkey: [u8; 32],
        metadata_json: &str,
    ) -> Result<(), StorageError> {
        let expiry_unix = i64::try_from(invite.expiry_unix).map_err(|_| {
            StorageError::Conversion(format!("expiry_unix overflows i64: {}", invite.expiry_unix))
        })?;
        let channel_size_hint_sats = invite.channel_size_hint_sats.map(i64::from);
        let max_fee_rate_sat_per_vb = invite.max_fee_rate_sat_per_vb.map(i64::from);
        let channel_open_intent_expiry_unix = invite
            .channel_open_intent_expiry_unix
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("channel_open_intent_expiry_unix overflows i64".into()))?;
        let created_at = i64::try_from(invite.created_at).map_err(|_| {
            StorageError::Conversion(format!("created_at overflows i64: {}", invite.created_at))
        })?;
        let accepted_at = invite
            .accepted_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("accepted_at overflows i64".into()))?;
        let revoked_at = invite
            .revoked_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("revoked_at overflows i64".into()))?;

        let node_id = NodeId::from_bytes(peer_pubkey).to_hex();
        let mut tx = self.pool.begin().await.map_err(StorageError::Database)?;

        sqlx::query(
            "INSERT INTO invites_issued \
             (id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(invite.id.as_bytes().as_slice())
        .bind(invite.invitee_pubkey.as_slice())
        .bind(expiry_unix)
        .bind(channel_size_hint_sats)
        .bind(&invite.addr)
        .bind(max_fee_rate_sat_per_vb)
        .bind(channel_open_intent_expiry_unix)
        .bind(invite.nonce.as_slice())
        .bind(invite.state.to_string())
        .bind(created_at)
        .bind(accepted_at)
        .bind(revoked_at)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::Database)?;

        // Overwrite the peer metadata wholesale with the caller-supplied blob.
        // For the EncryptedStorage wrapper this is an opaque ciphertext scalar,
        // so the backend must never parse/merge it — the caller already merged
        // `invite_ref` / `whitelist_source` before encrypting.
        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES ($1, NULL, NULL, NULL, $2) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = EXCLUDED.metadata_json",
        )
        .bind(&node_id)
        .bind(metadata_json)
        .execute(&mut *tx)
        .await
        .map_err(StorageError::Database)?;

        tx.commit().await.map_err(StorageError::Database)?;
        Ok(())
    }

    async fn find_invite_issued(
        &self,
        id: &uuid::Uuid,
    ) -> Result<Option<InviteIssuedRecord>, StorageError> {
        let row = sqlx::query_as::<
            _,
            (
                Vec<u8>,
                Vec<u8>,
                i64,
                Option<i64>,
                String,
                Option<i64>,
                Option<i64>,
                Vec<u8>,
                String,
                i64,
                Option<i64>,
                Option<i64>,
            ),
        >(
            "SELECT id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at \
             FROM invites_issued WHERE id = $1",
        )
        .bind(id.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| {
            let id_bytes: [u8; 16] = r
                .0
                .try_into()
                .map_err(|_| StorageError::Conversion("invalid invites_issued.id length".into()))?;
            let invitee_pubkey: [u8; 32] = r.1.try_into().map_err(|_| {
                StorageError::Conversion("invalid invites_issued.invitee_pubkey length".into())
            })?;
            let nonce: [u8; 16] = r.7.try_into().map_err(|_| {
                StorageError::Conversion("invalid invites_issued.nonce length".into())
            })?;
            let expiry_unix = u64::try_from(r.2).map_err(|_| {
                StorageError::Conversion(format!("negative invites_issued.expiry_unix: {}", r.2))
            })?;
            let channel_size_hint_sats = r
                .3
                .map(u32::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("channel_size_hint_sats out of range".into()))?;
            let max_fee_rate_sat_per_vb = r
                .5
                .map(u32::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("max_fee_rate_sat_per_vb out of range".into()))?;
            let channel_open_intent_expiry_unix = r
                .6
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("channel_open_intent_expiry_unix out of range".into()))?;
            let state = InviteState::from_str(&r.8)
                .map_err(|e| StorageError::Conversion(format!("invalid invites_issued.state: {e}")))?;
            let created_at = u64::try_from(r.9).map_err(|_| {
                StorageError::Conversion(format!("negative invites_issued.created_at: {}", r.9))
            })?;
            let accepted_at = r
                .10
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("accepted_at out of range".into()))?;
            let revoked_at = r
                .11
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("revoked_at out of range".into()))?;

            Ok(InviteIssuedRecord {
                id: uuid::Uuid::from_bytes(id_bytes),
                invitee_pubkey,
                expiry_unix,
                channel_size_hint_sats,
                addr: r.4,
                max_fee_rate_sat_per_vb,
                channel_open_intent_expiry_unix,
                nonce,
                state,
                created_at,
                accepted_at,
                revoked_at,
            })
        })
        .transpose()
    }

    async fn list_invites_issued(&self) -> Result<Vec<InviteIssuedRecord>, StorageError> {
        let rows = sqlx::query_as::<
            _,
            (
                Vec<u8>,
                Vec<u8>,
                i64,
                Option<i64>,
                String,
                Option<i64>,
                Option<i64>,
                Vec<u8>,
                String,
                i64,
                Option<i64>,
                Option<i64>,
            ),
        >(
            INVITES_ISSUED_SELECT,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        rows.into_iter()
            .map(|r| {
                let id_bytes: [u8; 16] = r.0.try_into().map_err(|_| {
                    StorageError::Conversion("invalid invites_issued.id length".into())
                })?;
                let invitee_pubkey: [u8; 32] = r.1.try_into().map_err(|_| {
                    StorageError::Conversion("invalid invites_issued.invitee_pubkey length".into())
                })?;
                let nonce: [u8; 16] = r.7.try_into().map_err(|_| {
                    StorageError::Conversion("invalid invites_issued.nonce length".into())
                })?;
                let expiry_unix = u64::try_from(r.2).map_err(|_| {
                    StorageError::Conversion(format!("negative invites_issued.expiry_unix: {}", r.2))
                })?;
                let channel_size_hint_sats = r
                    .3
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| {
                        StorageError::Conversion("channel_size_hint_sats out of range".into())
                    })?;
                let max_fee_rate_sat_per_vb = r
                    .5
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| {
                        StorageError::Conversion("max_fee_rate_sat_per_vb out of range".into())
                    })?;
                let channel_open_intent_expiry_unix = r
                    .6
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| {
                        StorageError::Conversion("channel_open_intent_expiry_unix out of range".into())
                    })?;
                let state = InviteState::from_str(&r.8).map_err(|e| {
                    StorageError::Conversion(format!("invalid invites_issued.state: {e}"))
                })?;
                let created_at = u64::try_from(r.9).map_err(|_| {
                    StorageError::Conversion(format!("negative invites_issued.created_at: {}", r.9))
                })?;
                let accepted_at = r
                    .10
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| StorageError::Conversion("accepted_at out of range".into()))?;
                let revoked_at = r
                    .11
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| StorageError::Conversion("revoked_at out of range".into()))?;

                Ok(InviteIssuedRecord {
                    id: uuid::Uuid::from_bytes(id_bytes),
                    invitee_pubkey,
                    expiry_unix,
                    channel_size_hint_sats,
                    addr: r.4,
                    max_fee_rate_sat_per_vb,
                    channel_open_intent_expiry_unix,
                    nonce,
                    state,
                    created_at,
                    accepted_at,
                    revoked_at,
                })
            })
            .collect()
    }

    async fn revoke_invite(&self, id: &uuid::Uuid, now_unix: u64) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE invites_issued SET state = $1, revoked_at = $2 WHERE id = $3 AND state = $4",
        )
        .bind(InviteState::Revoked.to_string())
        .bind(now_unix as i64)
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Pending.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn mark_invite_accepted(
        &self,
        id: &uuid::Uuid,
        now_unix: u64,
    ) -> Result<bool, StorageError> {
        let now_i64 = i64::try_from(now_unix)
            .map_err(|_| StorageError::Conversion("accepted_at overflows i64".into()))?;
        let result = sqlx::query(
            "UPDATE invites_issued SET state = $1, accepted_at = $2 WHERE id = $3 AND state IN ($4, $5)",
        )
        .bind(InviteState::Accepted.to_string())
        .bind(now_i64)
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Pending.to_string())
        .bind(InviteState::Opening.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn mark_invite_opening(
        &self,
        id: &uuid::Uuid,
        now_unix: u64,
    ) -> Result<bool, StorageError> {
        let now_i64 = i64::try_from(now_unix)
            .map_err(|_| StorageError::Conversion("accepted_at overflows i64".into()))?;
        let result = sqlx::query(
            "UPDATE invites_issued SET state = $1, accepted_at = $2 WHERE id = $3 AND state = $4",
        )
        .bind(InviteState::Opening.to_string())
        .bind(now_i64)
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Pending.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn mark_invite_pending(&self, id: &uuid::Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE invites_issued SET state = $1, accepted_at = NULL WHERE id = $2 AND state = $3",
        )
        .bind(InviteState::Pending.to_string())
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Opening.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn mark_invite_expired(
        &self,
        id: &uuid::Uuid,
        now_unix: u64,
    ) -> Result<bool, StorageError> {
        let now_i64 = i64::try_from(now_unix)
            .map_err(|_| StorageError::Conversion("revoked_at overflows i64".into()))?;
        let result = sqlx::query(
            "UPDATE invites_issued SET state = $1, revoked_at = $2 WHERE id = $3 AND state = $4",
        )
        .bind(InviteState::Expired.to_string())
        .bind(now_i64)
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Pending.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn add_whitelisted_peer_with_invite_ref(
        &self,
        pubkey: [u8; 32],
        invite_id: uuid::Uuid,
    ) -> Result<(), StorageError> {
        let node_id = NodeId::from_bytes(pubkey).to_hex();
        let mut metadata = sqlx::query_as::<_, (String,)>(
            "SELECT metadata_json FROM peers WHERE node_id = $1",
        )
        .bind(&node_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::Database)?
        .and_then(|(json,)| serde_json::from_str::<serde_json::Value>(&json).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));

        metadata["invite_ref"] = serde_json::Value::String(invite_id.to_string());
        metadata["whitelist_source"] = serde_json::Value::String("invite".to_string());
        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES ($1, NULL, NULL, NULL, $2) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = EXCLUDED.metadata_json",
        )
        .bind(&node_id)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(())
    }

    async fn add_whitelisted_peer_with_metadata(
        &self,
        pubkey: [u8; 32],
        metadata_json: &str,
    ) -> Result<(), StorageError> {
        let node_id = NodeId::from_bytes(pubkey).to_hex();

        // Overwrite the peer metadata wholesale with the caller-supplied blob.
        // The caller owns the `invite_ref` / `whitelist_source` merge and (for
        // the EncryptedStorage wrapper) the encryption, so the backend must not
        // parse or merge this value — it may be an opaque ciphertext scalar.
        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES ($1, NULL, NULL, NULL, $2) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = EXCLUDED.metadata_json",
        )
        .bind(&node_id)
        .bind(metadata_json)
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(())
    }

    async fn add_accepted_invite(&self, record: &AcceptedInviteRecord) -> Result<(), StorageError> {
        let expiry_unix = i64::try_from(record.expiry_unix).map_err(|_| {
            StorageError::Conversion(format!("expiry_unix overflows i64: {}", record.expiry_unix))
        })?;
        let accepted_at = i64::try_from(record.accepted_at).map_err(|_| {
            StorageError::Conversion(format!("accepted_at overflows i64: {}", record.accepted_at))
        })?;

        sqlx::query(
            "INSERT INTO accepted_invites (nonce, inviter_pubkey, expiry_unix, accepted_at) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(record.nonce.as_slice())
        .bind(record.inviter_pubkey.as_slice())
        .bind(expiry_unix)
        .bind(accepted_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some("23505") => {
                StorageError::AlreadyExists("accepted invite already exists".into())
            }
            _ => StorageError::Database(e),
        })?;

        Ok(())
    }

    async fn find_accepted_invite(
        &self,
        nonce: &[u8; 16],
    ) -> Result<Option<AcceptedInviteRecord>, StorageError> {
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, i64, i64)>(
            "SELECT nonce, inviter_pubkey, expiry_unix, accepted_at \
             FROM accepted_invites WHERE nonce = $1",
        )
        .bind(nonce.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        row.map(|r| {
            let inviter_pubkey: [u8; 32] = r.1.try_into().map_err(|_| {
                StorageError::Conversion("invalid accepted_invites.inviter_pubkey length".into())
            })?;
            let expiry_unix = u64::try_from(r.2).map_err(|_| {
                StorageError::Conversion(format!("negative accepted_invites.expiry_unix: {}", r.2))
            })?;
            let accepted_at = u64::try_from(r.3).map_err(|_| {
                StorageError::Conversion(format!("negative accepted_invites.accepted_at: {}", r.3))
            })?;

            Ok(AcceptedInviteRecord {
                nonce: r.0.try_into().map_err(|_| {
                    StorageError::Conversion("invalid accepted_invites.nonce length".into())
                })?,
                inviter_pubkey,
                expiry_unix,
                accepted_at,
            })
        })
        .transpose()
    }

    async fn list_active_accepted_invites(
        &self,
        now_unix: u64,
    ) -> Result<Vec<AcceptedInviteRecord>, StorageError> {
        let now_unix = i64::try_from(now_unix).map_err(|_| {
            StorageError::Conversion(format!("now_unix overflows i64: {now_unix}"))
        })?;
        let table_exists: bool =
            sqlx::query_scalar("SELECT to_regclass('public.accepted_invites') IS NOT NULL")
                .fetch_one(&self.pool)
                .await
                .map_err(StorageError::Database)?;
        if !table_exists {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, i64, i64)>(ACTIVE_ACCEPTED_INVITES_SELECT)
            .bind(now_unix)
            .fetch_all(&self.pool)
            .await
            .map_err(StorageError::Database)?;

        rows.into_iter()
            .map(|r| {
                let inviter_pubkey: [u8; 32] = r.1.try_into().map_err(|_| {
                    StorageError::Conversion("invalid accepted_invites.inviter_pubkey length".into())
                })?;
                let expiry_unix = u64::try_from(r.2).map_err(|_| {
                    StorageError::Conversion(format!("negative accepted_invites.expiry_unix: {}", r.2))
                })?;
                let accepted_at = u64::try_from(r.3).map_err(|_| {
                    StorageError::Conversion(format!("negative accepted_invites.accepted_at: {}", r.3))
                })?;

                Ok(AcceptedInviteRecord {
                    nonce: r.0.try_into().map_err(|_| {
                        StorageError::Conversion("invalid accepted_invites.nonce length".into())
                    })?,
                    inviter_pubkey,
                    expiry_unix,
                    accepted_at,
                })
            })
            .collect()
    }

    async fn upsert_onboarding_state(
        &self,
        state: &OnboardingStateRecord,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO onboarding_state
                (id, invite_id, inviter_pubkey, inviter_ln_pubkey, current_step, tier, funding_address, funding_amount_sats_required, funding_amount_sats_received, last_poll_at, funding_evidence)
             VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT(id) DO UPDATE SET
                invite_id = EXCLUDED.invite_id,
                inviter_pubkey = EXCLUDED.inviter_pubkey,
                inviter_ln_pubkey = EXCLUDED.inviter_ln_pubkey,
                current_step = EXCLUDED.current_step,
                tier = EXCLUDED.tier,
                funding_address = EXCLUDED.funding_address,
                funding_amount_sats_required = EXCLUDED.funding_amount_sats_required,
                funding_amount_sats_received = EXCLUDED.funding_amount_sats_received,
                last_poll_at = EXCLUDED.last_poll_at,
                funding_evidence = EXCLUDED.funding_evidence",
        )
        .bind(state.invite_id.map(|id| id.to_string()))
        .bind(state.inviter_pubkey.map(|bytes| bytes.to_vec()))
        .bind(&state.inviter_ln_pubkey)
        .bind(&state.current_step)
        .bind(&state.tier)
        .bind(&state.funding_address)
        .bind(state.funding_amount_sats_required.map(i64::from))
        .bind(i64::from(state.funding_amount_sats_received))
        .bind(state.last_poll_at.map(|v| v as i64))
        .bind(&state.funding_evidence)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_onboarding_state(&self) -> Result<Option<OnboardingStateRecord>, StorageError> {
        let row = sqlx::query_as::<
            _,
            (
                Option<String>,
                Option<Vec<u8>>,
                Option<String>,
                String,
                Option<String>,
                Option<String>,
                Option<i64>,
                i64,
                Option<i64>,
                Option<String>,
            ),
        >(
            "SELECT invite_id, inviter_pubkey, inviter_ln_pubkey, current_step, tier, funding_address, funding_amount_sats_required, funding_amount_sats_received, last_poll_at, funding_evidence
             FROM onboarding_state WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(invite_id, inviter_pubkey, inviter_ln_pubkey, current_step, tier, funding_address, req, recv, last_poll_at, funding_evidence)| {
            let invite_id = invite_id
                .map(|value| uuid::Uuid::parse_str(&value).map_err(|e| StorageError::Conversion(format!("onboarding_state.invite_id: {e}"))))
                .transpose()?;
            let inviter_pubkey = inviter_pubkey
                .map(|bytes| bytes.try_into().map_err(|_| StorageError::Conversion("onboarding_state.inviter_pubkey wrong length".into())))
                .transpose()?;
            let funding_amount_sats_required = req
                .map(|value| u32::try_from(value).map_err(|_| StorageError::Conversion("onboarding_state.funding_amount_sats_required out of range".into())))
                .transpose()?;
            let funding_amount_sats_received = u32::try_from(recv).map_err(|_| {
                StorageError::Conversion("onboarding_state.funding_amount_sats_received out of range".into())
            })?;
            let last_poll_at = last_poll_at
                .map(|value| u64::try_from(value).map_err(|_| StorageError::Conversion("onboarding_state.last_poll_at negative".into())))
                .transpose()?;

            Ok(OnboardingStateRecord {
                invite_id,
                inviter_pubkey,
                inviter_ln_pubkey,
                current_step,
                tier,
                funding_address,
                funding_amount_sats_required,
                funding_amount_sats_received,
                last_poll_at,
                funding_evidence,
            })
        })
        .transpose()
    }

    async fn store_calendar_event(&self, record: &CalendarEventRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO calendar_events
               (id, message_id, organizer, title, description, start_ms, end_ms, tz,
                location, attendees_json, recurrence_json, color, parent_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             ON CONFLICT(id) DO UPDATE SET
               message_id      = EXCLUDED.message_id,
               title           = EXCLUDED.title,
               description     = EXCLUDED.description,
               start_ms        = EXCLUDED.start_ms,
               end_ms          = EXCLUDED.end_ms,
               tz              = EXCLUDED.tz,
               location        = EXCLUDED.location,
               attendees_json  = EXCLUDED.attendees_json,
               recurrence_json = EXCLUDED.recurrence_json,
               color           = EXCLUDED.color,
               parent_id       = EXCLUDED.parent_id",
        )
        .bind(&record.id)
        .bind(&record.message_id)
        .bind(&record.organizer)
        .bind(&record.title)
        .bind(&record.description)
        .bind(record.start_ms as i64)
        .bind(record.end_ms as i64)
        .bind(&record.tz)
        .bind(&record.location)
        .bind(&record.attendees_json)
        .bind(&record.recurrence_json)
        .bind(&record.color)
        .bind(&record.parent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_calendar_event(&self, id: &str) -> Result<Option<CalendarEventRecord>, StorageError> {
        let row: Option<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            i64,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
                    location, attendees_json, recurrence_json, color, created_at, parent_id
             FROM calendar_events WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, message_id, organizer, title, description, start_ms, end_ms, tz,
              location, attendees_json, recurrence_json, color, created_at, parent_id)| {
                CalendarEventRecord {
                    id,
                    message_id,
                    organizer,
                    title,
                    description,
                    start_ms: start_ms as u64,
                    end_ms: end_ms as u64,
                    tz,
                    location,
                    attendees_json,
                    recurrence_json,
                    color,
                    created_at,
                    parent_id,
                }
            },
        ))
    }

    async fn list_calendar_events_in_range(
        &self,
        from_ms: u64,
        to_ms: u64,
        limit: u32,
    ) -> Result<Vec<CalendarEventRecord>, StorageError> {
        let rows: Vec<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            i64,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
                    location, attendees_json, recurrence_json, color, created_at, parent_id
             FROM calendar_events
             WHERE start_ms < $2 AND end_ms > $1
               AND recurrence_json IS NULL AND parent_id IS NULL
             ORDER BY start_ms ASC
             LIMIT $3",
        )
        .bind(from_ms as i64)
        .bind(to_ms as i64)
        .bind(limit.min(500) as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, message_id, organizer, title, description, start_ms, end_ms, tz,
                  location, attendees_json, recurrence_json, color, created_at, parent_id)| {
                    CalendarEventRecord {
                        id,
                        message_id,
                        organizer,
                        title,
                        description,
                        start_ms: start_ms as u64,
                        end_ms: end_ms as u64,
                        tz,
                        location,
                        attendees_json,
                        recurrence_json,
                        color,
                        created_at,
                        parent_id,
                    }
                },
            )
            .collect())
    }

    async fn delete_calendar_event(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM calendar_events WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_recurring_master_events(&self) -> Result<Vec<CalendarEventRecord>, StorageError> {
        let rows: Vec<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            i64,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(RECURRING_MASTER_EVENTS_SELECT)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, message_id, organizer, title, description, start_ms, end_ms, tz,
                  location, attendees_json, recurrence_json, color, created_at, parent_id)| {
                    CalendarEventRecord {
                        id,
                        message_id,
                        organizer,
                        title,
                        description,
                        start_ms: start_ms as u64,
                        end_ms: end_ms as u64,
                        tz,
                        location,
                        attendees_json,
                        recurrence_json,
                        color,
                        created_at,
                        parent_id,
                    }
                },
            )
            .collect())
    }

    async fn list_calendar_exceptions_in_range(
        &self,
        from_ms: u64,
        to_ms: u64,
    ) -> Result<Vec<CalendarEventRecord>, StorageError> {
        let rows: Vec<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            i64,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(CALENDAR_EXCEPTIONS_IN_RANGE_SELECT)
            .bind(from_ms as i64)
            .bind(to_ms as i64)
            .fetch_all(&self.pool)
            .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, message_id, organizer, title, description, start_ms, end_ms, tz,
                  location, attendees_json, recurrence_json, color, created_at, parent_id)| {
                    CalendarEventRecord {
                        id,
                        message_id,
                        organizer,
                        title,
                        description,
                        start_ms: start_ms as u64,
                        end_ms: end_ms as u64,
                        tz,
                        location,
                        attendees_json,
                        recurrence_json,
                        color,
                        created_at,
                        parent_id,
                    }
                },
            )
            .collect())
    }

    async fn store_rsvp(&self, record: &RsvpRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO calendar_rsvps (id, event_id, responder, response, comment)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT(event_id, responder) DO UPDATE SET
               response = EXCLUDED.response,
               comment  = EXCLUDED.comment",
        )
        .bind(&record.id)
        .bind(&record.event_id)
        .bind(&record.responder)
        .bind(&record.response)
        .bind(&record.comment)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn upsert_operator_hosting_contract(
        &self,
        contract: &OperatorHostingContract,
    ) -> Result<(), StorageError> {
        contract
            .validate()
            .map_err(|e| StorageError::Conversion(e.to_string()))?;
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO operator_hosting_contracts
                (id, tenant_pubkey, operator_pubkey, sats_per_day, started_at, last_paid_at, state, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT(id) DO UPDATE SET
                tenant_pubkey = EXCLUDED.tenant_pubkey,
                operator_pubkey = EXCLUDED.operator_pubkey,
                sats_per_day = EXCLUDED.sats_per_day,
                started_at = EXCLUDED.started_at,
                last_paid_at = EXCLUDED.last_paid_at,
                state = EXCLUDED.state,
                updated_at = EXCLUDED.updated_at",
        )
        .bind(contract.id.to_string())
        .bind(contract.tenant_pubkey.to_hex())
        .bind(&contract.operator_pubkey)
        .bind(u64_to_i64(contract.sats_per_day, "sats_per_day")?)
        .bind(u64_to_i64(contract.started_at, "started_at")?)
        .bind(contract.last_paid_at.map(|ts| u64_to_i64(ts, "last_paid_at")).transpose()?)
        .bind(contract.state.as_str())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_operator_hosting_contracts(
        &self,
    ) -> Result<Vec<OperatorHostingContract>, StorageError> {
        let rows: Vec<(String, String, String, i64, i64, Option<i64>, String)> =
            sqlx::query_as(OPERATOR_HOSTING_CONTRACTS_SELECT)
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter()
            .map(|(id, tenant, operator, sats, started, last_paid, state)| {
                row_to_hosting_contract(id, tenant, operator, sats, started, last_paid, state)
            })
            .collect()
    }

    async fn update_operator_hosting_contract_state(
        &self,
        contract_id: &uuid::Uuid,
        state: HostingContractState,
        updated_at: u64,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE operator_hosting_contracts
             SET state = $1, updated_at = $2
             WHERE id = $3",
        )
        .bind(state.as_str())
        .bind(u64_to_i64(updated_at, "updated_at")?)
        .bind(contract_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_operator_hosting_contract_paid(
        &self,
        contract_id: &uuid::Uuid,
        last_paid_at: u64,
        updated_at: u64,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE operator_hosting_contracts
             SET last_paid_at = $1, state = 'active', updated_at = $2
             WHERE id = $3",
        )
        .bind(u64_to_i64(last_paid_at, "last_paid_at")?)
        .bind(u64_to_i64(updated_at, "updated_at")?)
        .bind(contract_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_operator_hosting_payment(
        &self,
        payment: &OperatorHostingPayment,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "INSERT INTO operator_hosting_payments
                (payment_hash, contract_id, tenant_pubkey, operator_pubkey, amount_msat, paid_at, direction, preimage, memo, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
             ON CONFLICT(payment_hash) DO NOTHING",
        )
        .bind(&payment.payment_hash)
        .bind(payment.contract_id.to_string())
        .bind(payment.tenant_pubkey.to_hex())
        .bind(&payment.operator_pubkey)
        .bind(u64_to_i64(payment.amount_msat, "amount_msat")?)
        .bind(u64_to_i64(payment.paid_at, "paid_at")?)
        .bind(payment.direction.as_str())
        .bind(&payment.preimage)
        .bind(&payment.memo)
        .bind(chrono::Utc::now().timestamp())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_operator_hosting_payments(
        &self,
        contract_id: &uuid::Uuid,
    ) -> Result<Vec<OperatorHostingPayment>, StorageError> {
        let rows: Vec<(
            String,
            String,
            String,
            String,
            i64,
            i64,
            String,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(OPERATOR_HOSTING_PAYMENTS_SELECT)
            .bind(contract_id.to_string())
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|(hash, id, tenant, operator, amount, paid_at, direction, preimage, memo)| {
                row_to_hosting_payment(
                    hash, id, tenant, operator, amount, paid_at, direction, preimage, memo,
                )
            })
            .collect()
    }
}

// ── NonceStore implementation for PaymentGate ────────────────────────────

#[async_trait]
impl konsensus_core::gate::NonceStore for PostgresStorage {
    async fn check_and_store(
        &self,
        nonce: &Nonce,
        sender: &NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.store_nonce(nonce, sender).await?)
    }

    async fn check_and_store_payment_hash(
        &self,
        payment_hash: &[u8; 32],
        sender: &NodeId,
        message_id: &MessageId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.store_payment_receipt(payment_hash, sender, message_id).await?)
    }
}

#[cfg(test)]
mod dbh2_guard {
    /// DBH2: the Postgres sibling authority-listing queries
    /// (`list_sessions`, `get_pending_peers`, `get_room_members`) must never
    /// regain a `LIMIT` — each is a durable authority where a cap is a
    /// Principle-2 fail-open at scale, identical in shape to the DBH1
    /// `list_peers` truncation. CI has no Postgres service, so this string
    /// assertion plus code symmetry with the SQLite backend is the in-CI proof;
    /// the only true Postgres proof is the operator's GA-drill against a live
    /// Postgres node, which is out of scope for the autonomous build.
    #[test]
    fn sessions_select_is_unbounded() {
        assert!(
            !super::SESSIONS_SELECT.to_uppercase().contains("LIMIT"),
            "postgres SESSIONS_SELECT must not contain LIMIT (DBH2 fail-open guard): {}",
            super::SESSIONS_SELECT
        );
    }

    #[test]
    fn pending_peers_select_is_unbounded() {
        assert!(
            !super::PENDING_PEERS_SELECT.to_uppercase().contains("LIMIT"),
            "postgres PENDING_PEERS_SELECT must not contain LIMIT (DBH2 fail-open guard): {}",
            super::PENDING_PEERS_SELECT
        );
    }

    #[test]
    fn room_members_select_is_unbounded() {
        assert!(
            !super::ROOM_MEMBERS_SELECT.to_uppercase().contains("LIMIT"),
            "postgres ROOM_MEMBERS_SELECT must not contain LIMIT (DBH2 fail-open guard): {}",
            super::ROOM_MEMBERS_SELECT
        );
    }
}

#[cfg(test)]
mod hard4_guard {
    // CI has no Postgres service (see ci.yml), so the Postgres HARD-4 path is
    // verified by code symmetry with the SQLite impl plus this const-string
    // guard — the same approach DBH1/DBH2 used for their Postgres guards. The
    // only true Postgres proof is the operator's GA-drill against a live node.
    use super::*;

    #[test]
    fn hard4_postgres_select_consts_have_no_limit() {
        for (name, sql) in [
            ("PENDING_FOR_PEER_SELECT", PENDING_FOR_PEER_SELECT),
            ("INVITES_ISSUED_SELECT", INVITES_ISSUED_SELECT),
            ("RECURRING_MASTER_EVENTS_SELECT", RECURRING_MASTER_EVENTS_SELECT),
            (
                "CALENDAR_EXCEPTIONS_IN_RANGE_SELECT",
                CALENDAR_EXCEPTIONS_IN_RANGE_SELECT,
            ),
            (
                "OPERATOR_HOSTING_CONTRACTS_SELECT",
                OPERATOR_HOSTING_CONTRACTS_SELECT,
            ),
            (
                "OPERATOR_HOSTING_PAYMENTS_SELECT",
                OPERATOR_HOSTING_PAYMENTS_SELECT,
            ),
        ] {
            assert!(
                !sql.to_ascii_uppercase().contains("LIMIT"),
                "HARD-4: {name} must stay COMPLETE — a bare LIMIT re-creates the \
                 DBH1/DBH2 silent fail-open. Use a streaming/chunked complete-set \
                 read if a memory bound is genuinely needed."
            );
        }
    }

    /// DBH1: the Postgres peer-listing query must never regain a `LIMIT` clause —
    /// that silently truncates the durable gate-whitelist authority on a node
    /// with more than 1000 peers (Principle-2 fail-open). CI has no Postgres service, so
    /// this string assertion + code symmetry with the SQLite backend is the in-CI
    /// proof. The only true Postgres proof is the operator's GA-drill against a
    /// live Postgres node, which is out of scope for the autonomous build.
    #[test]
    fn peers_select_is_unbounded() {
        assert!(
            !super::PEERS_SELECT.to_uppercase().contains("LIMIT"),
            "postgres PEERS_SELECT must not contain LIMIT (DBH1 fail-open guard): {}",
            super::PEERS_SELECT
        );
    }
}

#[cfg(test)]
mod accepted_invites_guard {
    /// AUTHORITY: the accepted-invites replay query repopulates the admission
    /// whitelist at node startup. A `LIMIT` would silently drop active invites —
    /// a Principle-2 fail-open where validly-invited peers are rejected as
    /// `NotWhitelisted` after a restart, and the RV-RESTORE path loses
    /// relationships. Asserts the source constant so a cap cannot regress in.
    #[test]
    fn active_accepted_invites_select_is_unbounded() {
        assert!(
            !super::ACTIVE_ACCEPTED_INVITES_SELECT
                .to_uppercase()
                .contains("LIMIT"),
            "postgres ACTIVE_ACCEPTED_INVITES_SELECT must not contain LIMIT (AUTHORITY fail-open guard): {}",
            super::ACTIVE_ACCEPTED_INVITES_SELECT
        );
    }
}
