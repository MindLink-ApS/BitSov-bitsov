//! SQLite storage backend using sqlx.

use async_trait::async_trait;
use sqlx::migrate::{Migration, MigrationSource, MigrationType, Migrator};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::borrow::Cow;
use std::future::Future;
use std::pin::Pin;
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
use crate::reactions::ReactionRecord;
use crate::traits::Storage;

/// SQLite-backed storage for T1 Light and development.
pub struct SqliteStorage {
    pool: SqlitePool,
}

/// The on-disk file a SQLite connection string names, resolved with the same
/// parser [`SqliteStorage::open`] uses, so a filesystem probe and the runtime
/// agree on which file holds the store.
///
/// `open` accepts a bare path, `sqlite:<path>`, `sqlite://<path>` (so
/// `sqlite:///abs/store.sqlite` is `/abs/store.sqlite`), and trailing query
/// parameters such as `?mode=rwc`. A caller that treated the connection string
/// as a literal path would probe a file named `sqlite:///abs/store.sqlite`,
/// find nothing, and conclude the node holds no state.
///
/// Returns `None` when the string names no durable file — an in-memory
/// database, or a string `open` would itself reject — so the caller can fail
/// closed instead of probing a path that does not correspond to the store.
pub fn sqlite_file_path(connection: &str) -> Option<std::path::PathBuf> {
    let options = SqliteConnectOptions::from_str(connection).ok()?;
    let filename = options.get_filename();
    // `:memory:` is rewritten by sqlx to a synthetic `file:sqlx-in-memory-<n>`
    // name that never exists on disk.
    if filename.to_string_lossy().starts_with("file:") {
        return None;
    }
    Some(filename.to_path_buf())
}

impl SqliteStorage {
    /// Open (or create) a SQLite database at the given path.
    ///
    /// When `KONSENSUS_SQLITE_MIGRATIONS_DIR` is set, migrations are loaded from that
    /// directory (must be a superset of the embedded versions); otherwise the embedded
    /// set is used.
    pub async fn open(path: &str) -> Result<Self, StorageError> {
        let dir = std::env::var_os("KONSENSUS_SQLITE_MIGRATIONS_DIR").map(std::path::PathBuf::from);
        Self::open_with_migrations_dir(path, dir.as_deref()).await
    }

    /// Like [`Self::open`], with an explicit migrations directory (or embedded when `None`).
    ///
    /// Used by tests so they never mutate process-global environment variables that other
    /// concurrent `open` / `in_memory` callers also read.
    pub(crate) async fn open_with_migrations_dir(
        path: &str,
        migrations_dir: Option<&std::path::Path>,
    ) -> Result<Self, StorageError> {
        // `busy_timeout` and `cache_size` are PER-CONNECTION pragmas: set them on
        // the connect options so every connection the pool opens inherits them.
        // The previous `execute(&pool)` form configured only a single pooled
        // connection, leaving the other (up to 10) at busy_timeout=0 — an
        // immediate SQLITE_BUSY under concurrent writes (DBH2).
        let options = SqliteConnectOptions::from_str(path)
            .map_err(StorageError::Database)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(5))
            .pragma("cache_size", "-8000");

        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await?;

        let storage = Self { pool };
        storage.run_migrations(migrations_dir).await?;
        Ok(storage)
    }

    /// Create an in-memory SQLite database (for testing).
    pub async fn in_memory() -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")
            .map_err(StorageError::Database)?
            .busy_timeout(std::time::Duration::from_secs(5))
            .pragma("cache_size", "-8000");

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;

        let storage = Self { pool };
        let dir = std::env::var_os("KONSENSUS_SQLITE_MIGRATIONS_DIR").map(std::path::PathBuf::from);
        storage.run_migrations(dir.as_deref()).await?;
        Ok(storage)
    }

    /// Run schema migrations (genome #57).
    ///
    /// `migrations_dir` is the development override (from `KONSENSUS_SQLITE_MIGRATIONS_DIR`
    /// on the public `open` path); a released binary needs no files on disk. When `Some`,
    /// the directory must include **every** embedded migration version (extras are allowed).
    async fn run_migrations(
        &self,
        migrations_dir: Option<&std::path::Path>,
    ) -> Result<(), StorageError> {
        // Runtime sources on purpose: the sqlx `macros` feature (`sqlx::migrate!`) pulls
        // in MySQL support and the vulnerable `rsa` crate.
        let migrator = match migrations_dir {
            Some(path) => {
                validate_external_migrations_dir(path)?;
                Migrator::new(path).await?
            }
            None => Migrator::new(EmbeddedMigrations).await?,
        };
        migrator.run(&self.pool).await?;
        Ok(())
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

/// The SQLite schema, embedded in the binary so a released node is self-sufficient
/// (genome issue #57): rc4/rc5 shipped no migrations and resolved them from the build
/// host's `CARGO_MANIFEST_DIR`, which does not exist on a user's machine.
///
/// Version and SQL bytes are exactly what sqlx's file source produces for the same files,
/// so the applied-migration checksum (SHA-384 of the SQL) matches databases migrated by
/// earlier releases. Keep this table in sync with `migrations/`; the
/// `embedded_migrations_match_migrations_dir` test enforces it.
#[derive(Debug)]
pub(crate) struct EmbeddedMigrations;

/// `(version, description, sql)` — description mirrors sqlx's filename parsing
/// (`NNN_some_name.sql` → "some name").
const EMBEDDED_MIGRATIONS: &[(i64, &str, &str)] = &[
    (1, "initial", include_str!("../migrations/001_initial.sql")),
    (2, "sessions", include_str!("../migrations/002_sessions.sql")),
    (3, "pending deliveries", include_str!("../migrations/003_pending_deliveries.sql")),
    (4, "files", include_str!("../migrations/004_files.sql")),
    (5, "message plaintext", include_str!("../migrations/005_message_plaintext.sql")),
    (6, "pending deliveries fk", include_str!("../migrations/006_pending_deliveries_fk.sql")),
    (7, "fiat rate snapshots", include_str!("../migrations/007_fiat_rate_snapshots.sql")),
    (8, "recovery", include_str!("../migrations/008_recovery.sql")),
    (9, "contacts", include_str!("../migrations/009_contacts.sql")),
    (10, "invites issued", include_str!("../migrations/010_invites_issued.sql")),
    (11, "accepted invites", include_str!("../migrations/011_accepted_invites.sql")),
    (12, "onboarding state", include_str!("../migrations/012_onboarding_state.sql")),
    (
        13,
        "operator hosting contracts",
        include_str!("../migrations/013_operator_hosting_contracts.sql"),
    ),
    (14, "invite v2 fields", include_str!("../migrations/014_invite_v2_fields.sql")),
    (15, "invite expired state", include_str!("../migrations/015_invite_expired_state.sql")),
    (16, "invite opening state", include_str!("../migrations/016_invite_opening_state.sql")),
    (
        17,
        "onboarding state funding evidence",
        include_str!("../migrations/017_onboarding_state_funding_evidence.sql"),
    ),
    (18, "onboarding state scope", include_str!("../migrations/018_onboarding_state_scope.sql")),
    (19, "payment receipts", include_str!("../migrations/019_payment_receipts.sql")),
    (20, "pending delivery state", include_str!("../migrations/020_pending_delivery_state.sql")),
    (21, "paid delivery rejections", include_str!("../migrations/021_paid_delivery_rejections.sql")),
    (22, "receipt bindings", include_str!("../migrations/022_receipt_bindings.sql")),
    (23, "delivery price quotes", include_str!("../migrations/023_delivery_price_quotes.sql")),
    (24, "outbox operations", include_str!("../migrations/024_outbox_operations.sql")),
    (25, "outbox recovery", include_str!("../migrations/025_outbox_recovery.sql")),
    (26, "outstanding web requests", include_str!("../migrations/026_outstanding_web_requests.sql")),
];

/// Migration version numbers compiled into this binary, in ascending order.
pub fn embedded_migration_versions() -> Vec<i64> {
    EmbeddedMigrations::migrations()
        .into_iter()
        .map(|m| m.version)
        .collect()
}

/// Fail closed when an operator points `KONSENSUS_SQLITE_MIGRATIONS_DIR` at a stale tree
/// (for example a systemd unit left over from an older package) so the node cannot start
/// with a schema missing migrations the binary expects.
pub fn validate_external_migrations_dir(dir: &std::path::Path) -> Result<(), StorageError> {
    let embedded: Vec<i64> = embedded_migration_versions();
    let max_embedded = *embedded.last().unwrap_or(&0);
    let present = migration_versions_in_dir(dir)?;
    let missing: Vec<i64> = embedded
        .into_iter()
        .filter(|v| !present.contains(v))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(StorageError::IncompleteMigrationsDir {
        dir: dir.display().to_string(),
        missing,
        max_embedded,
    })
}

fn migration_versions_in_dir(dir: &std::path::Path) -> Result<std::collections::BTreeSet<i64>, StorageError> {
    let entries = std::fs::read_dir(dir).map_err(|e| {
        StorageError::Unsupported(format!(
            "KONSENSUS_SQLITE_MIGRATIONS_DIR={}: {e}",
            dir.display()
        ))
    })?;
    let mut versions = std::collections::BTreeSet::new();
    for entry in entries {
        let entry = entry.map_err(|e| StorageError::Unsupported(format!(
            "KONSENSUS_SQLITE_MIGRATIONS_DIR={}: {e}",
            dir.display()
        )))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("sql") {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        let Some((version_str, _)) = name.split_once('_') else {
            return Err(StorageError::Unsupported(format!(
                "KONSENSUS_SQLITE_MIGRATIONS_DIR={}: invalid migration filename {name}",
                dir.display()
            )));
        };
        let version: i64 = version_str.parse().map_err(|_| {
            StorageError::Unsupported(format!(
                "KONSENSUS_SQLITE_MIGRATIONS_DIR={}: invalid migration version in {name}",
                dir.display()
            ))
        })?;
        versions.insert(version);
    }
    Ok(versions)
}

impl EmbeddedMigrations {
    /// The embedded schema as sqlx migrations, in version order.
    pub(crate) fn migrations() -> Vec<Migration> {
        EMBEDDED_MIGRATIONS
            .iter()
            .map(|(version, description, sql)| {
                Migration::new(
                    *version,
                    Cow::Borrowed(*description),
                    MigrationType::Simple,
                    Cow::Borrowed(*sql),
                    sql.starts_with("-- no-transaction"),
                )
            })
            .collect()
    }
}

impl MigrationSource<'static> for EmbeddedMigrations {
    fn resolve(
        self,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<Vec<Migration>, Box<dyn std::error::Error + Send + Sync + 'static>>,
                > + Send
                + 'static,
        >,
    > {
        Box::pin(async move { Ok(Self::migrations()) })
    }
}

// Helper: serialize Recipient to (type, id) strings
fn recipient_to_parts(r: &Recipient) -> (&'static str, String) {
    match r {
        Recipient::Node(id) => ("node", id.to_hex()),
        Recipient::Room(id) => ("room", id.to_string()),
        Recipient::Broadcast => ("broadcast", String::new()),
    }
}

// Helper: deserialize Recipient from (type, id) strings
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

// Helper: reconstruct UkmEnvelope from database row fields
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

/// Session-listing query for the SQLite backend. Returns ALL stored sessions —
/// deliberately **no `LIMIT`** (DBH2, sibling of the DBH1 `list_peers` fix).
///
/// `restore_sessions()` reads this at boot to resume every E2EE Double-Ratchet
/// session from the previous run. A cap here silently drops the overflow ratchet
/// state on a node with more live sessions than the cap (the old `LIMIT 1000`
/// ordered `updated_at DESC`, so it discarded the *oldest* sessions first), forcing
/// an unnecessary X3DH re-handshake and orphaning any pending deliveries keyed to
/// those sessions — a Principle-2 fail-open at scale. The `dbh2_guard` unit test
/// asserts this constant never regains a `LIMIT`.
const SESSIONS_SELECT: &str = "SELECT peer_id FROM sessions ORDER BY updated_at DESC";

/// Distinct-recipient query for the SQLite backend. Returns EVERY peer with a
/// queued delivery — deliberately **no `LIMIT`** (DBH2).
///
/// `pending_deliveries` is the durable outbound queue authority. A cap here means a
/// node with queued mail to more than the cap of distinct peers silently never
/// enumerates the overflow recipients, so their own already-accepted messages are
/// never flushed on reconnect — a Principle-2 fail-open. The `dbh2_guard` unit test
/// asserts this constant never regains a `LIMIT`.
const PENDING_PEERS_SELECT: &str = "SELECT DISTINCT recipient_id FROM pending_deliveries WHERE state != 'failed_paid'";

/// Room-membership query for the SQLite backend. Returns ALL members of a room —
/// deliberately **no `LIMIT`** (DBH2).
///
/// The message send/compose fan-out reads this to decide who receives a room
/// message. A cap here silently excludes the overflow members from delivery on a
/// room larger than the cap (the old `LIMIT 10000` ordered `joined_at`, so it
/// dropped the most recently joined), a Principle-2 fail-open. The `dbh2_guard`
/// unit test asserts this constant never regains a `LIMIT`.
const ROOM_MEMBERS_SELECT: &str =
    "SELECT node_id FROM room_members WHERE room_id = ? ORDER BY joined_at";

// ── HARD-4 complete-set query constants (SQLite) ─────────────────────────
//
// Each query below was flagged (HARD-4, Codex red-team on #225) as
// "untruncated". STEP 0 of HARD-4 is to classify each as AUTHORITY (used by the
// gate / recovery / fan-out / money-path) vs READ-SURFACE, then enforce: an
// AUTHORITY query MUST return the COMPLETE set. Adding a bare `LIMIT` to any of
// these re-creates the DBH1/DBH2 silent fail-open (a node a) drops the overflow
// without error and b) makes a Principle-2 / correctness decision on a partial
// view). These constants exist so the contract is explicit and so the
// `hard4_guard` test can assert no `LIMIT` ever regresses back in. Mirrors the
// `PEERS_SELECT` pattern DBH1 established. None of these accepts a caller limit
// or is a paginated list endpoint, so there is no bounded variant to add; the
// few external list surfaces (e.g. `GET /api/v1/invites`) read the same complete
// authority method and filter in memory.

/// `get_pending_for_peer` — AUTHORITY. The per-peer outbound delivery queue read
/// by the pending-delivery flusher (`pending_handler::flush_peer`). A cap would
/// silently never re-send the overflow queued messages on reconnect. Bounded
/// naturally by one peer's queue depth (`WHERE recipient_id = ?`).
const PENDING_FOR_PEER_SELECT: &str =
    "SELECT message_id, attempts FROM pending_deliveries \
     WHERE recipient_id = ? AND state != 'failed_paid' AND retry_after_ms <= CAST(strftime('%s', 'now') AS BIGINT) * 1000 ORDER BY queued_at ASC";

/// `list_invites_issued` — AUTHORITY. Read by the duplicate-pending-invite gate
/// (`POST /api/v1/invites` → `has_live_pending_for_invitee`) and the acceptance
/// lookup (`find_pending_invite_for_invitee`). A cap could let a node re-issue a
/// duplicate invite or fail to find a valid one. The `GET /api/v1/invites` list
/// surface reads this same method and re-signs in memory.
const INVITES_ISSUED_SELECT: &str =
    "SELECT id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at \
     FROM invites_issued ORDER BY created_at DESC";

/// `list_active_accepted_invites` — AUTHORITY. Replayed at node startup
/// (`replay_accepted_invite_whitelist` in `konsensus-node`) to repopulate the
/// in-memory admission whitelist from durable accepted invites. A `LIMIT` here
/// is a Principle-2 fail-open: it would silently omit active invites from the
/// startup whitelist, so validly-invited peers would be rejected as
/// `NotWhitelisted` after a restart. The mnemonic-recovery / RV-RESTORE path
/// also depends on the COMPLETE active set surviving. The `accepted_invites_guard`
/// unit test asserts this constant never regains a `LIMIT`.
const ACTIVE_ACCEPTED_INVITES_SELECT: &str =
    "SELECT nonce, inviter_pubkey, expiry_unix, accepted_at \
     FROM accepted_invites WHERE expiry_unix > ? ORDER BY accepted_at ASC";

/// `list_recurring_master_events` — correctness-complete. The calendar view
/// (`GET /api/v1/calendar/events`) expands every recurring master into
/// occurrences inside the requested window; a cap would silently hide whole
/// recurring series from the user's calendar.
const RECURRING_MASTER_EVENTS_SELECT: &str =
    "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
            location, attendees_json, recurrence_json, color, created_at, parent_id
     FROM calendar_events
     WHERE recurrence_json IS NOT NULL AND parent_id IS NULL
     ORDER BY start_ms ASC";

/// `list_recurring_master_events_before` — bounded API read probe. The caller
/// passes `budget + 1` and fails closed if the extra row exists, so this LIMIT
/// does not silently hide recurring series.
const RECURRING_MASTER_EVENTS_BEFORE_SELECT: &str =
    "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
            location, attendees_json, recurrence_json, color, created_at, parent_id
     FROM calendar_events
     WHERE recurrence_json IS NOT NULL AND parent_id IS NULL AND start_ms < ?1
     ORDER BY start_ms ASC
     LIMIT ?2";

/// `list_calendar_exceptions_in_range` — correctness-complete. Exceptions
/// suppress / override expanded occurrences in the calendar view. A cap would
/// silently let a deleted or moved occurrence reappear. Range-scoped by
/// `start_ms`/`end_ms`.
const CALENDAR_EXCEPTIONS_IN_RANGE_SELECT: &str =
    "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
            location, attendees_json, recurrence_json, color, created_at, parent_id
     FROM calendar_events
     WHERE parent_id IS NOT NULL AND start_ms < ?2 AND end_ms > ?1
     ORDER BY start_ms ASC";

/// `list_fiat_rate_snapshots` — READ-SURFACE, range-scoped. Bounded by the
/// caller's `[from_date, to_date]` window; not a full-table scan. Documented
/// complete so a future cap (which would silently drop dates inside the
/// requested window) is rejected by the guard test.
const FIAT_RATE_SNAPSHOTS_SELECT: &str =
    "SELECT date, currency, rate, source, created_at
     FROM fiat_rate_snapshots
     WHERE date >= ?1 AND date <= ?2
     ORDER BY date DESC, currency ASC";

/// `list_operator_hosting_contracts` — AUTHORITY (money-path). The daily hosting
/// payment task (`hosting_pay::pay_due_contracts_once`) iterates EVERY contract
/// to pay due tenants. A cap would silently never pay the overflow contracts — a
/// Principle-2 money-path fail. If a memory bound is ever genuinely needed here,
/// it MUST be a streaming/chunked read with a complete-set contract, never a
/// bare `LIMIT`.
const OPERATOR_HOSTING_CONTRACTS_SELECT: &str =
    "SELECT id, tenant_pubkey, operator_pubkey, sats_per_day, started_at, last_paid_at, state
     FROM operator_hosting_contracts
     ORDER BY started_at ASC";

/// `list_operator_hosting_payments` — READ-SURFACE, scoped to one contract
/// (`WHERE contract_id = ?1`). Bounded by a single contract's payment history;
/// not a full-table scan. Documented complete so a future cap is rejected.
const OPERATOR_HOSTING_PAYMENTS_SELECT: &str =
    "SELECT payment_hash, contract_id, tenant_pubkey, operator_pubkey, amount_msat,
            paid_at, direction, preimage, memo
     FROM operator_hosting_payments
     WHERE contract_id = ?1
     ORDER BY paid_at DESC";
/// Peer-listing query for the SQLite backend. Returns ALL peers — deliberately
/// **no `LIMIT`** (DBH1). Since #197 the `peers` table is the single durable
/// gate-whitelist authority (boot-loaded into `PeerRegistry` via
/// `merge_persisted_peers`) and the RV-RESTORE backup source
/// (`WhitelistBackup::collect`). A cap here silently drops paid counterparties
/// off the gate whitelist on restart/restore — a Principle-2 fail-open. The
/// `dbh1_guard` unit test asserts this constant never regains a `LIMIT`.
const PEERS_SELECT: &str =
    "SELECT node_id, address, last_seen, display_name, metadata_json FROM peers ORDER BY node_id";

#[async_trait]
impl Storage for SqliteStorage {
    async fn record_outbox_sent(&self, id: &MessageId, peer: &NodeId) -> Result<(), StorageError> {
        sqlx::query("UPDATE outbox_operations SET state = 'sent', last_sent_at = CAST(strftime('%s', 'now') AS BIGINT) * 1000, updated_at = CAST(strftime('%s', 'now') AS BIGINT) * 1000, version = version + 1 WHERE message_id = ? AND recipient = ? AND state IN ('paid', 'sent')")
            .bind(id.to_hex()).bind(peer.to_hex()).execute(&self.pool).await?;
        Ok(())
    }

    async fn insert_outbox_operation(&self, op: &crate::OutboxOperation) -> Result<bool, StorageError> {
        Ok(sqlx::query("INSERT INTO outbox_operations (operation_id, recipient, kind, request_hash, state, payment_hash, admission_payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery, accounting_pending, recovery_compacted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(operation_id) DO NOTHING")
            .bind(&op.operation_id)
            .bind(&op.recipient)
            .bind(op.kind)
            .bind(&op.request_hash)
            .bind(&op.state)
            .bind(&op.payment_hash)
            .bind(&op.admission_payment_hash)
            .bind(&op.message_id)
            .bind(op.settled_msat)
            .bind(op.readmission_msat)
            .bind(op.created_at)
            .bind(op.updated_at)
            .bind(op.last_sent_at)
            .bind(op.attempts)
            .bind(&op.last_error)
            .bind(op.version)
            .bind(&op.recovery)
            .bind(op.accounting_pending)
            .bind(op.recovery_compacted)
            .execute(&self.pool).await?.rows_affected() == 1)
    }
    async fn update_outbox_operation(&self, op: &crate::OutboxOperation) -> Result<bool, StorageError> {
        Ok(sqlx::query("UPDATE outbox_operations SET state = ?, payment_hash = ?, admission_payment_hash = ?, message_id = ?, settled_msat = ?, readmission_msat = ?, updated_at = ?, last_sent_at = ?, attempts = ?, last_error = ?, recovery = ?, accounting_pending = ?, recovery_compacted = ?, version = version + 1 WHERE operation_id = ? AND version = ?")
            .bind(&op.state)
            .bind(&op.payment_hash)
            .bind(&op.admission_payment_hash)
            .bind(&op.message_id)
            .bind(op.settled_msat)
            .bind(op.readmission_msat)
            .bind(op.updated_at)
            .bind(op.last_sent_at)
            .bind(op.attempts)
            .bind(&op.last_error)
            .bind(&op.recovery)
            .bind(op.accounting_pending)
            .bind(op.recovery_compacted)
            .bind(&op.operation_id).bind(op.version)
            .execute(&self.pool).await?.rows_affected() == 1)
    }

    async fn get_outbox_operation(&self, id: &str) -> Result<Option<crate::OutboxOperation>, StorageError> {
        Ok(sqlx::query_as("SELECT operation_id, recipient, kind, request_hash, state, payment_hash, admission_payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery, accounting_pending, recovery_compacted FROM outbox_operations WHERE operation_id = ?").bind(id).fetch_optional(&self.pool).await?)
    }
    async fn list_recoverable_operations(&self) -> Result<Vec<crate::OutboxOperation>, StorageError> {
        Ok(sqlx::query_as("SELECT operation_id, recipient, kind, request_hash, state, payment_hash, admission_payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery, accounting_pending, recovery_compacted FROM outbox_operations INDEXED BY outbox_operations_recovery WHERE accounting_pending = TRUE OR state IN ('paying', 'payment_unknown', 'paid', 'sent', 'rejected_retryable') ORDER BY created_at").fetch_all(&self.pool).await?)
    }
    // Pin the partial index: without statistics SQLite can prefer the old
    // state index, walking all terminal history and sorting before LIMIT.
    async fn list_compactable_operations(&self, before_ms: i64, limit: u32) -> Result<Vec<crate::OutboxOperation>, StorageError> {
        Ok(sqlx::query_as("SELECT operation_id, recipient, kind, request_hash, state, payment_hash, admission_payment_hash, message_id, settled_msat, readmission_msat, created_at, updated_at, last_sent_at, attempts, last_error, version, recovery, accounting_pending, recovery_compacted FROM outbox_operations INDEXED BY outbox_operations_retention WHERE accounting_pending = FALSE AND recovery_compacted = FALSE AND state IN ('acked', 'failed_paid') AND updated_at < ? ORDER BY updated_at LIMIT ?")
            .bind(before_ms).bind(i64::from(limit)).fetch_all(&self.pool).await?)
    }


    // ── Messages ───────────────────────────────────────────────────────

    async fn commit_outbox_envelope(&self, op: &crate::OutboxOperation, envelope: &UkmEnvelope) -> Result<bool, StorageError> {
        if op.state != "paid" || op.message_id.as_deref() != Some(envelope.id.to_hex().as_str()) || envelope.recipient != Recipient::Node(NodeId::from_hex(&op.recipient).map_err(|e| StorageError::Conversion(e.to_string()))?) {
            return Err(StorageError::Conversion("invalid paid operation binding".into()));
        }
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("UPDATE outbox_operations SET state = ?, payment_hash = ?, admission_payment_hash = ?, message_id = ?, settled_msat = ?, readmission_msat = ?, updated_at = ?, last_sent_at = ?, attempts = ?, last_error = ?, recovery = ?, accounting_pending = ?, recovery_compacted = ?, version = version + 1 WHERE operation_id = ? AND version = ?")
            .bind(&op.state)
            .bind(&op.payment_hash)
            .bind(&op.admission_payment_hash)
            .bind(&op.message_id)
            .bind(op.settled_msat)
            .bind(op.readmission_msat)
            .bind(op.updated_at)
            .bind(op.last_sent_at)
            .bind(op.attempts)
            .bind(&op.last_error)
            .bind(&op.recovery)
            .bind(op.accounting_pending)
            .bind(op.recovery_compacted)
            .bind(&op.operation_id).bind(op.version)
            .execute(&mut *tx).await?.rows_affected() == 1;
        if !changed { tx.rollback().await?; return Ok(false); }
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
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .execute(&mut *tx)
        .await?;

        sqlx::query("INSERT INTO pending_deliveries (message_id, recipient_id) VALUES (?, ?) ON CONFLICT DO NOTHING")
            .bind(envelope.id.to_hex()).bind(&op.recipient).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(true)
    }

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
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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

    async fn record_delivery_prices(&self, sender: &NodeId, prices: &[(String, u64)], excluded_kinds: &[u16], issued_at: u64, expires_at: u64) -> Result<(), StorageError> {
        if expires_at <= issued_at || expires_at - issued_at > konsensus_core::gate::DELIVERY_PRICE_WINDOW_SECS {
            return Err(StorageError::Conversion("invalid delivery price window".into()));
        }
        let issued = i64::try_from(issued_at).map_err(|_| StorageError::Conversion("quote time overflow".into()))?;
        let expires = i64::try_from(expires_at).map_err(|_| StorageError::Conversion("quote expiry overflow".into()))?;
        let exclusions = format!(",{},", excluded_kinds.iter().map(u16::to_string).collect::<Vec<_>>().join(","));
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM delivery_price_quotes WHERE expires_at < ?").bind(issued.saturating_sub(konsensus_core::gate::DELIVERY_PRICE_WINDOW_SECS as i64)).execute(&mut *tx).await?;
        for (scope, amount) in prices {
            let amount = i64::try_from(*amount).map_err(|_| StorageError::Conversion("quote amount overflow".into()))?;
            sqlx::query("INSERT INTO delivery_price_quotes (sender, scope, amount_msat, issued_at, expires_at, excluded_kinds) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING")
                .bind(sender.to_hex()).bind(scope).bind(amount).bind(issued).bind(expires).bind(&exclusions).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn delivery_price_floor(&self, envelope: &UkmEnvelope, paid_at: u64, now: u64) -> Result<Option<u64>, StorageError> {
        // Paid-at comes from our Lightning backend, never the signed wrapper.
        if paid_at > now || now.saturating_sub(paid_at) > konsensus_core::gate::DELIVERY_PRICE_WINDOW_SECS { return Ok(None); }
        let paid = i64::try_from(paid_at).map_err(|_| StorageError::Conversion("payment time overflow".into()))?;
        let category = format!("category:{}", konsensus_core::kind::KindCategory::from_kind(envelope.kind).price_table_key());
        let amount: Option<i64> = sqlx::query_scalar("SELECT MIN(amount_msat) FROM delivery_price_quotes WHERE sender = ? AND (scope = ? OR (scope = ? AND excluded_kinds NOT LIKE ?)) AND issued_at <= ? AND expires_at >= ?")
            .bind(envelope.sender.to_hex()).bind(format!("kind:{}", envelope.kind)).bind(category).bind(format!("%,{},%", envelope.kind)).bind(paid).bind(paid)
            .fetch_one(&self.pool).await?;
        amount.map(|n| u64::try_from(n).map_err(|_| StorageError::Conversion("negative quoted price".into()))).transpose()
    }

    async fn is_paid_envelope_accepted(&self, envelope: &UkmEnvelope) -> Result<bool, StorageError> {
        let id = envelope.id.to_hex();
        let kind = i64::from(envelope.kind);
        let sender = envelope.sender.to_hex();
        let (rtype, rid) = recipient_to_parts(&envelope.recipient);
        let ph = hex::encode(envelope.payment_proof.payment_hash);
        let pi = hex::encode(envelope.payment_proof.preimage);
        let amt = i64::try_from(envelope.payment_proof.amount_msat)
            .map_err(|_| StorageError::Conversion(format!("amount_msat overflows i64: {}", envelope.payment_proof.amount_msat)))?;
        let nonce = hex::encode(envelope.nonce.as_bytes());
        let refs: Vec<String> = envelope.references.iter().map(|r| r.to_hex()).collect();
        let refs_json =
            serde_json::to_string(&refs).map_err(|e| StorageError::Serialization(e.to_string()))?;

        let durable: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_receipts WHERE payment_hash = ? AND message_id = ? AND sender = ? AND accepted = 1 AND kind = ? AND recipient_type = ? AND recipient_id = ? AND preimage = ? AND amount_msat = ? AND nonce = ? AND references_json = ?")
            .bind(&ph).bind(&id).bind(&sender).bind(kind).bind(rtype).bind(&rid)
            .bind(&pi).bind(amt).bind(&nonce).bind(&refs_json)
            .fetch_one(&self.pool).await?;
        if durable == 1 { return Ok(true); }
        let matched: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_receipts r JOIN messages m ON m.id = r.message_id WHERE r.payment_hash = ? AND r.message_id = ? AND r.sender = ? AND m.sender = r.sender AND m.kind = ? AND m.recipient_type = ? AND m.recipient_id = ? AND m.payment_hash = r.payment_hash AND m.preimage = ? AND m.amount_msat = ? AND m.nonce = ? AND m.references_json = ?")
            .bind(&ph).bind(&id).bind(&sender).bind(kind).bind(rtype).bind(&rid)
            .bind(&pi).bind(amt).bind(&nonce).bind(&refs_json)
            .fetch_one(&self.pool).await?;
        if matched != 1 { return Ok(false); }
        // A legacy full-message match is already accepted. Preserve its binding
        // before ACK so subsequent content retention cannot erase that evidence.
        // The guarded UPDATE never inserts a message or consumes a fresh proof.
        let upgraded = sqlx::query("UPDATE payment_receipts SET accepted = 1, kind = ?, recipient_type = ?, recipient_id = ?, preimage = ?, amount_msat = ?, nonce = ?, references_json = ? WHERE payment_hash = ? AND message_id = ? AND sender = ? AND EXISTS (SELECT 1 FROM messages m WHERE m.id = payment_receipts.message_id AND m.sender = payment_receipts.sender AND m.kind = ? AND m.recipient_type = ? AND m.recipient_id = ? AND m.payment_hash = payment_receipts.payment_hash AND m.preimage = ? AND m.amount_msat = ? AND m.nonce = ? AND m.references_json = ?)")
            .bind(kind).bind(rtype).bind(&rid).bind(&pi).bind(amt).bind(&nonce).bind(&refs_json)
            .bind(&ph).bind(&id).bind(&sender)
            .bind(kind).bind(rtype).bind(&rid).bind(&pi).bind(amt).bind(&nonce).bind(&refs_json)
            .execute(&self.pool).await?.rows_affected();
        if upgraded != 1 {
            // A retention race is retryable, never a current-price rejection.
            return Err(StorageError::Conversion("legacy acceptance binding changed during lookup".into()));
        }
        Ok(true)
    }

    async fn accept_paid_envelope(&self, envelope: &UkmEnvelope) -> Result<crate::PaidAcceptance, StorageError> {
        use crate::PaidAcceptance::*;
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

        let mut tx = self.pool.begin().await?;
        let receipt = sqlx::query("INSERT INTO payment_receipts (payment_hash, message_id, sender) VALUES (?, ?, ?) ON CONFLICT DO NOTHING")
            .bind(&ph).bind(&id).bind(&sender).execute(&mut *tx).await?;
        let healing = receipt.rows_affected() == 0;
        if healing {
            // Serialize legacy healers on the receipt binding (SQLite already
            // holds the writer lock from the INSERT above).
            let binding: (String, String, i32) = sqlx::query_as("SELECT message_id, sender, accepted FROM payment_receipts WHERE payment_hash = ?")
                .bind(&ph).fetch_one(&mut *tx).await?;
            if binding.0 != id || binding.1 != sender {
                tx.rollback().await?;
                return Ok(PaymentReused);
            }
            // Receipt metadata is independent of retained message content and
            // excludes only the timestamp/signature wrapper refreshed on retry.
            let durable: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_receipts WHERE payment_hash = ? AND message_id = ? AND sender = ? AND accepted = 1 AND kind = ? AND recipient_type = ? AND recipient_id = ? AND preimage = ? AND amount_msat = ? AND nonce = ? AND references_json = ?")
                .bind(&ph).bind(&id).bind(&sender).bind(kind).bind(rtype).bind(&rid)
                .bind(&pi).bind(amt).bind(&nonce).bind(&refs_json)
                .fetch_one(&mut *tx).await?;
            if durable == 1 {
                tx.rollback().await?;
                return Ok(AlreadyAccepted);
            }
            let matched: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM payment_receipts r JOIN messages m ON m.id = r.message_id WHERE r.payment_hash = ? AND r.message_id = ? AND r.sender = ? AND m.sender = r.sender AND m.kind = ? AND m.recipient_type = ? AND m.recipient_id = ? AND m.payment_hash = r.payment_hash AND m.preimage = ? AND m.amount_msat = ? AND m.nonce = ? AND m.references_json = ?")
                .bind(&ph).bind(&id).bind(&sender).bind(kind).bind(rtype).bind(&rid)
                .bind(&pi).bind(amt).bind(&nonce).bind(&refs_json)
                .fetch_one(&mut *tx).await?;
            if matched == 1 {
                sqlx::query("UPDATE payment_receipts SET accepted = 1, kind = ?, recipient_type = ?, recipient_id = ?, preimage = ?, amount_msat = ?, nonce = ?, references_json = ? WHERE payment_hash = ?")
                    .bind(kind).bind(rtype).bind(&rid).bind(&pi).bind(amt).bind(&nonce).bind(&refs_json).bind(&ph).execute(&mut *tx).await?;
                tx.commit().await?;
                return Ok(AlreadyAccepted);
            }
            let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM messages WHERE id = ?")
                .bind(&id).fetch_one(&mut *tx).await?;
            if exists != 0 || binding.2 != 0 {
                tx.rollback().await?;
                return Ok(PaymentReused);
            }
            // Full gate validation precedes this transaction. The receipt
            // binds this paid identity; repair only its missing message row.
        }
        let inserted = sqlx::query("INSERT INTO nonces (nonce_hex, sender) VALUES (?, ?) ON CONFLICT DO NOTHING")
            .bind(&nonce).bind(&sender).execute(&mut *tx).await?;
        if inserted.rows_affected() == 0 {
            let owner: String = sqlx::query_scalar("SELECT sender FROM nonces WHERE nonce_hex = ?")
                .bind(&nonce).fetch_one(&mut *tx).await?;
            if !healing || owner != sender {
                tx.rollback().await?;
                return Ok(NonceReused);
            }
        }
        sqlx::query(
            "INSERT INTO messages (id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
             ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .execute(&mut *tx)
        .await?;

        sqlx::query("UPDATE payment_receipts SET accepted = 1, kind = ?, recipient_type = ?, recipient_id = ?, preimage = ?, amount_msat = ?, nonce = ?, references_json = ? WHERE payment_hash = ?")
            .bind(kind).bind(rtype).bind(&rid).bind(&pi).bind(amt).bind(&nonce).bind(&refs_json).bind(&ph).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(Accepted)
    }

    async fn update_message_wrapper(&self, envelope: &UkmEnvelope) -> Result<(), StorageError> {
        let ts = i64::try_from(envelope.timestamp).map_err(|_| StorageError::Conversion("timestamp overflow".into()))?;
        let result = sqlx::query("UPDATE messages SET timestamp_ms = ?, signature = ? WHERE id = ? AND sender = ? AND payment_hash = ?")
            .bind(ts).bind(hex::encode(envelope.signature.as_bytes())).bind(envelope.id.to_hex())
            .bind(envelope.sender.to_hex()).bind(hex::encode(envelope.payment_proof.payment_hash))
            .execute(&self.pool).await?;
        if result.rows_affected() != 1 { return Err(StorageError::Conversion("missing paid envelope".into())); }
        Ok(())
    }

    async fn mark_pending_sent(&self, id: &MessageId, peer: &NodeId) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("UPDATE pending_deliveries SET dispatched = 1, retry_after_ms = 0 WHERE message_id = ? AND recipient_id = ? AND state != 'failed_paid' AND retry_after_ms <= CAST(strftime('%s', 'now') AS BIGINT) * 1000")
            .bind(id.to_hex()).bind(peer.to_hex()).execute(&mut *tx).await?.rows_affected();
        if changed != 1 { return Err(StorageError::Conversion("delivery is not eligible for dispatch".into())); }
        if changed == 1 {
            sqlx::query("UPDATE outbox_operations SET state = CASE WHEN state = 'rejected_retryable' THEN 'paid' ELSE state END, version = version + 1, updated_at = CAST(strftime('%s', 'now') AS BIGINT) * 1000, attempts = attempts + 1 WHERE message_id = ? AND recipient = ? AND state IN ('paid', 'sent', 'rejected_retryable')").bind(id.to_hex()).bind(peer.to_hex()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn is_pending_dispatched(&self, id: &MessageId, peer: &NodeId, sender: &NodeId) -> Result<bool, StorageError> {
        Ok(sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pending_deliveries p JOIN messages m ON m.id = p.message_id WHERE p.message_id = ? AND p.recipient_id = ? AND p.dispatched = 1 AND p.state != 'failed_paid' AND m.sender = ?)").bind(id.to_hex()).bind(peer.to_hex()).bind(sender.to_hex()).fetch_one(&self.pool).await?)
    }

    async fn reject_pending(&self, id: &MessageId, peer: &NodeId, sender: &NodeId, reason: &str, terminal: bool) -> Result<bool, StorageError> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("UPDATE pending_deliveries SET state = ?, rejection_reason = ?, retry_after_ms = CAST(strftime('%s', 'now') AS BIGINT) * 1000 + MIN(3600000, 60000 * (1 << MIN(attempts, 6))), attempts = attempts + 1 WHERE message_id = ? AND recipient_id = ? AND dispatched = 1 AND state != 'failed_paid' AND retry_after_ms = 0 AND EXISTS (SELECT 1 FROM messages WHERE id = pending_deliveries.message_id AND sender = ?)")
            .bind(if terminal { "failed_paid" } else { "pending" }).bind(reason)
            .bind(id.to_hex()).bind(peer.to_hex()).bind(sender.to_hex())
            .execute(&mut *tx).await?.rows_affected() == 1;
            if changed {
            sqlx::query("UPDATE outbox_operations SET state = ?, last_error = ?, version = version + 1, updated_at = CAST(strftime('%s', 'now') AS BIGINT) * 1000 WHERE message_id = ? AND recipient = ? AND state IN ('paid', 'sent', 'rejected_retryable')").bind(if terminal { "failed_paid" } else { "rejected_retryable" }).bind(reason).bind(id.to_hex()).bind(peer.to_hex()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    async fn acknowledge_pending(&self, id: &MessageId, peer: &NodeId, sender: &NodeId) -> Result<bool, StorageError> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("DELETE FROM pending_deliveries WHERE message_id = ? AND recipient_id = ? AND dispatched = 1 AND state != 'failed_paid' AND EXISTS (SELECT 1 FROM messages WHERE id = pending_deliveries.message_id AND sender = ?)").bind(id.to_hex()).bind(peer.to_hex()).bind(sender.to_hex())
            .execute(&mut *tx).await?.rows_affected() == 1;
            if changed {
            sqlx::query("UPDATE outbox_operations SET state = 'acked', version = version + 1, updated_at = CAST(strftime('%s', 'now') AS BIGINT) * 1000 WHERE message_id = ? AND recipient = ? AND state IN ('paid', 'sent', 'rejected_retryable')").bind(id.to_hex()).bind(peer.to_hex()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    async fn acknowledge_pending_payment(&self, id: &MessageId, peer: &NodeId, sender: &NodeId, hash: &[u8; 32]) -> Result<bool, StorageError> {
        let mut tx = self.pool.begin().await?;
        let changed = sqlx::query("DELETE FROM pending_deliveries WHERE message_id = ? AND recipient_id = ? AND dispatched = 1 AND state != 'failed_paid' AND EXISTS (SELECT 1 FROM messages WHERE id = pending_deliveries.message_id AND sender = ? AND payment_hash = ?)").bind(id.to_hex()).bind(peer.to_hex()).bind(sender.to_hex()).bind(hex::encode(hash))
            .execute(&mut *tx).await?.rows_affected() == 1;
            if changed {
            sqlx::query("UPDATE outbox_operations SET state = 'acked', version = version + 1, updated_at = CAST(strftime('%s', 'now') AS BIGINT) * 1000 WHERE message_id = ? AND recipient = ? AND state IN ('paid', 'sent', 'rejected_retryable')").bind(id.to_hex()).bind(peer.to_hex()).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    async fn get_message(&self, id: &MessageId) -> Result<Option<UkmEnvelope>, StorageError> {
        let id_hex = id.to_hex();

        let row = sqlx::query_as::<_, (
            String,  // id
            i64,     // kind
            String,  // sender
            String,  // recipient_type
            String,  // recipient_id
            i64,     // timestamp_ms
            Vec<u8>, // ciphertext
            String,  // payment_hash
            String,  // preimage
            i64,     // amount_msat
            String,  // signature
            String,  // nonce
            String,  // references_json
        )>(
            "SELECT id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
             ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json \
             FROM messages WHERE id = ?",
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
             FROM messages WHERE recipient_type = ? AND recipient_id = ? AND timestamp_ms < ? \
             ORDER BY timestamp_ms DESC LIMIT ?",
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
                 FROM messages WHERE recipient_type = 'room' AND recipient_id = ? AND timestamp_ms < ? \
                 ORDER BY timestamp_ms DESC LIMIT ?",
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
                   (sender = ? AND recipient_type = 'node' AND recipient_id = ?) \
                   OR (sender = ? AND recipient_type = 'node' AND recipient_id = ?) \
                 ) AND timestamp_ms < ? \
                 ORDER BY timestamp_ms DESC LIMIT ?",
            )
            .bind(peer_or_room_id)
            .bind(my_node_id)
            .bind(my_node_id)
            .bind(peer_or_room_id)
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
        sqlx::query("DELETE FROM pending_deliveries WHERE message_id = ?")
            .bind(&id_hex)
            .execute(&self.pool)
            .await?;
        let result = sqlx::query("DELETE FROM messages WHERE id = ?")
            .bind(&id_hex)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn energy_rows_since(
        &self,
        since_ms: u64,
        limit: u32,
    ) -> Result<Vec<crate::models::EnergyRow>, StorageError> {
        let rows = sqlx::query_as::<_, (String, String, String, i64, i64)>(
            "SELECT sender, recipient_type, recipient_id, timestamp_ms, amount_msat \
             FROM messages WHERE timestamp_ms >= ? AND amount_msat > 0 \
             ORDER BY timestamp_ms ASC LIMIT ?",
        )
        .bind(since_ms.min(i64::MAX as u64) as i64)
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(sender, recipient_type, recipient_id, ts, amount)| crate::models::EnergyRow {
                sender,
                recipient_type,
                recipient_id,
                timestamp_ms: u64::try_from(ts).unwrap_or(0),
                amount_msat: u64::try_from(amount).unwrap_or(0),
            })
            .collect())
    }

    async fn delete_messages_older_than(&self, before_ms: u64) -> Result<u64, StorageError> {
        let result = sqlx::query("DELETE FROM messages WHERE timestamp_ms < ? AND NOT EXISTS (SELECT 1 FROM pending_deliveries WHERE message_id = messages.id)")
            .bind(before_ms.min(i64::MAX as u64) as i64).execute(&self.pool).await?;
        Ok(result.rows_affected())
    }

    // ── Rooms ──────────────────────────────────────────────────────────

    async fn create_room(&self, room: &Room) -> Result<(), StorageError> {
        let id = room.id.to_string();
        let created_by = room.created_by.to_hex();
        let metadata =
            serde_json::to_string(&room.metadata).map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO rooms (id, name, created_by, created_at, metadata_json) \
             VALUES (?, ?, ?, ?, ?)",
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
            "SELECT id, name, created_by, created_at, metadata_json FROM rooms WHERE id = ?",
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

        // Delete memberships first (foreign key child)
        sqlx::query("DELETE FROM room_members WHERE room_id = ?")
            .bind(&rid)
            .execute(&self.pool)
            .await?;

        let result = sqlx::query("DELETE FROM rooms WHERE id = ?")
            .bind(&rid)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn add_room_member(&self, room_id: &RoomId, member: &NodeId) -> Result<(), StorageError> {
        let rid = room_id.to_string();
        let nid = member.to_hex();

        sqlx::query(
            "INSERT OR IGNORE INTO room_members (room_id, node_id) VALUES (?, ?)",
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

        sqlx::query("DELETE FROM room_members WHERE room_id = ? AND node_id = ?")
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

    // ── Peers ──────────────────────────────────────────────────────────

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
        // The `json_type(...) = 'object'` guard makes this safe for the
        // `EncryptedStorage` wrapper, where `metadata_json` is an opaque
        // encrypted *string scalar* rather than a JSON object: in that case we
        // overwrite wholesale (the wrapper merges plaintext metadata itself
        // before encrypting), because `json_patch` on a scalar target would
        // destroy the ciphertext.
        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(node_id) DO UPDATE SET \
             address = COALESCE(excluded.address, peers.address), \
             last_seen = COALESCE(excluded.last_seen, peers.last_seen), \
             display_name = COALESCE(excluded.display_name, peers.display_name), \
             metadata_json = CASE \
               WHEN json_type(excluded.metadata_json) = 'object' \
                AND json_type(peers.metadata_json) = 'object' \
               THEN json_patch( \
                 excluded.metadata_json, \
                 json_object( \
                   'invite_ref', COALESCE( \
                     json_extract(peers.metadata_json, '$.invite_ref'), \
                     json_extract(excluded.metadata_json, '$.invite_ref')), \
                   'whitelist_source', COALESCE( \
                     json_extract(peers.metadata_json, '$.whitelist_source'), \
                     json_extract(excluded.metadata_json, '$.whitelist_source')) \
                 )) \
               ELSE excluded.metadata_json \
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
            "SELECT node_id, address, last_seen, display_name, metadata_json FROM peers WHERE node_id = ?",
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
        let result = sqlx::query("DELETE FROM peers WHERE node_id = ?")
            .bind(&nid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── Nonces ─────────────────────────────────────────────────────────

    async fn store_paid_nonce(
        &self, nonce: &Nonce, payment_hash: &[u8; 32], sender: &NodeId, message_id: &MessageId,
    ) -> Result<konsensus_core::gate::PaidReplay, StorageError> {
        use konsensus_core::gate::PaidReplay;
        let mut tx = self.pool.begin().await?;
        let nonce_new = sqlx::query("INSERT OR IGNORE INTO nonces (nonce_hex, sender) VALUES (?, ?)")
            .bind(hex::encode(nonce.as_bytes())).bind(sender.to_hex()).execute(&mut *tx).await?.rows_affected() != 0;
        if !nonce_new { tx.rollback().await?; return Ok(PaidReplay::NonceReused); }
        let payment_new = sqlx::query("INSERT OR IGNORE INTO payment_receipts (payment_hash, message_id, sender) VALUES (?, ?, ?)")
            .bind(hex::encode(payment_hash)).bind(message_id.to_hex()).bind(sender.to_hex())
            .execute(&mut *tx).await?.rows_affected() != 0;
        if !payment_new { tx.rollback().await?; return Ok(PaidReplay::PaymentReused); }
        tx.commit().await?;
        Ok(PaidReplay::Accepted)
    }

    async fn store_nonce(&self, nonce: &Nonce, sender: &NodeId) -> Result<bool, StorageError> {
        let nonce_hex = hex::encode(nonce.as_bytes());
        let sender_hex = sender.to_hex();

        let result = sqlx::query(
            "INSERT OR IGNORE INTO nonces (nonce_hex, sender) VALUES (?, ?)",
        )
        .bind(&nonce_hex)
        .bind(&sender_hex)
        .execute(&self.pool)
        .await?;

        // rows_affected == 1 means new insert, 0 means duplicate (replay)
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
            "INSERT OR IGNORE INTO payment_receipts (payment_hash, message_id, sender) VALUES (?, ?, ?)",
        )
        .bind(&payment_hash_hex)
        .bind(&message_id_hex)
        .bind(&sender_hex)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn record_outgoing_web_request(
        &self,
        payment_hash: &[u8; 32],
        request: konsensus_core::web_reply::OutstandingWebRequest,
    ) -> Result<(), StorageError> {
        // Durable (#129 R1): a restart between paying and the reply keeps the binding.
        let expires = i64::try_from(request.expires_at_ms).map_err(|_| StorageError::Conversion("web request expiry overflow".into()))?;
        sqlx::query("INSERT INTO outstanding_web_requests (payment_hash, request_id, peer, expected_reply_kind, expires_at_ms) VALUES (?, ?, ?, ?, ?) ON CONFLICT(payment_hash) DO UPDATE SET request_id = excluded.request_id, peer = excluded.peer, expected_reply_kind = excluded.expected_reply_kind, expires_at_ms = excluded.expires_at_ms")
            .bind(hex::encode(payment_hash))
            .bind(request.request_id.to_hex())
            .bind(request.peer.to_hex())
            .bind(i64::from(request.expected_reply_kind))
            .bind(expires)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn take_outstanding_web_request(
        &self,
        payment_hash: &[u8; 32],
    ) -> Result<Option<konsensus_core::web_reply::OutstandingWebRequest>, StorageError> {
        // One statement: two concurrent takes cannot both get the row.
        let row: Option<(String, String, i64, i64)> = sqlx::query_as(
            "DELETE FROM outstanding_web_requests WHERE payment_hash = ? RETURNING request_id, peer, expected_reply_kind, expires_at_ms",
        )
        .bind(hex::encode(payment_hash))
        .fetch_optional(&self.pool)
        .await?;
        row.map(outstanding_from_row).transpose()
    }

    async fn sweep_outstanding_web_requests(&self, now_ms: u64, max: u32) -> Result<u64, StorageError> {
        let now = i64::try_from(now_ms).map_err(|_| StorageError::Conversion("sweep time overflow".into()))?;
        let result = sqlx::query("DELETE FROM outstanding_web_requests WHERE payment_hash IN (SELECT payment_hash FROM outstanding_web_requests WHERE expires_at_ms < ? ORDER BY expires_at_ms LIMIT ?)")
            .bind(now)
            .bind(i64::from(max))
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn has_nonce(&self, nonce: &Nonce) -> Result<bool, StorageError> {
        let nonce_hex = hex::encode(nonce.as_bytes());

        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM nonces WHERE nonce_hex = ?",
        )
        .bind(&nonce_hex)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0 > 0)
    }

    async fn cleanup_expired_nonces(&self, max_age_secs: u64) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM nonces WHERE received_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
        )
        .bind(format!("-{max_age_secs} seconds"))
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
             VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) \
             ON CONFLICT(peer_id) DO UPDATE SET \
             state_blob = excluded.state_blob, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
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
            "SELECT state_blob FROM sessions WHERE peer_id = ?",
        )
        .bind(&pid)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(blob,)| blob))
    }

    async fn delete_session(&self, peer_id: &NodeId) -> Result<bool, StorageError> {
        let pid = peer_id.to_hex();
        let result = sqlx::query("DELETE FROM sessions WHERE peer_id = ?")
            .bind(&pid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_sessions(&self) -> Result<Vec<NodeId>, StorageError> {
        let rows = sqlx::query_as::<_, (String,)>(SESSIONS_SELECT)
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
            "INSERT OR IGNORE INTO pending_deliveries (message_id, recipient_id) VALUES (?, ?)",
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

        let rows = sqlx::query_as::<_, (String, i64)>(PENDING_FOR_PEER_SELECT)
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

        sqlx::query("DELETE FROM pending_deliveries WHERE message_id = ? AND recipient_id = ?")
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
             WHERE message_id = ? AND recipient_id = ? AND state != 'failed_paid'",
        )
        .bind(&mid)
        .bind(&rid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_pending_peers(&self) -> Result<Vec<NodeId>, StorageError> {
        let rows = sqlx::query_as::<_, (String,)>(PENDING_PEERS_SELECT)
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

        u64::try_from(row.0)
            .map_err(|_| StorageError::Conversion(format!("pending count negative: {}", row.0)))
    }

    async fn clear_pending_for_peer(&self, recipient: &NodeId) -> Result<u64, StorageError> {
        let recipient_hex = recipient.to_hex();
        let result = sqlx::query(
            "DELETE FROM pending_deliveries WHERE recipient_id = ?",
        )
        .bind(&recipient_hex)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    async fn cleanup_stale_pending(&self, max_attempts: u32) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "UPDATE pending_deliveries SET state = 'stalled' WHERE attempts >= ? AND state = 'pending'",
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
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
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
            "SELECT id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, data, created_at \
             FROM files WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, data, created_at)| {
            let sz = u64::try_from(size_bytes)
                .map_err(|_| StorageError::Conversion(format!("file size negative: {size_bytes}")))?;
            Ok::<FileRecord, StorageError>(FileRecord {
                id,
                filename,
                mime_type,
                size_bytes: sz,
                blake3_hash,
                sender,
                message_id,
                data,
                created_at,
            })
        }).transpose()
    }

    async fn get_file_metadata(&self, id: &str) -> Result<Option<FileMetadata>, StorageError> {
        let row = sqlx::query_as::<_, (
            String, String, String, i64, String, String, Option<String>, String,
        )>(
            "SELECT id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at \
             FROM files WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at)| {
            let sz = u64::try_from(size_bytes)
                .map_err(|_| StorageError::Conversion(format!("file size negative: {size_bytes}")))?;
            Ok::<FileMetadata, StorageError>(FileMetadata {
                id,
                filename,
                mime_type,
                size_bytes: sz,
                blake3_hash,
                sender,
                message_id,
                created_at,
            })
        }).transpose()
    }

    async fn list_files(&self, limit: u32) -> Result<Vec<FileMetadata>, StorageError> {
        let lim = limit as i64;

        let rows = sqlx::query_as::<_, (
            String, String, String, i64, String, String, Option<String>, String,
        )>(
            "SELECT id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at \
             FROM files ORDER BY created_at DESC LIMIT ?",
        )
        .bind(lim)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|(id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at)| {
            let sz = u64::try_from(size_bytes)
                .map_err(|_| StorageError::Conversion(format!("file size negative: {size_bytes}")))?;
            Ok(FileMetadata {
                id,
                filename,
                mime_type,
                size_bytes: sz,
                blake3_hash,
                sender,
                message_id,
                created_at,
            })
        }).collect()
    }

    async fn delete_file(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM files WHERE id = ?")
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
        sqlx::query("UPDATE messages SET plaintext_enc = ? WHERE id = ?")
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
            sqlx::query_as("SELECT plaintext_enc FROM messages WHERE id = ?")
                .bind(id.to_hex())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|(data,)| data))
    }

    async fn invite_schema_capabilities(
        &self,
    ) -> Result<InviteSchemaCapabilities, StorageError> {
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('invites_issued')")
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
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .await?;

        let mut metadata = sqlx::query_as::<_, (String,)>(
            "SELECT metadata_json FROM peers WHERE node_id = ?",
        )
        .bind(&node_id)
        .fetch_optional(&mut *tx)
        .await?
        .and_then(|(json,)| serde_json::from_str::<serde_json::Value>(&json).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));

        metadata["invite_ref"] = serde_json::Value::String(invite.id.to_string());
        metadata["whitelist_source"] = serde_json::Value::String("invite".to_string());

        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES (?, NULL, NULL, NULL, ?) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = excluded.metadata_json",
        )
        .bind(&node_id)
        .bind(&metadata_json)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
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
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO invites_issued \
             (id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
        .await?;

        // Overwrite the peer metadata wholesale with the caller-supplied blob.
        // For the EncryptedStorage wrapper this is an opaque ciphertext scalar,
        // so the backend must never `json_extract`/merge it — the caller already
        // merged `invite_ref` / `whitelist_source` before encrypting.
        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES (?, NULL, NULL, NULL, ?) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = excluded.metadata_json",
        )
        .bind(&node_id)
        .bind(metadata_json)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
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
             FROM invites_issued WHERE id = ?",
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
        .await?;

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
            "UPDATE invites_issued SET state = ?, revoked_at = ? WHERE id = ? AND state = ?",
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
            "UPDATE invites_issued SET state = ?, accepted_at = ? WHERE id = ? AND state IN (?, ?)",
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
            "UPDATE invites_issued SET state = ?, accepted_at = ? WHERE id = ? AND state = ?",
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
            "UPDATE invites_issued SET state = ?, accepted_at = NULL WHERE id = ? AND state = ?",
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
            "UPDATE invites_issued SET state = ?, revoked_at = ? WHERE id = ? AND state = ?",
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
            "SELECT metadata_json FROM peers WHERE node_id = ?",
        )
        .bind(&node_id)
        .fetch_optional(&self.pool)
        .await?
        .and_then(|(json,)| serde_json::from_str::<serde_json::Value>(&json).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));

        metadata["invite_ref"] = serde_json::Value::String(invite_id.to_string());
        metadata["whitelist_source"] = serde_json::Value::String("invite".to_string());

        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES (?, NULL, NULL, NULL, ?) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = excluded.metadata_json",
        )
        .bind(&node_id)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await?;

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
             VALUES (?, NULL, NULL, NULL, ?) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = excluded.metadata_json",
        )
        .bind(&node_id)
        .bind(metadata_json)
        .execute(&self.pool)
        .await?;

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
             VALUES (?, ?, ?, ?)",
        )
        .bind(record.nonce.as_slice())
        .bind(record.inviter_pubkey.as_slice())
        .bind(expiry_unix)
        .bind(accepted_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if matches!(db_err.code().as_deref(), Some("2067" | "1555")) => {
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
             FROM accepted_invites WHERE nonce = ?",
        )
        .bind(nonce.as_slice())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| {
            let nonce: [u8; 16] = r.0.try_into().map_err(|_| {
                StorageError::Conversion("invalid accepted_invites.nonce length".into())
            })?;
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
                nonce,
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
        let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, i64, i64)>(ACTIVE_ACCEPTED_INVITES_SELECT)
            .bind(now_unix)
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|r| {
                let nonce: [u8; 16] = r.0.try_into().map_err(|_| {
                    StorageError::Conversion("invalid accepted_invites.nonce length".into())
                })?;
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
                    nonce,
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
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
                invite_id = excluded.invite_id,
                inviter_pubkey = excluded.inviter_pubkey,
                inviter_ln_pubkey = excluded.inviter_ln_pubkey,
                current_step = excluded.current_step,
                tier = excluded.tier,
                funding_address = excluded.funding_address,
                funding_amount_sats_required = excluded.funding_amount_sats_required,
                funding_amount_sats_received = excluded.funding_amount_sats_received,
                last_poll_at = excluded.last_poll_at,
                funding_evidence = excluded.funding_evidence",
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
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
               message_id      = excluded.message_id,
               title           = excluded.title,
               description     = excluded.description,
               start_ms        = excluded.start_ms,
               end_ms          = excluded.end_ms,
               tz              = excluded.tz,
               location        = excluded.location,
               attendees_json  = excluded.attendees_json,
               recurrence_json = excluded.recurrence_json,
               color           = excluded.color,
               parent_id       = excluded.parent_id",
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
             FROM calendar_events WHERE id = ?1",
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
             WHERE start_ms < ?2 AND end_ms > ?1
               AND recurrence_json IS NULL AND parent_id IS NULL
             ORDER BY start_ms ASC
             LIMIT ?3",
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
        let result = sqlx::query("DELETE FROM calendar_events WHERE id = ?1")
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

    async fn list_recurring_master_events_before(
        &self,
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
        )> = sqlx::query_as(RECURRING_MASTER_EVENTS_BEFORE_SELECT)
            .bind(to_ms as i64)
            .bind(limit as i64)
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
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(event_id, responder) DO UPDATE SET
               response = excluded.response,
               comment  = excluded.comment",
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

    async fn store_reaction(&self, record: &ReactionRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT OR IGNORE INTO message_reactions (message_id, sender, emoji)
             VALUES (?1, ?2, ?3)",
        )
        .bind(&record.message_id)
        .bind(&record.sender)
        .bind(&record.emoji)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_reaction(
        &self,
        message_id: &str,
        sender: &str,
        emoji: &str,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM message_reactions WHERE message_id = ?1 AND sender = ?2 AND emoji = ?3",
        )
        .bind(message_id)
        .bind(sender)
        .bind(emoji)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_reactions_for_message(
        &self,
        message_id: &str,
    ) -> Result<Vec<ReactionRecord>, StorageError> {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT message_id, sender, emoji, created_at
             FROM message_reactions
             WHERE message_id = ?1
             ORDER BY created_at ASC",
        )
        .bind(message_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(message_id, sender, emoji, created_at)| ReactionRecord {
                message_id,
                sender,
                emoji,
                created_at,
            })
            .collect())
    }
    // -- Fiat Rate Snapshots -----------------------------------------------

    async fn store_fiat_rate_snapshot(
        &self,
        snapshot: &crate::fiat_snapshots::FiatRateSnapshot,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO fiat_rate_snapshots (date, currency, rate, source)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(date, currency) DO UPDATE SET
               rate   = excluded.rate,
               source = excluded.source",
        )
        .bind(&snapshot.date)
        .bind(&snapshot.currency)
        .bind(snapshot.rate)
        .bind(&snapshot.source)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_fiat_rate_snapshots(
        &self,
        from_date: &str,
        to_date: &str,
    ) -> Result<Vec<crate::fiat_snapshots::FiatRateSnapshot>, StorageError> {
        let rows: Vec<(String, String, f64, String, String)> =
            sqlx::query_as(FIAT_RATE_SNAPSHOTS_SELECT)
                .bind(from_date)
                .bind(to_date)
                .fetch_all(&self.pool)
                .await?;

        Ok(rows
            .into_iter()
            .map(|(date, currency, rate, source, created_at)| {
                crate::fiat_snapshots::FiatRateSnapshot {
                    date,
                    currency,
                    rate,
                    source,
                    created_at,
                }
            })
            .collect())
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
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                tenant_pubkey = excluded.tenant_pubkey,
                operator_pubkey = excluded.operator_pubkey,
                sats_per_day = excluded.sats_per_day,
                started_at = excluded.started_at,
                last_paid_at = excluded.last_paid_at,
                state = excluded.state,
                updated_at = excluded.updated_at",
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
             SET state = ?1, updated_at = ?2
             WHERE id = ?3",
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
             SET last_paid_at = ?1, state = 'active', updated_at = ?2
             WHERE id = ?3",
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
            "INSERT OR IGNORE INTO operator_hosting_payments
                (payment_hash, contract_id, tenant_pubkey, operator_pubkey, amount_msat, paid_at, direction, preimage, memo, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
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
impl konsensus_core::gate::NonceStore for SqliteStorage {
    async fn check_and_store_paid(
        &self, nonce: &konsensus_core::Nonce, payment_hash: &[u8; 32],
        sender: &konsensus_core::NodeId, message_id: &konsensus_core::MessageId,
    ) -> Result<konsensus_core::gate::PaidReplay, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.store_paid_nonce(nonce, payment_hash, sender, message_id).await?)
    }

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
#[path = "tests/sqlite.rs"]
mod tests;

#[cfg(test)]
mod dbh2_guard {
    /// DBH2: the sibling authority-listing queries that DBH1 missed
    /// (`list_sessions`, `get_pending_peers`, `get_room_members`) must never
    /// regain a `LIMIT`. Each is a durable authority — restored sessions, the
    /// outbound delivery queue, room fan-out — where a cap is a Principle-2
    /// fail-open at scale, identical in shape to the `list_peers` truncation.
    /// The live >1000-row round-trips in
    /// `tests/dbh2_unbounded_siblings_tests.rs` prove the runtime behavior for
    /// sessions + pending_deliveries; this asserts the source constants so a
    /// future edit cannot silently re-introduce a cap (and is the in-CI proof
    /// for the `room_members` path, whose live cap was 10000).
    #[test]
    fn sessions_select_is_unbounded() {
        assert!(
            !super::SESSIONS_SELECT.to_uppercase().contains("LIMIT"),
            "sqlite SESSIONS_SELECT must not contain LIMIT (DBH2 fail-open guard): {}",
            super::SESSIONS_SELECT
        );
    }

    #[test]
    fn pending_peers_select_is_unbounded() {
        assert!(
            !super::PENDING_PEERS_SELECT.to_uppercase().contains("LIMIT"),
            "sqlite PENDING_PEERS_SELECT must not contain LIMIT (DBH2 fail-open guard): {}",
            super::PENDING_PEERS_SELECT
        );
    }

    #[test]
    fn room_members_select_is_unbounded() {
        assert!(
            !super::ROOM_MEMBERS_SELECT.to_uppercase().contains("LIMIT"),
            "sqlite ROOM_MEMBERS_SELECT must not contain LIMIT (DBH2 fail-open guard): {}",
            super::ROOM_MEMBERS_SELECT
        );
    }
}

#[cfg(test)]
mod dbh1_guard {
    /// DBH1: mirror of the Postgres guard — the SQLite peer-listing query must
    /// never regain a `LIMIT`. The live 1500-peer round-trip in
    /// `tests/dbh1_unbounded_peers_tests.rs` proves the runtime behavior; this
    /// asserts the source constant so a future edit cannot silently re-introduce
    /// the cap on the sibling path the integration test does not cover.
    #[test]
    fn peers_select_is_unbounded() {
        assert!(
            !super::PEERS_SELECT.to_uppercase().contains("LIMIT"),
            "sqlite PEERS_SELECT must not contain LIMIT (DBH1 fail-open guard): {}",
            super::PEERS_SELECT
        );
    }
}

#[cfg(test)]
mod sqlite_file_path_tests {
    use super::sqlite_file_path;
    use std::path::Path;

    /// The bootstrap probe must look at the file `open` creates, whatever
    /// spelling the operator used for the connection string (#76 P1-3).
    #[test]
    fn resolves_every_spelling_open_accepts_to_the_same_file() {
        let expected = Path::new("/var/lib/bitsov/external.sqlite");
        for spelling in [
            "/var/lib/bitsov/external.sqlite",
            "sqlite:/var/lib/bitsov/external.sqlite",
            "sqlite:///var/lib/bitsov/external.sqlite",
            "sqlite:///var/lib/bitsov/external.sqlite?mode=rwc",
        ] {
            assert_eq!(
                sqlite_file_path(spelling).as_deref(),
                Some(expected),
                "{spelling}"
            );
        }
        assert_eq!(
            sqlite_file_path("konsensus.db").as_deref(),
            Some(Path::new("konsensus.db"))
        );
        assert_eq!(
            sqlite_file_path("sqlite://relative/store.db").as_deref(),
            Some(Path::new("relative/store.db"))
        );
    }

    #[test]
    fn in_memory_names_no_file() {
        assert_eq!(sqlite_file_path("sqlite::memory:"), None);
    }

    /// The literal-path reading and the runtime reading must never disagree:
    /// a real database created through `open` sits exactly where the resolver
    /// says it does.
    #[tokio::test]
    async fn resolved_path_is_where_open_creates_the_database() {
        let dir = std::env::temp_dir().join(format!(
            "konsensus-sqlite-file-path-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("external.sqlite");
        let uri = format!("sqlite://{}", file.display());
        assert!(uri.starts_with("sqlite:///"), "{uri}");
        assert!(!Path::new(&uri).exists());
        {
            let _store = super::SqliteStorage::open(&uri).await.unwrap();
            assert!(file.exists());
            assert_eq!(sqlite_file_path(&uri).as_deref(), Some(file.as_path()));
            assert!(
                !Path::new(&uri).exists(),
                "the literal connection string is not a path on disk"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod accepted_invites_guard {
    /// AUTHORITY: the accepted-invites replay query repopulates the admission
    /// whitelist at node startup. A `LIMIT` would silently drop active invites
    /// from the startup whitelist — a Principle-2 fail-open where validly-invited
    /// peers are rejected as `NotWhitelisted` after a restart, and the
    /// mnemonic-recovery / RV-RESTORE path loses relationships. This asserts the
    /// source constant so a future edit cannot re-introduce a cap.
    #[test]
    fn active_accepted_invites_select_is_unbounded() {
        assert!(
            !super::ACTIVE_ACCEPTED_INVITES_SELECT
                .to_uppercase()
                .contains("LIMIT"),
            "sqlite ACTIVE_ACCEPTED_INVITES_SELECT must not contain LIMIT (AUTHORITY fail-open guard): {}",
            super::ACTIVE_ACCEPTED_INVITES_SELECT
        );
    }
}

/// A taken `outstanding_web_requests` row. A corrupt row is an error, never a binding.
fn outstanding_from_row(
    (request_id, peer, kind, expires): (String, String, i64, i64),
) -> Result<konsensus_core::web_reply::OutstandingWebRequest, StorageError> {
    let bad = |what: &str| StorageError::Conversion(format!("outstanding web request: bad {what}"));
    Ok(konsensus_core::web_reply::OutstandingWebRequest {
        request_id: konsensus_core::types::MessageId::from_hex(&request_id).map_err(|_| bad("request id"))?,
        peer: konsensus_core::types::NodeId::from_hex(&peer).map_err(|_| bad("peer"))?,
        expected_reply_kind: u16::try_from(kind).map_err(|_| bad("reply kind"))?,
        expires_at_ms: u64::try_from(expires).map_err(|_| bad("expiry"))?,
    })
}
