//! R3 SEAM-A2 — relay binding store abstraction (storage-agnostic).
//!
//! The [`RelayBindingStore`] trait is the engine's persistence seam: open a
//! binding, hold ciphertext envelopes under it, list/drain them, and delete on
//! ack. The in-memory implementation backs unit tests and a relay running
//! without durable storage; the durable (SQLite-backed) impl is a later
//! operator-gated migration (SEAM-C: `RelayBinding` / `RelayHeldEnvelope`
//! tables). Keeping the engine behind this trait lets the logic and the gated
//! dispatch (SEAM-B) be built and tested before the migration exists.
//!
//! The store never decrypts: a held envelope is opaque `Vec<u8>` ciphertext.

#![allow(dead_code)] // wired by the gated dispatch (SEAM-B); inert until then.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use konsensus_core::types::{MessageId, NodeId};
use sqlx::sqlite::SqlitePool;
use tokio::sync::Mutex;

use super::{DrainItem, RelayBindingView};

/// A registered binding: the recipient authorised this relay to hold mail for
/// them, with the quota/ttl/whitelist terms agreed at `RelayRegister`.
#[derive(Debug, Clone)]
pub(crate) struct RelayBinding {
    pub binding_id: [u8; 16],
    pub recipient: NodeId,
    pub quota_bytes: u64,
    pub held_bytes: u64,
    pub ttl_max_secs: u32,
    pub depositor_whitelist_root: [u8; 32],
    pub created_at: u64,
}

impl RelayBinding {
    /// The read view the SEAM-A `validate_deposit` consumes.
    pub(crate) fn as_view(&self) -> RelayBindingView {
        RelayBindingView {
            recipient: self.recipient,
            quota_bytes: self.quota_bytes,
            held_bytes: self.held_bytes,
            ttl_max_secs: self.ttl_max_secs,
            depositor_whitelist_root: self.depositor_whitelist_root,
        }
    }
}

/// Store-layer failures.
///
/// Not `Copy`: the durable [`SqliteRelayStore`] needs the `Backend(String)`
/// variant (P8.1 D-err) to carry a backend failure message, which `Copy`
/// forbids. `InMemoryRelayStore` never produces `Backend`; the two engine
/// `match` sites (`relay/engine.rs`) are already fail-closed on any non-listed
/// variant (a catch-all `other => Store(other)` on register; a `!=
/// BindingNotFound` re-raise on deposit), so a backend failure rejects the relay
/// op — it never admits, never silently drops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelayStoreError {
    /// A binding already exists for this recipient.
    BindingExists,
    /// No binding exists for this recipient.
    BindingNotFound,
    /// Holding this envelope would exceed the binding's total quota.
    QuotaExceeded,
    /// Holding this envelope would exceed the per-depositor sub-quota (D2): this
    /// single depositor is already at `min(max_bytes_per_depositor, quota_bytes)`,
    /// even though the binding as a whole may have room. Bounds one depositor's
    /// share so a sponsored peer cannot starve the others.
    PerDepositorQuotaExceeded,
    /// The relay is already at `max_bindings` and this is a new recipient. The
    /// store enforces the global binding cap atomically under the same lock as
    /// the insert, so a stale engine-side pre-check can never let a concurrent
    /// register push the live count past the cap (the SEAM-B register TOCTOU).
    CapExceeded,
    /// A durable-backend (SQLite/IO/transaction) failure: locked or corrupt DB,
    /// a serialization error, a closed pool. The in-memory store can never
    /// produce this; the durable [`SqliteRelayStore`] maps every `sqlx` error
    /// here so the engine fails the relay op CLOSED — it never admits a peer,
    /// never exposes plaintext, and never panics on a bad DB (THREAT_MODEL §6 /
    /// design §6 test 7). Carries the backend message for diagnostics.
    Backend(String),
}

/// Persistence seam for the relay engine. Async because the durable impl is
/// I/O-backed (SQLite); the in-memory impl satisfies it trivially.
#[async_trait]
pub(crate) trait RelayBindingStore: Send + Sync {
    /// Open a binding. Errors with [`RelayStoreError::BindingExists`] if one
    /// already exists for the recipient (one binding per recipient per relay),
    /// or [`RelayStoreError::CapExceeded`] if the relay already holds
    /// `max_bindings` bindings and this is a new recipient. The cap is checked
    /// under the SAME lock as the insert, so it is the authoritative global-cap
    /// gate — the engine's `register_allowed` count check is only an advisory
    /// fast-reject and cannot, by being stale, let two concurrent registers
    /// exceed the cap.
    async fn register_binding(
        &self,
        binding: RelayBinding,
        max_bindings: usize,
    ) -> Result<(), RelayStoreError>;

    /// Look up a binding by recipient.
    async fn get_binding(&self, recipient: &NodeId) -> Option<RelayBinding>;

    /// Hold one ciphertext envelope under the recipient's binding, assigning a
    /// monotonic per-binding sequence (so an adversarial relay cannot silently
    /// drop or reorder — THREAT_MODEL §6). `message_id` is the envelope's own
    /// `UkmEnvelope.id` (the recipient acks by it — seam-4). `depositor` is the
    /// authenticated kind-601 sender this hold is charged to. Increments
    /// `held_bytes`; errors with [`RelayStoreError::QuotaExceeded`] if the
    /// binding's total quota would be exceeded, with
    /// [`RelayStoreError::PerDepositorQuotaExceeded`] if THIS depositor's share
    /// would exceed `min(max_bytes_per_depositor, quota_bytes)` (D2), or
    /// [`RelayStoreError::BindingNotFound`] if no binding exists. Returns the
    /// assigned sequence.
    #[allow(clippy::too_many_arguments)]
    async fn hold_envelope(
        &self,
        recipient: &NodeId,
        message_id: MessageId,
        depositor: NodeId,
        envelope_bytes: Vec<u8>,
        max_bytes_per_depositor: u64,
        deposit_received_at: u64,
        expires_at: u64,
    ) -> Result<u64, RelayStoreError>;

    /// Up to `max` held items for the recipient in sequence order (oldest
    /// first), so the recipient drains deterministically.
    async fn list_held(&self, recipient: &NodeId, max: usize, now: u64) -> Vec<DrainItem>;

    /// Remove expired held items and free their quota. Returns how many expired
    /// holds were pruned. Missing binding is an error so callers can distinguish
    /// "unknown recipient" from "nothing expired".
    async fn prune_expired(&self, recipient: &NodeId, now: u64) -> Result<usize, RelayStoreError>;

    /// Delete held items the recipient acked (by `MessageId` — the handle it
    /// keeps after a drain re-injects the envelope; seam-4), decrementing
    /// `held_bytes`. Returns the number deleted. Idempotent — re-acking an
    /// already-deleted id is a no-op. A duplicate-deposit of the same envelope
    /// (same id) is deleted together, which correctly reclaims its redundant
    /// quota.
    async fn ack_delete(
        &self,
        recipient: &NodeId,
        message_ids: &[MessageId],
    ) -> Result<usize, RelayStoreError>;

    /// Revoke the recipient's binding entirely (kind-604 unregister), dropping all
    /// its held mail and freeing the binding slot. Registration without this would
    /// be a TRAP — revocability is a doctrine requirement. Errors
    /// [`RelayStoreError::BindingNotFound`] if there is no binding to remove (so a
    /// revoke of nothing is a reject, never a silent success).
    async fn remove_binding(&self, recipient: &NodeId) -> Result<(), RelayStoreError>;

    /// Number of live bindings (feeds the global cap in SEAM-A `register_allowed`).
    async fn binding_count(&self) -> usize;
}

struct BindingState {
    binding: RelayBinding,
    held: Vec<DrainItem>,
    next_sequence: u64,
}

fn prune_expired_locked(state: &mut BindingState, now: u64) -> usize {
    let before = state.held.len();
    let mut freed: u64 = 0;
    state.held.retain(|item| {
        let keep = item.expires_at > now;
        if !keep {
            freed = freed.saturating_add(item.envelope_bytes.len() as u64);
        }
        keep
    });
    state.binding.held_bytes = state.binding.held_bytes.saturating_sub(freed);
    before - state.held.len()
}

/// In-memory [`RelayBindingStore`] for tests and a relay running without durable
/// storage. The durable SQLite impl (SEAM-C) is an operator-gated migration.
#[derive(Default)]
pub(crate) struct InMemoryRelayStore {
    inner: Arc<Mutex<HashMap<NodeId, BindingState>>>,
}

impl InMemoryRelayStore {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl RelayBindingStore for InMemoryRelayStore {
    async fn register_binding(
        &self,
        binding: RelayBinding,
        max_bindings: usize,
    ) -> Result<(), RelayStoreError> {
        let mut map = self.inner.lock().await;
        // An existing recipient re-registering is a duplicate regardless of the
        // cap (it consumes no new slot), so check that first.
        if map.contains_key(&binding.recipient) {
            return Err(RelayStoreError::BindingExists);
        }
        // Authoritative global-cap gate, atomic with the insert below.
        if map.len() >= max_bindings {
            return Err(RelayStoreError::CapExceeded);
        }
        let recipient = binding.recipient;
        map.insert(
            recipient,
            BindingState {
                binding,
                held: Vec::new(),
                next_sequence: 0,
            },
        );
        Ok(())
    }

    async fn get_binding(&self, recipient: &NodeId) -> Option<RelayBinding> {
        self.inner
            .lock()
            .await
            .get(recipient)
            .map(|s| s.binding.clone())
    }

    #[allow(clippy::too_many_arguments)]
    async fn hold_envelope(
        &self,
        recipient: &NodeId,
        message_id: MessageId,
        depositor: NodeId,
        envelope_bytes: Vec<u8>,
        max_bytes_per_depositor: u64,
        deposit_received_at: u64,
        expires_at: u64,
    ) -> Result<u64, RelayStoreError> {
        let size = envelope_bytes.len() as u64;
        let mut map = self.inner.lock().await;
        let state = map
            .get_mut(recipient)
            .ok_or(RelayStoreError::BindingNotFound)?;
        prune_expired_locked(state, deposit_received_at);
        // Total-quota gate first (checked under this lock, so it is atomic with
        // the byte accounting below — concurrent holds serialize on the lock).
        if state.binding.held_bytes.saturating_add(size) > state.binding.quota_bytes {
            return Err(RelayStoreError::QuotaExceeded);
        }
        // Per-depositor sub-quota (D2): this depositor's CURRENT held share is the
        // sum of its live held items (the held Vec is the single source of truth,
        // so ack/prune reclaim it automatically — no parallel counter to desync).
        // The cap can never exceed the binding's own quota.
        let effective_cap = max_bytes_per_depositor.min(state.binding.quota_bytes);
        let depositor_held: u64 = state
            .held
            .iter()
            .filter(|item| item.depositor == depositor)
            .map(|item| item.envelope_bytes.len() as u64)
            .sum();
        if depositor_held.saturating_add(size) > effective_cap {
            return Err(RelayStoreError::PerDepositorQuotaExceeded);
        }
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        state.binding.held_bytes += size;
        state.held.push(DrainItem {
            envelope_bytes,
            message_id,
            sequence,
            depositor,
            deposit_received_at,
            expires_at,
        });
        Ok(sequence)
    }

    async fn list_held(&self, recipient: &NodeId, max: usize, now: u64) -> Vec<DrainItem> {
        let mut map = self.inner.lock().await;
        match map.get_mut(recipient) {
            Some(s) => {
                prune_expired_locked(s, now);
                s.held.iter().take(max).cloned().collect()
            }
            None => Vec::new(),
        }
    }

    async fn prune_expired(&self, recipient: &NodeId, now: u64) -> Result<usize, RelayStoreError> {
        let mut map = self.inner.lock().await;
        let state = map
            .get_mut(recipient)
            .ok_or(RelayStoreError::BindingNotFound)?;
        Ok(prune_expired_locked(state, now))
    }

    async fn ack_delete(
        &self,
        recipient: &NodeId,
        message_ids: &[MessageId],
    ) -> Result<usize, RelayStoreError> {
        let mut map = self.inner.lock().await;
        let state = map
            .get_mut(recipient)
            .ok_or(RelayStoreError::BindingNotFound)?;
        let acked: HashSet<MessageId> = message_ids.iter().copied().collect();
        let before = state.held.len();
        let mut freed: u64 = 0;
        state.held.retain(|item| {
            if acked.contains(&item.message_id) {
                freed += item.envelope_bytes.len() as u64;
                false
            } else {
                true
            }
        });
        state.binding.held_bytes = state.binding.held_bytes.saturating_sub(freed);
        Ok(before - state.held.len())
    }

    async fn remove_binding(&self, recipient: &NodeId) -> Result<(), RelayStoreError> {
        let mut map = self.inner.lock().await;
        map.remove(recipient)
            .map(|_| ())
            .ok_or(RelayStoreError::BindingNotFound)
    }

    async fn binding_count(&self) -> usize {
        self.inner.lock().await.len()
    }
}

// ---------------------------------------------------------------------------
// Durable (SQLite-backed) store — P8.1.
//
// Mirrors `InMemoryRelayStore` invariant-for-invariant against the design in
// `docs/v2/RELAY_DURABLE_STORE_DESIGN.md`. The engine and its tests cannot tell
// which store is underneath. Off-by-default: nothing wires this in yet — a relay
// keeps using `InMemoryRelayStore` until an operator flips it to the durable
// backend (a deploy decision) and runs the `[MANUAL]` `CREATE TABLE` migration
// (§4). The schema-creating `create_schema` below is `#[cfg(test)]` precisely so
// no code path can auto-create the tables in production — that stays the
// operator's migration.
// ---------------------------------------------------------------------------

/// A `relay_held` row as read for draining: (body, message_id, seq, depositor,
/// deposit_received_at, expires_at). Aliased so the query types stay readable
/// (clippy::type_complexity).
type HeldRow = (Vec<u8>, Vec<u8>, i64, Vec<u8>, i64, i64);

/// A `relay_bindings` row as read by `get_binding`: (binding_id, quota_bytes,
/// held_bytes, ttl_max_secs, depositor_whitelist_root, created_at).
type BindingRow = (Vec<u8>, i64, i64, i64, Vec<u8>, i64);

/// Map any `sqlx` failure to the fail-closed [`RelayStoreError::Backend`].
#[inline]
fn backend(e: sqlx::Error) -> RelayStoreError {
    RelayStoreError::Backend(e.to_string())
}

/// Open the operator-migrated durable relay pool at `path` for runtime use.
///
/// **Fence (P8.1 `[MANUAL]`):** this NEVER creates the database file or the
/// schema — `create_if_missing` is `false` and there is no DDL here. The DB and
/// its two tables are the operator's `[MANUAL]` `CREATE TABLE` migration (design
/// §4); the node only *opens* what the operator already migrated. A missing file
/// or missing tables is a loud, fail-closed error pointing at that migration —
/// never a silent fallback to the non-durable in-memory store. Connection pragmas
/// mirror the main storage pool (WAL, `busy_timeout`) so concurrent writers do not
/// hit immediate `SQLITE_BUSY`.
pub(crate) async fn open_durable_pool(
    path: &std::path::Path,
) -> Result<SqlitePool, RelayStoreError> {
    let options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(false)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(5));
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(10)
        .connect_with(options)
        .await
        .map_err(backend)?;
    ensure_schema_present(&pool).await?;
    Ok(pool)
}

/// Verify the operator's `[MANUAL]` migration has been applied: both relay tables
/// must already exist. Read-only — queries `sqlite_master`, creates nothing — so
/// it never crosses the migration fence. A missing table is a fail-closed error
/// that names the table and points at the migration.
async fn ensure_schema_present(pool: &SqlitePool) -> Result<(), RelayStoreError> {
    for table in ["relay_bindings", "relay_held"] {
        let present: Option<String> =
            sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
                .bind(table)
                .fetch_optional(pool)
                .await
                .map_err(backend)?;
        if present.is_none() {
            return Err(RelayStoreError::Backend(format!(
                "relay durable store is missing table `{table}` — run the [MANUAL] CREATE TABLE \
                 migration (docs/v2/RELAY_DURABLE_STORE_DESIGN.md §4) before enabling durable relay"
            )));
        }
    }
    Ok(())
}

/// SQLite stores `INTEGER` as `i64`; our counters are `u64`. A value read back
/// from our own writes is always non-negative, so a stray negative maps to 0.
#[inline]
fn from_i64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or(0)
}

/// Convert a `u64` counter to the `i64` SQLite stores, failing closed if it ever
/// exceeds `i64::MAX` (it never does for real byte/quota/timestamp values).
#[inline]
fn to_i64(v: u64) -> Result<i64, RelayStoreError> {
    i64::try_from(v).map_err(|_| RelayStoreError::Backend("value exceeds i64 range".to_string()))
}

/// A 32-byte id BLOB read back from the DB. STRICT + our own 32-byte writes make
/// the wrong-length case impossible; it maps to a clean `Backend` error, never a
/// panic.
fn to_arr32(v: Vec<u8>) -> Result<[u8; 32], RelayStoreError> {
    v.try_into()
        .map_err(|_| RelayStoreError::Backend("id blob is not 32 bytes".to_string()))
}

fn to_arr16(v: Vec<u8>) -> Result<[u8; 16], RelayStoreError> {
    v.try_into()
        .map_err(|_| RelayStoreError::Backend("binding_id blob is not 16 bytes".to_string()))
}

/// Durable [`RelayBindingStore`]: bindings and held ciphertext survive a relay
/// restart. A *ciphertext warehouse with quota accounting* — it never decrypts a
/// `body`, never holds a key, never verifies a payment, never admits a peer.
/// Admission (settlement single-use) stays upstream in the message gate's one
/// `payment_receipts` store (design §1, operator decision D1); this store adds no
/// second money path.
pub(crate) struct SqliteRelayStore {
    pool: SqlitePool,
    /// Serialises mutating methods so each method's count/quota check is atomic
    /// with its own insert/update — the same role `InMemoryRelayStore`'s `Mutex`
    /// plays. This makes the global cap and the quota gates authoritative (no two
    /// writers interleave a count/insert or a quota-check/insert), defeating the
    /// SEAM-B register TOCTOU; `sqlx`+SQLite then give durability. We do not rely
    /// on `BEGIN IMMEDIATE` lock semantics for correctness — the `Mutex` owns it.
    write_lock: Mutex<()>,
}

impl SqliteRelayStore {
    /// Wrap an open pool. The caller decides which DB the pool points at (shared
    /// `konsensus.db` vs a dedicated `relay.db` — design §7 D-place decision 2);
    /// the store does not care.
    pub(crate) fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            write_lock: Mutex::new(()),
        }
    }

    /// Create the two relay tables (design §4) in `pool`. **TEST/BOOTSTRAP ONLY**
    /// — `#[cfg(test)]` so production can never auto-create the schema; the
    /// `CREATE TABLE` migration is `[MANUAL]`/operator-gated (the factory refuses
    /// `CREATE TABLE`). The §6 test matrix builds the schema in-process with this.
    #[cfg(test)]
    pub(crate) async fn create_schema(pool: &SqlitePool) -> Result<(), RelayStoreError> {
        for stmt in [
            "CREATE TABLE IF NOT EXISTS relay_bindings (\
                 recipient                BLOB PRIMARY KEY, \
                 binding_id               BLOB NOT NULL, \
                 quota_bytes              INTEGER NOT NULL, \
                 held_bytes               INTEGER NOT NULL DEFAULT 0, \
                 ttl_max_secs             INTEGER NOT NULL, \
                 depositor_whitelist_root BLOB NOT NULL, \
                 created_at               INTEGER NOT NULL, \
                 next_sequence            INTEGER NOT NULL DEFAULT 0\
             ) STRICT",
            "CREATE TABLE IF NOT EXISTS relay_held (\
                 recipient           BLOB NOT NULL, \
                 seq                 INTEGER NOT NULL, \
                 message_id          BLOB NOT NULL, \
                 depositor           BLOB NOT NULL, \
                 bytes               INTEGER NOT NULL, \
                 body                BLOB NOT NULL, \
                 deposit_received_at INTEGER NOT NULL, \
                 expires_at          INTEGER NOT NULL, \
                 PRIMARY KEY (recipient, seq)\
             ) STRICT",
            "CREATE INDEX IF NOT EXISTS relay_held_expiry ON relay_held (recipient, expires_at)",
            "CREATE INDEX IF NOT EXISTS relay_held_msgid  ON relay_held (recipient, message_id)",
        ] {
            sqlx::query(stmt).execute(pool).await.map_err(backend)?;
        }
        Ok(())
    }

    /// `list_held`'s fallible body. `list_held` itself cannot return an error
    /// (trait signature), so a backend failure is logged and serves an empty
    /// list — fail-closed: the recipient drains nothing rather than the relay
    /// panicking or exposing plaintext.
    async fn list_held_inner(
        &self,
        recipient: &NodeId,
        max: usize,
        now: u64,
    ) -> Result<Vec<DrainItem>, RelayStoreError> {
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // Unknown recipient → empty (not an error), mirroring the in-memory impl.
        let binding: Option<(i64,)> =
            sqlx::query_as("SELECT held_bytes FROM relay_bindings WHERE recipient = ?")
                .bind(recipient.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
        let Some((held_bytes,)) = binding else {
            return Ok(Vec::new());
        };
        // Prune expired first (mirror the in-memory impl), freeing their bytes.
        let freed = prune_held_rows(&mut tx, recipient, now, from_i64(held_bytes)).await?;
        let _ = freed;
        // Drain up to `max`, oldest first.
        let max_i = i64::try_from(max).unwrap_or(i64::MAX);
        let rows: Vec<HeldRow> = sqlx::query_as(
            "SELECT body, message_id, seq, depositor, deposit_received_at, expires_at \
             FROM relay_held WHERE recipient = ? ORDER BY seq ASC LIMIT ?",
        )
        .bind(recipient.as_bytes().as_slice())
        .bind(max_i)
        .fetch_all(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        rows.into_iter()
            .map(|(body, mid, seq, dep, dra, exp)| {
                Ok(DrainItem {
                    envelope_bytes: body,
                    message_id: MessageId::from_bytes(to_arr32(mid)?),
                    sequence: from_i64(seq),
                    depositor: NodeId::from_bytes(to_arr32(dep)?),
                    deposit_received_at: from_i64(dra),
                    expires_at: from_i64(exp),
                })
            })
            .collect()
    }
}

/// Delete TTL-expired holds for `recipient` and decrement the binding's
/// `held_bytes` by the freed total, in the caller's transaction. Returns the
/// freed byte count. Shared by `hold_envelope`/`list_held`/`prune_expired` so the
/// prune order and accounting are identical everywhere.
async fn prune_held_rows(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    recipient: &NodeId,
    now: u64,
    current_held_bytes: u64,
) -> Result<u64, RelayStoreError> {
    let freed_rows: Vec<(i64,)> = sqlx::query_as(
        "DELETE FROM relay_held WHERE recipient = ? AND expires_at <= ? RETURNING bytes",
    )
    .bind(recipient.as_bytes().as_slice())
    .bind(to_i64(now)?)
    .fetch_all(&mut **tx)
    .await
    .map_err(backend)?;
    let freed: u64 = freed_rows.iter().map(|(b,)| from_i64(*b)).sum();
    if freed > 0 {
        let new_held = current_held_bytes.saturating_sub(freed);
        sqlx::query("UPDATE relay_bindings SET held_bytes = ? WHERE recipient = ?")
            .bind(to_i64(new_held)?)
            .bind(recipient.as_bytes().as_slice())
            .execute(&mut **tx)
            .await
            .map_err(backend)?;
    }
    Ok(freed)
}

#[async_trait]
impl RelayBindingStore for SqliteRelayStore {
    async fn register_binding(
        &self,
        binding: RelayBinding,
        max_bindings: usize,
    ) -> Result<(), RelayStoreError> {
        let _guard = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // An existing recipient re-registering consumes no new slot → BindingExists
        // regardless of the cap (checked first, mirroring the in-memory impl).
        let exists: Option<(i64,)> =
            sqlx::query_as("SELECT 1 FROM relay_bindings WHERE recipient = ?")
                .bind(binding.recipient.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
        if exists.is_some() {
            return Err(RelayStoreError::BindingExists);
        }
        // Authoritative global-cap gate, atomic with the insert (write_lock held).
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM relay_bindings")
            .fetch_one(&mut *tx)
            .await
            .map_err(backend)?;
        let max = i64::try_from(max_bindings)
            .map_err(|_| RelayStoreError::Backend("max_bindings exceeds i64 range".to_string()))?;
        if count >= max {
            return Err(RelayStoreError::CapExceeded);
        }
        sqlx::query(
            "INSERT INTO relay_bindings \
             (recipient, binding_id, quota_bytes, held_bytes, ttl_max_secs, \
              depositor_whitelist_root, created_at, next_sequence) \
             VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
        )
        .bind(binding.recipient.as_bytes().as_slice())
        .bind(binding.binding_id.as_slice())
        .bind(to_i64(binding.quota_bytes)?)
        .bind(to_i64(binding.held_bytes)?)
        .bind(i64::from(binding.ttl_max_secs))
        .bind(binding.depositor_whitelist_root.as_slice())
        .bind(to_i64(binding.created_at)?)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn get_binding(&self, recipient: &NodeId) -> Option<RelayBinding> {
        let row: Option<BindingRow> = match sqlx::query_as(
            "SELECT binding_id, quota_bytes, held_bytes, ttl_max_secs, \
                    depositor_whitelist_root, created_at \
             FROM relay_bindings WHERE recipient = ?",
        )
        .bind(recipient.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await
        {
            Ok(row) => row,
            Err(e) => {
                tracing::error!(error = %e, "relay store get_binding backend error; treating as absent");
                return None;
            }
        };
        let (binding_id, quota_bytes, held_bytes, ttl_max_secs, wl_root, created_at) = row?;
        Some(RelayBinding {
            binding_id: to_arr16(binding_id).ok()?,
            recipient: *recipient,
            quota_bytes: from_i64(quota_bytes),
            held_bytes: from_i64(held_bytes),
            ttl_max_secs: u32::try_from(ttl_max_secs).unwrap_or(0),
            depositor_whitelist_root: to_arr32(wl_root).ok()?,
            created_at: from_i64(created_at),
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn hold_envelope(
        &self,
        recipient: &NodeId,
        message_id: MessageId,
        depositor: NodeId,
        envelope_bytes: Vec<u8>,
        max_bytes_per_depositor: u64,
        deposit_received_at: u64,
        expires_at: u64,
    ) -> Result<u64, RelayStoreError> {
        let size = envelope_bytes.len() as u64;
        let _guard = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let binding: Option<(i64, i64, i64)> = sqlx::query_as(
            "SELECT quota_bytes, held_bytes, next_sequence FROM relay_bindings WHERE recipient = ?",
        )
        .bind(recipient.as_bytes().as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend)?;
        let (quota_bytes, held_bytes, next_sequence) =
            binding.ok_or(RelayStoreError::BindingNotFound)?;
        let quota_bytes = from_i64(quota_bytes);
        // Prune expired first (mirror the in-memory order) — this also updates
        // held_bytes. The whole method is one transaction: if a quota check below
        // rejects, the prune rolls back too and is re-applied on the next op, with
        // identical observable quota semantics (no test depends on a persisted
        // prune across a rejected hold). The gain is full atomicity.
        let freed = prune_held_rows(&mut tx, recipient, deposit_received_at, from_i64(held_bytes))
            .await?;
        let held_after_prune = from_i64(held_bytes).saturating_sub(freed);
        // Total-quota gate.
        if held_after_prune.saturating_add(size) > quota_bytes {
            return Err(RelayStoreError::QuotaExceeded);
        }
        // Per-depositor sub-quota (D2), computed on the post-prune state. The held
        // rows are the single source of truth (no parallel counter to desync).
        let (depositor_sum,): (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(bytes), 0) FROM relay_held WHERE recipient = ? AND depositor = ?",
        )
        .bind(recipient.as_bytes().as_slice())
        .bind(depositor.as_bytes().as_slice())
        .fetch_one(&mut *tx)
        .await
        .map_err(backend)?;
        let effective_cap = max_bytes_per_depositor.min(quota_bytes);
        if from_i64(depositor_sum).saturating_add(size) > effective_cap {
            return Err(RelayStoreError::PerDepositorQuotaExceeded);
        }
        // seq = the persistent per-binding counter (NOT MAX(seq)+1, which would
        // reset after acks/prunes delete rows and break the monotonic guard).
        sqlx::query(
            "INSERT INTO relay_held \
             (recipient, seq, message_id, depositor, bytes, body, deposit_received_at, expires_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(recipient.as_bytes().as_slice())
        .bind(next_sequence)
        .bind(message_id.as_bytes().as_slice())
        .bind(depositor.as_bytes().as_slice())
        .bind(to_i64(size)?)
        .bind(envelope_bytes.as_slice())
        .bind(to_i64(deposit_received_at)?)
        .bind(to_i64(expires_at)?)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        sqlx::query(
            "UPDATE relay_bindings \
             SET held_bytes = ?, next_sequence = next_sequence + 1 WHERE recipient = ?",
        )
        .bind(to_i64(held_after_prune.saturating_add(size))?)
        .bind(recipient.as_bytes().as_slice())
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(from_i64(next_sequence))
    }

    async fn list_held(&self, recipient: &NodeId, max: usize, now: u64) -> Vec<DrainItem> {
        let _guard = self.write_lock.lock().await;
        match self.list_held_inner(recipient, max, now).await {
            Ok(items) => items,
            Err(e) => {
                tracing::error!(error = ?e, "relay store list_held backend error; serving empty");
                Vec::new()
            }
        }
    }

    async fn prune_expired(&self, recipient: &NodeId, now: u64) -> Result<usize, RelayStoreError> {
        let _guard = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let binding: Option<(i64,)> =
            sqlx::query_as("SELECT held_bytes FROM relay_bindings WHERE recipient = ?")
                .bind(recipient.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
        let (held_bytes,) = binding.ok_or(RelayStoreError::BindingNotFound)?;
        // Count of expired holds = rows deleted; reuse prune_held_rows for the
        // byte accounting, but we need the COUNT, so do the delete here directly.
        let freed_rows: Vec<(i64,)> = sqlx::query_as(
            "DELETE FROM relay_held WHERE recipient = ? AND expires_at <= ? RETURNING bytes",
        )
        .bind(recipient.as_bytes().as_slice())
        .bind(to_i64(now)?)
        .fetch_all(&mut *tx)
        .await
        .map_err(backend)?;
        let count = freed_rows.len();
        let freed: u64 = freed_rows.iter().map(|(b,)| from_i64(*b)).sum();
        if freed > 0 {
            let new_held = from_i64(held_bytes).saturating_sub(freed);
            sqlx::query("UPDATE relay_bindings SET held_bytes = ? WHERE recipient = ?")
                .bind(to_i64(new_held)?)
                .bind(recipient.as_bytes().as_slice())
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)?;
        Ok(count)
    }

    async fn ack_delete(
        &self,
        recipient: &NodeId,
        message_ids: &[MessageId],
    ) -> Result<usize, RelayStoreError> {
        let _guard = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // Binding must exist (mirror the in-memory impl: BindingNotFound).
        let binding: Option<(i64,)> =
            sqlx::query_as("SELECT held_bytes FROM relay_bindings WHERE recipient = ?")
                .bind(recipient.as_bytes().as_slice())
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend)?;
        let (held_bytes,) = binding.ok_or(RelayStoreError::BindingNotFound)?;
        if message_ids.is_empty() {
            return Ok(0); // nothing to delete (tx rolls back; no writes happened)
        }
        // Build `IN (?, ?, …)` — sqlx/SQLite can't bind a slice to a single `?`.
        let placeholders = vec!["?"; message_ids.len()].join(", ");
        let sql = format!(
            "DELETE FROM relay_held WHERE recipient = ? AND message_id IN ({placeholders}) \
             RETURNING bytes"
        );
        let mut q = sqlx::query_as::<_, (i64,)>(&sql).bind(recipient.as_bytes().as_slice());
        for mid in message_ids {
            q = q.bind(mid.as_bytes().as_slice());
        }
        let deleted: Vec<(i64,)> = q.fetch_all(&mut *tx).await.map_err(backend)?;
        let count = deleted.len();
        let freed: u64 = deleted.iter().map(|(b,)| from_i64(*b)).sum();
        if freed > 0 {
            let new_held = from_i64(held_bytes).saturating_sub(freed);
            sqlx::query("UPDATE relay_bindings SET held_bytes = ? WHERE recipient = ?")
                .bind(to_i64(new_held)?)
                .bind(recipient.as_bytes().as_slice())
                .execute(&mut *tx)
                .await
                .map_err(backend)?;
        }
        tx.commit().await.map_err(backend)?;
        // Idempotent: a re-ack of an already-deleted id deletes 0 rows → Ok(0).
        Ok(count)
    }

    async fn remove_binding(&self, recipient: &NodeId) -> Result<(), RelayStoreError> {
        let _guard = self.write_lock.lock().await;
        let mut tx = self.pool.begin().await.map_err(backend)?;
        // Drop the held mail first, then the binding row.
        sqlx::query("DELETE FROM relay_held WHERE recipient = ?")
            .bind(recipient.as_bytes().as_slice())
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        let res = sqlx::query("DELETE FROM relay_bindings WHERE recipient = ?")
            .bind(recipient.as_bytes().as_slice())
            .execute(&mut *tx)
            .await
            .map_err(backend)?;
        if res.rows_affected() == 0 {
            // Revoke of nothing is a reject, never a silent success (tx rolls back).
            return Err(RelayStoreError::BindingNotFound);
        }
        tx.commit().await.map_err(backend)?;
        Ok(())
    }

    async fn binding_count(&self) -> usize {
        match sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM relay_bindings")
            .fetch_one(&self.pool)
            .await
        {
            Ok((n,)) => usize::try_from(n).unwrap_or(0),
            Err(e) => {
                tracing::error!(error = %e, "relay store binding_count backend error; reporting 0");
                0
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
    }

    fn mid(b: u8) -> MessageId {
        MessageId::from_bytes([b; 32])
    }

    fn binding(recipient: NodeId, quota: u64) -> RelayBinding {
        RelayBinding {
            binding_id: [1u8; 16],
            recipient,
            quota_bytes: quota,
            held_bytes: 0,
            ttl_max_secs: 3600,
            depositor_whitelist_root: [0u8; 32],
            created_at: 1,
        }
    }

    #[tokio::test]
    async fn register_then_get_and_reject_duplicate() {
        let store = InMemoryRelayStore::new();
        let r = node(1);
        assert_eq!(store.binding_count().await, 0);
        store.register_binding(binding(r, 1000), 1024).await.unwrap();
        assert_eq!(store.binding_count().await, 1);
        assert_eq!(store.get_binding(&r).await.unwrap().recipient, r);
        // One binding per recipient.
        assert_eq!(
            store.register_binding(binding(r, 1000), 1024).await,
            Err(RelayStoreError::BindingExists)
        );
    }

    // The store enforces the global binding cap atomically under its own insert
    // lock, so it is authoritative even when the engine's advisory count check is
    // stale (the SEAM-B register TOCTOU): two concurrent registers that both pass
    // a stale "count < cap" pre-check cannot both land past the cap.
    #[tokio::test]
    async fn register_binding_enforces_cap_atomically() {
        let store = InMemoryRelayStore::new();
        // Fill to a cap of 2 (no engine pre-check in the path — the store alone).
        store.register_binding(binding(node(1), 1000), 2).await.unwrap();
        store.register_binding(binding(node(2), 1000), 2).await.unwrap();
        // A third NEW recipient at the cap is refused by the store itself.
        assert_eq!(
            store.register_binding(binding(node(3), 1000), 2).await,
            Err(RelayStoreError::CapExceeded)
        );
        assert_eq!(store.binding_count().await, 2);
        // A duplicate of an EXISTING recipient is BindingExists, not CapExceeded —
        // it consumes no new slot, so the cap is irrelevant to it.
        assert_eq!(
            store.register_binding(binding(node(1), 1000), 2).await,
            Err(RelayStoreError::BindingExists)
        );
    }

    #[tokio::test]
    async fn hold_assigns_monotonic_sequence_and_tracks_bytes() {
        let store = InMemoryRelayStore::new();
        let r = node(1);
        store.register_binding(binding(r, 1000), 1024).await.unwrap();

        let s0 = store
            .hold_envelope(&r, mid(0), node(9), vec![0u8; 100], u64::MAX, 10, 110)
            .await
            .unwrap();
        let s1 = store
            .hold_envelope(&r, mid(1), node(9), vec![0u8; 200], u64::MAX, 11, 111)
            .await
            .unwrap();
        assert_eq!((s0, s1), (0, 1)); // monotonic per binding

        let held = store.list_held(&r, 10, 12).await;
        assert_eq!(held.len(), 2);
        assert_eq!(held[0].sequence, 0); // oldest first
        assert_eq!(held[1].sequence, 1);

        // held_bytes reflects the two envelopes.
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 300);
    }

    #[tokio::test]
    async fn hold_respects_quota_and_requires_binding() {
        let store = InMemoryRelayStore::new();
        let r = node(1);
        // No binding yet.
        assert_eq!(
            store.hold_envelope(&r, mid(0), node(9), vec![0u8; 10], u64::MAX, 1, 11).await,
            Err(RelayStoreError::BindingNotFound)
        );
        store.register_binding(binding(r, 250), 1024).await.unwrap();
        store
            .hold_envelope(&r, mid(1), node(9), vec![0u8; 200], u64::MAX, 1, 101)
            .await
            .unwrap();
        // 200 + 100 > 250 quota.
        assert_eq!(
            store.hold_envelope(&r, mid(2), node(9), vec![0u8; 100], u64::MAX, 2, 102).await,
            Err(RelayStoreError::QuotaExceeded)
        );
    }

    // D2: one depositor's share is capped at min(max_bytes_per_depositor,
    // quota_bytes) even when the binding as a whole still has room — so a sponsored
    // depositor cannot starve the others. The held Vec is the source of truth, so
    // a different depositor has its OWN independent sub-quota.
    #[tokio::test]
    async fn hold_enforces_per_depositor_sub_quota() {
        let store = InMemoryRelayStore::new();
        let r = node(1);
        store.register_binding(binding(r, 1000), 1024).await.unwrap();
        let a = node(5);
        let b = node(6);
        let cap = 300u64; // per-depositor sub-quota, well under the 1000 binding quota
        // A fills its 300-byte share.
        store.hold_envelope(&r, mid(0), a, vec![0u8; 200], cap, 1, 101).await.unwrap();
        store.hold_envelope(&r, mid(1), a, vec![0u8; 100], cap, 1, 101).await.unwrap();
        // A's next byte exceeds ITS share (300 + 1 > 300), though the binding has
        // 700 free — per-depositor, not total-quota, rejection.
        assert_eq!(
            store.hold_envelope(&r, mid(2), a, vec![0u8; 1], cap, 1, 101).await,
            Err(RelayStoreError::PerDepositorQuotaExceeded)
        );
        // A different depositor B still has its own full 300-byte share.
        store.hold_envelope(&r, mid(3), b, vec![0u8; 200], cap, 1, 101).await.unwrap();
        // Total held = 300 (A) + 200 (B) = 500, within the 1000 binding quota.
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 500);
        // After A acks one item, its share frees and a new A deposit fits again
        // (held Vec is the single source of truth — no counter to desync).
        store.ack_delete(&r, &[mid(0)]).await.unwrap();
        store.hold_envelope(&r, mid(4), a, vec![0u8; 200], cap, 1, 101).await.unwrap();
    }

    #[tokio::test]
    async fn list_held_respects_max() {
        let store = InMemoryRelayStore::new();
        let r = node(1);
        store.register_binding(binding(r, 10_000), 1024).await.unwrap();
        for i in 0..5u8 {
            store
                .hold_envelope(&r, mid(i), node(9), vec![0u8; 10], u64::MAX, 1, 101)
                .await
                .unwrap();
        }
        assert_eq!(store.list_held(&r, 3, 2).await.len(), 3);
        assert_eq!(store.list_held(&r, 100, 2).await.len(), 5);
        // Unknown recipient → empty, no panic.
        assert!(store.list_held(&node(9), 10, 2).await.is_empty());
    }

    #[tokio::test]
    async fn expired_holds_are_pruned_and_free_quota() {
        let store = InMemoryRelayStore::new();
        let r = node(1);
        store.register_binding(binding(r, 250), 1024).await.unwrap();

        store
            .hold_envelope(&r, mid(0), node(9), vec![0u8; 200], u64::MAX, 1, 10)
            .await
            .unwrap();
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 200);

        // At now=10, the first hold is expired (`expires_at <= now`), so it is
        // pruned and no longer returned or counted against quota.
        assert!(store.list_held(&r, 10, 10).await.is_empty());
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 0);

        store
            .hold_envelope(&r, mid(1), node(9), vec![0u8; 250], u64::MAX, 10, 20)
            .await
            .expect("expired hold should have freed the full quota");
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 250);
    }

    #[tokio::test]
    async fn ack_delete_frees_bytes_and_is_idempotent() {
        let store = InMemoryRelayStore::new();
        let r = node(1);
        store.register_binding(binding(r, 1000), 1024).await.unwrap();
        store
            .hold_envelope(&r, mid(0), node(9), vec![0u8; 100], u64::MAX, 1, 101)
            .await
            .unwrap(); // seq 0, id mid(0)
        store
            .hold_envelope(&r, mid(1), node(9), vec![0u8; 200], u64::MAX, 2, 102)
            .await
            .unwrap(); // seq 1, id mid(1)
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 300);

        // Ack mid(0) → one deleted, bytes freed.
        assert_eq!(store.ack_delete(&r, &[mid(0)]).await.unwrap(), 1);
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 200);
        assert_eq!(store.list_held(&r, 10, 3).await.len(), 1);

        // Re-ack the same id → idempotent no-op (0 deleted), bytes stable.
        assert_eq!(store.ack_delete(&r, &[mid(0)]).await.unwrap(), 0);
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 200);
    }

    #[tokio::test]
    async fn ack_delete_unknown_recipient_errors() {
        let store = InMemoryRelayStore::new();
        assert_eq!(
            store.ack_delete(&node(9), &[mid(0)]).await,
            Err(RelayStoreError::BindingNotFound)
        );
    }

    #[tokio::test]
    async fn remove_binding_revokes_and_frees_slot() {
        let store = InMemoryRelayStore::new();
        let r = node(1);
        store.register_binding(binding(r, 1000), 1024).await.unwrap();
        store
            .hold_envelope(&r, mid(0), node(9), vec![0u8; 100], u64::MAX, 1, 101)
            .await
            .unwrap();
        assert_eq!(store.binding_count().await, 1);

        // Revoke drops the binding (and its held mail) and frees the slot.
        store.remove_binding(&r).await.unwrap();
        assert_eq!(store.binding_count().await, 0);
        assert!(store.get_binding(&r).await.is_none());
        assert!(store.list_held(&r, 10, 2).await.is_empty());

        // Revoking nothing is an error, never a silent success.
        assert_eq!(
            store.remove_binding(&r).await,
            Err(RelayStoreError::BindingNotFound)
        );
    }
}

// ---------------------------------------------------------------------------
// §6 durable-store test matrix (design RELAY_DURABLE_STORE_DESIGN.md §6).
// Runs against an in-process temp SQLite — never an operator DB; the harness
// creates the schema via the `#[cfg(test)]` `create_schema`, so no `[MANUAL]`
// migration is required at test time.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod sqlite_tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    fn node(b: u8) -> NodeId {
        NodeId::from_bytes([b; 32])
    }

    fn mid(b: u8) -> MessageId {
        MessageId::from_bytes([b; 32])
    }

    fn binding(recipient: NodeId, quota: u64) -> RelayBinding {
        RelayBinding {
            binding_id: [7u8; 16],
            recipient,
            quota_bytes: quota,
            held_bytes: 0,
            ttl_max_secs: 3600,
            depositor_whitelist_root: [3u8; 32],
            created_at: 42,
        }
    }

    /// A shared-cache in-memory pool (1 connection so the schema persists across
    /// queries) with the relay schema created.
    async fn mem_store() -> SqliteRelayStore {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:").unwrap();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        SqliteRelayStore::create_schema(&pool).await.unwrap();
        SqliteRelayStore::new(pool)
    }

    async fn file_pool(path: &std::path::Path, create_schema: bool) -> SqlitePool {
        let opts = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        if create_schema {
            SqliteRelayStore::create_schema(&pool).await.unwrap();
        }
        pool
    }

    // P8.1 wiring — `open_durable_pool` opens an operator-migrated DB and is
    // fail-closed when the `[MANUAL]` migration has not been run.
    #[tokio::test]
    async fn open_durable_pool_succeeds_on_migrated_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        // Operator's [MANUAL] migration: create the file + schema, then close.
        drop(file_pool(&path, true).await);

        // Runtime open must succeed and yield a usable store.
        let pool = super::open_durable_pool(&path)
            .await
            .expect("migrated DB opens");
        let store = SqliteRelayStore::new(pool);
        assert_eq!(store.binding_count().await, 0);
    }

    #[tokio::test]
    async fn open_durable_pool_fails_closed_when_schema_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        // File exists but the [MANUAL] migration was NOT run (no tables).
        drop(file_pool(&path, false).await);

        let err = super::open_durable_pool(&path)
            .await
            .expect_err("missing schema must fail closed, never silently fall back");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("relay_bindings") && msg.contains("migration"),
            "error must name the missing table and point at the migration: {msg}"
        );
    }

    #[tokio::test]
    async fn open_durable_pool_does_not_create_the_db_file() {
        // Fence: a non-existent path must NOT be created by the node (that is the
        // operator's migration). `create_if_missing(false)` ⇒ open fails closed.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("never-created.db");
        assert!(super::open_durable_pool(&path).await.is_err());
        assert!(!path.exists(), "node must not create the durable DB file");
    }

    // §6.1 — bindings + held ciphertext survive a restart, byte-identical.
    #[tokio::test]
    async fn restart_persistence_survives_reopen_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.db");
        let r = node(1);
        let bodies = [vec![1u8; 50], vec![2u8; 70], vec![3u8; 90]];

        // First lifetime: write a binding + three holds, then close the pool.
        {
            let pool = file_pool(&path, true).await;
            let store = SqliteRelayStore::new(pool.clone());
            store.register_binding(binding(r, 10_000), 16).await.unwrap();
            for (i, body) in bodies.iter().enumerate() {
                store
                    .hold_envelope(&r, mid(i as u8), node(9), body.clone(), u64::MAX, 1, 10_000)
                    .await
                    .unwrap();
            }
            pool.close().await;
        }

        // Second lifetime: reopen the SAME file (no schema re-create), assert all
        // state survived and drains byte-identical, in sequence order.
        let pool = file_pool(&path, false).await;
        let store = SqliteRelayStore::new(pool);
        assert_eq!(store.binding_count().await, 1);
        let b = store.get_binding(&r).await.expect("binding survived");
        assert_eq!(b.held_bytes, 50 + 70 + 90);
        assert_eq!(b.binding_id, [7u8; 16]);
        let held = store.list_held(&r, 10, 5_000).await;
        assert_eq!(held.len(), 3);
        for (i, item) in held.iter().enumerate() {
            assert_eq!(item.sequence, i as u64); // monotonic, preserved
            assert_eq!(item.envelope_bytes, bodies[i]); // byte-identical
            assert_eq!(item.message_id, mid(i as u8));
        }
    }

    // §6.2 — total quota + per-depositor sub-quota at the right thresholds
    // (ports hold_respects_quota_and_requires_binding + per-depositor).
    #[tokio::test]
    async fn quota_and_per_depositor_sub_quota() {
        let store = mem_store().await;
        let r = node(1);
        // No binding yet → BindingNotFound.
        assert_eq!(
            store
                .hold_envelope(&r, mid(0), node(9), vec![0u8; 10], u64::MAX, 1, 11)
                .await,
            Err(RelayStoreError::BindingNotFound)
        );
        store.register_binding(binding(r, 1000), 16).await.unwrap();
        let a = node(5);
        let b = node(6);
        let cap = 300u64;
        store
            .hold_envelope(&r, mid(0), a, vec![0u8; 200], cap, 1, 101)
            .await
            .unwrap();
        store
            .hold_envelope(&r, mid(1), a, vec![0u8; 100], cap, 1, 101)
            .await
            .unwrap();
        // A's next byte exceeds ITS 300 share though the binding has room.
        assert_eq!(
            store
                .hold_envelope(&r, mid(2), a, vec![0u8; 1], cap, 1, 101)
                .await,
            Err(RelayStoreError::PerDepositorQuotaExceeded)
        );
        // B has its own independent share.
        store
            .hold_envelope(&r, mid(3), b, vec![0u8; 200], cap, 1, 101)
            .await
            .unwrap();
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 500);
        // After A acks, its share frees and a fresh A deposit fits again.
        store.ack_delete(&r, &[mid(0)]).await.unwrap();
        store
            .hold_envelope(&r, mid(4), a, vec![0u8; 200], cap, 1, 101)
            .await
            .unwrap();
        // Total-quota gate: fill to the 1000 binding quota, next byte rejected.
        let store2 = mem_store().await;
        store2.register_binding(binding(r, 250), 16).await.unwrap();
        store2
            .hold_envelope(&r, mid(1), node(9), vec![0u8; 200], u64::MAX, 1, 101)
            .await
            .unwrap();
        assert_eq!(
            store2
                .hold_envelope(&r, mid(2), node(9), vec![0u8; 100], u64::MAX, 2, 102)
                .await,
            Err(RelayStoreError::QuotaExceeded)
        );
    }

    // §6.3 — the global binding cap is enforced atomically under the store's own
    // lock (ports register_binding_enforces_cap_atomically).
    #[tokio::test]
    async fn atomic_binding_cap() {
        let store = mem_store().await;
        store.register_binding(binding(node(1), 1000), 2).await.unwrap();
        store.register_binding(binding(node(2), 1000), 2).await.unwrap();
        // A third NEW recipient at the cap is refused by the store itself.
        assert_eq!(
            store.register_binding(binding(node(3), 1000), 2).await,
            Err(RelayStoreError::CapExceeded)
        );
        assert_eq!(store.binding_count().await, 2);
        // A duplicate of an EXISTING recipient is BindingExists, not CapExceeded.
        assert_eq!(
            store.register_binding(binding(node(1), 1000), 2).await,
            Err(RelayStoreError::BindingExists)
        );
    }

    // §6.4 — ack frees bytes and a second ack of the same id is an idempotent
    // no-op; §6.5 — a re-drain after ack returns nothing (store-level replay).
    #[tokio::test]
    async fn idempotent_ack_and_redrain_empty() {
        let store = mem_store().await;
        let r = node(1);
        store.register_binding(binding(r, 1000), 16).await.unwrap();
        store
            .hold_envelope(&r, mid(0), node(9), vec![0u8; 100], u64::MAX, 1, 101)
            .await
            .unwrap();
        store
            .hold_envelope(&r, mid(1), node(9), vec![0u8; 200], u64::MAX, 2, 102)
            .await
            .unwrap();
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 300);

        assert_eq!(store.ack_delete(&r, &[mid(0)]).await.unwrap(), 1);
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 200);
        // Re-ack the same id → idempotent no-op, bytes stable.
        assert_eq!(store.ack_delete(&r, &[mid(0)]).await.unwrap(), 0);
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 200);
        // The acked item never re-drains.
        let held = store.list_held(&r, 10, 5).await;
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].message_id, mid(1));
        // Ack on an unknown recipient is BindingNotFound (mirrors in-memory).
        assert_eq!(
            store.ack_delete(&node(8), &[mid(0)]).await,
            Err(RelayStoreError::BindingNotFound)
        );
    }

    // §6.6 — recipient-binding isolation: an op scoped to B never touches A's mail.
    #[tokio::test]
    async fn recipient_binding_isolation() {
        let store = mem_store().await;
        let a = node(1);
        let b = node(2);
        store.register_binding(binding(a, 1000), 16).await.unwrap();
        store.register_binding(binding(b, 1000), 16).await.unwrap();
        store
            .hold_envelope(&a, mid(0), node(9), vec![1u8; 100], u64::MAX, 1, 500)
            .await
            .unwrap();
        store
            .hold_envelope(&b, mid(0), node(9), vec![2u8; 50], u64::MAX, 1, 500)
            .await
            .unwrap();
        // An ack scoped to B (same message_id value!) deletes only B's row.
        assert_eq!(store.ack_delete(&b, &[mid(0)]).await.unwrap(), 1);
        // A's mail is untouched.
        let held_a = store.list_held(&a, 10, 100).await;
        assert_eq!(held_a.len(), 1);
        assert_eq!(held_a[0].envelope_bytes, vec![1u8; 100]);
        assert_eq!(store.get_binding(&a).await.unwrap().held_bytes, 100);
        assert_eq!(store.get_binding(&b).await.unwrap().held_bytes, 0);
        // A prune scoped to B doesn't touch A.
        store.prune_expired(&b, 10_000).await.unwrap();
        assert_eq!(store.list_held(&a, 10, 100).await.len(), 1);
        // Removing B's binding leaves A's intact.
        store.remove_binding(&b).await.unwrap();
        assert_eq!(store.binding_count().await, 1);
        assert!(store.get_binding(&a).await.is_some());
    }

    // §6 (expiry) — list_held prunes expired holds and frees their quota.
    #[tokio::test]
    async fn expired_holds_pruned_on_list() {
        let store = mem_store().await;
        let r = node(1);
        store.register_binding(binding(r, 250), 16).await.unwrap();
        store
            .hold_envelope(&r, mid(0), node(9), vec![0u8; 200], u64::MAX, 1, 10)
            .await
            .unwrap();
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 200);
        // now=10 ⇒ expires_at(10) <= now ⇒ pruned on list.
        assert!(store.list_held(&r, 10, 10).await.is_empty());
        assert_eq!(store.get_binding(&r).await.unwrap().held_bytes, 0);
        // The freed quota lets a full-quota hold succeed.
        store
            .hold_envelope(&r, mid(1), node(9), vec![0u8; 250], u64::MAX, 10, 20)
            .await
            .expect("expired hold should have freed the full quota");
    }

    // §6.7 — a corrupt / missing-schema DB returns a clean Backend error from the
    // Result-returning methods (fail-closed) and serves empty from list_held —
    // never a panic, never plaintext exposure.
    #[tokio::test]
    async fn corrupt_db_fails_closed_never_panics() {
        // A pool with NO schema created stands in for a corrupt/missing-table DB:
        // every query hits "no such table", which must surface as Backend, not a
        // panic.
        let opts = SqliteConnectOptions::from_str("sqlite::memory:").unwrap();
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        let store = SqliteRelayStore::new(pool);
        let r = node(1);

        match store.register_binding(binding(r, 1000), 16).await {
            Err(RelayStoreError::Backend(_)) => {}
            other => panic!("expected Backend error on schemaless DB, got {other:?}"),
        }
        match store
            .hold_envelope(&r, mid(0), node(9), vec![0u8; 10], u64::MAX, 1, 11)
            .await
        {
            Err(RelayStoreError::Backend(_)) => {}
            other => panic!("expected Backend error on schemaless DB, got {other:?}"),
        }
        match store.prune_expired(&r, 10).await {
            Err(RelayStoreError::Backend(_)) => {}
            other => panic!("expected Backend error, got {other:?}"),
        }
        match store.ack_delete(&r, &[mid(0)]).await {
            Err(RelayStoreError::Backend(_)) => {}
            other => panic!("expected Backend error, got {other:?}"),
        }
        match store.remove_binding(&r).await {
            Err(RelayStoreError::Backend(_)) => {}
            other => panic!("expected Backend error, got {other:?}"),
        }
        // The infallible-signature methods fail closed without panicking.
        assert!(store.list_held(&r, 10, 10).await.is_empty());
        assert_eq!(store.binding_count().await, 0);
        assert!(store.get_binding(&r).await.is_none());
    }
}
