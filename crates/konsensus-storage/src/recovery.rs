//! Recovery storage — `RecoveryStore` trait with SQLite and PostgreSQL implementations.
//!
//! Three tables are managed here:
//!
//! * **`recovery_schemes`** — key-recovery configuration for this node (e.g. Shamir 2-of-3).
//! * **`recovery_trustees`** — peers who hold shards of *this* node's key (outbound).
//! * **`recovery_shards`** — shards *this* node holds on behalf of other nodes (inbound).
//!
//! # Shard encryption
//!
//! `RecoveryShard::shard_ciphertext` is AES-256-GCM encrypted at rest via
//! [`EncryptedRecoveryStore`].  The raw `SqliteRecoveryStore` /
//! `PostgresRecoveryStore` store whatever bytes they receive — callers **must**
//! wrap with `EncryptedRecoveryStore` (or pre-encrypt themselves) to satisfy
//! Principle 4.
//!
//! # Scheme upsert semantics
//!
//! `upsert_recovery_scheme` is timestamp-gated: a scheme row is only inserted or
//! updated when the incoming `updated_at` is **strictly greater** than the stored
//! value.  Returns `true` if the write was accepted.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use async_trait::async_trait;
use rand::RngCore;

use crate::error::StorageError;

// ── Models ────────────────────────────────────────────────────────────────────

/// A key-recovery scheme owned by this node.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryScheme {
    /// UUID identifying this scheme.
    pub id: String,
    /// Scheme type identifier, e.g. `"shamir_bip39"`.
    pub scheme_type: String,
    /// Minimum shares required to reconstruct the key (m).
    pub threshold: u32,
    /// Total number of shares distributed (n).
    pub total_shares: u32,
    /// Arbitrary metadata as a JSON object.
    pub metadata_json: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// ISO 8601 last-modified timestamp; used as the upsert guard.
    pub updated_at: String,
}

/// A trustee who holds one shard of this node's recovery key (outbound record).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryTrustee {
    /// UUID for this trustee slot.
    pub id: String,
    /// The recovery scheme this trustee belongs to.
    pub scheme_id: String,
    /// Node ID (hex) of the peer holding the shard.
    pub trustee_node_id: String,
    /// Which share index (1-based) this trustee holds.
    pub share_index: u32,
    /// Optional commitment hash to verify shard integrity on retrieval.
    pub shard_commitment: Option<String>,
    /// ISO 8601 timestamp of confirmed delivery; `None` if not yet delivered.
    pub delivered_at: Option<String>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// A shard this node holds on behalf of another node's recovery (inbound record).
///
/// `shard_ciphertext` **must** be AES-256-GCM encrypted before being passed to
/// `store_shard`.  Use [`EncryptedRecoveryStore`] to handle this automatically.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecoveryShard {
    /// UUID for this shard record.
    pub id: String,
    /// Node ID (hex) of the node whose key this shard helps recover.
    pub owner_node_id: String,
    /// Which share index (1-based) this shard represents.
    pub share_index: u32,
    /// AES-256-GCM encrypted shard bytes (nonce || ciphertext).
    pub shard_ciphertext: Vec<u8>,
    /// Scheme metadata provided by the owner, as a JSON object.
    pub scheme_metadata_json: String,
    /// ISO 8601 timestamp when this shard was received.
    pub received_at: String,
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Backend-agnostic recovery storage interface.
#[async_trait]
pub trait RecoveryStore: Send + Sync {
    // ── Schemes ────────────────────────────────────────────────────────────

    /// Insert or update a recovery scheme.
    ///
    /// The write is accepted only when the incoming `updated_at` is **strictly
    /// greater** than the stored value (or the row does not yet exist).
    ///
    /// Returns `true` if the row was inserted or updated.
    async fn upsert_recovery_scheme(
        &self,
        scheme: &RecoveryScheme,
    ) -> Result<bool, StorageError>;

    /// Retrieve a recovery scheme by ID.
    async fn get_recovery_scheme(
        &self,
        id: &str,
    ) -> Result<Option<RecoveryScheme>, StorageError>;

    /// List all recovery schemes, ordered by `created_at ASC`.
    async fn list_recovery_schemes(&self) -> Result<Vec<RecoveryScheme>, StorageError>;

    /// Delete a recovery scheme (and its trustees via CASCADE).
    ///
    /// Returns `true` if a row was deleted.
    async fn delete_recovery_scheme(&self, id: &str) -> Result<bool, StorageError>;

    // ── Trustees (outbound) ────────────────────────────────────────────────

    /// Insert or replace a trustee record (upsert by primary key).
    async fn upsert_trustee(&self, trustee: &RecoveryTrustee) -> Result<(), StorageError>;

    /// Retrieve a trustee record by ID.
    async fn get_trustee(&self, id: &str) -> Result<Option<RecoveryTrustee>, StorageError>;

    /// List all trustees for a given scheme, ordered by `share_index ASC`.
    async fn list_trustees_for_scheme(
        &self,
        scheme_id: &str,
    ) -> Result<Vec<RecoveryTrustee>, StorageError>;

    /// Mark a trustee's shard as delivered at `delivered_at`.
    ///
    /// Returns `true` if the row was found and updated.
    async fn mark_trustee_delivered(
        &self,
        id: &str,
        delivered_at: &str,
    ) -> Result<bool, StorageError>;

    /// Delete a trustee record by ID.
    ///
    /// Returns `true` if a row was deleted.
    async fn delete_trustee(&self, id: &str) -> Result<bool, StorageError>;

    // ── Shards (inbound) ───────────────────────────────────────────────────

    /// Store a shard held on behalf of another node.
    ///
    /// On conflict `(owner_node_id, share_index)` the existing row is replaced.
    async fn store_shard(&self, shard: &RecoveryShard) -> Result<(), StorageError>;

    /// Retrieve a shard by its UUID.
    async fn get_shard(&self, id: &str) -> Result<Option<RecoveryShard>, StorageError>;

    /// List all shards held for a given owner node, ordered by `share_index ASC`.
    async fn list_shards_for_owner(
        &self,
        owner_node_id: &str,
    ) -> Result<Vec<RecoveryShard>, StorageError>;

    /// Delete a shard by UUID. Returns `true` if a row was deleted.
    async fn delete_shard(&self, id: &str) -> Result<bool, StorageError>;

    /// Delete all shards held for a given owner node.
    ///
    /// Returns the number of rows deleted.
    async fn delete_shards_for_owner(&self, owner_node_id: &str) -> Result<u64, StorageError>;
}

// ── SQLite implementation ─────────────────────────────────────────────────────

/// SQLite-backed recovery store.
pub struct SqliteRecoveryStore {
    pool: sqlx::SqlitePool,
}

impl SqliteRecoveryStore {
    /// Wrap an existing SQLite connection pool.
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecoveryStore for SqliteRecoveryStore {
    async fn upsert_recovery_scheme(
        &self,
        scheme: &RecoveryScheme,
    ) -> Result<bool, StorageError> {
        let threshold = scheme.threshold as i64;
        let total_shares = scheme.total_shares as i64;

        let result = sqlx::query(
            "INSERT INTO recovery_schemes
               (id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
               scheme_type   = excluded.scheme_type,
               threshold     = excluded.threshold,
               total_shares  = excluded.total_shares,
               metadata_json = excluded.metadata_json,
               updated_at    = excluded.updated_at
             WHERE recovery_schemes.updated_at < excluded.updated_at",
        )
        .bind(&scheme.id)
        .bind(&scheme.scheme_type)
        .bind(threshold)
        .bind(total_shares)
        .bind(&scheme.metadata_json)
        .bind(&scheme.created_at)
        .bind(&scheme.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_recovery_scheme(
        &self,
        id: &str,
    ) -> Result<Option<RecoveryScheme>, StorageError> {
        let row: Option<(String, String, i64, i64, String, String, String)> = sqlx::query_as(
            "SELECT id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at
             FROM recovery_schemes WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at)| {
                RecoveryScheme {
                    id,
                    scheme_type,
                    threshold: threshold as u32,
                    total_shares: total_shares as u32,
                    metadata_json,
                    created_at,
                    updated_at,
                }
            },
        ))
    }

    async fn list_recovery_schemes(&self) -> Result<Vec<RecoveryScheme>, StorageError> {
        let rows: Vec<(String, String, i64, i64, String, String, String)> = sqlx::query_as(
            "SELECT id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at
             FROM recovery_schemes ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at)| {
                    RecoveryScheme {
                        id,
                        scheme_type,
                        threshold: threshold as u32,
                        total_shares: total_shares as u32,
                        metadata_json,
                        created_at,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    async fn delete_recovery_scheme(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM recovery_schemes WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn upsert_trustee(&self, trustee: &RecoveryTrustee) -> Result<(), StorageError> {
        let share_index = trustee.share_index as i64;

        sqlx::query(
            "INSERT INTO recovery_trustees
               (id, scheme_id, trustee_node_id, share_index, shard_commitment, delivered_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(id) DO UPDATE SET
               scheme_id        = excluded.scheme_id,
               trustee_node_id  = excluded.trustee_node_id,
               share_index      = excluded.share_index,
               shard_commitment = excluded.shard_commitment,
               delivered_at     = excluded.delivered_at",
        )
        .bind(&trustee.id)
        .bind(&trustee.scheme_id)
        .bind(&trustee.trustee_node_id)
        .bind(share_index)
        .bind(&trustee.shard_commitment)
        .bind(&trustee.delivered_at)
        .bind(&trustee.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_trustee(&self, id: &str) -> Result<Option<RecoveryTrustee>, StorageError> {
        let row: Option<(
            String,
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT id, scheme_id, trustee_node_id, share_index,
                    shard_commitment, delivered_at, created_at
             FROM recovery_trustees WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, scheme_id, trustee_node_id, share_index, shard_commitment, delivered_at, created_at)| {
                RecoveryTrustee {
                    id,
                    scheme_id,
                    trustee_node_id,
                    share_index: share_index as u32,
                    shard_commitment,
                    delivered_at,
                    created_at,
                }
            },
        ))
    }

    async fn list_trustees_for_scheme(
        &self,
        scheme_id: &str,
    ) -> Result<Vec<RecoveryTrustee>, StorageError> {
        let rows: Vec<(
            String,
            String,
            String,
            i64,
            Option<String>,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT id, scheme_id, trustee_node_id, share_index,
                    shard_commitment, delivered_at, created_at
             FROM recovery_trustees WHERE scheme_id = ?1
             ORDER BY share_index ASC",
        )
        .bind(scheme_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, scheme_id, trustee_node_id, share_index, shard_commitment, delivered_at, created_at)| {
                    RecoveryTrustee {
                        id,
                        scheme_id,
                        trustee_node_id,
                        share_index: share_index as u32,
                        shard_commitment,
                        delivered_at,
                        created_at,
                    }
                },
            )
            .collect())
    }

    async fn mark_trustee_delivered(
        &self,
        id: &str,
        delivered_at: &str,
    ) -> Result<bool, StorageError> {
        let result =
            sqlx::query("UPDATE recovery_trustees SET delivered_at = ?2 WHERE id = ?1")
                .bind(id)
                .bind(delivered_at)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_trustee(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM recovery_trustees WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn store_shard(&self, shard: &RecoveryShard) -> Result<(), StorageError> {
        let share_index = shard.share_index as i64;

        sqlx::query(
            "INSERT INTO recovery_shards
               (id, owner_node_id, share_index, shard_ciphertext, scheme_metadata_json, received_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(owner_node_id, share_index) DO UPDATE SET
               id                   = excluded.id,
               shard_ciphertext     = excluded.shard_ciphertext,
               scheme_metadata_json = excluded.scheme_metadata_json,
               received_at          = excluded.received_at",
        )
        .bind(&shard.id)
        .bind(&shard.owner_node_id)
        .bind(share_index)
        .bind(&shard.shard_ciphertext)
        .bind(&shard.scheme_metadata_json)
        .bind(&shard.received_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_shard(&self, id: &str) -> Result<Option<RecoveryShard>, StorageError> {
        let row: Option<(String, String, i64, Vec<u8>, String, String)> = sqlx::query_as(
            "SELECT id, owner_node_id, share_index, shard_ciphertext,
                    scheme_metadata_json, received_at
             FROM recovery_shards WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, owner_node_id, share_index, shard_ciphertext, scheme_metadata_json, received_at)| {
                RecoveryShard {
                    id,
                    owner_node_id,
                    share_index: share_index as u32,
                    shard_ciphertext,
                    scheme_metadata_json,
                    received_at,
                }
            },
        ))
    }

    async fn list_shards_for_owner(
        &self,
        owner_node_id: &str,
    ) -> Result<Vec<RecoveryShard>, StorageError> {
        let rows: Vec<(String, String, i64, Vec<u8>, String, String)> = sqlx::query_as(
            "SELECT id, owner_node_id, share_index, shard_ciphertext,
                    scheme_metadata_json, received_at
             FROM recovery_shards WHERE owner_node_id = ?1
             ORDER BY share_index ASC",
        )
        .bind(owner_node_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, owner_node_id, share_index, shard_ciphertext, scheme_metadata_json, received_at)| {
                    RecoveryShard {
                        id,
                        owner_node_id,
                        share_index: share_index as u32,
                        shard_ciphertext,
                        scheme_metadata_json,
                        received_at,
                    }
                },
            )
            .collect())
    }

    async fn delete_shard(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM recovery_shards WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_shards_for_owner(&self, owner_node_id: &str) -> Result<u64, StorageError> {
        let result = sqlx::query("DELETE FROM recovery_shards WHERE owner_node_id = ?1")
            .bind(owner_node_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// ── PostgreSQL implementation ─────────────────────────────────────────────────

/// PostgreSQL-backed recovery store.
pub struct PostgresRecoveryStore {
    pool: sqlx::PgPool,
}

impl PostgresRecoveryStore {
    /// Wrap an existing PostgreSQL connection pool.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RecoveryStore for PostgresRecoveryStore {
    async fn upsert_recovery_scheme(
        &self,
        scheme: &RecoveryScheme,
    ) -> Result<bool, StorageError> {
        let threshold = scheme.threshold as i32;
        let total_shares = scheme.total_shares as i32;

        let result = sqlx::query(
            "INSERT INTO recovery_schemes
               (id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(id) DO UPDATE SET
               scheme_type   = EXCLUDED.scheme_type,
               threshold     = EXCLUDED.threshold,
               total_shares  = EXCLUDED.total_shares,
               metadata_json = EXCLUDED.metadata_json,
               updated_at    = EXCLUDED.updated_at
             WHERE recovery_schemes.updated_at < EXCLUDED.updated_at",
        )
        .bind(&scheme.id)
        .bind(&scheme.scheme_type)
        .bind(threshold)
        .bind(total_shares)
        .bind(&scheme.metadata_json)
        .bind(&scheme.created_at)
        .bind(&scheme.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_recovery_scheme(
        &self,
        id: &str,
    ) -> Result<Option<RecoveryScheme>, StorageError> {
        let row: Option<(String, String, i32, i32, String, String, String)> = sqlx::query_as(
            "SELECT id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at
             FROM recovery_schemes WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at)| {
                RecoveryScheme {
                    id,
                    scheme_type,
                    threshold: threshold as u32,
                    total_shares: total_shares as u32,
                    metadata_json,
                    created_at,
                    updated_at,
                }
            },
        ))
    }

    async fn list_recovery_schemes(&self) -> Result<Vec<RecoveryScheme>, StorageError> {
        let rows: Vec<(String, String, i32, i32, String, String, String)> = sqlx::query_as(
            "SELECT id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at
             FROM recovery_schemes ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, scheme_type, threshold, total_shares, metadata_json, created_at, updated_at)| {
                    RecoveryScheme {
                        id,
                        scheme_type,
                        threshold: threshold as u32,
                        total_shares: total_shares as u32,
                        metadata_json,
                        created_at,
                        updated_at,
                    }
                },
            )
            .collect())
    }

    async fn delete_recovery_scheme(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM recovery_schemes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn upsert_trustee(&self, trustee: &RecoveryTrustee) -> Result<(), StorageError> {
        let share_index = trustee.share_index as i32;

        sqlx::query(
            "INSERT INTO recovery_trustees
               (id, scheme_id, trustee_node_id, share_index, shard_commitment, delivered_at, created_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT(id) DO UPDATE SET
               scheme_id        = EXCLUDED.scheme_id,
               trustee_node_id  = EXCLUDED.trustee_node_id,
               share_index      = EXCLUDED.share_index,
               shard_commitment = EXCLUDED.shard_commitment,
               delivered_at     = EXCLUDED.delivered_at",
        )
        .bind(&trustee.id)
        .bind(&trustee.scheme_id)
        .bind(&trustee.trustee_node_id)
        .bind(share_index)
        .bind(&trustee.shard_commitment)
        .bind(&trustee.delivered_at)
        .bind(&trustee.created_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_trustee(&self, id: &str) -> Result<Option<RecoveryTrustee>, StorageError> {
        let row: Option<(
            String,
            String,
            String,
            i32,
            Option<String>,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT id, scheme_id, trustee_node_id, share_index,
                    shard_commitment, delivered_at, created_at
             FROM recovery_trustees WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, scheme_id, trustee_node_id, share_index, shard_commitment, delivered_at, created_at)| {
                RecoveryTrustee {
                    id,
                    scheme_id,
                    trustee_node_id,
                    share_index: share_index as u32,
                    shard_commitment,
                    delivered_at,
                    created_at,
                }
            },
        ))
    }

    async fn list_trustees_for_scheme(
        &self,
        scheme_id: &str,
    ) -> Result<Vec<RecoveryTrustee>, StorageError> {
        let rows: Vec<(
            String,
            String,
            String,
            i32,
            Option<String>,
            Option<String>,
            String,
        )> = sqlx::query_as(
            "SELECT id, scheme_id, trustee_node_id, share_index,
                    shard_commitment, delivered_at, created_at
             FROM recovery_trustees WHERE scheme_id = $1
             ORDER BY share_index ASC",
        )
        .bind(scheme_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, scheme_id, trustee_node_id, share_index, shard_commitment, delivered_at, created_at)| {
                    RecoveryTrustee {
                        id,
                        scheme_id,
                        trustee_node_id,
                        share_index: share_index as u32,
                        shard_commitment,
                        delivered_at,
                        created_at,
                    }
                },
            )
            .collect())
    }

    async fn mark_trustee_delivered(
        &self,
        id: &str,
        delivered_at: &str,
    ) -> Result<bool, StorageError> {
        let result =
            sqlx::query("UPDATE recovery_trustees SET delivered_at = $2 WHERE id = $1")
                .bind(id)
                .bind(delivered_at)
                .execute(&self.pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_trustee(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM recovery_trustees WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn store_shard(&self, shard: &RecoveryShard) -> Result<(), StorageError> {
        let share_index = shard.share_index as i32;

        sqlx::query(
            "INSERT INTO recovery_shards
               (id, owner_node_id, share_index, shard_ciphertext, scheme_metadata_json, received_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT(owner_node_id, share_index) DO UPDATE SET
               id                   = EXCLUDED.id,
               shard_ciphertext     = EXCLUDED.shard_ciphertext,
               scheme_metadata_json = EXCLUDED.scheme_metadata_json,
               received_at          = EXCLUDED.received_at",
        )
        .bind(&shard.id)
        .bind(&shard.owner_node_id)
        .bind(share_index)
        .bind(&shard.shard_ciphertext)
        .bind(&shard.scheme_metadata_json)
        .bind(&shard.received_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_shard(&self, id: &str) -> Result<Option<RecoveryShard>, StorageError> {
        let row: Option<(String, String, i32, Vec<u8>, String, String)> = sqlx::query_as(
            "SELECT id, owner_node_id, share_index, shard_ciphertext,
                    scheme_metadata_json, received_at
             FROM recovery_shards WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, owner_node_id, share_index, shard_ciphertext, scheme_metadata_json, received_at)| {
                RecoveryShard {
                    id,
                    owner_node_id,
                    share_index: share_index as u32,
                    shard_ciphertext,
                    scheme_metadata_json,
                    received_at,
                }
            },
        ))
    }

    async fn list_shards_for_owner(
        &self,
        owner_node_id: &str,
    ) -> Result<Vec<RecoveryShard>, StorageError> {
        let rows: Vec<(String, String, i32, Vec<u8>, String, String)> = sqlx::query_as(
            "SELECT id, owner_node_id, share_index, shard_ciphertext,
                    scheme_metadata_json, received_at
             FROM recovery_shards WHERE owner_node_id = $1
             ORDER BY share_index ASC",
        )
        .bind(owner_node_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, owner_node_id, share_index, shard_ciphertext, scheme_metadata_json, received_at)| {
                    RecoveryShard {
                        id,
                        owner_node_id,
                        share_index: share_index as u32,
                        shard_ciphertext,
                        scheme_metadata_json,
                        received_at,
                    }
                },
            )
            .collect())
    }

    async fn delete_shard(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM recovery_shards WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_shards_for_owner(&self, owner_node_id: &str) -> Result<u64, StorageError> {
        let result = sqlx::query("DELETE FROM recovery_shards WHERE owner_node_id = $1")
            .bind(owner_node_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

// ── EncryptedRecoveryStore ────────────────────────────────────────────────────

/// AES-256-GCM at-rest encryption wrapper over any [`RecoveryStore`].
///
/// Encrypts `shard_ciphertext` before passing to the inner store, and decrypts
/// it after loading.  All other fields are stored as-is.
///
/// Encryption format: `nonce (12 bytes) || ciphertext`.
pub struct EncryptedRecoveryStore<S: RecoveryStore> {
    inner: S,
    cipher: Aes256Gcm,
}

impl<S: RecoveryStore> EncryptedRecoveryStore<S> {
    /// Create a new encrypted recovery store wrapper.
    ///
    /// `key` should be the 32-byte AES key from `NodeIdentity::aes_key()`.
    pub fn new(inner: S, key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key is always 32 bytes");
        Self { inner, cipher }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = AesNonce::from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StorageError::Encryption(format!("encrypt: {e}")))?;

        let mut result = Vec::with_capacity(12 + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        if data.len() < 12 {
            return Err(StorageError::Encryption(
                "encrypted shard data too short for nonce".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = AesNonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| StorageError::Encryption(format!("decrypt: {e}")))
    }
}

#[async_trait]
impl<S: RecoveryStore> RecoveryStore for EncryptedRecoveryStore<S> {
    // Schemes pass through unchanged — no sensitive binary payloads.

    async fn upsert_recovery_scheme(
        &self,
        scheme: &RecoveryScheme,
    ) -> Result<bool, StorageError> {
        self.inner.upsert_recovery_scheme(scheme).await
    }

    async fn get_recovery_scheme(
        &self,
        id: &str,
    ) -> Result<Option<RecoveryScheme>, StorageError> {
        self.inner.get_recovery_scheme(id).await
    }

    async fn list_recovery_schemes(&self) -> Result<Vec<RecoveryScheme>, StorageError> {
        self.inner.list_recovery_schemes().await
    }

    async fn delete_recovery_scheme(&self, id: &str) -> Result<bool, StorageError> {
        self.inner.delete_recovery_scheme(id).await
    }

    // Trustees pass through unchanged — no binary payloads.

    async fn upsert_trustee(&self, trustee: &RecoveryTrustee) -> Result<(), StorageError> {
        self.inner.upsert_trustee(trustee).await
    }

    async fn get_trustee(&self, id: &str) -> Result<Option<RecoveryTrustee>, StorageError> {
        self.inner.get_trustee(id).await
    }

    async fn list_trustees_for_scheme(
        &self,
        scheme_id: &str,
    ) -> Result<Vec<RecoveryTrustee>, StorageError> {
        self.inner.list_trustees_for_scheme(scheme_id).await
    }

    async fn mark_trustee_delivered(
        &self,
        id: &str,
        delivered_at: &str,
    ) -> Result<bool, StorageError> {
        self.inner.mark_trustee_delivered(id, delivered_at).await
    }

    async fn delete_trustee(&self, id: &str) -> Result<bool, StorageError> {
        self.inner.delete_trustee(id).await
    }

    // Shards: encrypt on write, decrypt on read.

    async fn store_shard(&self, shard: &RecoveryShard) -> Result<(), StorageError> {
        let encrypted = self.encrypt(&shard.shard_ciphertext)?;
        let encrypted_shard = RecoveryShard {
            shard_ciphertext: encrypted,
            ..shard.clone()
        };
        self.inner.store_shard(&encrypted_shard).await
    }

    async fn get_shard(&self, id: &str) -> Result<Option<RecoveryShard>, StorageError> {
        match self.inner.get_shard(id).await? {
            None => Ok(None),
            Some(shard) => {
                let plaintext = self.decrypt(&shard.shard_ciphertext)?;
                Ok(Some(RecoveryShard {
                    shard_ciphertext: plaintext,
                    ..shard
                }))
            }
        }
    }

    async fn list_shards_for_owner(
        &self,
        owner_node_id: &str,
    ) -> Result<Vec<RecoveryShard>, StorageError> {
        let shards = self.inner.list_shards_for_owner(owner_node_id).await?;
        shards
            .into_iter()
            .map(|shard| {
                let plaintext = self.decrypt(&shard.shard_ciphertext)?;
                Ok(RecoveryShard {
                    shard_ciphertext: plaintext,
                    ..shard
                })
            })
            .collect()
    }

    async fn delete_shard(&self, id: &str) -> Result<bool, StorageError> {
        self.inner.delete_shard(id).await
    }

    async fn delete_shards_for_owner(&self, owner_node_id: &str) -> Result<u64, StorageError> {
        self.inner.delete_shards_for_owner(owner_node_id).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    const SCHEMA: &str = "
        CREATE TABLE IF NOT EXISTS recovery_schemes (
            id            TEXT    PRIMARY KEY,
            scheme_type   TEXT    NOT NULL,
            threshold     INTEGER NOT NULL,
            total_shares  INTEGER NOT NULL,
            metadata_json TEXT    NOT NULL DEFAULT '{}',
            created_at    TEXT    NOT NULL,
            updated_at    TEXT    NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recovery_trustees (
            id               TEXT    PRIMARY KEY,
            scheme_id        TEXT    NOT NULL,
            trustee_node_id  TEXT    NOT NULL,
            share_index      INTEGER NOT NULL,
            shard_commitment TEXT,
            delivered_at     TEXT,
            created_at       TEXT    NOT NULL,
            UNIQUE (scheme_id, trustee_node_id),
            UNIQUE (scheme_id, share_index)
        );
        CREATE TABLE IF NOT EXISTS recovery_shards (
            id                   TEXT    PRIMARY KEY,
            owner_node_id        TEXT    NOT NULL,
            share_index          INTEGER NOT NULL,
            shard_ciphertext     BLOB    NOT NULL,
            scheme_metadata_json TEXT    NOT NULL DEFAULT '{}',
            received_at          TEXT    NOT NULL,
            UNIQUE (owner_node_id, share_index)
        );
    ";

    async fn make_repo() -> SqliteRecoveryStore {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        for stmt in SCHEMA.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
        SqliteRecoveryStore::new(pool)
    }

    fn make_scheme(id: &str, updated_at: &str) -> RecoveryScheme {
        RecoveryScheme {
            id: id.into(),
            scheme_type: "shamir_bip39".into(),
            threshold: 2,
            total_shares: 3,
            metadata_json: "{}".into(),
            created_at: "2026-01-01T00:00:00.000Z".into(),
            updated_at: updated_at.into(),
        }
    }

    fn make_trustee(id: &str, scheme_id: &str, share_index: u32) -> RecoveryTrustee {
        RecoveryTrustee {
            id: id.into(),
            scheme_id: scheme_id.into(),
            trustee_node_id: format!("node_{share_index}"),
            share_index,
            shard_commitment: Some("deadbeef".into()),
            delivered_at: None,
            created_at: "2026-01-01T00:00:00.000Z".into(),
        }
    }

    fn make_shard(id: &str, owner: &str, share_index: u32) -> RecoveryShard {
        RecoveryShard {
            id: id.into(),
            owner_node_id: owner.into(),
            share_index,
            shard_ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
            scheme_metadata_json: "{}".into(),
            received_at: "2026-01-01T00:00:00.000Z".into(),
        }
    }

    #[tokio::test]
    async fn test_scheme_insert_and_get() {
        let repo = make_repo().await;
        let scheme = make_scheme("s1", "2026-01-01T00:00:00.000Z");
        let inserted = repo.upsert_recovery_scheme(&scheme).await.unwrap();
        assert!(inserted);
        let got = repo.get_recovery_scheme("s1").await.unwrap().unwrap();
        assert_eq!(got.id, "s1");
        assert_eq!(got.threshold, 2);
        assert_eq!(got.total_shares, 3);
    }

    #[tokio::test]
    async fn test_scheme_upsert_newer_accepted() {
        let repo = make_repo().await;
        let old = make_scheme("s1", "2026-01-01T00:00:00.000Z");
        repo.upsert_recovery_scheme(&old).await.unwrap();
        let newer = RecoveryScheme {
            threshold: 3,
            total_shares: 5,
            updated_at: "2026-06-01T00:00:00.000Z".into(),
            ..old.clone()
        };
        let accepted = repo.upsert_recovery_scheme(&newer).await.unwrap();
        assert!(accepted);
        let got = repo.get_recovery_scheme("s1").await.unwrap().unwrap();
        assert_eq!(got.threshold, 3);
        assert_eq!(got.total_shares, 5);
    }

    #[tokio::test]
    async fn test_scheme_upsert_older_rejected() {
        let repo = make_repo().await;
        let row = make_scheme("s1", "2026-06-01T00:00:00.000Z");
        repo.upsert_recovery_scheme(&row).await.unwrap();
        let stale = RecoveryScheme {
            threshold: 99,
            updated_at: "2026-01-01T00:00:00.000Z".into(),
            ..row.clone()
        };
        let accepted = repo.upsert_recovery_scheme(&stale).await.unwrap();
        assert!(!accepted);
        let got = repo.get_recovery_scheme("s1").await.unwrap().unwrap();
        assert_eq!(got.threshold, 2, "stale write must not change threshold");
    }

    #[tokio::test]
    async fn test_scheme_list_and_delete() {
        let repo = make_repo().await;
        repo.upsert_recovery_scheme(&make_scheme("s1", "2026-01-01T00:00:00.000Z")).await.unwrap();
        repo.upsert_recovery_scheme(&make_scheme("s2", "2026-02-01T00:00:00.000Z")).await.unwrap();
        let all = repo.list_recovery_schemes().await.unwrap();
        assert_eq!(all.len(), 2);
        let deleted = repo.delete_recovery_scheme("s1").await.unwrap();
        assert!(deleted);
        let all = repo.list_recovery_schemes().await.unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, "s2");
        let deleted2 = repo.delete_recovery_scheme("s1").await.unwrap();
        assert!(!deleted2);
    }

    #[tokio::test]
    async fn test_trustee_upsert_and_get() {
        let repo = make_repo().await;
        repo.upsert_recovery_scheme(&make_scheme("s1", "2026-01-01T00:00:00.000Z")).await.unwrap();
        let trustee = make_trustee("t1", "s1", 1);
        repo.upsert_trustee(&trustee).await.unwrap();
        let got = repo.get_trustee("t1").await.unwrap().unwrap();
        assert_eq!(got.trustee_node_id, "node_1");
        assert_eq!(got.share_index, 1);
        assert!(got.delivered_at.is_none());
    }

    #[tokio::test]
    async fn test_trustee_list_for_scheme() {
        let repo = make_repo().await;
        repo.upsert_recovery_scheme(&make_scheme("s1", "2026-01-01T00:00:00.000Z")).await.unwrap();
        repo.upsert_trustee(&make_trustee("t1", "s1", 1)).await.unwrap();
        repo.upsert_trustee(&make_trustee("t2", "s1", 2)).await.unwrap();
        repo.upsert_trustee(&make_trustee("t3", "s1", 3)).await.unwrap();
        let trustees = repo.list_trustees_for_scheme("s1").await.unwrap();
        assert_eq!(trustees.len(), 3);
        assert_eq!(trustees[0].share_index, 1);
        assert_eq!(trustees[2].share_index, 3);
    }

    #[tokio::test]
    async fn test_trustee_mark_delivered() {
        let repo = make_repo().await;
        repo.upsert_recovery_scheme(&make_scheme("s1", "2026-01-01T00:00:00.000Z")).await.unwrap();
        repo.upsert_trustee(&make_trustee("t1", "s1", 1)).await.unwrap();
        let updated = repo.mark_trustee_delivered("t1", "2026-04-21T12:00:00.000Z").await.unwrap();
        assert!(updated);
        let got = repo.get_trustee("t1").await.unwrap().unwrap();
        assert_eq!(got.delivered_at.as_deref(), Some("2026-04-21T12:00:00.000Z"));
    }

    #[tokio::test]
    async fn test_trustee_delete() {
        let repo = make_repo().await;
        repo.upsert_recovery_scheme(&make_scheme("s1", "2026-01-01T00:00:00.000Z")).await.unwrap();
        repo.upsert_trustee(&make_trustee("t1", "s1", 1)).await.unwrap();
        let deleted = repo.delete_trustee("t1").await.unwrap();
        assert!(deleted);
        assert!(repo.get_trustee("t1").await.unwrap().is_none());
        let deleted2 = repo.delete_trustee("t1").await.unwrap();
        assert!(!deleted2);
    }

    #[tokio::test]
    async fn test_shard_store_and_get() {
        let repo = make_repo().await;
        let shard = make_shard("sh1", "owner_aabb", 1);
        repo.store_shard(&shard).await.unwrap();
        let got = repo.get_shard("sh1").await.unwrap().unwrap();
        assert_eq!(got.owner_node_id, "owner_aabb");
        assert_eq!(got.share_index, 1);
        assert_eq!(got.shard_ciphertext, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[tokio::test]
    async fn test_shard_replace_on_conflict() {
        let repo = make_repo().await;
        repo.store_shard(&make_shard("sh1", "owner", 1)).await.unwrap();
        let updated = RecoveryShard {
            id: "sh2".into(),
            shard_ciphertext: vec![0xca, 0xfe],
            ..make_shard("sh2", "owner", 1)
        };
        repo.store_shard(&updated).await.unwrap();
        assert!(repo.get_shard("sh1").await.unwrap().is_none());
        let got = repo.get_shard("sh2").await.unwrap().unwrap();
        assert_eq!(got.shard_ciphertext, vec![0xca, 0xfe]);
    }

    #[tokio::test]
    async fn test_shard_list_for_owner() {
        let repo = make_repo().await;
        repo.store_shard(&make_shard("sh1", "alice", 1)).await.unwrap();
        repo.store_shard(&make_shard("sh2", "alice", 2)).await.unwrap();
        repo.store_shard(&make_shard("sh3", "bob", 1)).await.unwrap();
        let alice_shards = repo.list_shards_for_owner("alice").await.unwrap();
        assert_eq!(alice_shards.len(), 2);
        assert_eq!(alice_shards[0].share_index, 1);
        assert_eq!(alice_shards[1].share_index, 2);
        let bob_shards = repo.list_shards_for_owner("bob").await.unwrap();
        assert_eq!(bob_shards.len(), 1);
    }

    #[tokio::test]
    async fn test_shard_delete_by_id() {
        let repo = make_repo().await;
        repo.store_shard(&make_shard("sh1", "alice", 1)).await.unwrap();
        let deleted = repo.delete_shard("sh1").await.unwrap();
        assert!(deleted);
        assert!(repo.get_shard("sh1").await.unwrap().is_none());
        let deleted2 = repo.delete_shard("sh1").await.unwrap();
        assert!(!deleted2);
    }

    #[tokio::test]
    async fn test_shard_delete_all_for_owner() {
        let repo = make_repo().await;
        repo.store_shard(&make_shard("sh1", "alice", 1)).await.unwrap();
        repo.store_shard(&make_shard("sh2", "alice", 2)).await.unwrap();
        repo.store_shard(&make_shard("sh3", "bob", 1)).await.unwrap();
        let n = repo.delete_shards_for_owner("alice").await.unwrap();
        assert_eq!(n, 2);
        let remaining = repo.list_shards_for_owner("alice").await.unwrap();
        assert!(remaining.is_empty());
        let bob = repo.list_shards_for_owner("bob").await.unwrap();
        assert_eq!(bob.len(), 1);
    }

    #[tokio::test]
    async fn test_encrypted_store_roundtrip() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        for stmt in SCHEMA.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
        let inner = SqliteRecoveryStore::new(pool);
        let key = [0x42u8; 32];
        let enc = EncryptedRecoveryStore::new(inner, &key);
        let plaintext = b"super secret shard material";
        let shard = RecoveryShard {
            id: "sh1".into(),
            owner_node_id: "owner".into(),
            share_index: 1,
            shard_ciphertext: plaintext.to_vec(),
            scheme_metadata_json: "{}".into(),
            received_at: "2026-04-21T00:00:00.000Z".into(),
        };
        enc.store_shard(&shard).await.unwrap();
        let got = enc.get_shard("sh1").await.unwrap().unwrap();
        assert_eq!(got.shard_ciphertext, plaintext.to_vec());
    }

    #[tokio::test]
    async fn test_encrypted_store_ciphertext_differs_on_disk() {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        for stmt in SCHEMA.split(';').map(str::trim).filter(|s| !s.is_empty()) {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
        let raw_pool = pool.clone();
        let inner = SqliteRecoveryStore::new(pool);
        let key = [0x13u8; 32];
        let enc = EncryptedRecoveryStore::new(inner, &key);
        let plaintext = b"raw shard bytes";
        let shard = RecoveryShard {
            id: "sh1".into(),
            owner_node_id: "owner".into(),
            share_index: 1,
            shard_ciphertext: plaintext.to_vec(),
            scheme_metadata_json: "{}".into(),
            received_at: "2026-04-21T00:00:00.000Z".into(),
        };
        enc.store_shard(&shard).await.unwrap();
        let raw: (Vec<u8>,) =
            sqlx::query_as("SELECT shard_ciphertext FROM recovery_shards WHERE id = 'sh1'")
                .fetch_one(&raw_pool)
                .await
                .unwrap();
        assert_ne!(raw.0, plaintext.to_vec(), "raw bytes must be encrypted");
        assert!(raw.0.len() > plaintext.len());
    }
}
