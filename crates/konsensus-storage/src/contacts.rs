//! Contact book storage — `ContactRepo` trait with SQLite and PostgreSQL implementations.
//!
//! Upsert semantics are timestamp-gated: a row is only inserted or updated when
//! the incoming `updated_at` is strictly greater than the stored value.  Callers
//! receive `Ok(false)` when a write is rejected because the incoming record is not
//! newer, allowing sync protocols to detect and discard stale payloads.
//!
//! # Avatar deduplication
//!
//! `avatar_blake3` stores the blake3 hash of the raw avatar blob.  The blob
//! itself lives in the `files` table (keyed by `blake3_hash`), so the same
//! image shared by many contacts is stored only once.

use async_trait::async_trait;

use crate::error::StorageError;

// ── Model ─────────────────────────────────────────────────────────────────────

/// A contact book entry for a known peer.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContactRow {
    /// The peer's node ID (hex-encoded public key).
    pub node_id: String,
    /// User-assigned local nickname (not shared with the peer).
    pub local_alias: Option<String>,
    /// Display name claimed by the peer in their NodeProfile.
    pub claimed_name: Option<String>,
    /// Full NodeProfile payload as a JSON object.
    pub profile_json: String,
    /// blake3 hash of the avatar blob; the blob is stored in `files.blake3_hash`.
    pub avatar_blake3: Option<String>,
    /// JSON array of verified external identity attestations.
    pub verified_identities_json: String,
    /// Whether this contact is muted (suppresses notifications).
    pub muted: bool,
    /// Whether this contact is blocked (rejects all inbound messages).
    pub blocked: bool,
    /// JSON array of user-assigned tag strings.
    pub tags_json: String,
    /// Free-form private notes visible only to this node.
    pub notes: Option<String>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// ISO 8601 last-modified timestamp; used as the upsert guard.
    pub updated_at: String,
}

impl ContactRow {
    /// Construct a minimal new contact with only the required fields.
    pub fn new(node_id: impl Into<String>) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            node_id: node_id.into(),
            local_alias: None,
            claimed_name: None,
            profile_json: "{}".into(),
            avatar_blake3: None,
            verified_identities_json: "[]".into(),
            muted: false,
            blocked: false,
            tags_json: "[]".into(),
            notes: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// Backend-agnostic contact book interface.
#[async_trait]
pub trait ContactRepo: Send + Sync {
    /// Insert or update a contact.
    ///
    /// The write is accepted only when the incoming `updated_at` is **strictly
    /// greater** than the stored value (or the row does not yet exist).
    ///
    /// Returns `true` if the row was inserted or updated, `false` if rejected
    /// because the incoming record is not newer than the stored one.
    async fn upsert_contact(&self, row: &ContactRow) -> Result<bool, StorageError>;

    /// Retrieve a contact by node ID.
    async fn get_contact(&self, node_id: &str) -> Result<Option<ContactRow>, StorageError>;

    /// List contacts, optionally filtered by blocked status.
    ///
    /// Results are ordered by `updated_at DESC`.
    /// Pass `blocked = Some(false)` to exclude blocked contacts (typical UI default).
    async fn list_contacts(
        &self,
        blocked: Option<bool>,
        limit: u32,
    ) -> Result<Vec<ContactRow>, StorageError>;

    /// Delete a contact by node ID. Returns `true` if a row was deleted.
    async fn delete_contact(&self, node_id: &str) -> Result<bool, StorageError>;
}

// ── SQLite implementation ─────────────────────────────────────────────────────

/// SQLite-backed contact repository.
pub struct SqliteContactRepo {
    pool: sqlx::SqlitePool,
}

impl SqliteContactRepo {
    /// Wrap an existing SQLite connection pool.
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ContactRepo for SqliteContactRepo {
    async fn upsert_contact(&self, row: &ContactRow) -> Result<bool, StorageError> {
        let muted: i64 = if row.muted { 1 } else { 0 };
        let blocked: i64 = if row.blocked { 1 } else { 0 };

        // ON CONFLICT … WHERE guards stale writes: the UPDATE only fires when
        // the stored updated_at is older than the incoming value.
        let result = sqlx::query(
            "INSERT INTO contacts
               (node_id, local_alias, claimed_name, profile_json, avatar_blake3,
                verified_identities_json, muted, blocked, tags_json, notes,
                created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
             ON CONFLICT(node_id) DO UPDATE SET
               local_alias              = excluded.local_alias,
               claimed_name             = excluded.claimed_name,
               profile_json             = excluded.profile_json,
               avatar_blake3            = excluded.avatar_blake3,
               verified_identities_json = excluded.verified_identities_json,
               muted                    = excluded.muted,
               blocked                  = excluded.blocked,
               tags_json                = excluded.tags_json,
               notes                    = excluded.notes,
               updated_at               = excluded.updated_at
             WHERE contacts.updated_at < excluded.updated_at",
        )
        .bind(&row.node_id)
        .bind(&row.local_alias)
        .bind(&row.claimed_name)
        .bind(&row.profile_json)
        .bind(&row.avatar_blake3)
        .bind(&row.verified_identities_json)
        .bind(muted)
        .bind(blocked)
        .bind(&row.tags_json)
        .bind(&row.notes)
        .bind(&row.created_at)
        .bind(&row.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_contact(&self, node_id: &str) -> Result<Option<ContactRow>, StorageError> {
        let row: Option<(
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
            String,
            i64,
            i64,
            String,
            Option<String>,
            String,
            String,
        )> = sqlx::query_as(
            "SELECT node_id, local_alias, claimed_name, profile_json, avatar_blake3,
                    verified_identities_json, muted, blocked, tags_json, notes,
                    created_at, updated_at
             FROM contacts WHERE node_id = ?1",
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(
                node_id,
                local_alias,
                claimed_name,
                profile_json,
                avatar_blake3,
                verified_identities_json,
                muted,
                blocked,
                tags_json,
                notes,
                created_at,
                updated_at,
            )| ContactRow {
                node_id,
                local_alias,
                claimed_name,
                profile_json,
                avatar_blake3,
                verified_identities_json,
                muted: muted != 0,
                blocked: blocked != 0,
                tags_json,
                notes,
                created_at,
                updated_at,
            },
        ))
    }

    async fn list_contacts(
        &self,
        blocked: Option<bool>,
        limit: u32,
    ) -> Result<Vec<ContactRow>, StorageError> {
        let lim = limit.min(1000) as i64;

        let rows: Vec<(
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
            String,
            i64,
            i64,
            String,
            Option<String>,
            String,
            String,
        )> = match blocked {
            Some(b) => {
                let b_int: i64 = if b { 1 } else { 0 };
                sqlx::query_as(
                    "SELECT node_id, local_alias, claimed_name, profile_json, avatar_blake3,
                            verified_identities_json, muted, blocked, tags_json, notes,
                            created_at, updated_at
                     FROM contacts WHERE blocked = ?1
                     ORDER BY updated_at DESC LIMIT ?2",
                )
                .bind(b_int)
                .bind(lim)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as(
                    "SELECT node_id, local_alias, claimed_name, profile_json, avatar_blake3,
                            verified_identities_json, muted, blocked, tags_json, notes,
                            created_at, updated_at
                     FROM contacts
                     ORDER BY updated_at DESC LIMIT ?1",
                )
                .bind(lim)
                .fetch_all(&self.pool)
                .await?
            }
        };

        Ok(rows
            .into_iter()
            .map(
                |(
                    node_id,
                    local_alias,
                    claimed_name,
                    profile_json,
                    avatar_blake3,
                    verified_identities_json,
                    muted,
                    blocked,
                    tags_json,
                    notes,
                    created_at,
                    updated_at,
                )| ContactRow {
                    node_id,
                    local_alias,
                    claimed_name,
                    profile_json,
                    avatar_blake3,
                    verified_identities_json,
                    muted: muted != 0,
                    blocked: blocked != 0,
                    tags_json,
                    notes,
                    created_at,
                    updated_at,
                },
            )
            .collect())
    }

    async fn delete_contact(&self, node_id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM contacts WHERE node_id = ?1")
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// ── PostgreSQL implementation ─────────────────────────────────────────────────

/// PostgreSQL-backed contact repository.
pub struct PostgresContactRepo {
    pool: sqlx::PgPool,
}

impl PostgresContactRepo {
    /// Wrap an existing PostgreSQL connection pool.
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ContactRepo for PostgresContactRepo {
    async fn upsert_contact(&self, row: &ContactRow) -> Result<bool, StorageError> {
        // Timestamps are stored as TEXT (ISO 8601) for cross-DB compatibility.
        // The WHERE guard ensures stale writes are rejected.
        let result = sqlx::query(
            "INSERT INTO contacts
               (node_id, local_alias, claimed_name, profile_json, avatar_blake3,
                verified_identities_json, muted, blocked, tags_json, notes,
                created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT(node_id) DO UPDATE SET
               local_alias              = EXCLUDED.local_alias,
               claimed_name             = EXCLUDED.claimed_name,
               profile_json             = EXCLUDED.profile_json,
               avatar_blake3            = EXCLUDED.avatar_blake3,
               verified_identities_json = EXCLUDED.verified_identities_json,
               muted                    = EXCLUDED.muted,
               blocked                  = EXCLUDED.blocked,
               tags_json                = EXCLUDED.tags_json,
               notes                    = EXCLUDED.notes,
               updated_at               = EXCLUDED.updated_at
             WHERE contacts.updated_at < EXCLUDED.updated_at",
        )
        .bind(&row.node_id)
        .bind(&row.local_alias)
        .bind(&row.claimed_name)
        .bind(&row.profile_json)
        .bind(&row.avatar_blake3)
        .bind(&row.verified_identities_json)
        .bind(row.muted)
        .bind(row.blocked)
        .bind(&row.tags_json)
        .bind(&row.notes)
        .bind(&row.created_at)
        .bind(&row.updated_at)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn get_contact(&self, node_id: &str) -> Result<Option<ContactRow>, StorageError> {
        let row: Option<(
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
            String,
            bool,
            bool,
            String,
            Option<String>,
            String,
            String,
        )> = sqlx::query_as(
            "SELECT node_id, local_alias, claimed_name, profile_json, avatar_blake3,
                    verified_identities_json, muted, blocked, tags_json, notes,
                    created_at, updated_at
             FROM contacts WHERE node_id = $1",
        )
        .bind(node_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(
                node_id,
                local_alias,
                claimed_name,
                profile_json,
                avatar_blake3,
                verified_identities_json,
                muted,
                blocked,
                tags_json,
                notes,
                created_at,
                updated_at,
            )| ContactRow {
                node_id,
                local_alias,
                claimed_name,
                profile_json,
                avatar_blake3,
                verified_identities_json,
                muted,
                blocked,
                tags_json,
                notes,
                created_at,
                updated_at,
            },
        ))
    }

    async fn list_contacts(
        &self,
        blocked: Option<bool>,
        limit: u32,
    ) -> Result<Vec<ContactRow>, StorageError> {
        let lim = limit.min(1000) as i64;

        let rows: Vec<(
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
            String,
            bool,
            bool,
            String,
            Option<String>,
            String,
            String,
        )> = match blocked {
            Some(b) => sqlx::query_as(
                "SELECT node_id, local_alias, claimed_name, profile_json, avatar_blake3,
                        verified_identities_json, muted, blocked, tags_json, notes,
                        created_at, updated_at
                 FROM contacts WHERE blocked = $1
                 ORDER BY updated_at DESC LIMIT $2",
            )
            .bind(b)
            .bind(lim)
            .fetch_all(&self.pool)
            .await?,

            None => sqlx::query_as(
                "SELECT node_id, local_alias, claimed_name, profile_json, avatar_blake3,
                        verified_identities_json, muted, blocked, tags_json, notes,
                        created_at, updated_at
                 FROM contacts
                 ORDER BY updated_at DESC LIMIT $1",
            )
            .bind(lim)
            .fetch_all(&self.pool)
            .await?,
        };

        Ok(rows
            .into_iter()
            .map(
                |(
                    node_id,
                    local_alias,
                    claimed_name,
                    profile_json,
                    avatar_blake3,
                    verified_identities_json,
                    muted,
                    blocked,
                    tags_json,
                    notes,
                    created_at,
                    updated_at,
                )| ContactRow {
                    node_id,
                    local_alias,
                    claimed_name,
                    profile_json,
                    avatar_blake3,
                    verified_identities_json,
                    muted,
                    blocked,
                    tags_json,
                    notes,
                    created_at,
                    updated_at,
                },
            )
            .collect())
    }

    async fn delete_contact(&self, node_id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM contacts WHERE node_id = $1")
            .bind(node_id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    async fn make_repo() -> SqliteContactRepo {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE contacts (
                node_id                  TEXT PRIMARY KEY,
                local_alias              TEXT,
                claimed_name             TEXT,
                profile_json             TEXT NOT NULL DEFAULT '{}',
                avatar_blake3            TEXT,
                verified_identities_json TEXT NOT NULL DEFAULT '[]',
                muted                    INTEGER NOT NULL DEFAULT 0,
                blocked                  INTEGER NOT NULL DEFAULT 0,
                tags_json                TEXT NOT NULL DEFAULT '[]',
                notes                    TEXT,
                created_at               TEXT NOT NULL,
                updated_at               TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        SqliteContactRepo::new(pool)
    }

    fn make_row(node_id: &str, updated_at: &str) -> ContactRow {
        ContactRow {
            node_id: node_id.into(),
            local_alias: Some("Alice".into()),
            claimed_name: Some("Alice Wonderland".into()),
            profile_json: "{}".into(),
            avatar_blake3: None,
            verified_identities_json: "[]".into(),
            muted: false,
            blocked: false,
            tags_json: "[]".into(),
            notes: None,
            created_at: "2026-01-01T00:00:00.000Z".into(),
            updated_at: updated_at.into(),
        }
    }

    #[tokio::test]
    async fn test_insert_and_get() {
        let repo = make_repo().await;
        let row = make_row("aabbcc", "2026-01-01T00:00:00.000Z");
        let inserted = repo.upsert_contact(&row).await.unwrap();
        assert!(inserted, "new row should be accepted");

        let got = repo.get_contact("aabbcc").await.unwrap().unwrap();
        assert_eq!(got.node_id, "aabbcc");
        assert_eq!(got.local_alias.as_deref(), Some("Alice"));
    }

    #[tokio::test]
    async fn test_upsert_newer_accepted() {
        let repo = make_repo().await;
        let old = make_row("aabbcc", "2026-01-01T00:00:00.000Z");
        repo.upsert_contact(&old).await.unwrap();

        let newer = ContactRow {
            local_alias: Some("Alicia".into()),
            updated_at: "2026-06-01T00:00:00.000Z".into(),
            ..old.clone()
        };
        let accepted = repo.upsert_contact(&newer).await.unwrap();
        assert!(accepted, "newer update should be accepted");

        let got = repo.get_contact("aabbcc").await.unwrap().unwrap();
        assert_eq!(got.local_alias.as_deref(), Some("Alicia"));
    }

    #[tokio::test]
    async fn test_upsert_older_rejected() {
        let repo = make_repo().await;
        let row = make_row("aabbcc", "2026-06-01T00:00:00.000Z");
        repo.upsert_contact(&row).await.unwrap();

        let stale = ContactRow {
            local_alias: Some("Stale".into()),
            updated_at: "2026-01-01T00:00:00.000Z".into(),
            ..row.clone()
        };
        let accepted = repo.upsert_contact(&stale).await.unwrap();
        assert!(!accepted, "stale write should be rejected");

        let got = repo.get_contact("aabbcc").await.unwrap().unwrap();
        assert_eq!(got.local_alias.as_deref(), Some("Alice"), "original data should be preserved");
    }

    #[tokio::test]
    async fn test_upsert_same_timestamp_rejected() {
        let repo = make_repo().await;
        let row = make_row("aabbcc", "2026-06-01T00:00:00.000Z");
        repo.upsert_contact(&row).await.unwrap();

        // Same timestamp = not strictly newer → rejected
        let same = ContactRow {
            local_alias: Some("SameTime".into()),
            ..row.clone()
        };
        let accepted = repo.upsert_contact(&same).await.unwrap();
        assert!(!accepted, "same-timestamp write should be rejected");
    }

    #[tokio::test]
    async fn test_list_contacts() {
        let repo = make_repo().await;
        repo.upsert_contact(&make_row("aa", "2026-01-01T00:00:00.000Z")).await.unwrap();
        repo.upsert_contact(&make_row("bb", "2026-02-01T00:00:00.000Z")).await.unwrap();

        let all = repo.list_contacts(None, 100).await.unwrap();
        assert_eq!(all.len(), 2);
        // newest first
        assert_eq!(all[0].node_id, "bb");
    }

    #[tokio::test]
    async fn test_list_contacts_filter_blocked() {
        let repo = make_repo().await;
        let unblocked = make_row("aa", "2026-01-01T00:00:00.000Z");
        let blocked = ContactRow { blocked: true, node_id: "bb".into(), ..make_row("bb", "2026-02-01T00:00:00.000Z") };
        repo.upsert_contact(&unblocked).await.unwrap();
        repo.upsert_contact(&blocked).await.unwrap();

        let unblocked_list = repo.list_contacts(Some(false), 100).await.unwrap();
        assert_eq!(unblocked_list.len(), 1);
        assert_eq!(unblocked_list[0].node_id, "aa");

        let blocked_list = repo.list_contacts(Some(true), 100).await.unwrap();
        assert_eq!(blocked_list.len(), 1);
        assert_eq!(blocked_list[0].node_id, "bb");
    }

    #[tokio::test]
    async fn test_delete_contact() {
        let repo = make_repo().await;
        let row = make_row("aabbcc", "2026-01-01T00:00:00.000Z");
        repo.upsert_contact(&row).await.unwrap();

        let deleted = repo.delete_contact("aabbcc").await.unwrap();
        assert!(deleted);

        let got = repo.get_contact("aabbcc").await.unwrap();
        assert!(got.is_none());

        // deleting again returns false
        let deleted2 = repo.delete_contact("aabbcc").await.unwrap();
        assert!(!deleted2);
    }

    #[tokio::test]
    async fn test_avatar_blake3_stored() {
        let repo = make_repo().await;
        let row = ContactRow {
            avatar_blake3: Some("deadbeef1234".into()),
            ..make_row("aabbcc", "2026-01-01T00:00:00.000Z")
        };
        repo.upsert_contact(&row).await.unwrap();
        let got = repo.get_contact("aabbcc").await.unwrap().unwrap();
        assert_eq!(got.avatar_blake3.as_deref(), Some("deadbeef1234"));
    }
}
