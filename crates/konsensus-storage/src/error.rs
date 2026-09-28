//! Storage error types.

use thiserror::Error;

/// Errors from storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Database query or connection error.
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Migration error.
    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    /// Record not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Duplicate record (conflict).
    #[error("duplicate: {0}")]
    Duplicate(String),

    /// Record already exists (conflict).
    #[error("already exists: {0}")]
    AlreadyExists(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Encryption / decryption error.
    #[error("encryption error: {0}")]
    Encryption(String),

    /// Core type conversion error.
    #[error("type conversion: {0}")]
    Conversion(String),

    /// Operation is not supported by this storage backend.
    #[error("unsupported operation: {0}")]
    Unsupported(String),

    /// `KONSENSUS_SQLITE_MIGRATIONS_DIR` does not contain every migration this binary embeds.
    #[error(
        "KONSENSUS_SQLITE_MIGRATIONS_DIR={dir} is missing migration version(s) {missing:?} \
         required by this binary (embedded through version {max_embedded}). Unset the variable \
         to apply embedded migrations, or point it at a directory that is a superset of the \
         embedded set."
    )]
    IncompleteMigrationsDir {
        /// Directory named in the environment variable.
        dir: String,
        /// Embedded versions with no matching file in the directory.
        missing: Vec<i64>,
        /// Highest embedded migration version.
        max_embedded: i64,
    },
}
