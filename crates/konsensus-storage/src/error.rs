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
}
