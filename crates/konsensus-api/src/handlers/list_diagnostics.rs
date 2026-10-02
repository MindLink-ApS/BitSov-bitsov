//! Diagnostics for one storage scan, before API filtering or truncation.
use serde::Serialize;

#[derive(Serialize)]
pub struct ListDiagnostics {
    pub unreadable_count: u64,
    /// Possible wrong storage key/passphrase or corruption, not a diagnosis.
    pub storage_key_mismatch: bool,
}

impl<T> From<&konsensus_storage::StorageList<T>> for ListDiagnostics {
    fn from(rows: &konsensus_storage::StorageList<T>) -> Self {
        Self {
            unreadable_count: rows.unreadable_count,
            storage_key_mismatch: rows.storage_key_mismatch(),
        }
    }
}
