//! Per-query diagnostics; never derive request counts from global counter deltas.

/// Readable rows and the number omitted by this particular storage scan.
#[derive(Debug)]
pub struct StorageList<T> {
    pub items: Vec<T>,
    pub unreadable_count: u64,
}

impl<T> StorageList<T> {
    pub fn readable(items: Vec<T>) -> Self {
        Self {
            items,
            unreadable_count: 0,
        }
    }

    /// A possible wrong key, not a diagnosis. Empty scans are healthy.
    pub fn storage_key_mismatch(&self) -> bool {
        self.unreadable_count > 0 && self.unreadable_count >= self.items.len() as u64
    }
}

/// Local observations since wrapper creation (normally process startup).
#[derive(Clone, Copy, Debug, Default)]
pub struct StorageReadHealth {
    /// Failed row reads, including repeat scans; not a distinct-row count.
    pub storage_unreadable_rows: u64,
    /// Latched until restart so a later healthy/empty list cannot hide a warning.
    pub storage_key_mismatch: bool,
}
