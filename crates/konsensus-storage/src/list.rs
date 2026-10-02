//! Per-query diagnostics; never derive request counts from global counter deltas.

/// Readable rows and the number omitted by this particular storage scan.
#[derive(Debug)]
pub struct StorageList<T> {
    pub items: Vec<T>,
    pub unreadable_count: u64,
    /// Set when the bounded scan stops before filling the readable page.
    pub continuation: Option<ListCursor<String>>,
    /// Lossless positions of readable rows, aligned with `items` for paged scans.
    pub readable_cursors: Vec<ListCursor<String>>,
}

impl<T> StorageList<T> {
    pub fn readable(items: Vec<T>) -> Self {
        Self {
            items,
            unreadable_count: 0,
            continuation: None,
            readable_cursors: Vec::new(),
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

/// Exclusive keyset position, ordered by timestamp DESC, id DESC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListCursor<T> {
    pub timestamp: T,
    pub id: String,
}

/// Existing message-list scopes, shared by raw keyset reads and readable scans.
pub enum MessageListQuery<'a> {
    Recipient(&'a konsensus_core::Recipient),
    Conversation { me: &'a str, peer: &'a str, is_room: bool },
    NodeKind { me: &'a str, kind: u16 },
}

/// Bound decryption work even for an entirely unreadable history.
pub const MAX_LIST_SCAN: u32 = 5_000;
pub(crate) fn scan_budget(limit: u32) -> u32 {
    limit.saturating_mul(10).min(MAX_LIST_SCAN)
}

/// Backend file metadata plus its lossless storage ordering key. PostgreSQL's
/// public metadata uses milliseconds; its keyset timestamp keeps microseconds.
pub struct FileListRow {
    pub metadata: crate::FileMetadata,
    pub cursor: ListCursor<String>,
}

impl From<crate::FileMetadata> for FileListRow {
    fn from(metadata: crate::FileMetadata) -> Self {
        let cursor = ListCursor { timestamp: metadata.created_at.clone(), id: metadata.id.clone() };
        Self { metadata, cursor }
    }
}
