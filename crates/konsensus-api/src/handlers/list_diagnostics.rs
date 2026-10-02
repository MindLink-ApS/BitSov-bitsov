//! Diagnostics for one storage scan, before API filtering or truncation.
use axum::http::HeaderValue;
use axum::response::{IntoResponseParts, ResponseParts};

#[derive(Default)]
pub struct ListDiagnostics {
    pub unreadable_count: u64,
    pub continuation: Option<konsensus_storage::ListCursor<String>>,
    pub next_before: Option<konsensus_storage::ListCursor<String>>,
    /// Possible wrong storage key/passphrase or corruption, not a diagnosis.
    pub storage_key_mismatch: bool,
}

impl<T> From<&konsensus_storage::StorageList<T>> for ListDiagnostics {
    fn from(rows: &konsensus_storage::StorageList<T>) -> Self {
        Self {
            unreadable_count: rows.unreadable_count,
            continuation: rows.continuation.clone(),
            next_before: rows.continuation.clone(),
            storage_key_mismatch: rows.storage_key_mismatch(),
        }
    }
}

// Response parts keep diagnostics out of the established JSON bodies.
impl IntoResponseParts for ListDiagnostics {
    type Error = std::convert::Infallible;

    fn into_response_parts(self, mut res: ResponseParts) -> Result<ResponseParts, Self::Error> {
        if self.unreadable_count > 0 {
            res.headers_mut().insert(
                "x-bitsov-unreadable-count",
                HeaderValue::from(self.unreadable_count),
            );
        }
        if self.storage_key_mismatch {
            res.headers_mut().insert(
                "x-bitsov-storage-key-mismatch",
                HeaderValue::from_static("true"),
            );
        }
        if let Some(cursor) = self.continuation {
            if let (Ok(timestamp), Ok(id)) = (HeaderValue::from_str(&cursor.timestamp), HeaderValue::from_str(&cursor.id)) {
                res.headers_mut().insert("x-bitsov-oldest-scanned-timestamp", timestamp);
                res.headers_mut().insert("x-bitsov-oldest-scanned-id", id);
            }
        }
        if let Some(cursor) = self.next_before {
            if let (Ok(timestamp), Ok(id)) = (HeaderValue::from_str(&cursor.timestamp), HeaderValue::from_str(&cursor.id)) {
                res.headers_mut().insert("x-bitsov-next-before", timestamp);
                res.headers_mut().insert("x-bitsov-next-before-id", id);
            }
        }
        Ok(res)
    }
}

/// Timestamp-only callers retain the existing exclusive `before` semantics.
/// A paired ID resumes within a timestamp without losing tied rows.
pub fn message_cursor(before: Option<u64>, before_id: Option<&str>) -> Result<Option<konsensus_storage::ListCursor<u64>>, crate::error::ApiError> {
    match (before, before_id) {
        (Some(timestamp), Some(id)) => {
            if id.len() != 64 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(crate::error::ApiError::BadRequest("invalid before_id: expected a message ID".into()));
            }
            Ok(Some(konsensus_storage::ListCursor { timestamp, id: id.to_ascii_lowercase() }))
        }
        (None, Some(_)) => Err(crate::error::ApiError::BadRequest("before_id requires before".into())),
        _ => Ok(None),
    }
}
