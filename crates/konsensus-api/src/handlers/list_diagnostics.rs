//! Diagnostics for one storage scan, before API filtering or truncation.
use axum::http::HeaderValue;
use axum::response::{IntoResponseParts, ResponseParts};

#[derive(Default)]
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
        Ok(res)
    }
}
