//! Durable `open-channel` idempotency records (#331). One row per caller
//! `operation_id`; a retry with the same id never dispatches a second open.
//! `request` and `result` are opaque bytes, encrypted by EncryptedStorage.
//! The send-onchain API also uses this ledger with `send-onchain:<UUID>` keys.
//! For those isolated records, `opened` holds a returned txid and `uncertain`
//! holds ambiguous outcomes (or legacy refusals); only that API interprets their blobs.
//! Direct Lightning payments use `pay:<request_id>` and `keysend:<request_id>`
//! keys: `opened` holds a final receipt (settled or failed), `uncertain` holds
//! an in-flight snapshot or an ambiguous error until a later backend read
//! finalizes it through `finalize_channel_open_operation`.

/// Dispatch is in flight, or the process stopped before the outcome was recorded.
pub const CHANNEL_OPEN_PENDING: &str = "pending";
/// The backend returned an ambiguous error (timeout, connection, backend):
/// the channel may exist. Never re-dispatched under the same id.
pub const CHANNEL_OPEN_UNCERTAIN: &str = "uncertain";
/// The backend returned a channel; `result` holds the response.
pub const CHANNEL_OPEN_OPENED: &str = "opened";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpenOperation {
    pub operation_id: String,
    /// Digest of the canonical request parameters; a mismatch is a 409.
    pub request_hash: String,
    pub state: String,
    /// Canonical request parameters (JSON).
    pub request: Vec<u8>,
    /// The original response body (JSON) once opened.
    pub result: Option<Vec<u8>>,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl ChannelOpenOperation {
    pub fn pending(operation_id: String, request_hash: String, request: Vec<u8>) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            operation_id,
            request_hash,
            state: CHANNEL_OPEN_PENDING.into(),
            request,
            result: None,
            last_error: None,
            created_at: now,
            updated_at: now,
        }
    }
}

macro_rules! channel_open_from_row {
    ($row:ty) => {
        impl sqlx::FromRow<'_, $row> for ChannelOpenOperation {
            fn from_row(row: &$row) -> Result<Self, sqlx::Error> {
                use sqlx::Row;
                Ok(Self {
                    operation_id: row.try_get("operation_id")?,
                    request_hash: row.try_get("request_hash")?,
                    state: row.try_get("state")?,
                    request: row.try_get("request")?,
                    result: row.try_get("result")?,
                    last_error: row.try_get("last_error")?,
                    created_at: row.try_get("created_at")?,
                    updated_at: row.try_get("updated_at")?,
                })
            }
        }
    };
}
channel_open_from_row!(sqlx::sqlite::SqliteRow);
channel_open_from_row!(sqlx::postgres::PgRow);
