//! Durable outgoing operation metadata. Recovery bytes are opaque to storage and
//! encrypted by EncryptedStorage; they never contain plaintext message content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxOperation {
    pub operation_id: String,
    pub recipient: String,
    pub kind: i64,
    pub request_hash: String,
    pub state: String,
    pub payment_hash: Option<String>,
    pub admission_payment_hash: Option<String>,
    pub message_id: Option<String>,
    pub settled_msat: i64,
    pub readmission_msat: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_sent_at: Option<i64>,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub version: i64,
    pub recovery: Vec<u8>,
    /// Unresolved accounting references/intents, including conservative legacy backfill.
    pub accounting_pending: bool,
    /// Terminal recovery payload has been compacted to a permanent replay tombstone.
    pub recovery_compacted: bool,
}
impl OutboxOperation {
    pub fn prepared(
        operation_id: String,
        recipient: String,
        kind: u16,
        request_hash: String,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            operation_id,
            recipient,
            kind: i64::from(kind),
            request_hash,
            state: "prepared".into(),
            payment_hash: None,
            admission_payment_hash: None,
            message_id: None,
            settled_msat: 0,
            readmission_msat: 0,
            created_at: now,
            updated_at: now,
            last_sent_at: None,
            attempts: 0,
            last_error: None,
            version: 0,
            recovery: Vec::new(),
            accounting_pending: true,
            recovery_compacted: false,
        }
    }
}

macro_rules! outbox_from_row {
    ($row:ty) => {
        impl sqlx::FromRow<'_, $row> for OutboxOperation {
            fn from_row(row: &$row) -> Result<Self, sqlx::Error> {
                use sqlx::Row;
                Ok(Self {
                    operation_id: row.try_get("operation_id")?,
                    recipient: row.try_get("recipient")?,
                    kind: row.try_get("kind")?,
                    request_hash: row.try_get("request_hash")?,
                    state: row.try_get("state")?,
                    payment_hash: row.try_get("payment_hash")?,
                    admission_payment_hash: row.try_get("admission_payment_hash")?,
                    message_id: row.try_get("message_id")?,
                    settled_msat: row.try_get("settled_msat")?,
                    readmission_msat: row.try_get("readmission_msat")?,
                    created_at: row.try_get("created_at")?,
                    updated_at: row.try_get("updated_at")?,
                    last_sent_at: row.try_get("last_sent_at")?,
                    attempts: row.try_get("attempts")?,
                    last_error: row.try_get("last_error")?,
                    version: row.try_get("version")?,
                    recovery: row.try_get("recovery")?,
                    accounting_pending: row.try_get("accounting_pending")?,
                    recovery_compacted: row.try_get("recovery_compacted")?,
                })
            }
        }
    };
}
outbox_from_row!(sqlx::sqlite::SqliteRow);
outbox_from_row!(sqlx::postgres::PgRow);
