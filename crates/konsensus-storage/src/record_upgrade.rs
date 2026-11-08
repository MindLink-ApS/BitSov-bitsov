//! Bounded, resumable upgrades of existing encrypted fields without schema changes.

use crate::{Storage, StorageError};
use konsensus_crypto::record_cipher::{
    LegacyReadPolicy, RecordCipher, CACHE_KEY_CONTEXT, SESSION_KEY_CONTEXT,
};

#[derive(Clone, Copy, Debug)]
pub enum RecordTable {
    Messages,
    Peers,
    Rooms,
    Files,
    Outbox,
    Channel,
    Sessions,
}
#[derive(Clone, Copy)]
pub(crate) enum Encoding {
    Bytes,
    Hex,
    JsonHex,
}
#[derive(Clone, Copy)]
pub(crate) struct Field {
    pub name: &'static str,
    pub encoding: Encoding,
}
impl RecordTable {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Messages => "messages",
            Self::Peers => "peers",
            Self::Rooms => "rooms",
            Self::Files => "files",
            Self::Outbox => "outbox_operations",
            Self::Channel => "channel_open_operations",
            Self::Sessions => "sessions",
        }
    }
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Peers => "node_id",
            Self::Sessions => "peer_id",
            Self::Outbox | Self::Channel => "operation_id",
            _ => "id",
        }
    }
    pub(crate) fn fields(self) -> &'static [Field] {
        use Encoding::*;
        match self {
            Self::Messages => &[
                Field {
                    name: "ciphertext",
                    encoding: Bytes,
                },
                Field {
                    name: "plaintext_enc",
                    encoding: Bytes,
                },
            ],
            Self::Peers => &[
                Field {
                    name: "address",
                    encoding: Hex,
                },
                Field {
                    name: "display_name",
                    encoding: Hex,
                },
                Field {
                    name: "metadata_json",
                    encoding: JsonHex,
                },
            ],
            Self::Rooms => &[
                Field {
                    name: "name",
                    encoding: Hex,
                },
                Field {
                    name: "metadata_json",
                    encoding: JsonHex,
                },
            ],
            Self::Files => &[
                Field {
                    name: "filename",
                    encoding: Hex,
                },
                Field {
                    name: "mime_type",
                    encoding: Hex,
                },
                Field {
                    name: "data",
                    encoding: Bytes,
                },
            ],
            Self::Outbox => &[Field {
                name: "recovery",
                encoding: Bytes,
            }],
            Self::Channel => &[
                Field {
                    name: "request",
                    encoding: Bytes,
                },
                Field {
                    name: "result",
                    encoding: Bytes,
                },
            ],
            Self::Sessions => &[Field {
                name: "state_blob",
                encoding: Bytes,
            }],
        }
    }
}

/// Raw values used only by the record-format maintenance pass.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordRow {
    pub id: String,
    /// Opaque pagination cursor, retaining even malformed SQLite key bytes/type.
    pub scan_after: String,
    pub values: Vec<Option<Vec<u8>>>,
    /// Field decoding failures retain raw snapshot bytes for a fenced partial update.
    pub unreadable_fields: Vec<usize>,
}

// The SQL identifiers come exclusively from RecordTable's static field definitions.
macro_rules! backend {
    ($module:ident, $db:ty, $pool:ty, $row:ty, $text_start:literal, $text_end:literal,
     $compare_start:literal, $compare_end:literal, $old_text_start:literal, $old_text_end:literal) => {
        pub(crate) mod $module {
            use super::*;
            use sqlx::{QueryBuilder, Row, TypeInfo, ValueRef};
            pub async fn rows(
                pool: &$pool,
                table: RecordTable,
                after: Option<&str>,
                limit: u32,
            ) -> Result<Vec<RecordRow>, StorageError> {
                let mut query = QueryBuilder::<$db>::new(format!("SELECT {}", table.key()));
                for field in table.fields() {
                    query.push(", ").push(field.name);
                }
                query.push(" FROM ").push(table.name());
                if let Some(after) = after {
                    let (kind, bytes) = after.split_once(':').ok_or_else(|| {
                        StorageError::Conversion("invalid record scan cursor".into())
                    })?;
                    let bytes = hex::decode(bytes).map_err(|_| {
                        StorageError::Conversion("invalid record scan cursor".into())
                    })?;
                    query.push(" WHERE ").push(table.key());
                    match kind {
                        "n" => {
                            query.push(" IS NOT NULL");
                        }
                        "b" => {
                            query.push(" > ").push_bind(bytes);
                        }
                        "t" => {
                            query
                                .push(" > ")
                                .push($text_start)
                                .push_bind(bytes)
                                .push($text_end);
                        }
                        _ => {
                            return Err(StorageError::Conversion(
                                "invalid record scan cursor".into(),
                            ))
                        }
                    }
                }
                query
                    .push(" ORDER BY ")
                    .push(table.key())
                    .push(" LIMIT ")
                    .push_bind(i64::from(limit));
                let rows = query.build().fetch_all(pool).await?;
                rows.iter().map(|row| decode_row(row, table)).collect()
            }
            fn decode_row(row: &$row, table: RecordTable) -> Result<RecordRow, StorageError> {
                // Capture type before asking SQLite to expose the raw bytes.
                // Comparisons keep the primary-key column bare, preserving its index.
                let key_type = row.try_get_raw(0)?.type_info().name().to_owned();
                let id = row.try_get::<String, _>(0);
                let key = match &id {
                    Ok(id) => Some(id.as_bytes().to_vec()),
                    // Preserve undecodable SQLite keys for pagination only.
                    Err(_) => row.try_get_unchecked::<Option<Vec<u8>>, _>(0)?,
                };
                let scan_after = match key {
                    None => "n:".to_owned(),
                    Some(bytes) => format!(
                        "{}:{}",
                        if key_type == "BLOB" { "b" } else { "t" },
                        hex::encode(bytes)
                    ),
                };
                let mut unreadable_fields = Vec::new();
                let values = table
                    .fields()
                    .iter()
                    .enumerate()
                    .map(|(i, field)| {
                        let value = match field.encoding {
                            Encoding::Bytes => row.try_get::<Option<Vec<u8>>, _>(i + 1),
                            _ => row
                                .try_get::<Option<String>, _>(i + 1)
                                .map(|value| value.map(String::into_bytes)),
                        };
                        match value {
                            Ok(value) => Ok(value),
                            Err(sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_)) => {
                                unreadable_fields.push(i);
                                row.try_get_unchecked::<Option<Vec<u8>>, _>(i + 1)
                                    .map_err(StorageError::Database)
                            }
                            Err(error) => Err(error.into()),
                        }
                    })
                    .collect::<Result<Vec<_>, StorageError>>()?;
                let id = match id {
                    Ok(id) => id,
                    Err(sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_)) => String::new(),
                    Err(error) => return Err(error.into()),
                };
                Ok(RecordRow {
                    id,
                    scan_after,
                    values,
                    unreadable_fields,
                })
            }

            pub async fn row(
                pool: &$pool,
                table: RecordTable,
                id: &str,
            ) -> Result<Option<RecordRow>, StorageError> {
                let mut query = QueryBuilder::<$db>::new(format!("SELECT {}", table.key()));
                for field in table.fields() {
                    query.push(", ").push(field.name);
                }
                query
                    .push(" FROM ")
                    .push(table.name())
                    .push(" WHERE ")
                    .push(table.key())
                    .push(" = ")
                    .push_bind(id);
                query
                    .build()
                    .fetch_optional(pool)
                    .await?
                    .map(|row| decode_row(&row, table))
                    .transpose()
            }

            pub async fn replace(
                pool: &$pool,
                table: RecordTable,
                old: &RecordRow,
                new: &RecordRow,
            ) -> Result<bool, StorageError> {
                if old.id != new.id
                    || old.values.len() != table.fields().len()
                    || new.values.len() != old.values.len()
                {
                    return Err(StorageError::Conversion(
                        "invalid record upgrade shape".into(),
                    ));
                }
                let mut query = QueryBuilder::<$db>::new(format!("UPDATE {} SET ", table.name()));
                let mut assigned = false;
                for (i, field) in table.fields().iter().enumerate() {
                    if old.values[i] == new.values[i] {
                        continue;
                    }
                    if assigned {
                        query.push(", ");
                    }
                    assigned = true;
                    query.push(field.name).push(" = ");
                    match field.encoding {
                        Encoding::Bytes => {
                            query.push_bind(new.values[i].clone());
                        }
                        _ => {
                            query.push_bind(
                                new.values[i]
                                    .as_deref()
                                    .map(std::str::from_utf8)
                                    .transpose()
                                    .map_err(|_| {
                                        StorageError::Conversion("invalid record text".into())
                                    })?,
                            );
                        }
                    }
                }
                if !assigned {
                    query.push(table.key()).push(" = ").push(table.key());
                }
                query
                    .push(" WHERE ")
                    .push(table.key())
                    .push(" = ")
                    .push_bind(&old.id);
                for (i, field) in table.fields().iter().enumerate() {
                    query
                        .push(" AND ")
                        .push($compare_start)
                        .push(field.name)
                        .push($compare_end);
                    if let Some(value) = &old.values[i] {
                        query.push(" = ");
                        match field.encoding {
                            Encoding::Bytes => {
                                query.push_bind(value);
                            }
                            _ => {
                                query
                                    .push($old_text_start)
                                    .push_bind(value)
                                    .push($old_text_end);
                            }
                        }
                    } else {
                        query.push(" IS NULL");
                    }
                }
                Ok(query.build().execute(pool).await?.rows_affected() == 1)
            }
        }
    };
}
// SQLite comparisons use raw bytes, so TEXT/BLOB storage-class changes do not
// invent a conflict. PostgreSQL keeps strict bytea/text comparisons.
backend!(
    sqlite,
    sqlx::Sqlite,
    sqlx::SqlitePool,
    sqlx::sqlite::SqliteRow,
    "CAST(",
    " AS TEXT)",
    "CAST(",
    " AS BLOB)",
    "",
    ""
);
backend!(
    postgres,
    sqlx::Postgres,
    sqlx::PgPool,
    sqlx::postgres::PgRow,
    "convert_from(",
    ", 'UTF8')",
    "",
    "",
    "convert_from(",
    ", 'UTF8')"
);

struct ConvertedRow {
    row: RecordRow,
    unreadable: bool,
    dropped_cache: bool,
}

impl ConvertedRow {
    fn unreadable(row: &RecordRow) -> Self {
        Self {
            row: row.clone(),
            unreadable: true,
            dropped_cache: false,
        }
    }
}

pub struct RecordUpgrade {
    storage: RecordCipher,
    cache: RecordCipher,
    sessions: RecordCipher,
    policy: LegacyReadPolicy,
    encrypted_storage: bool,
}

impl RecordUpgrade {
    fn rejection_code(code: &str, sqlite: bool) -> bool {
        if sqlite {
            // SQLITE_TOOBIG / SQLITE_CONSTRAINT, including extended trigger codes.
            code.parse::<u32>()
                .is_ok_and(|code| matches!(code & 0xff, 18 | 19))
        } else {
            // Row data/constraint errors and explicit rejecting triggers.
            code.starts_with("22") || code.starts_with("23") || matches!(code, "P0001" | "54000")
        }
    }

    fn rejected_write(error: &StorageError) -> bool {
        let StorageError::Database(sqlx::Error::Database(error)) = error else {
            return false;
        };
        let Some(code) = error.code() else {
            return false;
        };
        if error
            .try_downcast_ref::<sqlx::sqlite::SqliteError>()
            .is_some()
        {
            Self::rejection_code(&code, true)
        } else if error
            .try_downcast_ref::<sqlx::postgres::PgDatabaseError>()
            .is_some()
        {
            Self::rejection_code(&code, false)
        } else {
            false
        }
    }

    pub fn retry_delay(attempt: u32) -> std::time::Duration {
        std::time::Duration::from_secs(60u64.saturating_mul(2u64.saturating_pow(attempt)).min(3600))
    }

    pub fn new(key: &[u8; 32], policy: LegacyReadPolicy, encrypted_storage: bool) -> Self {
        Self {
            storage: RecordCipher::new(key, policy.clone()),
            cache: RecordCipher::derived(key, CACHE_KEY_CONTEXT, policy.for_crypto()),
            sessions: RecordCipher::derived(key, SESSION_KEY_CONTEXT, policy.for_crypto()),
            policy,
            encrypted_storage,
        }
    }

    fn convert(
        &self,
        table: RecordTable,
        row: &RecordRow,
        plaintext_message: bool,
    ) -> Result<ConvertedRow, StorageError> {
        let decoded: Vec<Result<Option<Vec<u8>>, StorageError>> = table
            .fields()
            .iter()
            .zip(&row.values)
            .enumerate()
            .map(|(i, (field, value))| {
                if row.unreadable_fields.contains(&i) {
                    return Err(StorageError::Conversion("unreadable stored field".into()));
                }
                let Some(value) = value else {
                    return Ok(None);
                };
                match field.encoding {
                    Encoding::Bytes => Ok(Some(value.clone())),
                    Encoding::Hex => Ok(hex::decode(value)
                        .ok()
                        .filter(|bytes| bytes.len() >= 28 || RecordCipher::is_v2(bytes))),
                    Encoding::JsonHex => {
                        let json: serde_json::Value = serde_json::from_slice(value)
                            .map_err(|_| StorageError::Conversion("invalid stored JSON".into()))?;
                        json.as_str()
                            .map(|value| {
                                hex::decode(value).map_err(|_| {
                                    StorageError::Encryption("invalid encrypted JSON".into())
                                })
                            })
                            .transpose()
                    }
                }
            })
            .collect();
        let plaintext_peer = matches!(table, RecordTable::Peers)
            && decoded
                .iter()
                .zip(&row.values)
                .any(|(decoded, value)| value.is_some() && matches!(decoded, Ok(None)));
        let plaintext_file = matches!(table, RecordTable::Files)
            && decoded[..2].iter().any(|value| matches!(value, Ok(None)));
        let mut converted = ConvertedRow {
            row: row.clone(),
            unreadable: false,
            dropped_cache: false,
        };
        for (i, field) in table.fields().iter().enumerate() {
            let Some(value) = &row.values[i] else {
                continue;
            };
            let cache = matches!(table, RecordTable::Messages) && field.name == "plaintext_enc";
            let sessions = matches!(table, RecordTable::Sessions);
            if !self.encrypted_storage && !cache && !sessions {
                continue;
            }
            if matches!(table, RecordTable::Outbox) && value.is_empty() {
                continue;
            }
            let cipher = if cache {
                &self.cache
            } else if sessions {
                &self.sessions
            } else {
                &self.storage
            };
            let plain = (|| -> Result<Vec<u8>, StorageError> {
                let blob = decoded[i]
                    .as_ref()
                    .map_err(|_| StorageError::Conversion("unreadable stored field".into()))?;
                let mut plain = match blob {
                    Some(blob) => match cipher.decrypt(table.name(), field.name, &row.id, blob) {
                        Ok(plain) => plain,
                        Err(_)
                            if ((plaintext_file && field.name == "data")
                                || (plaintext_message && field.name == "ciphertext"))
                                && !RecordCipher::is_v2(blob) =>
                        {
                            value.clone()
                        }
                        Err(error) => return Err(StorageError::Encryption(error)),
                    },
                    None if !cache && !sessions => value.clone(),
                    None => {
                        return Err(StorageError::Encryption(
                            "encrypted record is required".into(),
                        ))
                    }
                };
                if plaintext_peer && field.name == "metadata_json" {
                    let mut metadata: serde_json::Value = serde_json::from_slice(&plain)
                        .map_err(|_| StorageError::Conversion("invalid peer metadata".into()))?;
                    let object = metadata.as_object_mut().ok_or_else(|| {
                        StorageError::Conversion("peer metadata must be an object".into())
                    })?;
                    object.insert("storage_legacy_untrusted".into(), true.into());
                    plain = serde_json::to_vec(&metadata)
                        .map_err(|error| StorageError::Serialization(error.to_string()))?;
                }
                Ok(plain)
            })();
            let plain = match plain {
                Ok(plain) => plain,
                Err(_) => {
                    converted.unreadable = true;
                    if cache {
                        // Cache is optional and regenerable; never abandon its message.
                        converted.row.values[i] = None;
                        converted.row.unreadable_fields.retain(|index| *index != i);
                        converted.dropped_cache = true;
                    }
                    continue;
                }
            };
            if decoded[i]
                .as_ref()
                .ok()
                .and_then(Option::as_deref)
                .is_some_and(RecordCipher::is_v2)
                && !(plaintext_peer && field.name == "metadata_json")
            {
                continue;
            }
            let blob = cipher
                .encrypt(table.name(), field.name, &row.id, &plain)
                .map_err(StorageError::Encryption)?;
            converted.row.values[i] = Some(match field.encoding {
                Encoding::Bytes => blob,
                Encoding::Hex => hex::encode(blob).into_bytes(),
                Encoding::JsonHex => serde_json::to_vec(&hex::encode(blob))
                    .map_err(|error| StorageError::Serialization(error.to_string()))?,
            });
        }
        Ok(converted)
    }

    // None means the envelope changed after the field snapshot: retry, not corruption.
    async fn prepare_row(
        &self,
        store: &dyn Storage,
        table: RecordTable,
        row: &RecordRow,
    ) -> Result<Option<ConvertedRow>, StorageError> {
        if row.id.is_empty() || row.values.len() != table.fields().len() {
            return Ok(Some(ConvertedRow::unreadable(row)));
        }
        let mut plaintext_message = false;
        let mut validated = row.clone();
        if self.encrypted_storage && matches!(table, RecordTable::Messages) {
            let id = match konsensus_core::MessageId::from_hex(&row.id) {
                Ok(id) if id.to_hex() == row.id => id,
                _ => return Ok(Some(ConvertedRow::unreadable(row))),
            };
            let raw = match store.record_upgrade_envelope(&id).await {
                Ok(Some(raw)) => Some(raw),
                Ok(None) => return Ok(None),
                Err(
                    StorageError::Conversion(_)
                    | StorageError::Serialization(_)
                    | StorageError::Encryption(_)
                    | StorageError::Database(
                        sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_),
                    ),
                ) => None,
                Err(error) => return Err(error),
            };
            let valid_payload = if let Some(raw) = raw {
                if row.values[0].as_deref() != Some(raw.ciphertext.as_slice()) {
                    return Ok(None);
                }
                let ciphertext =
                    match self
                        .storage
                        .decrypt("messages", "ciphertext", &row.id, &raw.ciphertext)
                    {
                        Ok(bytes) => Some(bytes),
                        Err(_) if RecordCipher::is_v2(&raw.ciphertext) => None,
                        Err(_) => {
                            plaintext_message = true;
                            Some(raw.ciphertext.clone())
                        }
                    };
                ciphertext.is_some_and(|ciphertext| {
                    konsensus_core::UkmEnvelopeBuilder::new(
                        raw.kind,
                        raw.sender,
                        raw.recipient,
                        ciphertext,
                        raw.payment_proof.clone(),
                    )
                    .timestamp(raw.timestamp)
                    .nonce(raw.nonce)
                    .signature(raw.signature)
                    .references(raw.references.clone())
                    .build()
                    .id == id
                })
            } else {
                false
            };
            if !valid_payload && !validated.unreadable_fields.contains(&0) {
                validated.unreadable_fields.push(0);
            }
        }
        self.convert(table, &validated, plaintext_message).map(Some)
    }

    /// Convert usable rows and count unreadable rows without enabling v1 forever.
    /// Readable fields are converted even when a sibling is bad. Invalid cache
    /// fields are cleared; other unreadable bytes remain for recovery.
    /// Database failures and changed snapshots defer completion.
    pub async fn run(&self, store: &dyn Storage) -> Result<u64, StorageError> {
        if !self.policy.allows_v1() {
            return Ok(0);
        }
        let mut changed = 0;
        let mut conflicts = 0;
        for table in [
            RecordTable::Peers,
            RecordTable::Rooms,
            RecordTable::Files,
            RecordTable::Messages,
            RecordTable::Outbox,
            RecordTable::Channel,
            RecordTable::Sessions,
        ] {
            if !self.encrypted_storage
                && !matches!(table, RecordTable::Messages | RecordTable::Sessions)
            {
                continue;
            }
            let batch_size = if table
                .fields()
                .iter()
                .any(|field| matches!(field.encoding, Encoding::Bytes))
            {
                1
            } else {
                128
            };
            let (mut scanned, mut upgraded, mut unreadable, mut unwritable, mut discarded_cache) =
                (0u64, 0u64, 0u64, 0u64, 0u64);
            let mut cursor = None;
            loop {
                let rows = store
                    .record_upgrade_rows(table, cursor.as_deref(), batch_size)
                    .await
                    .inspect_err(|_| {
                        tracing::warn!(
                            table = table.name(),
                            scanned,
                            upgraded,
                            unreadable,
                            "storage record format scan deferred"
                        );
                    })?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    scanned += 1;
                    cursor = Some(row.scan_after.clone());
                    let converted = match self.prepare_row(store, table, &row).await? {
                        Some(converted) => converted,
                        None => {
                            conflicts += 1;
                            continue;
                        }
                    };
                    unreadable += u64::from(converted.unreadable);
                    if row.values != converted.row.values {
                        let swapped = match store
                            .record_upgrade_replace(table, &row, &converted.row)
                            .await
                        {
                            Ok(swapped) => swapped,
                            Err(error) if Self::rejected_write(&error) => false,
                            Err(error) => return Err(error),
                        };
                        if !swapped {
                            let current = store.record_upgrade_row(table, &row.id).await?;
                            match current {
                                None => continue, // Deleted rows cannot block the cutoff.
                                Some(current) if current == row => {
                                    // One failed write plus an unchanged reread is the bound.
                                    // This includes rejecting triggers; retrying cannot help.
                                    unwritable += 1;
                                    if !converted.unreadable {
                                        unreadable += 1;
                                    }
                                }
                                Some(_) => {
                                    conflicts += 1;
                                }
                            }
                            continue;
                        }
                        changed += 1;
                        upgraded += 1;
                        discarded_cache += u64::from(converted.dropped_cache);
                    }
                }
                tokio::task::yield_now().await;
            }
            if unreadable != 0 {
                // Only static table names and aggregate counts; never row IDs or errors.
                tracing::warn!(
                    table = table.name(),
                    scanned,
                    upgraded,
                    unreadable,
                    unwritable,
                    discarded_cache,
                    "storage record format unreadable fields or blocked writes reported"
                );
            } else {
                tracing::info!(
                    table = table.name(),
                    scanned,
                    upgraded,
                    unreadable,
                    unwritable,
                    discarded_cache,
                    "storage record format table scanned"
                );
            }
        }
        if conflicts != 0 {
            tracing::warn!(
                conflicts,
                "storage record format concurrent writes require another pass"
            );
            return Err(StorageError::Conversion(
                "record changed during format upgrade; retry required".into(),
            ));
        }
        self.policy.complete().map_err(|_| {
            StorageError::Conversion("could not persist record format completion".into())
        })?;
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptedStorage, Peer, SqliteStorage};
    use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
    use konsensus_core::NodeId;

    fn legacy(key: &[u8; 32], bytes: &[u8]) -> Vec<u8> {
        let nonce: [u8; 12] = rand::random();
        let mut blob = nonce.to_vec();
        blob.extend(
            Aes256Gcm::new_from_slice(key)
                .unwrap()
                .encrypt((&nonce).into(), bytes)
                .unwrap(),
        );
        blob
    }

    fn v1_peer(id: u8) -> Peer {
        let mut peer = Peer::new(NodeId::from_bytes([id; 32]));
        peer.metadata = hex::encode(legacy(&[7; 32], br#"{"label":"legacy"}"#)).into();
        peer
    }

    #[test]
    fn upgrade_binds_both_operation_fields_and_file_fields() {
        let dir = tempfile::tempdir().unwrap();
        let upgrade = RecordUpgrade::new(&[7; 32], LegacyReadPolicy::in_data_dir(dir.path()), true);
        let cases = [
            (
                RecordTable::Channel,
                "channel_open_operations",
                vec!["request", "result"],
                vec![
                    Some(legacy(&[7; 32], b"request")),
                    Some(legacy(&[7; 32], b"result")),
                ],
            ),
            (
                RecordTable::Outbox,
                "outbox_operations",
                vec!["recovery"],
                vec![Some(legacy(&[7; 32], b"recovery"))],
            ),
            (
                RecordTable::Files,
                "files",
                vec!["filename", "mime_type", "data"],
                vec![
                    Some(hex::encode(legacy(&[7; 32], b"filename")).into_bytes()),
                    Some(hex::encode(legacy(&[7; 32], b"mime_type")).into_bytes()),
                    Some(legacy(&[7; 32], b"data")),
                ],
            ),
        ];
        for (table, table_name, columns, values) in cases {
            let old = RecordRow {
                id: "record-a".into(),
                scan_after: String::new(),
                unreadable_fields: Vec::new(),
                values,
            };
            let upgraded = upgrade.convert(table, &old, false).unwrap().row;
            assert_ne!(old, upgraded);
            assert_eq!(
                upgrade.convert(table, &upgraded, false).unwrap().row,
                upgraded
            );
            for (i, column) in columns.iter().enumerate() {
                let encoded = upgraded.values[i].as_ref().unwrap();
                let bytes = if table_name == "files" && i < 2 {
                    hex::decode(encoded).unwrap()
                } else {
                    encoded.clone()
                };
                assert_eq!(
                    upgrade
                        .storage
                        .decrypt(table_name, column, "record-a", &bytes)
                        .unwrap(),
                    column.as_bytes()
                );
                assert!(upgrade
                    .storage
                    .decrypt(table_name, column, "record-b", &bytes)
                    .is_err());
                assert!(upgrade
                    .storage
                    .decrypt(table_name, "different", "record-a", &bytes)
                    .is_err());
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires BITSOV_TEST_POSTGRES_URL pointing to a disposable PostgreSQL server"]
    async fn postgres_record_upgrade_roundtrip_and_cutoff() {
        let url = std::env::var("BITSOV_TEST_POSTGRES_URL").unwrap();
        let admin = sqlx::PgPool::connect(&url).await.unwrap();
        let name = format!("record_binding_{}", uuid::Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        let db_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
        let raw = crate::PostgresStorage::connect(&db_url).await.unwrap();
        let peer = v1_peer(1);
        raw.upsert_peer(&peer).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(raw, &[7; 32], policy.clone());
        assert!(store.get_peer(&peer.node_id).await.unwrap().is_some());
        let upgrade = RecordUpgrade::new(&[7; 32], policy.clone(), true);
        assert_eq!(upgrade.run(&store).await.unwrap(), 1);
        assert_eq!(upgrade.run(&store).await.unwrap(), 0);
        assert_eq!(
            store
                .get_peer(&peer.node_id)
                .await
                .unwrap()
                .unwrap()
                .metadata["label"],
            "legacy"
        );
        let old = store
            .record_upgrade_rows(RecordTable::Peers, None, 1)
            .await
            .unwrap()
            .remove(0);
        let mut restored_v1 = old.clone();
        restored_v1.values[2] = Some(serde_json::to_vec(&peer.metadata).unwrap());
        assert!(store
            .record_upgrade_replace(RecordTable::Peers, &old, &restored_v1)
            .await
            .unwrap());
        assert!(store.get_peer(&peer.node_id).await.is_err());
        store.inner().pool().close().await;
        sqlx::query(&format!("DROP DATABASE {name}"))
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
    }

    // A corrupt record must not keep every other table's unbound reads enabled.
    #[derive(Clone, Default)]
    struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for LogCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    async fn bad_row_does_not_block_cutoff(table: RecordTable) {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let good = v1_peer(1);
        store.inner().upsert_peer(&good).await.unwrap();
        let peer = NodeId::from_bytes([2; 32]);
        match table {
            RecordTable::Peers => {
                store.inner().upsert_peer(&v1_peer(2)).await.unwrap();
            }
            RecordTable::Rooms => {
                let mut room = crate::Room::new(hex::encode(legacy(&[7; 32], b"room")), peer);
                room.metadata = hex::encode(legacy(&[7; 32], b"{}")).into();
                store.inner().create_room(&room).await.unwrap();
            }
            RecordTable::Files => {
                let file = crate::FileRecord {
                    id: "bad-file".into(),
                    filename: hex::encode(legacy(&[7; 32], b"file")),
                    mime_type: hex::encode(legacy(&[7; 32], b"text/plain")),
                    data: legacy(&[7; 32], b"data"),
                    size_bytes: 4,
                    blake3_hash: "hash".into(),
                    sender: peer.to_hex(),
                    message_id: None,
                    created_at: String::new(),
                };
                store.inner().store_file(&file).await.unwrap();
            }
            RecordTable::Messages => {
                let envelope = konsensus_core::UkmEnvelopeBuilder::new(
                    100,
                    peer,
                    konsensus_core::Recipient::Node(peer),
                    b"message".to_vec(),
                    konsensus_core::PaymentProof::new([0; 32], [0; 32], 1),
                )
                .build();
                store.inner().store_message(&envelope).await.unwrap();
            }
            RecordTable::Outbox => {
                let mut op = crate::OutboxOperation::prepared(
                    "bad-outbox".into(),
                    peer.to_hex(),
                    100,
                    "hash".into(),
                );
                op.recovery = legacy(&[7; 32], b"recovery");
                store.inner().insert_outbox_operation(&op).await.unwrap();
            }
            RecordTable::Channel => {
                let op = crate::ChannelOpenOperation::pending(
                    "bad-channel".into(),
                    "hash".into(),
                    legacy(&[7; 32], b"request"),
                );
                store
                    .inner()
                    .insert_channel_open_operation(&op)
                    .await
                    .unwrap();
            }
            RecordTable::Sessions => {
                store
                    .store_session(
                        &peer,
                        &legacy(
                            &blake3::derive_key(SESSION_KEY_CONTEXT, &[7; 32]),
                            b"session",
                        ),
                    )
                    .await
                    .unwrap();
            }
        }
        let rows = store.record_upgrade_rows(table, None, 10).await.unwrap();
        let old = rows.last().unwrap();
        let mut bad = old.clone();
        let i = if matches!(table, RecordTable::Peers | RecordTable::Rooms) {
            table.fields().len() - 1
        } else {
            0
        };
        bad.values[i] = Some(match table.fields()[i].encoding {
            Encoding::Bytes => vec![0; 64],
            Encoding::Hex => hex::encode([0; 64]).into_bytes(),
            Encoding::JsonHex => serde_json::to_vec(&hex::encode([0; 64])).unwrap(),
        });
        assert!(store
            .record_upgrade_replace(table, old, &bad)
            .await
            .unwrap());
        let upgrade = RecordUpgrade::new(&[7; 32], policy.clone(), true);
        let capture = LogCapture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let result = upgrade.run(&store).await;
        let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(
            logs.lines()
                .any(|line| line.contains(table.name()) && line.contains("unreadable=1")),
            "missing table/count: {logs}"
        );
        assert!(!logs.contains(&bad.id), "logs must not contain row IDs");
        assert!(result.is_ok(), "{}: {result:?}", table.name());
        assert!(!policy.allows_v1(), "{} kept v1 enabled", table.name());
        assert!(!LegacyReadPolicy::in_data_dir(dir.path()).allows_v1());
        assert!(store.get_peer(&good.node_id).await.unwrap().is_some());
        // Preserve each unreadable field while readable siblings can advance.
        let after = store.record_upgrade_rows(table, None, 10).await.unwrap();
        let preserved = after.iter().find(|row| row.id == bad.id).unwrap();
        assert_eq!(preserved.values[i], bad.values[i]);
        let completed = store
            .inner()
            .get_peer(&good.node_id)
            .await
            .unwrap()
            .unwrap();
        assert!(RecordCipher::is_v2(
            &hex::decode(completed.metadata.as_str().unwrap()).unwrap()
        ));
        assert_eq!(upgrade.run(&store).await.unwrap(), 0);
        sqlx::query("UPDATE peers SET metadata_json = ? WHERE node_id = ?")
            .bind(serde_json::to_string(&good.metadata).unwrap())
            .bind(good.node_id.to_hex())
            .execute(store.inner().pool())
            .await
            .unwrap();
        assert!(store.get_peer(&good.node_id).await.is_err());
    }

    macro_rules! bad_row_test {
        ($name:ident, $table:ident) => {
            #[tokio::test]
            async fn $name() {
                bad_row_does_not_block_cutoff(RecordTable::$table).await;
            }
        };
    }
    bad_row_test!(bad_peer_does_not_block_cutoff, Peers);
    bad_row_test!(bad_room_does_not_block_cutoff, Rooms);
    bad_row_test!(bad_file_does_not_block_cutoff, Files);
    bad_row_test!(bad_message_does_not_block_cutoff, Messages);
    bad_row_test!(bad_outbox_does_not_block_cutoff, Outbox);
    bad_row_test!(bad_channel_does_not_block_cutoff, Channel);
    bad_row_test!(bad_session_does_not_block_cutoff, Sessions);

    #[test]
    fn write_rejection_codes_keep_operational_failures_retryable() {
        for (code, sqlite, rejected) in [
            ("1811", true, true),
            ("18", true, true),
            ("23", true, false),
            ("13", true, false),
            ("8", true, false),
            ("5", true, false),
            ("23514", false, true),
            ("22021", false, true),
            ("P0001", false, true),
            ("54000", false, true),
            ("40001", false, false),
            ("42501", false, false),
            ("08006", false, false),
        ] {
            assert_eq!(
                RecordUpgrade::rejection_code(code, sqlite),
                rejected,
                "{code}"
            );
        }
    }

    #[test]
    fn retry_schedule_doubles_and_caps_without_overflow() {
        for (attempt, seconds) in [
            (0, 60),
            (1, 120),
            (2, 240),
            (3, 480),
            (4, 960),
            (5, 1920),
            (6, 3600),
            (7, 3600),
            (u32::MAX, 3600),
        ] {
            assert_eq!(RecordUpgrade::retry_delay(attempt).as_secs(), seconds);
        }
    }

    #[tokio::test]
    async fn constraint_rejected_row_cannot_hold_cutoff_open() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = v1_peer(1);
        store.inner().upsert_peer(&peer).await.unwrap();
        sqlx::query("CREATE TRIGGER reject_upgrade BEFORE UPDATE ON peers BEGIN SELECT RAISE(ABORT, 'upgrade blocked'); END")
            .execute(store.inner().pool()).await.unwrap();
        assert!(RecordUpgrade::new(&[7; 32], policy.clone(), true)
            .run(&store)
            .await
            .is_ok());
        assert!(!policy.allows_v1());
        assert_eq!(
            store
                .inner()
                .get_peer(&peer.node_id)
                .await
                .unwrap()
                .unwrap()
                .metadata,
            peer.metadata
        );
    }

    #[tokio::test]
    async fn text_retyped_outbox_reaches_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let mut op =
            crate::OutboxOperation::prepared("retyped".into(), "peer".into(), 100, "hash".into());
        op.recovery = legacy(&[7; 32], b"readable recovery");
        store.inner().insert_outbox_operation(&op).await.unwrap();
        sqlx::query("UPDATE outbox_operations SET recovery = CAST(recovery AS TEXT)")
            .execute(store.inner().pool())
            .await
            .unwrap();
        assert_eq!(
            store
                .get_outbox_operation("retyped")
                .await
                .unwrap()
                .unwrap()
                .recovery,
            b"readable recovery"
        );
        let upgrade = RecordUpgrade::new(&[7; 32], policy.clone(), true);
        assert!(upgrade.run(&store).await.is_ok());
        assert!(!policy.allows_v1());
        assert_eq!(
            store
                .get_outbox_operation("retyped")
                .await
                .unwrap()
                .unwrap()
                .recovery,
            b"readable recovery"
        );
        assert_eq!(upgrade.run(&store).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn plaintext_message_stored_as_text_reaches_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = NodeId::from_bytes([2; 32]);
        let envelope = konsensus_core::UkmEnvelopeBuilder::new(
            100,
            peer,
            konsensus_core::Recipient::Node(peer),
            b"plaintext envelope".to_vec(),
            konsensus_core::PaymentProof::new([0; 32], [0; 32], 1),
        )
        .build();
        store.inner().store_message(&envelope).await.unwrap();
        sqlx::query("UPDATE messages SET ciphertext = CAST(ciphertext AS TEXT)")
            .execute(store.inner().pool())
            .await
            .unwrap();
        let upgrade = RecordUpgrade::new(&[7; 32], policy.clone(), true);
        assert!(upgrade.run(&store).await.is_ok());
        assert!(!policy.allows_v1());
        assert_eq!(
            store
                .get_message(&envelope.id)
                .await
                .unwrap()
                .unwrap()
                .ciphertext,
            envelope.ciphertext
        );
        assert_eq!(upgrade.run(&store).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn unchanged_rejected_swap_cannot_hold_cutoff_open() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = v1_peer(1);
        store.inner().upsert_peer(&peer).await.unwrap();
        assert!(store.get_peer(&peer.node_id).await.unwrap().is_some());
        sqlx::query(
            "CREATE TRIGGER reject_upgrade BEFORE UPDATE ON peers BEGIN SELECT RAISE(IGNORE); END",
        )
        .execute(store.inner().pool())
        .await
        .unwrap();
        let upgrade = RecordUpgrade::new(&[7; 32], policy.clone(), true);
        let capture = LogCapture::default();
        let writer = capture.clone();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        assert!(upgrade.run(&store).await.is_ok());
        assert!(!policy.allows_v1());
        let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert!(logs.contains("unwritable=1"), "{logs}");
        assert!(!logs.contains(&peer.node_id.to_hex()));
        assert_eq!(
            store
                .inner()
                .get_peer(&peer.node_id)
                .await
                .unwrap()
                .unwrap()
                .metadata,
            peer.metadata
        );
        // A blocked write is reported, not silently treated as successful conversion.
        assert!(store.get_peer(&peer.node_id).await.is_err());
        assert_eq!(upgrade.run(&store).await.unwrap(), 0);
    }

    async fn cache_damage_preserves_message(kind: u8) {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = NodeId::from_bytes([2; 32]);
        let envelope = konsensus_core::UkmEnvelopeBuilder::new(
            100,
            peer,
            konsensus_core::Recipient::Node(peer),
            b"readable message".to_vec(),
            konsensus_core::PaymentProof::new([0; 32], [0; 32], 1),
        )
        .build();
        let mut raw = envelope.clone();
        raw.ciphertext = legacy(&[7; 32], &envelope.ciphertext);
        store.inner().store_message(&raw).await.unwrap();
        let cache = match kind {
            0 => vec![0; 64],
            1 => Vec::new(),
            _ => legacy(&[8; 32], b"wrong-key cache"),
        };
        store
            .store_message_plaintext(&envelope.id, &cache)
            .await
            .unwrap();
        if kind == 3 {
            sqlx::query("UPDATE messages SET plaintext_enc = 0")
                .execute(store.inner().pool())
                .await
                .unwrap();
        }
        assert_eq!(
            store
                .get_message(&envelope.id)
                .await
                .unwrap()
                .unwrap()
                .ciphertext,
            envelope.ciphertext
        );
        RecordUpgrade::new(&[7; 32], policy.clone(), true)
            .run(&store)
            .await
            .unwrap();
        assert!(!policy.allows_v1());
        assert_eq!(
            store
                .get_message(&envelope.id)
                .await
                .unwrap()
                .unwrap()
                .ciphertext,
            envelope.ciphertext
        );
        assert!(store
            .get_message_plaintext(&envelope.id)
            .await
            .unwrap()
            .is_none());
    }
    #[tokio::test]
    async fn corrupt_cache_preserves_message() {
        cache_damage_preserves_message(0).await;
    }
    #[tokio::test]
    async fn empty_cache_preserves_message() {
        cache_damage_preserves_message(1).await;
    }
    #[tokio::test]
    async fn wrong_key_cache_preserves_message() {
        cache_damage_preserves_message(2).await;
    }
    #[tokio::test]
    async fn mistyped_cache_preserves_message() {
        cache_damage_preserves_message(3).await;
    }

    async fn readable_cache_survives_bad_message(malformed_envelope: bool) {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = NodeId::from_bytes([2; 32]);
        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            100,
            peer,
            konsensus_core::Recipient::Node(peer),
            b"message".to_vec(),
            konsensus_core::PaymentProof::new([0; 32], [0; 32], 1),
        )
        .build();
        envelope.ciphertext = if malformed_envelope {
            legacy(&[7; 32], &envelope.ciphertext)
        } else {
            vec![0; 64]
        };
        store.inner().store_message(&envelope).await.unwrap();
        if malformed_envelope {
            sqlx::query("UPDATE messages SET sender = X'FF'")
                .execute(store.inner().pool())
                .await
                .unwrap();
        }
        let cache = legacy(
            &blake3::derive_key(CACHE_KEY_CONTEXT, &[7; 32]),
            b"readable cached plaintext",
        );
        store
            .store_message_plaintext(&envelope.id, &cache)
            .await
            .unwrap();
        let cipher = konsensus_crypto::PlaintextCacheCipher::with_policy(&[7; 32], policy.clone());
        assert_eq!(
            cipher.decrypt(&envelope.id.to_hex(), &cache).unwrap(),
            b"readable cached plaintext"
        );
        assert!(store.get_message(&envelope.id).await.is_err());
        RecordUpgrade::new(&[7; 32], policy.clone(), true)
            .run(&store)
            .await
            .unwrap();
        assert!(!policy.allows_v1());
        let upgraded = store
            .get_message_plaintext(&envelope.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            cipher.decrypt(&envelope.id.to_hex(), &upgraded).unwrap(),
            b"readable cached plaintext"
        );
        assert!(store.get_message(&envelope.id).await.is_err());
        let retained: Vec<u8> = sqlx::query_scalar("SELECT CAST(ciphertext AS BLOB) FROM messages")
            .fetch_one(store.inner().pool())
            .await
            .unwrap();
        assert_eq!(retained, envelope.ciphertext);
    }

    #[tokio::test]
    async fn bad_ciphertext_preserves_readable_cache() {
        readable_cache_survives_bad_message(false).await;
    }

    #[tokio::test]
    async fn bad_envelope_preserves_readable_cache() {
        readable_cache_survives_bad_message(true).await;
    }

    async fn bad_file_data_preserves_metadata(mistyped: bool) {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let file = crate::FileRecord {
            id: "readable-file-metadata".into(),
            filename: hex::encode(legacy(&[7; 32], b"original.txt")),
            mime_type: hex::encode(legacy(&[7; 32], b"text/plain")),
            data: vec![0; 64],
            size_bytes: 64,
            blake3_hash: "hash".into(),
            sender: NodeId::from_bytes([2; 32]).to_hex(),
            message_id: None,
            created_at: String::new(),
        };
        store.inner().store_file(&file).await.unwrap();
        if mistyped {
            sqlx::query("UPDATE files SET data = 0")
                .execute(store.inner().pool())
                .await
                .unwrap();
        }
        assert_eq!(
            store
                .get_file_metadata(&file.id)
                .await
                .unwrap()
                .unwrap()
                .filename,
            "original.txt"
        );
        assert!(store.get_file(&file.id).await.is_err());
        RecordUpgrade::new(&[7; 32], policy.clone(), true)
            .run(&store)
            .await
            .unwrap();
        assert!(!policy.allows_v1());
        let metadata = store.get_file_metadata(&file.id).await.unwrap().unwrap();
        assert_eq!(metadata.filename, "original.txt");
        assert_eq!(metadata.mime_type, "text/plain");
        assert_eq!(
            store.list_files(10).await.unwrap()[0].filename,
            "original.txt"
        );
        assert!(store.get_file(&file.id).await.is_err());
        let data: Vec<u8> = sqlx::query_scalar("SELECT CAST(data AS BLOB) FROM files")
            .fetch_one(store.inner().pool())
            .await
            .unwrap();
        assert_eq!(data, if mistyped { b"0".to_vec() } else { file.data });
        let storage_class: String = sqlx::query_scalar("SELECT typeof(data) FROM files")
            .fetch_one(store.inner().pool())
            .await
            .unwrap();
        assert_eq!(storage_class, if mistyped { "integer" } else { "blob" });
    }
    #[tokio::test]
    async fn corrupt_file_data_preserves_metadata() {
        bad_file_data_preserves_metadata(false).await;
    }
    #[tokio::test]
    async fn mistyped_file_data_preserves_metadata() {
        bad_file_data_preserves_metadata(true).await;
    }

    #[tokio::test]
    async fn database_failure_keeps_cutoff_pending() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = SqliteStorage::in_memory().await.unwrap();
        store.pool().close().await;
        assert!(RecordUpgrade::new(&[7; 32], policy.clone(), true)
            .run(&store)
            .await
            .is_err());
        assert!(policy.allows_v1());
    }

    #[tokio::test]
    async fn malformed_sqlite_values_do_not_block_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        store.inner().upsert_peer(&v1_peer(1)).await.unwrap();
        store.inner().upsert_peer(&v1_peer(2)).await.unwrap();
        sqlx::query("UPDATE peers SET metadata_json = X'FF' WHERE node_id = ?")
            .bind(NodeId::from_bytes([2; 32]).to_hex())
            .execute(store.inner().pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions (peer_id, state_blob) VALUES (?, 0)")
            .bind(NodeId::from_bytes([3; 32]).to_hex())
            .execute(store.inner().pool())
            .await
            .unwrap();
        // A TEXT value with invalid UTF-8, and malformed keys, must also be skipped.
        sqlx::query("INSERT INTO peers (node_id, metadata_json) VALUES (?, CAST(X'FF' AS TEXT))")
            .bind(NodeId::from_bytes([4; 32]).to_hex())
            .execute(store.inner().pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions (peer_id, state_blob) VALUES (X'FF', X'0102')")
            .execute(store.inner().pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO sessions (peer_id, state_blob) VALUES (CAST(X'FF' AS TEXT), X'0102')",
        )
        .execute(store.inner().pool())
        .await
        .unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            RecordUpgrade::new(&[7; 32], policy.clone(), true).run(&store),
        )
        .await
        .unwrap();
        assert!(result.is_ok(), "{result:?}");
        assert!(!policy.allows_v1());
        assert!(store
            .get_peer(&NodeId::from_bytes([1; 32]))
            .await
            .unwrap()
            .is_some());
        let classes: Vec<String> =
            sqlx::query_scalar("SELECT typeof(state_blob) FROM sessions ORDER BY peer_id")
                .fetch_all(store.inner().pool())
                .await
                .unwrap();
        assert_eq!(classes, ["integer", "blob", "blob"]);
    }

    #[tokio::test]
    async fn malformed_envelope_column_does_not_block_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = NodeId::from_bytes([2; 32]);
        let envelope = konsensus_core::UkmEnvelopeBuilder::new(
            100,
            peer,
            konsensus_core::Recipient::Node(peer),
            b"message".to_vec(),
            konsensus_core::PaymentProof::new([0; 32], [0; 32], 1),
        )
        .build();
        store.inner().store_message(&envelope).await.unwrap();
        sqlx::query("UPDATE messages SET sender = X'FF'")
            .execute(store.inner().pool())
            .await
            .unwrap();
        assert!(RecordUpgrade::new(&[7; 32], policy.clone(), true)
            .run(&store)
            .await
            .is_ok());
        assert!(!policy.allows_v1());
    }

    #[tokio::test]
    async fn noncanonical_message_id_does_not_block_cutoff() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = NodeId::from_bytes([2; 32]);
        let envelope = konsensus_core::UkmEnvelopeBuilder::new(
            100,
            peer,
            konsensus_core::Recipient::Node(peer),
            b"message".to_vec(),
            konsensus_core::PaymentProof::new([0; 32], [0; 32], 1),
        )
        .build();
        let alias = envelope.id.to_hex().to_uppercase();
        assert_ne!(alias, envelope.id.to_hex());
        store.inner().store_message(&envelope).await.unwrap();
        sqlx::query("UPDATE messages SET id = ?")
            .bind(&alias)
            .execute(store.inner().pool())
            .await
            .unwrap();
        assert!(RecordUpgrade::new(&[7; 32], policy.clone(), true)
            .run(&store)
            .await
            .is_ok());
        assert!(!policy.allows_v1());
        let stored: String = sqlx::query_scalar("SELECT id FROM messages")
            .fetch_one(store.inner().pool())
            .await
            .unwrap();
        assert_eq!(stored, alias);
    }

    #[tokio::test]
    async fn concurrent_write_defers_cutoff_but_other_rows_progress() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = v1_peer(1);
        store.inner().upsert_peer(&peer).await.unwrap();
        let session_peer = NodeId::from_bytes([2; 32]);
        store
            .store_session(
                &session_peer,
                &legacy(
                    &blake3::derive_key(SESSION_KEY_CONTEXT, &[7; 32]),
                    b"session",
                ),
            )
            .await
            .unwrap();
        let replacement = serde_json::to_string(&serde_json::Value::String(hex::encode(legacy(
            &[7; 32],
            br#"{"label":"concurrent"}"#,
        ))))
        .unwrap();
        sqlx::query(&format!(
            "CREATE TRIGGER hold_upgrade BEFORE UPDATE ON peers              WHEN NEW.metadata_json != '{replacement}' BEGIN              UPDATE peers SET metadata_json = '{replacement}' WHERE node_id = OLD.node_id;              SELECT RAISE(IGNORE); END"))
        .execute(store.inner().pool())
        .await
        .unwrap();
        let upgrade = RecordUpgrade::new(&[7; 32], policy.clone(), true);
        assert!(upgrade.run(&store).await.is_err());
        assert!(policy.allows_v1());
        assert!(RecordCipher::is_v2(
            &store.load_session(&session_peer).await.unwrap().unwrap()
        ));
        sqlx::query("DROP TRIGGER hold_upgrade")
            .execute(store.inner().pool())
            .await
            .unwrap();
        assert_eq!(upgrade.run(&store).await.unwrap(), 1);
        assert!(!policy.allows_v1());
        assert_eq!(
            store
                .get_peer(&peer.node_id)
                .await
                .unwrap()
                .unwrap()
                .metadata["label"],
            "concurrent"
        );
    }

    #[tokio::test]
    async fn held_message_is_upgraded_without_becoming_visible() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = NodeId::from_bytes([2; 32]);
        let envelope = konsensus_core::UkmEnvelopeBuilder::new(
            100,
            peer,
            konsensus_core::Recipient::Node(peer),
            b"held-message".to_vec(),
            konsensus_core::PaymentProof::new([0; 32], [0; 32], 1),
        )
        .build();
        store.inner().store_message(&envelope).await.unwrap();
        sqlx::query(
            "INSERT INTO call_admission_hold (message_id, sender, held_at_ms) VALUES (?, ?, 0)",
        )
        .bind(envelope.id.to_hex())
        .bind(peer.to_hex())
        .execute(store.inner().pool())
        .await
        .unwrap();
        assert!(store.get_message(&envelope.id).await.unwrap().is_none());
        RecordUpgrade::new(&[7; 32], policy.clone(), true)
            .run(&store)
            .await
            .unwrap();
        assert!(!policy.allows_v1());
        assert!(store.get_message(&envelope.id).await.unwrap().is_none());
        sqlx::query("DELETE FROM call_admission_hold")
            .execute(store.inner().pool())
            .await
            .unwrap();
        assert_eq!(
            store
                .get_message(&envelope.id)
                .await
                .unwrap()
                .unwrap()
                .ciphertext,
            b"held-message"
        );
    }

    #[tokio::test]
    async fn upgrade_preserves_concurrent_field_writes() {
        let store = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
        let mut peer = Peer::new(NodeId::from_bytes([1; 32]));
        store.upsert_peer(&peer).await.unwrap();
        let rows = store
            .record_upgrade_rows(RecordTable::Peers, None, 1)
            .await
            .unwrap();
        peer.display_name = Some("current".into());
        store.upsert_peer(&peer).await.unwrap();
        assert!(!store
            .record_upgrade_replace(RecordTable::Peers, &rows[0], &rows[0])
            .await
            .unwrap());
        assert_eq!(
            store
                .get_peer(&peer.node_id)
                .await
                .unwrap()
                .unwrap()
                .display_name
                .as_deref(),
            Some("current")
        );
    }

    #[tokio::test]
    async fn plaintext_peer_is_converted_without_a_trust_decision() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let mut peer = Peer::new(NodeId::from_bytes([1; 32]));
        peer.display_name = Some("Legacy peer".into());
        store.inner().upsert_peer(&peer).await.unwrap();
        assert!(store.list_peers().await.unwrap().is_empty());
        RecordUpgrade::new(&[7; 32], policy, true)
            .run(&store)
            .await
            .unwrap();
        let converted = store.get_peer(&peer.node_id).await.unwrap().unwrap();
        assert_eq!(converted.display_name, peer.display_name);
        assert_eq!(converted.metadata["storage_legacy_untrusted"], true);
    }

    #[tokio::test]
    async fn upgrade_covers_message_cache_and_session_key_domains() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let peer = NodeId::from_bytes([1; 32]);
        let envelope = konsensus_core::UkmEnvelopeBuilder::new(
            100,
            peer,
            konsensus_core::Recipient::Node(peer),
            b"content".to_vec(),
            konsensus_core::PaymentProof::new([0; 32], [0; 32], 1),
        )
        .build();
        // Recognizable plaintext envelopes retain their original ID.
        store.inner().store_message(&envelope).await.unwrap();
        let cache = legacy(&blake3::derive_key(CACHE_KEY_CONTEXT, &[7; 32]), b"cached");
        store
            .store_message_plaintext(&envelope.id, &cache)
            .await
            .unwrap();
        let session = legacy(
            &blake3::derive_key(SESSION_KEY_CONTEXT, &[7; 32]),
            b"session",
        );
        store.store_session(&peer, &session).await.unwrap();
        let upgrader = RecordUpgrade::new(&[7; 32], policy.clone(), true);
        assert_eq!(upgrader.run(&store).await.unwrap(), 2);
        assert_eq!(
            store
                .get_message(&envelope.id)
                .await
                .unwrap()
                .unwrap()
                .ciphertext,
            b"content"
        );
        let cache_cipher =
            konsensus_crypto::PlaintextCacheCipher::with_policy(&[7; 32], policy.clone());
        let current = store
            .get_message_plaintext(&envelope.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            cache_cipher
                .decrypt(&envelope.id.to_hex(), &current)
                .unwrap(),
            b"cached"
        );
        assert!(cache_cipher.decrypt(&envelope.id.to_hex(), &cache).is_err());
        let current_session = store.load_session(&peer).await.unwrap().unwrap();
        assert_eq!(
            upgrader
                .sessions
                .decrypt("sessions", "state_blob", &peer.to_hex(), &current_session)
                .unwrap(),
            b"session"
        );
        assert!(upgrader
            .sessions
            .decrypt(
                "sessions",
                "state_blob",
                &NodeId::from_bytes([2; 32]).to_hex(),
                &current_session
            )
            .is_err());
    }
}
