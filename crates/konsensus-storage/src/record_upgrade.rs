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
    /// Empty when a stored key or field cannot be decoded; never replace that row.
    pub values: Vec<Option<Vec<u8>>>,
}

// The SQL identifiers come exclusively from RecordTable's static field definitions.
macro_rules! backend {
    ($module:ident, $db:ty, $pool:ty, $text_start:literal, $text_end:literal) => {
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
                rows.iter()
                    .map(|row| {
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
                        let values = table
                            .fields()
                            .iter()
                            .enumerate()
                            .map(|(i, field)| -> Result<_, StorageError> {
                                Ok(match field.encoding {
                                    Encoding::Bytes => row.try_get::<Option<Vec<u8>>, _>(i + 1)?,
                                    _ => row
                                        .try_get::<Option<String>, _>(i + 1)?
                                        .map(String::into_bytes),
                                })
                            })
                            .collect::<Result<_, _>>();
                        let (id, values) = match (id, values) {
                            (Ok(id), Ok(values)) => (id, values),
                            (Err(sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_)), _)
                            | (
                                _,
                                Err(StorageError::Database(
                                    sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_),
                                )),
                            ) => (String::new(), Vec::new()),
                            (Err(error), _) => return Err(error.into()),
                            (_, Err(error)) => return Err(error),
                        };
                        Ok(RecordRow {
                            id,
                            scan_after,
                            values,
                        })
                    })
                    .collect()
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
                for (i, field) in table.fields().iter().enumerate() {
                    if i != 0 {
                        query.push(", ");
                    }
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
                query
                    .push(" WHERE ")
                    .push(table.key())
                    .push(" = ")
                    .push_bind(&old.id);
                for (i, field) in table.fields().iter().enumerate() {
                    query.push(" AND ").push(field.name);
                    if let Some(value) = &old.values[i] {
                        query.push(" = ");
                        match field.encoding {
                            Encoding::Bytes => {
                                query.push_bind(value);
                            }
                            _ => {
                                query.push_bind(std::str::from_utf8(value).map_err(|_| {
                                    StorageError::Conversion("invalid record text".into())
                                })?);
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
backend!(sqlite, sqlx::Sqlite, sqlx::SqlitePool, "CAST(", " AS TEXT)");
backend!(
    postgres,
    sqlx::Postgres,
    sqlx::PgPool,
    "convert_from(",
    ", 'UTF8')"
);

pub struct RecordUpgrade {
    storage: RecordCipher,
    cache: RecordCipher,
    sessions: RecordCipher,
    policy: LegacyReadPolicy,
    encrypted_storage: bool,
}

impl RecordUpgrade {
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
    ) -> Result<RecordRow, StorageError> {
        let mut next = row.clone();
        let mut plaintext_peer = false;
        let mut decoded = Vec::new();
        for (field, value) in table.fields().iter().zip(&row.values) {
            let Some(value) = value else {
                decoded.push(None);
                continue;
            };
            let bytes = match field.encoding {
                Encoding::Bytes => Some(value.clone()),
                Encoding::Hex => hex::decode(value)
                    .ok()
                    .filter(|bytes| bytes.len() >= 28 || RecordCipher::is_v2(bytes)),
                Encoding::JsonHex => {
                    let json: serde_json::Value = serde_json::from_slice(value)
                        .map_err(|_| StorageError::Conversion("invalid stored JSON".into()))?;
                    json.as_str()
                        .map(|s| {
                            hex::decode(s).map_err(|_| {
                                StorageError::Encryption("invalid encrypted JSON".into())
                            })
                        })
                        .transpose()?
                }
            };
            if bytes.is_none() && matches!(table, RecordTable::Peers) {
                plaintext_peer = true;
            }
            decoded.push(bytes);
        }
        // Plaintext files can be recognized from their textual metadata. Binary
        // fields alone do not provide enough information to classify old content.
        let plaintext_file =
            matches!(table, RecordTable::Files) && decoded[..2].iter().any(Option::is_none);
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
            let mut plain = match &decoded[i] {
                Some(blob) => match cipher.decrypt(table.name(), field.name, &row.id, blob) {
                    Ok(plain) => plain,
                    Err(_)
                        if ((plaintext_file && field.name == "data")
                            || (plaintext_message && field.name == "ciphertext"))
                            && !RecordCipher::is_v2(blob) =>
                    {
                        value.clone()
                    }
                    Err(e) => return Err(StorageError::Encryption(e)),
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
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
            }
            if decoded[i].as_deref().is_some_and(RecordCipher::is_v2)
                && !(plaintext_peer && field.name == "metadata_json")
            {
                continue;
            }
            let blob = cipher
                .encrypt(table.name(), field.name, &row.id, &plain)
                .map_err(StorageError::Encryption)?;
            next.values[i] = Some(match field.encoding {
                Encoding::Bytes => blob,
                Encoding::Hex => hex::encode(blob).into_bytes(),
                Encoding::JsonHex => serde_json::to_vec(&hex::encode(blob))
                    .map_err(|e| StorageError::Serialization(e.to_string()))?,
            });
        }
        Ok(next)
    }

    // None means the envelope changed after the field snapshot: retry, not corruption.
    async fn prepare_row(
        &self,
        store: &dyn Storage,
        table: RecordTable,
        row: &RecordRow,
    ) -> Result<Option<RecordRow>, StorageError> {
        if row.id.is_empty() || row.values.len() != table.fields().len() {
            return Err(StorageError::Conversion("unreadable record fields".into()));
        }
        let mut plaintext_message = false;
        if self.encrypted_storage && matches!(table, RecordTable::Messages) {
            let id = konsensus_core::MessageId::from_hex(&row.id)
                .map_err(|_| StorageError::Conversion("invalid message row id".into()))?;
            if id.to_hex() != row.id {
                return Err(StorageError::Conversion(
                    "noncanonical message row id".into(),
                ));
            }
            let Some(raw) = store.record_upgrade_envelope(&id).await? else {
                return Ok(None);
            };
            if row.values[0].as_deref() != Some(raw.ciphertext.as_slice()) {
                return Ok(None);
            }
            let ciphertext =
                match self
                    .storage
                    .decrypt("messages", "ciphertext", &row.id, &raw.ciphertext)
                {
                    Ok(bytes) => bytes,
                    Err(e) if RecordCipher::is_v2(&raw.ciphertext) => {
                        return Err(StorageError::Encryption(e))
                    }
                    Err(_) => {
                        plaintext_message = true;
                        raw.ciphertext.clone()
                    }
                };
            let rebuilt = konsensus_core::UkmEnvelopeBuilder::new(
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
            .build();
            if rebuilt.id != id {
                return Err(StorageError::Conversion(
                    "envelope id does not match stored row".into(),
                ));
            }
        }
        self.convert(table, row, plaintext_message).map(Some)
    }

    /// Convert usable rows and count unreadable rows without enabling v1 forever.
    /// Unreadable bytes remain untouched for recovery and are refused after cutoff.
    /// Database failures and concurrent replacements defer completion.
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
            let (mut scanned, mut upgraded, mut unreadable) = (0u64, 0u64, 0u64);
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
                    let next = match self.prepare_row(store, table, &row).await {
                        Ok(Some(next)) => next,
                        Ok(None) => {
                            conflicts += 1;
                            continue;
                        }
                        Err(
                            StorageError::Encryption(_)
                            | StorageError::Conversion(_)
                            | StorageError::Serialization(_),
                        ) => {
                            unreadable += 1;
                            continue;
                        }
                        Err(StorageError::Database(
                            sqlx::Error::ColumnDecode { .. } | sqlx::Error::Decode(_),
                        )) => {
                            unreadable += 1;
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    if row != next {
                        if !store.record_upgrade_replace(table, &row, &next).await? {
                            conflicts += 1;
                            continue;
                        }
                        changed += 1;
                        upgraded += 1;
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
                    "storage record format unreadable rows preserved"
                );
            } else {
                tracing::info!(
                    table = table.name(),
                    scanned,
                    upgraded,
                    unreadable,
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
                values,
            };
            let upgraded = upgrade.convert(table, &old, false).unwrap();
            assert_ne!(old, upgraded);
            assert_eq!(upgrade.convert(table, &upgraded, false).unwrap(), upgraded);
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
        // Preserve evidence; never delete or launder the unreadable row.
        let after = store.record_upgrade_rows(table, None, 10).await.unwrap();
        assert!(after.contains(&bad));
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
        sqlx::query(
            "CREATE TRIGGER hold_upgrade BEFORE UPDATE ON peers BEGIN SELECT RAISE(IGNORE); END",
        )
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
        assert!(store.get_peer(&peer.node_id).await.unwrap().is_some());
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
