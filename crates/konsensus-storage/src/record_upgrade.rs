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
    pub values: Vec<Option<Vec<u8>>>,
}

// The SQL identifiers come exclusively from RecordTable's static field definitions.
macro_rules! backend {
    ($module:ident, $db:ty, $pool:ty) => {
        pub(crate) mod $module {
            use super::*;
            use sqlx::{QueryBuilder, Row};
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
                    query
                        .push(" WHERE ")
                        .push(table.key())
                        .push(" > ")
                        .push_bind(after);
                }
                query
                    .push(" ORDER BY ")
                    .push(table.key())
                    .push(" LIMIT ")
                    .push_bind(i64::from(limit));
                let rows = query.build().fetch_all(pool).await?;
                rows.iter()
                    .map(|row| {
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
                            .collect::<Result<_, _>>()?;
                        Ok(RecordRow {
                            id: row.try_get(0)?,
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
backend!(sqlite, sqlx::Sqlite, sqlx::SqlitePool);
backend!(postgres, sqlx::Postgres, sqlx::PgPool);

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

    /// Every replacement compares all old encrypted fields, preserving concurrent writes.
    /// On interruption, the next run validates and skips completed v2 records.
    pub async fn run(&self, store: &dyn Storage) -> Result<u64, StorageError> {
        if !self.policy.allows_v1() {
            return Ok(0);
        }
        let mut changed = 0;
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
            // Fetch binary records individually so large file and message bodies
            // do not multiply the working set by the metadata batch size.
            let batch_size = if table
                .fields()
                .iter()
                .any(|field| matches!(field.encoding, Encoding::Bytes))
            {
                1
            } else {
                128
            };
            let mut cursor = None;
            loop {
                let rows = store
                    .record_upgrade_rows(table, cursor.as_deref(), batch_size)
                    .await?;
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    let mut plaintext_message = false;
                    if self.encrypted_storage && matches!(table, RecordTable::Messages) {
                        let id = konsensus_core::MessageId::from_hex(&row.id).map_err(|_| {
                            StorageError::Conversion("invalid message row id".into())
                        })?;
                        let raw = store.record_upgrade_envelope(&id).await?.ok_or_else(|| {
                            StorageError::Conversion("message changed during format upgrade".into())
                        })?;
                        if row.values[0].as_deref() != Some(raw.ciphertext.as_slice()) {
                            return Err(StorageError::Conversion(
                                "message changed during format upgrade".into(),
                            ));
                        }
                        let ciphertext = match self.storage.decrypt(
                            "messages",
                            "ciphertext",
                            &row.id,
                            &raw.ciphertext,
                        ) {
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
                    let next = self.convert(table, &row, plaintext_message)?;
                    if row != next {
                        if !store.record_upgrade_replace(table, &row, &next).await? {
                            return Err(StorageError::Conversion(
                                "record changed during format upgrade; retry required".into(),
                            ));
                        }
                        changed += 1;
                    }
                    cursor = Some(row.id);
                }
                tokio::task::yield_now().await;
            }
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
        let upgrade = RecordUpgrade::new(&[7; 32], LegacyReadPolicy::default(), true);
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

    #[tokio::test]
    async fn upgrade_resumes_and_preserves_completed_rows() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let store = EncryptedStorage::with_policy(
            SqliteStorage::in_memory().await.unwrap(),
            &[7; 32],
            policy.clone(),
        );
        let first = v1_peer(1);
        let second = v1_peer(2);
        store.inner().upsert_peer(&first).await.unwrap();
        let mut invalid = second.clone();
        invalid.metadata = hex::encode([0; 40]).into();
        store.inner().upsert_peer(&invalid).await.unwrap();
        assert_eq!(
            store
                .get_peer(&first.node_id)
                .await
                .unwrap()
                .unwrap()
                .metadata["label"],
            "legacy"
        );
        let upgrade = RecordUpgrade::new(&[7; 32], policy.clone(), true);
        assert!(upgrade.run(&store).await.is_err());
        assert!(policy.allows_v1());
        let completed = store
            .inner()
            .get_peer(&first.node_id)
            .await
            .unwrap()
            .unwrap();
        assert!(RecordCipher::is_v2(
            &hex::decode(completed.metadata.as_str().unwrap()).unwrap()
        ));
        // Repair the remaining row, then resume with a fresh upgrader.
        sqlx::query("UPDATE peers SET metadata_json = ? WHERE node_id = ?")
            .bind(serde_json::to_string(&second.metadata).unwrap())
            .bind(second.node_id.to_hex())
            .execute(store.inner().pool())
            .await
            .unwrap();
        let resumed = RecordUpgrade::new(&[7; 32], policy.clone(), true);
        assert_eq!(resumed.run(&store).await.unwrap(), 1);
        assert!(!policy.allows_v1());
        assert_eq!(
            store
                .inner()
                .get_peer(&first.node_id)
                .await
                .unwrap()
                .unwrap()
                .metadata,
            completed.metadata
        );
        assert_eq!(resumed.run(&store).await.unwrap(), 0);
        assert!(store.get_peer(&second.node_id).await.unwrap().is_some());
        sqlx::query("UPDATE peers SET metadata_json = ? WHERE node_id = ?")
            .bind(serde_json::to_string(&first.metadata).unwrap())
            .bind(first.node_id.to_hex())
            .execute(store.inner().pool())
            .await
            .unwrap();
        assert!(store.get_peer(&first.node_id).await.is_err());
        let reopened = RecordCipher::new(&[7; 32], LegacyReadPolicy::in_data_dir(dir.path()));
        assert!(reopened
            .decrypt(
                "peers",
                "metadata_json",
                &first.node_id.to_hex(),
                &hex::decode(first.metadata.as_str().unwrap()).unwrap()
            )
            .is_err());
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
