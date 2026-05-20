//! SQLite storage backend using sqlx.

use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool, SqlitePoolOptions};
use std::str::FromStr;

use konsensus_core::{
    HostingContractState, MessageId, NodeId, Nonce, OperatorHostingContract,
    OperatorHostingPayment, OperatorHostingPaymentDirection, PaymentProof, Recipient,
    RoomId, Signature, UkmEnvelope,
};

use crate::calendar::{CalendarEventRecord, RsvpRecord};
use crate::error::StorageError;
use crate::invites::{
    AcceptedInviteRecord, InviteIssuedRecord, InviteSchemaCapabilities, InviteState,
};
use crate::models::{
    merge_peer_metadata_preserving_invite_ref, FileMetadata, FileRecord, OnboardingStateRecord,
    Peer, Room,
};
use crate::reactions::ReactionRecord;
use crate::traits::Storage;

/// SQLite-backed storage for T1 Light and development.
pub struct SqliteStorage {
    pool: SqlitePool,
}

impl SqliteStorage {
    /// Open (or create) a SQLite database at the given path.
    pub async fn open(path: &str) -> Result<Self, StorageError> {
        let options = SqliteConnectOptions::from_str(path)
            .map_err(StorageError::Database)?
            .create_if_missing(true)
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await?;

        sqlx::query("PRAGMA busy_timeout = 5000").execute(&pool).await?;
        sqlx::query("PRAGMA cache_size = -8000").execute(&pool).await?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    /// Create an in-memory SQLite database (for testing).
    pub async fn in_memory() -> Result<Self, StorageError> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        let storage = Self { pool };
        storage.run_migrations().await?;
        Ok(storage)
    }

    /// Run embedded migrations.
    async fn run_migrations(&self) -> Result<(), StorageError> {
        // Use a runtime migration source to avoid the sqlx `macros` feature
        // (which pulls in MySQL support and the vulnerable `rsa` crate).
        // Deployed binaries can set KONSENSUS_SQLITE_MIGRATIONS_DIR because
        // CARGO_MANIFEST_DIR points at the build host, not the target node.
        let migrations_dir = std::env::var("KONSENSUS_SQLITE_MIGRATIONS_DIR")
            .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/migrations").to_string());
        let migrator = sqlx::migrate::Migrator::new(std::path::Path::new(&migrations_dir)).await?;
        migrator.run(&self.pool).await?;
        Ok(())
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

// Helper: serialize Recipient to (type, id) strings
fn recipient_to_parts(r: &Recipient) -> (&'static str, String) {
    match r {
        Recipient::Node(id) => ("node", id.to_hex()),
        Recipient::Room(id) => ("room", id.to_string()),
        Recipient::Broadcast => ("broadcast", String::new()),
    }
}

// Helper: deserialize Recipient from (type, id) strings
fn recipient_from_parts(rtype: &str, rid: &str) -> Result<Recipient, StorageError> {
    match rtype {
        "node" => {
            let id = NodeId::from_hex(rid)
                .map_err(|e| StorageError::Conversion(format!("node id: {e}")))?;
            Ok(Recipient::Node(id))
        }
        "room" => {
            let id = RoomId::parse(rid)
                .map_err(|e| StorageError::Conversion(format!("room id: {e}")))?;
            Ok(Recipient::Room(id))
        }
        "broadcast" => Ok(Recipient::Broadcast),
        other => Err(StorageError::Conversion(format!(
            "unknown recipient type: {other}"
        ))),
    }
}

// Helper: reconstruct UkmEnvelope from database row fields
#[allow(clippy::too_many_arguments)]
fn row_to_envelope(
    id: &str,
    kind: i64,
    sender: &str,
    recipient_type: &str,
    recipient_id: &str,
    timestamp_ms: i64,
    ciphertext: &[u8],
    payment_hash: &str,
    preimage: &str,
    amount_msat: i64,
    signature: &str,
    nonce: &str,
    references_json: &str,
) -> Result<UkmEnvelope, StorageError> {
    let sender_id =
        NodeId::from_hex(sender).map_err(|e| StorageError::Conversion(format!("sender: {e}")))?;
    let recipient = recipient_from_parts(recipient_type, recipient_id)?;

    let ph_bytes: [u8; 32] = hex::decode(payment_hash)
        .map_err(|e| StorageError::Conversion(format!("payment_hash: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("payment_hash: wrong length".into()))?;
    let pi_bytes: [u8; 32] = hex::decode(preimage)
        .map_err(|e| StorageError::Conversion(format!("preimage: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("preimage: wrong length".into()))?;
    let amount_u64 = u64::try_from(amount_msat)
        .map_err(|_| StorageError::Conversion(format!("amount_msat negative: {amount_msat}")))?;
    let proof = PaymentProof::new(ph_bytes, pi_bytes, amount_u64);

    let sig_bytes: [u8; 64] = hex::decode(signature)
        .map_err(|e| StorageError::Conversion(format!("signature: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("signature: wrong length".into()))?;
    let sig = Signature::from_bytes(sig_bytes);

    let nonce_bytes: [u8; 24] = hex::decode(nonce)
        .map_err(|e| StorageError::Conversion(format!("nonce: {e}")))?
        .try_into()
        .map_err(|_| StorageError::Conversion("nonce: wrong length".into()))?;
    let nonce = Nonce::from_bytes(nonce_bytes);

    let refs: Vec<String> = serde_json::from_str(references_json)
        .map_err(|e| StorageError::Serialization(format!("references: {e}")))?;
    let references: Result<Vec<MessageId>, _> = refs.iter().map(|s| MessageId::from_hex(s)).collect();
    let references =
        references.map_err(|e| StorageError::Conversion(format!("reference id: {e}")))?;

    let stored_id = MessageId::from_hex(id)
        .map_err(|e| StorageError::Conversion(format!("message id: {e}")))?;

    let kind_u16 = u16::try_from(kind)
        .map_err(|_| StorageError::Conversion(format!("kind out of u16 range: {kind}")))?;
    let timestamp_u64 = u64::try_from(timestamp_ms)
        .map_err(|_| StorageError::Conversion(format!("timestamp negative: {timestamp_ms}")))?;

    Ok(UkmEnvelope {
        id: stored_id,
        kind: kind_u16,
        sender: sender_id,
        recipient,
        timestamp: timestamp_u64,
        ciphertext: ciphertext.to_vec(),
        payment_proof: proof,
        signature: sig,
        nonce,
        references,
    })
}

fn u64_to_i64(value: u64, field: &str) -> Result<i64, StorageError> {
    i64::try_from(value)
        .map_err(|_| StorageError::Conversion(format!("{field} overflows i64: {value}")))
}

fn i64_to_u64(value: i64, field: &str) -> Result<u64, StorageError> {
    u64::try_from(value)
        .map_err(|_| StorageError::Conversion(format!("{field} negative: {value}")))
}

#[allow(clippy::too_many_arguments)]
fn row_to_hosting_contract(
    id: String,
    tenant_pubkey: String,
    operator_pubkey: String,
    sats_per_day: i64,
    started_at: i64,
    last_paid_at: Option<i64>,
    state: String,
) -> Result<OperatorHostingContract, StorageError> {
    let contract = OperatorHostingContract {
        id: uuid::Uuid::parse_str(&id)
            .map_err(|e| StorageError::Conversion(format!("hosting contract id: {e}")))?,
        tenant_pubkey: NodeId::from_hex(&tenant_pubkey)
            .map_err(|e| StorageError::Conversion(format!("tenant_pubkey: {e}")))?,
        operator_pubkey,
        sats_per_day: i64_to_u64(sats_per_day, "sats_per_day")?,
        started_at: i64_to_u64(started_at, "started_at")?,
        last_paid_at: last_paid_at
            .map(|ts| i64_to_u64(ts, "last_paid_at"))
            .transpose()?,
        state: HostingContractState::from_str(&state)
            .map_err(|e| StorageError::Conversion(e.to_string()))?,
    };
    contract
        .validate()
        .map_err(|e| StorageError::Conversion(e.to_string()))?;
    Ok(contract)
}

#[allow(clippy::too_many_arguments)]
fn row_to_hosting_payment(
    payment_hash: String,
    contract_id: String,
    tenant_pubkey: String,
    operator_pubkey: String,
    amount_msat: i64,
    paid_at: i64,
    direction: String,
    preimage: Option<String>,
    memo: Option<String>,
) -> Result<OperatorHostingPayment, StorageError> {
    Ok(OperatorHostingPayment {
        payment_hash,
        contract_id: uuid::Uuid::parse_str(&contract_id)
            .map_err(|e| StorageError::Conversion(format!("hosting contract id: {e}")))?,
        tenant_pubkey: NodeId::from_hex(&tenant_pubkey)
            .map_err(|e| StorageError::Conversion(format!("tenant_pubkey: {e}")))?,
        operator_pubkey,
        amount_msat: i64_to_u64(amount_msat, "amount_msat")?,
        paid_at: i64_to_u64(paid_at, "paid_at")?,
        direction: OperatorHostingPaymentDirection::from_str(&direction)
            .map_err(|e| StorageError::Conversion(e.to_string()))?,
        preimage,
        memo,
    })
}

#[async_trait]
impl Storage for SqliteStorage {
    // ── Messages ───────────────────────────────────────────────────────

    async fn store_message(&self, envelope: &UkmEnvelope) -> Result<(), StorageError> {
        let id = envelope.id.to_hex();
        let kind = i64::from(envelope.kind);
        let sender = envelope.sender.to_hex();
        let (rtype, rid) = recipient_to_parts(&envelope.recipient);
        let ts = i64::try_from(envelope.timestamp)
            .map_err(|_| StorageError::Conversion(format!("timestamp overflows i64: {}", envelope.timestamp)))?;
        let ciphertext = &envelope.ciphertext;
        let ph = hex::encode(envelope.payment_proof.payment_hash);
        let pi = hex::encode(envelope.payment_proof.preimage);
        let amt = i64::try_from(envelope.payment_proof.amount_msat)
            .map_err(|_| StorageError::Conversion(format!("amount_msat overflows i64: {}", envelope.payment_proof.amount_msat)))?;
        let sig = hex::encode(envelope.signature.as_bytes());
        let nonce = hex::encode(envelope.nonce.as_bytes());
        let refs: Vec<String> = envelope.references.iter().map(|r| r.to_hex()).collect();
        let refs_json =
            serde_json::to_string(&refs).map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO messages (id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
             ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(kind)
        .bind(&sender)
        .bind(rtype)
        .bind(&rid)
        .bind(ts)
        .bind(ciphertext)
        .bind(&ph)
        .bind(&pi)
        .bind(amt)
        .bind(&sig)
        .bind(&nonce)
        .bind(&refs_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_message(&self, id: &MessageId) -> Result<Option<UkmEnvelope>, StorageError> {
        let id_hex = id.to_hex();

        let row = sqlx::query_as::<_, (
            String,  // id
            i64,     // kind
            String,  // sender
            String,  // recipient_type
            String,  // recipient_id
            i64,     // timestamp_ms
            Vec<u8>, // ciphertext
            String,  // payment_hash
            String,  // preimage
            i64,     // amount_msat
            String,  // signature
            String,  // nonce
            String,  // references_json
        )>(
            "SELECT id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
             ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json \
             FROM messages WHERE id = ?",
        )
        .bind(&id_hex)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => {
                let envelope = row_to_envelope(
                    &r.0, r.1, &r.2, &r.3, &r.4, r.5, &r.6, &r.7, &r.8, r.9, &r.10, &r.11,
                    &r.12,
                )?;
                Ok(Some(envelope))
            }
            None => Ok(None),
        }
    }

    async fn get_messages_for_recipient(
        &self,
        recipient: &Recipient,
        limit: u32,
        before_timestamp: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError> {
        let (rtype, rid) = recipient_to_parts(recipient);
        let before = before_timestamp.map_or(i64::MAX, |t| t.min(i64::MAX as u64) as i64);
        let lim = limit as i64;

        let rows = sqlx::query_as::<_, (
            String, i64, String, String, String, i64, Vec<u8>, String, String, i64, String,
            String, String,
        )>(
            "SELECT id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
             ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json \
             FROM messages WHERE recipient_type = ? AND recipient_id = ? AND timestamp_ms < ? \
             ORDER BY timestamp_ms DESC LIMIT ?",
        )
        .bind(rtype)
        .bind(&rid)
        .bind(before)
        .bind(lim)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                row_to_envelope(
                    &r.0, r.1, &r.2, &r.3, &r.4, r.5, &r.6, &r.7, &r.8, r.9, &r.10, &r.11,
                    &r.12,
                )
            })
            .collect()
    }

    async fn get_conversation_messages(
        &self,
        my_node_id: &str,
        peer_or_room_id: &str,
        is_room: bool,
        limit: u32,
        before_timestamp: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError> {
        let before = before_timestamp.map_or(i64::MAX, |t| t.min(i64::MAX as u64) as i64);
        let lim = limit as i64;

        let rows = if is_room {
            sqlx::query_as::<_, (
                String, i64, String, String, String, i64, Vec<u8>, String, String, i64, String,
                String, String,
            )>(
                "SELECT id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
                 ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json \
                 FROM messages WHERE recipient_type = 'room' AND recipient_id = ? AND timestamp_ms < ? \
                 ORDER BY timestamp_ms DESC LIMIT ?",
            )
            .bind(peer_or_room_id)
            .bind(before)
            .bind(lim)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, (
                String, i64, String, String, String, i64, Vec<u8>, String, String, i64, String,
                String, String,
            )>(
                "SELECT id, kind, sender, recipient_type, recipient_id, timestamp_ms, \
                 ciphertext, payment_hash, preimage, amount_msat, signature, nonce, references_json \
                 FROM messages WHERE (\
                   (sender = ? AND recipient_type = 'node' AND recipient_id = ?) \
                   OR (sender = ? AND recipient_type = 'node' AND recipient_id = ?) \
                 ) AND timestamp_ms < ? \
                 ORDER BY timestamp_ms DESC LIMIT ?",
            )
            .bind(peer_or_room_id)
            .bind(my_node_id)
            .bind(my_node_id)
            .bind(peer_or_room_id)
            .bind(before)
            .bind(lim)
            .fetch_all(&self.pool)
            .await?
        };

        rows.into_iter()
            .map(|r| {
                row_to_envelope(
                    &r.0, r.1, &r.2, &r.3, &r.4, r.5, &r.6, &r.7, &r.8, r.9, &r.10, &r.11,
                    &r.12,
                )
            })
            .collect()
    }

    async fn delete_message(&self, id: &MessageId) -> Result<bool, StorageError> {
        let id_hex = id.to_hex();
        // Clean up pending deliveries first (belt-and-suspenders with FK CASCADE)
        sqlx::query("DELETE FROM pending_deliveries WHERE message_id = ?")
            .bind(&id_hex)
            .execute(&self.pool)
            .await?;
        let result = sqlx::query("DELETE FROM messages WHERE id = ?")
            .bind(&id_hex)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn delete_messages_older_than(&self, before_ms: u64) -> Result<u64, StorageError> {
        // Clean up pending deliveries for messages about to be deleted
        sqlx::query(
            "DELETE FROM pending_deliveries WHERE message_id IN \
             (SELECT id FROM messages WHERE timestamp_ms < ?)",
        )
        .bind(before_ms.min(i64::MAX as u64) as i64)
        .execute(&self.pool)
        .await?;
        let result = sqlx::query("DELETE FROM messages WHERE timestamp_ms < ?")
            .bind(before_ms.min(i64::MAX as u64) as i64)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    // ── Rooms ──────────────────────────────────────────────────────────

    async fn create_room(&self, room: &Room) -> Result<(), StorageError> {
        let id = room.id.to_string();
        let created_by = room.created_by.to_hex();
        let metadata =
            serde_json::to_string(&room.metadata).map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO rooms (id, name, created_by, created_at, metadata_json) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(&room.name)
        .bind(&created_by)
        .bind(&room.created_at)
        .bind(&metadata)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_room(&self, id: &RoomId) -> Result<Option<Room>, StorageError> {
        let id_str = id.to_string();

        let row = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT id, name, created_by, created_at, metadata_json FROM rooms WHERE id = ?",
        )
        .bind(&id_str)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((id, name, created_by, created_at, metadata_json)) => {
                let room_id = RoomId::parse(&id)
                    .map_err(|e| StorageError::Conversion(format!("room id: {e}")))?;
                let creator = NodeId::from_hex(&created_by)
                    .map_err(|e| StorageError::Conversion(format!("created_by: {e}")))?;
                let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(Room {
                    id: room_id,
                    name,
                    created_by: creator,
                    created_at,
                    metadata,
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_rooms(&self) -> Result<Vec<Room>, StorageError> {
        let rows = sqlx::query_as::<_, (String, String, String, String, String)>(
            "SELECT id, name, created_by, created_at, metadata_json FROM rooms ORDER BY created_at DESC LIMIT 1000",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(id, name, created_by, created_at, metadata_json)| {
                let room_id = RoomId::parse(&id)
                    .map_err(|e| StorageError::Conversion(format!("room id: {e}")))?;
                let creator = NodeId::from_hex(&created_by)
                    .map_err(|e| StorageError::Conversion(format!("created_by: {e}")))?;
                let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Room {
                    id: room_id,
                    name,
                    created_by: creator,
                    created_at,
                    metadata,
                })
            })
            .collect()
    }

    async fn delete_room(&self, id: &RoomId) -> Result<bool, StorageError> {
        let rid = id.to_string();

        // Delete memberships first (foreign key child)
        sqlx::query("DELETE FROM room_members WHERE room_id = ?")
            .bind(&rid)
            .execute(&self.pool)
            .await?;

        let result = sqlx::query("DELETE FROM rooms WHERE id = ?")
            .bind(&rid)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn add_room_member(&self, room_id: &RoomId, member: &NodeId) -> Result<(), StorageError> {
        let rid = room_id.to_string();
        let nid = member.to_hex();

        sqlx::query(
            "INSERT OR IGNORE INTO room_members (room_id, node_id) VALUES (?, ?)",
        )
        .bind(&rid)
        .bind(&nid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn remove_room_member(
        &self,
        room_id: &RoomId,
        member: &NodeId,
    ) -> Result<(), StorageError> {
        let rid = room_id.to_string();
        let nid = member.to_hex();

        sqlx::query("DELETE FROM room_members WHERE room_id = ? AND node_id = ?")
            .bind(&rid)
            .bind(&nid)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn get_room_members(&self, room_id: &RoomId) -> Result<Vec<NodeId>, StorageError> {
        let rid = room_id.to_string();

        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT node_id FROM room_members WHERE room_id = ? ORDER BY joined_at LIMIT 10000",
        )
        .bind(&rid)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(nid,)| {
                NodeId::from_hex(&nid)
                    .map_err(|e| StorageError::Conversion(format!("member node_id: {e}")))
            })
            .collect()
    }

    // ── Peers ──────────────────────────────────────────────────────────

    async fn upsert_peer(&self, peer: &Peer) -> Result<(), StorageError> {
        let nid = peer.node_id.to_hex();
        let existing_metadata = sqlx::query_as::<_, (String,)>(
            "SELECT metadata_json FROM peers WHERE node_id = ?",
        )
        .bind(&nid)
        .fetch_optional(&self.pool)
        .await?
        .map(|(metadata_json,)| {
            serde_json::from_str::<serde_json::Value>(&metadata_json)
                .map_err(|e| StorageError::Serialization(e.to_string()))
        })
        .transpose()?;
        let merged_metadata =
            merge_peer_metadata_preserving_invite_ref(&peer.metadata, existing_metadata.as_ref());
        let metadata = serde_json::to_string(&merged_metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES (?, ?, ?, ?, ?) \
             ON CONFLICT(node_id) DO UPDATE SET \
             address = COALESCE(excluded.address, peers.address), \
             last_seen = COALESCE(excluded.last_seen, peers.last_seen), \
             display_name = COALESCE(excluded.display_name, peers.display_name), \
             metadata_json = excluded.metadata_json",
        )
        .bind(&nid)
        .bind(&peer.address)
        .bind(&peer.last_seen)
        .bind(&peer.display_name)
        .bind(&metadata)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_peer(&self, id: &NodeId) -> Result<Option<Peer>, StorageError> {
        let nid = id.to_hex();

        let row = sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>, String)>(
            "SELECT node_id, address, last_seen, display_name, metadata_json FROM peers WHERE node_id = ?",
        )
        .bind(&nid)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((node_id, address, last_seen, display_name, metadata_json)) => {
                let nid = NodeId::from_hex(&node_id)
                    .map_err(|e| StorageError::Conversion(format!("peer node_id: {e}")))?;
                let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(Peer {
                    node_id: nid,
                    address,
                    last_seen,
                    display_name,
                    metadata,
                }))
            }
            None => Ok(None),
        }
    }

    async fn list_peers(&self) -> Result<Vec<Peer>, StorageError> {
        let rows = sqlx::query_as::<_, (String, Option<String>, Option<String>, Option<String>, String)>(
            "SELECT node_id, address, last_seen, display_name, metadata_json FROM peers ORDER BY node_id LIMIT 1000",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(node_id, address, last_seen, display_name, metadata_json)| {
                let nid = NodeId::from_hex(&node_id)
                    .map_err(|e| StorageError::Conversion(format!("peer node_id: {e}")))?;
                let metadata: serde_json::Value = serde_json::from_str(&metadata_json)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Peer {
                    node_id: nid,
                    address,
                    last_seen,
                    display_name,
                    metadata,
                })
            })
            .collect()
    }

    async fn delete_peer(&self, id: &NodeId) -> Result<bool, StorageError> {
        let nid = id.to_hex();
        let result = sqlx::query("DELETE FROM peers WHERE node_id = ?")
            .bind(&nid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── Nonces ─────────────────────────────────────────────────────────

    async fn store_nonce(&self, nonce: &Nonce, sender: &NodeId) -> Result<bool, StorageError> {
        let nonce_hex = hex::encode(nonce.as_bytes());
        let sender_hex = sender.to_hex();

        let result = sqlx::query(
            "INSERT OR IGNORE INTO nonces (nonce_hex, sender) VALUES (?, ?)",
        )
        .bind(&nonce_hex)
        .bind(&sender_hex)
        .execute(&self.pool)
        .await?;

        // rows_affected == 1 means new insert, 0 means duplicate (replay)
        Ok(result.rows_affected() > 0)
    }

    async fn has_nonce(&self, nonce: &Nonce) -> Result<bool, StorageError> {
        let nonce_hex = hex::encode(nonce.as_bytes());

        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM nonces WHERE nonce_hex = ?",
        )
        .bind(&nonce_hex)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.0 > 0)
    }

    async fn cleanup_expired_nonces(&self, max_age_secs: u64) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM nonces WHERE received_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
        )
        .bind(format!("-{max_age_secs} seconds"))
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ── E2EE Sessions ──────────────────────────────────────────────────

    async fn store_session(
        &self,
        peer_id: &NodeId,
        state_blob: &[u8],
    ) -> Result<(), StorageError> {
        let pid = peer_id.to_hex();

        sqlx::query(
            "INSERT INTO sessions (peer_id, state_blob, updated_at) \
             VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) \
             ON CONFLICT(peer_id) DO UPDATE SET \
             state_blob = excluded.state_blob, \
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
        )
        .bind(&pid)
        .bind(state_blob)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let pid = peer_id.to_hex();

        let row = sqlx::query_as::<_, (Vec<u8>,)>(
            "SELECT state_blob FROM sessions WHERE peer_id = ?",
        )
        .bind(&pid)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|(blob,)| blob))
    }

    async fn delete_session(&self, peer_id: &NodeId) -> Result<bool, StorageError> {
        let pid = peer_id.to_hex();
        let result = sqlx::query("DELETE FROM sessions WHERE peer_id = ?")
            .bind(&pid)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_sessions(&self) -> Result<Vec<NodeId>, StorageError> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT peer_id FROM sessions ORDER BY updated_at DESC LIMIT 1000",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(pid,)| {
                NodeId::from_hex(&pid)
                    .map_err(|e| StorageError::Conversion(format!("session peer_id: {e}")))
            })
            .collect()
    }

    // ── Pending Deliveries ──────────────────────────────────────────────

    async fn queue_pending_delivery(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError> {
        let mid = message_id.to_hex();
        let rid = recipient.to_hex();

        sqlx::query(
            "INSERT OR IGNORE INTO pending_deliveries (message_id, recipient_id) VALUES (?, ?)",
        )
        .bind(&mid)
        .bind(&rid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_pending_for_peer(
        &self,
        recipient: &NodeId,
    ) -> Result<Vec<(MessageId, u32)>, StorageError> {
        let rid = recipient.to_hex();

        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT message_id, attempts FROM pending_deliveries \
             WHERE recipient_id = ? ORDER BY queued_at ASC",
        )
        .bind(&rid)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(mid, attempts)| {
                let id = MessageId::from_hex(&mid)
                    .map_err(|e| StorageError::Conversion(format!("pending message_id: {e}")))?;
                let att = u32::try_from(attempts)
                    .map_err(|_| StorageError::Conversion(format!("attempts out of u32 range: {attempts}")))?;
                Ok((id, att))
            })
            .collect()
    }

    async fn remove_pending_delivery(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError> {
        let mid = message_id.to_hex();
        let rid = recipient.to_hex();

        sqlx::query("DELETE FROM pending_deliveries WHERE message_id = ? AND recipient_id = ?")
            .bind(&mid)
            .bind(&rid)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    async fn increment_pending_attempts(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError> {
        let mid = message_id.to_hex();
        let rid = recipient.to_hex();

        sqlx::query(
            "UPDATE pending_deliveries SET attempts = attempts + 1 \
             WHERE message_id = ? AND recipient_id = ?",
        )
        .bind(&mid)
        .bind(&rid)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_pending_peers(&self) -> Result<Vec<NodeId>, StorageError> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT DISTINCT recipient_id FROM pending_deliveries LIMIT 1000",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(rid,)| {
                NodeId::from_hex(&rid)
                    .map_err(|e| StorageError::Conversion(format!("pending recipient_id: {e}")))
            })
            .collect()
    }

    async fn count_pending_deliveries(&self) -> Result<u64, StorageError> {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT COUNT(*) FROM pending_deliveries",
        )
        .fetch_one(&self.pool)
        .await?;

        u64::try_from(row.0)
            .map_err(|_| StorageError::Conversion(format!("pending count negative: {}", row.0)))
    }

    async fn clear_pending_for_peer(&self, recipient: &NodeId) -> Result<u64, StorageError> {
        let recipient_hex = recipient.to_hex();
        let result = sqlx::query(
            "DELETE FROM pending_deliveries WHERE recipient_id = ?",
        )
        .bind(&recipient_hex)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    async fn cleanup_stale_pending(&self, max_attempts: u32) -> Result<u64, StorageError> {
        let result = sqlx::query(
            "DELETE FROM pending_deliveries WHERE attempts >= ?",
        )
        .bind(max_attempts as i64)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // ── Files ──────────────────────────────────────────────────────────

    async fn store_file(&self, file: &FileRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO files (id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, data) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&file.id)
        .bind(&file.filename)
        .bind(&file.mime_type)
        .bind(i64::try_from(file.size_bytes)
            .map_err(|_| StorageError::Conversion(format!("file size overflows i64: {}", file.size_bytes)))?)
        .bind(&file.blake3_hash)
        .bind(&file.sender)
        .bind(&file.message_id)
        .bind(&file.data)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn get_file(&self, id: &str) -> Result<Option<FileRecord>, StorageError> {
        let row = sqlx::query_as::<_, (
            String, String, String, i64, String, String, Option<String>, Vec<u8>, String,
        )>(
            "SELECT id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, data, created_at \
             FROM files WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, data, created_at)| {
            let sz = u64::try_from(size_bytes)
                .map_err(|_| StorageError::Conversion(format!("file size negative: {size_bytes}")))?;
            Ok::<FileRecord, StorageError>(FileRecord {
                id,
                filename,
                mime_type,
                size_bytes: sz,
                blake3_hash,
                sender,
                message_id,
                data,
                created_at,
            })
        }).transpose()
    }

    async fn get_file_metadata(&self, id: &str) -> Result<Option<FileMetadata>, StorageError> {
        let row = sqlx::query_as::<_, (
            String, String, String, i64, String, String, Option<String>, String,
        )>(
            "SELECT id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at \
             FROM files WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at)| {
            let sz = u64::try_from(size_bytes)
                .map_err(|_| StorageError::Conversion(format!("file size negative: {size_bytes}")))?;
            Ok::<FileMetadata, StorageError>(FileMetadata {
                id,
                filename,
                mime_type,
                size_bytes: sz,
                blake3_hash,
                sender,
                message_id,
                created_at,
            })
        }).transpose()
    }

    async fn list_files(&self, limit: u32) -> Result<Vec<FileMetadata>, StorageError> {
        let lim = limit as i64;

        let rows = sqlx::query_as::<_, (
            String, String, String, i64, String, String, Option<String>, String,
        )>(
            "SELECT id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at \
             FROM files ORDER BY created_at DESC LIMIT ?",
        )
        .bind(lim)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|(id, filename, mime_type, size_bytes, blake3_hash, sender, message_id, created_at)| {
            let sz = u64::try_from(size_bytes)
                .map_err(|_| StorageError::Conversion(format!("file size negative: {size_bytes}")))?;
            Ok(FileMetadata {
                id,
                filename,
                mime_type,
                size_bytes: sz,
                blake3_hash,
                sender,
                message_id,
                created_at,
            })
        }).collect()
    }

    async fn delete_file(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM files WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    // ── Plaintext Cache ─────────────────────────────────────────────────

    async fn store_message_plaintext(
        &self,
        id: &MessageId,
        encrypted_plaintext: &[u8],
    ) -> Result<(), StorageError> {
        sqlx::query("UPDATE messages SET plaintext_enc = ? WHERE id = ?")
            .bind(encrypted_plaintext)
            .bind(id.to_hex())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn get_message_plaintext(
        &self,
        id: &MessageId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let row: Option<(Option<Vec<u8>>,)> =
            sqlx::query_as("SELECT plaintext_enc FROM messages WHERE id = ?")
                .bind(id.to_hex())
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.and_then(|(data,)| data))
    }

    async fn invite_schema_capabilities(
        &self,
    ) -> Result<InviteSchemaCapabilities, StorageError> {
        let columns: Vec<String> =
            sqlx::query_scalar("SELECT name FROM pragma_table_info('invites_issued')")
                .fetch_all(&self.pool)
                .await?;

        Ok(InviteSchemaCapabilities {
            addr_column: columns.iter().any(|name| name == "addr"),
            max_fee_rate_sat_per_vb_column: columns
                .iter()
                .any(|name| name == "max_fee_rate_sat_per_vb"),
            channel_open_intent_expiry_unix_column: columns
                .iter()
                .any(|name| name == "channel_open_intent_expiry_unix"),
        })
    }

    async fn add_invite_issued(&self, record: &InviteIssuedRecord) -> Result<(), StorageError> {
        let expiry_unix = i64::try_from(record.expiry_unix).map_err(|_| {
            StorageError::Conversion(format!("expiry_unix overflows i64: {}", record.expiry_unix))
        })?;
        let channel_size_hint_sats = record.channel_size_hint_sats.map(i64::from);
        let max_fee_rate_sat_per_vb = record.max_fee_rate_sat_per_vb.map(i64::from);
        let channel_open_intent_expiry_unix = record
            .channel_open_intent_expiry_unix
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("channel_open_intent_expiry_unix overflows i64".into()))?;
        let created_at = i64::try_from(record.created_at).map_err(|_| {
            StorageError::Conversion(format!("created_at overflows i64: {}", record.created_at))
        })?;
        let accepted_at = record
            .accepted_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("accepted_at overflows i64".into()))?;
        let revoked_at = record
            .revoked_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("revoked_at overflows i64".into()))?;

        sqlx::query(
            "INSERT INTO invites_issued \
             (id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(record.id.as_bytes().as_slice())
        .bind(record.invitee_pubkey.as_slice())
        .bind(expiry_unix)
        .bind(channel_size_hint_sats)
        .bind(&record.addr)
        .bind(max_fee_rate_sat_per_vb)
        .bind(channel_open_intent_expiry_unix)
        .bind(record.nonce.as_slice())
        .bind(record.state.to_string())
        .bind(created_at)
        .bind(accepted_at)
        .bind(revoked_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn add_invite_and_whitelist(
        &self,
        invite: &InviteIssuedRecord,
        peer_pubkey: [u8; 32],
    ) -> Result<(), StorageError> {
        let expiry_unix = i64::try_from(invite.expiry_unix).map_err(|_| {
            StorageError::Conversion(format!("expiry_unix overflows i64: {}", invite.expiry_unix))
        })?;
        let channel_size_hint_sats = invite.channel_size_hint_sats.map(i64::from);
        let max_fee_rate_sat_per_vb = invite.max_fee_rate_sat_per_vb.map(i64::from);
        let channel_open_intent_expiry_unix = invite
            .channel_open_intent_expiry_unix
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("channel_open_intent_expiry_unix overflows i64".into()))?;
        let created_at = i64::try_from(invite.created_at).map_err(|_| {
            StorageError::Conversion(format!("created_at overflows i64: {}", invite.created_at))
        })?;
        let accepted_at = invite
            .accepted_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("accepted_at overflows i64".into()))?;
        let revoked_at = invite
            .revoked_at
            .map(i64::try_from)
            .transpose()
            .map_err(|_| StorageError::Conversion("revoked_at overflows i64".into()))?;

        let node_id = NodeId::from_bytes(peer_pubkey).to_hex();
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO invites_issued \
             (id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(invite.id.as_bytes().as_slice())
        .bind(invite.invitee_pubkey.as_slice())
        .bind(expiry_unix)
        .bind(channel_size_hint_sats)
        .bind(&invite.addr)
        .bind(max_fee_rate_sat_per_vb)
        .bind(channel_open_intent_expiry_unix)
        .bind(invite.nonce.as_slice())
        .bind(invite.state.to_string())
        .bind(created_at)
        .bind(accepted_at)
        .bind(revoked_at)
        .execute(&mut *tx)
        .await?;

        let mut metadata = sqlx::query_as::<_, (String,)>(
            "SELECT metadata_json FROM peers WHERE node_id = ?",
        )
        .bind(&node_id)
        .fetch_optional(&mut *tx)
        .await?
        .and_then(|(json,)| serde_json::from_str::<serde_json::Value>(&json).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));

        metadata["invite_ref"] = serde_json::Value::String(invite.id.to_string());
        metadata["whitelist_source"] = serde_json::Value::String("invite".to_string());

        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES (?, NULL, NULL, NULL, ?) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = excluded.metadata_json",
        )
        .bind(&node_id)
        .bind(&metadata_json)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn find_invite_issued(
        &self,
        id: &uuid::Uuid,
    ) -> Result<Option<InviteIssuedRecord>, StorageError> {
        let row = sqlx::query_as::<
            _,
            (
                Vec<u8>,
                Vec<u8>,
                i64,
                Option<i64>,
                String,
                Option<i64>,
                Option<i64>,
                Vec<u8>,
                String,
                i64,
                Option<i64>,
                Option<i64>,
            ),
        >(
            "SELECT id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at \
             FROM invites_issued WHERE id = ?",
        )
        .bind(id.as_bytes().as_slice())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| {
            let id_bytes: [u8; 16] = r
                .0
                .try_into()
                .map_err(|_| StorageError::Conversion("invalid invites_issued.id length".into()))?;
            let invitee_pubkey: [u8; 32] = r.1.try_into().map_err(|_| {
                StorageError::Conversion("invalid invites_issued.invitee_pubkey length".into())
            })?;
            let nonce: [u8; 16] = r.7.try_into().map_err(|_| {
                StorageError::Conversion("invalid invites_issued.nonce length".into())
            })?;
            let expiry_unix = u64::try_from(r.2).map_err(|_| {
                StorageError::Conversion(format!("negative invites_issued.expiry_unix: {}", r.2))
            })?;
            let channel_size_hint_sats = r
                .3
                .map(u32::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("channel_size_hint_sats out of range".into()))?;
            let max_fee_rate_sat_per_vb = r
                .5
                .map(u32::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("max_fee_rate_sat_per_vb out of range".into()))?;
            let channel_open_intent_expiry_unix = r
                .6
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("channel_open_intent_expiry_unix out of range".into()))?;
            let state = InviteState::from_str(&r.8)
                .map_err(|e| StorageError::Conversion(format!("invalid invites_issued.state: {e}")))?;
            let created_at = u64::try_from(r.9).map_err(|_| {
                StorageError::Conversion(format!("negative invites_issued.created_at: {}", r.9))
            })?;
            let accepted_at = r
                .10
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("accepted_at out of range".into()))?;
            let revoked_at = r
                .11
                .map(u64::try_from)
                .transpose()
                .map_err(|_| StorageError::Conversion("revoked_at out of range".into()))?;

            Ok(InviteIssuedRecord {
                id: uuid::Uuid::from_bytes(id_bytes),
                invitee_pubkey,
                expiry_unix,
                channel_size_hint_sats,
                addr: r.4,
                max_fee_rate_sat_per_vb,
                channel_open_intent_expiry_unix,
                nonce,
                state,
                created_at,
                accepted_at,
                revoked_at,
            })
        })
        .transpose()
    }

    async fn list_invites_issued(&self) -> Result<Vec<InviteIssuedRecord>, StorageError> {
        let rows = sqlx::query_as::<
            _,
            (
                Vec<u8>,
                Vec<u8>,
                i64,
                Option<i64>,
                String,
                Option<i64>,
                Option<i64>,
                Vec<u8>,
                String,
                i64,
                Option<i64>,
                Option<i64>,
            ),
        >(
            "SELECT id, invitee_pubkey, expiry_unix, channel_size_hint_sats, addr, max_fee_rate_sat_per_vb, channel_open_intent_expiry_unix, nonce, state, created_at, accepted_at, revoked_at \
             FROM invites_issued ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                let id_bytes: [u8; 16] = r.0.try_into().map_err(|_| {
                    StorageError::Conversion("invalid invites_issued.id length".into())
                })?;
                let invitee_pubkey: [u8; 32] = r.1.try_into().map_err(|_| {
                    StorageError::Conversion("invalid invites_issued.invitee_pubkey length".into())
                })?;
                let nonce: [u8; 16] = r.7.try_into().map_err(|_| {
                    StorageError::Conversion("invalid invites_issued.nonce length".into())
                })?;
                let expiry_unix = u64::try_from(r.2).map_err(|_| {
                    StorageError::Conversion(format!("negative invites_issued.expiry_unix: {}", r.2))
                })?;
                let channel_size_hint_sats = r
                    .3
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| {
                        StorageError::Conversion("channel_size_hint_sats out of range".into())
                    })?;
                let max_fee_rate_sat_per_vb = r
                    .5
                    .map(u32::try_from)
                    .transpose()
                    .map_err(|_| {
                        StorageError::Conversion("max_fee_rate_sat_per_vb out of range".into())
                    })?;
                let channel_open_intent_expiry_unix = r
                    .6
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| {
                        StorageError::Conversion("channel_open_intent_expiry_unix out of range".into())
                    })?;
                let state = InviteState::from_str(&r.8).map_err(|e| {
                    StorageError::Conversion(format!("invalid invites_issued.state: {e}"))
                })?;
                let created_at = u64::try_from(r.9).map_err(|_| {
                    StorageError::Conversion(format!("negative invites_issued.created_at: {}", r.9))
                })?;
                let accepted_at = r
                    .10
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| StorageError::Conversion("accepted_at out of range".into()))?;
                let revoked_at = r
                    .11
                    .map(u64::try_from)
                    .transpose()
                    .map_err(|_| StorageError::Conversion("revoked_at out of range".into()))?;

                Ok(InviteIssuedRecord {
                    id: uuid::Uuid::from_bytes(id_bytes),
                    invitee_pubkey,
                    expiry_unix,
                    channel_size_hint_sats,
                    addr: r.4,
                    max_fee_rate_sat_per_vb,
                    channel_open_intent_expiry_unix,
                    nonce,
                    state,
                    created_at,
                    accepted_at,
                    revoked_at,
                })
            })
            .collect()
    }

    async fn revoke_invite(&self, id: &uuid::Uuid, now_unix: u64) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE invites_issued SET state = ?, revoked_at = ? WHERE id = ? AND state = ?",
        )
        .bind(InviteState::Revoked.to_string())
        .bind(now_unix as i64)
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Pending.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn mark_invite_accepted(
        &self,
        id: &uuid::Uuid,
        now_unix: u64,
    ) -> Result<bool, StorageError> {
        let now_i64 = i64::try_from(now_unix)
            .map_err(|_| StorageError::Conversion("accepted_at overflows i64".into()))?;
        let result = sqlx::query(
            "UPDATE invites_issued SET state = ?, accepted_at = ? WHERE id = ? AND state IN (?, ?)",
        )
        .bind(InviteState::Accepted.to_string())
        .bind(now_i64)
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Pending.to_string())
        .bind(InviteState::Opening.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn mark_invite_opening(
        &self,
        id: &uuid::Uuid,
        now_unix: u64,
    ) -> Result<bool, StorageError> {
        let now_i64 = i64::try_from(now_unix)
            .map_err(|_| StorageError::Conversion("accepted_at overflows i64".into()))?;
        let result = sqlx::query(
            "UPDATE invites_issued SET state = ?, accepted_at = ? WHERE id = ? AND state = ?",
        )
        .bind(InviteState::Opening.to_string())
        .bind(now_i64)
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Pending.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn mark_invite_pending(&self, id: &uuid::Uuid) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "UPDATE invites_issued SET state = ?, accepted_at = NULL WHERE id = ? AND state = ?",
        )
        .bind(InviteState::Pending.to_string())
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Opening.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn mark_invite_expired(
        &self,
        id: &uuid::Uuid,
        now_unix: u64,
    ) -> Result<bool, StorageError> {
        let now_i64 = i64::try_from(now_unix)
            .map_err(|_| StorageError::Conversion("revoked_at overflows i64".into()))?;
        let result = sqlx::query(
            "UPDATE invites_issued SET state = ?, revoked_at = ? WHERE id = ? AND state = ?",
        )
        .bind(InviteState::Expired.to_string())
        .bind(now_i64)
        .bind(id.as_bytes().as_slice())
        .bind(InviteState::Pending.to_string())
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(result.rows_affected() > 0)
    }

    async fn add_whitelisted_peer_with_invite_ref(
        &self,
        pubkey: [u8; 32],
        invite_id: uuid::Uuid,
    ) -> Result<(), StorageError> {
        let node_id = NodeId::from_bytes(pubkey).to_hex();
        let mut metadata = sqlx::query_as::<_, (String,)>(
            "SELECT metadata_json FROM peers WHERE node_id = ?",
        )
        .bind(&node_id)
        .fetch_optional(&self.pool)
        .await?
        .and_then(|(json,)| serde_json::from_str::<serde_json::Value>(&json).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}));

        metadata["invite_ref"] = serde_json::Value::String(invite_id.to_string());
        metadata["whitelist_source"] = serde_json::Value::String("invite".to_string());

        let metadata_json = serde_json::to_string(&metadata)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        sqlx::query(
            "INSERT INTO peers (node_id, address, last_seen, display_name, metadata_json) \
             VALUES (?, NULL, NULL, NULL, ?) \
             ON CONFLICT(node_id) DO UPDATE SET metadata_json = excluded.metadata_json",
        )
        .bind(&node_id)
        .bind(&metadata_json)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn add_accepted_invite(&self, record: &AcceptedInviteRecord) -> Result<(), StorageError> {
        let expiry_unix = i64::try_from(record.expiry_unix).map_err(|_| {
            StorageError::Conversion(format!("expiry_unix overflows i64: {}", record.expiry_unix))
        })?;
        let accepted_at = i64::try_from(record.accepted_at).map_err(|_| {
            StorageError::Conversion(format!("accepted_at overflows i64: {}", record.accepted_at))
        })?;

        sqlx::query(
            "INSERT INTO accepted_invites (nonce, inviter_pubkey, expiry_unix, accepted_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(record.nonce.as_slice())
        .bind(record.inviter_pubkey.as_slice())
        .bind(expiry_unix)
        .bind(accepted_at)
        .execute(&self.pool)
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if matches!(db_err.code().as_deref(), Some("2067" | "1555")) => {
                StorageError::AlreadyExists("accepted invite already exists".into())
            }
            _ => StorageError::Database(e),
        })?;

        Ok(())
    }

    async fn find_accepted_invite(
        &self,
        nonce: &[u8; 16],
    ) -> Result<Option<AcceptedInviteRecord>, StorageError> {
        let row = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, i64, i64)>(
            "SELECT nonce, inviter_pubkey, expiry_unix, accepted_at \
             FROM accepted_invites WHERE nonce = ?",
        )
        .bind(nonce.as_slice())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| {
            let nonce: [u8; 16] = r.0.try_into().map_err(|_| {
                StorageError::Conversion("invalid accepted_invites.nonce length".into())
            })?;
            let inviter_pubkey: [u8; 32] = r.1.try_into().map_err(|_| {
                StorageError::Conversion("invalid accepted_invites.inviter_pubkey length".into())
            })?;
            let expiry_unix = u64::try_from(r.2).map_err(|_| {
                StorageError::Conversion(format!("negative accepted_invites.expiry_unix: {}", r.2))
            })?;
            let accepted_at = u64::try_from(r.3).map_err(|_| {
                StorageError::Conversion(format!("negative accepted_invites.accepted_at: {}", r.3))
            })?;

            Ok(AcceptedInviteRecord {
                nonce,
                inviter_pubkey,
                expiry_unix,
                accepted_at,
            })
        })
        .transpose()
    }

    async fn list_active_accepted_invites(
        &self,
        now_unix: u64,
    ) -> Result<Vec<AcceptedInviteRecord>, StorageError> {
        let now_unix = i64::try_from(now_unix).map_err(|_| {
            StorageError::Conversion(format!("now_unix overflows i64: {now_unix}"))
        })?;
        let rows = sqlx::query_as::<_, (Vec<u8>, Vec<u8>, i64, i64)>(
            "SELECT nonce, inviter_pubkey, expiry_unix, accepted_at \
             FROM accepted_invites WHERE expiry_unix > ? ORDER BY accepted_at ASC",
        )
        .bind(now_unix)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                let nonce: [u8; 16] = r.0.try_into().map_err(|_| {
                    StorageError::Conversion("invalid accepted_invites.nonce length".into())
                })?;
                let inviter_pubkey: [u8; 32] = r.1.try_into().map_err(|_| {
                    StorageError::Conversion("invalid accepted_invites.inviter_pubkey length".into())
                })?;
                let expiry_unix = u64::try_from(r.2).map_err(|_| {
                    StorageError::Conversion(format!("negative accepted_invites.expiry_unix: {}", r.2))
                })?;
                let accepted_at = u64::try_from(r.3).map_err(|_| {
                    StorageError::Conversion(format!("negative accepted_invites.accepted_at: {}", r.3))
                })?;

                Ok(AcceptedInviteRecord {
                    nonce,
                    inviter_pubkey,
                    expiry_unix,
                    accepted_at,
                })
            })
            .collect()
    }

    async fn upsert_onboarding_state(
        &self,
        state: &OnboardingStateRecord,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO onboarding_state
                (id, invite_id, inviter_pubkey, inviter_ln_pubkey, current_step, tier, funding_address, funding_amount_sats_required, funding_amount_sats_received, last_poll_at, funding_evidence)
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(id) DO UPDATE SET
                invite_id = excluded.invite_id,
                inviter_pubkey = excluded.inviter_pubkey,
                inviter_ln_pubkey = excluded.inviter_ln_pubkey,
                current_step = excluded.current_step,
                tier = excluded.tier,
                funding_address = excluded.funding_address,
                funding_amount_sats_required = excluded.funding_amount_sats_required,
                funding_amount_sats_received = excluded.funding_amount_sats_received,
                last_poll_at = excluded.last_poll_at,
                funding_evidence = excluded.funding_evidence",
        )
        .bind(state.invite_id.map(|id| id.to_string()))
        .bind(state.inviter_pubkey.map(|bytes| bytes.to_vec()))
        .bind(&state.inviter_ln_pubkey)
        .bind(&state.current_step)
        .bind(&state.tier)
        .bind(&state.funding_address)
        .bind(state.funding_amount_sats_required.map(i64::from))
        .bind(i64::from(state.funding_amount_sats_received))
        .bind(state.last_poll_at.map(|v| v as i64))
        .bind(&state.funding_evidence)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_onboarding_state(&self) -> Result<Option<OnboardingStateRecord>, StorageError> {
        let row = sqlx::query_as::<
            _,
            (
                Option<String>,
                Option<Vec<u8>>,
                Option<String>,
                String,
                Option<String>,
                Option<String>,
                Option<i64>,
                i64,
                Option<i64>,
                Option<String>,
            ),
        >(
            "SELECT invite_id, inviter_pubkey, inviter_ln_pubkey, current_step, tier, funding_address, funding_amount_sats_required, funding_amount_sats_received, last_poll_at, funding_evidence
             FROM onboarding_state WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(|(invite_id, inviter_pubkey, inviter_ln_pubkey, current_step, tier, funding_address, req, recv, last_poll_at, funding_evidence)| {
            let invite_id = invite_id
                .map(|value| uuid::Uuid::parse_str(&value).map_err(|e| StorageError::Conversion(format!("onboarding_state.invite_id: {e}"))))
                .transpose()?;
            let inviter_pubkey = inviter_pubkey
                .map(|bytes| bytes.try_into().map_err(|_| StorageError::Conversion("onboarding_state.inviter_pubkey wrong length".into())))
                .transpose()?;
            let funding_amount_sats_required = req
                .map(|value| u32::try_from(value).map_err(|_| StorageError::Conversion("onboarding_state.funding_amount_sats_required out of range".into())))
                .transpose()?;
            let funding_amount_sats_received = u32::try_from(recv).map_err(|_| {
                StorageError::Conversion("onboarding_state.funding_amount_sats_received out of range".into())
            })?;
            let last_poll_at = last_poll_at
                .map(|value| u64::try_from(value).map_err(|_| StorageError::Conversion("onboarding_state.last_poll_at negative".into())))
                .transpose()?;

            Ok(OnboardingStateRecord {
                invite_id,
                inviter_pubkey,
                inviter_ln_pubkey,
                current_step,
                tier,
                funding_address,
                funding_amount_sats_required,
                funding_amount_sats_received,
                last_poll_at,
                funding_evidence,
            })
        })
        .transpose()
    }

    async fn store_calendar_event(&self, record: &CalendarEventRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO calendar_events
               (id, message_id, organizer, title, description, start_ms, end_ms, tz,
                location, attendees_json, recurrence_json, color, parent_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
             ON CONFLICT(id) DO UPDATE SET
               message_id      = excluded.message_id,
               title           = excluded.title,
               description     = excluded.description,
               start_ms        = excluded.start_ms,
               end_ms          = excluded.end_ms,
               tz              = excluded.tz,
               location        = excluded.location,
               attendees_json  = excluded.attendees_json,
               recurrence_json = excluded.recurrence_json,
               color           = excluded.color,
               parent_id       = excluded.parent_id",
        )
        .bind(&record.id)
        .bind(&record.message_id)
        .bind(&record.organizer)
        .bind(&record.title)
        .bind(&record.description)
        .bind(record.start_ms as i64)
        .bind(record.end_ms as i64)
        .bind(&record.tz)
        .bind(&record.location)
        .bind(&record.attendees_json)
        .bind(&record.recurrence_json)
        .bind(&record.color)
        .bind(&record.parent_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_calendar_event(&self, id: &str) -> Result<Option<CalendarEventRecord>, StorageError> {
        let row: Option<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            i64,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
                    location, attendees_json, recurrence_json, color, created_at, parent_id
             FROM calendar_events WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(
            |(id, message_id, organizer, title, description, start_ms, end_ms, tz,
              location, attendees_json, recurrence_json, color, created_at, parent_id)| {
                CalendarEventRecord {
                    id,
                    message_id,
                    organizer,
                    title,
                    description,
                    start_ms: start_ms as u64,
                    end_ms: end_ms as u64,
                    tz,
                    location,
                    attendees_json,
                    recurrence_json,
                    color,
                    created_at,
                    parent_id,
                }
            },
        ))
    }

    async fn list_calendar_events_in_range(
        &self,
        from_ms: u64,
        to_ms: u64,
        limit: u32,
    ) -> Result<Vec<CalendarEventRecord>, StorageError> {
        let rows: Vec<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            i64,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
                    location, attendees_json, recurrence_json, color, created_at, parent_id
             FROM calendar_events
             WHERE start_ms < ?2 AND end_ms > ?1
               AND recurrence_json IS NULL AND parent_id IS NULL
             ORDER BY start_ms ASC
             LIMIT ?3",
        )
        .bind(from_ms as i64)
        .bind(to_ms as i64)
        .bind(limit.min(500) as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, message_id, organizer, title, description, start_ms, end_ms, tz,
                  location, attendees_json, recurrence_json, color, created_at, parent_id)| {
                    CalendarEventRecord {
                        id,
                        message_id,
                        organizer,
                        title,
                        description,
                        start_ms: start_ms as u64,
                        end_ms: end_ms as u64,
                        tz,
                        location,
                        attendees_json,
                        recurrence_json,
                        color,
                        created_at,
                        parent_id,
                    }
                },
            )
            .collect())
    }

    async fn delete_calendar_event(&self, id: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM calendar_events WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_recurring_master_events(&self) -> Result<Vec<CalendarEventRecord>, StorageError> {
        let rows: Vec<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            i64,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
                    location, attendees_json, recurrence_json, color, created_at, parent_id
             FROM calendar_events
             WHERE recurrence_json IS NOT NULL AND parent_id IS NULL
             ORDER BY start_ms ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, message_id, organizer, title, description, start_ms, end_ms, tz,
                  location, attendees_json, recurrence_json, color, created_at, parent_id)| {
                    CalendarEventRecord {
                        id,
                        message_id,
                        organizer,
                        title,
                        description,
                        start_ms: start_ms as u64,
                        end_ms: end_ms as u64,
                        tz,
                        location,
                        attendees_json,
                        recurrence_json,
                        color,
                        created_at,
                        parent_id,
                    }
                },
            )
            .collect())
    }

    async fn list_calendar_exceptions_in_range(
        &self,
        from_ms: u64,
        to_ms: u64,
    ) -> Result<Vec<CalendarEventRecord>, StorageError> {
        let rows: Vec<(
            String,
            Option<String>,
            String,
            String,
            Option<String>,
            i64,
            i64,
            String,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT id, message_id, organizer, title, description, start_ms, end_ms, tz,
                    location, attendees_json, recurrence_json, color, created_at, parent_id
             FROM calendar_events
             WHERE parent_id IS NOT NULL AND start_ms < ?2 AND end_ms > ?1
             ORDER BY start_ms ASC",
        )
        .bind(from_ms as i64)
        .bind(to_ms as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(id, message_id, organizer, title, description, start_ms, end_ms, tz,
                  location, attendees_json, recurrence_json, color, created_at, parent_id)| {
                    CalendarEventRecord {
                        id,
                        message_id,
                        organizer,
                        title,
                        description,
                        start_ms: start_ms as u64,
                        end_ms: end_ms as u64,
                        tz,
                        location,
                        attendees_json,
                        recurrence_json,
                        color,
                        created_at,
                        parent_id,
                    }
                },
            )
            .collect())
    }

    async fn store_rsvp(&self, record: &RsvpRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO calendar_rsvps (id, event_id, responder, response, comment)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(event_id, responder) DO UPDATE SET
               response = excluded.response,
               comment  = excluded.comment",
        )
        .bind(&record.id)
        .bind(&record.event_id)
        .bind(&record.responder)
        .bind(&record.response)
        .bind(&record.comment)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn store_reaction(&self, record: &ReactionRecord) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT OR IGNORE INTO message_reactions (message_id, sender, emoji)
             VALUES (?1, ?2, ?3)",
        )
        .bind(&record.message_id)
        .bind(&record.sender)
        .bind(&record.emoji)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_reaction(
        &self,
        message_id: &str,
        sender: &str,
        emoji: &str,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "DELETE FROM message_reactions WHERE message_id = ?1 AND sender = ?2 AND emoji = ?3",
        )
        .bind(message_id)
        .bind(sender)
        .bind(emoji)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    async fn get_reactions_for_message(
        &self,
        message_id: &str,
    ) -> Result<Vec<ReactionRecord>, StorageError> {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT message_id, sender, emoji, created_at
             FROM message_reactions
             WHERE message_id = ?1
             ORDER BY created_at ASC",
        )
        .bind(message_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(message_id, sender, emoji, created_at)| ReactionRecord {
                message_id,
                sender,
                emoji,
                created_at,
            })
            .collect())
    }
    // -- Fiat Rate Snapshots -----------------------------------------------

    async fn store_fiat_rate_snapshot(
        &self,
        snapshot: &crate::fiat_snapshots::FiatRateSnapshot,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO fiat_rate_snapshots (date, currency, rate, source)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(date, currency) DO UPDATE SET
               rate   = excluded.rate,
               source = excluded.source",
        )
        .bind(&snapshot.date)
        .bind(&snapshot.currency)
        .bind(snapshot.rate)
        .bind(&snapshot.source)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_fiat_rate_snapshots(
        &self,
        from_date: &str,
        to_date: &str,
    ) -> Result<Vec<crate::fiat_snapshots::FiatRateSnapshot>, StorageError> {
        let rows: Vec<(String, String, f64, String, String)> = sqlx::query_as(
            "SELECT date, currency, rate, source, created_at
             FROM fiat_rate_snapshots
             WHERE date >= ?1 AND date <= ?2
             ORDER BY date DESC, currency ASC",
        )
        .bind(from_date)
        .bind(to_date)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(date, currency, rate, source, created_at)| {
                crate::fiat_snapshots::FiatRateSnapshot {
                    date,
                    currency,
                    rate,
                    source,
                    created_at,
                }
            })
            .collect())
    }

    async fn upsert_operator_hosting_contract(
        &self,
        contract: &OperatorHostingContract,
    ) -> Result<(), StorageError> {
        contract
            .validate()
            .map_err(|e| StorageError::Conversion(e.to_string()))?;
        let now = chrono::Utc::now().timestamp();

        sqlx::query(
            "INSERT INTO operator_hosting_contracts
                (id, tenant_pubkey, operator_pubkey, sats_per_day, started_at, last_paid_at, state, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(id) DO UPDATE SET
                tenant_pubkey = excluded.tenant_pubkey,
                operator_pubkey = excluded.operator_pubkey,
                sats_per_day = excluded.sats_per_day,
                started_at = excluded.started_at,
                last_paid_at = excluded.last_paid_at,
                state = excluded.state,
                updated_at = excluded.updated_at",
        )
        .bind(contract.id.to_string())
        .bind(contract.tenant_pubkey.to_hex())
        .bind(&contract.operator_pubkey)
        .bind(u64_to_i64(contract.sats_per_day, "sats_per_day")?)
        .bind(u64_to_i64(contract.started_at, "started_at")?)
        .bind(contract.last_paid_at.map(|ts| u64_to_i64(ts, "last_paid_at")).transpose()?)
        .bind(contract.state.as_str())
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_operator_hosting_contracts(
        &self,
    ) -> Result<Vec<OperatorHostingContract>, StorageError> {
        let rows: Vec<(String, String, String, i64, i64, Option<i64>, String)> =
            sqlx::query_as(
                "SELECT id, tenant_pubkey, operator_pubkey, sats_per_day, started_at, last_paid_at, state
                 FROM operator_hosting_contracts
                 ORDER BY started_at ASC",
            )
            .fetch_all(&self.pool)
            .await?;

        rows.into_iter()
            .map(|(id, tenant, operator, sats, started, last_paid, state)| {
                row_to_hosting_contract(id, tenant, operator, sats, started, last_paid, state)
            })
            .collect()
    }

    async fn update_operator_hosting_contract_state(
        &self,
        contract_id: &uuid::Uuid,
        state: HostingContractState,
        updated_at: u64,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE operator_hosting_contracts
             SET state = ?1, updated_at = ?2
             WHERE id = ?3",
        )
        .bind(state.as_str())
        .bind(u64_to_i64(updated_at, "updated_at")?)
        .bind(contract_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn mark_operator_hosting_contract_paid(
        &self,
        contract_id: &uuid::Uuid,
        last_paid_at: u64,
        updated_at: u64,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE operator_hosting_contracts
             SET last_paid_at = ?1, state = 'active', updated_at = ?2
             WHERE id = ?3",
        )
        .bind(u64_to_i64(last_paid_at, "last_paid_at")?)
        .bind(u64_to_i64(updated_at, "updated_at")?)
        .bind(contract_id.to_string())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn record_operator_hosting_payment(
        &self,
        payment: &OperatorHostingPayment,
    ) -> Result<bool, StorageError> {
        let result = sqlx::query(
            "INSERT OR IGNORE INTO operator_hosting_payments
                (payment_hash, contract_id, tenant_pubkey, operator_pubkey, amount_msat, paid_at, direction, preimage, memo, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        )
        .bind(&payment.payment_hash)
        .bind(payment.contract_id.to_string())
        .bind(payment.tenant_pubkey.to_hex())
        .bind(&payment.operator_pubkey)
        .bind(u64_to_i64(payment.amount_msat, "amount_msat")?)
        .bind(u64_to_i64(payment.paid_at, "paid_at")?)
        .bind(payment.direction.as_str())
        .bind(&payment.preimage)
        .bind(&payment.memo)
        .bind(chrono::Utc::now().timestamp())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn list_operator_hosting_payments(
        &self,
        contract_id: &uuid::Uuid,
    ) -> Result<Vec<OperatorHostingPayment>, StorageError> {
        let rows: Vec<(
            String,
            String,
            String,
            String,
            i64,
            i64,
            String,
            Option<String>,
            Option<String>,
        )> = sqlx::query_as(
            "SELECT payment_hash, contract_id, tenant_pubkey, operator_pubkey, amount_msat,
                    paid_at, direction, preimage, memo
             FROM operator_hosting_payments
             WHERE contract_id = ?1
             ORDER BY paid_at DESC",
        )
        .bind(contract_id.to_string())
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|(hash, id, tenant, operator, amount, paid_at, direction, preimage, memo)| {
                row_to_hosting_payment(
                    hash, id, tenant, operator, amount, paid_at, direction, preimage, memo,
                )
            })
            .collect()
    }
}

// ── NonceStore implementation for PaymentGate ────────────────────────────

#[async_trait]
impl konsensus_core::gate::NonceStore for SqliteStorage {
    async fn check_and_store(
        &self,
        nonce: &Nonce,
        sender: &NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.store_nonce(nonce, sender).await?)
    }
}

#[cfg(test)]
#[path = "tests/sqlite.rs"]
mod tests;
