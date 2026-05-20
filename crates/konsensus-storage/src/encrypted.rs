//! EncryptedStorage wrapper — adds AES-256-GCM at-rest encryption.
//!
//! Wraps any `Storage` implementation and encrypts/decrypts sensitive fields
//! before/after storage. This ensures that even if the database is compromised,
//! message payloads and metadata remain encrypted.
//!
//! ## What is encrypted
//!
//! - **Message ciphertext** — the E2EE payload (already encrypted, defense-in-depth)
//! - **Peer metadata** — display_name, address, metadata (protects social graph / topology)
//! - **Room metadata** — name, metadata (protects group identifiers)
//! - **File metadata** — filename, mime_type (protects file content indicators)
//!
//! Principle 4: Data lives only on sender & receiver — no plaintext at any layer.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use async_trait::async_trait;
use rand::RngCore;

use hex;

use konsensus_core::{
    HostingContractState, MessageId, NodeId, Nonce, OperatorHostingContract,
    OperatorHostingPayment, Recipient, RoomId, UkmEnvelope, UkmEnvelopeBuilder,
};

use crate::calendar::{CalendarEventRecord, RsvpRecord};
use crate::error::StorageError;
use crate::invites::{AcceptedInviteRecord, InviteIssuedRecord, InviteSchemaCapabilities};
use crate::models::{
    merge_peer_metadata_preserving_invite_ref, FileMetadata, FileRecord, OnboardingStateRecord,
    Peer, Room,
};
use crate::traits::Storage;

/// AES-256-GCM at-rest encryption wrapper over any `Storage` backend.
///
/// Encrypts the ciphertext field before storing; decrypts after loading.
/// All other operations (rooms, peers, nonces) pass through unchanged.
pub struct EncryptedStorage<S: Storage> {
    inner: S,
    cipher: Aes256Gcm,
}

impl<S: Storage> EncryptedStorage<S> {
    /// Create a new encrypted storage wrapper.
    ///
    /// The `key` should be the 32-byte AES key from `NodeIdentity::aes_key()`.
    pub fn new(inner: S, key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key is always 32 bytes");
        Self { inner, cipher }
    }

    /// Encrypt data with a random 12-byte nonce.
    /// Returns nonce || ciphertext.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = AesNonce::from_slice(&nonce_bytes);

        let encrypted = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| StorageError::Encryption(format!("encrypt: {e}")))?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + encrypted.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    /// Decrypt data. Expects nonce (12 bytes) || ciphertext.
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, StorageError> {
        if data.len() < 12 {
            return Err(StorageError::Encryption(
                "encrypted data too short for nonce".into(),
            ));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = AesNonce::from_slice(nonce_bytes);

        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| StorageError::Encryption(format!("decrypt: {e}")))
    }

    /// Encrypt the ciphertext field of an envelope for storage.
    fn encrypt_envelope(&self, envelope: &UkmEnvelope) -> Result<UkmEnvelope, StorageError> {
        let encrypted_ct = self.encrypt(&envelope.ciphertext)?;

        // Rebuild envelope with encrypted ciphertext but same nonce/id
        // We need to set the ID manually since the ciphertext changed
        let mut encrypted = envelope.clone();
        encrypted.ciphertext = encrypted_ct;
        Ok(encrypted)
    }

    /// Decrypt the ciphertext field of an envelope after loading.
    fn decrypt_envelope(&self, envelope: &UkmEnvelope) -> Result<UkmEnvelope, StorageError> {
        let decrypted_ct = self.decrypt(&envelope.ciphertext)?;

        // Rebuild with original plaintext ciphertext and recompute ID
        let rebuilt = UkmEnvelopeBuilder::new(
            envelope.kind,
            envelope.sender,
            envelope.recipient,
            decrypted_ct,
            envelope.payment_proof.clone(),
        )
        .timestamp(envelope.timestamp)
        .nonce(envelope.nonce)
        .signature(envelope.signature)
        .references(envelope.references.clone())
        .build();

        Ok(rebuilt)
    }

    /// Encrypt a string field for at-rest storage.
    ///
    /// Returns the encrypted bytes as a hex-encoded string, suitable for
    /// TEXT columns in SQLite/PostgreSQL.
    fn encrypt_string(&self, plaintext: &str) -> Result<String, StorageError> {
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        Ok(hex::encode(encrypted))
    }

    /// Decrypt a hex-encoded encrypted string field.
    fn decrypt_string(&self, hex_ciphertext: &str) -> Result<String, StorageError> {
        let encrypted = hex::decode(hex_ciphertext)
            .map_err(|e| StorageError::Encryption(format!("hex decode: {e}")))?;
        let decrypted = self.decrypt(&encrypted)?;
        String::from_utf8(decrypted)
            .map_err(|e| StorageError::Encryption(format!("utf8 decode: {e}")))
    }

    /// Encrypt an optional string field.
    fn encrypt_opt_string(
        &self,
        opt: &Option<String>,
    ) -> Result<Option<String>, StorageError> {
        match opt {
            Some(s) => Ok(Some(self.encrypt_string(s)?)),
            None => Ok(None),
        }
    }

    /// Decrypt an optional hex-encoded encrypted string field.
    fn decrypt_opt_string(
        &self,
        opt: &Option<String>,
    ) -> Result<Option<String>, StorageError> {
        match opt {
            Some(s) => Ok(Some(self.decrypt_string(s)?)),
            None => Ok(None),
        }
    }

    /// Encrypt a serde_json::Value field (serialized to JSON string, then encrypted).
    fn encrypt_json(&self, value: &serde_json::Value) -> Result<serde_json::Value, StorageError> {
        let json_str = serde_json::to_string(value)
            .map_err(|e| StorageError::Encryption(format!("json serialize: {e}")))?;
        let encrypted = self.encrypt_string(&json_str)?;
        Ok(serde_json::Value::String(encrypted))
    }

    /// Decrypt a serde_json::Value field (hex string → decrypt → parse JSON).
    fn decrypt_json(&self, value: &serde_json::Value) -> Result<serde_json::Value, StorageError> {
        match value.as_str() {
            Some(hex_str) => {
                let json_str = self.decrypt_string(hex_str)?;
                serde_json::from_str(&json_str)
                    .map_err(|e| StorageError::Encryption(format!("json parse: {e}")))
            }
            None => {
                // Not encrypted (e.g., legacy data) — return as-is
                Ok(value.clone())
            }
        }
    }

    /// Encrypt a Peer's sensitive fields (display_name, address, metadata).
    fn encrypt_peer(&self, peer: &Peer) -> Result<Peer, StorageError> {
        Ok(Peer {
            node_id: peer.node_id,
            address: self.encrypt_opt_string(&peer.address)?,
            last_seen: peer.last_seen.clone(),
            display_name: self.encrypt_opt_string(&peer.display_name)?,
            metadata: self.encrypt_json(&peer.metadata)?,
        })
    }

    /// Decrypt a Peer's sensitive fields.
    fn decrypt_peer(&self, peer: &Peer) -> Result<Peer, StorageError> {
        Ok(Peer {
            node_id: peer.node_id,
            address: self.decrypt_opt_string(&peer.address)?,
            last_seen: peer.last_seen.clone(),
            display_name: self.decrypt_opt_string(&peer.display_name)?,
            metadata: self.decrypt_json(&peer.metadata)?,
        })
    }

    /// Encrypt a Room's sensitive fields (name, metadata).
    fn encrypt_room(&self, room: &Room) -> Result<Room, StorageError> {
        Ok(Room {
            id: room.id,
            name: self.encrypt_string(&room.name)?,
            created_by: room.created_by,
            created_at: room.created_at.clone(),
            metadata: self.encrypt_json(&room.metadata)?,
        })
    }

    /// Decrypt a Room's sensitive fields.
    fn decrypt_room(&self, room: &Room) -> Result<Room, StorageError> {
        Ok(Room {
            id: room.id,
            name: self.decrypt_string(&room.name)?,
            created_by: room.created_by,
            created_at: room.created_at.clone(),
            metadata: self.decrypt_json(&room.metadata)?,
        })
    }

    /// Encrypt a FileRecord's sensitive metadata fields (filename, mime_type).
    fn encrypt_file_record(&self, file: &FileRecord) -> Result<FileRecord, StorageError> {
        Ok(FileRecord {
            id: file.id.clone(),
            filename: self.encrypt_string(&file.filename)?,
            mime_type: self.encrypt_string(&file.mime_type)?,
            size_bytes: file.size_bytes,
            blake3_hash: file.blake3_hash.clone(),
            sender: file.sender.clone(),
            message_id: file.message_id.clone(),
            data: file.data.clone(),
            created_at: file.created_at.clone(),
        })
    }

    /// Decrypt a FileRecord's sensitive metadata fields.
    fn decrypt_file_record(&self, file: &FileRecord) -> Result<FileRecord, StorageError> {
        Ok(FileRecord {
            id: file.id.clone(),
            filename: self.decrypt_string(&file.filename)?,
            mime_type: self.decrypt_string(&file.mime_type)?,
            size_bytes: file.size_bytes,
            blake3_hash: file.blake3_hash.clone(),
            sender: file.sender.clone(),
            message_id: file.message_id.clone(),
            data: file.data.clone(),
            created_at: file.created_at.clone(),
        })
    }

    /// Decrypt a FileMetadata's sensitive fields.
    fn decrypt_file_metadata(&self, meta: &FileMetadata) -> Result<FileMetadata, StorageError> {
        Ok(FileMetadata {
            id: meta.id.clone(),
            filename: self.decrypt_string(&meta.filename)?,
            mime_type: self.decrypt_string(&meta.mime_type)?,
            size_bytes: meta.size_bytes,
            blake3_hash: meta.blake3_hash.clone(),
            sender: meta.sender.clone(),
            message_id: meta.message_id.clone(),
            created_at: meta.created_at.clone(),
        })
    }

    /// Get a reference to the inner storage.
    pub fn inner(&self) -> &S {
        &self.inner
    }
}

#[async_trait]
impl<S: Storage> Storage for EncryptedStorage<S> {
    async fn store_message(&self, envelope: &UkmEnvelope) -> Result<(), StorageError> {
        let encrypted = self.encrypt_envelope(envelope)?;
        self.inner.store_message(&encrypted).await
    }

    async fn get_message(&self, id: &MessageId) -> Result<Option<UkmEnvelope>, StorageError> {
        // The stored ID is based on encrypted ciphertext, so we can't look up
        // by the original ID directly. We need to search differently.
        // However, the ID in storage was computed from the *original* ciphertext
        // before encryption — wait, no. In encrypt_envelope we clone and replace
        // ciphertext, keeping the original ID. So the stored ID matches.
        match self.inner.get_message(id).await? {
            Some(encrypted) => Ok(Some(self.decrypt_envelope(&encrypted)?)),
            None => Ok(None),
        }
    }

    async fn get_messages_for_recipient(
        &self,
        recipient: &Recipient,
        limit: u32,
        before_timestamp: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError> {
        let encrypted = self
            .inner
            .get_messages_for_recipient(recipient, limit, before_timestamp)
            .await?;

        encrypted
            .iter()
            .map(|e| self.decrypt_envelope(e))
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
        let encrypted = self
            .inner
            .get_conversation_messages(my_node_id, peer_or_room_id, is_room, limit, before_timestamp)
            .await?;

        encrypted
            .iter()
            .map(|e| self.decrypt_envelope(e))
            .collect()
    }

    async fn delete_message(&self, id: &MessageId) -> Result<bool, StorageError> {
        self.inner.delete_message(id).await
    }

    async fn delete_messages_older_than(&self, before_ms: u64) -> Result<u64, StorageError> {
        self.inner.delete_messages_older_than(before_ms).await
    }

    // Room operations — encrypt name and metadata at rest
    async fn create_room(&self, room: &Room) -> Result<(), StorageError> {
        let encrypted = self.encrypt_room(room)?;
        self.inner.create_room(&encrypted).await
    }

    async fn get_room(&self, id: &RoomId) -> Result<Option<Room>, StorageError> {
        match self.inner.get_room(id).await? {
            Some(encrypted) => Ok(Some(self.decrypt_room(&encrypted)?)),
            None => Ok(None),
        }
    }

    async fn list_rooms(&self) -> Result<Vec<Room>, StorageError> {
        let encrypted = self.inner.list_rooms().await?;
        encrypted.iter().map(|r| self.decrypt_room(r)).collect()
    }

    async fn delete_room(&self, id: &RoomId) -> Result<bool, StorageError> {
        self.inner.delete_room(id).await
    }

    async fn add_room_member(&self, room_id: &RoomId, member: &NodeId) -> Result<(), StorageError> {
        self.inner.add_room_member(room_id, member).await
    }

    async fn remove_room_member(
        &self,
        room_id: &RoomId,
        member: &NodeId,
    ) -> Result<(), StorageError> {
        self.inner.remove_room_member(room_id, member).await
    }

    async fn get_room_members(&self, room_id: &RoomId) -> Result<Vec<NodeId>, StorageError> {
        self.inner.get_room_members(room_id).await
    }

    // Peer operations — encrypt display_name, address, metadata at rest
    async fn upsert_peer(&self, peer: &Peer) -> Result<(), StorageError> {
        let existing = match self.inner.get_peer(&peer.node_id).await? {
            Some(encrypted) => Some(self.decrypt_peer(&encrypted)?),
            None => None,
        };
        let mut merged_peer = peer.clone();
        merged_peer.metadata = merge_peer_metadata_preserving_invite_ref(
            &peer.metadata,
            existing.as_ref().map(|peer| &peer.metadata),
        );
        let encrypted = self.encrypt_peer(&merged_peer)?;
        self.inner.upsert_peer(&encrypted).await
    }

    async fn get_peer(&self, id: &NodeId) -> Result<Option<Peer>, StorageError> {
        match self.inner.get_peer(id).await? {
            Some(encrypted) => Ok(Some(self.decrypt_peer(&encrypted)?)),
            None => Ok(None),
        }
    }

    async fn list_peers(&self) -> Result<Vec<Peer>, StorageError> {
        let encrypted = self.inner.list_peers().await?;
        encrypted.iter().map(|p| self.decrypt_peer(p)).collect()
    }

    async fn delete_peer(&self, id: &NodeId) -> Result<bool, StorageError> {
        self.inner.delete_peer(id).await
    }

    // Nonce operations pass through unchanged
    async fn store_nonce(&self, nonce: &Nonce, sender: &NodeId) -> Result<bool, StorageError> {
        self.inner.store_nonce(nonce, sender).await
    }

    async fn has_nonce(&self, nonce: &Nonce) -> Result<bool, StorageError> {
        self.inner.has_nonce(nonce).await
    }

    async fn cleanup_expired_nonces(&self, max_age_secs: u64) -> Result<u64, StorageError> {
        self.inner.cleanup_expired_nonces(max_age_secs).await
    }

    // Session operations pass through — session blobs are encrypted
    // with AES-256-GCM by the SessionManager (domain-separated key)
    // before reaching storage. No double-encryption needed.
    async fn store_session(
        &self,
        peer_id: &NodeId,
        state_blob: &[u8],
    ) -> Result<(), StorageError> {
        self.inner.store_session(peer_id, state_blob).await
    }

    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.load_session(peer_id).await
    }

    async fn delete_session(&self, peer_id: &NodeId) -> Result<bool, StorageError> {
        self.inner.delete_session(peer_id).await
    }

    async fn list_sessions(&self) -> Result<Vec<NodeId>, StorageError> {
        self.inner.list_sessions().await
    }

    // ── Pending Deliveries (passthrough — no encryption needed) ─────

    async fn queue_pending_delivery(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError> {
        self.inner.queue_pending_delivery(message_id, recipient).await
    }

    async fn get_pending_for_peer(
        &self,
        recipient: &NodeId,
    ) -> Result<Vec<(MessageId, u32)>, StorageError> {
        self.inner.get_pending_for_peer(recipient).await
    }

    async fn remove_pending_delivery(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError> {
        self.inner.remove_pending_delivery(message_id, recipient).await
    }

    async fn increment_pending_attempts(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError> {
        self.inner.increment_pending_attempts(message_id, recipient).await
    }

    async fn get_pending_peers(&self) -> Result<Vec<NodeId>, StorageError> {
        self.inner.get_pending_peers().await
    }

    async fn count_pending_deliveries(&self) -> Result<u64, StorageError> {
        self.inner.count_pending_deliveries().await
    }

    async fn clear_pending_for_peer(&self, recipient: &NodeId) -> Result<u64, StorageError> {
        self.inner.clear_pending_for_peer(recipient).await
    }

    async fn cleanup_stale_pending(&self, max_attempts: u32) -> Result<u64, StorageError> {
        self.inner.cleanup_stale_pending(max_attempts).await
    }

    // ── Files — encrypt filename and mime_type at rest ─────

    async fn store_file(&self, file: &FileRecord) -> Result<(), StorageError> {
        let encrypted = self.encrypt_file_record(file)?;
        self.inner.store_file(&encrypted).await
    }

    async fn get_file(&self, id: &str) -> Result<Option<FileRecord>, StorageError> {
        match self.inner.get_file(id).await? {
            Some(encrypted) => Ok(Some(self.decrypt_file_record(&encrypted)?)),
            None => Ok(None),
        }
    }

    async fn get_file_metadata(&self, id: &str) -> Result<Option<FileMetadata>, StorageError> {
        match self.inner.get_file_metadata(id).await? {
            Some(encrypted) => Ok(Some(self.decrypt_file_metadata(&encrypted)?)),
            None => Ok(None),
        }
    }

    async fn list_files(&self, limit: u32) -> Result<Vec<FileMetadata>, StorageError> {
        let encrypted = self.inner.list_files(limit).await?;
        encrypted
            .iter()
            .map(|m| self.decrypt_file_metadata(m))
            .collect()
    }

    async fn delete_file(&self, id: &str) -> Result<bool, StorageError> {
        self.inner.delete_file(id).await
    }

    // ── Plaintext Cache (pass-through — caller pre-encrypts) ────────────

    async fn store_message_plaintext(
        &self,
        id: &MessageId,
        encrypted_plaintext: &[u8],
    ) -> Result<(), StorageError> {
        self.inner
            .store_message_plaintext(id, encrypted_plaintext)
            .await
    }

    async fn get_message_plaintext(
        &self,
        id: &MessageId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get_message_plaintext(id).await
    }

    // ── Invites (pass-through — invite rows contain signed protocol data) ─

    async fn invite_schema_capabilities(
        &self,
    ) -> Result<InviteSchemaCapabilities, StorageError> {
        self.inner.invite_schema_capabilities().await
    }

    async fn add_invite_issued(&self, record: &InviteIssuedRecord) -> Result<(), StorageError> {
        self.inner.add_invite_issued(record).await
    }

    async fn add_invite_and_whitelist(
        &self,
        invite: &InviteIssuedRecord,
        peer_pubkey: [u8; 32],
    ) -> Result<(), StorageError> {
        self.inner
            .add_invite_and_whitelist(invite, peer_pubkey)
            .await
    }

    async fn find_invite_issued(
        &self,
        id: &uuid::Uuid,
    ) -> Result<Option<InviteIssuedRecord>, StorageError> {
        self.inner.find_invite_issued(id).await
    }

    async fn list_invites_issued(&self) -> Result<Vec<InviteIssuedRecord>, StorageError> {
        self.inner.list_invites_issued().await
    }

    async fn find_pending_invite_for_invitee(
        &self,
        invitee_pubkey: &[u8; 32],
    ) -> Result<Option<InviteIssuedRecord>, StorageError> {
        self.inner.find_pending_invite_for_invitee(invitee_pubkey).await
    }

    async fn mark_invite_accepted(
        &self,
        id: &uuid::Uuid,
        now_unix: u64,
    ) -> Result<bool, StorageError> {
        self.inner.mark_invite_accepted(id, now_unix).await
    }

    async fn mark_invite_opening(
        &self,
        id: &uuid::Uuid,
        now_unix: u64,
    ) -> Result<bool, StorageError> {
        self.inner.mark_invite_opening(id, now_unix).await
    }

    async fn mark_invite_pending(&self, id: &uuid::Uuid) -> Result<bool, StorageError> {
        self.inner.mark_invite_pending(id).await
    }

    async fn mark_invite_expired(
        &self,
        id: &uuid::Uuid,
        now_unix: u64,
    ) -> Result<bool, StorageError> {
        self.inner.mark_invite_expired(id, now_unix).await
    }

    async fn revoke_invite(&self, id: &uuid::Uuid, now_unix: u64) -> Result<bool, StorageError> {
        self.inner.revoke_invite(id, now_unix).await
    }

    async fn add_whitelisted_peer_with_invite_ref(
        &self,
        pubkey: [u8; 32],
        invite_id: uuid::Uuid,
    ) -> Result<(), StorageError> {
        self.inner
            .add_whitelisted_peer_with_invite_ref(pubkey, invite_id)
            .await
    }

    async fn add_accepted_invite(
        &self,
        record: &AcceptedInviteRecord,
    ) -> Result<(), StorageError> {
        self.inner.add_accepted_invite(record).await
    }

    async fn find_accepted_invite(
        &self,
        nonce: &[u8; 16],
    ) -> Result<Option<AcceptedInviteRecord>, StorageError> {
        self.inner.find_accepted_invite(nonce).await
    }

    async fn list_active_accepted_invites(
        &self,
        now_unix: u64,
    ) -> Result<Vec<AcceptedInviteRecord>, StorageError> {
        self.inner.list_active_accepted_invites(now_unix).await
    }

    async fn upsert_onboarding_state(
        &self,
        state: &OnboardingStateRecord,
    ) -> Result<(), StorageError> {
        self.inner.upsert_onboarding_state(state).await
    }

    async fn get_onboarding_state(&self) -> Result<Option<OnboardingStateRecord>, StorageError> {
        self.inner.get_onboarding_state().await
    }

    // ── Calendar (pass-through — calendar metadata queried plaintext for indexing) ─

    async fn store_calendar_event(&self, record: &CalendarEventRecord) -> Result<(), StorageError> {
        self.inner.store_calendar_event(record).await
    }

    async fn get_calendar_event(&self, id: &str) -> Result<Option<CalendarEventRecord>, StorageError> {
        self.inner.get_calendar_event(id).await
    }

    async fn list_calendar_events_in_range(
        &self,
        from_ms: u64,
        to_ms: u64,
        limit: u32,
    ) -> Result<Vec<CalendarEventRecord>, StorageError> {
        self.inner.list_calendar_events_in_range(from_ms, to_ms, limit).await
    }

    async fn delete_calendar_event(&self, id: &str) -> Result<bool, StorageError> {
        self.inner.delete_calendar_event(id).await
    }

    async fn store_rsvp(&self, record: &RsvpRecord) -> Result<(), StorageError> {
        self.inner.store_rsvp(record).await
    }

    // ── Operator hosting (pass-through — contract state contains no message plaintext) ─

    async fn upsert_operator_hosting_contract(
        &self,
        contract: &OperatorHostingContract,
    ) -> Result<(), StorageError> {
        self.inner.upsert_operator_hosting_contract(contract).await
    }

    async fn list_operator_hosting_contracts(
        &self,
    ) -> Result<Vec<OperatorHostingContract>, StorageError> {
        self.inner.list_operator_hosting_contracts().await
    }

    async fn update_operator_hosting_contract_state(
        &self,
        contract_id: &uuid::Uuid,
        state: HostingContractState,
        updated_at: u64,
    ) -> Result<(), StorageError> {
        self.inner
            .update_operator_hosting_contract_state(contract_id, state, updated_at)
            .await
    }

    async fn mark_operator_hosting_contract_paid(
        &self,
        contract_id: &uuid::Uuid,
        last_paid_at: u64,
        updated_at: u64,
    ) -> Result<(), StorageError> {
        self.inner
            .mark_operator_hosting_contract_paid(contract_id, last_paid_at, updated_at)
            .await
    }

    async fn record_operator_hosting_payment(
        &self,
        payment: &OperatorHostingPayment,
    ) -> Result<bool, StorageError> {
        self.inner.record_operator_hosting_payment(payment).await
    }

    async fn list_operator_hosting_payments(
        &self,
        contract_id: &uuid::Uuid,
    ) -> Result<Vec<OperatorHostingPayment>, StorageError> {
        self.inner.list_operator_hosting_payments(contract_id).await
    }
}

// ── NonceStore implementation for PaymentGate ────────────────────────────

#[async_trait]
impl<S: Storage + konsensus_core::gate::NonceStore> konsensus_core::gate::NonceStore
    for EncryptedStorage<S>
{
    async fn check_and_store(
        &self,
        nonce: &Nonce,
        sender: &NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.inner.check_and_store(nonce, sender).await
    }
}

#[cfg(test)]
#[path = "tests/encrypted.rs"]
mod tests;
