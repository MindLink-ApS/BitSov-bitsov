//! Storage trait — the interface implemented by SQLite and PostgreSQL backends.

use async_trait::async_trait;

use konsensus_core::{
    HostingContractState, MessageId, NodeId, Nonce, OperatorHostingContract,
    OperatorHostingPayment, Recipient, RoomId, UkmEnvelope,
};

use crate::calendar::{CalendarEventRecord, RsvpRecord};
use crate::error::StorageError;
use crate::invites::{
    AcceptedInviteRecord, InviteIssuedRecord, InviteSchemaCapabilities, InviteState,
};
use crate::models::{FileMetadata, FileRecord, OnboardingStateRecord, Peer, Room};
use crate::reactions::ReactionRecord;

/// Backend-agnostic storage interface for UKM envelopes, rooms, peers, and nonces.
#[async_trait]
pub trait Storage: Send + Sync {
    // ── Messages ───────────────────────────────────────────────────────

    /// Store a UKM envelope.
    async fn store_message(&self, envelope: &UkmEnvelope) -> Result<(), StorageError>;

    /// Retrieve a message by its ID.
    async fn get_message(&self, id: &MessageId) -> Result<Option<UkmEnvelope>, StorageError>;

    /// Get messages for a recipient, newest first, with pagination.
    async fn get_messages_for_recipient(
        &self,
        recipient: &Recipient,
        limit: u32,
        before_timestamp: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError>;

    /// Get messages for a conversation (both sent and received), newest first.
    ///
    /// For peer conversations: returns messages where (sender=peer AND
    /// recipient=my_node) OR (sender=my_node AND recipient=peer).
    /// For room conversations: returns messages where recipient=room_id.
    ///
    /// This is the primary method for loading a conversation's full history,
    /// including outgoing messages that `get_messages_for_recipient` misses.
    async fn get_conversation_messages(
        &self,
        my_node_id: &str,
        peer_or_room_id: &str,
        is_room: bool,
        limit: u32,
        before_timestamp: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError>;

    /// Delete a message by ID. Returns true if a row was deleted.
    async fn delete_message(&self, id: &MessageId) -> Result<bool, StorageError>;

    /// Delete all messages older than the given timestamp (milliseconds since epoch).
    ///
    /// Used by the retention cleanup task. Returns the number of messages deleted.
    async fn delete_messages_older_than(&self, before_ms: u64) -> Result<u64, StorageError>;

    // ── Rooms ──────────────────────────────────────────────────────────

    /// Create a new room.
    async fn create_room(&self, room: &Room) -> Result<(), StorageError>;

    /// Get a room by ID.
    async fn get_room(&self, id: &RoomId) -> Result<Option<Room>, StorageError>;

    /// List all rooms.
    async fn list_rooms(&self) -> Result<Vec<Room>, StorageError>;

    /// Add a member to a room.
    async fn add_room_member(&self, room_id: &RoomId, member: &NodeId) -> Result<(), StorageError>;

    /// Remove a member from a room.
    async fn remove_room_member(
        &self,
        room_id: &RoomId,
        member: &NodeId,
    ) -> Result<(), StorageError>;

    /// Delete a room and all its memberships.
    ///
    /// Returns `true` if the room existed and was deleted.
    async fn delete_room(&self, id: &RoomId) -> Result<bool, StorageError>;

    /// Get all members of a room.
    async fn get_room_members(&self, room_id: &RoomId) -> Result<Vec<NodeId>, StorageError>;

    // ── Peers ──────────────────────────────────────────────────────────

    /// Insert or update a peer.
    async fn upsert_peer(&self, peer: &Peer) -> Result<(), StorageError>;

    /// Get a peer by node ID.
    async fn get_peer(&self, id: &NodeId) -> Result<Option<Peer>, StorageError>;

    /// List all known peers.
    async fn list_peers(&self) -> Result<Vec<Peer>, StorageError>;

    /// Delete a peer. Returns true if a row was deleted.
    async fn delete_peer(&self, id: &NodeId) -> Result<bool, StorageError>;

    // ── Nonces (replay protection) ─────────────────────────────────────

    /// Store a nonce for replay protection.
    /// Returns `false` if the nonce already exists (replay detected).
    async fn store_nonce(&self, nonce: &Nonce, sender: &NodeId) -> Result<bool, StorageError>;

    /// Check if a nonce has been seen before.
    async fn has_nonce(&self, nonce: &Nonce) -> Result<bool, StorageError>;

    /// Remove nonces older than `max_age_secs` seconds.
    ///
    /// Returns the number of nonces deleted. This prevents unbounded table
    /// growth over time. Nonces older than the max message age are no longer
    /// needed for replay protection since the timestamp check will reject
    /// messages that old anyway.
    async fn cleanup_expired_nonces(&self, max_age_secs: u64) -> Result<u64, StorageError>;

    // ── E2EE Sessions ──────────────────────────────────────────────────

    /// Store or update serialized E2EE session state for a peer.
    ///
    /// The `state_blob` is an opaque byte array (typically JSON-serialized
    /// `RatchetState`). The caller is responsible for encrypting it before
    /// storage if at-rest encryption is needed.
    async fn store_session(
        &self,
        peer_id: &NodeId,
        state_blob: &[u8],
    ) -> Result<(), StorageError>;

    /// Load serialized E2EE session state for a peer.
    ///
    /// Returns `None` if no session exists for this peer.
    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, StorageError>;

    /// Delete a stored session for a peer.
    ///
    /// Returns `true` if a session was deleted.
    async fn delete_session(&self, peer_id: &NodeId) -> Result<bool, StorageError>;

    /// List all peer IDs that have stored sessions.
    async fn list_sessions(&self) -> Result<Vec<NodeId>, StorageError>;

    // ── Pending Deliveries (message queue for offline peers) ─────────

    /// Queue a message for later delivery to a peer.
    ///
    /// Called when a message can't be delivered because the recipient is
    /// offline. The delivery will be retried when the peer reconnects.
    async fn queue_pending_delivery(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError>;

    /// Get all pending message IDs for a specific peer.
    ///
    /// Returns `(message_id, attempt_count)` pairs ordered by queue time.
    async fn get_pending_for_peer(
        &self,
        recipient: &NodeId,
    ) -> Result<Vec<(MessageId, u32)>, StorageError>;

    /// Remove a pending delivery after successful delivery.
    async fn remove_pending_delivery(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError>;

    /// Increment the attempt counter for a pending delivery.
    async fn increment_pending_attempts(
        &self,
        message_id: &MessageId,
        recipient: &NodeId,
    ) -> Result<(), StorageError>;

    /// Get all peer IDs that have pending deliveries.
    async fn get_pending_peers(&self) -> Result<Vec<NodeId>, StorageError>;

    /// Count total pending deliveries.
    async fn count_pending_deliveries(&self) -> Result<u64, StorageError>;

    /// Remove all pending deliveries for a specific peer.
    ///
    /// Called when an E2EE session is re-negotiated — pending messages encrypted
    /// with the old session keys become undeliverable and must be cleared.
    async fn clear_pending_for_peer(&self, recipient: &NodeId) -> Result<u64, StorageError>;

    /// Remove pending deliveries that have exceeded the maximum retry attempts.
    ///
    /// Returns the number of entries removed. This prevents unbounded table
    /// growth when a peer is permanently unreachable or messages are encrypted
    /// with stale keys that will never decrypt.
    async fn cleanup_stale_pending(&self, max_attempts: u32) -> Result<u64, StorageError>;

    // ── Files ──────────────────────────────────────────────────────────

    /// Store a file record (metadata + data).
    async fn store_file(&self, file: &FileRecord) -> Result<(), StorageError>;

    /// Get a file record by ID (includes data).
    async fn get_file(&self, id: &str) -> Result<Option<FileRecord>, StorageError>;

    /// Get file metadata only (no data payload).
    async fn get_file_metadata(&self, id: &str) -> Result<Option<FileMetadata>, StorageError>;

    /// List file metadata, newest first, with a limit.
    async fn list_files(&self, limit: u32) -> Result<Vec<FileMetadata>, StorageError>;

    /// Delete a file by ID. Returns true if a row was deleted.
    async fn delete_file(&self, id: &str) -> Result<bool, StorageError>;

    // ── Plaintext Cache ─────────────────────────────────────────────────

    /// Store cached (encrypted-at-rest) plaintext for a message.
    ///
    /// Called after the node decrypts an incoming E2EE message. The data
    /// is AES-256-GCM encrypted by the caller before storage — this method
    /// stores opaque bytes. The REST API retrieves and decrypts these bytes
    /// so the frontend can access decrypted content (e.g., for the sovereign
    /// browser's page responses).
    async fn store_message_plaintext(
        &self,
        id: &MessageId,
        encrypted_plaintext: &[u8],
    ) -> Result<(), StorageError>;

    /// Retrieve cached (encrypted-at-rest) plaintext for a message.
    ///
    /// Returns `None` if no plaintext was cached (e.g., decryption failed
    /// on receive, or the message predates the plaintext cache migration).
    async fn get_message_plaintext(
        &self,
        id: &MessageId,
    ) -> Result<Option<Vec<u8>>, StorageError>;

    // ── Invites (ON-B inviter flow) ────────────────────────────────────

    /// Report whether the local storage schema can persist BitSovInvite v2 fields.
    async fn invite_schema_capabilities(
        &self,
    ) -> Result<InviteSchemaCapabilities, StorageError> {
        Ok(InviteSchemaCapabilities::not_ready())
    }

    /// Persist a newly issued invite.
    async fn add_invite_issued(&self, _record: &InviteIssuedRecord) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "invite issuance storage not implemented for this backend".into(),
        ))
    }

    /// Atomically persist a newly issued invite and invite-derived whitelist entry.
    ///
    /// Backends must ensure both writes succeed or both are rolled back.
    async fn add_invite_and_whitelist(
        &self,
        _invite: &InviteIssuedRecord,
        _peer_pubkey: [u8; 32],
    ) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "atomic invite+whitelist storage not implemented for this backend".into(),
        ))
    }

    /// Find an issued invite by UUID.
    async fn find_invite_issued(
        &self,
        _id: &uuid::Uuid,
    ) -> Result<Option<InviteIssuedRecord>, StorageError> {
        Err(StorageError::Unsupported(
            "invite issuance storage not implemented for this backend".into(),
        ))
    }

    /// List all issued invites.
    async fn list_invites_issued(&self) -> Result<Vec<InviteIssuedRecord>, StorageError> {
        Err(StorageError::Unsupported(
            "invite issuance listing not implemented for this backend".into(),
        ))
    }

    /// Find the newest pending issued invite for a specific invitee public key.
    async fn find_pending_invite_for_invitee(
        &self,
        invitee_pubkey: &[u8; 32],
    ) -> Result<Option<InviteIssuedRecord>, StorageError> {
        let invites = self.list_invites_issued().await?;
        Ok(invites
            .into_iter()
            .filter(|invite| {
                invite.invitee_pubkey == *invitee_pubkey
                    && invite.state == InviteState::Pending
            })
            .max_by_key(|invite| invite.created_at))
    }

    /// Mark a pending issued invite accepted. Returns false if it was not pending.
    async fn mark_invite_accepted(
        &self,
        _id: &uuid::Uuid,
        _now_unix: u64,
    ) -> Result<bool, StorageError> {
        Err(StorageError::Unsupported(
            "invite accept-state update not implemented for this backend".into(),
        ))
    }

    /// Mark a pending issued invite as having an in-flight channel open.
    ///
    /// Returns false if the invite was not pending. This is used as the
    /// persisted idempotency gate before spending sats on automatic channel
    /// open, so duplicate peer events cannot race a second open while LDK is
    /// still negotiating the first channel.
    async fn mark_invite_opening(
        &self,
        _id: &uuid::Uuid,
        _now_unix: u64,
    ) -> Result<bool, StorageError> {
        Err(StorageError::Unsupported(
            "invite opening-state update not implemented for this backend".into(),
        ))
    }

    /// Roll an in-flight channel-open invite back to pending after open failure.
    async fn mark_invite_pending(&self, _id: &uuid::Uuid) -> Result<bool, StorageError> {
        Err(StorageError::Unsupported(
            "invite pending-state rollback not implemented for this backend".into(),
        ))
    }

    /// Mark a pending issued invite expired. Returns false if it was not pending.
    async fn mark_invite_expired(
        &self,
        _id: &uuid::Uuid,
        _now_unix: u64,
    ) -> Result<bool, StorageError> {
        Err(StorageError::Unsupported(
            "invite expiry-state update not implemented for this backend".into(),
        ))
    }

    /// Revoke an issued invite.
    async fn revoke_invite(&self, _id: &uuid::Uuid, _now_unix: u64) -> Result<bool, StorageError> {
        Err(StorageError::Unsupported(
            "invite revocation not implemented for this backend".into(),
        ))
    }

    /// Add a peer to the local whitelist and tag it with the issuing invite UUID.
    ///
    /// Backends should persist this so inviter-side invite revocation can remove
    /// invite-derived whitelist entries deterministically.
    async fn add_whitelisted_peer_with_invite_ref(
        &self,
        _pubkey: [u8; 32],
        _invite_id: uuid::Uuid,
    ) -> Result<(), StorageError> {
        Err(StorageError::Serialization(
            "invite-derived whitelist storage not implemented for this backend".into(),
        ))
    }

    /// Persist a newly accepted invite.
    async fn add_accepted_invite(
        &self,
        _record: &AcceptedInviteRecord,
    ) -> Result<(), StorageError> {
        Err(StorageError::Serialization(
            "accepted invite storage not implemented for this backend".into(),
        ))
    }

    /// Find an accepted invite by nonce.
    async fn find_accepted_invite(
        &self,
        _nonce: &[u8; 16],
    ) -> Result<Option<AcceptedInviteRecord>, StorageError> {
        Err(StorageError::Serialization(
            "accepted invite storage not implemented for this backend".into(),
        ))
    }

    /// List accepted invites whose original invite expiry is still in the future.
    ///
    /// Node startup uses this to replay invite-derived whitelist entries into
    /// the dynamic transport whitelist before accepting inbound peer traffic.
    async fn list_active_accepted_invites(
        &self,
        _now_unix: u64,
    ) -> Result<Vec<AcceptedInviteRecord>, StorageError> {
        Err(StorageError::Serialization(
            "accepted invite listing not implemented for this backend".into(),
        ))
    }

    // ── Onboarding state (ONB6 invitee funding) ─────────────────────────

    /// Upsert invitee onboarding state row (`id=1`).
    async fn upsert_onboarding_state(
        &self,
        _state: &OnboardingStateRecord,
    ) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "onboarding state storage not implemented for this backend".into(),
        ))
    }

    /// Load invitee onboarding state row (`id=1`).
    async fn get_onboarding_state(&self) -> Result<Option<OnboardingStateRecord>, StorageError> {
        Err(StorageError::Unsupported(
            "onboarding state storage not implemented for this backend".into(),
        ))
    }

    // ── Calendar ────────────────────────────────────────────────────────

    /// Insert or update a calendar event record (upsert by `id`).
    async fn store_calendar_event(&self, _record: &CalendarEventRecord) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "calendar storage not implemented for this backend".into(),
        ))
    }

    /// Retrieve a calendar event by its UUID.
    async fn get_calendar_event(&self, _id: &str) -> Result<Option<CalendarEventRecord>, StorageError> {
        Err(StorageError::Unsupported(
            "calendar storage not implemented for this backend".into(),
        ))
    }

    /// List calendar events whose time range overlaps `[from_ms, to_ms)`.
    async fn list_calendar_events_in_range(
        &self,
        _from_ms: u64,
        _to_ms: u64,
        _limit: u32,
    ) -> Result<Vec<CalendarEventRecord>, StorageError> {
        Err(StorageError::Unsupported(
            "calendar storage not implemented for this backend".into(),
        ))
    }

    /// Delete a calendar event by UUID. Returns `true` if a row was deleted.
    async fn delete_calendar_event(&self, _id: &str) -> Result<bool, StorageError> {
        Err(StorageError::Unsupported(
            "calendar storage not implemented for this backend".into(),
        ))
    }

    /// Insert or update an RSVP record (upsert by `(event_id, responder)`).
    async fn store_rsvp(&self, _record: &RsvpRecord) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "calendar storage not implemented for this backend".into(),
        ))
    }

    /// Return all recurring master events (recurrence_json IS NOT NULL, parent_id IS NULL).
    async fn list_recurring_master_events(&self) -> Result<Vec<CalendarEventRecord>, StorageError> {
        Err(StorageError::Unsupported(
            "calendar storage not implemented for this backend".into(),
        ))
    }

    /// Return exception/override records whose window overlaps `[from_ms, to_ms)`.
    async fn list_calendar_exceptions_in_range(
        &self,
        _from_ms: u64,
        _to_ms: u64,
    ) -> Result<Vec<CalendarEventRecord>, StorageError> {
        Err(StorageError::Unsupported(
            "calendar storage not implemented for this backend".into(),
        ))
    }

    // ── Reactions ───────────────────────────────────────────────────────

    /// Upsert a reaction record keyed by `(message_id, sender, emoji)`.
    ///
    /// If a reaction with the same `(message_id, sender, emoji)` already exists,
    /// this is a no-op (idempotent). To retract, call `delete_reaction`.
    async fn store_reaction(&self, _record: &ReactionRecord) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "reaction storage not implemented for this backend".into(),
        ))
    }

    /// Delete a reaction by `(message_id, sender, emoji)`.
    ///
    /// Returns `true` if a row was deleted (i.e., the reaction existed).
    async fn delete_reaction(
        &self,
        _message_id: &str,
        _sender: &str,
        _emoji: &str,
    ) -> Result<bool, StorageError> {
        Err(StorageError::Unsupported(
            "reaction storage not implemented for this backend".into(),
        ))
    }

    /// Return all reactions for a given message, ordered by creation time.
    async fn get_reactions_for_message(
        &self,
        _message_id: &str,
    ) -> Result<Vec<ReactionRecord>, StorageError> {
        Err(StorageError::Unsupported(
            "reaction storage not implemented for this backend".into(),
        ))
    }
    // -- Fiat Rate Snapshots -----------------------------------------------

    /// Persist (or update) a daily fiat exchange-rate snapshot.
    ///
    /// Uses upsert semantics keyed on `(date, currency)` -- repeated writes for
    /// the same day overwrite with the latest rate and source, so the task is
    /// safe to restart mid-day.
    async fn store_fiat_rate_snapshot(
        &self,
        _snapshot: &crate::fiat_snapshots::FiatRateSnapshot,
    ) -> Result<(), StorageError> {
        Err(StorageError::Unsupported(
            "fiat rate snapshots not implemented for this backend".into(),
        ))
    }

    /// Return all snapshots whose date falls in `[from_date, to_date]` (inclusive).
    ///
    /// Both bounds are ISO-8601 date strings (`"YYYY-MM-DD"`).  Results are
    /// ordered `date DESC, currency ASC`.
    async fn list_fiat_rate_snapshots(
        &self,
        _from_date: &str,
        _to_date: &str,
    ) -> Result<Vec<crate::fiat_snapshots::FiatRateSnapshot>, StorageError> {
        Err(StorageError::Unsupported(
            "fiat rate snapshots not implemented for this backend".into(),
        ))
    }

    // -- Operator Hosting Contracts ----------------------------------------

    /// Insert or update an operator hosting contract.
    async fn upsert_operator_hosting_contract(
        &self,
        _contract: &OperatorHostingContract,
    ) -> Result<(), StorageError> {
        Err(StorageError::Serialization(
            "operator hosting contracts not implemented for this backend".into(),
        ))
    }

    /// Return all operator hosting contracts known to this node.
    async fn list_operator_hosting_contracts(
        &self,
    ) -> Result<Vec<OperatorHostingContract>, StorageError> {
        Err(StorageError::Serialization(
            "operator hosting contracts not implemented for this backend".into(),
        ))
    }

    /// Update only the contract state.
    async fn update_operator_hosting_contract_state(
        &self,
        _contract_id: &uuid::Uuid,
        _state: HostingContractState,
        _updated_at: u64,
    ) -> Result<(), StorageError> {
        Err(StorageError::Serialization(
            "operator hosting contracts not implemented for this backend".into(),
        ))
    }

    /// Update state and last paid timestamp after a successful tenant payment.
    async fn mark_operator_hosting_contract_paid(
        &self,
        _contract_id: &uuid::Uuid,
        _last_paid_at: u64,
        _updated_at: u64,
    ) -> Result<(), StorageError> {
        Err(StorageError::Serialization(
            "operator hosting contracts not implemented for this backend".into(),
        ))
    }

    /// Record a hosting payment. Returns `true` when a row was inserted.
    async fn record_operator_hosting_payment(
        &self,
        _payment: &OperatorHostingPayment,
    ) -> Result<bool, StorageError> {
        Err(StorageError::Serialization(
            "operator hosting payments not implemented for this backend".into(),
        ))
    }

    /// List payments for a hosting contract, newest first.
    async fn list_operator_hosting_payments(
        &self,
        _contract_id: &uuid::Uuid,
    ) -> Result<Vec<OperatorHostingPayment>, StorageError> {
        Err(StorageError::Serialization(
            "operator hosting payments not implemented for this backend".into(),
        ))
    }
}
