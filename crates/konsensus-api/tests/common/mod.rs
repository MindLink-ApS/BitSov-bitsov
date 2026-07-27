#![allow(unused_imports)]
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use tower::ServiceExt;

use konsensus_core::gate::PaymentGate;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::chain::{BlockHeader, ChainError, ChainProvider, FeeEstimate, TrustLevel};
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection,
    PaymentStatus,
};
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::{MessageId, NodeId, Nonce, Recipient, RoomId};
use konsensus_core::UkmEnvelope;
use konsensus_message::PeerRegistry;
use konsensus_storage::error::StorageError;
use konsensus_storage::models::{OnboardingStateRecord, Peer, Room};
use konsensus_storage::InviteSchemaCapabilities;
use konsensus_storage::Storage;

use konsensus_api::audit::AuditLog;
use konsensus_api::auth;
use konsensus_api::rate_limit::RateLimiter;
use konsensus_api::state::AppState;
use konsensus_api::build_router;

// ─── Stub: In-memory Storage ────────────────────────────────────────

pub struct MemStorage {
    messages: Mutex<HashMap<String, UkmEnvelope>>,
    /// AES-GCM-encrypted plaintext blobs keyed by message id hex (mirrors prod).
    message_plaintext: Mutex<HashMap<String, Vec<u8>>>,
    rooms: Mutex<HashMap<String, Room>>,
    room_members: Mutex<HashMap<String, Vec<NodeId>>>,
    peers: Mutex<HashMap<String, Peer>>,
    files: Mutex<HashMap<String, konsensus_storage::FileRecord>>,
    invites_issued:
        Mutex<HashMap<uuid::Uuid, konsensus_storage::InviteIssuedRecord>>,
    accepted_invites:
        Mutex<HashMap<[u8; 16], konsensus_storage::AcceptedInviteRecord>>,
    onboarding_state: Mutex<Option<OnboardingStateRecord>>,
    invite_schema_capabilities: InviteSchemaCapabilities,
    fail_next_whitelist_write: Mutex<bool>,
}

impl MemStorage {
    pub fn new() -> Self {
        Self {
            messages: Mutex::new(HashMap::new()),
            message_plaintext: Mutex::new(HashMap::new()),
            rooms: Mutex::new(HashMap::new()),
            room_members: Mutex::new(HashMap::new()),
            peers: Mutex::new(HashMap::new()),
            files: Mutex::new(HashMap::new()),
            invites_issued: Mutex::new(HashMap::new()),
            accepted_invites: Mutex::new(HashMap::new()),
            onboarding_state: Mutex::new(None),
            invite_schema_capabilities: InviteSchemaCapabilities::v2_ready_default(),
            fail_next_whitelist_write: Mutex::new(false),
        }
    }

    pub fn new_v1_only() -> Self {
        Self {
            invite_schema_capabilities: InviteSchemaCapabilities::not_ready(),
            ..Self::new()
        }
    }

    pub fn fail_next_whitelist_write(&self) {
        *self.fail_next_whitelist_write.lock().unwrap() = true;
    }
}

#[async_trait]
impl Storage for MemStorage {
    async fn invite_schema_capabilities(
        &self,
    ) -> Result<InviteSchemaCapabilities, StorageError> {
        Ok(self.invite_schema_capabilities)
    }

    async fn store_message(&self, envelope: &UkmEnvelope) -> Result<(), StorageError> {
        self.messages
            .lock()
            .unwrap()
            .insert(envelope.id.to_hex(), envelope.clone());
        Ok(())
    }

    async fn get_message(&self, id: &MessageId) -> Result<Option<UkmEnvelope>, StorageError> {
        Ok(self.messages.lock().unwrap().get(&id.to_hex()).cloned())
    }

    async fn get_messages_for_recipient(
        &self,
        _recipient: &Recipient,
        limit: u32,
        _before_timestamp: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError> {
        let msgs = self.messages.lock().unwrap();
        Ok(msgs.values().take(limit as usize).cloned().collect())
    }

    async fn get_conversation_messages(
        &self,
        my_node_id: &str,
        peer_or_room_id: &str,
        is_room: bool,
        limit: u32,
        before_timestamp: Option<u64>,
    ) -> Result<Vec<UkmEnvelope>, StorageError> {
        let msgs = self.messages.lock().unwrap();
        let before = before_timestamp.unwrap_or(u64::MAX);
        let mut result: Vec<_> = msgs
            .values()
            .filter(|env| {
                if env.timestamp >= before {
                    return false;
                }
                if is_room {
                    if let Recipient::Room(ref rid) = env.recipient {
                        return rid.to_string() == peer_or_room_id;
                    }
                    false
                } else {
                    let sender_hex = env.sender.to_hex();
                    let recip_hex = match &env.recipient {
                        Recipient::Node(n) => n.to_hex(),
                        Recipient::Room(_) | Recipient::Broadcast => return false,
                    };
                    (sender_hex == peer_or_room_id && recip_hex == my_node_id)
                        || (sender_hex == my_node_id && recip_hex == peer_or_room_id)
                }
            })
            .cloned()
            .collect();
        result.sort_by_key(|p| std::cmp::Reverse(p.timestamp));
        result.truncate(limit as usize);
        Ok(result)
    }

    async fn delete_message(&self, id: &MessageId) -> Result<bool, StorageError> {
        Ok(self.messages.lock().unwrap().remove(&id.to_hex()).is_some())
    }

    async fn delete_messages_older_than(&self, before_ms: u64) -> Result<u64, StorageError> {
        let mut msgs = self.messages.lock().unwrap();
        let before_count = msgs.len();
        msgs.retain(|_, env| env.timestamp >= before_ms);
        Ok((before_count - msgs.len()) as u64)
    }

    async fn create_room(&self, room: &Room) -> Result<(), StorageError> {
        self.rooms
            .lock()
            .unwrap()
            .insert(room.id.to_string(), room.clone());
        Ok(())
    }

    async fn get_room(&self, id: &RoomId) -> Result<Option<Room>, StorageError> {
        Ok(self.rooms.lock().unwrap().get(&id.to_string()).cloned())
    }

    async fn list_rooms(&self) -> Result<Vec<Room>, StorageError> {
        Ok(self.rooms.lock().unwrap().values().cloned().collect())
    }

    async fn add_room_member(
        &self,
        room_id: &RoomId,
        member: &NodeId,
    ) -> Result<(), StorageError> {
        self.room_members
            .lock()
            .unwrap()
            .entry(room_id.to_string())
            .or_default()
            .push(*member);
        Ok(())
    }

    async fn remove_room_member(
        &self,
        room_id: &RoomId,
        member: &NodeId,
    ) -> Result<(), StorageError> {
        if let Some(members) = self.room_members.lock().unwrap().get_mut(&room_id.to_string()) {
            members.retain(|m| m != member);
        }
        Ok(())
    }

    async fn delete_room(&self, id: &RoomId) -> Result<bool, StorageError> {
        let rid = id.to_string();
        let existed = self.rooms.lock().unwrap().remove(&rid).is_some();
        self.room_members.lock().unwrap().remove(&rid);
        Ok(existed)
    }

    async fn get_room_members(&self, room_id: &RoomId) -> Result<Vec<NodeId>, StorageError> {
        Ok(self
            .room_members
            .lock()
            .unwrap()
            .get(&room_id.to_string())
            .cloned()
            .unwrap_or_default())
    }

    async fn upsert_peer(&self, peer: &Peer) -> Result<(), StorageError> {
        self.peers
            .lock()
            .unwrap()
            .insert(peer.node_id.to_hex(), peer.clone());
        Ok(())
    }

    async fn get_peer(&self, id: &NodeId) -> Result<Option<Peer>, StorageError> {
        Ok(self.peers.lock().unwrap().get(&id.to_hex()).cloned())
    }

    async fn list_peers(&self) -> Result<Vec<Peer>, StorageError> {
        Ok(self.peers.lock().unwrap().values().cloned().collect())
    }

    async fn delete_peer(&self, id: &NodeId) -> Result<bool, StorageError> {
        Ok(self.peers.lock().unwrap().remove(&id.to_hex()).is_some())
    }

    async fn store_nonce(&self, _nonce: &Nonce, _sender: &NodeId) -> Result<bool, StorageError> {
        Ok(true)
    }

    // Explicitly accept fresh payment hashes. The `Storage` trait default for
    // `store_payment_receipt` is fail-closed (returns an error) so that real
    // backends cannot silently skip economic replay protection. This in-memory
    // test stub mirrors `store_nonce` above and always reports "new"; dedicated
    // replay-rejection coverage lives against the real SQLite/Postgres backends
    // and the gate (see konsensus-storage and konsensus-core test suites).
    async fn store_payment_receipt(
        &self,
        _payment_hash: &[u8; 32],
        _sender: &NodeId,
        _message_id: &MessageId,
    ) -> Result<bool, StorageError> {
        Ok(true)
    }

    async fn has_nonce(&self, _nonce: &Nonce) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn store_session(&self, _peer_id: &NodeId, _state_blob: &[u8]) -> Result<(), StorageError> {
        Ok(())
    }

    async fn load_session(&self, _peer_id: &NodeId) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(None)
    }

    async fn delete_session(&self, _peer_id: &NodeId) -> Result<bool, StorageError> {
        Ok(false)
    }

    async fn list_sessions(&self) -> Result<Vec<NodeId>, StorageError> {
        Ok(Vec::new())
    }

    async fn queue_pending_delivery(&self, _: &MessageId, _: &NodeId) -> Result<(), StorageError> {
        Ok(())
    }

    async fn get_pending_for_peer(&self, _: &NodeId) -> Result<Vec<(MessageId, u32)>, StorageError> {
        Ok(Vec::new())
    }

    async fn remove_pending_delivery(&self, _: &MessageId, _: &NodeId) -> Result<(), StorageError> {
        Ok(())
    }

    async fn increment_pending_attempts(&self, _: &MessageId, _: &NodeId) -> Result<(), StorageError> {
        Ok(())
    }

    async fn get_pending_peers(&self) -> Result<Vec<NodeId>, StorageError> {
        Ok(Vec::new())
    }

    async fn clear_pending_for_peer(&self, _: &NodeId) -> Result<u64, StorageError> {
        Ok(0)
    }

    async fn cleanup_stale_pending(&self, _: u32) -> Result<u64, StorageError> {
        Ok(0)
    }

    async fn count_pending_deliveries(&self) -> Result<u64, StorageError> {
        Ok(0)
    }

    async fn cleanup_expired_nonces(&self, _max_age_secs: u64) -> Result<u64, StorageError> {
        Ok(0)
    }

    async fn store_file(&self, file: &konsensus_storage::FileRecord) -> Result<(), StorageError> {
        self.files.lock().unwrap().insert(file.id.clone(), file.clone());
        Ok(())
    }
    async fn get_file(&self, id: &str) -> Result<Option<konsensus_storage::FileRecord>, StorageError> {
        Ok(self.files.lock().unwrap().get(id).cloned())
    }
    async fn get_file_metadata(&self, _: &str) -> Result<Option<konsensus_storage::FileMetadata>, StorageError> {
        Ok(None)
    }
    async fn list_files(&self, _: u32) -> Result<Vec<konsensus_storage::FileMetadata>, StorageError> {
        Ok(vec![])
    }
    async fn delete_file(&self, id: &str) -> Result<bool, StorageError> {
        Ok(self.files.lock().unwrap().remove(id).is_some())
    }
    async fn store_message_plaintext(
        &self,
        id: &konsensus_core::MessageId,
        encrypted: &[u8],
    ) -> Result<(), StorageError> {
        self.message_plaintext
            .lock()
            .unwrap()
            .insert(id.to_hex(), encrypted.to_vec());
        Ok(())
    }
    async fn get_message_plaintext(
        &self,
        id: &konsensus_core::MessageId,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.message_plaintext.lock().unwrap().get(&id.to_hex()).cloned())
    }

    async fn add_invite_issued(
        &self,
        record: &konsensus_storage::InviteIssuedRecord,
    ) -> Result<(), StorageError> {
        self.invites_issued
            .lock()
            .unwrap()
            .insert(record.id, record.clone());
        Ok(())
    }

    async fn add_invite_and_whitelist(
        &self,
        invite: &konsensus_storage::InviteIssuedRecord,
        peer_pubkey: [u8; 32],
    ) -> Result<(), StorageError> {
        self.add_invite_issued(invite).await?;
        if let Err(e) = self
            .add_whitelisted_peer_with_invite_ref(peer_pubkey, invite.id)
            .await
        {
            self.invites_issued.lock().unwrap().remove(&invite.id);
            return Err(e);
        }

        Ok(())
    }

    async fn find_invite_issued(
        &self,
        id: &uuid::Uuid,
    ) -> Result<Option<konsensus_storage::InviteIssuedRecord>, StorageError> {
        Ok(self.invites_issued.lock().unwrap().get(id).cloned())
    }

    async fn list_invites_issued(
        &self,
    ) -> Result<Vec<konsensus_storage::InviteIssuedRecord>, StorageError> {
        Ok(self
            .invites_issued
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect())
    }

    async fn add_whitelisted_peer_with_invite_ref(
        &self,
        pubkey: [u8; 32],
        invite_id: uuid::Uuid,
    ) -> Result<(), StorageError> {
        let mut fail = self.fail_next_whitelist_write.lock().unwrap();
        if *fail {
            *fail = false;
            return Err(StorageError::Serialization(
                "injected whitelist write failure".into(),
            ));
        }
        drop(fail);

        let node_id = NodeId::from_bytes(pubkey);
        let mut peers = self.peers.lock().unwrap();
        let mut peer = peers
            .remove(&node_id.to_hex())
            .unwrap_or_else(|| Peer::new(node_id));
        peer.metadata["invite_ref"] = serde_json::Value::String(invite_id.to_string());
        peer.metadata["whitelist_source"] = serde_json::Value::String("invite".to_string());
        peers.insert(node_id.to_hex(), peer);
        Ok(())
    }

    async fn add_invite_and_whitelist_with_peer_metadata(
        &self,
        invite: &konsensus_storage::InviteIssuedRecord,
        peer_pubkey: [u8; 32],
        metadata_json: &str,
    ) -> Result<(), StorageError> {
        // Mirror of the real backends' atomic primitive (HARD-3): write the invite
        // row and the peer row whose metadata_json is taken verbatim — no
        // server-side invite_ref/whitelist_source merge — rolling the invite back
        // if the whitelist write fails, so both succeed or both roll back.
        self.add_invite_issued(invite).await?;
        if let Err(e) = self
            .add_whitelisted_peer_with_metadata(peer_pubkey, metadata_json)
            .await
        {
            self.invites_issued.lock().unwrap().remove(&invite.id);
            return Err(e);
        }
        Ok(())
    }

    async fn add_whitelisted_peer_with_metadata(
        &self,
        pubkey: [u8; 32],
        metadata_json: &str,
    ) -> Result<(), StorageError> {
        // Honour the same injected-failure hook the invite_ref variant uses so the
        // atomicity tests can force a whitelist-write failure on this path too.
        let mut fail = self.fail_next_whitelist_write.lock().unwrap();
        if *fail {
            *fail = false;
            return Err(StorageError::Serialization(
                "injected whitelist write failure".into(),
            ));
        }
        drop(fail);

        // The caller owns the metadata blob; overwrite the peer's metadata column
        // wholesale rather than merging individual keys. This matches the real
        // backends, where the blob is opaque (ciphertext under EncryptedStorage)
        // and must never be re-parsed or split.
        let metadata: serde_json::Value = serde_json::from_str(metadata_json).map_err(|e| {
            StorageError::Serialization(format!("invalid peer metadata_json: {e}"))
        })?;
        let node_id = NodeId::from_bytes(pubkey);
        let mut peers = self.peers.lock().unwrap();
        let mut peer = peers
            .remove(&node_id.to_hex())
            .unwrap_or_else(|| Peer::new(node_id));
        peer.metadata = metadata;
        peers.insert(node_id.to_hex(), peer);
        Ok(())
    }

    async fn add_accepted_invite(
        &self,
        record: &konsensus_storage::AcceptedInviteRecord,
    ) -> Result<(), StorageError> {
        // Mirror production semantics: a second insert with the same
        // nonce fails as an already-exists conflict.
        let mut map = self.accepted_invites.lock().unwrap();
        if map.contains_key(&record.nonce) {
            return Err(StorageError::AlreadyExists(
                "accepted invite already exists".into(),
            ));
        }
        map.insert(record.nonce, record.clone());
        Ok(())
    }

    async fn find_accepted_invite(
        &self,
        nonce: &[u8; 16],
    ) -> Result<Option<konsensus_storage::AcceptedInviteRecord>, StorageError> {
        Ok(self.accepted_invites.lock().unwrap().get(nonce).cloned())
    }

    async fn upsert_onboarding_state(
        &self,
        state: &OnboardingStateRecord,
    ) -> Result<(), StorageError> {
        *self.onboarding_state.lock().unwrap() = Some(state.clone());
        Ok(())
    }

    async fn get_onboarding_state(&self) -> Result<Option<OnboardingStateRecord>, StorageError> {
        Ok(self.onboarding_state.lock().unwrap().clone())
    }
}

// ─── Stub: Lightning Provider ───────────────────────────────────────

pub struct StubLightning;

#[async_trait]
impl LightningProvider for StubLightning {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        Ok(Invoice {
            bolt11: "lnbc1stub...".into(),
            payment_hash: "aa".repeat(32),
            amount_msat,
            description: description.to_string(),
            expiry_secs,
            created_at: 1_700_000_000,
        })
    }

    async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
        Ok(PaymentDetails {
            payment_hash: "bb".repeat(32),
            preimage: Some("cc".repeat(32)),
            amount_msat: 1000,
            status: PaymentStatus::Settled,
            direction: PaymentDirection::Outgoing,
            timestamp: 1_700_000_000,
            memo: None,
            fee_msat: None,
        })
    }

    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        Ok(PaymentDetails {
            payment_hash: payment_hash.to_string(),
            preimage: None,
            amount_msat: 1000,
            status: PaymentStatus::Pending,
            direction: PaymentDirection::Incoming,
            timestamp: 1_700_000_000,
            memo: None,
            fee_msat: None,
        })
    }

    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(100_000_000) // 100k sats
    }

    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        let mut payments = vec![
            PaymentDetails {
                payment_hash: "dd".repeat(32),
                preimage: Some("ee".repeat(32)),
                amount_msat: 25,
                status: PaymentStatus::Settled,
                direction: PaymentDirection::Outgoing,
                timestamp: 1_700_000_100,
                memo: Some("test message".into()),
                fee_msat: Some(1),
            },
            PaymentDetails {
                payment_hash: "ff".repeat(32),
                preimage: None,
                amount_msat: 50,
                status: PaymentStatus::Settled,
                direction: PaymentDirection::Incoming,
                timestamp: 1_700_000_200,
                memo: None,
                fee_msat: None,
            },
        ];
        payments.truncate(limit as usize);
        Ok(payments)
    }

    async fn keysend(
        &self,
        _dest_pubkey: &str,
        amount_msat: u64,
        _memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        Ok(PaymentDetails {
            payment_hash: "ab".repeat(32),
            preimage: Some("cd".repeat(32)),
            amount_msat,
            status: PaymentStatus::Settled,
            direction: PaymentDirection::Outgoing,
            timestamp: 1_700_000_000,
            memo: None,
            fee_msat: Some(1),
        })
    }

    async fn is_available(&self) -> bool {
        true
    }

    async fn get_funding_address(&self) -> Option<String> {
        Some("bcrt1qstubfundingaddress0000000000000000000000".into())
    }

    async fn send_onchain(
        &self,
        _address: &str,
        _amount_sats: u64,
        _fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        Ok("deadbeef".repeat(8))
    }

    async fn open_channel(
        &self,
        _peer_pubkey: &str,
        _peer_addr: &str,
        _amount_sats: u64,
        _announce: bool,
        _fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        Ok("stub-channel-id".into())
    }

    async fn close_channel(
        &self,
        channel_id: &str,
        force: bool,
    ) -> Result<Option<String>, LightningError> {
        if channel_id == "fail" {
            return Err(LightningError::Backend("stub close failed".into()));
        }
        let suffix = if force { "force" } else { "coop" };
        Ok(Some(format!("stub-closing-txid-{suffix}")))
    }
}

// ─── Stub: Chain Provider ───────────────────────────────────────────

pub struct StubChain;

#[async_trait]
impl ChainProvider for StubChain {
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::ServerTrust
    }

    async fn get_block_height(&self) -> Result<u64, ChainError> {
        Ok(850_000)
    }

    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        Ok(BlockHeader {
            height,
            hash: "00".repeat(32),
            timestamp: 1_700_000_000,
            bits: 0x1703_2e3b,
        })
    }

    async fn estimate_fee(&self, _target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        Ok(FeeEstimate {
            sat_per_vbyte: 5.0,
            target_blocks: 6,
        })
    }

    async fn is_tx_confirmed(
        &self,
        _txid: &str,
        _min_confirmations: u32,
    ) -> Result<bool, ChainError> {
        Ok(true)
    }

    async fn is_synced(&self) -> bool {
        true
    }
}

// ─── Stub: Pricing Engine ───────────────────────────────────────────

pub struct StubPricing;

#[async_trait]
impl PricingEngine for StubPricing {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
        Ok(10)
    }

    async fn get_category_price_msat(
        &self,
        _category: konsensus_core::kind::KindCategory,
    ) -> Result<u64, PricingError> {
        Ok(10)
    }
}

// ─── Stub: Transport ────────────────────────────────────────────────

pub struct StubTransport;

#[async_trait]
impl MessageTransport for StubTransport {
    async fn send(&self, _peer: &NodeId, _envelope: &UkmEnvelope) -> Result<(), TransportError> {
        Ok(())
    }

    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        // Block forever — tests don't call recv
        futures::future::pending().await
    }

    async fn connect(&self, _peer: &NodeId, _addr: &str) -> Result<(), TransportError> {
        Ok(())
    }

    async fn disconnect(&self, _peer: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }

    async fn is_connected(&self, _peer: &NodeId) -> bool {
        false
    }

    async fn connected_peers(&self) -> Vec<NodeId> {
        Vec::new()
    }
}

// ─── Test Helper ────────────────────────────────────────────────────

/// Build the production router for a test, injecting a loopback
/// `ConnectInfo` so the rate-limit middleware can identify the caller.
///
/// In production the router is served with
/// `into_make_service_with_connect_info::<SocketAddr>()`, which populates
/// every request with the real peer address. `tower`'s `oneshot` — used by
/// these integration tests — bypasses that, leaving `ConnectInfo` absent.
///
/// HARD-8 makes the rate-limit middleware fail closed on a missing client
/// IP (a missing address must NOT masquerade as loopback), so tests must
/// supply an address explicitly. `MockConnectInfo` is axum's sanctioned
/// mechanism for exactly this. We use loopback because the tests run on the
/// same host; it carries no special rate-limit exemption.
pub fn test_router(state: Arc<AppState>) -> axum::Router {
    use axum::extract::connect_info::MockConnectInfo;
    use std::net::{Ipv4Addr, SocketAddr};

    build_router(state).layer(MockConnectInfo(SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::LOCALHOST),
        50000,
    )))
}

pub fn test_identity() -> NodeIdentity {
    NodeIdentity::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
    )
    .unwrap()
}

pub fn test_state() -> Arc<AppState> {
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));

    Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    })
}

/// Fixed AES master key for the plaintext cache in cipher-enabled tests.
pub const TEST_PLAINTEXT_KEY: [u8; 32] = [0x11u8; 32];

/// The plaintext-cache cipher paired with [`TEST_PLAINTEXT_KEY`]; use it to seed
/// encrypted plaintext that a cipher-enabled `AppState` can decrypt.
pub fn test_plaintext_cipher() -> konsensus_crypto::PlaintextCacheCipher {
    konsensus_crypto::PlaintextCacheCipher::new(&TEST_PLAINTEXT_KEY)
}

/// Like [`test_state_with_storage`] but with the plaintext-cache cipher configured
/// (keyed by [`TEST_PLAINTEXT_KEY`]), so the message-plaintext and search endpoints
/// can decrypt cached blobs seeded via [`test_plaintext_cipher`].
pub fn test_state_with_storage_and_cipher(storage: Arc<dyn Storage>) -> Arc<AppState> {
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));

    Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage,
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: Some(Arc::new(test_plaintext_cipher())),
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    })
}

pub fn test_state_with_storage(storage: Arc<dyn Storage>) -> Arc<AppState> {
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));

    Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage,
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    })
}

pub fn auth_header(state: &AppState) -> String {
    let node_id_hex = state.identity.node_id().to_hex();
    let token = auth::create_token(&node_id_hex, &state.jwt_secret).unwrap();
    format!("Bearer {token}")
}


pub fn test_state_with_content_dir(dir: std::path::PathBuf) -> Arc<AppState> {
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));

    Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: Some(dir),
        web_page_price_msat: Some(50),
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    })
}

pub fn test_state_with_data_dir(dir: std::path::PathBuf) -> Arc<AppState> {
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));

    Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: Some(dir),
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: None,
    })
}

// ─── Connected Transport Stub ──────────────────────────────────────
//
// Unlike StubTransport (which returns is_connected=false for all peers),
// this transport tracks which peers are "connected" and records sent
// envelopes/frames for verification.

pub struct ConnectedStubTransport {
    pub connected: std::sync::Mutex<std::collections::HashSet<NodeId>>,
    pub sent_envelopes: std::sync::Mutex<Vec<(NodeId, UkmEnvelope)>>,
    /// Invoice request fulfiller: when send_raw_frame receives a
    /// RequestInvoice frame, this closure produces the InvoiceResponseData.
    /// Used to simulate the peer responding to invoice requests.
    pub invoice_responder: Option<Box<dyn Fn(String, u64) -> Option<konsensus_api::state::InvoiceResponseData> + Send + Sync>>,
    /// Shared reference to the invoice_requests map so the transport can
    /// fulfill pending requests (simulating the peer responding).
    pub invoice_requests: Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceResponseData>>>>,
}

impl ConnectedStubTransport {
    pub fn new(
        connected_peers: Vec<NodeId>,
        invoice_requests: Arc<tokio::sync::Mutex<HashMap<String, tokio::sync::oneshot::Sender<konsensus_api::state::InvoiceResponseData>>>>,
    ) -> Self {
        Self {
            connected: std::sync::Mutex::new(connected_peers.into_iter().collect()),
            sent_envelopes: std::sync::Mutex::new(Vec::new()),
            invoice_responder: None,
            invoice_requests,
        }
    }

    pub fn with_invoice_responder(
        mut self,
        responder: impl Fn(String, u64) -> Option<konsensus_api::state::InvoiceResponseData> + Send + Sync + 'static,
    ) -> Self {
        self.invoice_responder = Some(Box::new(responder));
        self
    }
}

#[async_trait]
impl MessageTransport for ConnectedStubTransport {
    async fn send(&self, peer: &NodeId, envelope: &UkmEnvelope) -> Result<(), TransportError> {
        if !self.connected.lock().unwrap().contains(peer) {
            return Err(TransportError::NotConnected(peer.to_hex()));
        }
        self.sent_envelopes.lock().unwrap().push((*peer, envelope.clone()));
        Ok(())
    }

    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        futures::future::pending().await
    }

    async fn connect(&self, _peer: &NodeId, _addr: &str) -> Result<(), TransportError> {
        Ok(())
    }

    async fn disconnect(&self, _peer: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }

    async fn is_connected(&self, peer: &NodeId) -> bool {
        self.connected.lock().unwrap().contains(peer)
    }

    async fn connected_peers(&self) -> Vec<NodeId> {
        self.connected.lock().unwrap().iter().cloned().collect()
    }

    async fn send_raw_frame(&self, _peer: &NodeId, frame_bytes: &[u8]) -> Result<(), TransportError> {
        // Parse the frame to detect invoice requests and auto-respond.
        if let Ok(frame) = konsensus_message::wire::Frame::from_bytes(frame_bytes) {
            if let konsensus_message::wire::Frame::RequestInvoice { ref request_id, amount_msat, .. } = frame {
                if let Some(ref responder) = self.invoice_responder {
                    if let Some(response_data) = responder(request_id.clone(), amount_msat) {
                        let invoice_requests = Arc::clone(&self.invoice_requests);
                        let req_id = request_id.clone();
                        // Fulfill the pending request asynchronously.
                        tokio::spawn(async move {
                            // Brief delay to simulate network round-trip.
                            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                            let mut map = invoice_requests.lock().await;
                            if let Some(tx) = map.remove(&req_id) {
                                let _ = tx.send(response_data);
                            }
                        });
                    }
                }
            }
        }
        Ok(())
    }
}


// ─── Test BOLT11 Invoice Helper ────────────────────────────────────

/// Create a valid BOLT11 invoice string for test purposes.
///
/// Uses the lightning-invoice InvoiceBuilder with a deterministic key.
pub fn create_test_bolt11(amount_msat: u64) -> String {
    use bitcoin::hashes::{sha256, Hash};
    use lightning_invoice::{Currency, InvoiceBuilder};

    let payment_hash = sha256::Hash::from_slice(&[0u8; 32]).unwrap();
    let payment_secret = lightning_invoice::PaymentSecret([42u8; 32]);

    let invoice = InvoiceBuilder::new(Currency::BitcoinTestnet)
        .description("konsensus test".into())
        .payment_hash(payment_hash)
        .payment_secret(payment_secret)
        .current_timestamp()
        .min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(amount_msat)
        .build_signed(|hash| {
            let secp = secp256k1::Secp256k1::new();
            let key = secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
            secp.sign_ecdsa_recoverable(hash, &key)
        })
        .unwrap();

    invoice.to_string()
}

// ─── E2EE Session Setup Helper ─────────────────────────────────────

/// Create a peer identity and establish an E2EE session with it in
/// the given session manager. Returns the peer's NodeId.
pub async fn setup_e2ee_session(session_manager: &konsensus_crypto::SessionManager) -> NodeId {
    setup_e2ee_session_with_mnemonic(
        session_manager,
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    )
    .await
}

/// Like [`setup_e2ee_session`], but lets the caller pick the peer's mnemonic so
/// multiple *distinct* peers can be established against the same session manager
/// (e.g. the members of a room fan-out). Returns the peer's NodeId.
pub async fn setup_e2ee_session_with_mnemonic(
    session_manager: &konsensus_crypto::SessionManager,
    mnemonic: &str,
) -> NodeId {
    let peer_identity = NodeIdentity::from_mnemonic(mnemonic, "").unwrap();
    let peer_id = *peer_identity.node_id();

    // Create the peer's session manager to get a prekey bundle.
    let peer_sm = konsensus_crypto::SessionManager::new(Arc::new(peer_identity));
    let peer_bundle = peer_sm.prekey_bundle().await;

    // Our session manager initiates a sender session with the peer.
    session_manager
        .initiate_session(&peer_id, &peer_bundle)
        .await
        .unwrap();

    peer_id
}


pub fn test_state_with_gossip() -> Arc<AppState> {
    let identity = Arc::new(test_identity());
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let session_manager = Arc::new(konsensus_crypto::SessionManager::new(Arc::new(test_identity())));

    Arc::new(AppState {
        identity: Arc::clone(&identity),
        storage: Arc::new(MemStorage::new()),
        lightning: Arc::new(StubLightning),
        chain: Arc::new(StubChain),
        pricing: Arc::new(StubPricing),
        gate: Arc::new(PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::new(StubTransport),
        session_manager,
        jwt_secret: "test-jwt-secret-for-api-tests".into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::new(AuditLog::open(tmp.path()).unwrap()),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        data_dir: None,
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        gossip_validator: Some(Arc::new(
            konsensus_gossip::GossipValidator::new(Default::default()),
        )),
    })
}

/// Helper: build a test UKM envelope and store it in state.
pub async fn store_test_envelope(state: &AppState) -> String {
    use konsensus_core::{PaymentProof, UkmEnvelopeBuilder};
    use sha2::{Digest, Sha256};

    let sender = *state.identity.node_id();
    let recipient = Recipient::Node(sender); // send to self for testing
    let preimage = [0xABu8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 10);

    let mut envelope = UkmEnvelopeBuilder::new(
        100, // KIND_CHAT
        sender,
        recipient,
        b"encrypted-test-data".to_vec(),
        proof,
    )
    .build();

    let sig = state.identity.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

    let msg_id = envelope.id.to_hex();
    state.storage.store_message(&envelope).await.unwrap();
    msg_id
}

/// Store a to-self message with a distinct id (varied by `distinct`) plus its
/// plaintext encrypted under [`test_plaintext_cipher`], so search/plaintext
/// endpoints on a cipher-enabled state can decrypt it. Returns the message id.
pub async fn store_test_message_with_plaintext(
    state: &AppState,
    distinct: &[u8],
    plaintext: &str,
) -> String {
    use konsensus_core::{PaymentProof, UkmEnvelopeBuilder};
    use sha2::{Digest, Sha256};

    let sender = *state.identity.node_id();
    let recipient = Recipient::Node(sender);
    let preimage = [0xABu8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 10);

    // `distinct` varies the ciphertext so each message gets a unique id.
    let mut envelope =
        UkmEnvelopeBuilder::new(100, sender, recipient, distinct.to_vec(), proof).build();
    let sig = state.identity.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

    let msg_id = envelope.id.to_hex();
    state.storage.store_message(&envelope).await.unwrap();

    let encrypted = test_plaintext_cipher().encrypt(plaintext.as_bytes()).unwrap();
    state
        .storage
        .store_message_plaintext(&envelope.id, &encrypted)
        .await
        .unwrap();
    msg_id
}
