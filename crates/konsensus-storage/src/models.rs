//! Storage model types for rooms and peers.

use serde::{Deserialize, Serialize};

use konsensus_core::{NodeId, RoomId};

/// A group chat room.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Room {
    /// Room identifier.
    pub id: RoomId,
    /// Human-readable room name.
    pub name: String,
    /// Node that created the room.
    pub created_by: NodeId,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Arbitrary metadata (JSON object).
    pub metadata: serde_json::Value,
}

impl Room {
    /// Create a new room with the given name and creator.
    pub fn new(name: String, created_by: NodeId) -> Self {
        Self {
            id: RoomId::new(),
            name,
            created_by,
            created_at: chrono::Utc::now().to_rfc3339(),
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

/// A stored file with metadata and encrypted data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    /// Unique file identifier (UUID).
    pub id: String,
    /// Original filename.
    pub filename: String,
    /// MIME type.
    pub mime_type: String,
    /// Size in bytes (of the original plaintext data).
    pub size_bytes: u64,
    /// blake3 hash of the original plaintext data (hex).
    pub blake3_hash: String,
    /// Node ID of the sender (hex).
    pub sender: String,
    /// Associated message ID (hex), if sent/received via UKM envelope.
    pub message_id: Option<String>,
    /// The file data (encrypted at rest by EncryptedStorage layer).
    #[serde(skip_serializing)]
    pub data: Vec<u8>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

/// File metadata without the data payload (for listing).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Unique file identifier (UUID).
    pub id: String,
    /// Original filename.
    pub filename: String,
    /// MIME type.
    pub mime_type: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// blake3 hash (hex).
    pub blake3_hash: String,
    /// Sender node ID (hex).
    pub sender: String,
    /// Associated message ID (hex).
    pub message_id: Option<String>,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}

impl From<&FileRecord> for FileMetadata {
    fn from(f: &FileRecord) -> Self {
        Self {
            id: f.id.clone(),
            filename: f.filename.clone(),
            mime_type: f.mime_type.clone(),
            size_bytes: f.size_bytes,
            blake3_hash: f.blake3_hash.clone(),
            sender: f.sender.clone(),
            message_id: f.message_id.clone(),
            created_at: f.created_at.clone(),
        }
    }
}

/// A known peer node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    /// The peer's node identity.
    pub node_id: NodeId,
    /// Network address (host:port).
    pub address: Option<String>,
    /// ISO 8601 timestamp of last contact.
    pub last_seen: Option<String>,
    /// Human-readable display name.
    pub display_name: Option<String>,
    /// Arbitrary metadata (JSON object).
    pub metadata: serde_json::Value,
}

pub(crate) fn merge_peer_metadata_preserving_invite_ref(
    incoming: &serde_json::Value,
    existing: Option<&serde_json::Value>,
) -> serde_json::Value {
    let mut merged = incoming.clone();
    let Some(existing_obj) = existing.and_then(|value| value.as_object()) else {
        return merged;
    };
    let Some(merged_obj) = merged.as_object_mut() else {
        return merged;
    };

    for key in ["invite_ref", "whitelist_source"] {
        if let Some(value) = existing_obj.get(key) {
            merged_obj.insert(key.to_string(), value.clone());
        }
    }

    merged
}

impl Peer {
    /// Create a new peer with just a node ID.
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            address: None,
            last_seen: None,
            display_name: None,
            metadata: serde_json::Value::Object(serde_json::Map::new()),
        }
    }
}

/// Persistent single-row onboarding progress state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingStateRecord {
    /// Optional invite identifier when the flow originated from a stored issued invite.
    pub invite_id: Option<uuid::Uuid>,
    /// Ed25519 BitSov node pubkey for the inviter this onboarding flow belongs to.
    pub inviter_pubkey: Option<[u8; 32]>,
    /// Lightning node pubkey advertised by the inviter during the session handshake.
    pub inviter_ln_pubkey: Option<String>,
    /// Current onboarding step.
    pub current_step: String,
    /// Selected tier (`"light"` or `"full"`), if chosen.
    pub tier: Option<String>,
    /// Funding address for full-tier onboarding.
    pub funding_address: Option<String>,
    /// Required funding amount in sats.
    pub funding_amount_sats_required: Option<u32>,
    /// Observed funding amount in sats.
    pub funding_amount_sats_received: u32,
    /// Last poll timestamp (unix seconds).
    pub last_poll_at: Option<u64>,
    /// Evidence marker for what was observed.
    pub funding_evidence: Option<String>,
}

#[cfg(test)]
#[path = "tests/models.rs"]
mod tests;
