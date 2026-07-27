//! Core types: MessageId, NodeId, RoomId, Nonce, Signature, PaymentProof, Recipient.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Serde helper for hex-encoding fixed-size byte arrays.
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize_32<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }

    pub fn deserialize_64<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }

    pub fn deserialize_24<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 24], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 24 bytes"))
    }
}

// ---------------------------------------------------------------------------
// MessageId — blake3 hash of content + nonce (32 bytes)
// ---------------------------------------------------------------------------

/// Unique identifier for a UKM, derived from blake3(ciphertext || nonce).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageId([u8; 32]);

impl Serialize for MessageId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for MessageId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl MessageId {
    /// Byte length of a MessageId.
    pub const LEN: usize = 32;

    /// Compute a MessageId from ciphertext and nonce.
    pub fn compute(ciphertext: &[u8], nonce: &Nonce) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(ciphertext);
        hasher.update(nonce.as_bytes());
        Self(*hasher.finalize().as_bytes())
    }

    /// Create from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Try to create from a byte slice.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CoreError> {
        let bytes: [u8; 32] = slice.try_into().map_err(|_| {
            CoreError::InvalidMessageId(format!("expected 32 bytes, got {}", slice.len()))
        })?;
        Ok(Self(bytes))
    }

    /// Parse from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, CoreError> {
        let bytes = hex::decode(s)?;
        Self::try_from_slice(&bytes)
    }

    /// Return the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// NodeId — Ed25519 public key (32 bytes), the root identity of a node
// ---------------------------------------------------------------------------

/// A node's public identity, derived from its Ed25519 verifying key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 32]);

impl Serialize for NodeId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl NodeId {
    /// Byte length of a NodeId.
    pub const LEN: usize = 32;

    /// Create from an ed25519-dalek VerifyingKey.
    pub fn from_verifying_key(key: &ed25519_dalek::VerifyingKey) -> Self {
        Self(key.to_bytes())
    }

    /// Create from raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Try to create from a byte slice.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CoreError> {
        let bytes: [u8; 32] = slice.try_into().map_err(|_| {
            CoreError::InvalidPublicKey(format!("expected 32 bytes, got {}", slice.len()))
        })?;
        Ok(Self(bytes))
    }

    /// Parse from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, CoreError> {
        let bytes = hex::decode(s)?;
        Self::try_from_slice(&bytes)
    }

    /// Convert back to an ed25519-dalek VerifyingKey.
    pub fn to_verifying_key(&self) -> Result<ed25519_dalek::VerifyingKey, CoreError> {
        ed25519_dalek::VerifyingKey::from_bytes(&self.0)
            .map_err(|e| CoreError::InvalidPublicKey(e.to_string()))
    }

    /// Return the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Compute a safety number for verifying identity with a peer.
    ///
    /// The safety number is a deterministic fingerprint derived from both
    /// node IDs via blake3. Both parties compute the same number regardless
    /// of who initiates, because the IDs are sorted before hashing.
    ///
    /// Returns a string of 12 groups of 5 digits (60 digits total),
    /// similar to Signal's safety numbers. Example:
    /// `12345 67890 11223 34455 66778 89900 11223 34455 66778 89900 11223 34455`
    pub fn safety_number(&self, peer: &NodeId) -> String {
        // Sort so both sides produce the same result
        let (a, b) = if self.0 < peer.0 {
            (&self.0, &peer.0)
        } else {
            (&peer.0, &self.0)
        };

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"konsensus-safety-number-v1");
        hasher.update(a);
        hasher.update(b);
        let hash = hasher.finalize();

        // Convert hash bytes to 12 groups of 5-digit numbers.
        // We need 12 groups but only have 32 bytes. Use overlapping windows
        // with a secondary hash for the remaining groups.
        let bytes = hash.as_bytes();
        let hash2 = blake3::hash(bytes);
        let bytes2 = hash2.as_bytes();
        let mut groups = Vec::with_capacity(12);
        for i in 0..12 {
            // Pick source bytes from hash1 (first 8 groups) or hash2 (last 4)
            let src = if i < 8 { bytes } else { bytes2 };
            let offset = (i % 8) * 4;
            let val = u32::from_be_bytes([src[offset], src[offset + 1], src[offset + 2], src[offset + 3]]);
            groups.push(format!("{:05}", val % 100_000));
        }
        groups.join(" ")
    }

    /// Compute a short fingerprint for display (8 hex characters).
    ///
    /// This is a truncated blake3 hash of the node ID, suitable for
    /// compact display in the UI (e.g., peer list badges).
    pub fn short_fingerprint(&self) -> String {
        let hash = blake3::hash(self.as_bytes());
        hex::encode(&hash.as_bytes()[..4]).to_uppercase()
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

// ---------------------------------------------------------------------------
// RoomId — UUID v4 identifying a group/room
// ---------------------------------------------------------------------------

/// Unique identifier for a group chat room.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoomId(uuid::Uuid);

impl RoomId {
    /// Generate a new random RoomId.
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Create from a UUID.
    pub fn from_uuid(uuid: uuid::Uuid) -> Self {
        Self(uuid)
    }

    /// Parse from a string (standard UUID format).
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let uuid = uuid::Uuid::parse_str(s)
            .map_err(|e| CoreError::InvalidRoomId(e.to_string()))?;
        Ok(Self(uuid))
    }

    /// Return the inner UUID.
    pub fn as_uuid(&self) -> &uuid::Uuid {
        &self.0
    }
}

impl Default for RoomId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RoomId({})", self.0)
    }
}

impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Recipient — who a message is addressed to
// ---------------------------------------------------------------------------

/// The destination of a UKM: either a specific node, a room, or broadcast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Recipient {
    /// Direct message to a single node.
    Node(NodeId),
    /// Message to a group room (MLS encrypted).
    Room(RoomId),
    /// Broadcast to all connected peers (gossip propagation).
    ///
    /// Legacy free gossip is disabled in launch-facing nodes until paid
    /// broadcast semantics land on the normal UKM payment-gated path. Only
    /// public data should ever use this variant — never private content.
    Broadcast,
}

// ---------------------------------------------------------------------------
// Nonce — 24-byte random value for replay protection
// ---------------------------------------------------------------------------

/// 24-byte nonce used for replay protection and MessageId derivation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce([u8; 24]);

impl Serialize for Nonce {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hex_serde::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        hex_serde::deserialize_24(deserializer).map(Self)
    }
}

impl Nonce {
    /// Byte length of a Nonce.
    pub const LEN: usize = 24;

    /// Generate a cryptographically random nonce.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 24];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 24]) -> Self {
        Self(bytes)
    }

    /// Try to create from a byte slice.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CoreError> {
        let bytes: [u8; 24] = slice.try_into().map_err(|_| {
            CoreError::InvalidNonce(format!("expected 24 bytes, got {}", slice.len()))
        })?;
        Ok(Self(bytes))
    }

    /// Return the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 24] {
        &self.0
    }
}

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({})", hex::encode(&self.0[..8]))
    }
}

// ---------------------------------------------------------------------------
// Signature — Ed25519 signature over envelope fields
// ---------------------------------------------------------------------------

/// Ed25519 signature (64 bytes) over the signable fields of a UKM envelope.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hex_serde::serialize(&self.0, serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        hex_serde::deserialize_64(deserializer).map(Self)
    }
}

impl Signature {
    /// Byte length of a Signature.
    pub const LEN: usize = 64;

    /// Create from an ed25519-dalek Signature.
    pub fn from_ed25519(sig: &ed25519_dalek::Signature) -> Self {
        Self(sig.to_bytes())
    }

    /// Create from raw 64 bytes.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Try to create from a byte slice.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CoreError> {
        let bytes: [u8; 64] = slice.try_into().map_err(|_| {
            CoreError::InvalidSignature(format!("expected 64 bytes, got {}", slice.len()))
        })?;
        Ok(Self(bytes))
    }

    /// Convert to an ed25519-dalek Signature.
    pub fn to_ed25519(&self) -> ed25519_dalek::Signature {
        ed25519_dalek::Signature::from_bytes(&self.0)
    }

    /// Return the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature({}...)", hex::encode(&self.0[..8]))
    }
}

// ---------------------------------------------------------------------------
// PaymentProof — proof that a Lightning payment was made
// ---------------------------------------------------------------------------

/// Proof that a Lightning payment was successfully completed.
///
/// Every UKM **must** carry a valid payment proof — this is Principle 2
/// ("Lightning Clearance = Message Gate"). An envelope without proof is
/// rejected fail-closed.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentProof {
    /// SHA-256 hash of the preimage, identifying the Lightning invoice.
    #[serde(
        serialize_with = "hex_serde::serialize",
        deserialize_with = "hex_serde::deserialize_32"
    )]
    pub payment_hash: [u8; 32],
    /// The 32-byte preimage that proves payment was made.
    #[serde(
        serialize_with = "hex_serde::serialize",
        deserialize_with = "hex_serde::deserialize_32"
    )]
    pub preimage: [u8; 32],
    /// Amount paid in millisatoshis.
    pub amount_msat: u64,
}

impl std::fmt::Debug for PaymentProof {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PaymentProof")
            .field("payment_hash", &hex::encode(self.payment_hash))
            .field("preimage", &"[REDACTED]")
            .field("amount_msat", &self.amount_msat)
            .finish()
    }
}

impl PaymentProof {
    /// Create a new payment proof.
    pub fn new(payment_hash: [u8; 32], preimage: [u8; 32], amount_msat: u64) -> Self {
        Self {
            payment_hash,
            preimage,
            amount_msat,
        }
    }

    /// Verify that the preimage matches the payment hash.
    ///
    /// The payment hash must equal SHA-256(preimage).
    /// Uses constant-time comparison to prevent timing oracle attacks.
    pub fn verify_preimage(&self) -> Result<(), CoreError> {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;
        let computed = Sha256::digest(self.preimage);
        if computed.as_slice().ct_eq(&self.payment_hash).into() {
            Ok(())
        } else {
            Err(CoreError::InvalidPaymentProof(
                "preimage does not match payment hash".into(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_compute_deterministic() {
        let nonce = Nonce::from_bytes([1u8; 24]);
        let ciphertext = b"hello encrypted world";
        let id1 = MessageId::compute(ciphertext, &nonce);
        let id2 = MessageId::compute(ciphertext, &nonce);
        assert_eq!(id1, id2);
    }

    #[test]
    fn message_id_different_inputs_differ() {
        let nonce = Nonce::from_bytes([1u8; 24]);
        let id1 = MessageId::compute(b"aaa", &nonce);
        let id2 = MessageId::compute(b"bbb", &nonce);
        assert_ne!(id1, id2);
    }

    #[test]
    fn message_id_hex_roundtrip() {
        let nonce = Nonce::from_bytes([42u8; 24]);
        let id = MessageId::compute(b"test", &nonce);
        let hex_str = id.to_hex();
        let parsed = MessageId::from_hex(&hex_str).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn node_id_from_hex_roundtrip() {
        let bytes = [7u8; 32];
        let node_id = NodeId::from_bytes(bytes);
        let hex_str = node_id.to_hex();
        let parsed = NodeId::from_hex(&hex_str).unwrap();
        assert_eq!(node_id, parsed);
    }

    #[test]
    fn node_id_verifying_key_roundtrip() {
        use ed25519_dalek::SigningKey;
        let signing = SigningKey::from_bytes(&[1u8; 32]);
        let verifying = signing.verifying_key();
        let node_id = NodeId::from_verifying_key(&verifying);
        let recovered = node_id.to_verifying_key().unwrap();
        assert_eq!(verifying, recovered);
    }

    #[test]
    fn room_id_parse_roundtrip() {
        let room = RoomId::new();
        let s = room.to_string();
        let parsed = RoomId::parse(&s).unwrap();
        assert_eq!(room, parsed);
    }

    #[test]
    fn nonce_generate_unique() {
        let n1 = Nonce::generate();
        let n2 = Nonce::generate();
        assert_ne!(n1, n2);
    }

    #[test]
    fn nonce_try_from_slice_rejects_bad_len() {
        let result = Nonce::try_from_slice(&[0u8; 16]);
        assert!(result.is_err());
    }

    #[test]
    fn signature_roundtrip() {
        let bytes = [99u8; 64];
        let sig = Signature::from_bytes(bytes);
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn payment_proof_verify_valid() {
        use sha2::{Digest, Sha256};
        let preimage = [42u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        let proof = PaymentProof::new(hash, preimage, 1000);
        assert!(proof.verify_preimage().is_ok());
    }

    #[test]
    fn payment_proof_verify_invalid() {
        let proof = PaymentProof::new([0u8; 32], [1u8; 32], 1000);
        assert!(proof.verify_preimage().is_err());
    }

    #[test]
    fn recipient_equality() {
        let node = NodeId::from_bytes([1u8; 32]);
        let r1 = Recipient::Node(node);
        let r2 = Recipient::Node(node);
        assert_eq!(r1, r2);

        let room = RoomId::new();
        let r3 = Recipient::Room(room);
        assert_ne!(r1, r3);
    }

    #[test]
    fn safety_number_is_symmetric() {
        let a = NodeId::from_bytes([1u8; 32]);
        let b = NodeId::from_bytes([2u8; 32]);
        assert_eq!(a.safety_number(&b), b.safety_number(&a));
    }

    #[test]
    fn safety_number_is_deterministic() {
        let a = NodeId::from_bytes([3u8; 32]);
        let b = NodeId::from_bytes([4u8; 32]);
        let sn1 = a.safety_number(&b);
        let sn2 = a.safety_number(&b);
        assert_eq!(sn1, sn2);
    }

    #[test]
    fn safety_number_differs_for_different_peers() {
        let a = NodeId::from_bytes([1u8; 32]);
        let b = NodeId::from_bytes([2u8; 32]);
        let c = NodeId::from_bytes([3u8; 32]);
        assert_ne!(a.safety_number(&b), a.safety_number(&c));
    }

    #[test]
    fn safety_number_format() {
        let a = NodeId::from_bytes([10u8; 32]);
        let b = NodeId::from_bytes([20u8; 32]);
        let sn = a.safety_number(&b);
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), 12, "safety number should have 12 groups");
        for group in &groups {
            assert_eq!(group.len(), 5, "each group should be 5 digits: {}", group);
            assert!(group.chars().all(|c| c.is_ascii_digit()), "group should be digits only: {}", group);
        }
    }

    #[test]
    fn short_fingerprint_format() {
        let a = NodeId::from_bytes([42u8; 32]);
        let fp = a.short_fingerprint();
        assert_eq!(fp.len(), 8, "fingerprint should be 8 hex chars");
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()), "should be hex: {}", fp);
    }

    #[test]
    fn short_fingerprint_deterministic() {
        let a = NodeId::from_bytes([7u8; 32]);
        assert_eq!(a.short_fingerprint(), a.short_fingerprint());
    }

    #[test]
    fn short_fingerprint_differs() {
        let a = NodeId::from_bytes([1u8; 32]);
        let b = NodeId::from_bytes([2u8; 32]);
        assert_ne!(a.short_fingerprint(), b.short_fingerprint());
    }

    // ── Recipient serialization ────────────────────────────────────────

    #[test]
    fn recipient_node_serialization_roundtrip() {
        let node = NodeId::from_bytes([0xAA; 32]);
        let r = Recipient::Node(node);
        let json = serde_json::to_string(&r).unwrap();
        let decoded: Recipient = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn recipient_room_serialization_roundtrip() {
        let room = RoomId::new();
        let r = Recipient::Room(room);
        let json = serde_json::to_string(&r).unwrap();
        let decoded: Recipient = serde_json::from_str(&json).unwrap();
        assert_eq!(r, decoded);
    }

    #[test]
    fn recipient_node_and_room_are_distinct_in_json() {
        let node = NodeId::from_bytes([0xBB; 32]);
        let room = RoomId::new();
        let node_json = serde_json::to_string(&Recipient::Node(node)).unwrap();
        let room_json = serde_json::to_string(&Recipient::Room(room)).unwrap();
        assert_ne!(node_json, room_json, "Node and Room must serialize differently");
    }

    // ── Nonce constructor tests ────────────────────────────────────────

    #[test]
    fn nonce_from_bytes_and_as_bytes() {
        let bytes = [42u8; 24];
        let nonce = Nonce::from_bytes(bytes);
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn nonce_try_from_slice_valid() {
        let bytes = [7u8; 24];
        let nonce = Nonce::try_from_slice(&bytes).unwrap();
        assert_eq!(nonce.as_bytes(), &bytes);
    }

    #[test]
    fn nonce_try_from_slice_wrong_length() {
        assert!(Nonce::try_from_slice(&[0u8; 16]).is_err());
        assert!(Nonce::try_from_slice(&[0u8; 32]).is_err());
        assert!(Nonce::try_from_slice(&[]).is_err());
    }

    #[test]
    fn nonce_generate_is_random() {
        let n1 = Nonce::generate();
        let n2 = Nonce::generate();
        assert_ne!(n1, n2, "two random nonces must not collide");
    }

    #[test]
    fn nonce_serialization_roundtrip() {
        let nonce = Nonce::generate();
        let json = serde_json::to_string(&nonce).unwrap();
        let decoded: Nonce = serde_json::from_str(&json).unwrap();
        assert_eq!(nonce, decoded);
    }

    // ── Signature constructor tests ────────────────────────────────────

    #[test]
    fn signature_try_from_slice_valid() {
        let bytes = [0xABu8; 64];
        let sig = Signature::try_from_slice(&bytes).unwrap();
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn signature_try_from_slice_wrong_length() {
        assert!(Signature::try_from_slice(&[0u8; 32]).is_err());
        assert!(Signature::try_from_slice(&[0u8; 63]).is_err());
        assert!(Signature::try_from_slice(&[0u8; 65]).is_err());
        assert!(Signature::try_from_slice(&[]).is_err());
    }

    // ── MessageId constructor tests ────────────────────────────────────

    #[test]
    fn message_id_try_from_slice_valid() {
        let bytes = [0xCDu8; 32];
        let mid = MessageId::try_from_slice(&bytes).unwrap();
        assert_eq!(mid.as_bytes(), &bytes);
    }

    #[test]
    fn message_id_try_from_slice_wrong_length() {
        assert!(MessageId::try_from_slice(&[0u8; 16]).is_err());
        assert!(MessageId::try_from_slice(&[0u8; 64]).is_err());
        assert!(MessageId::try_from_slice(&[]).is_err());
    }

    #[test]
    fn message_id_hex_roundtrip_full() {
        let mid = MessageId::from_bytes([0xEFu8; 32]);
        let hex = mid.to_hex();
        let decoded = MessageId::from_hex(&hex).unwrap();
        assert_eq!(mid, decoded);
    }

    // ── RoomId tests ───────────────────────────────────────────────────

    #[test]
    fn room_id_uuid_roundtrip() {
        let room = RoomId::new();
        let uuid = room.as_uuid();
        let room2 = RoomId::from_uuid(*uuid);
        assert_eq!(room, room2);
    }

    #[test]
    fn room_id_display_is_uuid_format() {
        let room = RoomId::new();
        let display = room.to_string();
        // UUID format: 8-4-4-4-12
        assert_eq!(display.len(), 36);
        assert_eq!(display.chars().filter(|c| *c == '-').count(), 4);
    }

    #[test]
    fn room_id_default_generates_unique() {
        let r1 = RoomId::default();
        let r2 = RoomId::default();
        assert_ne!(r1, r2);
    }

    // ── PaymentProof tests ─────────────────────────────────────────────

    #[test]
    fn payment_proof_new_sets_fields() {
        let hash = [1u8; 32];
        let preimage = [2u8; 32];
        let proof = PaymentProof::new(hash, preimage, 1000);
        assert_eq!(proof.payment_hash, hash);
        assert_eq!(proof.preimage, preimage);
        assert_eq!(proof.amount_msat, 1000);
    }

    #[test]
    fn payment_proof_serialization_roundtrip() {
        let proof = PaymentProof::new([0xAA; 32], [0xBB; 32], 50_000);
        let json = serde_json::to_string(&proof).unwrap();
        let decoded: PaymentProof = serde_json::from_str(&json).unwrap();
        assert_eq!(proof.payment_hash, decoded.payment_hash);
        assert_eq!(proof.preimage, decoded.preimage);
        assert_eq!(proof.amount_msat, decoded.amount_msat);
    }
}
