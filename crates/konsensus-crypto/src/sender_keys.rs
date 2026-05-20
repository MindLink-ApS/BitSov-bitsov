//! Sender Keys — group E2EE using symmetric key ratchets.
//!
//! Each group member maintains a **sender key** — a chain key that ratchets forward
//! with each message sent. Group messages are encrypted once with the sender's current
//! chain key (efficient: one encryption regardless of group size), and each member
//! can decrypt using the sender's chain key they received via their 1:1 Double Ratchet
//! channel.
//!
//! # Why Sender Keys instead of MLS (TreeKEM)
//!
//! MLS (RFC 9420) is designed for large groups with server-assisted delivery and
//! tree-based key management. In a sovereign mesh:
//! - All group members are already connected via pairwise 1:1 channels
//! - Groups are typically small (tens of members, not thousands)
//! - No central server exists to manage key trees
//! - Sender Keys maps cleanly to existing Double Ratchet infrastructure
//!
//! Sender Keys trade per-member post-compromise security for simplicity and
//! mesh-native operation. When a member is removed, all remaining members
//! rotate their sender keys (distributed via 1:1 channels), which provides
//! forward secrecy on eviction.
//!
//! # Protocol
//!
//! 1. When Alice joins/creates a group, she generates a `SenderKeyState` (random
//!    chain key + signing key pair).
//! 2. She distributes a `SenderKeyDistribution` message to each group member
//!    over their 1:1 Double Ratchet channel.
//! 3. To send a group message, Alice ratchets her chain key, derives a message
//!    key, and encrypts with AES-256-GCM. She signs the ciphertext with her
//!    signing key for authentication.
//! 4. Recipients look up Alice's sender key, derive the same message key,
//!    decrypt, and verify the signature.
//! 5. On member removal, every remaining member generates a new `SenderKeyState`
//!    and redistributes — the removed member cannot decrypt future messages.

use std::collections::HashMap;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesNonce};
use ed25519_dalek::{Signer, Verifier};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use konsensus_core::types::NodeId;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

/// Errors from Sender Keys operations.
#[derive(Debug, Error)]
pub enum SenderKeyError {
    /// No sender key found for the given member.
    #[error("no sender key for node {0}")]
    UnknownSender(String),

    /// Decryption failed (wrong key, tampered ciphertext).
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Encryption failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Signature verification failed.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Chain key is too far ahead (too many skipped messages).
    #[error("too many skipped messages: {0} (max {1})")]
    TooManySkipped(u32, u32),

    /// Invalid distribution message.
    #[error("invalid distribution: {0}")]
    InvalidDistribution(String),
}

/// Maximum number of skipped message keys to store per sender.
const MAX_SKIP: u32 = 256;

/// A sender key distribution message — sent to each group member via 1:1 channel.
///
/// This contains everything a recipient needs to decrypt future messages from
/// this sender in the group.
#[derive(Clone, Serialize, Deserialize)]
pub struct SenderKeyDistribution {
    /// The group this sender key belongs to.
    pub group_id: [u8; 32],
    /// The sender's node ID.
    pub sender: NodeId,
    /// The initial chain key (32 bytes).
    pub chain_key: [u8; 32],
    /// The sender's Ed25519 signing public key for message authentication.
    pub signing_key: [u8; 32],
    /// Generation counter — incremented on each key rotation.
    pub generation: u32,
}

impl std::fmt::Debug for SenderKeyDistribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderKeyDistribution")
            .field("group_id", &hex::encode(self.group_id))
            .field("sender", &self.sender)
            .field("chain_key", &"[REDACTED]")
            .field("signing_key", &hex::encode(self.signing_key))
            .field("generation", &self.generation)
            .finish()
    }
}

/// The local sender's key state — used to encrypt outgoing group messages.
pub struct SenderKeyState {
    /// Current chain key (ratchets forward with each message).
    chain_key: [u8; 32],
    /// Number of messages sent with this chain key generation.
    message_count: u32,
    /// Ed25519 signing key for message authentication.
    signing_key: ed25519_dalek::SigningKey,
    /// Generation counter.
    generation: u32,
}

impl Drop for SenderKeyState {
    fn drop(&mut self) {
        self.chain_key.zeroize();
    }
}

impl SenderKeyState {
    /// Generate a new sender key state with random keys.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut chain_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut chain_key);

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());

        Self {
            chain_key,
            message_count: 0,
            signing_key,
            generation: 0,
        }
    }

    /// Create a distribution message for this sender key.
    pub fn distribution(&self, group_id: [u8; 32], sender: NodeId) -> SenderKeyDistribution {
        SenderKeyDistribution {
            group_id,
            sender,
            chain_key: self.chain_key,
            signing_key: self.signing_key.verifying_key().to_bytes(),
            generation: self.generation,
        }
    }

    /// Rotate this sender key (generates new chain key + signing key).
    ///
    /// Called when a member is removed from the group. The old chain key is
    /// discarded — the removed member cannot derive future message keys.
    pub fn rotate(&mut self) {
        use rand::RngCore;
        let mut chain_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut chain_key);

        self.chain_key = chain_key;
        self.signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
        self.message_count = 0;
        self.generation += 1;
    }

    /// Encrypt a plaintext message for the group.
    ///
    /// Returns a `GroupCiphertext` containing the encrypted payload, message
    /// counter, signing key generation, and Ed25519 signature.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupCiphertext, SenderKeyError> {
        // Derive message key from chain key
        let (next_chain, message_key) = ratchet_chain_key(&self.chain_key);
        self.chain_key = next_chain;

        let msg_num = self.message_count;
        self.message_count += 1;

        // Encrypt with AES-256-GCM
        let nonce = derive_nonce(&message_key, msg_num);
        let cipher = Aes256Gcm::new((&message_key).into());
        let aes_nonce = AesNonce::from_slice(&nonce);

        let ciphertext = cipher
            .encrypt(aes_nonce, plaintext)
            .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))?;

        // Sign: generation || message_number || ciphertext
        let sig_payload = build_sig_payload(self.generation, msg_num, &ciphertext);
        let signature = self.signing_key.sign(&sig_payload);

        Ok(GroupCiphertext {
            generation: self.generation,
            message_number: msg_num,
            ciphertext,
            signature: signature.to_bytes(),
        })
    }
}

/// An encrypted group message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCiphertext {
    /// The sender key generation (for key rotation tracking).
    pub generation: u32,
    /// Message number within this generation.
    pub message_number: u32,
    /// The AES-256-GCM encrypted payload.
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature over (generation || message_number || ciphertext).
    #[serde(with = "hex_64")]
    pub signature: [u8; 64],
}

/// Serde helper for hex-encoding [u8; 64].
mod hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

/// Receiver-side state for a single sender's key within a group.
struct ReceiverSenderKey {
    /// Current chain key.
    chain_key: [u8; 32],
    /// How far we've ratcheted the chain key.
    chain_index: u32,
    /// Signing public key for authentication.
    signing_key: ed25519_dalek::VerifyingKey,
    /// Generation counter (must match incoming messages).
    generation: u32,
    /// Skipped message keys: message_number → message_key.
    skipped_keys: HashMap<u32, [u8; 32]>,
}

/// A group session managing sender keys for all members.
///
/// Each node maintains one `GroupSession` per group it participates in.
/// The session holds:
/// - The node's own `SenderKeyState` for encrypting outgoing messages
/// - `ReceiverSenderKey` entries for each other group member
pub struct GroupSession {
    /// The group identifier.
    group_id: [u8; 32],
    /// Our node ID.
    our_node_id: NodeId,
    /// Our sender key state (for encrypting).
    our_sender_key: SenderKeyState,
    /// Receiver-side sender keys for other members.
    member_keys: HashMap<NodeId, ReceiverSenderKey>,
}

impl GroupSession {
    /// Create a new group session.
    ///
    /// Generates a fresh sender key for the local node. The caller must distribute
    /// the resulting `SenderKeyDistribution` to all other group members via their
    /// 1:1 channels.
    pub fn new(group_id: [u8; 32], our_node_id: NodeId) -> Self {
        Self {
            group_id,
            our_node_id,
            our_sender_key: SenderKeyState::generate(),
            member_keys: HashMap::new(),
        }
    }

    /// Get the distribution message for our sender key.
    ///
    /// Send this to each group member over their 1:1 Double Ratchet channel.
    pub fn our_distribution(&self) -> SenderKeyDistribution {
        self.our_sender_key
            .distribution(self.group_id, self.our_node_id)
    }

    /// Process a sender key distribution from another group member.
    ///
    /// This registers or updates the member's sender key so we can decrypt
    /// their future group messages.
    pub fn process_distribution(
        &mut self,
        dist: &SenderKeyDistribution,
    ) -> Result<(), SenderKeyError> {
        if dist.group_id != self.group_id {
            return Err(SenderKeyError::InvalidDistribution(
                "group ID mismatch".into(),
            ));
        }

        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&dist.signing_key)
            .map_err(|e| SenderKeyError::InvalidDistribution(format!("bad signing key: {e}")))?;

        // If this is a newer generation, replace entirely
        // If same generation, it's a duplicate (idempotent)
        let entry = self.member_keys.entry(dist.sender).or_insert_with(|| {
            ReceiverSenderKey {
                chain_key: [0u8; 32],
                chain_index: 0,
                signing_key: verifying_key,
                generation: 0,
                skipped_keys: HashMap::new(),
            }
        });

        if dist.generation >= entry.generation {
            entry.chain_key = dist.chain_key;
            entry.chain_index = 0;
            entry.signing_key = verifying_key;
            entry.generation = dist.generation;
            entry.skipped_keys.clear();
        }

        Ok(())
    }

    /// Encrypt a plaintext message for the group.
    ///
    /// Uses our sender key — all group members who have our distribution
    /// can decrypt.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<GroupCiphertext, SenderKeyError> {
        self.our_sender_key.encrypt(plaintext)
    }

    /// Decrypt a group message from a specific sender.
    pub fn decrypt(
        &mut self,
        sender: &NodeId,
        message: &GroupCiphertext,
    ) -> Result<Vec<u8>, SenderKeyError> {
        let entry = self
            .member_keys
            .get_mut(sender)
            .ok_or_else(|| SenderKeyError::UnknownSender(sender.to_hex()))?;

        // Verify generation matches
        if message.generation != entry.generation {
            return Err(SenderKeyError::DecryptionFailed(format!(
                "generation mismatch: expected {}, got {}",
                entry.generation, message.generation
            )));
        }

        // Verify signature
        let sig_payload =
            build_sig_payload(message.generation, message.message_number, &message.ciphertext);
        let signature = ed25519_dalek::Signature::from_bytes(&message.signature);
        entry
            .signing_key
            .verify(&sig_payload, &signature)
            .map_err(|e| SenderKeyError::InvalidSignature(e.to_string()))?;

        // Check for skipped key
        if let Some(message_key) = entry.skipped_keys.remove(&message.message_number) {
            let nonce = derive_nonce(&message_key, message.message_number);
            return aead_decrypt(&message_key, &nonce, &message.ciphertext);
        }

        // Message is behind our chain — can't go backwards
        if message.message_number < entry.chain_index {
            return Err(SenderKeyError::DecryptionFailed(
                "message number behind chain index with no skipped key".into(),
            ));
        }

        // Check for too many skipped
        let skip_count = message.message_number - entry.chain_index;
        if skip_count > MAX_SKIP {
            return Err(SenderKeyError::TooManySkipped(skip_count, MAX_SKIP));
        }

        // Ratchet forward, storing skipped keys
        let mut chain_key = entry.chain_key;
        for i in entry.chain_index..message.message_number {
            let (next_chain, msg_key) = ratchet_chain_key(&chain_key);
            entry.skipped_keys.insert(i, msg_key);
            chain_key = next_chain;
        }

        // Derive the target message key
        let (next_chain, message_key) = ratchet_chain_key(&chain_key);
        entry.chain_key = next_chain;
        entry.chain_index = message.message_number + 1;

        let nonce = derive_nonce(&message_key, message.message_number);
        aead_decrypt(&message_key, &nonce, &message.ciphertext)
    }

    /// Remove a member from the group.
    ///
    /// This removes their sender key and rotates our own sender key.
    /// The caller must redistribute our new `SenderKeyDistribution` to
    /// all remaining members.
    pub fn remove_member(&mut self, node_id: &NodeId) -> SenderKeyDistribution {
        self.member_keys.remove(node_id);
        self.our_sender_key.rotate();
        self.our_distribution()
    }

    /// Get the set of group member NodeIds (excluding ourselves).
    pub fn members(&self) -> Vec<NodeId> {
        self.member_keys.keys().copied().collect()
    }

    /// Check if a specific member's sender key is registered.
    pub fn has_member(&self, node_id: &NodeId) -> bool {
        self.member_keys.contains_key(node_id)
    }

    /// The group identifier.
    pub fn group_id(&self) -> &[u8; 32] {
        &self.group_id
    }
}

// ─── Cryptographic primitives ────────────────────────────────────────────────

/// Ratchet a chain key forward: derive next chain key + message key.
fn ratchet_chain_key(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    type HmacSha256 = Hmac<Sha256>;

    // Message key: HMAC(chain_key, 0x01)
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC key length always valid");
    mac.update(&[0x01]);
    let msg_key_result = mac.finalize().into_bytes();
    let mut message_key = [0u8; 32];
    message_key.copy_from_slice(&msg_key_result);

    // Next chain key: HMAC(chain_key, 0x02)
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(chain_key).expect("HMAC key length always valid");
    mac.update(&[0x02]);
    let chain_result = mac.finalize().into_bytes();
    let mut next_chain = [0u8; 32];
    next_chain.copy_from_slice(&chain_result);

    (next_chain, message_key)
}

/// Derive a 12-byte AES-GCM nonce from a message key and message number.
fn derive_nonce(message_key: &[u8; 32], message_number: u32) -> [u8; 12] {
    let hkdf = Hkdf::<Sha256>::new(Some(message_key), &message_number.to_be_bytes());
    let mut nonce = [0u8; 12];
    hkdf.expand(b"konsensus-v2-sender-key-nonce", &mut nonce)
        .expect("12 bytes is a valid HKDF output length");
    nonce
}

/// Build the payload for Ed25519 signing: generation || message_number || ciphertext.
fn build_sig_payload(generation: u32, message_number: u32, ciphertext: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + ciphertext.len());
    payload.extend_from_slice(&generation.to_be_bytes());
    payload.extend_from_slice(&message_number.to_be_bytes());
    payload.extend_from_slice(ciphertext);
    payload
}

/// AES-256-GCM decrypt.
fn aead_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, SenderKeyError> {
    let cipher = Aes256Gcm::new(key.into());
    let aes_nonce = AesNonce::from_slice(nonce);
    cipher
        .decrypt(aes_nonce, ciphertext)
        .map_err(|e| SenderKeyError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
#[path = "tests/sender_keys.rs"]
mod tests;
