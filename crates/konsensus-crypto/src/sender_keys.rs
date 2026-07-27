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
//!    key, and encrypts with AES-256-GCM. The AEAD associated data binds the
//!    ciphertext to its `(format_version, group_id, sender_id, generation,
//!    message_number)` context so it cannot be replayed into a different group,
//!    attributed to a different sender, or have its counters rewritten. She
//!    signs the ciphertext with her signing key for authentication.
//! 4. Recipients look up Alice's sender key, derive the same message key,
//!    reconstruct the AEAD associated data from *their own* session context
//!    (group + claimed sender + message counters), decrypt, and verify the
//!    signature. A context mismatch fails the AEAD tag check before any
//!    plaintext is produced.
//! 5. On member removal, every remaining member generates a new `SenderKeyState`
//!    and redistributes — the removed member cannot decrypt future messages.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, Payload};
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

/// AEAD framing version for group ciphertexts.
///
/// Version 1 is the original framing: AES-256-GCM with **no** associated data
/// and a nonce derived from `(message_key, message_number)` only. It is kept as
/// a named constant for documentation and forward-compatibility but is no longer
/// produced or accepted — there are no live group sessions on the wire yet, so
/// this is a clean break rather than a dual-decode path.
///
/// Version 2 (current) binds `(format_version, group_id, sender_id, generation,
/// message_number)` as AEAD associated data and folds the same context into the
/// nonce derivation for domain separation. The version byte is itself part of
/// the associated data, so downgrading the framing is detectable: a v1 reader
/// could never produce the v2 tag, and a v2 reader rebuilds the v2 AAD.
const SENDER_KEY_AEAD_VERSION: u8 = 2;

/// Domain-separation tag mixed into the AEAD associated data and the nonce
/// HKDF. Distinguishes group sender-key ciphertexts from every other AEAD use
/// in the crate (e.g. the Double Ratchet), so a key/ciphertext can never be
/// cross-applied between protocols even if a key were ever reused.
const SENDER_KEY_AAD_DOMAIN: &[u8] = b"konsensus-v2-sender-key-aead";

/// HKDF `info` tag for the group message nonce. Kept distinct from the AAD
/// domain tag so the nonce stream and the AAD never collide.
const SENDER_KEY_NONCE_INFO: &[u8] = b"konsensus-v2-sender-key-nonce-v2";

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
    /// `group_id` / `sender` identify the context this ciphertext is produced
    /// for; they are bound into the AEAD associated data (alongside the
    /// generation and message number) so the ciphertext cannot be replayed into
    /// another group or attributed to another sender. They are *not* placed on
    /// the wire — the recipient reconstructs them from its own session state.
    ///
    /// Returns a `GroupCiphertext` containing the encrypted payload, message
    /// counter, signing key generation, and Ed25519 signature.
    pub fn encrypt(
        &mut self,
        group_id: &[u8; 32],
        sender: &NodeId,
        plaintext: &[u8],
    ) -> Result<GroupCiphertext, SenderKeyError> {
        // Derive message key from chain key
        let (next_chain, message_key) = ratchet_chain_key(&self.chain_key);
        self.chain_key = next_chain;

        let msg_num = self.message_count;
        self.message_count += 1;

        // Bind (version, group, sender, generation, message number) as AEAD AAD.
        let aad = build_aad(group_id, sender, self.generation, msg_num);

        // Encrypt with AES-256-GCM (nonce + AAD both context-bound).
        let ciphertext = aead_encrypt(&message_key, plaintext, &aad)?;

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
        let group_id = self.group_id;
        let our_node_id = self.our_node_id;
        self.our_sender_key
            .encrypt(&group_id, &our_node_id, plaintext)
    }

    /// Decrypt a group message from a specific sender.
    pub fn decrypt(
        &mut self,
        sender: &NodeId,
        message: &GroupCiphertext,
    ) -> Result<Vec<u8>, SenderKeyError> {
        // Copy out the group id before borrowing `member_keys` mutably so the
        // AEAD AAD can be built from session context without a borrow conflict.
        let group_id = self.group_id;

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

        // Rebuild the AEAD associated data from *our* session context: this
        // group, the claimed sender, and the message's own counters. A
        // ciphertext minted for a different (group, sender) context — or with
        // rewritten counters — yields a different AAD and fails the GCM tag
        // check, so cross-context substitution cannot smuggle plaintext through.
        let aad = build_aad(&group_id, sender, message.generation, message.message_number);

        // Check for skipped key
        if let Some(message_key) = entry.skipped_keys.remove(&message.message_number) {
            return aead_decrypt(&message_key, &message.ciphertext, &aad);
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

        aead_decrypt(&message_key, &message.ciphertext, &aad)
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

/// Build the AEAD associated data binding a group ciphertext to its context.
///
/// Layout:
/// `domain || version(1) || group_id(32) || sender_id(32) || generation(4 BE) || msg_no(4 BE)`,
/// where `domain` is [`SENDER_KEY_AAD_DOMAIN`]. Both encrypt and decrypt rebuild
/// this from authoritative session context, never from attacker-controlled bytes
/// beyond the (signed, then re-checked) counters, so a ciphertext is
/// cryptographically pinned to exactly one
/// `(domain, version, group, sender, generation, message_number)` tuple.
fn build_aad(group_id: &[u8; 32], sender: &NodeId, generation: u32, message_number: u32) -> Vec<u8> {
    let sender_bytes = sender.as_bytes();
    let mut aad =
        Vec::with_capacity(SENDER_KEY_AAD_DOMAIN.len() + 1 + 32 + sender_bytes.len() + 4 + 4);
    aad.extend_from_slice(SENDER_KEY_AAD_DOMAIN);
    aad.push(SENDER_KEY_AEAD_VERSION);
    aad.extend_from_slice(group_id);
    aad.extend_from_slice(sender_bytes);
    aad.extend_from_slice(&generation.to_be_bytes());
    aad.extend_from_slice(&message_number.to_be_bytes());
    aad
}

/// Derive a 12-byte AES-GCM nonce from a message key and the AEAD associated
/// data.
///
/// Each message key is used exactly once (the chain ratchets forward per
/// message), so a deterministic nonce is sound. Folding the full AAD into the
/// HKDF salt — alongside the domain-separated [`SENDER_KEY_NONCE_INFO`] `info`
/// tag — gives key/domain/context separation: two different contexts can never
/// collide on the same `(key, nonce)` pair, and the nonce stream is disjoint
/// from every other AEAD use in the crate.
fn derive_nonce(message_key: &[u8; 32], aad: &[u8]) -> [u8; 12] {
    let hkdf = Hkdf::<Sha256>::new(Some(message_key), aad);
    let mut nonce = [0u8; 12];
    hkdf.expand(SENDER_KEY_NONCE_INFO, &mut nonce)
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

/// AES-256-GCM encrypt with context-bound nonce and associated data.
fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SenderKeyError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = derive_nonce(key, aad);
    let aes_nonce = AesNonce::from_slice(&nonce_bytes);
    cipher
        .encrypt(aes_nonce, Payload { msg: plaintext, aad })
        .map_err(|e| SenderKeyError::EncryptionFailed(e.to_string()))
}

/// AES-256-GCM decrypt with context-bound nonce and associated data.
fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, SenderKeyError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = derive_nonce(key, aad);
    let aes_nonce = AesNonce::from_slice(&nonce_bytes);
    cipher
        .decrypt(aes_nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| SenderKeyError::DecryptionFailed(e.to_string()))
}

#[cfg(test)]
#[path = "tests/sender_keys.rs"]
mod tests;
