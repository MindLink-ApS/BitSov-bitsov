//! Double Ratchet algorithm for per-message E2EE key derivation.
//!
//! After X3DH establishes a shared secret between two nodes, the Double Ratchet
//! provides:
//! - **Forward secrecy**: compromising current keys doesn't reveal past messages
//! - **Post-compromise security**: session heals after a key compromise
//! - **Out-of-order delivery**: messages can arrive in any order
//!
//! # Architecture
//!
//! The Double Ratchet combines three ratchets:
//!
//! 1. **DH Ratchet**: Each party regularly generates new DH key pairs and performs
//!    DH with the other party's latest public key. This provides post-compromise
//!    security — even if an attacker compromises the current state, the next DH
//!    ratchet step generates fresh keys the attacker can't predict.
//!
//! 2. **Sending chain**: A symmetric key ratchet (HMAC-based KDF chain) that
//!    derives a new message key for each outgoing message.
//!
//! 3. **Receiving chain**: Same as sending chain but for incoming messages.
//!
//! # Message format
//!
//! Each encrypted message includes a header:
//! ```text
//! [32 bytes: DH ratchet public key]
//! [4 bytes: previous chain length (u32 BE)]
//! [4 bytes: message number (u32 BE)]
//! [N bytes: AEAD encrypted payload]
//! ```

use std::collections::HashMap;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce as AesNonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Errors from Double Ratchet operations.
#[derive(Debug, Error)]
pub enum RatchetError {
    /// Decryption failed (wrong key, tampered ciphertext, or replay).
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Too many skipped messages (possible attack or severe reordering).
    #[error("too many skipped messages: {0} (max {1})")]
    TooManySkipped(u32, u32),

    /// Session not initialized.
    #[error("session not initialized")]
    NotInitialized,

    /// AEAD encryption error.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// Internal cryptographic primitive error (should never occur with valid inputs).
    #[error("crypto primitive error: {0}")]
    CryptoPrimitive(String),
}

/// Maximum number of skipped message keys to store (prevents memory exhaustion attack).
const MAX_SKIP: u32 = 1000;

/// Maximum total skipped keys across all ratchet generations.
/// Beyond this, oldest entries are evicted to bound memory usage.
const MAX_TOTAL_SKIPPED_KEYS: usize = 2000;

/// Header attached to each Double Ratchet message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageHeader {
    /// The sender's current DH ratchet public key.
    pub dh_public: [u8; 32],
    /// Number of messages in the previous sending chain.
    pub previous_chain_length: u32,
    /// Message number in the current sending chain.
    pub message_number: u32,
}

impl MessageHeader {
    /// Serialize to bytes (40 bytes total).
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(&self.dh_public);
        buf[32..36].copy_from_slice(&self.previous_chain_length.to_be_bytes());
        buf[36..40].copy_from_slice(&self.message_number.to_be_bytes());
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(buf: &[u8; 40]) -> Self {
        let mut dh_public = [0u8; 32];
        dh_public.copy_from_slice(&buf[..32]);
        let previous_chain_length = u32::from_be_bytes([buf[32], buf[33], buf[34], buf[35]]);
        let message_number = u32::from_be_bytes([buf[36], buf[37], buf[38], buf[39]]);
        Self {
            dh_public,
            previous_chain_length,
            message_number,
        }
    }
}

/// An encrypted message from the Double Ratchet.
#[derive(Debug, Clone)]
pub struct RatchetMessage {
    /// The message header (sent in plaintext — contains no secret data).
    pub header: MessageHeader,
    /// The AEAD-encrypted payload.
    pub ciphertext: Vec<u8>,
}

/// Symmetric chain key state.
#[derive(Clone)]
struct ChainKey {
    key: [u8; 32],
}

impl Drop for ChainKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ChainKey {
    /// Derive the next chain key and a message key.
    fn ratchet(&self) -> Result<(ChainKey, [u8; 32]), RatchetError> {
        // Message key: HMAC(chain_key, 0x01)
        let message_key = hmac_sha256(&self.key, &[0x01])?;
        // Next chain key: HMAC(chain_key, 0x02)
        let next_chain = hmac_sha256(&self.key, &[0x02])?;
        Ok((ChainKey { key: next_chain }, message_key))
    }
}

/// A Double Ratchet session between two nodes.
///
/// Initialized from an X3DH shared secret. Provides encrypt/decrypt with
/// forward secrecy and post-compromise security.
pub struct DoubleRatchet {
    /// Our current DH ratchet key pair.
    dh_secret: StaticSecret,
    dh_public: PublicKey,

    /// The remote peer's current DH ratchet public key.
    remote_dh_public: Option<PublicKey>,

    /// Root key (ratcheted on each DH exchange).
    root_key: [u8; 32],

    /// Current sending chain key.
    sending_chain: Option<ChainKey>,

    /// Current receiving chain key.
    receiving_chain: Option<ChainKey>,

    /// Number of messages sent in the current sending chain.
    send_count: u32,

    /// Number of messages received in the current receiving chain.
    recv_count: u32,

    /// Previous sending chain length (sent in headers for skip detection).
    previous_chain_length: u32,

    /// Skipped message keys: (ratchet_public, message_number) → (message_key, insertion_seq).
    /// Stored for out-of-order message decryption. The insertion_seq tracks insertion
    /// order for correct FIFO eviction (oldest-inserted first, not lowest message number).
    skipped_keys: HashMap<([u8; 32], u32), ([u8; 32], u64)>,

    /// Monotonically increasing counter for skipped key insertion order.
    skipped_key_seq: u64,

    /// Associated data for AEAD (IK_A || IK_B from X3DH).
    associated_data: Vec<u8>,
}

impl Drop for DoubleRatchet {
    fn drop(&mut self) {
        self.root_key.zeroize();
        for (key, _) in self.skipped_keys.values_mut() {
            key.zeroize();
        }
    }
}

impl DoubleRatchet {
    /// Initialize as the sender (Alice — who performed X3DH initiation).
    ///
    /// Alice knows Bob's signed pre-key (used as Bob's initial DH ratchet public key).
    pub fn init_sender(
        shared_secret: &[u8; 32],
        bob_signed_prekey: &PublicKey,
        associated_data: Vec<u8>,
    ) -> Result<Self, RatchetError> {
        // Generate initial DH ratchet key pair
        let dh_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let dh_public = PublicKey::from(&dh_secret);

        // Perform initial DH ratchet step
        let dh_output = dh_secret.diffie_hellman(bob_signed_prekey);
        let (root_key, sending_chain_key) = kdf_rk(shared_secret, dh_output.as_bytes())?;

        Ok(Self {
            dh_secret,
            dh_public,
            remote_dh_public: Some(*bob_signed_prekey),
            root_key,
            sending_chain: Some(ChainKey {
                key: sending_chain_key,
            }),
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
            skipped_key_seq: 0,
            associated_data,
        })
    }

    /// Initialize as the receiver (Bob — who performed X3DH response).
    ///
    /// Bob uses his signed pre-key as the initial DH ratchet key pair.
    pub fn init_receiver(
        shared_secret: &[u8; 32],
        bob_signed_prekey_secret: &StaticSecret,
        bob_signed_prekey_public: &PublicKey,
        associated_data: Vec<u8>,
    ) -> Self {
        Self {
            dh_secret: bob_signed_prekey_secret.clone(),
            dh_public: *bob_signed_prekey_public,
            remote_dh_public: None,
            root_key: *shared_secret,
            sending_chain: None,
            receiving_chain: None,
            send_count: 0,
            recv_count: 0,
            previous_chain_length: 0,
            skipped_keys: HashMap::new(),
            skipped_key_seq: 0,
            associated_data,
        }
    }

    /// Check whether the sending chain is initialized (i.e., we can encrypt).
    ///
    /// Returns `false` for an acceptor who hasn't yet received and decrypted
    /// the initiator's first ratchet message (which triggers the DH ratchet
    /// step that initializes the sending chain).
    pub fn can_send(&self) -> bool {
        self.sending_chain.is_some()
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns the header and ciphertext. The header must be sent alongside
    /// the ciphertext (it's not secret — contains the DH public key and counters).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<RatchetMessage, RatchetError> {
        let chain = self
            .sending_chain
            .as_ref()
            .ok_or(RatchetError::NotInitialized)?;

        // Derive message key from sending chain
        let (next_chain, message_key) = chain.ratchet()?;
        self.sending_chain = Some(next_chain);

        let header = MessageHeader {
            dh_public: *self.dh_public.as_bytes(),
            previous_chain_length: self.previous_chain_length,
            message_number: self.send_count,
        };

        self.send_count += 1;

        // AEAD encrypt: key = message_key, nonce = header bytes, AD = associated_data + header
        let ciphertext = aead_encrypt(&message_key, plaintext, &self.aead_ad(&header))?;

        Ok(RatchetMessage { header, ciphertext })
    }

    /// Decrypt a received message.
    ///
    /// Handles out-of-order delivery by checking skipped keys and performing
    /// DH ratchet steps as needed.
    pub fn decrypt(&mut self, message: &RatchetMessage) -> Result<Vec<u8>, RatchetError> {
        // Check if we have a skipped key for this message
        let skip_key = (message.header.dh_public, message.header.message_number);
        if let Some((message_key, _seq)) = self.skipped_keys.remove(&skip_key) {
            return aead_decrypt(&message_key, &message.ciphertext, &self.aead_ad(&message.header));
        }

        let remote_pub = PublicKey::from(message.header.dh_public);

        // Check if this is a new DH ratchet key from the peer
        let is_new_ratchet = match &self.remote_dh_public {
            Some(current) => current.as_bytes() != &message.header.dh_public,
            None => true, // First message from peer
        };

        if is_new_ratchet {
            // Skip any remaining messages in the current receiving chain
            if self.receiving_chain.is_some() {
                self.skip_messages(message.header.previous_chain_length)?;
            }

            // Perform DH ratchet step
            self.dh_ratchet(&remote_pub)?;
        }

        // Skip any messages before this one in the current chain
        self.skip_messages(message.header.message_number)?;

        // Derive the message key
        let chain = self
            .receiving_chain
            .as_ref()
            .ok_or(RatchetError::NotInitialized)?;
        let (next_chain, message_key) = chain.ratchet()?;
        self.receiving_chain = Some(next_chain);
        self.recv_count += 1;

        aead_decrypt(&message_key, &message.ciphertext, &self.aead_ad(&message.header))
    }

    /// Get our current DH ratchet public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.dh_public
    }

    /// Build AEAD associated data: our AD || header bytes.
    fn aead_ad(&self, header: &MessageHeader) -> Vec<u8> {
        let header_bytes = header.to_bytes();
        let mut ad = Vec::with_capacity(self.associated_data.len() + header_bytes.len());
        ad.extend_from_slice(&self.associated_data);
        ad.extend_from_slice(&header_bytes);
        ad
    }

    /// Perform a DH ratchet step with a new remote public key.
    fn dh_ratchet(&mut self, remote_pub: &PublicKey) -> Result<(), RatchetError> {
        self.remote_dh_public = Some(*remote_pub);
        self.previous_chain_length = self.send_count;
        self.send_count = 0;
        self.recv_count = 0;

        // Derive new receiving chain
        let dh_output = self.dh_secret.diffie_hellman(remote_pub);
        let (root_key, receiving_chain_key) = kdf_rk(&self.root_key, dh_output.as_bytes())?;
        self.root_key = root_key;
        self.receiving_chain = Some(ChainKey {
            key: receiving_chain_key,
        });

        // Generate new DH key pair and derive new sending chain
        self.dh_secret = StaticSecret::random_from_rng(rand::thread_rng());
        self.dh_public = PublicKey::from(&self.dh_secret);

        let dh_output = self.dh_secret.diffie_hellman(remote_pub);
        let (root_key, sending_chain_key) = kdf_rk(&self.root_key, dh_output.as_bytes())?;
        self.root_key = root_key;
        self.sending_chain = Some(ChainKey {
            key: sending_chain_key,
        });

        Ok(())
    }

    /// Store skipped message keys for out-of-order decryption.
    fn skip_messages(&mut self, until: u32) -> Result<(), RatchetError> {
        let chain = match &self.receiving_chain {
            Some(c) => c,
            None => return Ok(()), // No chain yet, nothing to skip
        };

        if self.recv_count + MAX_SKIP < until {
            return Err(RatchetError::TooManySkipped(
                until - self.recv_count,
                MAX_SKIP,
            ));
        }

        let remote_pub = match &self.remote_dh_public {
            Some(p) => *p.as_bytes(),
            None => return Ok(()),
        };

        let mut chain = chain.clone();
        while self.recv_count < until {
            let (next_chain, message_key) = chain.ratchet()?;
            let seq = self.skipped_key_seq;
            self.skipped_key_seq += 1;
            self.skipped_keys
                .insert((remote_pub, self.recv_count), (message_key, seq));
            chain = next_chain;
            self.recv_count += 1;
        }
        self.receiving_chain = Some(chain);

        // Evict oldest skipped keys if we exceed the total cap.
        // This bounds memory: at 2000 entries × 68 bytes = ~136 KB max per session.
        self.evict_excess_skipped_keys();

        Ok(())
    }

    /// Evict oldest-inserted skipped keys when total exceeds the cap.
    ///
    /// Uses insertion sequence numbers for FIFO eviction, ensuring recently-inserted
    /// keys are retained even if they have low message numbers (out-of-order delivery).
    fn evict_excess_skipped_keys(&mut self) {
        while self.skipped_keys.len() > MAX_TOTAL_SKIPPED_KEYS {
            // Remove the entry with the lowest insertion sequence (oldest insertion).
            // This is a linear scan but only runs when the cap is exceeded.
            if let Some(&key) = self
                .skipped_keys
                .iter()
                .min_by_key(|(_, (_, seq))| *seq)
                .map(|(k, _)| k)
            {
                if let Some((mut msg_key, _seq)) = self.skipped_keys.remove(&key) {
                    msg_key.zeroize();
                }
            } else {
                break;
            }
        }
    }
}

// ─── Serializable session state ──────────────────────────────────────────────

/// Serializable snapshot of a Double Ratchet session.
///
/// Captures all state needed to resume a session after restart. All cryptographic
/// keys are stored as raw byte arrays (since `StaticSecret`/`PublicKey` don't
/// implement serde). The caller is responsible for encrypting this at rest.
#[derive(Serialize, Deserialize)]
pub struct RatchetState {
    /// Our DH ratchet secret key (32 bytes).
    pub dh_secret: [u8; 32],
    /// Our DH ratchet public key (32 bytes).
    pub dh_public: [u8; 32],
    /// Remote peer's DH ratchet public key (if known).
    pub remote_dh_public: Option<[u8; 32]>,
    /// Root key.
    pub root_key: [u8; 32],
    /// Sending chain key (if initialized).
    pub sending_chain: Option<[u8; 32]>,
    /// Receiving chain key (if initialized).
    pub receiving_chain: Option<[u8; 32]>,
    /// Messages sent in current sending chain.
    pub send_count: u32,
    /// Messages received in current receiving chain.
    pub recv_count: u32,
    /// Previous sending chain length.
    pub previous_chain_length: u32,
    /// Skipped message keys: (ratchet_public_hex, message_number) → key_hex.
    pub skipped_keys: Vec<SkippedKey>,
    /// AEAD associated data.
    pub associated_data: Vec<u8>,
}

impl std::fmt::Debug for RatchetState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RatchetState")
            .field("dh_secret", &"[REDACTED]")
            .field("dh_public", &hex::encode(self.dh_public))
            .field("remote_dh_public", &self.remote_dh_public.map(hex::encode))
            .field("root_key", &"[REDACTED]")
            .field("sending_chain", &"[REDACTED]")
            .field("receiving_chain", &"[REDACTED]")
            .field("send_count", &self.send_count)
            .field("recv_count", &self.recv_count)
            .field("previous_chain_length", &self.previous_chain_length)
            .field("skipped_keys_count", &self.skipped_keys.len())
            .field("associated_data_len", &self.associated_data.len())
            .finish()
    }
}

/// A stored skipped message key.
#[derive(Serialize, Deserialize)]
pub struct SkippedKey {
    /// The ratchet public key (32 bytes).
    pub ratchet_public: [u8; 32],
    /// The message number.
    pub message_number: u32,
    /// The message key (32 bytes).
    pub message_key: [u8; 32],
}

impl std::fmt::Debug for SkippedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkippedKey")
            .field("ratchet_public", &hex::encode(self.ratchet_public))
            .field("message_number", &self.message_number)
            .field("message_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RatchetState {
    fn drop(&mut self) {
        self.dh_secret.zeroize();
        self.root_key.zeroize();
        if let Some(ref mut k) = self.sending_chain {
            k.zeroize();
        }
        if let Some(ref mut k) = self.receiving_chain {
            k.zeroize();
        }
        for sk in &mut self.skipped_keys {
            sk.message_key.zeroize();
        }
    }
}

impl DoubleRatchet {
    /// Export the current ratchet state as a serializable snapshot.
    ///
    /// This captures all state needed to resume the session. The caller MUST
    /// encrypt the resulting `RatchetState` before persisting it (Principle 4).
    pub fn export_state(&self) -> RatchetState {
        let mut skipped_entries: Vec<_> = self
            .skipped_keys
            .iter()
            .map(|((ratchet_pub, msg_num), (key, seq))| (*ratchet_pub, *msg_num, *key, *seq))
            .collect();
        // Sort by insertion sequence so import preserves order
        skipped_entries.sort_by_key(|(_, _, _, seq)| *seq);
        let skipped_keys = skipped_entries
            .into_iter()
            .map(|(ratchet_pub, msg_num, key, _)| SkippedKey {
                ratchet_public: ratchet_pub,
                message_number: msg_num,
                message_key: key,
            })
            .collect();

        RatchetState {
            dh_secret: self.dh_secret.to_bytes(),
            dh_public: *self.dh_public.as_bytes(),
            remote_dh_public: self.remote_dh_public.map(|k| *k.as_bytes()),
            root_key: self.root_key,
            sending_chain: self.sending_chain.as_ref().map(|c| c.key),
            receiving_chain: self.receiving_chain.as_ref().map(|c| c.key),
            send_count: self.send_count,
            recv_count: self.recv_count,
            previous_chain_length: self.previous_chain_length,
            skipped_keys,
            associated_data: self.associated_data.clone(),
        }
    }

    /// Restore a Double Ratchet session from a serialized state snapshot.
    ///
    /// This reconstructs the full ratchet from persisted data, enabling
    /// session resumption across node restarts.
    pub fn from_state(state: &RatchetState) -> Self {
        let mut skipped_keys = HashMap::new();
        // Import in order — entries are sorted by insertion sequence from export
        for (seq, sk) in state.skipped_keys.iter().enumerate() {
            skipped_keys.insert(
                (sk.ratchet_public, sk.message_number),
                (sk.message_key, seq as u64),
            );
        }
        let skipped_key_seq = state.skipped_keys.len() as u64;

        Self {
            dh_secret: StaticSecret::from(state.dh_secret),
            dh_public: PublicKey::from(state.dh_public),
            remote_dh_public: state.remote_dh_public.map(PublicKey::from),
            root_key: state.root_key,
            sending_chain: state.sending_chain.map(|key| ChainKey { key }),
            receiving_chain: state.receiving_chain.map(|key| ChainKey { key }),
            send_count: state.send_count,
            recv_count: state.recv_count,
            previous_chain_length: state.previous_chain_length,
            skipped_keys,
            skipped_key_seq,
            associated_data: state.associated_data.clone(),
        }
    }
}

// ─── Cryptographic primitives ────────────────────────────────────────────────

/// HMAC-SHA256.
fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> Result<[u8; 32], RatchetError> {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key)
        .map_err(|e| RatchetError::CryptoPrimitive(e.to_string()))?;
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Ok(out)
}

/// Root key KDF: derive new root key and chain key from root key + DH output.
fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> Result<([u8; 32], [u8; 32]), RatchetError> {
    let hkdf = Hkdf::<Sha256>::new(Some(root_key), dh_output);
    let mut output = [0u8; 64];
    hkdf.expand(b"konsensus-v2-double-ratchet", &mut output)
        .map_err(|e| RatchetError::CryptoPrimitive(e.to_string()))?;
    let mut new_root = [0u8; 32];
    let mut chain_key = [0u8; 32];
    new_root.copy_from_slice(&output[..32]);
    chain_key.copy_from_slice(&output[32..]);
    Ok((new_root, chain_key))
}

/// AEAD encrypt using AES-256-GCM.
fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let cipher = Aes256Gcm::new(key.into());
    // Derive nonce from key + AD via HKDF (deterministic but unique per message key)
    let nonce_bytes = derive_nonce(key, ad)?;
    let nonce = AesNonce::from_slice(&nonce_bytes);

    let payload = aes_gcm::aead::Payload { msg: plaintext, aad: ad };
    cipher
        .encrypt(nonce, payload)
        .map_err(|e| RatchetError::EncryptionError(e.to_string()))
}

/// AEAD decrypt using AES-256-GCM.
fn aead_decrypt(key: &[u8; 32], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>, RatchetError> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce_bytes = derive_nonce(key, ad)?;
    let nonce = AesNonce::from_slice(&nonce_bytes);

    let payload = aes_gcm::aead::Payload { msg: ciphertext, aad: ad };
    cipher
        .decrypt(nonce, payload)
        .map_err(|e| RatchetError::DecryptionFailed(e.to_string()))
}

/// Derive a 12-byte nonce from key and AD.
/// Each message key is used exactly once, so the nonce is deterministic.
fn derive_nonce(key: &[u8; 32], ad: &[u8]) -> Result<[u8; 12], RatchetError> {
    let hkdf = Hkdf::<Sha256>::new(Some(key), ad);
    let mut nonce = [0u8; 12];
    hkdf.expand(b"konsensus-v2-aead-nonce", &mut nonce)
        .map_err(|e| RatchetError::CryptoPrimitive(e.to_string()))?;
    Ok(nonce)
}

#[cfg(test)]
#[path = "tests/double_ratchet.rs"]
mod tests;
