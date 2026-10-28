//! E2EE Session Manager — manages X3DH key agreement and Double Ratchet sessions per peer.
//!
//! The SessionManager is the bridge between the identity layer and the message layer.
//! It handles the full lifecycle of encrypted sessions:
//!
//! 1. **Prekey generation** — creates our prekey bundle for distribution to peers
//! 2. **Session initiation** — performs X3DH with a peer's prekey bundle (sender side)
//! 3. **Session acceptance** — responds to an X3DH initiation (receiver side)
//! 4. **Encrypt/Decrypt** — uses Double Ratchet for per-message keys
//!
//! # Thread Safety
//!
//! The SessionManager uses `RwLock` for concurrent access. Multiple readers can
//! query session status simultaneously, while encrypt/decrypt operations take
//! write locks on individual sessions.
//!
//! # Scale Implications
//!
//! Each peer session stores ~500 bytes of ratchet state plus skipped message keys.
//! At 10K peers, this is ~5MB. At 1M peers, ~500MB — acceptable for a node that
//! actually has 1M active conversations, but in practice most nodes will have
//! far fewer active sessions.

use std::collections::HashMap;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce as AesNonce};
use async_trait::async_trait;
use ed25519_dalek::Signer;
use rand::RngCore;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use x25519_dalek::PublicKey as X25519Public;
use zeroize::Zeroize;

use konsensus_core::identity::NodeIdentity;
use konsensus_core::types::NodeId;

use crate::double_ratchet::{
    DoubleRatchet, MessageHeader, RatchetError, RatchetMessage, RatchetState,
};
use crate::x3dh::{self, OneTimePreKey, PrekeyBundle, SignedPreKey, X3dhError};

/// Errors from session management.
#[derive(Debug, Error)]
pub enum SessionError {
    /// No active session exists with this peer.
    #[error("no session with peer {0}")]
    NoSession(NodeId),

    /// Session already exists with this peer.
    #[error("session already exists with peer {0}")]
    SessionExists(NodeId),

    /// X3DH key agreement failed.
    #[error("key agreement failed: {0}")]
    KeyAgreement(#[from] X3dhError),

    /// Double Ratchet error.
    #[error("ratchet error: {0}")]
    Ratchet(#[from] RatchetError),

    /// The advanced session could not be saved. The in-memory ratchet is
    /// unchanged, and the caller must not transmit a ciphertext from this call.
    #[error("failed to persist session state: {0}")]
    Persist(String),

    /// Invalid peer data.
    #[error("invalid peer data: {0}")]
    InvalidPeerData(String),
}

/// Data sent from initiator to responder to establish an E2EE session.
///
/// After performing X3DH, the initiator sends this to the responder so
/// they can derive the same shared secret.
#[derive(Debug, Clone)]
pub struct SessionInitData {
    /// Initiator's X25519 identity public key.
    pub identity_key: [u8; 32],
    /// Initiator's ephemeral X25519 public key (generated during X3DH).
    pub ephemeral_key: [u8; 32],
    /// ID of the one-time pre-key that was consumed (if any).
    pub one_time_prekey_id: Option<u32>,
    /// Initiator's initial Double Ratchet public key.
    pub ratchet_key: [u8; 32],
}

/// Serializable prekey bundle for wire protocol exchange.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializablePrekeyBundle {
    /// X25519 identity public key (32 bytes, hex).
    pub identity_key: String,
    /// Signed pre-key (32 bytes, hex).
    pub signed_prekey: String,
    /// Ed25519 signature over signed_prekey (64 bytes, hex).
    pub signed_prekey_sig: String,
    /// Ed25519 verifying key / NodeId (32 bytes, hex).
    pub node_id: String,
    /// Optional one-time pre-key (32 bytes, hex).
    pub one_time_prekey: Option<String>,
    /// ID of the one-time pre-key.
    pub one_time_prekey_id: Option<u32>,
}

/// Serializable session init data for wire protocol.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SerializableSessionInit {
    /// Initiator's X25519 identity key (hex).
    pub identity_key: String,
    /// Initiator's ephemeral key (hex).
    pub ephemeral_key: String,
    /// Consumed one-time pre-key ID.
    pub one_time_prekey_id: Option<u32>,
    /// Initiator's ratchet public key (hex).
    pub ratchet_key: String,
}

/// Minimal async trait for persisting E2EE session state.
///
/// This trait is implemented by the node layer to bridge `SessionManager`
/// (in `konsensus-crypto`) with `Storage` (in `konsensus-storage`), avoiding
/// a circular dependency between crates.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Persist serialized session state for a peer.
    async fn save_session(
        &self,
        peer_id: &NodeId,
        state_json: &[u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Load serialized session state for a peer.
    async fn load_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>>;

    /// Delete stored session state for a peer.
    async fn delete_session(
        &self,
        peer_id: &NodeId,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// List all peer IDs with stored sessions.
    async fn list_sessions(&self) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>>;
}

/// An active E2EE session with a peer.
#[derive(Clone)]
struct PeerSession {
    /// The Double Ratchet for this session.
    ratchet: DoubleRatchet,
    /// Pending wire ciphertext and receive receipts saved with their ratchet.
    recovery_data: HashMap<String, Vec<u8>>,
}

/// Keep the original ratchet JSON fields so existing encrypted sessions restore
/// without a schema migration. Missing recovery data defaults to an empty map.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredSession {
    #[serde(flatten)]
    ratchet: RatchetState,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    recovery_data: HashMap<String, Vec<u8>>,
}

/// Domain-separation context for deriving the session-encryption key from the
/// node's AES master key. This ensures the session-at-rest key is independent
/// of the key used for `EncryptedStorage` envelope encryption.
const SESSION_ENCRYPTION_CTX: &str = "konsensus-v2 session-at-rest encryption key";

/// Manages E2EE sessions with all peers.
///
/// Handles prekey bundle generation, X3DH key agreement, and Double Ratchet
/// session lifecycle. Thread-safe via `RwLock`.
///
/// When a `SessionStore` is provided, sessions are automatically persisted
/// to storage after every encrypt/decrypt operation, enabling session
/// resumption across node restarts. Persisted session state is encrypted
/// with AES-256-GCM using a key derived from the node identity (Principle 4).
pub struct SessionManager {
    /// Our node identity.
    identity: Arc<NodeIdentity>,
    /// Our current signed pre-key (rotated periodically).
    signed_prekey: RwLock<SignedPreKey>,
    /// Our one-time pre-keys (consumed on use).
    one_time_prekeys: RwLock<Vec<OneTimePreKey>>,
    /// Next OPK ID counter.
    next_opk_id: RwLock<u32>,
    /// Active sessions keyed by peer NodeId.
    sessions: RwLock<HashMap<NodeId, PeerSession>>,
    /// Optional persistent session store.
    store: Option<Arc<dyn SessionStore>>,
    /// AES-256-GCM cipher for encrypting session state at rest.
    /// Derived from the node's AES key with domain separation.
    session_cipher: Aes256Gcm,
}

impl SessionManager {
    /// Derive the AES-256-GCM cipher for session-at-rest encryption from
    /// the node's AES master key using domain separation.
    fn derive_session_cipher(identity: &NodeIdentity) -> Aes256Gcm {
        let derived: [u8; 32] = blake3::derive_key(SESSION_ENCRYPTION_CTX, identity.aes_key());
        Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&derived))
    }

    /// Create a new session manager for the given identity.
    ///
    /// Generates an initial signed pre-key and a batch of one-time pre-keys.
    pub fn new(identity: Arc<NodeIdentity>) -> Self {
        let spk = SignedPreKey::generate();
        let session_cipher = Self::derive_session_cipher(&identity);

        // Generate initial batch of one-time pre-keys
        let mut otpks = Vec::with_capacity(10);
        for id in 0..10u32 {
            otpks.push(OneTimePreKey::generate(id));
        }

        Self {
            identity,
            signed_prekey: RwLock::new(spk),
            one_time_prekeys: RwLock::new(otpks),
            next_opk_id: RwLock::new(10),
            sessions: RwLock::new(HashMap::new()),
            store: None,
            session_cipher,
        }
    }

    /// Create a session manager with persistent storage.
    ///
    /// Encrypt saves the advanced ratchet before it returns ciphertext, and
    /// decrypt commits a copy of the ratchet only after authentication.
    /// Sessions are loaded from storage on startup via `restore_sessions()`.
    /// Session state is encrypted at rest using AES-256-GCM with a key
    /// derived from the node identity (Principle 4: no plaintext at any layer).
    pub fn with_store(identity: Arc<NodeIdentity>, store: Arc<dyn SessionStore>) -> Self {
        let spk = SignedPreKey::generate();
        let session_cipher = Self::derive_session_cipher(&identity);

        let mut otpks = Vec::with_capacity(10);
        for id in 0..10u32 {
            otpks.push(OneTimePreKey::generate(id));
        }

        Self {
            identity,
            signed_prekey: RwLock::new(spk),
            one_time_prekeys: RwLock::new(otpks),
            next_opk_id: RwLock::new(10),
            sessions: RwLock::new(HashMap::new()),
            store: Some(store),
            session_cipher,
        }
    }

    /// Restore sessions from persistent storage.
    ///
    /// Called at node startup to resume E2EE sessions from the previous run.
    /// Errors from individual session loads are logged and skipped (best-effort).
    pub async fn restore_sessions(&self) -> usize {
        let store = match &self.store {
            Some(s) => s,
            None => return 0,
        };

        let peer_ids = match store.list_sessions().await {
            Ok(ids) => ids,
            Err(e) => {
                warn!(error = %e, "failed to list stored sessions");
                return 0;
            }
        };

        // L0b (2026-04-30): the previous code path AES-decrypted the stored
        // session blob and, on failure, fell through to deserializing the
        // raw blob bytes as plaintext JSON. An attacker with disk-write
        // access could rewrite an encrypted blob with attacker-known
        // ratchet state in plaintext; on next restart the plaintext branch
        // would load it, then `persist_session` would re-encrypt it under
        // the legitimate key — laundering the injection. The fallback is
        // removed entirely. Decryption failure is now a hard "skip this
        // session" with a warning, and the session re-establishes via the
        // normal X3DH flow on next contact.
        //
        // For one-time migration of legacy plaintext sessions written
        // before AES-GCM-at-rest landed (ADR-019), a dedicated migration
        // binary built with `--features legacy-session-migration` AND booted
        // with `KONSENSUS_LEGACY_SESSION_MIGRATION=1` may import a plaintext
        // blob ONCE (it is immediately re-persisted encrypted). Both gates
        // are required:
        //
        //   * the cargo feature compiles the plaintext-accepting code IN —
        //     a default/production build does not contain it at all, so a
        //     plaintext blob is rejected unconditionally regardless of any
        //     env var an attacker might set on the process;
        //   * the env var is a second, per-boot operator opt-in so the
        //     migration capability is not active just because a migration
        //     binary happens to be running.
        //
        // `allow_legacy_plaintext_migration` is the AND of both gates. In a
        // default build it is a compile-time `false`, so every plaintext
        // branch below is dead code the optimizer drops.
        let allow_legacy_plaintext_migration = legacy_plaintext_migration_enabled();
        if allow_legacy_plaintext_migration {
            warn!(
                "legacy-session-migration build with KONSENSUS_LEGACY_SESSION_MIGRATION=1 — \
                 plaintext-fallback restore enabled FOR THIS BOOT ONLY. Operator MUST unset \
                 this env var (and redeploy a default-build binary) after the first \
                 successful boot. Legacy plaintext sessions are a downgrade-attack vector if \
                 left enabled; use only for a single legacy migration boot."
            );
        }

        let mut restored = 0;
        for peer_id in &peer_ids {
            match store.load_session(peer_id).await {
                Ok(Some(blob)) => {
                    // Decrypt the stored session state (AES-256-GCM: nonce || ciphertext).
                    // `decrypt_or_migrate_blob` returns the JSON bytes on success, or
                    // `None` to skip the session. In a default (production) build it ONLY
                    // ever returns `Some` for a blob that authenticated under AES-256-GCM;
                    // the plaintext-accepting branches are compiled out.
                    let json_bytes = match self.decrypt_or_migrate_blob(
                        peer_id,
                        &blob,
                        allow_legacy_plaintext_migration,
                    ) {
                        Some(bytes) => bytes,
                        None => continue,
                    };

                    match serde_json::from_slice::<StoredSession>(&json_bytes) {
                        Ok(state) => {
                            let ratchet = DoubleRatchet::from_state(&state.ratchet);
                            self.sessions.write().await.insert(
                                *peer_id,
                                PeerSession {
                                    ratchet,
                                    recovery_data: state.recovery_data,
                                },
                            );
                            restored += 1;
                            debug!(peer = %peer_id, "restored E2EE session from storage");

                            // Re-persist with encryption only when we just imported a
                            // legacy-plaintext blob under the migration flag. The feature
                            // gate keeps this branch out of default builds entirely.
                            #[cfg(feature = "legacy-session-migration")]
                            if allow_legacy_plaintext_migration
                                && self.decrypt_session_blob(&blob).is_err()
                            {
                                debug!(peer = %peer_id, "re-encrypting legacy plaintext session");
                                if let Err(e) = self.persist_session(peer_id).await {
                                    warn!(peer = %peer_id, error = %e, "failed to persist session state");
                                }
                            }
                        }
                        Err(e) => {
                            warn!(peer = %peer_id, error = %e, "failed to deserialize stored session, will re-establish");
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(peer = %peer_id, error = %e, "failed to load stored session");
                }
            }
        }

        debug!(
            count = restored,
            total = peer_ids.len(),
            "session restore complete"
        );
        restored
    }

    /// Resolve a stored session blob to its JSON bytes during restore.
    ///
    /// Returns `Some(json)` for a blob to load, or `None` to skip the session
    /// (it will re-establish via X3DH on next contact).
    ///
    /// # Security
    ///
    /// In a default (production) build — i.e. WITHOUT the
    /// `legacy-session-migration` feature — this function ONLY returns `Some`
    /// for a blob that authenticated under AES-256-GCM. The plaintext-accepting
    /// branches are compiled out, so a non-encrypted blob is unconditionally
    /// rejected (`None`) no matter what `KONSENSUS_LEGACY_SESSION_MIGRATION` is
    /// set to. This closes the downgrade vector where an attacker with
    /// disk-write access plants attacker-known ratchet state in plaintext and a
    /// flipped env var would launder it (L0b / MED-A).
    ///
    /// `allow_legacy` is the AND of the build feature and the per-boot env var;
    /// in a default build it is always `false`.
    fn decrypt_or_migrate_blob(
        &self,
        peer_id: &NodeId,
        blob: &[u8],
        allow_legacy: bool,
    ) -> Option<Vec<u8>> {
        // Authenticated path: a valid AES-GCM blob is `nonce(12) || ciphertext`.
        if blob.len() > 12 {
            match self.decrypt_session_blob(blob) {
                Ok(decrypted) => return Some(decrypted),
                Err(e) => {
                    // Decryption failed. In a default build the only safe action
                    // is to skip. The plaintext fallback below is compiled in
                    // ONLY for the migration build, and even then requires the
                    // per-boot env var.
                    if !allow_legacy {
                        warn!(
                            peer = %peer_id,
                            error = %e,
                            "decryption failed; legacy-migration disabled — skipping session, \
                             will re-establish via X3DH on next contact"
                        );
                        return None;
                    }
                    #[cfg(feature = "legacy-session-migration")]
                    {
                        warn!(
                            peer = %peer_id,
                            error = %e,
                            "decryption failed; legacy-migration build + env flag active, \
                             attempting plaintext fallback ONCE"
                        );
                        return Some(blob.to_vec());
                    }
                    // Defensive: unreachable in a default build because
                    // `allow_legacy` is compile-time false there. Kept so the
                    // function still type-checks without the feature.
                    #[cfg(not(feature = "legacy-session-migration"))]
                    {
                        let _ = e;
                        return None;
                    }
                }
            }
        }

        // Blob below the AES-GCM minimum (12-byte nonce + >=1-byte ciphertext).
        // This can only be a legacy plaintext blob from before ADR-019.
        if !allow_legacy {
            warn!(
                peer = %peer_id,
                len = blob.len(),
                "blob below AES-GCM minimum; legacy-migration disabled — skipping"
            );
            return None;
        }
        #[cfg(feature = "legacy-session-migration")]
        {
            warn!(
                peer = %peer_id,
                len = blob.len(),
                "blob below AES-GCM minimum; legacy-migration build + env flag active, \
                 treating as plaintext ONCE"
            );
            Some(blob.to_vec())
        }
        #[cfg(not(feature = "legacy-session-migration"))]
        {
            None
        }
    }

    /// Decrypt a session state blob. Expects nonce (12 bytes) || ciphertext.
    fn decrypt_session_blob(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("session blob too short for nonce".into());
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = AesNonce::from_slice(nonce_bytes);
        self.session_cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("session decrypt: {e}"))
    }

    /// Persist the current session state for a peer.
    ///
    /// Session state is serialized to JSON and then encrypted with AES-256-GCM
    /// before being written to the store (Principle 4: no plaintext at rest).
    ///
    /// Encrypt and decrypt do not use this helper: they save a prepared snapshot
    /// while holding the session write lock. Establishment still logs a failure
    /// and continues, because that path has not produced a message ciphertext.
    async fn persist_session(&self, peer_id: &NodeId) -> Result<(), SessionError> {
        // Hold the read guard through the save. Otherwise an encrypt/decrypt
        // can save a newer state while this snapshot is pending, and this save
        // can overwrite it, reusing a sent key and nonce after restart.
        let sessions = self.sessions.read().await;
        let session = match sessions.get(peer_id) {
            Some(session) => session,
            None => return Ok(()),
        };
        write_session_state(self.store.as_ref(), &self.session_cipher, peer_id, session).await
    }

    /// Get our prekey bundle for distribution to peers.
    ///
    /// This is what we send to peers so they can initiate X3DH with us.
    pub async fn prekey_bundle(&self) -> SerializablePrekeyBundle {
        let spk = self.signed_prekey.read().await;
        let otpks = self.one_time_prekeys.read().await;

        // Sign the signed pre-key with Ed25519
        let sig = self
            .identity
            .ed25519_signing_key()
            .sign(spk.public.as_bytes());

        let (otpk, otpk_id) = if let Some(otpk) = otpks.first() {
            (Some(hex::encode(otpk.public.as_bytes())), Some(otpk.id))
        } else {
            (None, None)
        };

        SerializablePrekeyBundle {
            identity_key: hex::encode(self.identity.x25519_public().as_bytes()),
            signed_prekey: hex::encode(spk.public.as_bytes()),
            signed_prekey_sig: hex::encode(sig.to_bytes()),
            node_id: self.identity.node_id().to_hex(),
            one_time_prekey: otpk,
            one_time_prekey_id: otpk_id,
        }
    }

    /// Initiate an E2EE session with a peer using their prekey bundle.
    ///
    /// Performs X3DH key agreement and initializes a Double Ratchet session
    /// as the sender. Returns the session init data that must be sent to
    /// the peer so they can derive the same shared secret.
    pub async fn initiate_session(
        &self,
        peer_id: &NodeId,
        peer_bundle: &SerializablePrekeyBundle,
    ) -> Result<SerializableSessionInit, SessionError> {
        // Check for existing session
        if self.sessions.read().await.contains_key(peer_id) {
            return Err(SessionError::SessionExists(*peer_id));
        }

        // Deserialize peer's prekey bundle
        let bundle = deserialize_prekey_bundle(peer_bundle)?;

        // Perform X3DH as initiator (Alice)
        let alice_secret = self.identity.x25519_secret();
        let alice_public = self.identity.x25519_public();

        let initiation = x3dh::initiate(alice_secret, alice_public, &bundle)?;

        // Initialize Double Ratchet as sender
        let ratchet = DoubleRatchet::init_sender(
            initiation.shared_secret.as_bytes(),
            &bundle.signed_prekey,
            initiation.shared_secret.associated_data.clone(),
        )?;

        let ratchet_key = *ratchet.public_key().as_bytes();

        // Store session
        self.sessions.write().await.insert(
            *peer_id,
            PeerSession {
                ratchet,
                recovery_data: HashMap::new(),
            },
        );

        // Persist to storage. No message ciphertext exists yet; a later send
        // saves the advanced ratchet before returning ciphertext.
        if let Err(e) = self.persist_session(peer_id).await {
            warn!(peer = %peer_id, error = %e, "failed to persist session state");
        }

        Ok(SerializableSessionInit {
            identity_key: hex::encode(initiation.identity_key.as_bytes()),
            ephemeral_key: hex::encode(initiation.ephemeral_key.as_bytes()),
            one_time_prekey_id: initiation.one_time_prekey_id,
            ratchet_key: hex::encode(ratchet_key),
        })
    }

    /// Accept an E2EE session initiated by a peer.
    ///
    /// Performs X3DH key agreement as the responder and initializes a
    /// Double Ratchet session as the receiver.
    pub async fn accept_session(
        &self,
        peer_id: &NodeId,
        init_data: &SerializableSessionInit,
    ) -> Result<(), SessionError> {
        // Check for existing session
        if self.sessions.read().await.contains_key(peer_id) {
            return Err(SessionError::SessionExists(*peer_id));
        }

        // Parse init data
        let alice_identity_key = parse_x25519_key(&init_data.identity_key)?;
        let alice_ephemeral_key = parse_x25519_key(&init_data.ephemeral_key)?;

        // Look up our signed pre-key
        let spk = self.signed_prekey.read().await.clone();

        // Look up and consume the one-time pre-key if used
        let otpk = if let Some(opk_id) = init_data.one_time_prekey_id {
            let mut otpks = self.one_time_prekeys.write().await;
            let idx = otpks.iter().position(|k| k.id == opk_id);
            idx.map(|i| otpks.remove(i))
        } else {
            None
        };

        // Perform X3DH as responder (Bob)
        let bob_identity_secret = self.identity.x25519_secret();
        let bob_identity_public = self.identity.x25519_public();

        let shared_secret = x3dh::respond(
            bob_identity_secret,
            bob_identity_public,
            &spk,
            otpk.as_ref(),
            &alice_identity_key,
            &alice_ephemeral_key,
        )?;

        // Initialize Double Ratchet as receiver
        let ratchet = DoubleRatchet::init_receiver(
            shared_secret.as_bytes(),
            spk.secret(),
            &spk.public,
            shared_secret.associated_data.clone(),
        );

        // Store session
        self.sessions.write().await.insert(
            *peer_id,
            PeerSession {
                ratchet,
                recovery_data: HashMap::new(),
            },
        );

        // Persist to storage. No message ciphertext exists yet; a later send
        // saves the advanced ratchet before returning ciphertext.
        if let Err(e) = self.persist_session(peer_id).await {
            warn!(peer = %peer_id, error = %e, "failed to persist session state");
        }

        // Replenish one-time pre-keys if running low
        self.replenish_prekeys().await;

        Ok(())
    }

    /// Encrypt a plaintext message for a peer.
    ///
    /// Uses the Double Ratchet to derive a per-message key and encrypt.
    /// Returns the ratchet message (header + ciphertext) which should be
    /// placed in the UKM envelope's `ciphertext` field.
    ///
    /// The advanced ratchet is saved before this returns. If saving fails the
    /// in-memory session stays where it was and the ciphertext is not returned,
    /// so the caller cannot transmit it.
    pub async fn encrypt(
        &self,
        peer_id: &NodeId,
        plaintext: &[u8],
    ) -> Result<RatchetMessage, SessionError> {
        let store = self.store.clone();
        let cipher = &self.session_cipher;
        // The sessions write lock is held across the store await below on
        // purpose. Two sends then cannot clone one ratchet and derive the same
        // message key: the next key stays invisible until this send has saved
        // and installed it. The cost is that every other session operation on
        // this manager waits out that write.
        let mut sessions = self.sessions.write().await;
        let (msg, trial) = {
            let session = sessions
                .get_mut(peer_id)
                .ok_or(SessionError::NoSession(*peer_id))?;
            let mut trial = session.clone();
            let msg = trial.ratchet.encrypt(plaintext)?;
            (msg, trial)
        };

        write_session_state(store.as_ref(), cipher, peer_id, &trial).await?;
        match sessions.get_mut(peer_id) {
            Some(session) => *session = trial,
            None => return Err(SessionError::NoSession(*peer_id)),
        }
        Ok(msg)
    }

    /// Encrypt once and retain the encoded wire message in the same encrypted
    /// snapshot as its advanced ratchet. Retries, including after restore,
    /// return the exact saved bytes without consuming another sending key.
    /// `encode` must only construct the wire message; it must not transmit it.
    pub async fn encrypt_retained<F>(
        &self,
        peer_id: &NodeId,
        retention_key: &str,
        plaintext: &[u8],
        encode: F,
    ) -> Result<Vec<u8>, SessionError>
    where
        F: FnOnce(&RatchetMessage) -> Result<Vec<u8>, SessionError>,
    {
        let mut sessions = self.sessions.write().await;
        let session = sessions
            .get_mut(peer_id)
            .ok_or(SessionError::NoSession(*peer_id))?;
        if let Some(saved) = session.recovery_data.get(retention_key) {
            return Ok(saved.clone());
        }
        let mut trial = session.clone();
        let message = trial.ratchet.encrypt(plaintext)?;
        let wire = encode(&message)?;
        trial
            .recovery_data
            .insert(retention_key.to_owned(), wire.clone());
        write_session_state(self.store.as_ref(), &self.session_cipher, peer_id, &trial).await?;
        *session = trial;
        Ok(wire)
    }

    /// Read recovery bytes retained with this session.
    pub async fn recovery_data(&self, peer_id: &NodeId, retention_key: &str) -> Option<Vec<u8>> {
        self.sessions
            .read()
            .await
            .get(peer_id)?
            .recovery_data
            .get(retention_key)
            .cloned()
    }

    /// Forget completed recovery data. A failed save preserves its bytes.
    pub async fn clear_recovery_data(
        &self,
        peer_id: &NodeId,
        retention_key: &str,
    ) -> Result<(), SessionError> {
        let mut sessions = self.sessions.write().await;
        let Some(session) = sessions.get_mut(peer_id) else {
            return Ok(());
        };
        if !session.recovery_data.contains_key(retention_key) {
            return Ok(());
        }
        let mut trial = session.clone();
        trial.recovery_data.remove(retention_key);
        write_session_state(self.store.as_ref(), &self.session_cipher, peer_id, &trial).await?;
        *session = trial;
        Ok(())
    }

    /// Prove that the committed receive chain has passed this header and no
    /// skipped key remains. A different DH generation is unknown, not proof of
    /// consumption; callers must not mistake an authentication error for replay.
    pub async fn has_consumed(&self, peer_id: &NodeId, header: &MessageHeader) -> bool {
        self.sessions
            .read()
            .await
            .get(peer_id)
            .is_some_and(|session| session.ratchet.has_consumed(header))
    }

    /// Inspect a payment-validated payload before application admission without
    /// consuming ratchet keys or persisting session changes. Once accepted, the
    /// caller must use `decrypt` to advance the real session normally.
    pub async fn preview_decrypt(
        &self,
        peer_id: &NodeId,
        message: &RatchetMessage,
    ) -> Result<Vec<u8>, SessionError> {
        let mut preview = {
            let sessions = self.sessions.read().await;
            let session = sessions.get(peer_id).ok_or(SessionError::NoSession(*peer_id))?;
            DoubleRatchet::from_state(&session.ratchet.export_state())
        };
        // Both the snapshot and disposable ratchet zeroize their secrets on drop.
        Ok(preview.decrypt(message)?)
    }

    /// Decrypt a ciphertext message from a peer.
    ///
    /// Uses the Double Ratchet to derive the message key and decrypt.
    /// Handles out-of-order delivery transparently.
    ///
    /// The ratchet is authenticated on a copy. The copy is saved and then
    /// installed only after the AEAD tag succeeds. A failed tag or a failed
    /// save leaves the stored session unchanged.
    pub async fn decrypt(
        &self,
        peer_id: &NodeId,
        message: &RatchetMessage,
    ) -> Result<Vec<u8>, SessionError> {
        self.decrypt_with_precommit(peer_id, message, |_| async { Ok(()) })
            .await
    }

    /// Authenticate a message and persist application recovery data before
    /// committing its receive ratchet. The callback runs only after successful
    /// authentication, while competing ratchet operations are excluded. A
    /// callback error leaves both the live and stored ratchets unchanged.
    ///
    /// The callback's write may outlive a failed ratchet save. Callers must
    /// reconcile that recovery data on retry before acting on the plaintext.
    /// The callback must not call back into this session manager.
    pub async fn decrypt_with_precommit<F, Fut>(
        &self,
        peer_id: &NodeId,
        message: &RatchetMessage,
        before_commit: F,
    ) -> Result<Vec<u8>, SessionError>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Result<(), SessionError>>,
    {
        self.decrypt_with_recovery(peer_id, message, None, before_commit)
            .await
    }

    /// Authenticate and save a receive receipt alongside the committed ratchet.
    /// The receipt contains the authenticated header bytes under the caller's
    /// envelope-bound recovery key. It proves consumption across later DH
    /// generations until the caller completes and clears its recovery data.
    pub async fn decrypt_with_recovery<F, Fut>(
        &self,
        peer_id: &NodeId,
        message: &RatchetMessage,
        receipt_key: Option<&str>,
        before_commit: F,
    ) -> Result<Vec<u8>, SessionError>
    where
        F: FnOnce(Vec<u8>) -> Fut,
        Fut: std::future::Future<Output = Result<(), SessionError>>,
    {
        let store = self.store.clone();
        let cipher = &self.session_cipher;
        // Same lock as `encrypt`: held across the store await so a concurrent
        // send cannot derive a key from the ratchet this decrypt is replacing.
        // Other session operations wait for the write.
        let mut sessions = self.sessions.write().await;
        let (plaintext, mut trial) = {
            let session = sessions
                .get_mut(peer_id)
                .ok_or(SessionError::NoSession(*peer_id))?;
            let mut trial = session.clone();
            let plaintext = trial.ratchet.decrypt(message)?;
            (plaintext, trial)
        };

        before_commit(plaintext.clone()).await?;
        if let Some(key) = receipt_key {
            trial
                .recovery_data
                .insert(key.to_owned(), message.header.to_bytes().to_vec());
        }
        write_session_state(store.as_ref(), cipher, peer_id, &trial).await?;
        match sessions.get_mut(peer_id) {
            Some(session) => *session = trial,
            None => return Err(SessionError::NoSession(*peer_id)),
        }
        Ok(plaintext)
    }

    /// Check if we have an active session with a peer.
    pub async fn has_session(&self, peer_id: &NodeId) -> bool {
        self.sessions.read().await.contains_key(peer_id)
    }

    /// Check if the session with a peer is ready for bidirectional messaging.
    ///
    /// Returns `true` only if the session exists AND the sending chain is
    /// initialized. An acceptor's session won't be ready until they've
    /// received the initiator's `RatchetInit` message.
    pub async fn can_send(&self, peer_id: &NodeId) -> bool {
        let sessions = self.sessions.read().await;
        sessions
            .get(peer_id)
            .map(|s| s.ratchet.can_send())
            .unwrap_or(false)
    }

    /// Whether a retained ciphertext still belongs to the current sending
    /// ratchet. Control-frame retries use this to discard frames after a session
    /// replacement or DH rotation instead of sending stale initialization data.
    pub async fn is_current_ratchet_key(&self, peer_id: &NodeId, key: &[u8; 32]) -> bool {
        self.sessions
            .read()
            .await
            .get(peer_id)
            .is_some_and(|session| session.ratchet.public_key().as_bytes() == key)
    }

    /// Count active E2EE sessions.
    pub async fn session_count(&self) -> usize {
        self.sessions.read().await.len()
    }

    /// List all peers with active sessions.
    pub async fn active_sessions(&self) -> Vec<NodeId> {
        self.sessions.read().await.keys().copied().collect()
    }

    /// Remove a session with a peer (e.g., on disconnect or key rotation).
    pub async fn remove_session(&self, peer_id: &NodeId) -> bool {
        let removed = self.sessions.write().await.remove(peer_id).is_some();
        if removed {
            if let Some(store) = &self.store {
                if let Err(e) = store.delete_session(peer_id).await {
                    warn!(peer = %peer_id, error = %e, "failed to delete stored session");
                }
            }
        }
        removed
    }

    /// Replenish one-time pre-keys when running low.
    async fn replenish_prekeys(&self) {
        let mut otpks = self.one_time_prekeys.write().await;
        if otpks.len() < 5 {
            let mut next_id = self.next_opk_id.write().await;
            let batch_size = 10 - otpks.len();
            for _ in 0..batch_size {
                otpks.push(OneTimePreKey::generate(*next_id));
                *next_id += 1;
            }
        }
    }
}

/// Serialize a RatchetMessage to bytes for embedding in a UKM envelope's ciphertext field.
///
/// Format: [40 bytes header] [N bytes ciphertext]
pub fn ratchet_message_to_bytes(msg: &RatchetMessage) -> Vec<u8> {
    let header_bytes = msg.header.to_bytes();
    let mut out = Vec::with_capacity(40 + msg.ciphertext.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&msg.ciphertext);
    out
}

/// Deserialize a RatchetMessage from bytes (reverse of `ratchet_message_to_bytes`).
pub fn ratchet_message_from_bytes(data: &[u8]) -> Result<RatchetMessage, SessionError> {
    if data.len() < 40 {
        return Err(SessionError::InvalidPeerData(format!(
            "ratchet message too short: {} bytes, need at least 40",
            data.len()
        )));
    }

    let mut header_bytes = [0u8; 40];
    header_bytes.copy_from_slice(&data[..40]);
    let header = MessageHeader::from_bytes(&header_bytes);
    let ciphertext = data[40..].to_vec();

    Ok(RatchetMessage { header, ciphertext })
}

/// Parse an X25519 public key from hex.
fn parse_x25519_key(hex_str: &str) -> Result<X25519Public, SessionError> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| SessionError::InvalidPeerData(format!("invalid hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| SessionError::InvalidPeerData("expected 32-byte X25519 key".into()))?;
    Ok(X25519Public::from(arr))
}

/// Deserialize a wire-format prekey bundle into the X3DH bundle type.
fn deserialize_prekey_bundle(
    bundle: &SerializablePrekeyBundle,
) -> Result<PrekeyBundle, SessionError> {
    let identity_key = parse_x25519_key(&bundle.identity_key)?;
    let signed_prekey = parse_x25519_key(&bundle.signed_prekey)?;

    let sig_bytes = hex::decode(&bundle.signed_prekey_sig)
        .map_err(|e| SessionError::InvalidPeerData(format!("invalid sig hex: {e}")))?;
    let sig = ed25519_dalek::Signature::from_slice(&sig_bytes)
        .map_err(|e| SessionError::InvalidPeerData(format!("invalid signature: {e}")))?;

    let node_id = NodeId::from_hex(&bundle.node_id)
        .map_err(|e| SessionError::InvalidPeerData(format!("invalid node_id: {e}")))?;
    let verifying_key = node_id
        .to_verifying_key()
        .map_err(|e| SessionError::InvalidPeerData(format!("invalid verifying key: {e}")))?;

    let one_time_prekey = if let Some(ref otpk_hex) = bundle.one_time_prekey {
        Some(parse_x25519_key(otpk_hex)?)
    } else {
        None
    };

    Ok(PrekeyBundle {
        identity_key,
        signed_prekey,
        signed_prekey_sig: sig,
        identity_verifying_key: verifying_key,
        one_time_prekey,
        one_time_prekey_id: bundle.one_time_prekey_id,
    })
}

/// Seal session JSON as nonce (12 bytes) || AES-256-GCM ciphertext.
fn seal_session_blob(cipher: &Aes256Gcm, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = AesNonce::from_slice(&nonce_bytes);

    let encrypted = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("session encrypt: {e}"))?;

    let mut result = Vec::with_capacity(12 + encrypted.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&encrypted);
    Ok(result)
}

/// Save `state` for `peer_id`. With no store this is a no-op success.
///
/// The JSON buffer is wiped after sealing. A store error is returned to the
/// caller; this function does not log and continue.
async fn write_session_state(
    store: Option<&Arc<dyn SessionStore>>,
    cipher: &Aes256Gcm,
    peer_id: &NodeId,
    session: &PeerSession,
) -> Result<(), SessionError> {
    let Some(store) = store else {
        return Ok(());
    };

    let state = StoredSession {
        ratchet: session.ratchet.export_state(),
        recovery_data: session.recovery_data.clone(),
    };
    let mut json_blob = serde_json::to_vec(&state)
        .map_err(|e| SessionError::Persist(format!("serialize session state: {e}")))?;
    let encrypted = seal_session_blob(cipher, &json_blob);
    json_blob.zeroize();
    let encrypted_blob = encrypted.map_err(SessionError::Persist)?;
    store
        .save_session(peer_id, &encrypted_blob)
        .await
        .map_err(|e| SessionError::Persist(e.to_string()))?;
    Ok(())
}

/// Whether the legacy plaintext-session migration path is active for this boot.
///
/// This is the AND of two independent gates:
///
///   1. **Build gate** — the `legacy-session-migration` cargo feature must be
///      compiled in. A default/production build returns a compile-time `false`
///      here, which lets the optimizer drop every plaintext-handling branch in
///      [`SessionManager::restore_sessions`]. The plaintext-accepting code does
///      not exist in a production binary.
///   2. **Runtime gate** — even in a migration build, the operator must set
///      `KONSENSUS_LEGACY_SESSION_MIGRATION=1` for the single migration boot.
///
/// Both must be true to ingest a non-encrypted session blob. This is
/// defense-in-depth: an attacker who can only influence the process
/// environment (set the env var) cannot re-enable the downgrade path against a
/// default build, because the code to do so was never compiled.
#[inline]
fn legacy_plaintext_migration_enabled() -> bool {
    #[cfg(feature = "legacy-session-migration")]
    {
        std::env::var("KONSENSUS_LEGACY_SESSION_MIGRATION").as_deref() == Ok("1")
    }
    #[cfg(not(feature = "legacy-session-migration"))]
    {
        false
    }
}

#[cfg(test)]
#[path = "tests/session.rs"]
mod tests;
