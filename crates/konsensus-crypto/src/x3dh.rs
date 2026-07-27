//! X3DH (Extended Triple Diffie-Hellman) key agreement for 1:1 E2EE.
//!
//! Implements the Signal Protocol's X3DH key agreement, establishing a shared
//! secret between two nodes for initializing a Double Ratchet session.
//!
//! # Protocol flow
//!
//! ```text
//! Bob publishes a prekey bundle:
//!   IK_B  — identity key (long-term X25519, from NodeIdentity)
//!   SPK_B — signed pre-key (medium-term, signed by Ed25519)
//!   OPK_B — one-time pre-key (single use, optional)
//!   Sig   — Ed25519 signature over SPK_B
//!
//! Alice initiates:
//!   1. Fetches Bob's prekey bundle
//!   2. Generates ephemeral key EK_A
//!   3. Computes shared secret:
//!      DH1 = DH(IK_A, SPK_B)      — identity-to-signed-prekey
//!      DH2 = DH(EK_A, IK_B)       — ephemeral-to-identity
//!      DH3 = DH(EK_A, SPK_B)      — ephemeral-to-signed-prekey
//!      DH4 = DH(EK_A, OPK_B)      — ephemeral-to-one-time (if available)
//!      SK  = KDF(DH1 || DH2 || DH3 || DH4)
//!   4. Sends initial message with {IK_A, EK_A, OPK_id, ciphertext}
//!
//! Bob receives:
//!   1. Computes the same DH values using his private keys
//!   2. Derives the same SK
//!   3. Both initialize Double Ratchet with SK
//! ```
//!
//! # Architecture for PQXDH upgrade
//!
//! The shared secret derivation is designed to accept an additional KEM output.
//! When PQXDH is implemented, the KDF input becomes:
//! `DH1 || DH2 || DH3 || DH4 || KEM_output`
//! This is a backward-compatible extension — the same API, one more input to KDF.

use ed25519_dalek::Verifier;
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Errors from X3DH operations.
#[derive(Debug, Error)]
pub enum X3dhError {
    /// Signed pre-key signature verification failed.
    #[error("invalid signed pre-key signature: {0}")]
    InvalidSignature(String),

    /// No one-time pre-key available (warning, not fatal).
    #[error("no one-time pre-key available")]
    NoOneTimePreKey,

    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    DerivationFailed(String),

    /// Invalid public key bytes.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),
}

/// A node's published prekey bundle (Bob's side).
///
/// This is what a node publishes so that others can initiate E2EE sessions
/// without the node being online at the time.
#[derive(Debug, Clone)]
pub struct PrekeyBundle {
    /// Identity public key (long-term X25519, from NodeIdentity).
    pub identity_key: PublicKey,
    /// Signed pre-key (medium-term X25519, rotated periodically).
    pub signed_prekey: PublicKey,
    /// Ed25519 signature over the signed pre-key bytes.
    pub signed_prekey_sig: ed25519_dalek::Signature,
    /// The Ed25519 verifying key (NodeId) for signature verification.
    pub identity_verifying_key: ed25519_dalek::VerifyingKey,
    /// Optional one-time pre-key (consumed after first use).
    pub one_time_prekey: Option<PublicKey>,
    /// ID of the one-time pre-key (for Bob to identify which key was used).
    pub one_time_prekey_id: Option<u32>,
}

/// Signed pre-key pair (Bob generates and publishes these).
#[derive(Clone)]
pub struct SignedPreKey {
    /// The X25519 private key.
    secret: StaticSecret,
    /// The X25519 public key.
    pub public: PublicKey,
}

impl SignedPreKey {
    /// Generate a new signed pre-key pair.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Create from raw secret bytes (for deterministic testing).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The private key (for DH computations).
    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }
}

/// One-time pre-key pair (Bob generates batches of these).
#[derive(Clone)]
pub struct OneTimePreKey {
    /// Unique identifier for this key.
    pub id: u32,
    /// The X25519 private key.
    secret: StaticSecret,
    /// The X25519 public key.
    pub public: PublicKey,
}

impl OneTimePreKey {
    /// Generate a new one-time pre-key with the given ID.
    pub fn generate(id: u32) -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Self { id, secret, public }
    }

    /// The private key (consumed after first use).
    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }
}

/// The result of an X3DH key agreement — a shared secret for Double Ratchet.
pub struct X3dhSharedSecret {
    /// The derived shared secret (32 bytes).
    secret: [u8; 32],
    /// Associated data: IK_A || IK_B (for AEAD binding).
    pub associated_data: Vec<u8>,
}

impl Drop for X3dhSharedSecret {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl std::fmt::Debug for X3dhSharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X3dhSharedSecret")
            .field("secret", &"[REDACTED]")
            .field("associated_data_len", &self.associated_data.len())
            .finish()
    }
}

impl X3dhSharedSecret {
    /// The raw 32-byte shared secret.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.secret
    }
}

/// Alice's side: initiate an X3DH key agreement with Bob.
///
/// Returns the shared secret and the initial message components that
/// Alice must send to Bob (so Bob can derive the same secret).
#[derive(Debug)]
pub struct X3dhInitiation {
    /// The shared secret for initializing Double Ratchet.
    pub shared_secret: X3dhSharedSecret,
    /// Alice's identity public key (to include in the initial message).
    pub identity_key: PublicKey,
    /// Alice's ephemeral public key (to include in the initial message).
    pub ephemeral_key: PublicKey,
    /// ID of the one-time pre-key that was used (if any).
    pub one_time_prekey_id: Option<u32>,
}

/// Derive the X3DH shared secret from DH outputs using HKDF.
///
/// Input: DH1 || DH2 || DH3 [|| DH4]
/// The KDF uses a 32-byte all-0xFF salt (as specified by Signal's X3DH spec).
fn kdf(dh_outputs: &[u8], info: &[u8]) -> Result<[u8; 32], X3dhError> {
    use hkdf::Hkdf;

    // Signal's X3DH spec: 32 bytes of 0xFF as salt
    let salt = [0xFF_u8; 32];

    // Prepend 32 bytes of 0xFF to the input (as specified by Signal).
    // L0c (2026-04-30): wrap in `Zeroizing` so the IKM buffer — which holds
    // the full DH-output concatenation in cleartext — is zeroed on drop.
    // Without this, forward-secret material persists in the freed Vec
    // allocation until the OS reclaims it.
    let mut ikm: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0xFF_u8; 32]);
    ikm.extend_from_slice(dh_outputs);

    let hkdf = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|e| X3dhError::DerivationFailed(e.to_string()))?;
    Ok(output)
}

/// Build associated data from both identity keys (for AEAD binding).
fn build_associated_data(ik_a: &PublicKey, ik_b: &PublicKey) -> Vec<u8> {
    let mut ad = Vec::with_capacity(64);
    ad.extend_from_slice(ik_a.as_bytes());
    ad.extend_from_slice(ik_b.as_bytes());
    ad
}

/// Alice initiates X3DH with Bob's prekey bundle.
///
/// This is the sender-side operation. Alice:
/// 1. Verifies Bob's signed pre-key signature
/// 2. Generates an ephemeral key pair
/// 3. Performs the DH computations
/// 4. Derives the shared secret via HKDF
pub fn initiate(
    alice_identity_secret: &StaticSecret,
    alice_identity_public: &PublicKey,
    bob_bundle: &PrekeyBundle,
) -> Result<X3dhInitiation, X3dhError> {
    // Step 1: Verify Bob's signed pre-key signature
    bob_bundle
        .identity_verifying_key
        .verify(
            bob_bundle.signed_prekey.as_bytes(),
            &bob_bundle.signed_prekey_sig,
        )
        .map_err(|e| X3dhError::InvalidSignature(e.to_string()))?;

    // Step 2: Generate ephemeral key pair
    // Using StaticSecret rather than EphemeralSecret because we need multiple DH
    // operations. The key is still ephemeral — generated fresh for each initiation.
    let ephemeral_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);

    // Step 3: Compute DH values
    let dh1 = alice_identity_secret.diffie_hellman(&bob_bundle.signed_prekey);
    let dh2 = ephemeral_secret.diffie_hellman(&bob_bundle.identity_key);
    let dh3 = ephemeral_secret.diffie_hellman(&bob_bundle.signed_prekey);

    // Concatenate DH outputs.
    // L0c (2026-04-30): `dh_concat` accumulates 96–128 raw bytes of
    // forward-secret DH material. Wrap in `Zeroizing<Vec<u8>>` so the
    // backing allocation is zeroed on drop instead of leaking into the
    // process heap until the OS reclaims it.
    let mut dh_concat: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(128));
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    let mut opk_id = None;

    if let Some(opk) = &bob_bundle.one_time_prekey {
        let dh4 = ephemeral_secret.diffie_hellman(opk);
        dh_concat.extend_from_slice(dh4.as_bytes());
        opk_id = bob_bundle.one_time_prekey_id;
    }

    // Step 4: Derive shared secret via HKDF
    let info = b"konsensus-v2-x3dh";
    let secret = kdf(&dh_concat, info)?;

    let associated_data = build_associated_data(alice_identity_public, &bob_bundle.identity_key);

    Ok(X3dhInitiation {
        shared_secret: X3dhSharedSecret {
            secret,
            associated_data,
        },
        identity_key: *alice_identity_public,
        ephemeral_key: ephemeral_public,
        one_time_prekey_id: opk_id,
    })
}

/// Bob receives Alice's initial message and derives the same shared secret.
///
/// This is the receiver-side operation. Bob:
/// 1. Looks up his signed pre-key and optional one-time pre-key
/// 2. Performs the same DH computations
/// 3. Derives the same shared secret
pub fn respond(
    bob_identity_secret: &StaticSecret,
    bob_identity_public: &PublicKey,
    bob_signed_prekey: &SignedPreKey,
    bob_one_time_prekey: Option<&OneTimePreKey>,
    alice_identity_key: &PublicKey,
    alice_ephemeral_key: &PublicKey,
) -> Result<X3dhSharedSecret, X3dhError> {
    // Compute DH values (same as Alice but with Bob's private keys)
    let dh1 = bob_signed_prekey.secret().diffie_hellman(alice_identity_key);
    let dh2 = bob_identity_secret.diffie_hellman(alice_ephemeral_key);
    let dh3 = bob_signed_prekey.secret().diffie_hellman(alice_ephemeral_key);

    // L0c (2026-04-30): same zeroize discipline as `initiate` — wrap the
    // DH accumulator so the buffer is zeroed on drop.
    let mut dh_concat: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(128));
    dh_concat.extend_from_slice(dh1.as_bytes());
    dh_concat.extend_from_slice(dh2.as_bytes());
    dh_concat.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = bob_one_time_prekey {
        let dh4 = opk.secret().diffie_hellman(alice_ephemeral_key);
        dh_concat.extend_from_slice(dh4.as_bytes());
    }

    // Derive shared secret via HKDF
    let info = b"konsensus-v2-x3dh";
    let secret = kdf(&dh_concat, info)?;

    let associated_data = build_associated_data(alice_identity_key, bob_identity_public);

    Ok(X3dhSharedSecret {
        secret,
        associated_data,
    })
}

#[cfg(test)]
#[path = "tests/x3dh.rs"]
mod tests;
