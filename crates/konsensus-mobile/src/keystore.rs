//! Device identity key management — Ed25519 key generation and signing primitives.
//!
//! This module provides the Rust-side crypto for device identity. Key *storage* is
//! delegated to the host platform: iOS uses the Keychain (`BitsovDeviceKeychain`)
//! and Android uses the Keystore (`BitsovDeviceKeystore`). Both platform wrappers
//! call the functions here to generate and use keys; they never perform raw crypto
//! themselves.
//!
//! # Key material
//! An Ed25519 key pair is represented as:
//!   - `private_key`: 32-byte seed (RFC 8032).  Store in platform secure storage.
//!   - `public_key`:  32-byte compressed point. Share freely as the device identity.
//!
//! # Biometric gate
//! The platform wrappers enforce a biometric gate *before* passing `private_key`
//! bytes to [`ed25519_sign`].  Rust never touches platform auth APIs — it only
//! sees bytes that have already been authenticated.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::error::MobileError;

// ── Types ─────────────────────────────────────────────────────────────────────

/// An Ed25519 key pair for device identity.
///
/// The `private_key` is the 32-byte seed (RFC 8032).  **Store it in the platform
/// Keychain (iOS) or Keystore (Android) — never in plaintext on disk.**
///
/// The `public_key` is the 32-byte compressed point that identifies this device on
/// the BitSov mesh.
#[derive(Debug, uniffi::Record)]
pub struct Ed25519KeyPair {
    /// 32-byte Ed25519 seed.  Treat as a secret; zeroize after use.
    pub private_key: Vec<u8>,
    /// 32-byte Ed25519 public key (compressed Edwards point).
    pub public_key: Vec<u8>,
}

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate a fresh Ed25519 key pair for device identity.
///
/// Call once during onboarding.  Immediately pass `private_key` to the platform
/// keychain/keystore wrapper — do not hold it in memory longer than necessary.
#[uniffi::export]
pub fn generate_ed25519_keypair() -> Ed25519KeyPair {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    // Zeroize the signing key bytes on scope exit.
    let seed = Zeroizing::new(signing_key.to_bytes());
    Ed25519KeyPair {
        private_key: seed.to_vec(),
        public_key: verifying_key.to_bytes().to_vec(),
    }
}

/// Derive the Ed25519 public key from a 32-byte seed.
///
/// Use this to recover the public key after loading the seed from the platform
/// keychain/keystore, without storing the public key separately.
#[uniffi::export]
pub fn ed25519_public_key_from_seed(seed: Vec<u8>) -> Result<Vec<u8>, MobileError> {
    let bytes = seed_to_array(seed)?;
    let signing_key = SigningKey::from_bytes(&bytes);
    Ok(signing_key.verifying_key().to_bytes().to_vec())
}

// ── Signing ───────────────────────────────────────────────────────────────────

/// Sign `message` with the Ed25519 `seed` (32 bytes).
///
/// Returns a 64-byte detached signature.
///
/// The caller (platform wrapper) is responsible for ensuring the seed was retrieved
/// from secure storage through a biometric-gated path before calling this function.
#[uniffi::export]
pub fn ed25519_sign(seed: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, MobileError> {
    let bytes = seed_to_array(seed)?;
    let signing_key = SigningKey::from_bytes(&bytes);
    let signature: Signature = signing_key.sign(&message);
    Ok(signature.to_bytes().to_vec())
}

// ── Verification ──────────────────────────────────────────────────────────────

/// Verify an Ed25519 `signature` (64 bytes) over `message` with `public_key` (32 bytes).
///
/// Returns `true` if the signature is valid, `false` if it is not.
/// Returns [`MobileError::InvalidKey`] if `public_key` is malformed.
#[uniffi::export]
pub fn ed25519_verify(
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, MobileError> {
    let pk_bytes: [u8; 32] = public_key.try_into().map_err(|_| MobileError::InvalidKey {
        msg: "Ed25519 public key must be exactly 32 bytes".to_owned(),
    })?;
    let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| MobileError::InvalidKey {
        msg: "Ed25519 signature must be exactly 64 bytes".to_owned(),
    })?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|e| MobileError::InvalidKey {
            msg: format!("invalid public key: {e}"),
        })?;
    let sig = Signature::from_bytes(&sig_bytes);
    Ok(verifying_key.verify(&message, &sig).is_ok())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn seed_to_array(seed: Vec<u8>) -> Result<[u8; 32], MobileError> {
    seed.try_into().map_err(|_| MobileError::InvalidKey {
        msg: "Ed25519 seed must be exactly 32 bytes".to_owned(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_correct_lengths() {
        let kp = generate_ed25519_keypair();
        assert_eq!(kp.private_key.len(), 32, "seed must be 32 bytes");
        assert_eq!(kp.public_key.len(), 32, "public key must be 32 bytes");
    }

    #[test]
    fn public_key_derivation_is_deterministic() {
        let kp = generate_ed25519_keypair();
        let derived = ed25519_public_key_from_seed(kp.private_key.clone()).unwrap();
        assert_eq!(derived, kp.public_key, "derived public key must match generated");
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = generate_ed25519_keypair();
        let message = b"bitsovsovereign".to_vec();

        let sig = ed25519_sign(kp.private_key.clone(), message.clone()).unwrap();
        assert_eq!(sig.len(), 64, "signature must be 64 bytes");

        let valid = ed25519_verify(kp.public_key.clone(), message.clone(), sig.clone()).unwrap();
        assert!(valid, "valid signature must verify");
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let kp = generate_ed25519_keypair();
        let sig = ed25519_sign(kp.private_key.clone(), b"message".to_vec()).unwrap();
        let valid =
            ed25519_verify(kp.public_key.clone(), b"tampered".to_vec(), sig).unwrap();
        assert!(!valid, "signature over different message must not verify");
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();
        let message = b"hello".to_vec();
        let sig = ed25519_sign(kp1.private_key, message.clone()).unwrap();
        let valid = ed25519_verify(kp2.public_key, message, sig).unwrap();
        assert!(!valid, "signature from different key must not verify");
    }

    #[test]
    fn verify_rejects_malformed_signature() {
        let kp = generate_ed25519_keypair();
        let bad_sig = vec![0u8; 64];
        let valid = ed25519_verify(kp.public_key, b"msg".to_vec(), bad_sig).unwrap();
        assert!(!valid, "all-zero signature must not verify");
    }

    #[test]
    fn invalid_seed_length_is_rejected() {
        let err = ed25519_sign(vec![0u8; 31], b"msg".to_vec()).unwrap_err();
        assert!(matches!(err, MobileError::InvalidKey { .. }));
    }

    #[test]
    fn invalid_public_key_length_is_rejected() {
        let err =
            ed25519_verify(vec![0u8; 31], b"msg".to_vec(), vec![0u8; 64]).unwrap_err();
        assert!(matches!(err, MobileError::InvalidKey { .. }));
    }

    #[test]
    fn invalid_signature_length_is_rejected() {
        let kp = generate_ed25519_keypair();
        let err = ed25519_verify(kp.public_key, b"msg".to_vec(), vec![0u8; 63]).unwrap_err();
        assert!(matches!(err, MobileError::InvalidKey { .. }));
    }

    #[test]
    fn two_keypairs_are_unique() {
        let kp1 = generate_ed25519_keypair();
        let kp2 = generate_ed25519_keypair();
        assert_ne!(kp1.private_key, kp2.private_key);
        assert_ne!(kp1.public_key, kp2.public_key);
    }
}
