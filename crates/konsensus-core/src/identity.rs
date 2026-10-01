//! Node identity — deterministic key derivation from a BIP-39 mnemonic.
//!
//! A single mnemonic seed produces all cryptographic keys a node needs:
//! - **Ed25519** — node identity, message signing, federation signing
//! - **X25519** — key exchange (Noise_XX handshakes, PQXDH)
//! - **secp256k1** — Bitcoin/Lightning operations
//! - **AES-256** — at-rest storage encryption
//! - **Ed25519 owner-approval key** — signs owner decisions (device-key
//!   registration). Derived from the seed **and** an owner secret stretched
//!   from the recovery-phrase password, so a copy of the seed alone (say, a
//!   `mnemonic.txt` read before it was encrypted) does not yield it (see
//!   [`OwnerApprovalKey`], `docs/protocol/ACCOUNT-LAYER.md`)
//!
//! Key derivation uses blake3's KDF with unique context strings, ensuring
//! domain separation between key types (see ADR-001). All keys — including
//! secp256k1 — are derived via blake3, not BIP-32 HD paths.

use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::types::NodeId;

/// Errors from identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// Invalid mnemonic phrase.
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Key derivation failed.
    #[error("key derivation failed: {0}")]
    DerivationFailed(String),

    /// Invalid seed length.
    #[error("invalid seed length: expected 64 bytes, got {0}")]
    InvalidSeedLength(usize),
}

/// A node's complete cryptographic identity, derived from a BIP-39 mnemonic.
///
/// Implements Principle 1: Node = Sovereign Identity & Server.
/// The BIP-39 seed is the root of all keys, derived via blake3 KDF.
pub struct NodeIdentity {
    // Ed25519 (signing / verification — node identity)
    ed25519_signing: Ed25519SigningKey,
    ed25519_verifying: Ed25519VerifyingKey,

    // X25519 (key exchange — Noise_XX, PQXDH)
    x25519_secret: X25519StaticSecret,
    x25519_public: X25519PublicKey,
    /// Raw X25519 secret bytes (pre-clamped) for passing to snow/Noise.
    x25519_secret_bytes: [u8; 32],

    // secp256k1 (Bitcoin/Lightning)
    secp_secret: bitcoin::secp256k1::SecretKey,
    secp_public: bitcoin::secp256k1::PublicKey,

    // AES-256 key (at-rest storage encryption)
    aes_key: [u8; 32],

    // NodeId (derived from Ed25519 public key)
    node_id: NodeId,
}

/// The owner-approval key: Ed25519, derived under its own context from the
/// seed **and** a 32-byte owner secret (the node stretches it from the
/// recovery-phrase password with argon2id). Unlinkable to the node identity
/// key, and not derivable from the seed alone. Held only for the moment it is
/// derived or signs, then dropped (the signing key zeroizes itself).
pub struct OwnerApprovalKey {
    signing: Ed25519SigningKey,
}

impl OwnerApprovalKey {
    /// Derive from a 64-byte BIP-39 seed and the owner secret.
    pub fn from_seed(seed: &[u8], owner_secret: &[u8; 32]) -> Result<Self, IdentityError> {
        if seed.len() != 64 {
            return Err(IdentityError::InvalidSeedLength(seed.len()));
        }
        let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(CTX_OWNER_APPROVAL));
        hasher.update(seed);
        hasher.update(owner_secret);
        let bytes = finish_key_derivation(&hasher);
        let signing = Ed25519SigningKey::from_bytes(&bytes);
        Ok(Self { signing })
    }

    /// Derive from a mnemonic, BIP-39 passphrase (same inputs as the node) and
    /// the owner secret.
    pub fn from_mnemonic(
        mnemonic_str: &str,
        passphrase: &str,
        owner_secret: &[u8; 32],
    ) -> Result<Self, IdentityError> {
        let seed = mnemonic_seed(mnemonic_str, passphrase)?;
        Self::from_seed(seed.as_ref(), owner_secret)
    }

    /// The public half, as the node knows it.
    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        self.signing.verifying_key()
    }

    /// Sign an owner decision. Callers pass a domain-separated message.
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.signing.sign(message)
    }
}

// blake3 KDF context strings — domain separation
const CTX_ED25519: &str = "konsensus-v2 ed25519 signing key";
const CTX_X25519: &str = "konsensus-v2 x25519 key exchange";
const CTX_SECP256K1: &str = "konsensus-v2 secp256k1 bitcoin key";
const CTX_AES256: &str = "konsensus-v2 aes256 storage key";
const CTX_OWNER_APPROVAL: &str = "konsensus-v2 ed25519 owner-approval key v2 (seed+owner secret)";

fn mnemonic_seed(mnemonic_str: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>, IdentityError> {
    let mnemonic = bip39::Mnemonic::parse(mnemonic_str)
        .map_err(|e| IdentityError::InvalidMnemonic(e.to_string()))?;
    Ok(Zeroizing::new(mnemonic.to_seed(passphrase)))
}

fn finish_key_derivation(hasher: &blake3::Hasher) -> Zeroizing<[u8; 32]> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    let mut output = Zeroizing::new(hasher.finalize_xof());
    output.fill(bytes.as_mut());
    bytes
}

fn derive_key(context: &str, seed: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Zeroizing::new(blake3::Hasher::new_derive_key(context));
    hasher.update(seed);
    finish_key_derivation(&hasher)
}

impl NodeIdentity {
    /// Create a new identity from a BIP-39 mnemonic phrase.
    ///
    /// The passphrase is used in BIP-39 seed derivation (can be empty).
    /// All keys are derived deterministically — the same mnemonic + passphrase
    /// always produces the same identity.
    pub fn from_mnemonic(mnemonic_str: &str, passphrase: &str) -> Result<Self, IdentityError> {
        let seed = mnemonic_seed(mnemonic_str, passphrase)?;
        Self::from_seed(seed.as_ref())
    }

    /// Create a new identity from a raw 64-byte seed.
    ///
    /// This is the core derivation function. All key types are derived
    /// deterministically from the seed using blake3 KDF with unique contexts.
    pub fn from_seed(seed: &[u8]) -> Result<Self, IdentityError> {
        if seed.len() != 64 {
            return Err(IdentityError::InvalidSeedLength(seed.len()));
        }

        // Ed25519 signing key
        let ed25519_bytes = derive_key(CTX_ED25519, seed);
        let ed25519_signing = Ed25519SigningKey::from_bytes(&ed25519_bytes);
        let ed25519_verifying = ed25519_signing.verifying_key();

        // X25519 key exchange
        let x25519_bytes = derive_key(CTX_X25519, seed);
        let x25519_secret = X25519StaticSecret::from(*x25519_bytes);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // secp256k1 (Bitcoin/Lightning)
        let secp_bytes = derive_key(CTX_SECP256K1, seed);
        let secp_secret = bitcoin::secp256k1::SecretKey::from_slice(secp_bytes.as_ref())
            .map_err(|e| IdentityError::DerivationFailed(format!("secp256k1: {e}")))?;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secp_public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secp_secret);

        // AES-256 key for at-rest encryption
        let aes_key = derive_key(CTX_AES256, seed);

        // NodeId from Ed25519 public key
        let node_id = NodeId::from_verifying_key(&ed25519_verifying);

        Ok(Self {
            ed25519_signing,
            ed25519_verifying,
            x25519_secret,
            x25519_public,
            x25519_secret_bytes: *x25519_bytes,
            secp_secret,
            secp_public,
            aes_key: *aes_key,
            node_id,
        })
    }

    /// Generate a new random identity with a fresh 24-word mnemonic.
    ///
    /// Returns `(mnemonic_phrase, identity)`.
    pub fn generate() -> Result<(String, Self), IdentityError> {
        let mnemonic = bip39::Mnemonic::generate_in(bip39::Language::English, 24)
            .map_err(|e| IdentityError::DerivationFailed(e.to_string()))?;
        let phrase = mnemonic.to_string();
        let identity = Self::from_mnemonic(&phrase, "")?;
        Ok((phrase, identity))
    }

    /// The node's unique identifier (Ed25519 public key).
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// The Ed25519 signing key (for message and federation signing).
    pub fn ed25519_signing_key(&self) -> &Ed25519SigningKey {
        &self.ed25519_signing
    }

    /// The Ed25519 verifying key (public key for signature verification).
    pub fn ed25519_verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.ed25519_verifying
    }

    /// The X25519 static secret (for Noise_XX and PQXDH key exchanges).
    pub fn x25519_secret(&self) -> &X25519StaticSecret {
        &self.x25519_secret
    }

    /// The X25519 public key.
    pub fn x25519_public(&self) -> &X25519PublicKey {
        &self.x25519_public
    }

    /// The raw X25519 secret key bytes (for Noise protocol integration).
    pub fn x25519_secret_bytes(&self) -> &[u8; 32] {
        &self.x25519_secret_bytes
    }

    /// The secp256k1 secret key (for Bitcoin/Lightning operations).
    pub fn secp_secret_key(&self) -> &bitcoin::secp256k1::SecretKey {
        &self.secp_secret
    }

    /// The secp256k1 public key.
    pub fn secp_public_key(&self) -> &bitcoin::secp256k1::PublicKey {
        &self.secp_public
    }

    /// The AES-256 key for at-rest storage encryption.
    pub fn aes_key(&self) -> &[u8; 32] {
        &self.aes_key
    }

    /// Derive a deterministic JWT signing secret from the node's AES key.
    ///
    /// This ensures JWT tokens survive node restarts without storing a separate
    /// secret in the config file. Uses blake3 keyed hash with a domain-separated
    /// context to avoid key reuse.
    pub fn derive_jwt_secret(&self) -> [u8; 32] {
        blake3::derive_key("konsensus-v2 jwt signing secret", &self.aes_key)
    }

    /// Sign arbitrary data with the Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer;
        self.ed25519_signing.sign(message)
    }

    /// Verify an Ed25519 signature against this node's public key.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &ed25519_dalek::Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        use ed25519_dalek::Verifier;
        self.ed25519_verifying.verify(message, signature)
    }
}

/// Zeroize secret key material on drop.
///
/// This ensures that private keys (Ed25519, X25519, secp256k1, AES) are
/// overwritten with zeros when the identity goes out of scope, reducing
/// the window for memory-based key extraction attacks.
impl Drop for NodeIdentity {
    fn drop(&mut self) {
        // Zeroize raw byte fields we control directly
        self.x25519_secret_bytes.zeroize();
        self.aes_key.zeroize();
        // Ed25519SigningKey, X25519StaticSecret, and secp256k1::SecretKey
        // handle their own zeroization internally via their Drop impls.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn mnemonic_seed_holder_is_zeroizing() {
        let seed: zeroize::Zeroizing<[u8; 64]> = mnemonic_seed(TEST_MNEMONIC, "secret").unwrap();
        fn assert_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
        assert_drop(&seed);
        let from_seed = NodeIdentity::from_seed(seed.as_ref()).unwrap();
        let from_words = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "secret").unwrap();
        assert_eq!(from_seed.node_id(), from_words.node_id());
    }

    #[test]
    fn derived_key_holders_are_zeroizing_and_compatible() {
        let seed = mnemonic_seed(TEST_MNEMONIC, "secret").unwrap();
        for context in [CTX_ED25519, CTX_X25519, CTX_SECP256K1, CTX_AES256] {
            let key: Zeroizing<[u8; 32]> = derive_key(context, seed.as_ref());
            fn assert_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
            assert_drop(&key);
            assert_eq!(*key, blake3::derive_key(context, seed.as_ref()));
        }
    }

    #[test]
    fn mnemonic_identity_matches_pre_zeroizing_vectors() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        for (passphrase, node_id, owner_key) in [
            (
                "",
                "47657a4344334f384d60152794f0db00a11136196c47bc849c68dea56c1358a8",
                "18c49f5c1792a82abaaf206205bf0c3b91ac3f3f5b0683036b365251f6ffad6a",
            ),
            (
                "TREZOR",
                "1553e3bdab5702319e68fc40951e563d0c7e60a9eaba3c7fffe0923b1bc994a6",
                "f4b911ec9a66c89fa758d76105df184917a7b990627b81f4537f3929bf89bf36",
            ),
        ] {
            let identity = NodeIdentity::from_mnemonic(words, passphrase).unwrap();
            assert_eq!(identity.node_id().to_hex(), node_id);
            let owner = OwnerApprovalKey::from_mnemonic(words, passphrase, &[7u8; 32]).unwrap();
            assert_eq!(hex::encode(owner.verifying_key().to_bytes()), owner_key);
        }
    }

    #[test]
    fn from_mnemonic_deterministic() {
        let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        assert_eq!(id1.node_id(), id2.node_id());
        assert_eq!(id1.aes_key(), id2.aes_key());
        assert_eq!(
            id1.ed25519_signing.to_bytes(),
            id2.ed25519_signing.to_bytes()
        );
        assert_eq!(
            id1.x25519_public.as_bytes(),
            id2.x25519_public.as_bytes()
        );
        assert_eq!(id1.secp_secret.secret_bytes(), id2.secp_secret.secret_bytes());
    }

    #[test]
    fn different_passphrase_different_keys() {
        let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "secret").unwrap();
        assert_ne!(id1.node_id(), id2.node_id());
        assert_ne!(id1.aes_key(), id2.aes_key());
    }

    #[test]
    fn all_keys_are_different() {
        let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();

        // Ed25519, X25519, secp256k1, AES keys should all be different
        let ed_bytes = id.ed25519_signing.to_bytes();
        let x_bytes = id.x25519_public.as_bytes();
        let secp_bytes = id.secp_secret.secret_bytes();
        let aes_bytes = id.aes_key();

        assert_ne!(&ed_bytes[..], &secp_bytes[..]);
        assert_ne!(&ed_bytes[..], aes_bytes);
        assert_ne!(&secp_bytes[..], aes_bytes);
        // X25519 public key is derived from secret, just check it's non-zero
        assert_ne!(x_bytes, &[0u8; 32]);
    }

    #[test]
    fn ed25519_sign_verify() {
        let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let message = b"Principle 2: No payment, no packet.";
        let sig = id.sign(message);
        assert!(id.verify(message, &sig).is_ok());

        // Tampered message should fail
        assert!(id.verify(b"tampered", &sig).is_err());
    }

    #[test]
    fn ed25519_cross_node_verify() {
        let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "different").unwrap();

        let message = b"test message";
        let sig = id1.sign(message);

        // Verify with id1's own key should pass
        assert!(id1.verify(message, &sig).is_ok());

        // Verify with id2's key should fail (different identity)
        assert!(id2.verify(message, &sig).is_err());
    }

    #[test]
    fn x25519_key_exchange() {
        let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alice").unwrap();
        let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "bob").unwrap();

        // Both sides compute the same shared secret
        let shared1 = id1.x25519_secret().diffie_hellman(id2.x25519_public());
        let shared2 = id2.x25519_secret().diffie_hellman(id1.x25519_public());

        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }

    #[test]
    fn generate_produces_valid_identity() {
        let (mnemonic, id) = NodeIdentity::generate().unwrap();

        // Should be a 24-word mnemonic
        assert_eq!(mnemonic.split_whitespace().count(), 24);

        // Re-deriving should produce the same identity
        let id2 = NodeIdentity::from_mnemonic(&mnemonic, "").unwrap();
        assert_eq!(id.node_id(), id2.node_id());
    }

    #[test]
    fn node_id_matches_verifying_key() {
        let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let expected = NodeId::from_verifying_key(id.ed25519_verifying_key());
        assert_eq!(id.node_id(), &expected);
    }

    #[test]
    fn invalid_mnemonic_rejected() {
        let result = NodeIdentity::from_mnemonic("not a valid mnemonic", "");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_seed_length_rejected() {
        let result = NodeIdentity::from_seed(&[0u8; 32]);
        assert!(matches!(result, Err(IdentityError::InvalidSeedLength(32))));
    }

    #[test]
    fn seed_shorter_than_64_bytes_rejected() {
        // Empty seed
        let result = NodeIdentity::from_seed(&[]);
        assert!(matches!(result, Err(IdentityError::InvalidSeedLength(0))));

        // 1 byte
        let result = NodeIdentity::from_seed(&[0u8; 1]);
        assert!(matches!(result, Err(IdentityError::InvalidSeedLength(1))));

        // 63 bytes (one short)
        let result = NodeIdentity::from_seed(&[0u8; 63]);
        assert!(matches!(result, Err(IdentityError::InvalidSeedLength(63))));

        // 65 bytes (one over)
        let result = NodeIdentity::from_seed(&[0u8; 65]);
        assert!(matches!(result, Err(IdentityError::InvalidSeedLength(65))));

        // 128 bytes (double)
        let result = NodeIdentity::from_seed(&[0u8; 128]);
        assert!(
            matches!(result, Err(IdentityError::InvalidSeedLength(128))),
            "seeds longer than 64 bytes should also be rejected"
        );
    }

    #[test]
    fn valid_64_byte_seed_works() {
        // A valid 64-byte seed should produce a usable identity
        let seed = [42u8; 64];
        let identity = NodeIdentity::from_seed(&seed).expect("64-byte seed should succeed");

        // Identity should have a non-zero node ID
        assert_ne!(identity.node_id().as_bytes(), &[0u8; 32]);

        // Keys should be non-zero
        assert_ne!(identity.aes_key(), &[0u8; 32]);
        assert_ne!(identity.x25519_public().as_bytes(), &[0u8; 32]);

        // Deterministic: same seed produces same identity
        let identity2 = NodeIdentity::from_seed(&seed).unwrap();
        assert_eq!(identity.node_id(), identity2.node_id());
        assert_eq!(identity.aes_key(), identity2.aes_key());
        assert_eq!(
            identity.ed25519_signing_key().to_bytes(),
            identity2.ed25519_signing_key().to_bytes()
        );
    }

    #[test]
    fn secp256k1_key_valid() {
        let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();

        // Verify the public key matches the secret key
        let expected_pub =
            bitcoin::secp256k1::PublicKey::from_secret_key(&secp, id.secp_secret_key());
        assert_eq!(id.secp_public_key(), &expected_pub);
    }

    #[test]
    fn derive_jwt_secret_is_deterministic() {
        let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        assert_eq!(id1.derive_jwt_secret(), id2.derive_jwt_secret());
    }

    #[test]
    fn derive_jwt_secret_differs_per_identity() {
        let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "different").unwrap();
        assert_ne!(id1.derive_jwt_secret(), id2.derive_jwt_secret());
    }

    #[test]
    fn derive_jwt_secret_is_not_aes_key() {
        let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        assert_ne!(
            &id.derive_jwt_secret(),
            id.aes_key(),
            "JWT secret must differ from AES key"
        );
    }

    #[test]
    fn derive_jwt_secret_is_nonzero() {
        let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        assert_ne!(id.derive_jwt_secret(), [0u8; 32]);
    }

    #[test]
    fn owner_approval_key_needs_the_seed_and_the_owner_secret() {
        let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
        let secret = [7u8; 32];
        let owner = OwnerApprovalKey::from_mnemonic(TEST_MNEMONIC, "", &secret).unwrap();
        // Deterministic for the same seed and secret.
        assert_eq!(
            OwnerApprovalKey::from_mnemonic(TEST_MNEMONIC, "", &secret).unwrap().verifying_key(),
            owner.verifying_key()
        );
        // The seed alone is not enough: another secret, another key.
        assert_ne!(
            OwnerApprovalKey::from_mnemonic(TEST_MNEMONIC, "", &[8u8; 32]).unwrap().verifying_key(),
            owner.verifying_key()
        );
        // Unlinkable to the node identity key and every other subkey.
        let pk = owner.verifying_key().to_bytes();
        assert_ne!(pk, id.ed25519_verifying_key().to_bytes());
        assert_ne!(pk, *id.x25519_public().as_bytes());
        assert_ne!(pk[..], id.aes_key()[..]);
        // A different passphrase is a different owner.
        assert_ne!(
            OwnerApprovalKey::from_mnemonic(TEST_MNEMONIC, "x", &secret).unwrap().verifying_key(),
            owner.verifying_key()
        );
        let sig = owner.sign(b"approve");
        assert!(owner.verifying_key().verify_strict(b"approve", &sig).is_ok());
        assert!(id.ed25519_verifying_key().verify_strict(b"approve", &sig).is_err());
        assert!(matches!(OwnerApprovalKey::from_seed(&[0u8; 32], &secret), Err(IdentityError::InvalidSeedLength(32))));
    }
}
