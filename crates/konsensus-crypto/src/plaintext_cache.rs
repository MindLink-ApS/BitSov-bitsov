//! Plaintext cache encryption — AES-256-GCM at-rest protection for cached
//! decrypted message content.
//!
//! When the node decrypts an incoming E2EE message, it caches the plaintext
//! in the `plaintext_enc` column so the REST API can return it to the frontend
//! without requiring the original E2EE session. The cached data is always
//! encrypted at rest using a domain-separated key derived from the node's
//! AES master key.
//!
//! This module provides a lightweight cipher wrapper that encrypts and decrypts
//! the cached plaintext. It follows the same pattern as session-at-rest
//! encryption (ADR-019) but with a separate domain context.

use aes_gcm::{
    aead::{Aead, OsRng},
    AeadCore, Aes256Gcm, KeyInit,
};

/// Domain-separation context for deriving the plaintext-cache encryption key.
/// Independent of the session-at-rest key and the EncryptedStorage key.
const PLAINTEXT_CACHE_CTX: &str = "konsensus-v2 plaintext-cache encryption key";

/// Cipher for encrypting/decrypting cached message plaintext at rest.
///
/// Holds a single AES-256-GCM key derived from the node's master AES key
/// via blake3 KDF with domain separation. Clone is intentionally NOT
/// implemented — there should be one instance per node.
pub struct PlaintextCacheCipher {
    cipher: Aes256Gcm,
}

impl PlaintextCacheCipher {
    /// Create a new cipher from the node's AES master key.
    ///
    /// The derived key is independent of all other domain-separated keys
    /// (session encryption, storage encryption) thanks to the unique context
    /// string.
    pub fn new(aes_master_key: &[u8; 32]) -> Self {
        let derived = blake3::derive_key(PLAINTEXT_CACHE_CTX, aes_master_key);
        Self {
            cipher: Aes256Gcm::new_from_slice(&derived)
                .expect("32-byte key is always valid for AES-256"),
        }
    }

    /// Encrypt plaintext bytes for at-rest storage.
    ///
    /// Returns `[12-byte nonce || AES-GCM ciphertext]`. The nonce is
    /// randomly generated per call — every encryption produces unique output.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, PlaintextCacheError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| PlaintextCacheError::EncryptionFailed)?;
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt previously cached plaintext.
    ///
    /// Input format: `[12-byte nonce || AES-GCM ciphertext]`.
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>, PlaintextCacheError> {
        if encrypted.len() < 12 {
            return Err(PlaintextCacheError::TruncatedData);
        }
        let (nonce_bytes, ciphertext) = encrypted.split_at(12);
        let nonce = aes_gcm::Nonce::from_slice(nonce_bytes);
        self.cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| PlaintextCacheError::DecryptionFailed)
    }
}

/// Errors from plaintext cache encryption/decryption.
#[derive(Debug, thiserror::Error)]
pub enum PlaintextCacheError {
    /// AES-GCM encryption failed (should never happen with valid key).
    #[error("plaintext cache encryption failed")]
    EncryptionFailed,
    /// Stored data is too short to contain a nonce.
    #[error("cached data truncated (< 12 bytes)")]
    TruncatedData,
    /// AES-GCM decryption failed — wrong key or corrupted data.
    #[error("plaintext cache decryption failed")]
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn roundtrip() {
        let cipher = PlaintextCacheCipher::new(&test_key());
        let plaintext = b"hello sovereign world";
        let encrypted = cipher.encrypt(plaintext).unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_nonces() {
        let cipher = PlaintextCacheCipher::new(&test_key());
        let plaintext = b"same data";
        let enc1 = cipher.encrypt(plaintext).unwrap();
        let enc2 = cipher.encrypt(plaintext).unwrap();
        // Different nonces → different ciphertext
        assert_ne!(enc1, enc2);
        // Both decrypt to the same plaintext
        assert_eq!(cipher.decrypt(&enc1).unwrap(), plaintext);
        assert_eq!(cipher.decrypt(&enc2).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let cipher1 = PlaintextCacheCipher::new(&test_key());
        let cipher2 = PlaintextCacheCipher::new(&[0x99u8; 32]);
        let encrypted = cipher1.encrypt(b"secret").unwrap();
        assert!(cipher2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn truncated_data_fails() {
        let cipher = PlaintextCacheCipher::new(&test_key());
        assert!(matches!(
            cipher.decrypt(&[1, 2, 3]),
            Err(PlaintextCacheError::TruncatedData)
        ));
    }

    #[test]
    fn corrupted_data_fails() {
        let cipher = PlaintextCacheCipher::new(&test_key());
        let mut encrypted = cipher.encrypt(b"data").unwrap();
        // Flip a byte in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(matches!(
            cipher.decrypt(&encrypted),
            Err(PlaintextCacheError::DecryptionFailed)
        ));
    }

    #[test]
    fn empty_plaintext() {
        let cipher = PlaintextCacheCipher::new(&test_key());
        let encrypted = cipher.encrypt(b"").unwrap();
        let decrypted = cipher.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"");
    }
}
