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

use crate::record_cipher::{RecordCipher, LegacyReadPolicy, CACHE_KEY_CONTEXT};

/// Cipher for encrypting/decrypting cached message plaintext at rest.
///
/// Holds a single AES-256-GCM key derived from the node's master AES key
/// via blake3 KDF with domain separation. Clone is intentionally NOT
/// implemented — there should be one instance per node.
pub struct PlaintextCacheCipher {
    cipher: RecordCipher,
}

impl PlaintextCacheCipher {
    /// Create a new cipher from the node's AES master key.
    ///
    /// The derived key is independent of all other domain-separated keys
    /// (session encryption, storage encryption) thanks to the unique context
    /// string.
    pub fn new(aes_master_key: &[u8; 32]) -> Self {
        Self::with_policy(aes_master_key, LegacyReadPolicy::default())
    }

    pub fn with_policy(aes_master_key: &[u8; 32], policy: LegacyReadPolicy) -> Self {
        Self { cipher: RecordCipher::derived(aes_master_key, CACHE_KEY_CONTEXT, policy.for_crypto()) }
    }

    /// Encrypt a cache field bound to its message row ID.
    pub fn encrypt(&self, message_id: &str, plaintext: &[u8]) -> Result<Vec<u8>, PlaintextCacheError> {
        self.cipher.encrypt("messages", "plaintext_enc", message_id, plaintext)
            .map_err(|_| PlaintextCacheError::EncryptionFailed)
    }

    /// Read v2 or, before the local cutoff, v1 cache data.
    pub fn decrypt(&self, message_id: &str, encrypted: &[u8]) -> Result<Vec<u8>, PlaintextCacheError> {
        if encrypted.len() < 12 { return Err(PlaintextCacheError::TruncatedData); }
        self.cipher.decrypt("messages", "plaintext_enc", message_id, encrypted)
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
        let encrypted = cipher.encrypt("message-a", plaintext).unwrap();
        let decrypted = cipher.decrypt("message-a", &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_nonces() {
        let cipher = PlaintextCacheCipher::new(&test_key());
        let plaintext = b"same data";
        let enc1 = cipher.encrypt("message-a", plaintext).unwrap();
        let enc2 = cipher.encrypt("message-a", plaintext).unwrap();
        // Different nonces → different ciphertext
        assert_ne!(enc1, enc2);
        // Both decrypt to the same plaintext
        assert_eq!(cipher.decrypt("message-a", &enc1).unwrap(), plaintext);
        assert_eq!(cipher.decrypt("message-a", &enc2).unwrap(), plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let cipher1 = PlaintextCacheCipher::new(&test_key());
        let cipher2 = PlaintextCacheCipher::new(&[0x99u8; 32]);
        let encrypted = cipher1.encrypt("message-a", b"secret").unwrap();
        assert!(cipher2.decrypt("message-a", &encrypted).is_err());
    }

    #[test]
    fn truncated_data_fails() {
        let cipher = PlaintextCacheCipher::new(&test_key());
        assert!(matches!(
            cipher.decrypt("message-a", &[1, 2, 3]),
            Err(PlaintextCacheError::TruncatedData)
        ));
    }

    #[test]
    fn corrupted_data_fails() {
        let cipher = PlaintextCacheCipher::new(&test_key());
        let mut encrypted = cipher.encrypt("message-a", b"data").unwrap();
        // Flip a byte in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(matches!(
            cipher.decrypt("message-a", &encrypted),
            Err(PlaintextCacheError::DecryptionFailed)
        ));
    }

    #[test]
    fn empty_plaintext() {
        let cipher = PlaintextCacheCipher::new(&test_key());
        let encrypted = cipher.encrypt("message-a", b"").unwrap();
        let decrypted = cipher.decrypt("message-a", &encrypted).unwrap();
        assert_eq!(decrypted, b"");
    }
}

#[cfg(test)]
#[test]
fn cached_plaintext_cannot_move_to_another_message() {
    let cipher = PlaintextCacheCipher::new(&[7; 32]);
    let blob = cipher.encrypt("message-a", b"text").unwrap();
    assert!(cipher.decrypt("message-b", &blob).is_err());
}
