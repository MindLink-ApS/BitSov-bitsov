//! Shared, in-memory SCB envelope. Extracted from Lightning's rotation code.
//! The v1 wire format and authenticated data are unchanged. Callers handling
//! untrusted files must bound their input before decryption allocates plaintext.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use rand::RngCore;

const MAGIC: &[u8; 8] = b"BSOVSCB1";
const AAD: &[u8] = b"bitsov-scb-backup-v1";
const NONCE_LEN: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum ScbCryptoError {
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("invalid encrypted SCB backup: {0}")]
    InvalidFormat(String),
}

/// Decrypt an encrypted SCB backup created by the SCB rotation exporter.
pub fn decrypt_scb_backup(
    encrypted: &[u8],
    master_aes_key: &[u8; 32],
) -> Result<Vec<u8>, ScbCryptoError> {
    if encrypted.len() < MAGIC.len() + NONCE_LEN {
        return Err(ScbCryptoError::InvalidFormat("file too short".into()));
    }
    if &encrypted[..MAGIC.len()] != MAGIC {
        return Err(ScbCryptoError::InvalidFormat("bad magic".into()));
    }

    let nonce_start = MAGIC.len();
    let ciphertext_start = nonce_start + NONCE_LEN;
    let nonce = AesNonce::from_slice(&encrypted[nonce_start..ciphertext_start]);
    let ciphertext = &encrypted[ciphertext_start..];
    let cipher = Aes256Gcm::new_from_slice(master_aes_key)
        .map_err(|e| ScbCryptoError::Crypto(format!("key init: {e}")))?;

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|e| ScbCryptoError::Crypto(format!("decrypt: {e}")))
}

/// Encrypt bytes in the existing SCB v1 envelope with a fresh random nonce.
pub fn encrypt_scb(plaintext: &[u8], master_aes_key: &[u8; 32]) -> Result<Vec<u8>, ScbCryptoError> {
    let cipher = Aes256Gcm::new_from_slice(master_aes_key)
        .map_err(|e| ScbCryptoError::Crypto(format!("key init: {e}")))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = AesNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|e| ScbCryptoError::Crypto(format!("encrypt: {e}")))?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}
