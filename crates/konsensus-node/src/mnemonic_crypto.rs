//! Mnemonic encryption at rest — protects the seed phrase with a user password.
//!
//! Uses argon2id for password-based key derivation (memory-hard, resistant to
//! GPU attacks) and AES-256-GCM for authenticated encryption. The encrypted
//! file format includes a version byte, salt, nonce, and ciphertext+tag.
//!
//! # File format (`.enc`)
//!
//! ```text
//! [1 byte: version (0x01)]
//! [16 bytes: argon2 salt]
//! [12 bytes: AES-GCM nonce]
//! [remaining: ciphertext + 16-byte GCM tag]
//! ```

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

/// Current format version.
const FORMAT_VERSION: u8 = 0x01;

/// Salt length for argon2.
const SALT_LEN: usize = 16;

/// Nonce length for AES-256-GCM.
const NONCE_LEN: usize = 12;

/// Header size: version + salt + nonce.
const HEADER_LEN: usize = 1 + SALT_LEN + NONCE_LEN;

/// Errors from mnemonic encryption/decryption.
#[derive(Debug, Error)]
pub enum MnemonicCryptoError {
    /// Password-based key derivation failed.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// Encryption failed.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Decryption failed (wrong password or corrupted file).
    #[error("decryption failed — wrong password or corrupted file")]
    Decryption,

    /// Invalid file format.
    #[error("invalid encrypted mnemonic file: {0}")]
    InvalidFormat(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Derive a 32-byte AES key from a password and salt using argon2id.
///
/// Parameters chosen for a balance of security and usability on modest hardware:
/// - Memory: 64 MiB (runs on a $5/month VPS)
/// - Iterations: 3
/// - Parallelism: 1
fn derive_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], MnemonicCryptoError> {
    let params = argon2::Params::new(64 * 1024, 3, 1, Some(32))
        .map_err(|e| MnemonicCryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| MnemonicCryptoError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

/// Encrypt a mnemonic phrase with a password.
///
/// Returns the encrypted bytes in the `.enc` format (version + salt + nonce + ciphertext).
pub fn encrypt_mnemonic(
    mnemonic: &str,
    password: &str,
) -> Result<Vec<u8>, MnemonicCryptoError> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(password.as_bytes(), &salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| MnemonicCryptoError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, mnemonic.as_bytes())
        .map_err(|e| MnemonicCryptoError::Encryption(e.to_string()))?;

    let mut output = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    output.push(FORMAT_VERSION);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a mnemonic phrase from encrypted bytes.
///
/// Returns the plaintext mnemonic string if the password is correct.
pub fn decrypt_mnemonic(
    encrypted: &[u8],
    password: &str,
) -> Result<String, MnemonicCryptoError> {
    if encrypted.len() < HEADER_LEN + 16 {
        // Minimum: header + 16-byte GCM tag (even empty plaintext has a tag)
        return Err(MnemonicCryptoError::InvalidFormat(
            "file too short".into(),
        ));
    }

    let version = encrypted[0];
    if version != FORMAT_VERSION {
        return Err(MnemonicCryptoError::InvalidFormat(format!(
            "unsupported version {version:#04x}, expected {FORMAT_VERSION:#04x}"
        )));
    }

    let salt = &encrypted[1..1 + SALT_LEN];
    let nonce_bytes = &encrypted[1 + SALT_LEN..HEADER_LEN];
    let ciphertext = &encrypted[HEADER_LEN..];

    let key = derive_key(password.as_bytes(), salt)?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| MnemonicCryptoError::Encryption(e.to_string()))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| MnemonicCryptoError::Decryption)?;

    String::from_utf8(plaintext).map_err(|_| {
        MnemonicCryptoError::InvalidFormat("decrypted data is not valid UTF-8".into())
    })
}

/// Check if a file path looks like an encrypted mnemonic (`.enc` extension).
pub fn is_encrypted_path(path: &std::path::Path) -> bool {
    path.extension().is_some_and(|ext| ext == "enc")
}

/// Read a mnemonic from a file, decrypting if the file has `.enc` extension.
///
/// If the file is plaintext (no `.enc` extension), reads it directly.
/// If encrypted, prompts for the password or uses the provided one.
///
/// Returns the phrase wrapped in [`Zeroizing`] so the heap-allocated seed
/// material is scrubbed from memory when the value is dropped (HARD-9). The
/// node holds this for its whole process lifetime, so it is the most
/// important seed string to zeroize.
pub fn read_mnemonic(
    path: &std::path::Path,
    password: Option<&str>,
) -> Result<Zeroizing<String>, MnemonicCryptoError> {
    if is_encrypted_path(path) {
        let encrypted = std::fs::read(path)?;
        let password = password.unwrap_or("");
        decrypt_mnemonic(&encrypted, password).map(Zeroizing::new)
    } else {
        // `read_to_string` allocates the full file (incl. the seed) on the
        // heap. Wrap that buffer in `Zeroizing` immediately so the untrimmed
        // plaintext is scrubbed on drop, then trim into a second zeroizing
        // allocation. Both the raw buffer and the trimmed result are wiped —
        // no residual non-zeroizing seed plaintext (#238).
        let raw = Zeroizing::new(std::fs::read_to_string(path)?);
        Ok(Zeroizing::new(raw.trim().to_string()))
    }
}

/// Write a mnemonic to a file, encrypting if a password is provided.
///
/// If password is empty, writes plaintext with restricted permissions.
/// If password is provided, writes encrypted `.enc` file.
pub fn write_mnemonic(
    path: &std::path::Path,
    mnemonic: &str,
    password: Option<&str>,
) -> Result<std::path::PathBuf, MnemonicCryptoError> {
    let (final_path, data) = match password {
        Some(pw) if !pw.is_empty() => {
            let enc_path = path.with_extension("enc");
            let encrypted = encrypt_mnemonic(mnemonic, pw)?;
            (enc_path, encrypted)
        }
        _ => (path.to_path_buf(), mnemonic.as_bytes().to_vec()),
    };

    std::fs::write(&final_path, &data)?;

    // Set file permissions to owner-only on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&final_path, perms)?;
    }

    Ok(final_path)
}

#[cfg(test)]
#[path = "tests/mnemonic_crypto.rs"]
mod tests;
