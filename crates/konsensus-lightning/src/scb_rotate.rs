//! Encrypted local rotation for LDK static channel backup files.
//!
//! L5a writes the current static channel backup to `scb.bin`. This module turns
//! that local plaintext backup into a small ring of AES-256-GCM encrypted files
//! owned by the node operator, without introducing a cloud dependency.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use rand::RngCore;
use thiserror::Error;

const MAGIC: &[u8; 8] = b"BSOVSCB1";
const AAD: &[u8] = b"bitsov-scb-backup-v1";
const NONCE_LEN: usize = 12;
const SNAPSHOT_PREFIX: &str = "scb-";
const SNAPSHOT_SUFFIX: &str = ".aes";
const LATEST_NAME: &str = "scb-latest.aes";

/// Inputs for one SCB rotation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScbRotationConfig {
    /// Plaintext SCB path produced by L5a.
    pub scb_path: PathBuf,
    /// Directory where encrypted snapshots and `scb-latest.aes` are stored.
    pub backup_dir: PathBuf,
    /// Number of timestamped snapshots to retain. `scb-latest.aes` is extra.
    pub rotation_count: usize,
}

/// Metadata for a successful rotation pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScbBackupMetadata {
    /// Timestamped encrypted snapshot that was written.
    pub snapshot_path: PathBuf,
    /// Stable latest encrypted backup path.
    pub latest_path: PathBuf,
    /// Plaintext SCB byte length.
    pub source_len: u64,
    /// Encrypted file byte length, including header and nonce.
    pub encrypted_len: u64,
    /// Unix timestamp when the backup was rotated.
    pub rotated_at_unix: u64,
}

/// Errors from encrypted SCB rotation.
#[derive(Debug, Error)]
pub enum ScbRotationError {
    /// `rotation_count` must be at least one timestamped copy.
    #[error("rotation_count must be at least 1")]
    InvalidRotationCount,
    /// Filesystem operation failed.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// AES-256-GCM encryption or decryption failed.
    #[error("crypto: {0}")]
    Crypto(String),
    /// The encrypted backup does not match the expected v1 file format.
    #[error("invalid encrypted SCB backup: {0}")]
    InvalidFormat(String),
}

/// Encrypt `scb_path` into `backup_dir`, update `scb-latest.aes`, and prune old
/// timestamped snapshots to `rotation_count`.
pub fn rotate_scb_backup(
    config: &ScbRotationConfig,
    master_aes_key: &[u8; 32],
) -> Result<ScbBackupMetadata, ScbRotationError> {
    if config.rotation_count == 0 {
        return Err(ScbRotationError::InvalidRotationCount);
    }

    let plaintext = fs::read(&config.scb_path)?;
    fs::create_dir_all(&config.backup_dir)?;

    let rotated_at_unix = now_unix()?;
    let encrypted = encrypt_scb(&plaintext, master_aes_key)?;
    let snapshot_path = config.backup_dir.join(snapshot_name()?);
    let latest_path = config.backup_dir.join(LATEST_NAME);

    write_private_atomic(&snapshot_path, &encrypted)?;
    write_private_atomic(&latest_path, &encrypted)?;
    prune_snapshots(&config.backup_dir, config.rotation_count)?;

    Ok(ScbBackupMetadata {
        snapshot_path,
        latest_path,
        source_len: plaintext.len() as u64,
        encrypted_len: encrypted.len() as u64,
        rotated_at_unix,
    })
}

/// Decrypt an encrypted SCB backup created by [`rotate_scb_backup`].
pub fn decrypt_scb_backup(
    encrypted: &[u8],
    master_aes_key: &[u8; 32],
) -> Result<Vec<u8>, ScbRotationError> {
    if encrypted.len() < MAGIC.len() + NONCE_LEN {
        return Err(ScbRotationError::InvalidFormat("file too short".into()));
    }
    if &encrypted[..MAGIC.len()] != MAGIC {
        return Err(ScbRotationError::InvalidFormat("bad magic".into()));
    }

    let nonce_start = MAGIC.len();
    let ciphertext_start = nonce_start + NONCE_LEN;
    let nonce = AesNonce::from_slice(&encrypted[nonce_start..ciphertext_start]);
    let ciphertext = &encrypted[ciphertext_start..];
    let cipher = Aes256Gcm::new_from_slice(master_aes_key)
        .map_err(|e| ScbRotationError::Crypto(format!("key init: {e}")))?;

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|e| ScbRotationError::Crypto(format!("decrypt: {e}")))
}

fn encrypt_scb(plaintext: &[u8], master_aes_key: &[u8; 32]) -> Result<Vec<u8>, ScbRotationError> {
    let cipher = Aes256Gcm::new_from_slice(master_aes_key)
        .map_err(|e| ScbRotationError::Crypto(format!("key init: {e}")))?;

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
        .map_err(|e| ScbRotationError::Crypto(format!("encrypt: {e}")))?;

    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<(), ScbRotationError> {
    let mut random = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut random);
    let tmp_path = path.with_extension(format!("tmp-{}", hex::encode(random)));

    {
        let mut file = create_private_file(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    fs::rename(&tmp_path, path)?;
    sync_parent_dir(path)?;
    Ok(())
}

fn create_private_file(path: &Path) -> Result<fs::File, ScbRotationError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(file)
}

fn sync_parent_dir(path: &Path) -> Result<(), ScbRotationError> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn prune_snapshots(dir: &Path, rotation_count: usize) -> Result<(), ScbRotationError> {
    let mut snapshots = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy();
        if name.starts_with(SNAPSHOT_PREFIX)
            && name.ends_with(SNAPSHOT_SUFFIX)
            && name != LATEST_NAME
        {
            snapshots.push((name.to_string(), entry.path()));
        }
    }

    snapshots.sort_by(|a, b| a.0.cmp(&b.0));
    let prune_count = snapshots.len().saturating_sub(rotation_count);
    for (_, path) in snapshots.into_iter().take(prune_count) {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn snapshot_name() -> Result<String, ScbRotationError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ScbRotationError::Io(std::io::Error::other(e)))?
        .as_millis();
    let mut random = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut random);
    Ok(format!(
        "{SNAPSHOT_PREFIX}{millis}-{}{SNAPSHOT_SUFFIX}",
        hex::encode(random)
    ))
}

fn now_unix() -> Result<u64, ScbRotationError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| ScbRotationError::Io(std::io::Error::other(e)))?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path, rotation_count: usize) -> ScbRotationConfig {
        ScbRotationConfig {
            scb_path: dir.join("scb.bin"),
            backup_dir: dir.join("backups"),
            rotation_count,
        }
    }

    fn snapshot_count(dir: &Path) -> usize {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                name.starts_with(SNAPSHOT_PREFIX)
                    && name.ends_with(SNAPSHOT_SUFFIX)
                    && name != LATEST_NAME
            })
            .count()
    }

    #[test]
    fn scb_rotate_writes_encrypted_latest_and_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let plaintext = b"ldk static channel backup bytes";
        fs::write(tmp.path().join("scb.bin"), plaintext).unwrap();
        let key = [7u8; 32];

        let meta = rotate_scb_backup(&config(tmp.path(), 24), &key).unwrap();

        assert_eq!(meta.source_len, plaintext.len() as u64);
        assert!(meta.snapshot_path.exists());
        assert!(meta.latest_path.exists());
        assert_eq!(snapshot_count(&tmp.path().join("backups")), 1);

        let encrypted = fs::read(&meta.latest_path).unwrap();
        assert_ne!(encrypted, plaintext);
        assert!(encrypted.starts_with(MAGIC));
        let decrypted = decrypt_scb_backup(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn scb_rotate_prunes_old_timestamped_snapshots() {
        let tmp = tempfile::tempdir().unwrap();
        let key = [8u8; 32];
        let cfg = config(tmp.path(), 2);

        for i in 0..4 {
            fs::write(cfg.scb_path.clone(), format!("scb-{i}")).unwrap();
            rotate_scb_backup(&cfg, &key).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(2));
        }

        assert_eq!(snapshot_count(&cfg.backup_dir), 2);
        assert!(cfg.backup_dir.join(LATEST_NAME).exists());
        let latest = fs::read(cfg.backup_dir.join(LATEST_NAME)).unwrap();
        assert_eq!(decrypt_scb_backup(&latest, &key).unwrap(), b"scb-3");
    }

    #[test]
    fn scb_rotate_rejects_zero_rotation_count() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("scb.bin"), b"scb").unwrap();
        let err = rotate_scb_backup(&config(tmp.path(), 0), &[1u8; 32]).unwrap_err();
        assert!(matches!(err, ScbRotationError::InvalidRotationCount));
    }

    #[test]
    fn scb_rotate_rejects_wrong_decryption_key() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("scb.bin"), b"scb").unwrap();
        let meta = rotate_scb_backup(&config(tmp.path(), 1), &[1u8; 32]).unwrap();
        let encrypted = fs::read(meta.latest_path).unwrap();

        let err = decrypt_scb_backup(&encrypted, &[2u8; 32]).unwrap_err();
        assert!(matches!(err, ScbRotationError::Crypto(_)));
    }

    #[cfg(unix)]
    #[test]
    fn scb_rotate_writes_private_backup_file_modes() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("scb.bin"), b"scb").unwrap();

        let meta = rotate_scb_backup(&config(tmp.path(), 1), &[1u8; 32]).unwrap();

        let snapshot_mode = fs::metadata(&meta.snapshot_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let latest_mode = fs::metadata(&meta.latest_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(snapshot_mode, 0o600);
        assert_eq!(latest_mode, 0o600);
    }
}
