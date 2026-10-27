//! Versioned encryption of a field at a specific record location.

use aes_gcm::{
    aead::{Aead, OsRng, Payload},
    AeadCore, Aes256Gcm, KeyInit,
};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

const V2: &[u8] = b"KSBLOB\x02\0";
pub const RECORD_BINDING_MARKER: &str = "storage-record-binding-v2.complete";
pub const SESSION_KEY_CONTEXT: &str = "konsensus-v2 session-at-rest encryption key";
pub const CACHE_KEY_CONTEXT: &str = "konsensus-v2 plaintext-cache encryption key";

/// Shared cutoff for v1 reads. A local marker also applies across restarts.
#[derive(Clone)]
pub struct LegacyReadPolicy(Arc<LegacyState>);
struct LegacyState {
    marker: Option<PathBuf>,
    other_marker: Option<PathBuf>,
    disabled: AtomicBool,
}

impl Default for LegacyReadPolicy {
    fn default() -> Self {
        Self(Arc::new(LegacyState {
            marker: None,
            other_marker: None,
            disabled: AtomicBool::new(false),
        }))
    }
}

impl LegacyReadPolicy {
    pub fn for_storage(dir: &Path, encrypted_storage: bool) -> Self {
        let mut policy = Self::in_data_dir(dir);
        if !encrypted_storage {
            Arc::get_mut(&mut policy.0).expect("new policy").marker =
                Some(dir.join("crypto-record-binding-v2.complete"));
        }
        policy
    }

    pub fn in_data_dir(dir: &Path) -> Self {
        Self(Arc::new(LegacyState {
            marker: Some(dir.join(RECORD_BINDING_MARKER)),
            other_marker: None,
            disabled: AtomicBool::new(false),
        }))
    }

    /// Cache and session completion remains effective across storage-mode changes.
    pub fn for_crypto(&self) -> Self {
        let other_marker = self.0.marker.as_ref().and_then(|marker| {
            marker.parent().map(|dir| {
                let other = if marker
                    .file_name()
                    .is_some_and(|name| name == RECORD_BINDING_MARKER)
                {
                    "crypto-record-binding-v2.complete"
                } else {
                    RECORD_BINDING_MARKER
                };
                dir.join(other)
            })
        });
        Self(Arc::new(LegacyState {
            marker: self.0.marker.clone(),
            other_marker,
            disabled: AtomicBool::new(self.0.disabled.load(Ordering::Acquire)),
        }))
    }

    pub fn allows_v1(&self) -> bool {
        if self.0.disabled.load(Ordering::Acquire) {
            return false;
        }
        for path in self.0.marker.iter().chain(self.0.other_marker.iter()) {
            match std::fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                _ => {
                    self.0.disabled.store(true, Ordering::Release);
                    return false;
                }
            }
        }
        true
    }

    /// Publish only after every applicable stored field has been upgraded.
    pub fn complete(&self) -> std::io::Result<()> {
        use std::io::Write;
        let path = self.0.marker.as_ref().ok_or_else(|| {
            std::io::Error::other("record binding completion requires a local data directory")
        })?;
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("invalid marker directory"))?;
        let temp = parent.join(format!(
            ".storage-record-binding-{:016x}.tmp",
            rand::random::<u64>()
        ));
        let result: std::io::Result<()> = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp)?;
            file.write_all(b"v2\n")?;
            file.sync_all()?;
            std::fs::rename(&temp, path)?;
            std::fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result?;
        self.0.disabled.store(true, Ordering::Release);
        Ok(())
    }
}

pub struct RecordCipher {
    cipher: Aes256Gcm,
    policy: LegacyReadPolicy,
}

impl RecordCipher {
    pub fn new(key: &[u8; 32], policy: LegacyReadPolicy) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key).expect("32-byte AES key"),
            policy,
        }
    }

    pub fn derived(key: &[u8; 32], context: &str, policy: LegacyReadPolicy) -> Self {
        Self::new(&blake3::derive_key(context, key), policy)
    }

    pub fn allows_v1(&self) -> bool {
        self.policy.allows_v1()
    }

    pub fn policy(&self) -> LegacyReadPolicy {
        self.policy.clone()
    }

    pub fn is_v2(data: &[u8]) -> bool {
        data.starts_with(V2)
    }

    fn aad(table: &str, column: &str, row: &str) -> Vec<u8> {
        let mut aad = V2.to_vec();
        for part in [table, column, row] {
            aad.extend_from_slice(&(part.len() as u64).to_be_bytes());
            aad.extend_from_slice(part.as_bytes());
        }
        aad
    }

    pub fn encrypt(
        &self,
        table: &str,
        column: &str,
        row: &str,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let aad = Self::aad(table, column, row);
        let encrypted = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| "record encryption failed")?;
        let mut result = V2.to_vec();
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&encrypted);
        Ok(result)
    }

    pub fn decrypt(
        &self,
        table: &str,
        column: &str,
        row: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, String> {
        let (blob, aad) = if Self::is_v2(data) {
            (&data[V2.len()..], Self::aad(table, column, row))
        } else if self.policy.allows_v1() {
            (data, Vec::new())
        } else {
            return Err("legacy record format is disabled".into());
        };
        if blob.len() < 28 {
            return Err("encrypted record is truncated".into());
        }
        let (nonce, ciphertext) = blob.split_at(12);
        self.cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "record decryption failed".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_cutoff_survives_storage_mode_changes() {
        for completed_mode in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let completed = LegacyReadPolicy::for_storage(dir.path(), completed_mode);
            let key = blake3::derive_key(CACHE_KEY_CONTEXT, &[7; 32]);
            let nonce = [3u8; 12];
            let mut v1 = nonce.to_vec();
            v1.extend(
                Aes256Gcm::new_from_slice(&key)
                    .unwrap()
                    .encrypt((&nonce).into(), b"cache".as_slice())
                    .unwrap(),
            );
            completed.complete().unwrap();
            let next = LegacyReadPolicy::for_storage(dir.path(), !completed_mode);
            let cipher = crate::PlaintextCacheCipher::with_policy(&[7; 32], next);
            assert!(cipher.decrypt("message", &v1).is_err());
        }
    }

    #[test]
    fn location_is_required_for_v2() {
        let cipher = RecordCipher::new(&[7; 32], LegacyReadPolicy::default());
        let blob = cipher
            .encrypt("peers", "metadata_json", "row-a", b"{}")
            .unwrap();
        assert_eq!(
            cipher
                .decrypt("peers", "metadata_json", "row-a", &blob)
                .unwrap(),
            b"{}"
        );
        for (table, column, row) in [
            ("rooms", "metadata_json", "row-a"),
            ("peers", "display_name", "row-a"),
            ("peers", "metadata_json", "row-b"),
        ] {
            assert!(cipher.decrypt(table, column, row, &blob).is_err());
        }
        assert!(cipher
            .decrypt("peers", "metadata_json", "row-a", &blob[V2.len()..])
            .is_err());
    }

    #[test]
    fn v1_cutoff_applies_to_existing_ciphers_and_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let policy = LegacyReadPolicy::in_data_dir(dir.path());
        let cipher = RecordCipher::new(&[7; 32], policy.clone());
        let raw = Aes256Gcm::new_from_slice(&[7; 32]).unwrap();
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let mut v1 = nonce.to_vec();
        v1.extend(raw.encrypt(&nonce, b"legacy".as_slice()).unwrap());
        assert_eq!(cipher.decrypt("a", "b", "c", &v1).unwrap(), b"legacy");
        let v2 = cipher.encrypt("a", "b", "c", b"current").unwrap();
        policy.complete().unwrap();
        assert!(cipher.decrypt("a", "b", "c", &v1).is_err());
        let restarted = RecordCipher::new(&[7; 32], LegacyReadPolicy::in_data_dir(dir.path()));
        assert!(restarted.decrypt("a", "b", "c", &v1).is_err());
        assert_eq!(restarted.decrypt("a", "b", "c", &v2).unwrap(), b"current");
    }
}
