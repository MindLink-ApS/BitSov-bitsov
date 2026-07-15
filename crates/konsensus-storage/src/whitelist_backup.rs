//! Encrypted, portable backup of the gate-whitelist state (peers + accepted invites).
//!
//! **RV-RESTORE.** A mnemonic + SCB restore reconstructs only identity keys and
//! LDK channel-monitor state — `konsensus.db` (the `peers` table that backs the
//! PaymentGate whitelist after P3-2, plus `accepted_invites`) is **not** in the
//! SCB. Without a separate backup, a node restored onto fresh hardware comes
//! back rejecting every invite-onboarded peer at the gate (`NotWhitelisted`),
//! and the GA4 drill would pass on channel recovery while silently failing
//! relationship recovery (see memory `project_scb_restore_scope`).
//!
//! This module is the portable artifact that closes that gap: it serializes the
//! whitelist state and seals it with AES-256-GCM under a 32-byte mnemonic-derived
//! key — the same audited at-rest primitive as [`crate::EncryptedStorage`]. No
//! crypto is rolled here.
//!
//! This is the **core** (collect → seal → open → restore). Wiring it into SCB
//! rotation (producer, alongside `scb-latest.aes`) and the restore CLI
//! (consumer, applied to a fresh DB) are the remaining RV-RESTORE sub-tasks.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce as AesNonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::error::StorageError;
use crate::invites::AcceptedInviteRecord;
use crate::models::Peer;
use crate::traits::Storage;

/// Backup format version. `open` rejects any other value rather than silently
/// misinterpreting an incompatible payload.
const BACKUP_VERSION: u8 = 1;

/// The portable whitelist state — everything a restored node needs to re-admit
/// the peers it was federating with before the loss of its storage DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistBackup {
    /// Backup format version.
    pub version: u8,
    /// All known peers. Their `node_id`s become the gate whitelist after the
    /// P3-2 boot-load (`merge_persisted_peers`).
    pub peers: Vec<Peer>,
    /// Active accepted invites — replayed into the transport whitelist at boot.
    pub accepted_invites: Vec<AcceptedInviteRecord>,
}

impl WhitelistBackup {
    /// Collect the current whitelist state from storage.
    ///
    /// Accepted invites are best-effort: a backend that does not implement the
    /// table yields an empty list rather than failing the whole backup (the
    /// `peers` rows are the load-bearing whitelist authority).
    pub async fn collect(storage: &dyn Storage, now_unix: u64) -> Result<Self, StorageError> {
        let peers = storage.list_peers().await?;
        let accepted_invites = storage
            .list_active_accepted_invites(now_unix)
            .await
            .unwrap_or_default();
        Ok(Self {
            version: BACKUP_VERSION,
            peers,
            accepted_invites,
        })
    }

    /// Seal the backup with AES-256-GCM. Returns `nonce(12) || ciphertext`.
    ///
    /// `key` must be a 32-byte mnemonic-derived key (e.g. a domain-separated
    /// sub-key of `NodeIdentity::aes_key()`). The key derivation is the caller's
    /// responsibility — never generate or hard-code a key here.
    pub fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        let plaintext = serde_json::to_vec(self)
            .map_err(|e| StorageError::Serialization(format!("whitelist backup encode: {e}")))?;
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key is always 32 bytes");
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = AesNonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| StorageError::Encryption(format!("whitelist backup seal: {e}")))?;
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Open a sealed backup. Expects `nonce(12) || ciphertext`. Fails closed on
    /// a wrong key (AEAD tag mismatch), a truncated blob, or a version mismatch.
    pub fn open(data: &[u8], key: &[u8; 32]) -> Result<Self, StorageError> {
        if data.len() < 12 {
            return Err(StorageError::Encryption(
                "whitelist backup too short for nonce".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256 key is always 32 bytes");
        let nonce = AesNonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| {
            StorageError::Encryption(format!("whitelist backup open (wrong key or corrupt): {e}"))
        })?;
        let backup: WhitelistBackup = serde_json::from_slice(&plaintext)
            .map_err(|e| StorageError::Serialization(format!("whitelist backup decode: {e}")))?;
        if backup.version != BACKUP_VERSION {
            return Err(StorageError::Serialization(format!(
                "unsupported whitelist backup version {} (expected {BACKUP_VERSION})",
                backup.version
            )));
        }
        Ok(backup)
    }

    /// Restore the backup into storage. Idempotent — re-applying is safe (a peer
    /// is upserted; an already-present accepted invite is skipped). Returns the
    /// number of peers restored.
    pub async fn restore_into(&self, storage: &dyn Storage) -> Result<usize, StorageError> {
        for peer in &self.peers {
            storage.upsert_peer(peer).await?;
        }
        for invite in &self.accepted_invites {
            match storage.add_accepted_invite(invite).await {
                Ok(()) | Err(StorageError::AlreadyExists(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(self.peers.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::NodeId;

    fn sample() -> WhitelistBackup {
        let mut peer = Peer::new(NodeId::from_bytes([7u8; 32]));
        peer.address = Some("203.0.113.9:9735".into());
        peer.display_name = Some("alice".into());
        WhitelistBackup {
            version: BACKUP_VERSION,
            peers: vec![peer],
            accepted_invites: vec![AcceptedInviteRecord {
                nonce: [3u8; 16],
                inviter_pubkey: [7u8; 32],
                expiry_unix: 1_900_000_000,
                accepted_at: 1_800_000_000,
            }],
        }
    }

    #[test]
    fn seal_open_round_trip_preserves_state() {
        let key = [42u8; 32];
        let backup = sample();
        let sealed = backup.seal(&key).expect("seal");

        // The blob must actually be ciphertext, not the plaintext fields.
        assert!(
            !sealed.windows(5).any(|w| w == b"alice"),
            "whitelist backup must be encrypted at rest"
        );

        let opened = WhitelistBackup::open(&sealed, &key).expect("open");
        assert_eq!(opened.peers.len(), 1);
        assert_eq!(opened.peers[0].node_id, backup.peers[0].node_id);
        assert_eq!(opened.peers[0].address.as_deref(), Some("203.0.113.9:9735"));
        assert_eq!(opened.accepted_invites, backup.accepted_invites);
    }

    #[test]
    fn open_with_wrong_key_fails_closed() {
        let sealed = sample().seal(&[1u8; 32]).expect("seal");
        assert!(
            WhitelistBackup::open(&sealed, &[2u8; 32]).is_err(),
            "a wrong key must fail the AEAD tag check"
        );
    }

    #[test]
    fn open_rejects_truncated_blob() {
        assert!(WhitelistBackup::open(&[0u8; 4], &[0u8; 32]).is_err());
    }
}
