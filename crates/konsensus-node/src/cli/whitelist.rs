//! `konsensus whitelist backup` — producer side of RV-RESTORE (sub-PR 2/3).
//!
//! The SCB (`scb-latest.aes`) backs up only LDK channel-monitor state. The
//! gate whitelist — the `peers` table that backs `PaymentGate` after P3-2, plus
//! `accepted_invites` — lives in `konsensus.db`, which the SCB does not cover.
//! Without a separate backup, a mnemonic+SCB restore onto fresh hardware comes
//! back rejecting every invite-onboarded peer (memory `project_scb_restore_scope`).
//!
//! This command exports that whitelist state into an encrypted sidecar
//! (`whitelist-latest.aes`) sealed with the node's mnemonic-derived AES key
//! (the same key class as at-rest storage — re-derivable on restore from the
//! mnemonic alone). Run it on the SCB-rotation cadence (e.g. cron) and keep the
//! file alongside `scb-latest.aes`; `konsensus whitelist restore` (sub-PR 3)
//! applies it to a fresh DB.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use konsensus_storage::{Storage, WhitelistBackup};

use crate::config::{NodeConfig, StorageConfig};

/// Default sidecar filename, written next to `scb-latest.aes`. `pub(crate)` so the
/// periodic producer (`housekeeping::run_whitelist_backup`) and the recovery
/// consumer (`scb_restore`) resolve the same path.
pub(crate) const WHITELIST_BACKUP_NAME: &str = "whitelist-latest.aes";

/// `konsensus whitelist backup` — export + encrypt the gate-whitelist state.
pub async fn cmd_whitelist_backup(
    config_path: &Path,
    mnemonic_password: Option<&str>,
    out: Option<&Path>,
) -> Result<()> {
    let config = NodeConfig::load(config_path)
        .with_context(|| format!("failed to load config: {}", config_path.display()))?;

    let mnemonic =
        crate::mnemonic_crypto::read_mnemonic(&config.identity.mnemonic_file, mnemonic_password)
            .with_context(|| {
                format!(
                    "failed to read mnemonic from {}",
                    config.identity.mnemonic_file.display()
                )
            })?;
    let identity =
        konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, config.identity.passphrase.as_str())
            .context("failed to derive identity from mnemonic")?;

    let storage = open_storage(&config, &identity).await?;

    let out_path: PathBuf = match out {
        Some(p) => p.to_path_buf(),
        None => Path::new(&config.backup.scb_dir).join(WHITELIST_BACKUP_NAME),
    };

    let bytes = write_whitelist_backup(storage.as_ref(), identity.aes_key(), &out_path).await?;

    println!(
        "Whitelist backup written: {} ({bytes} bytes)",
        out_path.display()
    );
    println!(
        "Keep this alongside scb-latest.aes; restore with `konsensus whitelist restore` after `scb restore`."
    );
    Ok(())
}

/// Build the configured storage backend (mirrors node startup so the backup
/// reads the same decrypted view the running node sees).
async fn open_storage(
    config: &NodeConfig,
    identity: &konsensus_core::NodeIdentity,
) -> Result<Arc<dyn Storage>> {
    let storage: Arc<dyn Storage> = match &config.storage {
        StorageConfig::Sqlite {
            path, encrypted, ..
        } => {
            let sqlite = konsensus_storage::SqliteStorage::open(path)
                .await
                .with_context(|| format!("failed to open SQLite at {path}"))?;
            if *encrypted {
                Arc::new(konsensus_storage::EncryptedStorage::new(
                    sqlite,
                    identity.aes_key(),
                ))
            } else {
                Arc::new(sqlite)
            }
        }
        StorageConfig::Postgres { url, encrypted, .. } => {
            let pg = konsensus_storage::PostgresStorage::connect(url)
                .await
                .context("failed to connect to PostgreSQL")?;
            if *encrypted {
                Arc::new(konsensus_storage::EncryptedStorage::new(
                    pg,
                    identity.aes_key(),
                ))
            } else {
                Arc::new(pg)
            }
        }
    };
    Ok(storage)
}

/// Collect → seal → atomically write the whitelist backup. Returns the sealed
/// byte count. Separated from CLI plumbing so it is unit-testable with an
/// in-memory store and an arbitrary key.
pub async fn write_whitelist_backup(
    storage: &dyn Storage,
    key: &[u8; 32],
    out_path: &Path,
) -> Result<usize> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = WhitelistBackup::collect(storage, now_unix)
        .await
        .context("failed to collect whitelist state from storage")?;
    let sealed = backup.seal(key).context("failed to seal whitelist backup")?;

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create backup dir {}", parent.display()))?;
        }
    }
    // Write to a temp file then rename, so a crash mid-write never leaves a
    // truncated `whitelist-latest.aes` that a later restore would choke on.
    let tmp = out_path.with_extension("aes.tmp");
    fs::write(&tmp, &sealed).with_context(|| format!("failed to write {}", tmp.display()))?;
    fs::rename(&tmp, out_path)
        .with_context(|| format!("failed to finalize {}", out_path.display()))?;
    Ok(sealed.len())
}

/// `konsensus whitelist restore` — decrypt the sidecar and re-insert the
/// whitelist state into the configured storage DB. Idempotent; intended to run
/// on fresh hardware after `scb restore` so the node re-admits invite-onboarded
/// peers (the P3-2 boot-load then loads them into the gate whitelist).
pub async fn cmd_whitelist_restore(
    config_path: &Path,
    mnemonic_password: Option<&str>,
    from: &Path,
) -> Result<()> {
    let config = NodeConfig::load(config_path)
        .with_context(|| format!("failed to load config: {}", config_path.display()))?;
    let mnemonic =
        crate::mnemonic_crypto::read_mnemonic(&config.identity.mnemonic_file, mnemonic_password)
            .with_context(|| {
                format!(
                    "failed to read mnemonic from {}",
                    config.identity.mnemonic_file.display()
                )
            })?;
    let identity =
        konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, config.identity.passphrase.as_str())
            .context("failed to derive identity from mnemonic")?;
    let storage = open_storage(&config, &identity).await?;

    let restored = read_whitelist_backup(storage.as_ref(), identity.aes_key(), from).await?;

    println!("Whitelist restore applied from: {}", from.display());
    println!("Re-admitted {restored} peer(s) into the storage whitelist.");
    println!(
        "On next start the P3-2 boot-load (merge_persisted_peers) loads them into the gate whitelist."
    );
    Ok(())
}

/// Open → restore the whitelist backup into storage. Returns the number of
/// peers restored. Separated from CLI plumbing for unit testing.
pub async fn read_whitelist_backup(
    storage: &dyn Storage,
    key: &[u8; 32],
    from: &Path,
) -> Result<usize> {
    let bytes = fs::read(from)
        .with_context(|| format!("failed to read whitelist backup: {}", from.display()))?;
    let backup = WhitelistBackup::open(&bytes, key)
        .with_context(|| "failed to open whitelist backup (wrong mnemonic or corrupt file)")?;
    let restored = backup
        .restore_into(storage)
        .await
        .context("failed to restore whitelist into storage")?;
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::NodeId;
    use konsensus_storage::Peer;

    #[tokio::test]
    async fn backup_round_trips_peer_through_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("t.db");
        let storage = konsensus_storage::SqliteStorage::open(db.to_str().unwrap())
            .await
            .expect("open sqlite");
        let mut peer = Peer::new(NodeId::from_bytes([9u8; 32]));
        peer.address = Some("198.51.100.4:9735".into());
        storage.upsert_peer(&peer).await.expect("upsert peer");

        let key = [5u8; 32];
        let out = dir.path().join("whitelist-latest.aes");
        let n = write_whitelist_backup(&storage, &key, &out)
            .await
            .expect("write backup");
        assert!(n > 12, "sealed blob must include nonce + ciphertext");
        assert!(out.exists(), "backup file must be written");

        // The on-disk file must open with the same key and contain the peer.
        let bytes = std::fs::read(&out).unwrap();
        let opened = WhitelistBackup::open(&bytes, &key).expect("open written backup");
        assert!(
            opened
                .peers
                .iter()
                .any(|p| p.node_id == NodeId::from_bytes([9u8; 32])),
            "restored backup must contain the upserted peer"
        );
    }

    #[tokio::test]
    async fn written_file_is_ciphertext_not_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let storage = konsensus_storage::SqliteStorage::open(
            dir.path().join("t.db").to_str().unwrap(),
        )
        .await
        .unwrap();
        let mut peer = Peer::new(NodeId::from_bytes([1u8; 32]));
        peer.display_name = Some("recognizable-name".into());
        storage.upsert_peer(&peer).await.unwrap();

        let out = dir.path().join("whitelist-latest.aes");
        write_whitelist_backup(&storage, &[7u8; 32], &out).await.unwrap();
        let bytes = std::fs::read(&out).unwrap();
        assert!(
            !bytes
                .windows(b"recognizable-name".len())
                .any(|w| w == b"recognizable-name"),
            "backup file must be encrypted at rest"
        );
    }

    #[tokio::test]
    async fn backup_then_restore_into_fresh_db_recovers_gate_whitelist() {
        use crate::node::merge_persisted_peers;
        use konsensus_message::PeerRegistry;

        let dir = tempfile::tempdir().unwrap();
        let key = [11u8; 32];

        // Node A: storage holding an invite-onboarded peer.
        let store_a =
            konsensus_storage::SqliteStorage::open(dir.path().join("a.db").to_str().unwrap())
                .await
                .unwrap();
        let peer_id = NodeId::from_bytes([21u8; 32]);
        let mut peer = Peer::new(peer_id);
        peer.address = Some("203.0.113.50:9735".into());
        store_a.upsert_peer(&peer).await.unwrap();

        // Back up A's whitelist to the sidecar.
        let backup_file = dir.path().join("whitelist-latest.aes");
        write_whitelist_backup(&store_a, &key, &backup_file)
            .await
            .unwrap();

        // Node B: a FRESH DB — simulates restore onto new hardware.
        let store_b =
            konsensus_storage::SqliteStorage::open(dir.path().join("b.db").to_str().unwrap())
                .await
                .unwrap();
        assert!(
            store_b.list_peers().await.unwrap().is_empty(),
            "fresh DB must start with no peers"
        );

        // Restore the sidecar into B.
        let restored = read_whitelist_backup(&store_b, &key, &backup_file)
            .await
            .unwrap();
        assert_eq!(restored, 1);
        let peers_b = store_b.list_peers().await.unwrap();
        assert!(peers_b.iter().any(|p| p.node_id == peer_id));

        // The P3-2 boot-load then places the restored peer in the gate whitelist
        // — proving fresh-hardware relationship recovery end to end (GA4).
        let mut registry = PeerRegistry::new();
        merge_persisted_peers(&mut registry, peers_b);
        assert!(
            registry.whitelist().contains(&peer_id),
            "restored peer must land in the gate whitelist after boot-load"
        );
    }
}
