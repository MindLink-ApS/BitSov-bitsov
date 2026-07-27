//! SCB restore/import support for disaster recovery.
//!
//! `ldk-node` 0.7 does not currently expose a dedicated public
//! restore-from-monitor constructor. We therefore rehydrate the persisted
//! monitor key/value rows into the target node storage, then boot the node and
//! use its runtime APIs to inspect balances and force-close channels.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;

use bip39::Mnemonic;
use ldk_node::bitcoin::Network;
use ldk_node::config::EsploraSyncConfig;
use ldk_node::{Builder as LdkBuilder, LightningBalance, Node as LdkNode};
use rusqlite::params;

use crate::scb_rotate::decrypt_scb_backup;

const SCB_BLOB_MAGIC: &[u8; 8] = b"BSCBKV01";
const SQLITE_DB_FILE: &str = "ldk_node_data.sqlite";
const LDK_KDF_CONTEXT: &str = "konsensus-v2 ldk-lightning";
const SCB_ROTATION_KDF_CONTEXT: &str = "konsensus-v2 scb-rotation";
const CHANNEL_MANAGER_PRIMARY_NAMESPACE: &str = "";
const CHANNEL_MANAGER_SECONDARY_NAMESPACE: &str = "";
const CHANNEL_MANAGER_KEY: &str = "manager";

#[derive(Debug, thiserror::Error)]
pub enum ScbRestoreError {
    #[error("SCB restore I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SCB restore SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("SCB restore decode error: {0}")]
    Decode(String),
    #[error("SCB restore LDK error: {0}")]
    Ldk(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MonitorEntry {
    primary_namespace: String,
    secondary_namespace: String,
    key: String,
    value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredChannelEstimate {
    pub channel_id: String,
    pub counterparty: String,
    pub amount_sats: u64,
}

pub struct RestoredScbContext {
    pub node: LdkNode,
    pub estimates: Vec<RestoredChannelEstimate>,
}

pub fn derive_scb_master_key(
    mnemonic: &str,
    passphrase: Option<&str>,
) -> Result<[u8; 32], ScbRestoreError> {
    let ldk_seed = derive_ldk_entropy_seed(mnemonic, passphrase)?;
    Ok(derive_scb_master_key_from_ldk_seed(&ldk_seed))
}

pub fn derive_ldk_entropy_seed(
    mnemonic: &str,
    passphrase: Option<&str>,
) -> Result<[u8; 64], ScbRestoreError> {
    let mnemonic = Mnemonic::from_str(mnemonic)
        .map_err(|e| ScbRestoreError::Decode(format!("invalid mnemonic: {e}")))?;
    let seed = mnemonic.to_seed(passphrase.unwrap_or(""));

    let mut ldk_seed = [0u8; 64];
    let mut reader = blake3::Hasher::new_derive_key(LDK_KDF_CONTEXT)
        .update(&seed)
        .finalize_xof();
    reader.fill(&mut ldk_seed);

    Ok(ldk_seed)
}

pub fn derive_scb_master_key_from_ldk_seed(ldk_seed: &[u8; 64]) -> [u8; 32] {
    blake3::derive_key(SCB_ROTATION_KDF_CONTEXT, ldk_seed)
}

pub fn decrypt_and_load_scb_backup(
    encrypted_bytes: &[u8],
    master_aes_key: &[u8; 32],
    ldk_entropy_seed: [u8; 64],
    storage_dir: &Path,
    network: &str,
    esplora_url: &str,
) -> Result<RestoredScbContext, ScbRestoreError> {
    let decrypted = decrypt_scb_backup(encrypted_bytes, master_aes_key)
        .map_err(|e| ScbRestoreError::Decode(e.to_string()))?;
    load_plain_scb_blob(&decrypted, storage_dir)?;

    let mut builder = LdkBuilder::new();
    let network = match network {
        "bitcoin" => Network::Bitcoin,
        "testnet" => Network::Testnet,
        "signet" => Network::Signet,
        "regtest" => Network::Regtest,
        other => return Err(ScbRestoreError::Decode(format!("invalid network: {other}"))),
    };
    builder.set_network(network);
    builder.set_entropy_seed_bytes(ldk_entropy_seed);
    builder.set_storage_dir_path(storage_dir.to_string_lossy().to_string());
    builder.set_chain_source_esplora(esplora_url.to_string(), Some(EsploraSyncConfig::default()));

    let node = builder
        .build()
        .map_err(|e| ScbRestoreError::Ldk(format!("build failed: {e}")))?;
    node.start()
        .map_err(|e| ScbRestoreError::Ldk(format!("start failed: {e}")))?;

    let estimates = summarize_estimates(&node.list_balances().lightning_balances);

    Ok(RestoredScbContext { node, estimates })
}

pub fn force_close_restored_channels(node: &LdkNode) -> Result<Vec<String>, ScbRestoreError> {
    let channels = node.list_channels();
    let mut forced = Vec::new();

    for ch in channels {
        let user_channel_id = ch.user_channel_id;
        node.force_close_channel(&user_channel_id, ch.counterparty_node_id, None)
            .map_err(|e| ScbRestoreError::Ldk(format!("force-close failed: {e}")))?;
        forced.push(format!("{}", user_channel_id));
    }

    Ok(forced)
}

fn load_plain_scb_blob(blob: &[u8], storage_dir: &Path) -> Result<(), ScbRestoreError> {
    let entries = parse_blob_entries(blob)?;
    validate_required_entries(&entries)?;
    std::fs::create_dir_all(storage_dir)?;

    let db_path = storage_dir.join(SQLITE_DB_FILE);
    let conn = rusqlite::Connection::open(db_path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS ldk_node_data (
            primary_namespace TEXT NOT NULL,
            secondary_namespace TEXT DEFAULT '' NOT NULL,
            key TEXT NOT NULL CHECK (key <> ''),
            value BLOB,
            PRIMARY KEY (primary_namespace, secondary_namespace, key)
        )",
    )?;

    let tx = conn.unchecked_transaction()?;
    tx.execute("DELETE FROM ldk_node_data", [])?;
    for entry in entries {
        tx.execute(
            "INSERT OR REPLACE INTO ldk_node_data
             (primary_namespace, secondary_namespace, key, value)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                entry.primary_namespace,
                entry.secondary_namespace,
                entry.key,
                entry.value,
            ],
        )?;
    }
    tx.commit()?;
    Ok(())
}

fn validate_required_entries(entries: &[MonitorEntry]) -> Result<(), ScbRestoreError> {
    let has_channel_manager = entries.iter().any(|entry| {
        entry.primary_namespace == CHANNEL_MANAGER_PRIMARY_NAMESPACE
            && entry.secondary_namespace == CHANNEL_MANAGER_SECONDARY_NAMESPACE
            && entry.key == CHANNEL_MANAGER_KEY
    });

    if !has_channel_manager {
        return Err(ScbRestoreError::Decode(
            "SCB blob missing LDK channel-manager state; cannot force-close restored channels"
                .into(),
        ));
    }

    Ok(())
}

fn parse_blob_entries(blob: &[u8]) -> Result<Vec<MonitorEntry>, ScbRestoreError> {
    if blob.len() < SCB_BLOB_MAGIC.len() + 4 {
        return Err(ScbRestoreError::Decode("blob too short".into()));
    }
    if &blob[..SCB_BLOB_MAGIC.len()] != SCB_BLOB_MAGIC {
        return Err(ScbRestoreError::Decode("invalid SCB blob magic".into()));
    }

    let mut cursor = SCB_BLOB_MAGIC.len();
    let count = read_u32(blob, &mut cursor)? as usize;
    let mut out = Vec::with_capacity(count);

    for _ in 0..count {
        let primary = read_str(blob, &mut cursor)?;
        let secondary = read_str(blob, &mut cursor)?;
        let key = read_str(blob, &mut cursor)?;
        let value_len = read_u32(blob, &mut cursor)? as usize;
        if cursor + value_len > blob.len() {
            return Err(ScbRestoreError::Decode("value exceeds blob bounds".into()));
        }
        let value = blob[cursor..cursor + value_len].to_vec();
        cursor += value_len;

        out.push(MonitorEntry {
            primary_namespace: primary,
            secondary_namespace: secondary,
            key,
            value,
        });
    }

    if cursor != blob.len() {
        return Err(ScbRestoreError::Decode(
            "trailing bytes after SCB entries".into(),
        ));
    }

    Ok(out)
}

fn summarize_estimates(balances: &[LightningBalance]) -> Vec<RestoredChannelEstimate> {
    let mut by_channel = BTreeMap::<(String, String), u64>::new();
    for bal in balances {
        let (channel_id, counterparty, amount) = match bal {
            LightningBalance::ClaimableOnChannelClose {
                channel_id,
                counterparty_node_id,
                amount_satoshis,
                ..
            }
            | LightningBalance::ClaimableAwaitingConfirmations {
                channel_id,
                counterparty_node_id,
                amount_satoshis,
                ..
            }
            | LightningBalance::ContentiousClaimable {
                channel_id,
                counterparty_node_id,
                amount_satoshis,
                ..
            }
            | LightningBalance::MaybeTimeoutClaimableHTLC {
                channel_id,
                counterparty_node_id,
                amount_satoshis,
                ..
            }
            | LightningBalance::MaybePreimageClaimableHTLC {
                channel_id,
                counterparty_node_id,
                amount_satoshis,
                ..
            }
            | LightningBalance::CounterpartyRevokedOutputClaimable {
                channel_id,
                counterparty_node_id,
                amount_satoshis,
            } => (
                channel_id.to_string(),
                counterparty_node_id.to_string(),
                *amount_satoshis,
            ),
        };
        *by_channel.entry((channel_id, counterparty)).or_insert(0) += amount;
    }

    by_channel
        .into_iter()
        .map(
            |((channel_id, counterparty), amount_sats)| RestoredChannelEstimate {
                channel_id,
                counterparty,
                amount_sats,
            },
        )
        .collect()
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<u16, ScbRestoreError> {
    if *cursor + 2 > input.len() {
        return Err(ScbRestoreError::Decode("unexpected EOF (u16)".into()));
    }
    let value = u16::from_be_bytes([input[*cursor], input[*cursor + 1]]);
    *cursor += 2;
    Ok(value)
}

fn read_u32(input: &[u8], cursor: &mut usize) -> Result<u32, ScbRestoreError> {
    if *cursor + 4 > input.len() {
        return Err(ScbRestoreError::Decode("unexpected EOF (u32)".into()));
    }
    let value = u32::from_be_bytes([
        input[*cursor],
        input[*cursor + 1],
        input[*cursor + 2],
        input[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(value)
}

fn read_str(input: &[u8], cursor: &mut usize) -> Result<String, ScbRestoreError> {
    let len = read_u16(input, cursor)? as usize;
    if *cursor + len > input.len() {
        return Err(ScbRestoreError::Decode("unexpected EOF (str)".into()));
    }
    let bytes = &input[*cursor..*cursor + len];
    *cursor += len;
    String::from_utf8(bytes.to_vec())
        .map_err(|e| ScbRestoreError::Decode(format!("invalid utf-8 field: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scb_restore_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let storage_dir = tmp.path().join("ldk");

        let mut blob = Vec::new();
        blob.extend_from_slice(SCB_BLOB_MAGIC);
        blob.extend_from_slice(&2u32.to_be_bytes());
        blob.extend_from_slice(&0u16.to_be_bytes());
        blob.extend_from_slice(&0u16.to_be_bytes());
        blob.extend_from_slice(&7u16.to_be_bytes());
        blob.extend_from_slice(b"manager");
        blob.extend_from_slice(&12u32.to_be_bytes());
        blob.extend_from_slice(b"manager-data");
        blob.extend_from_slice(&8u16.to_be_bytes());
        blob.extend_from_slice(b"monitors");
        blob.extend_from_slice(&0u16.to_be_bytes());
        blob.extend_from_slice(&6u16.to_be_bytes());
        blob.extend_from_slice(b"chan-a");
        blob.extend_from_slice(&4u32.to_be_bytes());
        blob.extend_from_slice(b"data");

        load_plain_scb_blob(&blob, &storage_dir).unwrap();

        let conn = rusqlite::Connection::open(storage_dir.join(SQLITE_DB_FILE)).unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT value FROM ldk_node_data
                 WHERE primary_namespace = 'monitors' AND key = 'chan-a'",
            )
            .unwrap();
        let value: Vec<u8> = stmt.query_row([], |row| row.get(0)).unwrap();
        assert_eq!(value, b"data");
    }

    #[test]
    fn scb_restore_rejects_blob_without_channel_manager() {
        let tmp = tempfile::tempdir().unwrap();
        let storage_dir = tmp.path().join("ldk");

        let mut blob = Vec::new();
        blob.extend_from_slice(SCB_BLOB_MAGIC);
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.extend_from_slice(&8u16.to_be_bytes());
        blob.extend_from_slice(b"monitors");
        blob.extend_from_slice(&0u16.to_be_bytes());
        blob.extend_from_slice(&6u16.to_be_bytes());
        blob.extend_from_slice(b"chan-a");
        blob.extend_from_slice(&4u32.to_be_bytes());
        blob.extend_from_slice(b"data");

        let err = load_plain_scb_blob(&blob, &storage_dir).unwrap_err();
        assert!(
            err.to_string().contains("channel-manager"),
            "unexpected error: {err}"
        );
    }
}
