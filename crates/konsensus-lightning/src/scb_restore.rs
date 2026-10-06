//! SCB key derivation and permanently disabled legacy restore entry points.
//! Never rehydrate a historical channel manager/monitor into a running LDK node.
use bip39::Mnemonic;
use ldk_node::Node as LdkNode;
use std::{path::Path, str::FromStr};

pub const RESTORE_DISABLED: &str = "SCB restore is disabled: stale channel state can broadcast a revoked commitment and lose channel funds with the pinned LDK. Preview is disabled too; there is no override. To move funds from a healthy node with its current live state, use `konsensus move-home` (docs/operations/move-home.md). For a lost disk, preserve backups and coordinate recovery with channel peers; move-home cannot recover lost channel state. Restore relationships separately with `konsensus whitelist restore`.";
const LDK_KDF_CONTEXT: &str = "konsensus-v2 ldk-lightning";
const SCB_ROTATION_KDF_CONTEXT: &str = "konsensus-v2 scb-rotation";

#[derive(Debug, thiserror::Error)]
pub enum ScbRestoreError {
    #[error("{RESTORE_DISABLED}")]
    Disabled,
    #[error("SCB restore decode error: {0}")]
    Decode(String),
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

/// Compatibility entry point: fail before decrypting, touching disk or building LDK.
pub fn decrypt_and_load_scb_backup(
    _encrypted_bytes: &[u8],
    _master_aes_key: &[u8; 32],
    _ldk_entropy_seed: [u8; 64],
    _storage_dir: &Path,
    _network: &str,
    _esplora_url: &str,
) -> Result<RestoredScbContext, ScbRestoreError> {
    Err(ScbRestoreError::Disabled)
}

/// Disabled even for callers bypassing the CLI. There is no feature/flag override.
pub fn force_close_restored_channels(_node: &LdkNode) -> Result<Vec<String>, ScbRestoreError> {
    Err(ScbRestoreError::Disabled)
}
