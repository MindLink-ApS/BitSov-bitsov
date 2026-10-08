//! Read-only metadata from BSCBKV01 exports and pinned LDK 0.2.2 monitors.
//!
//! No LDK dependency exists in the production recovery dependency graph. In
//! particular we do not implement LDK serialization, retain monitor bytes, or
//! expose a store, signer provider, event handler, or broadcaster to this parser.
//! Updates and the manager are opaque: snapshot counters are historical hints,
//! never proof of freshness, current balance, or permission to broadcast.

mod wire;
use wire::Reader;

use std::collections::BTreeSet;

use bitcoin::{hashes::Hash, secp256k1::PublicKey, OutPoint, Txid};
use zeroize::Zeroizing;

use crate::{RecoveryKeys, RecoveryScript};

/// Hard cap before decryption allocates plaintext (64 MiB plus v1 envelope).
pub const MAX_BACKUP_BYTES: usize = 64 * 1024 * 1024 + 36;
const MAX_ENTRIES: usize = 65_536;
const MAX_CHANNELS: usize = 4096;

/// Errors never contain plaintext, cryptographic keys, or underlying LDK objects.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackupError {
    #[error("backup exceeds recovery resource limits")]
    LimitExceeded,
    #[error("backup authentication or encrypted envelope failed")]
    Decryption,
    #[error("invalid or truncated backup metadata")]
    InvalidFormat,
    #[error("unsupported backup or monitor format")]
    UnsupportedFormat,
    #[error("backup script is not a v2 static script for this seed")]
    UnknownScript,
    #[error("duplicate funding outpoint in backup")]
    DuplicateChannel,
}

/// Public hints only; no commitments, signatures, secrets, or serialized state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRecoveryMetadata {
    pub funding_outpoint: OutPoint,
    pub counterparty_node_id: PublicKey,
    /// Exact stored script, matched against PR2 derivation. AnchorToRemote is
    /// the CSV-1 balance output, not the separate 330-sat funding-key anchor.
    pub to_remote: RecoveryScript,
    /// Original capacity, not a claim about the recoverable/current balance.
    pub channel_value_satoshis: u64,
    pub archived: bool,
    /// Snapshot's monitor update id. Separate monitor_updates are not applied.
    pub monitor_update_id: u64,
    /// LDK's descending 48-bit commitment counters at snapshot time.
    pub holder_commitment_number: u64,
    pub counterparty_commitment_number: u64,
    /// Monitor's last observed chain height, not a freshness proof.
    pub best_block_height: u32,
}

/// Immutable, owned public index. Decrypted state is erased after parsing.
///
/// The index cannot be used as an LDK monitor or deserialized through LDK:
/// ```compile_fail
/// use konsensus_recovery::BackupIndex;
/// use lightning::util::ser::Readable;
/// fn require_ldk_reader<T: Readable>() {}
/// require_ldk_reader::<BackupIndex>();
/// ```
/// ```compile_fail
/// use konsensus_recovery::ChannelRecoveryMetadata;
/// use lightning::util::ser::Writeable;
/// fn require_ldk_writer<T: Writeable>() {}
/// require_ldk_writer::<ChannelRecoveryMetadata>();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupIndex {
    channels: Vec<ChannelRecoveryMetadata>,
}

impl BackupIndex {
    /// Authenticate with the existing SCB AES envelope, parse in memory, and
    /// erase the owned plaintext buffer on both success and failure. The key is
    /// the existing mnemonic-derived backup AES key, not the 32-byte LDK seed.
    pub fn decrypt(
        encrypted: &[u8],
        backup_key: &[u8; 32],
        keys: &RecoveryKeys,
    ) -> Result<Self, BackupError> {
        if encrypted.len() > MAX_BACKUP_BYTES {
            return Err(BackupError::LimitExceeded);
        }
        let plaintext = Zeroizing::new(
            konsensus_crypto::scb::decrypt_scb_backup(encrypted, backup_key)
                .map_err(|_| BackupError::Decryption)?,
        );
        Self::from_plaintext(&plaintext, keys)
    }

    /// Parse an already authenticated export. Caller owns and must erase this
    /// plaintext. Manager/update values are skipped, never replayed. Only the
    /// pinned monitor layout is supported; unknown versions fail closed.
    /// Even a verified script/outpoint must be authenticated against the chain.
    pub fn from_plaintext(plaintext: &[u8], keys: &RecoveryKeys) -> Result<Self, BackupError> {
        if plaintext.len() > MAX_BACKUP_BYTES - 36 {
            return Err(BackupError::LimitExceeded);
        }
        let mut r = Reader::new(plaintext);
        if r.take(8)? != b"BSCBKV01" {
            return Err(BackupError::UnsupportedFormat);
        }
        let count = r.u32()? as usize;
        if count > MAX_ENTRIES {
            return Err(BackupError::LimitExceeded);
        }
        let mut channels = Vec::new();
        let mut funding = BTreeSet::new();
        for _ in 0..count {
            let primary = r.field()?;
            let secondary = r.field()?;
            let key = r.field()?;
            let len = r.u32()? as usize;
            let value = r.take(len)?;
            if key.is_empty() {
                return Err(BackupError::InvalidFormat);
            }
            match primary {
                b"monitors" | b"archived_monitors" if secondary.is_empty() => {
                    if channels.len() == MAX_CHANNELS {
                        return Err(BackupError::LimitExceeded);
                    }
                    let channel = monitor(value, keys, primary == b"archived_monitors")?;
                    if !funding.insert(channel.funding_outpoint) {
                        return Err(BackupError::DuplicateChannel);
                    }
                    channels.push(channel);
                }
                b"monitor_updates" => {}
                b"" if secondary.is_empty() && key == b"manager" => {}
                _ => return Err(BackupError::UnsupportedFormat),
            }
        }
        r.finish()?;
        channels.sort_by_key(|channel| channel.funding_outpoint);
        Ok(Self { channels })
    }

    pub fn channels(&self) -> &[ChannelRecoveryMetadata] {
        &self.channels
    }
}

// Walk write_chanmon_internal in vendor/lightning/src/chain/channelmonitor.rs.
// All ignored state is borrowed and skipped; no operational LDK value is built.
fn monitor(
    bytes: &[u8],
    keys: &RecoveryKeys,
    archived: bool,
) -> Result<ChannelRecoveryMetadata, BackupError> {
    let mut r = Reader::new(bytes);
    r.version()?;
    let monitor_update_id = r.u64()?;
    r.take(6)?; // obscure factor
    r.field()?; // destination script
    match r.u8()? {
        0 => {
            r.field()?;
            r.take(33)?;
            r.field()?;
        }
        1 => {}
        _ => return Err(BackupError::InvalidFormat),
    }
    // Despite its name, counterparty_payment_script is OUR output on their tx.
    let script = r.field()?;
    let to_remote = keys
        .scripts()
        .iter()
        .find(|s| s.script_pubkey.as_bytes() == script)
        .ok_or(BackupError::UnknownScript)?
        .clone();
    r.field()?; // shutdown script
    r.take(32 + 33)?; // channel_keys_id and holder revocation basepoint
    let funding_outpoint = OutPoint {
        txid: Txid::from_byte_array(r.array()?),
        vout: u32::from(r.u16()?),
    };
    r.field()?; // funding script
    r.option()?;
    r.option()?; // current/previous counterparty txids
    if r.u64()? != 0 {
        return Err(BackupError::UnsupportedFormat);
    } // pre-0.0.100 legacy state
    r.tlv()?; // counterparty commitment parameters
    r.field()?; // funding redeemscript
    let channel_value_satoshis = r.u64()?;
    if channel_value_satoshis > bitcoin::Amount::MAX_MONEY.to_sat() {
        return Err(BackupError::InvalidFormat);
    }
    if r.u48()? != 0 {
        r.take(66)?;
    }
    r.take(2 + 49 * 40)?; // CSV and revocation secret slots (never copy secrets)
    r.tlv()?;
    for _ in 0..r.count()? {
        r.take(32)?;
        for _ in 0..r.count()? {
            r.take(1 + 8 + 4 + 32)?; // HTLC scalar fields
            r.option()?;
            r.option()?; // output index and HTLC source
        }
    }
    for _ in 0..2 {
        let count = r.count()?;
        r.skip_items(count, 38)?;
    }
    if r.boolean()? {
        r.tlv()?;
    } // previous holder commitment
    r.tlv()?; // current holder commitment: skip signatures and transactions
    let counterparty_commitment_number = r.u48()?;
    let holder_commitment_number = r.u48()?;
    let count = r.count()?;
    r.skip_items(count, 32)?; // payment preimages
    for _ in 0..r.count()? {
        match r.u8()? {
            0 => {
                r.tlv()?;
            }
            1 => {}
            _ => return Err(BackupError::InvalidFormat),
        }
    }
    for _ in 0..r.count()? {
        r.event()?;
    }
    r.take(32)?;
    let best_block_height = r.u32()?;
    for _ in 0..r.count()? {
        r.tlv()?;
    }
    for _ in 0..r.count()? {
        r.take(32)?;
        for _ in 0..r.count()? {
            r.take(4)?;
            r.field()?;
        }
    }
    r.onchain_handler()?;
    r.boolean()?;
    r.boolean()?;
    let mut fields = Reader::new(r.tlv()?);
    let mut previous = None;
    let mut counterparty_node_id = None;
    while !fields.is_empty() {
        let typ = fields.bigsize()?;
        if previous.is_some_and(|p| typ <= p) {
            return Err(BackupError::InvalidFormat);
        }
        previous = Some(typ);
        let value = fields.tlv()?;
        if typ == 9 {
            counterparty_node_id =
                Some(PublicKey::from_slice(value).map_err(|_| BackupError::InvalidFormat)?);
        }
    }
    r.finish()?;
    Ok(ChannelRecoveryMetadata {
        funding_outpoint,
        counterparty_node_id: counterparty_node_id.ok_or(BackupError::InvalidFormat)?,
        to_remote,
        channel_value_satoshis,
        archived,
        monitor_update_id,
        holder_commitment_number,
        counterparty_commitment_number,
        best_block_height,
    })
}
