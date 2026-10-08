//! Offline recovery of LDK v2 static `to_remote` outputs, optionally indexed by backup.
//!
//! This library does not start a node, read a wallet, access the network, or broadcast.
//! Supply the **32-byte LDK seed**, not a BIP39 seed or the BDK wallet seed. Only
//! channels using LDK's v2 remote-key derivation are covered; HTLCs and v1 keys are not.
//! [`BackupIndex`] authenticates an SCB export and extracts only seed-verified
//! public hints. It never restores a manager or monitor; legacy v1 scripts fail
//! with [`BackupError::UnknownScript`].
//! Scanners receive public scripts only. The caller must authenticate prevouts against
//! the chain, check destination network/ownership, and recheck unspentness and maturity
//! after reorgs before broadcasting. Confirmation counts here are a scanner assertion,
//! not a chain proof. One confirmation permits CSV-1 spending in the next block.
#![forbid(unsafe_code)]

mod backup;
mod keys;
mod sweep;

pub use backup::{BackupError, BackupIndex, ChannelRecoveryMetadata, MAX_BACKUP_BYTES};
pub use keys::{OutputKind, RecoveryKeys, RecoveryScript, STATIC_KEY_COUNT};
pub use sweep::Sweep;

use bitcoin::{OutPoint, TxOut};

/// A candidate unspent output from a chain scan. Contains no secret material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FoundOutput {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    /// Confirmations at the scanner's chain tip; zero means unconfirmed.
    pub confirmations: u32,
}

/// Backend boundary for PR4. Implementations must return complete, authenticated
/// prevouts and confirmation counts from a consistent chain view. Implementations
/// must not return spent outputs. A scan can be repeated using only public data.
#[async_trait::async_trait]
pub trait Scanner {
    type Error: std::error::Error + Send + Sync + 'static;
    async fn scan(&self, scripts: &[RecoveryScript]) -> Result<Vec<FoundOutput>, Self::Error>;
}

/// Errors deliberately contain no seed, key, or underlying secret-bearing object.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RecoveryError {
    #[error("LDK static key derivation failed")]
    Derivation,
    #[error("no outputs to sweep")]
    NoOutputs,
    #[error("duplicate outpoint")]
    DuplicateOutpoint,
    #[error("output script is not a derived v2 static script")]
    UnknownScript,
    #[error("output must be confirmed before recovery")]
    UnconfirmedOutput,
    #[error("invalid input amount or total exceeds MAX_MONEY")]
    InvalidAmount,
    #[error("destination must be a standard payment script")]
    InvalidDestination,
    #[error("feerate must be nonzero")]
    ZeroFeeRate,
    #[error("fee calculation overflow")]
    FeeOverflow,
    #[error("inputs do not cover the fee")]
    InsufficientFunds,
    #[error("sweep output would be dust")]
    DustOutput,
    #[error("sweep exceeds standard transaction weight; split the inputs")]
    TooHeavy,
    #[error("sweep signature construction failed")]
    Signing,
}

#[cfg(test)]
mod tests;
