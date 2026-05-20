//! Error types for the konsensus-mobile crate.

use thiserror::Error;

/// Errors surfaced to Swift/Kotlin via UniFFI.
#[derive(Debug, Error, uniffi::Error)]
pub enum MobileError {
    #[error("transport error: {msg}")]
    Transport { msg: String },

    #[error("noise error: {msg}")]
    Noise { msg: String },

    #[error("invalid key: {msg}")]
    InvalidKey { msg: String },

    #[error("connection closed")]
    ConnectionClosed,

    #[error("payload too large: {size} bytes (max 65519)")]
    PayloadTooLarge { size: u64 },
    /// Platform keychain/keystore returned an OS-level error.
    #[error("keychain error: {msg}")]
    KeychainError { msg: String },

    /// Biometric authentication was denied or cancelled by the user.
    #[error("biometric authentication denied or cancelled")]
    BiometricDenied,

    /// The device identity key has not been stored yet (run onboarding).
    #[error("device key not found — run onboarding first")]
    DeviceKeyNotFound,
}

impl MobileError {
    pub(crate) fn transport(e: impl std::fmt::Display) -> Self {
        Self::Transport { msg: e.to_string() }
    }

    pub(crate) fn noise(e: impl std::fmt::Display) -> Self {
        Self::Noise { msg: e.to_string() }
    }
}
