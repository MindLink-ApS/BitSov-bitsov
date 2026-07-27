//! Core error types for the BitSov system.

use thiserror::Error;

/// Top-level error type for konsensus-core operations.
#[derive(Debug, Error)]
pub enum CoreError {
    /// Invalid Ed25519 public key bytes.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid signature bytes or verification failure.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Invalid message ID (wrong length or format).
    #[error("invalid message id: {0}")]
    InvalidMessageId(String),

    /// Invalid nonce (wrong length).
    #[error("invalid nonce: {0}")]
    InvalidNonce(String),

    /// Envelope validation failure.
    #[error("envelope validation failed: {0}")]
    EnvelopeValidation(String),

    /// Payment proof validation failure.
    #[error("payment proof invalid: {0}")]
    InvalidPaymentProof(String),

    /// Serialization / deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Invalid room ID (wrong format).
    #[error("invalid room id: {0}")]
    InvalidRoomId(String),

    /// Hex decoding error.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),
}
