//! konsensus-core — types, traits, identity, federation, and errors for the BitSov v2 system.
//!
//! This crate has no internal dependencies and defines the foundational types
//! shared across all other BitSov crates.

#![forbid(unsafe_code)]

pub mod logging;
pub mod calendar;
pub mod card_cache;
pub mod contracts;
pub mod envelope;
pub mod error;
pub mod federation;
pub mod fee_rate;
pub mod front_door;
pub mod gate;
pub mod identity;
pub mod introduction;
pub mod sponsor;
pub mod invite;
pub mod kind;
pub mod payloads;
pub mod profile;
pub mod tower;
pub mod traits;
pub mod types;
pub mod web_reply;

// Re-export primary types for convenience.
pub use contracts::{
    HostingContractError, HostingContractState, OperatorHostingContract, OperatorHostingPayment,
    OperatorHostingPaymentDirection,
};
pub use envelope::{UkmEnvelope, UkmEnvelopeBuilder};
pub use error::CoreError;
pub use federation::SignedMessage;
pub use identity::{IdentityError, NodeIdentity, OwnerApprovalKey};
pub use kind::KindCategory;
pub use types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, RoomId, Signature};

// Re-export core traits.
pub use gate::{GateConfig, GateRejection, NonceStore, PaymentGate};
pub use invite::{BitSovInvite, InviteError, InviteToken};
pub use web_reply::{
    expected_reply_kind, is_web_service_reply, reply_bound_proof, reply_matches_outstanding,
    OutstandingWebRequest, OUTSTANDING_TTL_MS,
};
pub use traits::{
    BlockHeader, ChainError, ChainProvider, FeeEstimate, TrustLevel,
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
    MediaError, MediaTransport,
    MessageTransport, TransportError,
    PricingEngine, PricingError,
};

pub mod admission_quote;
