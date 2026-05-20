//! konsensus-storage — SQLite + PostgreSQL storage backends with optional at-rest encryption.

#![forbid(unsafe_code)]

pub mod calendar;
pub mod contacts;
pub mod encrypted;
pub mod error;
pub mod fiat_snapshots;
pub mod models;
pub mod postgres;
pub mod reactions;
pub mod recovery;
pub mod sqlite;
pub mod traits;

pub use calendar::{CalendarEventRecord, RsvpRecord};
pub use contacts::{ContactRepo, ContactRow, PostgresContactRepo, SqliteContactRepo};
pub use encrypted::EncryptedStorage;
pub use error::StorageError;
pub use fiat_snapshots::FiatRateSnapshot;
pub use invites::{
    AcceptedInviteRecord, InviteIssuedRecord, InviteSchemaCapabilities, InviteState,
};
pub use models::{FileMetadata, FileRecord, OnboardingStateRecord, Peer, Room};
pub use postgres::PostgresStorage;
pub use reactions::ReactionRecord;
pub use recovery::{
    EncryptedRecoveryStore, PostgresRecoveryStore, RecoveryScheme, RecoveryShard, RecoveryStore,
    RecoveryTrustee, SqliteRecoveryStore,
};
pub use sqlite::SqliteStorage;
pub use traits::Storage;

pub mod invites {
    use std::fmt;
    use std::str::FromStr;

    /// Lifecycle state for an issued invite.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum InviteState {
        /// Invite is issued and awaiting acceptance.
        Pending,
        /// Invite has been accepted.
        Accepted,
        /// Invite has passed guards and a channel open is in-flight.
        Opening,
        /// Invite has been revoked by inviter.
        Revoked,
        /// Invite auto-channel intent expired before acceptance.
        Expired,
    }

    impl fmt::Display for InviteState {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let state = match self {
                Self::Pending => "pending",
                Self::Accepted => "accepted",
                Self::Opening => "opening",
                Self::Revoked => "revoked",
                Self::Expired => "expired",
            };
            write!(f, "{state}")
        }
    }

    impl FromStr for InviteState {
        type Err = String;

        fn from_str(value: &str) -> Result<Self, Self::Err> {
            match value {
                "pending" => Ok(Self::Pending),
                "accepted" => Ok(Self::Accepted),
                "opening" => Ok(Self::Opening),
                "revoked" => Ok(Self::Revoked),
                "expired" => Ok(Self::Expired),
                _ => Err(format!("invalid invite state: {value}")),
            }
        }
    }

    /// Persistent record for an issued BitSov invite (inviter-side).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct InviteIssuedRecord {
        /// Invite identifier (UUID v4).
        pub id: uuid::Uuid,
        /// Invitee Ed25519 public key.
        pub invitee_pubkey: [u8; 32],
        /// Invite expiry timestamp (Unix seconds).
        pub expiry_unix: u64,
        /// Optional channel size hint in sats.
        pub channel_size_hint_sats: Option<u32>,
        /// Inviter's dialable network address, signed into BitSovInvite v2.
        pub addr: String,
        /// Inviter-signed upper bound for automatic channel-open fee rate.
        pub max_fee_rate_sat_per_vb: Option<u32>,
        /// Inviter-signed expiry for the automatic channel-open intent.
        pub channel_open_intent_expiry_unix: Option<u64>,
        /// Invite nonce (16 random bytes).
        pub nonce: [u8; 16],
        /// Lifecycle state.
        pub state: InviteState,
        /// Creation timestamp (Unix seconds).
        pub created_at: u64,
        /// Acceptance timestamp (Unix seconds), if accepted.
        pub accepted_at: Option<u64>,
        /// Revocation timestamp (Unix seconds), if revoked.
        pub revoked_at: Option<u64>,
    }

    /// Persistent record for an accepted BitSov invite (invitee-side).
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct AcceptedInviteRecord {
        /// Invite nonce (16 random bytes), unique per invite.
        pub nonce: [u8; 16],
        /// Inviter Ed25519 public key.
        pub inviter_pubkey: [u8; 32],
        /// Original invite expiry timestamp (Unix seconds).
        pub expiry_unix: u64,
        /// Acceptance timestamp (Unix seconds).
        pub accepted_at: u64,
    }

    /// Runtime view of the invite storage schema.
    ///
    /// ONB5a made BitSovInvite v2 issuance depend on three persisted columns.
    /// This capability surface lets the API fail closed during mixed-version
    /// deploys instead of signing invites that the local database cannot store.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct InviteSchemaCapabilities {
        pub addr_column: bool,
        pub max_fee_rate_sat_per_vb_column: bool,
        pub channel_open_intent_expiry_unix_column: bool,
    }

    impl InviteSchemaCapabilities {
        pub fn v2_ready(self) -> bool {
            self.addr_column
                && self.max_fee_rate_sat_per_vb_column
                && self.channel_open_intent_expiry_unix_column
        }

        pub fn v2_ready_default() -> Self {
            Self {
                addr_column: true,
                max_fee_rate_sat_per_vb_column: true,
                channel_open_intent_expiry_unix_column: true,
            }
        }

        pub fn not_ready() -> Self {
            Self {
                addr_column: false,
                max_fee_rate_sat_per_vb_column: false,
                channel_open_intent_expiry_unix_column: false,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{InviteSchemaCapabilities, InviteState};
        use std::str::FromStr;

        #[test]
        fn invite_state_display_from_str_round_trip() {
            let states = [
                InviteState::Pending,
                InviteState::Accepted,
                InviteState::Opening,
                InviteState::Revoked,
                InviteState::Expired,
            ];

            for state in states {
                let text = state.to_string();
                assert_eq!(InviteState::from_str(&text).expect("valid state"), state);
            }
        }

        #[test]
        fn invite_schema_capabilities_reports_v2_readiness() {
            assert!(InviteSchemaCapabilities::v2_ready_default().v2_ready());
            assert!(!InviteSchemaCapabilities::not_ready().v2_ready());
        }
    }
}

/// Adapter that bridges `dyn Storage` → `NonceStore` for the payment gate.
///
/// The payment gate (konsensus-core) requires a `NonceStore` for replay protection,
/// but the full `Storage` trait lives in this crate. This adapter wraps any `Storage`
/// impl to satisfy the `NonceStore` interface.
pub struct StorageNonceAdapter<S: Storage + ?Sized> {
    inner: std::sync::Arc<S>,
}

impl<S: Storage + ?Sized> StorageNonceAdapter<S> {
    /// Create a new adapter wrapping the given storage.
    pub fn new(storage: std::sync::Arc<S>) -> Self {
        Self { inner: storage }
    }
}

#[async_trait::async_trait]
impl<S: Storage + ?Sized> konsensus_core::gate::NonceStore for StorageNonceAdapter<S> {
    async fn check_and_store(
        &self,
        nonce: &konsensus_core::Nonce,
        sender: &konsensus_core::NodeId,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.inner
            .store_nonce(nonce, sender)
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
    }
}
