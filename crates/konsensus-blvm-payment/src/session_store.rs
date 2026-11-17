//! Persistence for outbound on-chain session state (path 3).

use async_trait::async_trait;
use konsensus_core::types::{MessageId, NodeId};
use thiserror::Error;

/// Stored open session for a recipient peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnChainSessionRecord {
    pub recipient: NodeId,
    pub payment_request_id: String,
    pub tx_hash: [u8; 32],
    pub amount_sats: u64,
    /// Next debit sequence to assign (monotonic within session).
    pub debit_counter: u64,
    /// Cumulative millisats debited from this session on send.
    pub spent_msat: u64,
}

/// Assigned debit sequence and session fields for one outbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnChainSessionDebit {
    pub payment_request_id: String,
    pub tx_hash: [u8; 32],
    pub amount_sats: u64,
    pub session_debit_seq: u64,
}

#[derive(Debug, Error)]
pub enum SessionStoreError {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("no open on-chain session for recipient {0}")]
    NoSession(String),

    #[error("session balance exhausted: need {required_msat} msat, {remaining_msat} remaining")]
    BalanceExhausted {
        required_msat: u64,
        remaining_msat: u64,
    },
}

#[async_trait]
pub trait OnChainSessionStore: Send + Sync {
    async fn get_for_recipient(
        &self,
        recipient: &NodeId,
    ) -> Result<Option<OnChainSessionRecord>, SessionStoreError>;

    async fn upsert(&self, record: &OnChainSessionRecord) -> Result<(), SessionStoreError>;

    /// Atomically assign the next debit sequence and increment spent balance (immediate).
    async fn try_debit_for_recipient(
        &self,
        recipient: &NodeId,
        debit_msat: u64,
    ) -> Result<OnChainSessionDebit, SessionStoreError>;

    /// Reserve a debit sequence; spent balance commits on peer ACK.
    async fn try_reserve_debit_for_recipient(
        &self,
        recipient: &NodeId,
        message_id: &MessageId,
        debit_msat: u64,
    ) -> Result<OnChainSessionDebit, SessionStoreError>;

    async fn commit_debit(&self, message_id: &MessageId) -> Result<(), SessionStoreError>;

    async fn rollback_debit(&self, message_id: &MessageId) -> Result<bool, SessionStoreError>;

    async fn delete_for_recipient(&self, recipient: &NodeId) -> Result<bool, SessionStoreError>;
}

/// In-memory atomic debit helper for tests and MemStore backends.
pub fn mem_try_debit_record(
    record: &mut OnChainSessionRecord,
    debit_msat: u64,
) -> Result<u64, SessionStoreError> {
    let session_total_msat = record.amount_sats.saturating_mul(1000);
    if record.spent_msat.saturating_add(debit_msat) > session_total_msat {
        let remaining_msat = session_total_msat.saturating_sub(record.spent_msat);
        return Err(SessionStoreError::BalanceExhausted {
            required_msat: debit_msat,
            remaining_msat,
        });
    }
    let seq = record.debit_counter;
    record.debit_counter = record.debit_counter.saturating_add(1);
    record.spent_msat = record.spent_msat.saturating_add(debit_msat);
    Ok(seq)
}
