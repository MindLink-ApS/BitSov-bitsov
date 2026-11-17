//! BLVM payment verification for UKM gate paths 2–3.

use async_trait::async_trait;
use thiserror::Error;

use crate::gate_payment::GatePaymentProof;

/// Errors from BLVM payment verification at the gate.
#[derive(Debug, Error)]
pub enum BlvmPaymentError {
    #[error("covenant verification failed: {0}")]
    CovenantRejected(String),

    #[error("on-chain session verification failed: {0}")]
    OnChainRejected(String),

    #[error("blvm payment backend unavailable: {0}")]
    Unavailable(String),
}

/// Verifies BLVM covenant and on-chain session proofs (paths 2–3).
#[async_trait]
pub trait BlvmPaymentVerifier: Send + Sync {
    async fn verify_gate_proof(&self, proof: &GatePaymentProof) -> Result<(), BlvmPaymentError>;
}

/// One inbound chat debit failed to record.
#[derive(Debug, Error)]
pub enum SessionDebitError {
    #[error("session debit sequence already used")]
    Replay,

    #[error("session debit store failed: {0}")]
    Store(String),
}

/// Durable inbound debit ledger. One settled on-chain tx pays many chats only
/// through `session_debit_seq`. Replaying a sequence fails.
#[async_trait]
pub trait SessionDebitStore: Send + Sync {
    async fn record_inbound_debit(
        &self,
        payment_request_id: &str,
        tx_hash: &[u8; 32],
        session_debit_seq: u64,
        debit_msat: u64,
    ) -> Result<(), SessionDebitError>;
}
