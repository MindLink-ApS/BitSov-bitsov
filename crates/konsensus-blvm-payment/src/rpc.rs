//! Node RPC surface used by BLVM gate verification and payment providers.

use async_trait::async_trait;
use thiserror::Error;

/// Result of `verify_on_chain_payment` RPC (path 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnChainVerification {
    pub verified: bool,
    pub state: String,
    pub amount_sats: Option<u64>,
    pub tx_hash: Option<String>,
    pub reason: Option<String>,
}

/// BIP70 payment output for `createpaymentrequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequestOutput {
    pub amount_sats: u64,
    /// Output script pubkey (hex).
    pub script_pubkey_hex: String,
}

/// Result of `createpaymentrequest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatedPaymentRequest {
    pub payment_id: String,
    /// Present when `create_covenant` was true and the node has CTV enabled.
    pub covenant_proof: Option<Vec<u8>>,
}

/// Snapshot of `getpaymentstate` for polling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentStateSnapshot {
    pub state: String,
    pub tx_hash: Option<String>,
}

/// Errors from BLVM node RPC adapters.
#[derive(Debug, Error)]
pub enum RpcBlvmError {
    #[error("rpc call failed: {0}")]
    CallFailed(String),

    #[error("covenant verification failed: {0}")]
    CovenantFailed(String),
}

/// Minimal BLVM node RPC used by BitSov adapters (HTTP/IPC implementations live in konsensus-node).
#[async_trait]
pub trait BlvmNodeRpc: Send + Sync {
    async fn verify_on_chain_payment(
        &self,
        payment_request_id: &str,
        tx_hash_hex: &str,
    ) -> Result<OnChainVerification, RpcBlvmError>;

    /// Confirm a `pending` payment request from BIP70 outputs already stored on this node.
    ///
    /// blvm-node method: `verifyonchainpaymentbytx` with params
    /// `[payment_request_id, tx_hash_hex, min_amount_sats]`.
    /// A request that is not stored here returns `request_not_found`. That is terminal.
    /// Default: not supported — [`BlvmGateVerifier`] keeps the local reason.
    async fn verify_on_chain_payment_by_tx(
        &self,
        payment_request_id: &str,
        tx_hash_hex: &str,
        min_amount_sats: u64,
    ) -> Result<OnChainVerification, RpcBlvmError> {
        let _ = (payment_request_id, tx_hash_hex, min_amount_sats);
        Err(RpcBlvmError::CallFailed(
            "verifyonchainpaymentbytx not supported".into(),
        ))
    }

    async fn verify_covenant_proof(
        &self,
        covenant_proof: &[u8],
        output_index: u32,
        amount_sats: u64,
    ) -> Result<bool, RpcBlvmError>;

    /// Create a BIP70 payment request (path 3 session prepay).
    ///
    /// Params mirror blvm-node: `[outputs, merchant_data_hex?, create_covenant?]`.
    async fn create_payment_request(
        &self,
        outputs: &[PaymentRequestOutput],
        merchant_data: Option<&[u8]>,
        create_covenant: bool,
    ) -> Result<CreatedPaymentRequest, RpcBlvmError>;

    /// Query payment state for polling after broadcast.
    async fn get_payment_state(
        &self,
        payment_request_id: &str,
    ) -> Result<PaymentStateSnapshot, RpcBlvmError>;

    /// Create a CTV covenant proof for an existing payment request (path 2 send).
    ///
    /// Params mirror blvm-node: `["payment_request_id"]`.
    async fn create_covenant_proof(
        &self,
        payment_request_id: &str,
    ) -> Result<Vec<u8>, RpcBlvmError>;
}
