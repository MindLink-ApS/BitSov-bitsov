//! Owner control for an outbound path-3 chat session.
//!
//! The payment gate holds this so the API can open a session without a
//! dependency on the BLVM RPC crate. Absent means `[blvm]` is off.

use async_trait::async_trait;

use crate::types::NodeId;

/// Stored prepaid session for one recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlvmOutboundSessionView {
    pub recipient: NodeId,
    pub payment_request_id: String,
    pub tx_hash: [u8; 32],
    pub amount_sats: u64,
    pub debit_counter: u64,
    pub spent_msat: u64,
}

#[async_trait]
pub trait BlvmSessionControl: Send + Sync {
    /// Create a BIP70 payment request on this node's blvm-payment module.
    async fn create_chat_payment_request(
        &self,
        amount_sats: u64,
        script_pubkey_hex: &str,
    ) -> Result<String, String>;

    /// Verify the payment on this node and store the outbound session.
    ///
    /// One attempt. The caller retries after broadcast. This does not poll.
    async fn confirm_chat_session(
        &self,
        recipient: &NodeId,
        payment_request_id: &str,
        tx_hash_hex: &str,
    ) -> Result<BlvmOutboundSessionView, String>;

    async fn chat_session(
        &self,
        recipient: &NodeId,
    ) -> Result<Option<BlvmOutboundSessionView>, String>;
}
