//! Path 3: BIP70 session prepay → on-chain gate proof.

use crate::rpc::{BlvmNodeRpc, RpcBlvmError};
use konsensus_core::gate_payment::GatePaymentProof;
use std::time::{SystemTime, UNIX_EPOCH};

/// Open on-chain session state (one BIP70 request + tx covers N messages).
#[derive(Debug, Clone)]
pub struct OnChainSession {
    pub payment_request_id: String,
    pub tx_hash: [u8; 32],
    pub amount_sats: u64,
    pub debit_counter: u64,
}

impl OnChainSession {
    pub fn gate_proof_for_debit(&self) -> GatePaymentProof {
        GatePaymentProof::BlvmOnChainSession {
            payment_request_id: self.payment_request_id.clone(),
            tx_hash: self.tx_hash,
            amount_sats: self.amount_sats,
            timestamp: unix_now(),
            session_debit_seq: Some(self.debit_counter),
        }
    }

    pub fn next_debit(&mut self) -> GatePaymentProof {
        self.debit_counter = self.debit_counter.saturating_add(1);
        self.gate_proof_for_debit()
    }
}

/// Poll node RPC until on-chain payment is verified, then open a session.
pub async fn open_session_from_rpc<R: BlvmNodeRpc + ?Sized>(
    rpc: &R,
    payment_request_id: String,
    tx_hash: [u8; 32],
) -> Result<OnChainSession, RpcBlvmError> {
    let verification = rpc
        .verify_on_chain_payment(&payment_request_id, &hex::encode(tx_hash))
        .await?;

    if !verification.verified {
        return Err(RpcBlvmError::CallFailed(
            verification
                .reason
                .unwrap_or_else(|| format!("payment not verified: {}", verification.state)),
        ));
    }

    let amount_sats = verification.amount_sats.unwrap_or(0);
    if amount_sats == 0 {
        return Err(RpcBlvmError::CallFailed(
            "verified payment missing amount_sats".into(),
        ));
    }

    Ok(OnChainSession {
        payment_request_id,
        tx_hash,
        amount_sats,
        debit_counter: 0,
    })
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{
        BlvmNodeRpc, CreatedPaymentRequest, OnChainVerification, PaymentRequestOutput,
        PaymentStateSnapshot, RpcBlvmError,
    };
    use async_trait::async_trait;

    struct MockRpc {
        verification: OnChainVerification,
    }

    #[async_trait]
    impl BlvmNodeRpc for MockRpc {
        async fn verify_on_chain_payment(
            &self,
            _payment_request_id: &str,
            _tx_hash_hex: &str,
        ) -> Result<OnChainVerification, RpcBlvmError> {
            Ok(self.verification.clone())
        }

        async fn verify_covenant_proof(
            &self,
            _covenant_proof: &[u8],
            _output_index: u32,
            _amount_sats: u64,
        ) -> Result<bool, RpcBlvmError> {
            Ok(true)
        }

        async fn create_payment_request(
            &self,
            _outputs: &[PaymentRequestOutput],
            _merchant_data: Option<&[u8]>,
            _create_covenant: bool,
        ) -> Result<CreatedPaymentRequest, RpcBlvmError> {
            Ok(CreatedPaymentRequest {
                payment_id: "mock-req".into(),
                covenant_proof: None,
            })
        }

        async fn get_payment_state(
            &self,
            _payment_request_id: &str,
        ) -> Result<PaymentStateSnapshot, RpcBlvmError> {
            Ok(PaymentStateSnapshot {
                state: "in_mempool".into(),
                tx_hash: None,
            })
        }

        async fn create_covenant_proof(
            &self,
            _payment_request_id: &str,
        ) -> Result<Vec<u8>, RpcBlvmError> {
            Ok(vec![0xAB])
        }
    }

    #[tokio::test]
    async fn open_session_from_verified_rpc() {
        let rpc = MockRpc {
            verification: OnChainVerification {
                verified: true,
                state: "in_mempool".into(),
                amount_sats: Some(150_000),
                tx_hash: Some(hex::encode([0x42; 32])),
                reason: None,
            },
        };

        let session = open_session_from_rpc(&rpc, "req-1".into(), [0x42; 32])
            .await
            .expect("session opens");

        assert_eq!(session.amount_sats, 150_000);
        let proof = session.gate_proof_for_debit();
        assert!(matches!(
            proof,
            GatePaymentProof::BlvmOnChainSession {
                session_debit_seq: Some(0),
                ..
            }
        ));
    }
}
