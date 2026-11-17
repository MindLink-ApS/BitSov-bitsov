//! `BlvmPaymentVerifier` backed by node RPC.

use async_trait::async_trait;
use konsensus_core::gate_payment::GatePaymentProof;
use konsensus_core::traits::blvm_payment::{BlvmPaymentError, BlvmPaymentVerifier};

use crate::rpc::{BlvmNodeRpc, OnChainVerification, RpcBlvmError};

/// Gate verifier for BLVM covenant and on-chain session proofs.
pub struct BlvmGateVerifier<R: BlvmNodeRpc> {
    rpc: R,
}

impl<R: BlvmNodeRpc> BlvmGateVerifier<R> {
    pub fn new(rpc: R) -> Self {
        Self { rpc }
    }

    async fn verify_on_chain_session(
        &self,
        payment_request_id: &str,
        tx_hash: &[u8; 32],
        amount_sats: u64,
    ) -> Result<(), BlvmPaymentError> {
        let tx_hash_hex = hex::encode(tx_hash);

        let local = self
            .rpc
            .verify_on_chain_payment(payment_request_id, &tx_hash_hex)
            .await
            .map_err(|e| BlvmPaymentError::OnChainRejected(e.to_string()))?;

        // These states are unpaid even when a later response sets `verified`.
        // `not_found` and `request_not_found` are terminal: bytx also requires
        // the BIP70 outputs to already be stored on this node.
        if is_unpaid_terminal_state(&local.state) {
            return Err(BlvmPaymentError::OnChainRejected(owner_facing_unpaid(
                &local.state,
                local.reason.clone(),
            )));
        }

        if local.verified {
            return check_on_chain_amount(&local, amount_sats);
        }

        // `pending` means the request exists but is not in the mempool yet.
        // `verifyonchainpaymentbytx` can confirm it from stored BIP70 outputs.
        let result = if local.state.eq_ignore_ascii_case("pending") {
            match self
                .rpc
                .verify_on_chain_payment_by_tx(payment_request_id, &tx_hash_hex, amount_sats)
                .await
            {
                Ok(chain) => chain,
                Err(RpcBlvmError::CallFailed(msg))
                    if msg.contains("not supported") || msg.contains("Method not found") =>
                {
                    return Err(BlvmPaymentError::OnChainRejected(
                        local
                            .reason
                            .unwrap_or_else(|| format!("state={}", local.state)),
                    ));
                }
                Err(e) => return Err(BlvmPaymentError::OnChainRejected(e.to_string())),
            }
        } else {
            return Err(BlvmPaymentError::OnChainRejected(
                local
                    .reason
                    .unwrap_or_else(|| format!("state={}", local.state)),
            ));
        };

        if is_unpaid_terminal_state(&result.state) || !result.verified {
            return Err(BlvmPaymentError::OnChainRejected(owner_facing_unpaid(
                &result.state,
                result.reason,
            )));
        }

        check_on_chain_amount(&result, amount_sats)
    }
}

/// Stable owner-facing text for a chain state that does not pay for chat.
fn owner_facing_unpaid(state: &str, _detail: Option<String>) -> String {
    match state.to_ascii_lowercase().as_str() {
        "reorg_pending" => "reorg_pending: payment is not settled on this node".into(),
        "tx_mismatch" => "tx_mismatch: transaction does not match the payment request".into(),
        "output_mismatch" => {
            "output_mismatch: transaction outputs do not match the payment request".into()
        }
        "underpaid" => "underpaid: on-chain amount is below the proof".into(),
        "failed" => "failed: on-chain payment failed".into(),
        "not_found" | "request_not_found" => "payment request not found on this node".into(),
        other => _detail.unwrap_or_else(|| format!("state={other}")),
    }
}

fn is_unpaid_terminal_state(state: &str) -> bool {
    matches!(
        state.to_ascii_lowercase().as_str(),
        "reorg_pending"
            | "tx_mismatch"
            | "output_mismatch"
            | "underpaid"
            | "failed"
            | "not_found"
            | "request_not_found"
    )
}

fn check_on_chain_amount(
    result: &OnChainVerification,
    amount_sats: u64,
) -> Result<(), BlvmPaymentError> {
    let Some(rpc_sats) = result.amount_sats else {
        return Err(BlvmPaymentError::OnChainRejected(
            "verified payment is missing amount_sats".into(),
        ));
    };
    if rpc_sats < amount_sats {
        return Err(BlvmPaymentError::OnChainRejected(format!(
            "underpaid: rpc amount_sats {rpc_sats} below proof amount_sats {amount_sats}"
        )));
    }
    Ok(())
}

#[async_trait]
impl<R: BlvmNodeRpc> BlvmPaymentVerifier for BlvmGateVerifier<R> {
    async fn verify_gate_proof(&self, proof: &GatePaymentProof) -> Result<(), BlvmPaymentError> {
        match proof {
            GatePaymentProof::Lightning(_) => Err(BlvmPaymentError::Unavailable(
                "lightning proofs use the Lightning provider".into(),
            )),
            GatePaymentProof::BlvmCovenant {
                covenant_proof,
                output_index,
                amount_sats,
                ..
            } => {
                let ok = self
                    .rpc
                    .verify_covenant_proof(covenant_proof, *output_index, *amount_sats)
                    .await
                    .map_err(|e| BlvmPaymentError::CovenantRejected(e.to_string()))?;
                if ok {
                    Ok(())
                } else {
                    Err(BlvmPaymentError::CovenantRejected(
                        "covenant proof rejected by node".into(),
                    ))
                }
            }
            GatePaymentProof::BlvmOnChainSession {
                payment_request_id,
                tx_hash,
                amount_sats,
                ..
            } => {
                self.verify_on_chain_session(payment_request_id, tx_hash, *amount_sats)
                    .await
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_amount_is_rejected() {
        let result = OnChainVerification {
            verified: true,
            state: "settled".into(),
            amount_sats: None,
            tx_hash: Some("aa".into()),
            reason: None,
        };
        assert!(check_on_chain_amount(&result, 1).is_err());
    }

    #[test]
    fn underpay_is_rejected() {
        let result = OnChainVerification {
            verified: true,
            state: "settled".into(),
            amount_sats: Some(1),
            tx_hash: Some("aa".into()),
            reason: None,
        };
        assert!(check_on_chain_amount(&result, 2).is_err());
        assert!(check_on_chain_amount(&result, 1).is_ok());
    }

    struct CountingRpc {
        local: OnChainVerification,
        bytx: Option<OnChainVerification>,
        bytx_calls: std::sync::Arc<std::sync::Mutex<u32>>,
    }

    #[async_trait]
    impl BlvmNodeRpc for CountingRpc {
        async fn verify_on_chain_payment(
            &self,
            _payment_request_id: &str,
            _tx_hash_hex: &str,
        ) -> Result<OnChainVerification, RpcBlvmError> {
            Ok(self.local.clone())
        }

        async fn verify_on_chain_payment_by_tx(
            &self,
            _payment_request_id: &str,
            _tx_hash_hex: &str,
            _min_amount_sats: u64,
        ) -> Result<OnChainVerification, RpcBlvmError> {
            *self.bytx_calls.lock().unwrap() += 1;
            self.bytx.clone().ok_or_else(|| {
                RpcBlvmError::CallFailed("verifyonchainpaymentbytx not supported".into())
            })
        }

        async fn verify_covenant_proof(
            &self,
            _covenant_proof: &[u8],
            _output_index: u32,
            _amount_sats: u64,
        ) -> Result<bool, RpcBlvmError> {
            Ok(false)
        }

        async fn create_payment_request(
            &self,
            _outputs: &[crate::rpc::PaymentRequestOutput],
            _merchant_data: Option<&[u8]>,
            _create_covenant: bool,
        ) -> Result<crate::rpc::CreatedPaymentRequest, RpcBlvmError> {
            Err(RpcBlvmError::CallFailed("unused".into()))
        }

        async fn get_payment_state(
            &self,
            _payment_request_id: &str,
        ) -> Result<crate::rpc::PaymentStateSnapshot, RpcBlvmError> {
            Err(RpcBlvmError::CallFailed("Method not found".into()))
        }

        async fn create_covenant_proof(
            &self,
            _payment_request_id: &str,
        ) -> Result<Vec<u8>, RpcBlvmError> {
            Err(RpcBlvmError::CallFailed("unused".into()))
        }
    }

    fn session_proof() -> GatePaymentProof {
        GatePaymentProof::BlvmOnChainSession {
            payment_request_id: "req".into(),
            tx_hash: [9u8; 32],
            amount_sats: 2,
            timestamp: 1,
            session_debit_seq: Some(1),
        }
    }

    #[tokio::test]
    async fn not_found_does_not_call_bytx() {
        let bytx_calls = std::sync::Arc::new(std::sync::Mutex::new(0));
        let rpc = CountingRpc {
            local: OnChainVerification {
                verified: false,
                state: "not_found".into(),
                amount_sats: None,
                tx_hash: None,
                reason: Some("payment request not found".into()),
            },
            bytx: None,
            bytx_calls: std::sync::Arc::clone(&bytx_calls),
        };
        let err = BlvmGateVerifier::new(rpc)
            .verify_gate_proof(&session_proof())
            .await
            .unwrap_err();
        assert!(err.to_string().contains("payment request not found"));
        assert_eq!(*bytx_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn pending_calls_bytx() {
        let rpc = CountingRpc {
            local: OnChainVerification {
                verified: false,
                state: "pending".into(),
                amount_sats: None,
                tx_hash: None,
                reason: None,
            },
            bytx: Some(OnChainVerification {
                verified: true,
                state: "confirmed".into(),
                amount_sats: Some(2),
                tx_hash: Some("aa".into()),
                reason: None,
            }),
            bytx_calls: std::sync::Arc::new(std::sync::Mutex::new(0)),
        };
        let calls = std::sync::Arc::clone(&rpc.bytx_calls);
        BlvmGateVerifier::new(rpc)
            .verify_gate_proof(&session_proof())
            .await
            .expect("pending confirms through bytx");
        assert_eq!(*calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn reorg_pending_is_unpaid_even_when_verified() {
        let rpc = CountingRpc {
            local: OnChainVerification {
                verified: true,
                state: "reorg_pending".into(),
                amount_sats: Some(2),
                tx_hash: Some("aa".into()),
                reason: Some("reorg_pending".into()),
            },
            bytx: Some(OnChainVerification {
                verified: true,
                state: "confirmed".into(),
                amount_sats: Some(2),
                tx_hash: Some("aa".into()),
                reason: None,
            }),
            bytx_calls: std::sync::Arc::new(std::sync::Mutex::new(0)),
        };
        let calls = std::sync::Arc::clone(&rpc.bytx_calls);
        let verifier = BlvmGateVerifier::new(rpc);
        let err = verifier.verify_gate_proof(&session_proof()).await.unwrap_err();
        assert!(err.to_string().contains("reorg_pending"));
        assert_eq!(*calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn unpaid_states_name_themselves() {
        for (state, needle) in [
            ("reorg_pending", "reorg_pending:"),
            ("tx_mismatch", "tx_mismatch:"),
            ("output_mismatch", "output_mismatch:"),
            ("underpaid", "underpaid:"),
            ("not_found", "payment request not found"),
        ] {
            let rpc = CountingRpc {
                local: OnChainVerification {
                    verified: true,
                    state: state.into(),
                    amount_sats: Some(2),
                    tx_hash: Some("aa".into()),
                    reason: None,
                },
                bytx: None,
                bytx_calls: std::sync::Arc::new(std::sync::Mutex::new(0)),
            };
            let err = BlvmGateVerifier::new(rpc)
                .verify_gate_proof(&session_proof())
                .await
                .unwrap_err();
            assert!(err.to_string().contains(needle), "{state} produced {err}");
        }
    }
}

/// Startup check that `blvm-payment` is registered on the node RPC.
///
/// "Method not found" means the module is not loaded. Any other answer, including
/// an unknown payment id, means the method exists.
pub async fn probe_payment_module(rpc: &impl BlvmNodeRpc) -> Result<(), BlvmPaymentError> {
    match rpc.get_payment_state("bitsov-startup-probe").await {
        Ok(_) => Ok(()),
        Err(RpcBlvmError::CallFailed(msg)) if msg.contains("Method not found") => {
            Err(BlvmPaymentError::Unavailable(
                "blvm-payment module is not loaded: Method not found".into(),
            ))
        }
        Err(RpcBlvmError::CallFailed(_)) => Ok(()),
        Err(e) => Err(BlvmPaymentError::Unavailable(e.to_string())),
    }
}
