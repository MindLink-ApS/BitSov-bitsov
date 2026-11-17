//! Path 2: BLVM + CTV covenant payment provider.

use std::sync::Arc;

use crate::rpc::{BlvmNodeRpc, PaymentRequestOutput, RpcBlvmError};
use konsensus_core::gate_payment::GatePaymentProof;

/// Covenant payment request result (path 2).
#[derive(Debug, Clone)]
pub struct CovenantPaymentResult {
    pub payment_request_id: String,
    pub covenant_proof: Vec<u8>,
    pub output_index: u32,
    pub amount_sats: u64,
}

/// Creates CTV covenant proofs via blvm-node RPC.
pub struct BlvmCovenantPaymentProvider {
    rpc: Arc<dyn BlvmNodeRpc>,
}

impl BlvmCovenantPaymentProvider {
    pub fn new(rpc: Arc<dyn BlvmNodeRpc>) -> Self {
        Self { rpc }
    }

    /// Create a payment request + covenant proof and return a verified UKM gate proof.
    pub async fn create_and_finalize(
        &self,
        amount_sats: u64,
        script_pubkey_hex: &str,
        output_index: u32,
    ) -> Result<GatePaymentProof, RpcBlvmError> {
        let created = self
            .rpc
            .create_payment_request(
                &[PaymentRequestOutput {
                    amount_sats,
                    script_pubkey_hex: script_pubkey_hex.to_string(),
                }],
                None,
                true,
            )
            .await?;

        let proof_bytes = match created.covenant_proof {
            Some(bytes) => bytes,
            None => self.rpc.create_covenant_proof(&created.payment_id).await?,
        };

        self.finalize_gate_proof(proof_bytes, output_index, amount_sats)
            .await
    }

    /// Verify covenant bytes and build a UKM gate proof.
    pub async fn finalize_gate_proof(
        &self,
        covenant_proof: Vec<u8>,
        output_index: u32,
        amount_sats: u64,
    ) -> Result<GatePaymentProof, RpcBlvmError> {
        let ok = self
            .rpc
            .verify_covenant_proof(&covenant_proof, output_index, amount_sats)
            .await?;
        if !ok {
            return Err(RpcBlvmError::CovenantFailed(
                "covenant proof rejected by node".into(),
            ));
        }

        Ok(GatePaymentProof::BlvmCovenant {
            covenant_proof,
            output_index,
            amount_sats,
            timestamp: unix_now(),
        })
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{
        BlvmNodeRpc, CreatedPaymentRequest, OnChainVerification, PaymentStateSnapshot, RpcBlvmError,
    };
    use async_trait::async_trait;

    struct MockRpc {
        covenant_ok: bool,
        covenant_bytes: Vec<u8>,
    }

    #[async_trait]
    impl BlvmNodeRpc for MockRpc {
        async fn verify_on_chain_payment(
            &self,
            _: &str,
            _: &str,
        ) -> Result<OnChainVerification, RpcBlvmError> {
            Err(RpcBlvmError::CallFailed("unused".into()))
        }

        async fn verify_covenant_proof(
            &self,
            _: &[u8],
            _: u32,
            _: u64,
        ) -> Result<bool, RpcBlvmError> {
            Ok(self.covenant_ok)
        }

        async fn create_payment_request(
            &self,
            _: &[PaymentRequestOutput],
            _: Option<&[u8]>,
            create_covenant: bool,
        ) -> Result<CreatedPaymentRequest, RpcBlvmError> {
            Ok(CreatedPaymentRequest {
                payment_id: "mock-req".into(),
                covenant_proof: create_covenant.then(|| self.covenant_bytes.clone()),
            })
        }

        async fn get_payment_state(&self, _: &str) -> Result<PaymentStateSnapshot, RpcBlvmError> {
            Ok(PaymentStateSnapshot {
                state: "request_created".into(),
                tx_hash: None,
            })
        }

        async fn create_covenant_proof(&self, _: &str) -> Result<Vec<u8>, RpcBlvmError> {
            Ok(self.covenant_bytes.clone())
        }
    }

    #[tokio::test]
    async fn finalize_gate_proof_success() {
        let rpc: Arc<dyn BlvmNodeRpc> = Arc::new(MockRpc {
            covenant_ok: true,
            covenant_bytes: vec![0xAB],
        });
        let provider = BlvmCovenantPaymentProvider::new(rpc);
        let proof = provider
            .finalize_gate_proof(vec![0xAB], 0, 5000)
            .await
            .expect("proof");
        assert!(matches!(
            proof,
            GatePaymentProof::BlvmCovenant {
                amount_sats: 5000,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn finalize_gate_proof_rejects_bad_covenant() {
        let rpc: Arc<dyn BlvmNodeRpc> = Arc::new(MockRpc {
            covenant_ok: false,
            covenant_bytes: vec![0xAB],
        });
        let provider = BlvmCovenantPaymentProvider::new(rpc);
        let err = provider
            .finalize_gate_proof(vec![0xAB], 0, 5000)
            .await
            .expect_err("must fail");
        assert!(matches!(err, RpcBlvmError::CovenantFailed(_)));
    }

    #[tokio::test]
    async fn create_and_finalize_uses_inline_covenant() {
        let rpc: Arc<dyn BlvmNodeRpc> = Arc::new(MockRpc {
            covenant_ok: true,
            covenant_bytes: vec![0xCD],
        });
        let provider = BlvmCovenantPaymentProvider::new(rpc);
        let proof = provider
            .create_and_finalize(1000, "0014deadbeef", 0)
            .await
            .expect("proof");
        assert!(matches!(
            proof,
            GatePaymentProof::BlvmCovenant {
                amount_sats: 1000,
                output_index: 0,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn create_and_finalize_falls_back_to_create_covenant_proof() {
        struct FallbackRpc {
            covenant_ok: bool,
        }

        #[async_trait]
        impl BlvmNodeRpc for FallbackRpc {
            async fn verify_on_chain_payment(
                &self,
                _: &str,
                _: &str,
            ) -> Result<OnChainVerification, RpcBlvmError> {
                Err(RpcBlvmError::CallFailed("unused".into()))
            }

            async fn verify_covenant_proof(
                &self,
                _: &[u8],
                _: u32,
                _: u64,
            ) -> Result<bool, RpcBlvmError> {
                Ok(self.covenant_ok)
            }

            async fn create_payment_request(
                &self,
                _: &[PaymentRequestOutput],
                _: Option<&[u8]>,
                _: bool,
            ) -> Result<CreatedPaymentRequest, RpcBlvmError> {
                Ok(CreatedPaymentRequest {
                    payment_id: "req-fallback".into(),
                    covenant_proof: None,
                })
            }

            async fn get_payment_state(
                &self,
                _: &str,
            ) -> Result<PaymentStateSnapshot, RpcBlvmError> {
                Ok(PaymentStateSnapshot {
                    state: "request_created".into(),
                    tx_hash: None,
                })
            }

            async fn create_covenant_proof(&self, _: &str) -> Result<Vec<u8>, RpcBlvmError> {
                Ok(vec![0xEF])
            }
        }

        let rpc: Arc<dyn BlvmNodeRpc> = Arc::new(FallbackRpc { covenant_ok: true });
        let provider = BlvmCovenantPaymentProvider::new(rpc);
        let proof = provider
            .create_and_finalize(500, "0014aa", 0)
            .await
            .expect("proof");
        assert!(matches!(
            proof,
            GatePaymentProof::BlvmCovenant {
                amount_sats: 500,
                ..
            }
        ));
    }
}
