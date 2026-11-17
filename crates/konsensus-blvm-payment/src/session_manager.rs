//! Outbound path-3 session lifecycle: open, confirm, per-message debit.

use std::sync::Arc;
use std::time::Duration;

use konsensus_core::gate_payment::GatePaymentProof;
use konsensus_core::types::NodeId;
use thiserror::Error;
use tracing::debug;

use crate::providers::on_chain::{open_session_from_rpc, OnChainSession};
use crate::rpc::{BlvmNodeRpc, PaymentRequestOutput, RpcBlvmError};
use crate::session_store::{OnChainSessionRecord, OnChainSessionStore, SessionStoreError};

/// Default poll interval while waiting for mempool attestation.
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Default timeout for session open confirmation.
const DEFAULT_OPEN_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Error)]
pub enum SessionManagerError {
    #[error("blvm rpc error: {0}")]
    Rpc(#[from] RpcBlvmError),

    #[error("session store error: {0}")]
    Store(#[from] SessionStoreError),

    #[error("no open on-chain session for recipient {0}")]
    NoSession(String),

    #[error("session balance exhausted: need {required_msat} msat, {remaining_msat} remaining")]
    BalanceExhausted {
        required_msat: u64,
        remaining_msat: u64,
    },

    #[error("invalid tx hash: {0}")]
    InvalidTxHash(String),

    #[error("session open timed out after {0}s")]
    OpenTimeout(u64),

    #[error("payment not verified: {0}")]
    NotVerified(String),
}

/// Manages outbound BLVM on-chain sessions (path 3) per recipient.
pub struct BlvmOnChainSessionManager {
    rpc: Arc<dyn BlvmNodeRpc>,
    store: Arc<dyn OnChainSessionStore>,
    poll_interval: Duration,
    open_timeout: Duration,
}

impl BlvmOnChainSessionManager {
    pub fn new(rpc: Arc<dyn BlvmNodeRpc>, store: Arc<dyn OnChainSessionStore>) -> Self {
        Self {
            rpc,
            store,
            poll_interval: DEFAULT_POLL_INTERVAL,
            open_timeout: DEFAULT_OPEN_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub fn with_timeouts(
        rpc: Arc<dyn BlvmNodeRpc>,
        store: Arc<dyn OnChainSessionStore>,
        poll_interval: Duration,
        open_timeout: Duration,
    ) -> Self {
        Self {
            rpc,
            store,
            poll_interval,
            open_timeout,
        }
    }

    /// Create a BIP70 payment request on the local blvm-node (step 1 of open).
    pub async fn create_payment_request(
        &self,
        amount_sats: u64,
        script_pubkey_hex: &str,
    ) -> Result<String, SessionManagerError> {
        let created = self
            .rpc
            .create_payment_request(
                &[PaymentRequestOutput {
                    amount_sats,
                    script_pubkey_hex: script_pubkey_hex.to_string(),
                }],
                None,
                false,
            )
            .await?;
        Ok(created.payment_id)
    }

    /// Confirm session after payer broadcast tx (poll verify RPC, persist session).
    pub async fn confirm_open(
        &self,
        recipient: &NodeId,
        payment_request_id: String,
        tx_hash_hex: &str,
    ) -> Result<OnChainSessionRecord, SessionManagerError> {
        let tx_hash = decode_tx_hash(tx_hash_hex)?;
        let deadline = std::time::Instant::now() + self.open_timeout;

        loop {
            let verification = self
                .rpc
                .verify_on_chain_payment(&payment_request_id, tx_hash_hex)
                .await?;

            if verification.verified {
                let session =
                    open_session_from_rpc(self.rpc.as_ref(), payment_request_id.clone(), tx_hash)
                        .await?;
                let record = record_from_session(recipient, session);
                self.store.upsert(&record).await?;
                debug!(
                    recipient = %recipient,
                    payment_request_id = %record.payment_request_id,
                    amount_sats = record.amount_sats,
                    "on-chain session opened"
                );
                return Ok(record);
            }

            if std::time::Instant::now() >= deadline {
                return Err(SessionManagerError::NotVerified(
                    verification
                        .reason
                        .unwrap_or_else(|| format!("state={}", verification.state)),
                ));
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }

    /// Open session immediately when tx is already verified (no polling).
    pub async fn open_verified(
        &self,
        recipient: &NodeId,
        payment_request_id: String,
        tx_hash_hex: &str,
    ) -> Result<OnChainSessionRecord, SessionManagerError> {
        let tx_hash = decode_tx_hash(tx_hash_hex)?;
        let session = open_session_from_rpc(self.rpc.as_ref(), payment_request_id, tx_hash).await?;
        let record = record_from_session(recipient, session);
        self.store.upsert(&record).await?;
        Ok(record)
    }

    /// Produce the next gate proof for an outbound message (immediate spent update; tests).
    pub async fn debit_for_message(
        &self,
        recipient: &NodeId,
        price_msat: u64,
    ) -> Result<GatePaymentProof, SessionManagerError> {
        let debit = self
            .store
            .try_debit_for_recipient(recipient, price_msat)
            .await?;
        Ok(debit_to_proof(debit))
    }

    /// Reserve session debit for an outbound message; commit after peer ACK.
    pub async fn reserve_debit_for_message(
        &self,
        recipient: &NodeId,
        message_id: &konsensus_core::types::MessageId,
        price_msat: u64,
    ) -> Result<GatePaymentProof, SessionManagerError> {
        let debit = self
            .store
            .try_reserve_debit_for_recipient(recipient, message_id, price_msat)
            .await?;
        Ok(debit_to_proof(debit))
    }

    pub async fn commit_debit_for_message(
        &self,
        message_id: &konsensus_core::types::MessageId,
    ) -> Result<(), SessionManagerError> {
        self.store.commit_debit(message_id).await?;
        Ok(())
    }

    pub async fn rollback_debit_for_message(
        &self,
        message_id: &konsensus_core::types::MessageId,
    ) -> Result<bool, SessionManagerError> {
        Ok(self.store.rollback_debit(message_id).await?)
    }

    pub async fn get_session(
        &self,
        recipient: &NodeId,
    ) -> Result<Option<OnChainSessionRecord>, SessionManagerError> {
        Ok(self.store.get_for_recipient(recipient).await?)
    }
}

fn debit_to_proof(debit: crate::session_store::OnChainSessionDebit) -> GatePaymentProof {
    let session = OnChainSession {
        payment_request_id: debit.payment_request_id,
        tx_hash: debit.tx_hash,
        amount_sats: debit.amount_sats,
        debit_counter: debit.session_debit_seq,
    };
    session.gate_proof_for_debit()
}

fn record_from_session(recipient: &NodeId, session: OnChainSession) -> OnChainSessionRecord {
    OnChainSessionRecord {
        recipient: *recipient,
        payment_request_id: session.payment_request_id,
        tx_hash: session.tx_hash,
        amount_sats: session.amount_sats,
        debit_counter: session.debit_counter,
        spent_msat: 0,
    }
}

fn decode_tx_hash(hex_str: &str) -> Result<[u8; 32], SessionManagerError> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|e| SessionManagerError::InvalidTxHash(e.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| SessionManagerError::InvalidTxHash("expected 32 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::{
        BlvmNodeRpc, CreatedPaymentRequest, OnChainVerification, PaymentStateSnapshot,
    };
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

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
                payment_id: "req-test".into(),
                covenant_proof: None,
            })
        }

        async fn get_payment_state(
            &self,
            _payment_request_id: &str,
        ) -> Result<PaymentStateSnapshot, RpcBlvmError> {
            Ok(PaymentStateSnapshot {
                state: "in_mempool".into(),
                tx_hash: Some(hex::encode([0x11; 32])),
            })
        }

        async fn create_covenant_proof(
            &self,
            _payment_request_id: &str,
        ) -> Result<Vec<u8>, RpcBlvmError> {
            Ok(vec![0xAB])
        }
    }

    struct MemStore {
        sessions: Mutex<HashMap<String, OnChainSessionRecord>>,
    }

    impl MemStore {
        fn new() -> Self {
            Self {
                sessions: Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl OnChainSessionStore for MemStore {
        async fn get_for_recipient(
            &self,
            recipient: &NodeId,
        ) -> Result<Option<OnChainSessionRecord>, SessionStoreError> {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .get(&recipient.to_hex())
                .cloned())
        }

        async fn upsert(&self, record: &OnChainSessionRecord) -> Result<(), SessionStoreError> {
            self.sessions
                .lock()
                .unwrap()
                .insert(record.recipient.to_hex(), record.clone());
            Ok(())
        }

        async fn delete_for_recipient(
            &self,
            recipient: &NodeId,
        ) -> Result<bool, SessionStoreError> {
            Ok(self
                .sessions
                .lock()
                .unwrap()
                .remove(&recipient.to_hex())
                .is_some())
        }

        async fn try_debit_for_recipient(
            &self,
            recipient: &NodeId,
            debit_msat: u64,
        ) -> Result<crate::session_store::OnChainSessionDebit, SessionStoreError> {
            let mut sessions = self.sessions.lock().unwrap();
            let record = sessions
                .get_mut(&recipient.to_hex())
                .ok_or_else(|| SessionStoreError::NoSession(recipient.to_hex()))?;
            let seq = crate::session_store::mem_try_debit_record(record, debit_msat)?;
            Ok(crate::session_store::OnChainSessionDebit {
                payment_request_id: record.payment_request_id.clone(),
                tx_hash: record.tx_hash,
                amount_sats: record.amount_sats,
                session_debit_seq: seq,
            })
        }

        async fn try_reserve_debit_for_recipient(
            &self,
            recipient: &NodeId,
            _message_id: &konsensus_core::types::MessageId,
            debit_msat: u64,
        ) -> Result<crate::session_store::OnChainSessionDebit, SessionStoreError> {
            self.try_debit_for_recipient(recipient, debit_msat).await
        }

        async fn commit_debit(
            &self,
            _message_id: &konsensus_core::types::MessageId,
        ) -> Result<(), SessionStoreError> {
            Ok(())
        }

        async fn rollback_debit(
            &self,
            _message_id: &konsensus_core::types::MessageId,
        ) -> Result<bool, SessionStoreError> {
            Ok(false)
        }
    }

    #[tokio::test]
    async fn debit_for_message_advances_seq_and_tracks_spent() {
        let rpc: Arc<dyn BlvmNodeRpc> = Arc::new(MockRpc {
            verification: OnChainVerification {
                verified: true,
                state: "in_mempool".into(),
                amount_sats: Some(10),
                tx_hash: Some(hex::encode([0x22; 32])),
                reason: None,
            },
        });
        let store: Arc<dyn OnChainSessionStore> = Arc::new(MemStore::new());
        let mgr = BlvmOnChainSessionManager::new(rpc, store);
        let bob = NodeId::from_bytes([2u8; 32]);

        mgr.open_verified(&bob, "req-1".into(), &hex::encode([0x22; 32]))
            .await
            .expect("open");

        let proof1 = mgr.debit_for_message(&bob, 1000).await.expect("debit 1");
        assert!(matches!(
            proof1,
            GatePaymentProof::BlvmOnChainSession {
                session_debit_seq: Some(0),
                ..
            }
        ));

        let proof2 = mgr.debit_for_message(&bob, 1000).await.expect("debit 2");
        assert!(matches!(
            proof2,
            GatePaymentProof::BlvmOnChainSession {
                session_debit_seq: Some(1),
                ..
            }
        ));

        let err = mgr
            .debit_for_message(&bob, 9000)
            .await
            .expect_err("exhausted");
        assert!(matches!(
            err,
            SessionManagerError::Store(SessionStoreError::BalanceExhausted { .. })
        ));
    }
}
