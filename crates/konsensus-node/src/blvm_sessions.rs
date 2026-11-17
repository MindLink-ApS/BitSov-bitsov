//! Storage-backed outbound path-3 sessions, and the owner control the API calls.

use std::sync::Arc;

use async_trait::async_trait;
use konsensus_blvm_payment::{
    BlvmOnChainSessionManager, OnChainSessionDebit, OnChainSessionRecord, OnChainSessionStore,
    SessionStoreError,
};
use konsensus_core::{BlvmOutboundSessionView, BlvmSessionControl, MessageId, NodeId, Nonce};
use konsensus_storage::{BlvmOutboundSession, Storage, StorageError};

/// Persists path-3 sessions in the node database compose already reads.
pub struct StorageOnChainSessions {
    storage: Arc<dyn Storage>,
}

impl StorageOnChainSessions {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }
}

fn map_store(err: StorageError) -> SessionStoreError {
    let text = err.to_string();
    if text.contains("blvm session balance exhausted") {
        let required_msat = text
            .split("need ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        let remaining_msat = text
            .split(", ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        return SessionStoreError::BalanceExhausted {
            required_msat,
            remaining_msat,
        };
    }
    SessionStoreError::Storage(text)
}

fn record_from_session(session: BlvmOutboundSession) -> OnChainSessionRecord {
    OnChainSessionRecord {
        recipient: session.recipient,
        payment_request_id: session.payment_request_id,
        tx_hash: session.tx_hash,
        amount_sats: session.amount_sats,
        debit_counter: session.debit_counter,
        spent_msat: session.spent_msat,
    }
}

fn session_from_record(record: &OnChainSessionRecord) -> BlvmOutboundSession {
    BlvmOutboundSession {
        recipient: record.recipient,
        payment_request_id: record.payment_request_id.clone(),
        tx_hash: record.tx_hash,
        amount_sats: record.amount_sats,
        debit_counter: record.debit_counter,
        spent_msat: record.spent_msat,
    }
}

fn debit_from_reservation(
    reservation: konsensus_storage::BlvmOutboundReservation,
) -> OnChainSessionDebit {
    OnChainSessionDebit {
        payment_request_id: reservation.payment_request_id,
        tx_hash: reservation.tx_hash,
        amount_sats: reservation.amount_sats,
        session_debit_seq: reservation.session_debit_seq,
    }
}

#[async_trait]
impl OnChainSessionStore for StorageOnChainSessions {
    async fn get_for_recipient(
        &self,
        recipient: &NodeId,
    ) -> Result<Option<OnChainSessionRecord>, SessionStoreError> {
        Ok(self
            .storage
            .get_blvm_outbound_session(recipient)
            .await
            .map_err(map_store)?
            .map(record_from_session))
    }

    async fn upsert(&self, record: &OnChainSessionRecord) -> Result<(), SessionStoreError> {
        self.storage
            .upsert_blvm_outbound_session(&session_from_record(record))
            .await
            .map_err(map_store)
    }

    async fn try_debit_for_recipient(
        &self,
        recipient: &NodeId,
        debit_msat: u64,
    ) -> Result<OnChainSessionDebit, SessionStoreError> {
        let current = self
            .get_for_recipient(recipient)
            .await?
            .ok_or_else(|| SessionStoreError::NoSession(recipient.to_hex()))?;
        let message_id = MessageId::compute(
            format!(
                "bitsov-blvm-immediate-debit:{}:{}",
                recipient.to_hex(),
                current.debit_counter
            )
            .as_bytes(),
            &Nonce::from_bytes([0; 24]),
        );
        let debit = self
            .try_reserve_debit_for_recipient(recipient, &message_id, debit_msat)
            .await?;
        self.commit_debit(&message_id).await?;
        Ok(debit)
    }

    async fn try_reserve_debit_for_recipient(
        &self,
        recipient: &NodeId,
        message_id: &MessageId,
        debit_msat: u64,
    ) -> Result<OnChainSessionDebit, SessionStoreError> {
        match self
            .storage
            .reserve_blvm_outbound_debit(recipient, message_id, debit_msat)
            .await
            .map_err(map_store)?
        {
            Some(reservation) => Ok(debit_from_reservation(reservation)),
            None => Err(SessionStoreError::NoSession(recipient.to_hex())),
        }
    }

    async fn commit_debit(&self, message_id: &MessageId) -> Result<(), SessionStoreError> {
        self.storage
            .commit_blvm_outbound_debit(message_id)
            .await
            .map_err(map_store)?;
        Ok(())
    }

    async fn rollback_debit(&self, message_id: &MessageId) -> Result<bool, SessionStoreError> {
        self.storage
            .rollback_blvm_outbound_debit(message_id)
            .await
            .map_err(map_store)
    }

    async fn delete_for_recipient(&self, recipient: &NodeId) -> Result<bool, SessionStoreError> {
        self.storage
            .delete_blvm_outbound_session(recipient)
            .await
            .map_err(map_store)
    }
}

/// Owner API in front of [`BlvmOnChainSessionManager`].
pub struct NodeBlvmSessions {
    manager: BlvmOnChainSessionManager,
}

impl NodeBlvmSessions {
    pub fn new(manager: BlvmOnChainSessionManager) -> Self {
        Self { manager }
    }
}

fn view_from_record(record: OnChainSessionRecord) -> BlvmOutboundSessionView {
    BlvmOutboundSessionView {
        recipient: record.recipient,
        payment_request_id: record.payment_request_id,
        tx_hash: record.tx_hash,
        amount_sats: record.amount_sats,
        debit_counter: record.debit_counter,
        spent_msat: record.spent_msat,
    }
}

#[async_trait]
impl BlvmSessionControl for NodeBlvmSessions {
    async fn create_chat_payment_request(
        &self,
        amount_sats: u64,
        script_pubkey_hex: &str,
    ) -> Result<String, String> {
        if amount_sats == 0 || amount_sats > (i64::MAX as u64) / 1000 {
            return Err("amount_sats is outside the chat session range".into());
        }
        let script = hex::decode(script_pubkey_hex.trim()).map_err(|_| "script_pubkey_hex is not hex".to_string())?;
        if script.is_empty() || script.len() > 10_000 {
            return Err("script_pubkey_hex is outside the script length range".into());
        }
        self.manager
            .create_payment_request(amount_sats, script_pubkey_hex.trim())
            .await
            .map_err(|e| e.to_string())
    }

    async fn confirm_chat_session(
        &self,
        recipient: &NodeId,
        payment_request_id: &str,
        tx_hash_hex: &str,
    ) -> Result<BlvmOutboundSessionView, String> {
        if payment_request_id.is_empty() || payment_request_id.len() > 128 {
            return Err("payment_request_id length is invalid".into());
        }
        let record = self
            .manager
            .open_verified(recipient, payment_request_id.to_string(), tx_hash_hex)
            .await
            .map_err(|e| e.to_string())?;
        Ok(view_from_record(record))
    }

    async fn chat_session(
        &self,
        recipient: &NodeId,
    ) -> Result<Option<BlvmOutboundSessionView>, String> {
        Ok(self
            .manager
            .get_session(recipient)
            .await
            .map_err(|e| e.to_string())?
            .map(view_from_record))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_blvm_payment::{BlvmNodeRpc, OnChainVerification, RpcBlvmError};
    use konsensus_storage::SqliteStorage;

    struct VerifiedRpc;

    #[async_trait]
    impl BlvmNodeRpc for VerifiedRpc {
        async fn verify_on_chain_payment(
            &self,
            _payment_request_id: &str,
            _tx_hash_hex: &str,
        ) -> Result<OnChainVerification, RpcBlvmError> {
            Ok(OnChainVerification {
                verified: true,
                state: "confirmed".into(),
                amount_sats: Some(2),
                tx_hash: Some(hex::encode([0x22; 32])),
                reason: None,
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
            _outputs: &[konsensus_blvm_payment::PaymentRequestOutput],
            _merchant_data: Option<&[u8]>,
            _create_covenant: bool,
        ) -> Result<konsensus_blvm_payment::CreatedPaymentRequest, RpcBlvmError> {
            Ok(konsensus_blvm_payment::CreatedPaymentRequest {
                payment_id: "req-open".into(),
                covenant_proof: None,
            })
        }

        async fn get_payment_state(
            &self,
            _payment_request_id: &str,
        ) -> Result<konsensus_blvm_payment::PaymentStateSnapshot, RpcBlvmError> {
            Ok(konsensus_blvm_payment::PaymentStateSnapshot {
                state: "confirmed".into(),
                tx_hash: Some(hex::encode([0x22; 32])),
            })
        }

        async fn create_covenant_proof(
            &self,
            _payment_request_id: &str,
        ) -> Result<Vec<u8>, RpcBlvmError> {
            Ok(Vec::new())
        }
    }

    #[tokio::test]
    async fn confirmed_session_is_the_row_compose_debits() {
        let db = SqliteStorage::in_memory().await.expect("migrate");
        let storage: Arc<dyn Storage> = Arc::new(db);
        let store = Arc::new(StorageOnChainSessions::new(Arc::clone(&storage)));
        let manager = BlvmOnChainSessionManager::new(Arc::new(VerifiedRpc), store);
        let control = NodeBlvmSessions::new(manager);
        let bob = NodeId::from_bytes([2; 32]);

        let request = control
            .create_chat_payment_request(2, "51")
            .await
            .expect("request");
        assert_eq!(request, "req-open");
        let opened = control
            .confirm_chat_session(&bob, "req-open", &hex::encode([0x22; 32]))
            .await
            .expect("confirm");
        assert_eq!(opened.amount_sats, 2);
        assert_eq!(opened.spent_msat, 0);

        let message = MessageId::from_bytes([9; 32]);
        let reserved = storage
            .reserve_blvm_outbound_debit(&bob, &message, 1_000)
            .await
            .unwrap()
            .expect("compose can see the session");
        assert_eq!(reserved.session_debit_seq, 0);
        assert_eq!(reserved.payment_request_id, "req-open");
    }
}
