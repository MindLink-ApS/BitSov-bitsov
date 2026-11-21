//! Durable outgoing operation metadata. Recovery bytes are opaque to storage and
//! encrypted by EncryptedStorage; they never contain plaintext message content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxOperation {
    pub operation_id: String,
    pub recipient: String,
    pub kind: i64,
    pub request_hash: String,
    pub state: String,
    pub payment_hash: Option<String>,
    pub admission_payment_hash: Option<String>,
    pub message_id: Option<String>,
    pub settled_msat: i64,
    pub readmission_msat: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_sent_at: Option<i64>,
    pub attempts: i64,
    pub last_error: Option<String>,
    pub version: i64,
    pub recovery: Vec<u8>,
    /// Unresolved accounting references/intents, including conservative legacy backfill.
    pub accounting_pending: bool,
    /// Terminal recovery payload has been compacted to a permanent replay tombstone.
    pub recovery_compacted: bool,
}
impl OutboxOperation {
    pub fn prepared(
        operation_id: String,
        recipient: String,
        kind: u16,
        request_hash: String,
    ) -> Self {
        let now = chrono::Utc::now().timestamp_millis();
        Self {
            operation_id,
            recipient,
            kind: i64::from(kind),
            request_hash,
            state: "prepared".into(),
            payment_hash: None,
            admission_payment_hash: None,
            message_id: None,
            settled_msat: 0,
            readmission_msat: 0,
            created_at: now,
            updated_at: now,
            last_sent_at: None,
            attempts: 0,
            last_error: None,
            version: 0,
            recovery: Vec::new(),
            accounting_pending: true,
            recovery_compacted: false,
        }
    }
}

macro_rules! outbox_from_row {
    ($row:ty) => {
        impl sqlx::FromRow<'_, $row> for OutboxOperation {
            fn from_row(row: &$row) -> Result<Self, sqlx::Error> {
                use sqlx::Row;
                Ok(Self {
                    operation_id: row.try_get("operation_id")?,
                    recipient: row.try_get("recipient")?,
                    kind: row.try_get("kind")?,
                    request_hash: row.try_get("request_hash")?,
                    state: row.try_get("state")?,
                    payment_hash: row.try_get("payment_hash")?,
                    admission_payment_hash: row.try_get("admission_payment_hash")?,
                    message_id: row.try_get("message_id")?,
                    settled_msat: row.try_get("settled_msat")?,
                    readmission_msat: row.try_get("readmission_msat")?,
                    created_at: row.try_get("created_at")?,
                    updated_at: row.try_get("updated_at")?,
                    last_sent_at: row.try_get("last_sent_at")?,
                    attempts: row.try_get("attempts")?,
                    last_error: row.try_get("last_error")?,
                    version: row.try_get("version")?,
                    recovery: row.try_get("recovery")?,
                    accounting_pending: row.try_get("accounting_pending")?,
                    recovery_compacted: row.try_get("recovery_compacted")?,
                })
            }
        }
    };
}
outbox_from_row!(sqlx::sqlite::SqliteRow);
outbox_from_row!(sqlx::postgres::PgRow);

pub(crate) fn validate_handover_replacement(
    current: &OutboxOperation,
    next: &OutboxOperation,
    previous: &konsensus_core::MessageId,
    envelope: &konsensus_core::UkmEnvelope,
) -> Result<bool, crate::StorageError> {
    if current.version != next.version { return Ok(false); }
    if current.message_id.as_deref() != Some(previous.to_hex().as_str())
        || !matches!(current.state.as_str(), "paid" | "sent" | "rejected_retryable")
        || !current.last_error.as_deref().is_some_and(|reason| reason.starts_with("session_handover:"))
        || current.recipient != next.recipient || current.kind != next.kind
        || current.request_hash != next.request_hash || current.payment_hash != next.payment_hash
        || current.admission_payment_hash != next.admission_payment_hash
        || current.settled_msat != next.settled_msat || current.readmission_msat != next.readmission_msat
        || next.kind != i64::from(envelope.kind)
        || next.payment_hash.as_deref() != Some(hex::encode(envelope.payment_proof.payment_hash).as_str())
        || u64::try_from(next.settled_msat).ok() != Some(envelope.payment_proof.amount_msat)
        || previous == &envelope.id
    {
        return Err(crate::StorageError::Conversion("invalid deferred envelope replacement".into()));
    }
    Ok(true)
}

#[cfg(test)]
mod handover_tests {
    use super::*;
    use crate::{EncryptedStorage, SqliteStorage, Storage};
    use konsensus_core::{MessageId, NodeId, PaymentProof, Recipient, UkmEnvelope, UkmEnvelopeBuilder};

    async fn stores() -> Vec<Box<dyn Storage>> {
        vec![
            Box::new(SqliteStorage::in_memory().await.unwrap()),
            Box::new(EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32])),
        ]
    }

    async fn deferred(store: &dyn Storage) -> (OutboxOperation, UkmEnvelope, NodeId) {
        deferred_with_reason(store, "session_handover: the session cannot yet read this envelope").await
    }

    async fn deferred_with_reason(store: &dyn Storage, reason: &str) -> (OutboxOperation, UkmEnvelope, NodeId) {
        let sender = NodeId::from_bytes([1; 32]);
        let peer = NodeId::from_bytes([2; 32]);
        let env = UkmEnvelopeBuilder::new(1, sender, Recipient::Node(peer), b"old ciphertext".to_vec(),
            PaymentProof::new([3; 32], [4; 32], 10)).build();
        let mut op = OutboxOperation::prepared("retry-handover".into(), peer.to_hex(), 1, "request".into());
        op.state = "paid".into();
        op.message_id = Some(env.id.to_hex());
        op.payment_hash = Some(hex::encode(env.payment_proof.payment_hash));
        op.settled_msat = 10;
        op.recovery = b"encrypted recovery evidence".to_vec();
        assert!(store.insert_outbox_operation(&op).await.unwrap());
        assert!(store.commit_outbox_envelope(&op, &env).await.unwrap());
        store.mark_pending_sent(&env.id, &peer).await.unwrap();
        assert!(store.reject_pending(&env.id, &peer, &sender, reason, false).await.unwrap());
        (store.get_outbox_operation(&op.operation_id).await.unwrap().unwrap(), env, peer)
    }

    fn replacement(op: &OutboxOperation, old: &UkmEnvelope) -> (OutboxOperation, UkmEnvelope) {
        let mut env = old.clone();
        env.ciphertext = b"new ciphertext".to_vec();
        env.id = MessageId::compute(&env.ciphertext, &env.nonce);
        let mut op = op.clone();
        op.message_id = Some(env.id.to_hex());
        op.state = "paid".into();
        op.last_error = None;
        (op, env)
    }

    #[tokio::test]
    async fn handover_replacement_keeps_one_paid_delivery_and_ignores_old_ack() {
        for store in stores().await {
            let (old_op, old, peer) = deferred(store.as_ref()).await;
            let (new_op, new) = replacement(&old_op, &old);
            assert!(store.replace_outbox_envelope(&new_op, &old.id, &new, Some(b"new cache")).await.unwrap());
            assert!(store.get_message(&old.id).await.unwrap().is_none());
            assert_eq!(store.get_message(&new.id).await.unwrap().unwrap().ciphertext, b"new ciphertext");
            assert_eq!(store.get_message_plaintext(&new.id).await.unwrap().unwrap(), b"new cache");
            assert_eq!(store.count_pending_deliveries().await.unwrap(), 1);
            assert!(!store.acknowledge_pending(&old.id, &peer, &old.sender).await.unwrap());
            let current = store.get_outbox_operation(&new_op.operation_id).await.unwrap().unwrap();
            assert_eq!(current.state, "paid");
            assert_eq!(current.message_id, Some(new.id.to_hex()));
            assert_eq!(current.payment_hash, old_op.payment_hash);
            assert_eq!(current.settled_msat, 10);
            assert_eq!(current.recovery, old_op.recovery);
            store.mark_pending_sent(&new.id, &peer).await.unwrap();
            assert!(store.acknowledge_pending(&new.id, &peer, &new.sender).await.unwrap());
            assert_eq!(store.get_outbox_operation(&new_op.operation_id).await.unwrap().unwrap().state, "acked");
        }
    }

    #[tokio::test]
    async fn handover_replacement_rejects_stale_versions_and_changed_payment() {
        for store in stores().await {
            let (old_op, old, peer) = deferred(store.as_ref()).await;
            let (mut stale, new) = replacement(&old_op, &old);
            stale.version -= 1;
            assert!(!store.replace_outbox_envelope(&stale, &old.id, &new, None).await.unwrap());
            let (mut changed, mut invalid) = replacement(&old_op, &old);
            invalid.payment_proof.amount_msat = 20;
            changed.settled_msat = 20;
            assert!(store.replace_outbox_envelope(&changed, &old.id, &invalid, None).await.is_err());
            assert!(store.get_message(&old.id).await.unwrap().is_some());
            assert!(store.get_message(&new.id).await.unwrap().is_none());
            assert_eq!(store.count_pending_deliveries().await.unwrap(), 1);
            assert!(store.is_pending_dispatched(&old.id, &peer, &old.sender).await.unwrap());
        }
    }

    #[tokio::test]
    async fn handover_replacement_preserves_envelope_and_operation_bindings() {
        for store in stores().await {
            let (old_op, old, _) = deferred(store.as_ref()).await;
            for mutation in 0..12 {
                let (mut next, mut env) = replacement(&old_op, &old);
                match mutation {
                    0 => env.sender = NodeId::from_bytes([8; 32]),
                    1 => env.kind = 2,
                    2 => { env.recipient = Recipient::Node(NodeId::from_bytes([8; 32])); next.recipient = NodeId::from_bytes([8; 32]).to_hex(); },
                    3 => { env.payment_proof.payment_hash[0] ^= 1; next.payment_hash = Some(hex::encode(env.payment_proof.payment_hash)); },
                    4 => env.payment_proof.preimage[0] ^= 1,
                    5 => { env.payment_proof.amount_msat = 20; next.settled_msat = 20; },
                    6 => { env.nonce = konsensus_core::Nonce::from_bytes([8; 24]); env.id = MessageId::compute(&env.ciphertext, &env.nonce); next.message_id = Some(env.id.to_hex()); },
                    7 => env.references.push(MessageId::from_bytes([8; 32])),
                    8 => next.request_hash = "other request".into(),
                    9 => next.readmission_msat = 20,
                    10 => next.admission_payment_hash = Some("other admission".into()),
                    _ => next.kind = 2,
                }
                assert!(store.replace_outbox_envelope(&next, &old.id, &env, None).await.is_err(), "mutation {mutation}");
                assert_eq!(store.get_outbox_operation(&old_op.operation_id).await.unwrap().unwrap(), old_op);
                assert!(store.get_message(&old.id).await.unwrap().is_some());
                assert!(store.get_message(&env.id).await.unwrap().is_none());
                assert_eq!(store.count_pending_deliveries().await.unwrap(), 1);
            }
        }
    }

    #[tokio::test]
    async fn handover_replacement_requires_explicit_reason_and_live_state() {
        for (state, reason) in [
                ("rejected_retryable", "undecryptable: older recipient"),
                ("rejected_retryable", "session_pending: missing earlier messages"),
                ("failed_paid", "session_handover: unavailable"),
                ("acked", "session_handover: unavailable"),
        ] {
            for store in stores().await {
                let (mut current, old, _) = deferred_with_reason(store.as_ref(), reason).await;
                current.state = state.into();
                current.last_error = Some(reason.into());
                assert!(store.update_outbox_operation(&current).await.unwrap());
                current = store.get_outbox_operation(&current.operation_id).await.unwrap().unwrap();
                let (next, env) = replacement(&current, &old);
                assert!(store.replace_outbox_envelope(&next, &old.id, &env, None).await.is_err());
                assert!(store.get_message(&old.id).await.unwrap().is_some());
                assert!(store.get_message(&env.id).await.unwrap().is_none());
                assert_eq!(store.count_pending_deliveries().await.unwrap(), 1);
            }
        }
    }

    #[tokio::test]
    async fn handover_replacement_cache_failure_rolls_back_queue_and_operation() {
        let store = SqliteStorage::in_memory().await.unwrap();
        let (current, old, _) = deferred(&store).await;
        let (next, env) = replacement(&current, &old);
        sqlx::query("CREATE TRIGGER refuse_new_cache BEFORE INSERT ON messages WHEN NEW.plaintext_enc IS NOT NULL BEGIN SELECT RAISE(ABORT, 'cache unavailable'); END")
            .execute(store.pool()).await.unwrap();
        assert!(store.replace_outbox_envelope(&next, &old.id, &env, Some(b"new cache")).await.is_err());
        assert_eq!(store.get_outbox_operation(&current.operation_id).await.unwrap().unwrap(), current);
        assert!(store.get_message(&old.id).await.unwrap().is_some());
        assert!(store.get_message(&env.id).await.unwrap().is_none());
        assert_eq!(store.count_pending_deliveries().await.unwrap(), 1);
        sqlx::query("DROP TRIGGER refuse_new_cache").execute(store.pool()).await.unwrap();
        assert!(store.replace_outbox_envelope(&next, &old.id, &env, Some(b"new cache")).await.unwrap());
    }

    #[tokio::test]
    async fn handover_replacement_yields_to_an_old_ack_before_commit() {
        for store in stores().await {
            let (old_op, old, peer) = deferred(store.as_ref()).await;
            let (next, env) = replacement(&old_op, &old);
            assert!(store.acknowledge_pending(&old.id, &peer, &old.sender).await.unwrap());
            assert!(!store.replace_outbox_envelope(&next, &old.id, &env, None).await.unwrap());
            assert_eq!(store.get_outbox_operation(&old_op.operation_id).await.unwrap().unwrap().state, "acked");
            assert!(store.get_message(&old.id).await.unwrap().is_some());
            assert!(store.get_message(&env.id).await.unwrap().is_none());
            assert_eq!(store.count_pending_deliveries().await.unwrap(), 0);
        }
    }

    fn incoming() -> UkmEnvelope {
        UkmEnvelopeBuilder::new(1, NodeId::from_bytes([1; 32]), Recipient::Node(NodeId::from_bytes([2; 32])),
            b"old ciphertext".to_vec(), PaymentProof::new([3; 32], [4; 32], 10)).build()
    }

    #[tokio::test]
    async fn handover_deferral_preserves_proof_and_nonce_for_new_ciphertext() {
        for store in stores().await {
            let old = incoming();
            assert!(store.defer_unreadable_envelope(&old).await.unwrap());
            assert!(store.is_envelope_deferred(&old).await.unwrap());
            assert!(!store.has_nonce(&old.nonce).await.unwrap());
            assert!(store.accept_paid_envelope(&old).await.is_err());
            let (_, new) = replacement(&OutboxOperation::prepared("unused".into(), "peer".into(), 1, "request".into()), &old);
            assert_eq!(store.accept_paid_envelope(&new).await.unwrap(), crate::PaidAcceptance::Accepted);
            assert!(!store.is_envelope_deferred(&old).await.unwrap());
            assert_eq!(store.accept_paid_envelope(&old).await.unwrap(), crate::PaidAcceptance::PaymentReused);
            assert!(!store.defer_unreadable_envelope(&UkmEnvelope { id: MessageId::from_bytes([9; 32]), ..old.clone() }).await.unwrap());
        }
    }

    #[tokio::test]
    async fn handover_deferral_remains_retryable_until_acceptance_and_is_exactly_bound() {
        for store in stores().await {
            let old = incoming();
            for n in 0..3 {
                let mut env = old.clone();
                env.id = MessageId::from_bytes([n; 32]);
                assert!(store.defer_unreadable_envelope(&env).await.unwrap());
                assert!(store.defer_unreadable_envelope(&env).await.unwrap(), "exact retry uses no extra slot");
                assert!(store.is_envelope_deferred(&env).await.unwrap());
                let mut other_sender = env.clone();
                other_sender.sender = NodeId::from_bytes([8; 32]);
                assert!(!store.is_envelope_deferred(&other_sender).await.unwrap());
                assert!(!store.defer_unreadable_envelope(&other_sender).await.unwrap());
                let mut other_proof = env.clone();
                other_proof.payment_proof.payment_hash[0] ^= 1;
                assert!(!store.is_envelope_deferred(&other_proof).await.unwrap());
                assert!(!store.defer_unreadable_envelope(&other_proof).await.unwrap());
            }
            assert!(!store.has_nonce(&old.nonce).await.unwrap());
            let mut accepted = old.clone();
            accepted.ciphertext = b"readable replacement".to_vec();
            accepted.id = MessageId::compute(&accepted.ciphertext, &accepted.nonce);
            assert_eq!(store.accept_paid_envelope(&accepted).await.unwrap(), crate::PaidAcceptance::Accepted);
            for n in 0..64 {
                let mut previous = old.clone();
                previous.id = MessageId::from_bytes([n; 32]);
                assert!(!store.is_envelope_deferred(&previous).await.unwrap());
                assert_eq!(store.accept_paid_envelope(&previous).await.unwrap(), crate::PaidAcceptance::PaymentReused);
                assert!(!store.defer_unreadable_envelope(&previous).await.unwrap());
            }
        }
    }

    #[tokio::test]
    async fn handover_deferral_survives_restart_and_write_failure_authorizes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = format!("sqlite:{}", dir.path().join("deferrals.db").display());
        let store = SqliteStorage::open(&path).await.unwrap();
        let old = incoming();
        sqlx::query("CREATE TRIGGER refuse_deferral BEFORE INSERT ON envelope_deferrals BEGIN SELECT RAISE(ABORT, 'defer unavailable'); END")
            .execute(store.pool()).await.unwrap();
        assert!(store.defer_unreadable_envelope(&old).await.is_err());
        assert!(!store.is_envelope_deferred(&old).await.unwrap());
        assert!(!store.has_nonce(&old.nonce).await.unwrap());
        sqlx::query("DROP TRIGGER refuse_deferral").execute(store.pool()).await.unwrap();
        assert!(store.defer_unreadable_envelope(&old).await.unwrap());
        drop(store);
        let reopened = SqliteStorage::open(&path).await.unwrap();
        assert!(reopened.is_envelope_deferred(&old).await.unwrap());
        assert!(reopened.accept_paid_envelope(&old).await.is_err());
    }

    #[tokio::test]
    async fn handover_deferral_and_acceptance_cannot_both_win() {
        for _ in 0..8 {
            let store = SqliteStorage::in_memory().await.unwrap();
            let old = incoming();
            let (deferred, accepted) = tokio::join!(store.defer_unreadable_envelope(&old), store.accept_paid_envelope(&old));
            let deferred = deferred.unwrap_or(false);
            let accepted = matches!(accepted, Ok(crate::PaidAcceptance::Accepted));
            assert_ne!(deferred, accepted, "either deferral or admission wins");
            assert_eq!(store.is_envelope_deferred(&old).await.unwrap(), deferred);
            assert_eq!(store.has_nonce(&old.nonce).await.unwrap(), accepted);
        }
        for store in stores().await {
            let old = incoming();
            assert_eq!(store.accept_paid_envelope(&old).await.unwrap(), crate::PaidAcceptance::Accepted);
            assert!(!store.defer_unreadable_envelope(&old).await.unwrap());
            assert!(!store.is_envelope_deferred(&old).await.unwrap());
            assert!(store.has_nonce(&old.nonce).await.unwrap());
        }
    }
}
