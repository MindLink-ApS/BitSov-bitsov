mod common;
use konsensus_api::calls;
use konsensus_core::{
    payloads::call::{self as rules, HangupReason, Phase},
    NodeId,
};
use konsensus_storage::{SqliteStorage, Storage};

const ID: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn unpaid_notice_is_single_use_callee_only_and_reason_checked() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = NodeId::from_bytes([1; 32]);
    let peer = NodeId::from_bytes([2; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ringing = rules::receive(None, 400, None, now - 31_000).unwrap();
    let pending = rules::reserve(Some(ringing), 401, "answer", "hash", now - 31_000).unwrap();
    let ended = rules::commit(pending, "answer", now - 31_000).unwrap().at(now).unwrap();
    let unpaid = format!(r#"{{"v":1,"call_id":"{ID}","reason":"unpaid"}}"#);
    store.call_put(&peer, ID, &ended).await.unwrap();
    assert!(calls::admit_incoming(&store, &own, &peer, 403, Some(&unpaid)).await.is_err(), "caller cannot send the notice");
    let ended = rules::CallEntry { side: rules::Side::Caller, ..ended };
    store.call_put(&peer, ID, &ended).await.unwrap();
    for reason in ["hangup", "timeout", "busy"] {
        let body = format!(r#"{{"v":1,"call_id":"{ID}","reason":"{reason}"}}"#);
        assert!(calls::admit_incoming(&store, &own, &peer, 403, Some(&body)).await.is_err());
        assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(ended.clone()));
    }
    calls::admit_incoming(&store, &own, &peer, 403, Some(&unpaid)).await.unwrap();
    assert!(calls::admit_incoming(&store, &own, &peer, 403, Some(&unpaid)).await.is_err(), "a new paid envelope cannot notify again");
    let notified = store.call_get(&peer, ID).await.unwrap().unwrap();
    assert_eq!(notified.deadline_ms, ended.deadline_ms);
    assert_eq!(notified.end_reason, ended.end_reason);
    assert_eq!(notified.paid_until_ms, ended.paid_until_ms);
    assert!(!notified.media_admitted(now));
}

#[tokio::test]
async fn block_admission_keeps_its_decision_through_acceptance_and_expiry() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([9; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let answered_at = now;
    let ringing = rules::receive(None, 400, None, answered_at).unwrap();
    let pending = rules::reserve(Some(ringing), 401, "answer", "hash", answered_at).unwrap();
    let entry = rules::commit(pending, "answer", answered_at).unwrap();
    let deadline = entry.deadline_ms;
    store.call_put(&peer, ID, &entry).await.unwrap();
    let body = format!(r#"{{"v":1,"call_id":"{ID}","seq":0}}"#);

    // Aborting paid acceptance releases the lock without admitting media.
    let prepared = calls::prepare_incoming_block(&store, &peer, Some(&body)).await.unwrap();
    assert!(!calls::call_media_admitted(&store, &peer, ID, now).await);
    drop(prepared);
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(entry));

    let prepared = calls::prepare_incoming_block(&store, &peer, Some(&body)).await.unwrap();
    let expiry = calls::expire_calls(&store, deadline + 1);
    tokio::pin!(expiry);
    assert!(futures::poll!(&mut expiry).is_pending());
    // The expiry sweep is already checking a time beyond the old deadline.
    // It must wait for acceptance, then observe the extended paid interval.
    prepared.commit().await.unwrap();
    assert!(expiry.await.unwrap().is_empty());
    let paid = store.call_get(&peer, ID).await.unwrap().unwrap();
    assert_eq!(paid.paid_until_ms, Some(answered_at + 60_000));
    assert_eq!(paid.next_block_seq, 1);
    assert!(paid.media_admitted(deadline + 1));
}

#[tokio::test]
async fn expiry_ends_both_sides_but_only_callee_needs_notification() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let caller_peer = NodeId::from_bytes([7; 32]);
    let callee_peer = NodeId::from_bytes([8; 32]);
    let ringing = rules::receive(None, 400, None, 0).unwrap();
    let pending = rules::reserve(Some(ringing), 401, "answer", "hash", 1_000).unwrap();
    let callee = rules::commit(pending, "answer", 1_000).unwrap();
    let caller = rules::CallEntry { side: rules::Side::Caller, ..callee.clone() };
    store.call_put(&caller_peer, ID, &caller).await.unwrap();
    store.call_put(&callee_peer, ID, &callee).await.unwrap();
    assert_eq!(calls::expire_calls(&store, 31_001).await.unwrap(), vec![(callee_peer, ID.to_owned())]);
    for peer in [caller_peer, callee_peer] {
        let ended = store.call_get(&peer, ID).await.unwrap().unwrap();
        assert_eq!(ended.phase, Phase::Ended);
        assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
        assert!(!ended.media_admitted(31_001));
    }
    assert!(calls::expire_calls(&store, 31_002).await.unwrap().is_empty());
}

#[tokio::test]
async fn paid_blocks_survive_storage_roundtrip_and_admit_only_the_right_call() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([1; 32]);
    let ringing = rules::receive(None, 400, None, 0).unwrap();
    let pending = rules::reserve(Some(ringing), 401, "answer", "hash", 1_000).unwrap();
    let live = rules::commit(pending, "answer", 1_000).unwrap();
    assert!(!live.media_admitted(1_000));
    let paid = rules::receive_block(Some(live), 0, 1_000).unwrap();
    store.call_put(&peer, ID, &paid).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(paid));
    assert!(calls::call_media_admitted(&store, &peer, ID, 71_000).await);
    assert!(!calls::call_media_admitted(&store, &peer, ID, 71_001).await);
    assert!(!calls::call_media_admitted(&store, &NodeId::from_bytes([2; 32]), ID, 2_000).await);
    assert!(!calls::call_media_admitted(&store, &peer, "unknown", 2_000).await);
    let expired = calls::expire_calls(&store, 71_001).await.unwrap();
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0], (peer, ID.to_owned()));
    let ended = store.call_get(&peer, ID).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    assert!(calls::expire_calls(&store, 71_002)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(rules::receive_block(Some(ended), 1, 71_002).unwrap().paid_until_ms, Some(131_002));
}

#[tokio::test]
async fn incoming_block_and_outgoing_block_reservations_use_normal_call_admission() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = NodeId::from_bytes([1; 32]);
    let peer = NodeId::from_bytes([2; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let entry = rules::commit(
        rules::reserve(
            Some(rules::receive(None, 400, None, now).unwrap()),
            401,
            "answer",
            "hash",
            now,
        )
        .unwrap(),
        "answer",
        now,
    ).unwrap();
    store.call_put(&peer, ID, &entry).await.unwrap();
    let body = format!(r#"{{"call_id":"{ID}","seq":0}}"#);
    calls::admit_incoming(&store, &own, &peer, 404, Some(&body))
        .await
        .unwrap();
    assert!(calls::call_media_admitted(&store, &peer, ID, now + 1).await);
    assert!(calls::admit_incoming(&store, &own, &peer, 404, Some(&body))
        .await
        .is_err());
    assert!(
        calls::reserve_outgoing(&store, &own, &peer, 404, &body, "wrong-side", "hash")
            .await
            .is_err()
    );
    assert!(calls::is_call_kind(404));
}

#[tokio::test]
async fn unpaid_expiry_notification_cannot_grant_media_even_if_dispatch_fails() {
    let mut state = common::test_state();
    std::sync::Arc::get_mut(&mut state).unwrap().storage =
        std::sync::Arc::new(SqliteStorage::in_memory().await.unwrap());
    let peer = NodeId::from_bytes([3; 32]);
    let entry = rules::commit(
        rules::reserve(
            Some(rules::receive(None, 400, None, 0).unwrap()),
            401,
            "answer",
            "hash",
            1_000,
        )
        .unwrap(),
        "answer",
        1_000,
    ).unwrap();
    state.storage.call_put(&peer, ID, &entry).await.unwrap();
    calls::maintain_calls(&state, 31_001).await.unwrap();
    let ended = state.storage.call_get(&peer, ID).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    assert!(!calls::call_media_admitted(state.storage.as_ref(), &peer, ID, 31_001).await);
}

#[tokio::test]
async fn block_price_queries_are_kind_specific_and_never_use_sender_tariff() {
    let mut state = common::test_state();
    let peer = NodeId::from_bytes([4; 32]);
    let transport = std::sync::Arc::new(common::ConnectedStubTransport::new(
        vec![peer],
        state.invoice_requests.clone(),
    ));
    std::sync::Arc::get_mut(&mut state).unwrap().transport = transport;
    let answer = async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        state
            .peer_prices
            .update_kind_price(peer, 400, 77_000, 850_000)
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        state
            .peer_prices
            .update_kind_price(peer, 404, 23_000, 850_000)
            .await;
    };
    let (price, ()) = tokio::join!(calls::peer_call_kind_price(&state, &peer, 404), answer);
    assert_eq!(price.unwrap(), 23_000);
    assert_eq!(
        state.peer_prices.get_peer_price(&peer, 400).await,
        Some(77_000)
    );
    let absent = NodeId::from_bytes([5; 32]);
    assert!(calls::peer_call_kind_price(&state, &absent, 404)
        .await
        .is_err());
}

#[tokio::test]
async fn delayed_block_invoice_cannot_charge_after_grace() {
    delayed_block_invoice(28_000).await;
}

#[tokio::test]
async fn delayed_block_invoice_cannot_charge_inside_deadline_margin() {
    delayed_block_invoice(23_000).await;
}

async fn delayed_block_invoice(answer_age_ms: u64) {
    use axum::{body::Body, http::Request};
    use konsensus_core::traits::lightning::LightningProvider;
    use konsensus_lightning::shared_mock::SharedMockProvider;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tower::ServiceExt;
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("payments.sqlite");
    let payer = Arc::new(SharedMockProvider::new(&ledger, "caller", 100_000).unwrap());
    let payee = Arc::new(SharedMockProvider::new(&ledger, "callee", 0).unwrap());
    let mut state = common::test_state_with_lightning(payer.clone());
    let (_, identity) = konsensus_core::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let invoices = Arc::new(AtomicUsize::new(0));
    let observed = invoices.clone();
    let transport = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                observed.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(2_500));
                let invoice =
                    futures::executor::block_on(payee.create_invoice(amount, "call block", 60))
                        .unwrap();
                Some(konsensus_api::state::InvoiceResponseData {
                    recipient: peer,
                    bolt11: invoice.bolt11,
                    payment_hash: invoice.payment_hash,
                })
            }),
    );
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.transport = transport;
    mutable.storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state
        .session_manager
        .initiate_session(&peer, &target.prekey_bundle().await)
        .await
        .unwrap();
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ringing = rules::commit(
        rules::reserve(None, 400, "offer", "hash", now - answer_age_ms).unwrap(),
        "offer",
        now - answer_age_ms,
    ).unwrap();
    let answered = rules::receive(Some(ringing), 401, None, now - answer_age_ms).unwrap();
    state.storage.call_put(&peer, ID, &answered).await.unwrap();
    let request = Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&state)).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"operation_id":uuid::Uuid::new_v4().to_string(),"recipient":peer.to_hex(),"kind":404,"plaintext":format!(r#"{{"call_id":"{ID}","seq":0}}"#),"wait_ack_ms":0}).to_string())).unwrap();
    let quote = async {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        state
            .peer_prices
            .update_kind_price(peer, 404, 23_000, 850_000)
            .await;
    };
    let (response, ()) = tokio::join!(common::test_router(state.clone()).oneshot(request), quote);
    let response = response.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    assert_eq!(
        invoices.load(Ordering::SeqCst),
        1,
        "the invoice exchange was reached"
    );
    assert!(
        payer.list_payments(100).await.unwrap().is_empty(),
        "expired invoice must not dispatch money: {status} {}",
        String::from_utf8_lossy(&body)
    );
    assert!(
        !calls::call_media_admitted(
            state.storage.as_ref(),
            &peer,
            ID,
            chrono::Utc::now().timestamp_millis() as u64
        )
        .await
    );
}

#[tokio::test]
async fn grace_endpoint_still_counts_against_call_bounds() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([6; 32]);
    let entry = rules::commit(
        rules::reserve(
            Some(rules::receive(None, 400, None, 0).unwrap()),
            401,
            "answer",
            "hash",
            1_000,
        )
        .unwrap(),
        "answer",
        1_000,
    ).unwrap();
    let paid = rules::receive_block(Some(entry), 0, 1_000).unwrap();
    store.call_put(&peer, ID, &paid).await.unwrap();
    assert_eq!(store.call_counts(&peer, 71_000).await.unwrap().open_peer, 1);
    assert_eq!(
        store.call_open_by_peer(&peer, 71_000).await.unwrap().len(),
        1
    );
    assert_eq!(store.call_counts(&peer, 71_001).await.unwrap().open_peer, 0);
}

#[tokio::test]
async fn hangup_during_dispatch_journal_save_does_not_charge_a_block() {
    use axum::{body::Body, http::Request};
    use konsensus_core::traits::lightning::LightningProvider;
    use konsensus_lightning::shared_mock::SharedMockProvider;
    use std::{sync::Arc, time::Duration};
    use tower::ServiceExt;

    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("payments.sqlite");
    let payer = Arc::new(SharedMockProvider::new(&ledger, "caller", 100_000).unwrap());
    let payee = Arc::new(SharedMockProvider::new(&ledger, "callee", 0).unwrap());
    let mut state = common::test_state_with_lightning(payer.clone());
    let (_, identity) = konsensus_core::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let transport = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                let invoice = futures::executor::block_on(payee.create_invoice(amount, "call block", 60)).unwrap();
                Some(konsensus_api::state::InvoiceResponseData {
                    recipient: peer,
                    bolt11: invoice.bolt11,
                    payment_hash: invoice.payment_hash,
                })
            }),
    );
    let store = Arc::new(common::MemStorage::new());
    let gate = Arc::new(common::PeerWriteGate::default());
    *store.call_block_dispatch_gate.lock().unwrap() = Some(gate.clone());
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.transport = transport;
    mutable.storage = store.clone();
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state.session_manager.initiate_session(&peer, &target.prekey_bundle().await).await.unwrap();
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ringing = rules::commit(rules::reserve(None, 400, "offer", "hash", now).unwrap(), "offer", now).unwrap();
    store.call_put(&peer, ID, &rules::receive(Some(ringing), 401, None, now).unwrap()).await.unwrap();
    let request = Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&state)).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"operation_id":uuid::Uuid::new_v4().to_string(),"recipient":peer.to_hex(),"kind":404,"plaintext":format!(r#"{{"call_id":"{ID}","seq":0}}"#),"wait_ack_ms":0}).to_string())).unwrap();
    let response = tokio::spawn(common::test_router(state.clone()).oneshot(request));
    tokio::time::sleep(Duration::from_millis(50)).await;
    state.peer_prices.update_kind_price(peer, 404, 23_000, 850_000).await;
    tokio::time::timeout(Duration::from_secs(5), gate.entered.notified()).await.unwrap();
    let hangup = format!(r#"{{"v":1,"call_id":"{ID}","reason":"hangup"}}"#);
    calls::admit_incoming(store.as_ref(), state.identity.node_id(), &peer, 403, Some(&hangup)).await.unwrap();
    gate.release.notify_one();
    let response = tokio::time::timeout(Duration::from_secs(5), response).await.unwrap().unwrap().unwrap();
    assert!(payer.list_payments(100).await.unwrap().is_empty(), "ended call was charged: {}", response.status());
    assert_eq!(store.call_get(&peer, ID).await.unwrap().unwrap().phase, Phase::Ended);
}

#[tokio::test]
async fn unpaid_notice_reservation_survives_encrypted_storage_restart() {
    use konsensus_storage::EncryptedStorage;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calls.sqlite");
    let own = NodeId::from_bytes([1; 32]);
    let peer = NodeId::from_bytes([2; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ringing = rules::receive(None, 400, None, now - 31_000).unwrap();
    let pending = rules::reserve(Some(ringing), 401, "answer", "hash", now - 31_000).unwrap();
    let ended = rules::commit(pending, "answer", now - 31_000).unwrap().at(now).unwrap();
    let body = format!(r#"{{"v":1,"call_id":"{ID}","reason":"unpaid"}}"#);
    {
        let store = EncryptedStorage::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap(), &[7; 32]);
        store.call_put(&peer, ID, &ended).await.unwrap();
        calls::reserve_outgoing(&store, &own, &peer, 403, &body, "notice", "hash").await.unwrap();
        calls::reserve_outgoing(&store, &own, &peer, 403, &body, "notice", "hash").await.unwrap();
        assert!(calls::reserve_outgoing(&store, &own, &peer, 403, &body, "other", "hash").await.is_err());
    }
    {
        let store = EncryptedStorage::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap(), &[7; 32]);
        let pending = store.call_pending().await.unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].2.unpaid_notice_used);
        calls::reserve_outgoing(&store, &own, &peer, 403, &body, "notice", "hash").await.unwrap();
        calls::commit_outgoing(&store, &peer, &body, "notice", "hash").await.unwrap();
    }
    let store = EncryptedStorage::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap(), &[7; 32]);
    assert!(store.call_pending().await.unwrap().is_empty());
    assert!(calls::reserve_outgoing(&store, &own, &peer, 403, &body, "second", "hash2").await.is_err());
    let committed = store.call_get(&peer, ID).await.unwrap().unwrap();
    assert!(committed.unpaid_notice_used);
    assert_eq!(committed.deadline_ms, ended.deadline_ms);
    assert!(!committed.media_admitted(now));
    let caller = rules::CallEntry { side: rules::Side::Caller, unpaid_notice_used: false, ..ended };
    store.call_put(&peer, ID, &caller).await.unwrap();
    assert!(calls::reserve_outgoing(&store, &own, &peer, 403, &body, "caller", "hash").await.is_err());
}

#[tokio::test]
async fn failed_paid_block_commit_preserves_pending_evidence() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([10; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let answered_at = now - 31_000;
    let ringing = rules::commit(
        rules::reserve(None, 400, "offer", "hash", answered_at).unwrap(),
        "offer",
        answered_at,
    ).unwrap();
    let answered = rules::receive(Some(ringing), 401, None, answered_at).unwrap();
    let pending = rules::reserve_block(Some(answered), 0, "block", "hash", answered_at).unwrap();
    let body = format!(r#"{{"call_id":"{ID}","seq":0}}"#);
    // Exercise both an unswept Live row and the durable Unpaid tombstone.
    for entry in [pending.clone(), pending.at(now).unwrap()] {
        // Explicit hangup is never resumable, even with a settled reservation.
        let entry = rules::CallEntry { phase: Phase::Ended, end_reason: Some(HangupReason::Hangup), ..entry };
        store.call_put(&peer, ID, &entry).await.unwrap();
        assert!(calls::commit_outgoing(&store, &peer, &body, "block", "hash").await.is_err());
        assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(entry),
            "a rejected paid transition must retain its pending reconciliation evidence");
    }
}

#[tokio::test]
async fn callee_grant_resumes_caller_after_unpaid_notice_and_is_bound_to_paid_message() {
    use konsensus_core::{UkmEnvelopeBuilder, Recipient, PaymentProof};
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = NodeId::from_bytes([21; 32]);
    let peer = NodeId::from_bytes([22; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ended = rules::CallEntry { side: rules::Side::Caller, phase: Phase::Ended,
        deadline_ms: now + rules::TOMBSTONE_MS, paid_until_ms: None, next_block_seq: 0,
        pending: None, end_reason: Some(HangupReason::Unpaid), unpaid_notice_used: true };
    store.call_put(&peer, ID, &ended).await.unwrap();
    let envelope = UkmEnvelopeBuilder::new(404, own, Recipient::Node(peer), vec![], PaymentProof::new([24; 32], [25; 32], 23_000)).build();
    store.store_message(&envelope).await.unwrap();
    let mut op = konsensus_storage::OutboxOperation::prepared("block-grant".into(), peer.to_hex(), 404, "request".into());
    op.state = "sent".into();
    op.message_id = Some(envelope.id.to_hex());
    op.recovery = serde_json::to_vec(&serde_json::json!({
        "call_block": [ID, 0], "dispatched": true, "expected_msat": 23_000,
        "fee_ceiling_msat": 0, "admission_msat": 0,
    })).unwrap();
    store.insert_outbox_operation(&op).await.unwrap();
    store.queue_pending_delivery(&envelope.id, &peer).await.unwrap();
    store.mark_pending_sent(&envelope.id, &peer).await.unwrap();
    // Deliberately no plaintext cache: durable operation binding is enough.
    calls::receive_block_grant(&store, &konsensus_crypto::PlaintextCacheCipher::new(&[23; 32]), &own, &NodeId::from_bytes([99; 32]), &envelope.id, now + 60_000).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(ended));
    calls::receive_block_grant(&store, &konsensus_crypto::PlaintextCacheCipher::new(&[23; 32]), &own, &peer, &envelope.id, now + 60_000).await.unwrap();
    let granted = store.call_get(&peer, ID).await.unwrap().unwrap();
    assert_eq!(granted.phase, Phase::Live);
    assert_eq!(granted.paid_until_ms, Some(now + 60_000));
    assert_eq!(granted.next_block_seq, 1);
    assert!(granted.media_admitted(now + 59_999));
    calls::receive_block_grant(&store, &konsensus_crypto::PlaintextCacheCipher::new(&[23; 32]), &own, &peer, &envelope.id, now + 60_000).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(granted.clone()));
    // Upgrade recovery: a legacy pending block needs its cached plaintext;
    // a missing cache must retain the delivery instead of silently ACKing.
    let mut legacy = store.get_outbox_operation_by_message(&envelope.id).await.unwrap().unwrap();
    let mut recovery: serde_json::Value = serde_json::from_slice(&legacy.recovery).unwrap();
    recovery.as_object_mut().unwrap().remove("call_block");
    legacy.recovery = serde_json::to_vec(&recovery).unwrap();
    assert!(store.update_outbox_operation(&legacy).await.unwrap());
    let cipher = konsensus_crypto::PlaintextCacheCipher::new(&[23; 32]);
    assert!(calls::receive_block_grant(&store, &cipher, &own, &peer, &envelope.id, now + 60_000).await.is_err());
    assert!(store.is_pending_dispatched(&envelope.id, &peer, &own).await.unwrap());
    let body = format!(r#"{{"call_id":"{ID}","seq":0}}"#);
    store.store_message_plaintext(&envelope.id, &cipher.encrypt(body.as_bytes()).unwrap()).await.unwrap();
    calls::receive_block_grant(&store, &cipher, &own, &peer, &envelope.id, now + 60_000).await.unwrap();
    let upgraded = store.get_outbox_operation_by_message(&envelope.id).await.unwrap().unwrap();
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&upgraded.recovery).unwrap()["call_block"], serde_json::json!([ID, 0]));
    let hung_up = rules::CallEntry { phase: Phase::Ended, end_reason: Some(HangupReason::Hangup), ..granted };
    store.call_put(&peer, ID, &hung_up).await.unwrap();
    calls::receive_block_grant(&store, &konsensus_crypto::PlaintextCacheCipher::new(&[23; 32]), &own, &peer, &envelope.id, now + 60_000).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(hung_up));
}
