mod common;
use konsensus_api::calls;
use konsensus_core::{
    payloads::call::{self as rules, HangupReason, Phase},
    NodeId,
};
use konsensus_storage::{SqliteStorage, Storage};

const ID: &str = "0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn paid_blocks_survive_storage_roundtrip_and_admit_only_the_right_call() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let peer = NodeId::from_bytes([1; 32]);
    let ringing = rules::receive(None, 400, 0).unwrap();
    let pending = rules::reserve(Some(ringing), 401, "answer", "hash", 1_000).unwrap();
    let live = rules::commit(pending, "answer", 1_000);
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
    assert!(rules::receive_block(Some(ended), 1, 71_002).is_err());
}

#[tokio::test]
async fn incoming_block_and_outgoing_block_reservations_use_normal_call_admission() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = NodeId::from_bytes([1; 32]);
    let peer = NodeId::from_bytes([2; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let entry = rules::commit(
        rules::reserve(
            Some(rules::receive(None, 400, now).unwrap()),
            401,
            "answer",
            "hash",
            now,
        )
        .unwrap(),
        "answer",
        now,
    );
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
            Some(rules::receive(None, 400, 0).unwrap()),
            401,
            "answer",
            "hash",
            1_000,
        )
        .unwrap(),
        "answer",
        1_000,
    );
    state.storage.call_put(&peer, ID, &entry).await.unwrap();
    calls::maintain_calls(&state, 11_001).await.unwrap();
    let ended = state.storage.call_get(&peer, ID).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
    assert!(!calls::call_media_admitted(state.storage.as_ref(), &peer, ID, 11_001).await);
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
        rules::reserve(None, 400, "offer", "hash", now - 8_000).unwrap(),
        "offer",
        now - 8_000,
    );
    let answered = rules::receive(Some(ringing), 401, now - 8_000).unwrap();
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
            Some(rules::receive(None, 400, 0).unwrap()),
            401,
            "answer",
            "hash",
            1_000,
        )
        .unwrap(),
        "answer",
        1_000,
    );
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
    let ringing = rules::commit(rules::reserve(None, 400, "offer", "hash", now).unwrap(), "offer", now);
    store.call_put(&peer, ID, &rules::receive(Some(ringing), 401, now).unwrap()).await.unwrap();
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
