mod common;
use konsensus_api::calls;
use konsensus_core::{
    payloads::call::{self as rules, HangupReason, Phase},
    NodeId,
};
use konsensus_storage::{SqliteStorage, Storage};

const ID: &str = "0123456789abcdef0123456789abcdef";

async fn answer_block_price_query(
    state: &konsensus_api::state::AppState,
    transport: &common::ConnectedStubTransport,
    peer: NodeId,
) {
    // Compose may spend longer than 50 ms in storage before asking. A price
    // injected before its query is correctly rejected as a stale answer.
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let queried = transport.raw_frames.lock().unwrap().iter().any(|bytes| {
                matches!(
                    konsensus_message::wire::Frame::from_bytes(bytes).unwrap(),
                    konsensus_message::wire::Frame::PriceQuery { kind: 404 }
                )
            });
            if queried {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("compose must request the block price before the peer answers");
    state.peer_prices.update_kind_price(peer, 404, 23_000, 850_000).await;
}

// SQLx must progress on another worker while the invoice responder records
// the callee's binding. The wallet supports keysend, as a real LN peer does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn known_ln_peer_call_block_uses_bound_invoice_and_is_admitted() {
    use axum::{body::Body, http::Request};
    use konsensus_core::traits::lightning::LightningProvider;
    use konsensus_lightning::MockLightningProvider;
    use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};
    use tower::ServiceExt;

    let payer = Arc::new(MockLightningProvider::new());
    let payee = Arc::new(MockLightningProvider::new());
    let initial_balance = payer.get_balance_msat().await.unwrap();
    let mut state = common::test_state_with_lightning(payer.clone());
    let (_, identity) = konsensus_core::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let caller_id = *state.identity.node_id();
    let callee_store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let invoice_store = callee_store.clone();
    let invoices = Arc::new(AtomicUsize::new(0));
    let observed = invoices.clone();
    // The mock's advertised pubkey is a placeholder; advertise the identity
    // that actually signs its BOLT11s, as LightningInfo does for a real wallet.
    let identity_invoice = payee.create_invoice(1_000, "identity", 60).await.unwrap();
    let ln_pubkey = identity_invoice.bolt11.parse::<lightning_invoice::Bolt11Invoice>()
        .unwrap().recover_payee_pub_key().to_string();
    let transport = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                observed.fetch_add(1, Ordering::SeqCst);
                let invoice = futures::executor::block_on(async {
                    let now = chrono::Utc::now().timestamp_millis() as u64;
                    let entry = invoice_store.call_get(&caller_id, ID).await.unwrap().unwrap();
                    rules::validate_block_invoice(&entry, 0, now).unwrap();
                    let invoice = payee.create_invoice(amount, "call block", rules::CALL_BLOCK_INVOICE_EXPIRY_SECS).await.unwrap();
                    invoice_store.record_call_block_invoice(&caller_id, ID, 0,
                        &hex::decode(&invoice.payment_hash).unwrap().try_into().unwrap(),
                        entry.deadline_ms + rules::CALL_BLOCK_RESUME_MS).await.unwrap();
                    invoice
                });
                Some(konsensus_api::state::InvoiceResponseData {
                    recipient: peer, bolt11: invoice.bolt11, payment_hash: invoice.payment_hash,
                })
            }),
    );
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.transport = transport.clone();
    mutable.storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    // LightningInfo fills this map in a money-ready connection.
    state.peer_ln_pubkeys.lock().await.insert(peer, ln_pubkey);
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state.session_manager.initiate_session(&peer, &target.prekey_bundle().await).await.unwrap();
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let caller = rules::receive(Some(rules::commit(
        rules::reserve(None, 400, "offer", "hash", now).unwrap(), "offer", now,
    ).unwrap()), 401, None, now).unwrap();
    callee_store.call_put(&caller_id, ID, &rules::CallEntry { side: rules::Side::Callee, ..caller.clone() }).await.unwrap();
    state.storage.call_put(&peer, ID, &caller).await.unwrap();
    let plaintext = format!(r#"{{"call_id":"{ID}","seq":0}}"#);
    let request = Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&state)).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"operation_id":uuid::Uuid::new_v4().to_string(),"recipient":peer.to_hex(),"kind":404,"plaintext":plaintext,"wait_ack_ms":0}).to_string())).unwrap();
    let quote = answer_block_price_query(&state, &transport, peer);
    let (response, ()) = tokio::join!(common::test_router(state.clone()).oneshot(request), quote);
    let response = response.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 65536).await.unwrap();
    assert_eq!(status, axum::http::StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(invoices.load(Ordering::SeqCst), 1, "known LN peers must still request the block invoice");
    let purposes: Vec<_> = transport.raw_frames.lock().unwrap().iter().filter_map(|bytes| {
        match konsensus_message::wire::Frame::from_bytes(bytes).unwrap() {
            konsensus_message::wire::Frame::RequestInvoice { purpose, .. } => Some(purpose),
            _ => None,
        }
    }).collect();
    assert_eq!(purposes, vec![format!("konsensus:call_block:{ID}:0")]);
    assert_eq!(initial_balance - payer.get_balance_msat().await.unwrap(), 23_000);
    let envelopes = transport.sent_envelopes.lock().unwrap().clone();
    let blocks: Vec<_> = envelopes.iter().filter(|(_, envelope)| envelope.kind == 404).collect();
    assert_eq!(blocks.len(), 1);
    let hash = &blocks[0].1.payment_proof.payment_hash;
    assert!(callee_store.has_call_block_invoice(&caller_id, ID, 0, hash).await.unwrap());
    calls::prepare_incoming_block(callee_store.as_ref(), &caller_id, Some(&plaintext), hash)
        .await.unwrap().commit().await.unwrap();
    assert!(calls::call_media_admitted(callee_store.as_ref(), &caller_id, ID, now + 1).await);
}

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
    // An explicit hangup is covered by the late-termination regression below;
    // unrelated reasons still cannot masquerade as the single-use Unpaid notice.
    for reason in ["timeout", "busy"] {
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

    store.record_call_block_invoice(&peer, ID, 0, &[1; 32], deadline + 60_000).await.unwrap();
    // Aborting paid acceptance releases the lock without admitting media.
    let prepared = calls::prepare_incoming_block(&store, &peer, Some(&body), &[1; 32]).await.unwrap();
    assert!(!calls::call_media_admitted(&store, &peer, ID, now).await);
    drop(prepared);
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(entry));

    let prepared = calls::prepare_incoming_block(&store, &peer, Some(&body), &[1; 32]).await.unwrap();
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
    assert!(calls::admit_incoming(&store, &own, &peer, 404, Some(&body)).await.is_err());
    let unbound = calls::prepare_incoming_block(&store, &peer, Some(&body), &[1; 32]).await.unwrap();
    assert!(unbound.refusal().is_some());
    drop(unbound);
    store.record_call_block_invoice(&peer, ID, 0, &[1; 32], now + 90_000).await.unwrap();
    calls::prepare_incoming_block(&store, &peer, Some(&body), &[1; 32]).await.unwrap().commit().await.unwrap();
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
    mutable.transport = transport.clone();
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
    let quote = answer_block_price_query(&state, &transport, peer);
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
async fn remote_hangup_during_block_payment_frees_slots_and_allows_next_call() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = NodeId::from_bytes([11; 32]);
    let peer = NodeId::from_bytes([10; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    for index in 0..rules::MAX_OPEN_CALLS_PER_PEER {
        let id = format!("{index:032x}");
        let ringing = rules::commit(rules::reserve(None, 400, "offer", "hash", now).unwrap(), "offer", now).unwrap();
        let answered = rules::receive(Some(ringing), 401, None, now).unwrap();
        let pending = rules::reserve_block(Some(answered), 0, "block", "hash", now).unwrap();
        store.call_put(&peer, &id, &pending).await.unwrap();
        let hangup = format!(r#"{{"v":1,"call_id":"{id}","reason":"hangup"}}"#);
        calls::admit_incoming(&store, &own, &peer, 403, Some(&hangup)).await.unwrap();
        assert!(store.call_pending().await.unwrap().is_empty());
        let body = format!(r#"{{"call_id":"{id}","seq":0}}"#);
        calls::commit_outgoing(&store, &peer, &body, "block", "hash").await.unwrap();
        let ended = store.call_get(&peer, &id).await.unwrap().unwrap();
        assert_eq!(ended.phase, Phase::Ended);
        assert_eq!(ended.end_reason, Some(HangupReason::Hangup));
        assert!(!ended.media_admitted(now));
    }
    assert_eq!(store.call_counts(&peer, now).await.unwrap().open_peer, 0);
    let offer = format!(r#"{{"v":1,"call_id":"{ID}","media":"audio","sdp":"v=0"}}"#);
    calls::reserve_outgoing(&store, &own, &peer, 400, &offer, "later", "later-hash").await.unwrap();
    calls::commit_outgoing(&store, &peer, &offer, "later", "later-hash").await.unwrap();
    let answer = format!(r#"{{"v":1,"call_id":"{ID}","sdp":"v=0"}}"#);
    calls::admit_incoming(&store, &own, &peer, 401, Some(&answer)).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap().unwrap().phase, Phase::Live);
}

#[tokio::test]
async fn explicit_hangup_after_local_unpaid_expiry_prevents_late_resume() {
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = NodeId::from_bytes([11; 32]);
    let peer = NodeId::from_bytes([10; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ended = rules::CallEntry { side: rules::Side::Caller, phase: Phase::Ended,
        deadline_ms: now - 1_000 + rules::TOMBSTONE_MS, paid_until_ms: None, next_block_seq: 0,
        pending: Some(rules::Pending { operation_id: "block".into(), kind: 404, request_hash: "hash".into() }),
        end_reason: Some(HangupReason::Unpaid), unpaid_notice_used: true };
    store.call_put(&peer, ID, &ended).await.unwrap();
    let hangup = format!(r#"{{"v":1,"call_id":"{ID}","reason":"hangup"}}"#);
    calls::admit_incoming(&store, &own, &peer, 403, Some(&hangup)).await.unwrap();
    let body = format!(r#"{{"call_id":"{ID}","seq":0}}"#);
    calls::commit_outgoing(&store, &peer, &body, "block", "hash").await.unwrap();
    let actual = store.call_get(&peer, ID).await.unwrap().unwrap();
    assert_eq!(actual.phase, Phase::Ended);
    assert_eq!(actual.end_reason, Some(HangupReason::Hangup));
    assert_eq!(actual.deadline_ms, ended.deadline_ms);
    assert!(actual.pending.is_none());
    assert_eq!(store.call_counts(&peer, now).await.unwrap().open_peer, 0);
}

#[tokio::test]
async fn legacy_ended_pending_blocks_are_reclaimed_by_settlement_and_sweep() {
    use konsensus_storage::EncryptedStorage;
    let store = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[7; 32]);
    let peer = NodeId::from_bytes([10; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let ended = rules::CallEntry { side: rules::Side::Caller, phase: Phase::Ended,
        deadline_ms: now + rules::TOMBSTONE_MS, paid_until_ms: None, next_block_seq: 0,
        pending: Some(rules::Pending { operation_id: "block".into(), kind: 404, request_hash: "hash".into() }),
        end_reason: Some(HangupReason::Hangup), unpaid_notice_used: false };
    let body = format!(r#"{{"call_id":"{ID}","seq":0}}"#);
    store.call_put(&peer, ID, &ended).await.unwrap();
    calls::commit_outgoing(&store, &peer, &body, "block", "hash").await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(rules::CallEntry { pending: None, ..ended.clone() }));
    store.call_put(&peer, ID, &ended).await.unwrap();
    store.call_sweep(now, 100).await.unwrap();
    assert!(store.call_pending().await.unwrap().is_empty());
    assert_eq!(store.call_counts(&peer, now).await.unwrap().open_peer, 0);
    assert!(store.call_get(&peer, ID).await.unwrap().is_some(), "keep replay protection");
    store.call_put(&peer, ID, &ended).await.unwrap();
    store.call_sweep(now + 10 * rules::TOMBSTONE_MS, 100).await.unwrap();
    assert!(store.call_get(&peer, ID).await.unwrap().is_none());
    assert!(ended.at(now + 10 * rules::TOMBSTONE_MS).is_none());
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
    // A peer cannot keep this row open with an unbounded ACK boundary.
    calls::receive_block_grant(&store, &konsensus_crypto::PlaintextCacheCipher::new(&[23; 32]), &own, &peer, &envelope.id, u64::MAX).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(granted.clone()));
    // Leave room for elapsed test time when checking the wall-clock cap.
    calls::receive_block_grant(&store, &konsensus_crypto::PlaintextCacheCipher::new(&[23; 32]), &own, &peer, &envelope.id, now + 125_000).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(granted.clone()));
    calls::receive_block_grant(&store, &konsensus_crypto::PlaintextCacheCipher::new(&[23; 32]), &own, &peer, &envelope.id, now + 120_000).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap().unwrap().paid_until_ms, Some(now + 120_000));
    store.call_put(&peer, ID, &granted).await.unwrap();
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
    store.store_message_plaintext(&envelope.id, &cipher.encrypt(&envelope.id.to_hex(), body.as_bytes()).unwrap()).await.unwrap();
    calls::receive_block_grant(&store, &cipher, &own, &peer, &envelope.id, now + 60_000).await.unwrap();
    let upgraded = store.get_outbox_operation_by_message(&envelope.id).await.unwrap().unwrap();
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&upgraded.recovery).unwrap()["call_block"], serde_json::json!([ID, 0]));
    let hung_up = rules::CallEntry { phase: Phase::Ended, end_reason: Some(HangupReason::Hangup), ..granted };
    store.call_put(&peer, ID, &hung_up).await.unwrap();
    calls::receive_block_grant(&store, &konsensus_crypto::PlaintextCacheCipher::new(&[23; 32]), &own, &peer, &envelope.id, now + 60_000).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(hung_up));
}

#[tokio::test]
async fn callee_grant_accepts_exact_resume_boundary_for_initial_and_renewal_blocks() {
    use konsensus_core::{UkmEnvelopeBuilder, Recipient, PaymentProof};
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = NodeId::from_bytes([31; 32]);
    let peer = NodeId::from_bytes([32; 32]);
    let cipher = konsensus_crypto::PlaintextCacheCipher::new(&[33; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    // Block zero: answered + 30s initial + 60s resume + 60s block.
    // Renewal: previous paid boundary + 10s grace + 60s resume + 60s block.
    for (seq, previous_paid, deadline, due) in [
        (0, None, now - 60_000, now - 90_000),
        (1, Some(now - 70_000), now - 60_000, now - 90_000),
    ] {
        let before = rules::CallEntry {
            side: rules::Side::Caller, phase: Phase::Live, deadline_ms: deadline,
            paid_until_ms: previous_paid, next_block_seq: seq,
            pending: None, end_reason: None, unpaid_notice_used: false,
        };
        let callee = rules::CallEntry { side: rules::Side::Callee, ..before.clone() };
        let grant = rules::receive_block(Some(callee), seq, now).unwrap();
        assert_eq!(grant.paid_until_ms, Some(now + 60_000));
        let committed = rules::commit(
            rules::reserve_block(Some(before.clone()), seq, "block", "hash", due).unwrap(),
            "block", due,
        ).unwrap();
        let envelope = UkmEnvelopeBuilder::new(404, own, Recipient::Node(peer), vec![], PaymentProof::new([34; 32], [35; 32], 23_000)).build();
        store.store_message(&envelope).await.unwrap();
        let mut op = konsensus_storage::OutboxOperation::prepared(format!("boundary-{seq}"), peer.to_hex(), 404, "request".into());
        op.state = "sent".into();
        op.message_id = Some(envelope.id.to_hex());
        op.recovery = serde_json::to_vec(&serde_json::json!({
            "call_block": [ID, seq], "dispatched": true, "expected_msat": 23_000,
            "fee_ceiling_msat": 0, "admission_msat": 0,
        })).unwrap();
        store.insert_outbox_operation(&op).await.unwrap();
        store.queue_pending_delivery(&envelope.id, &peer).await.unwrap();
        store.mark_pending_sent(&envelope.id, &peer).await.unwrap();
        // Cover both sides of local commit, with and without the expiry sweep.
        for row in [before.clone(), before.at(now).unwrap(), committed.clone(), committed.at(now).unwrap()] {
            store.call_put(&peer, ID, &row).await.unwrap();
            calls::receive_block_grant(&store, &cipher, &own, &peer, &envelope.id, now + 60_001).await.unwrap();
            assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(row));
            calls::receive_block_grant(&store, &cipher, &own, &peer, &envelope.id, now + 60_000).await.unwrap();
            let accepted = store.call_get(&peer, ID).await.unwrap().unwrap();
            assert_eq!(accepted.paid_until_ms, Some(now + 60_000), "seq {seq}");
            assert_eq!(accepted.next_block_seq, seq + 1);
            assert!(accepted.media_admitted(now + 59_999));
        }
    }
}

#[tokio::test]
async fn callee_grant_clears_only_its_own_pending_block() {
    use konsensus_core::{UkmEnvelopeBuilder, Recipient, PaymentProof};
    let store = SqliteStorage::in_memory().await.unwrap();
    let own = NodeId::from_bytes([41; 32]);
    let peer = NodeId::from_bytes([42; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let before = rules::CallEntry {
        side: rules::Side::Caller, phase: Phase::Live, deadline_ms: now + 60_000,
        paid_until_ms: Some(now + 50_000), next_block_seq: 1,
        pending: None, end_reason: None, unpaid_notice_used: false,
    };
    let pending = rules::reserve_block(Some(before), 1, "block-grant", "request", now + 30_000).unwrap();
    // Dispatch happened on time, but a backwards clock step makes the local
    // commit NotDue. Recovery can still deliver the paid envelope to the callee.
    assert_eq!(rules::commit(pending.clone(), "block-grant", now), Err(rules::CallRefusal::NotDue));
    store.call_put(&peer, ID, &pending).await.unwrap();
    let envelope = UkmEnvelopeBuilder::new(404, own, Recipient::Node(peer), vec![], PaymentProof::new([44; 32], [45; 32], 23_000)).build();
    store.store_message(&envelope).await.unwrap();
    let mut op = konsensus_storage::OutboxOperation::prepared("block-grant".into(), peer.to_hex(), 404, "request".into());
    op.state = "sent".into();
    op.message_id = Some(envelope.id.to_hex());
    op.recovery = serde_json::to_vec(&serde_json::json!({
        "call_block": [ID, 1], "dispatched": true, "expected_msat": 23_000,
        "fee_ceiling_msat": 0, "admission_msat": 0,
    })).unwrap();
    store.insert_outbox_operation(&op).await.unwrap();
    store.queue_pending_delivery(&envelope.id, &peer).await.unwrap();
    store.mark_pending_sent(&envelope.id, &peer).await.unwrap();
    let cipher = konsensus_crypto::PlaintextCacheCipher::new(&[43; 32]);
    calls::receive_block_grant(&store, &cipher, &own, &peer, &envelope.id, now + 110_000).await.unwrap();
    let granted = store.call_get(&peer, ID).await.unwrap().unwrap();
    assert_eq!(granted.next_block_seq, 2);
    assert!(granted.pending.is_none(), "the grant completes its paid reservation");
    assert_eq!(rules::commit(granted.clone(), "block-grant", now + 90_000).unwrap(), granted,
        "recovery must not apply an extra block without payment");
    let renewal = rules::reserve_block(Some(granted), 2, "next-block", "next-request", now + 90_000).unwrap();
    store.call_put(&peer, ID, &renewal).await.unwrap();
    calls::receive_block_grant(&store, &cipher, &own, &peer, &envelope.id, now + 110_000).await.unwrap();
    assert_eq!(store.call_get(&peer, ID).await.unwrap(), Some(renewal),
        "a delayed duplicate grant must preserve the next payment's reservation");
}
