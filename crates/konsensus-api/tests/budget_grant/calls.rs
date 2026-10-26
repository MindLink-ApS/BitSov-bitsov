use super::*;
use konsensus_core::payloads::call::{HangupReason, Phase};
use konsensus_storage::{EncryptedStorage, SqliteStorage};

const CALL: &str = "11111111222243338444555555555555";

async fn send(fx: &Fx, token: &str, kind: u16, price: u64, seq: u32) -> (StatusCode, Value) {
    let prices = fx.state.peer_prices.clone();
    let peer = fx.peer;
    let quotes = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            prices.update_kind_price(peer, 400, 1_000, 850_000).await;
            prices.update_kind_price(peer, 404, price, 850_000).await;
        }
    });
    let body = if kind == 400 {
        json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"})
    } else {
        json!({"v": 1, "call_id": CALL, "seq": seq})
    };
    let result = fx.call("POST", "/api/v1/messages/compose", Some(json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": peer.to_hex(),
        "kind": kind, "plaintext": body.to_string(), "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })), Some(token)).await;
    quotes.abort();
    result
}

async fn prepared() -> (Fx, String) {
    let mut fx = fixture().await;
    // Admission locks and price-query throttles are process-wide and peer keyed.
    // Independent node fixtures therefore need independent peers.
    let (_, identity) = konsensus_core::NodeIdentity::generate().unwrap();
    fx.peer = *identity.node_id();
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    fx.state
        .session_manager
        .initiate_session(&fx.peer, &target.prekey_bundle().await)
        .await
        .unwrap();
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PEER_LN.into());
    // Exercise the production encrypted call storage as well as the pairing file.
    let store = SqliteStorage::open(fx.tmp.path().join("calls.sqlite").to_str().unwrap())
        .await
        .unwrap();
    fx.state = Arc::new(AppState {
        storage: Arc::new(EncryptedStorage::new(store, &[7; 32])),
        transport: Arc::new(ConnectedStubTransport::new(
            vec![fx.peer],
            fx.state.invoice_requests.clone(),
        )),
        ..(*fx.state).clone()
    });
    fx.wallet.call_capacity.store(10_000_000, Ordering::SeqCst);
    let mut terms = GrantTerms::new(5_000_000);
    terms.breakers.max_msat_per_10_minutes = 5_000_000;
    let token = fx.grant(None, terms).await;
    (fx, token)
}

async fn answer(fx: &Fx) {
    konsensus_api::calls::admit_incoming(
        fx.state.storage.as_ref(),
        fx.state.identity.node_id(),
        &fx.peer,
        401,
        Some(&json!({"v":1,"call_id":CALL,"sdp":"answer"}).to_string()),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn call_reserves_before_offer_draws_above_message_cap_and_releases_each_end_path() {
    for reason in [
        HangupReason::Hangup,
        HangupReason::Unpaid,
        HangupReason::Failed,
        HangupReason::Timeout,
    ] {
        let (fx, token) = prepared().await;
        let (status, body) = send(&fx, &token, 400, 7_000, 0).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let hold = fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .unwrap();
        assert_eq!((hold.reserved_msat, hold.spent_msat), (1_680_000, 0));
        assert_eq!(fx.used(), 1_681_000); // offer plus the complete block hold
        answer(&fx).await;
        let (status, body) = send(&fx, &token, 404, 7_000, 0).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let view = fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .unwrap();
        assert_eq!((view.spent_msat, view.remaining_msat), (7_000, 1_673_000));
        assert_eq!(fx.used(), 1_681_000);
        let request = Request::builder()
            .uri(format!("/api/v1/calls?peer={}", fx.peer))
            .header("authorization", common::auth_header(&fx.state))
            .body(Body::empty())
            .unwrap();
        let response = common::test_router(fx.state.clone())
            .oneshot(request)
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap();
        let calls: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(calls[0]["reservation"]["spent_msat"], 7_000);
        assert_eq!(calls[0]["reservation"]["per_block_msat"], 7_000);
        if reason == HangupReason::Timeout {
            let deadline = fx
                .state
                .storage
                .call_get(&fx.peer, CALL)
                .await
                .unwrap()
                .unwrap()
                .deadline_ms;
            konsensus_api::calls::maintain_calls(&fx.state, deadline + 1)
                .await
                .unwrap();
        } else {
            let hangup = json!({"v":1,"call_id":CALL,"reason":reason.as_str()}).to_string();
            konsensus_api::calls::admit_incoming(
                fx.state.storage.as_ref(),
                fx.state.identity.node_id(),
                &fx.peer,
                403,
                Some(&hangup),
            )
            .await
            .unwrap();
        }
        for _ in 0..2 {
            konsensus_api::calls::reconcile_call_spend(
                &fx.state,
                chrono::Utc::now().timestamp_millis() as u64,
            )
            .await
            .unwrap();
        }
        assert_eq!(fx.used(), 8_000);
        let budget = fx.service.reload_from_disk().unwrap().grants[0]
            .budget
            .clone()
            .unwrap();
        assert_eq!(
            budget
                .breaker_status(chrono::Utc::now().timestamp())
                .payments_last_hour,
            2
        ); // offer + ONE call hold
        assert!(budget.pending.is_empty());
    }
}

#[tokio::test]
async fn call_liquidity_and_grant_cap_refuse_before_any_offer_payment() {
    for liquidity in [true, false] {
        let (fx, token) = prepared().await;
        let token = if liquidity {
            fx.wallet.call_capacity.store(1_679_999, Ordering::SeqCst);
            token
        } else {
            let mut terms = GrantTerms::new(100_000);
            terms.breakers.max_msat_per_10_minutes = 5_000_000;
            fx.grant(None, terms).await
        };
        let (status, body) = send(&fx, &token, 400, 7_000, 0).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["reason"],
            if liquidity {
                "call_liquidity_insufficient"
            } else {
                "per_call"
            }
        );
        assert_eq!(fx.wallet.money(), 0);
        assert_eq!(fx.used(), 0);
        assert!(fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .is_none());
    }
}

#[tokio::test]
async fn call_price_increase_and_payment_failure_end_without_extra_spend() {
    for price_change in [true, false] {
        let (fx, token) = prepared().await;
        assert_eq!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
        answer(&fx).await;
        assert_eq!(send(&fx, &token, 404, 7_000, 0).await.0, StatusCode::OK);
        // Advance the real call's paid interval to its renewal window.
        let now = chrono::Utc::now().timestamp_millis() as u64;
        let mut entry = fx
            .state
            .storage
            .call_get(&fx.peer, CALL)
            .await
            .unwrap()
            .unwrap();
        entry.paid_until_ms = Some(now + 10_000);
        entry.deadline_ms = now + 20_000;
        fx.state
            .storage
            .call_put(&fx.peer, CALL, &entry)
            .await
            .unwrap();
        if !price_change {
            fx.wallet.set(FAILED);
        }
        // Replace the cached kind price before the next query can reuse it.
        let price = if price_change { 8_000 } else { 7_000 };
        fx.state
            .peer_prices
            .update_kind_price(fx.peer, 404, price, 850_000)
            .await;
        let (status, body) = send(&fx, &token, 404, price, 1).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        if price_change {
            assert_eq!(body["reason"], "call_price_changed");
        }
        assert_eq!(fx.wallet.left(), 8_000);
        assert_eq!(fx.used(), 8_000);
        assert_eq!(
            fx.state
                .storage
                .call_get(&fx.peer, CALL)
                .await
                .unwrap()
                .unwrap()
                .phase,
            Phase::Ended
        );
    }
}

#[tokio::test]
async fn call_restart_recovers_release_after_durable_hangup() {
    let (mut fx, token) = prepared().await;
    assert_eq!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
    answer(&fx).await;
    assert_eq!(send(&fx, &token, 404, 7_000, 0).await.0, StatusCode::OK);
    let hangup = json!({"v":1,"call_id":CALL,"reason":"hangup"}).to_string();
    konsensus_api::calls::admit_incoming(
        fx.state.storage.as_ref(),
        fx.state.identity.node_id(),
        &fx.peer,
        403,
        Some(&hangup),
    )
    .await
    .unwrap();
    // Simulate a crash between durable hangup and releasing the unused hold.
    let fingerprint = pairing::identity_fingerprint(&fx.state.identity.node_id().to_hex());
    let service = open_owner_service(fx.tmp.path(), &fingerprint, &fx.console);
    let store = SqliteStorage::open(fx.tmp.path().join("calls.sqlite").to_str().unwrap())
        .await
        .unwrap();
    fx.state = Arc::new(AppState {
        pairing: Some(service.clone()),
        storage: Arc::new(EncryptedStorage::new(store, &[7; 32])),
        ..(*fx.state).clone()
    });
    fx.service = service;
    konsensus_api::calls::recover(fx.state.storage.as_ref())
        .await
        .unwrap();
    konsensus_api::calls::maintain_calls(&fx.state, chrono::Utc::now().timestamp_millis() as u64)
        .await
        .unwrap();
    assert_eq!(fx.used(), 8_000);
    assert!(
        fx.service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .unwrap()
            .closed
    );
}

#[tokio::test]
async fn failed_offer_cannot_retry_with_a_closed_reservation() {
    let (fx, token) = prepared().await;
    fx.wallet.set(FAILED);
    assert_ne!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
    assert_eq!(fx.used(), 0);
    assert!(
        fx.service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .unwrap()
            .closed
    );
    fx.wallet.set(SETTLE);
    // Call-row cleanup must not make a permanently closed hold reusable.
    fx.state.storage.call_delete(&fx.peer, CALL).await.unwrap();
    let attempts = fx.wallet.money();
    let (status, body) = send(&fx, &token, 400, 7_000, 0).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(body["reason"], "call_reservation_closed");
    assert_eq!(fx.wallet.money(), attempts);
    assert_eq!(fx.used(), 0);
}

#[tokio::test]
async fn expired_offer_cannot_dispatch_after_journal_wait() {
    for release_hold in [false, true] {
        let (mut fx, token) = prepared().await;
        let store = Arc::new(common::MemStorage::new());
        let gate = Arc::new(common::PeerWriteGate::default());
        *store.call_offer_dispatch_gate.lock().unwrap() = Some(gate.clone());
        let peer = fx.peer;
        let transport = ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                let bolt11 = create_test_bolt11(amount);
                let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
                Some(konsensus_api::state::InvoiceResponseData {
                    payment_hash: invoice.payment_hash().to_string(),
                    recipient: peer,
                    bolt11,
                })
            });
        fx.state.peer_ln_pubkeys.lock().await.remove(&peer);
        fx.state = Arc::new(AppState {
            storage: store,
            transport: Arc::new(transport),
            ..(*fx.state).clone()
        });
        let expire = async {
            if tokio::time::timeout(std::time::Duration::from_secs(5), gate.entered.notified())
                .await
                .is_err()
            {
                return false;
            }
            let deadline = fx
                .state
                .storage
                .call_get(&fx.peer, CALL)
                .await
                .unwrap()
                .unwrap()
                .deadline_ms;
            if release_hold {
                konsensus_api::calls::maintain_calls(&fx.state, deadline + 1)
                    .await
                    .unwrap();
            } else {
                konsensus_api::calls::expire_calls(fx.state.storage.as_ref(), deadline + 1)
                    .await
                    .unwrap();
            }
            gate.release.notify_one();
            true
        };
        let ((status, body), reached) = tokio::join!(send(&fx, &token, 400, 7000, 0), expire);
        assert!(
            reached,
            "offer never reached dispatch journal: {status} {body}"
        );
        assert_ne!(status, StatusCode::OK, "{body}");
        assert_eq!(fx.wallet.money(), 0);
        assert_eq!(fx.used(), 0);
        assert!(
            fx.service
                .call_spend_status(&fx.peer.to_hex(), CALL)
                .unwrap()
                .closed
        );
    }
}

#[tokio::test]
async fn slow_liquidity_query_does_not_block_another_calls_transitions() {
    use konsensus_core::payloads::call as rules;
    let (fx, token) = prepared().await;
    fx.wallet.pause_capacity.store(true, Ordering::SeqCst);
    let peer = NodeId::from_bytes([8; 32]);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let entry = rules::receive(None, 400, None, now).unwrap();
    let entry = rules::commit(
        rules::reserve(Some(entry), 401, "answer", "hash", now).unwrap(),
        "answer",
        now,
    );
    fx.state
        .storage
        .call_put(&peer, CALL, &entry)
        .await
        .unwrap();
    let accept_block = async {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fx.wallet.capacity_entered.notified(),
        )
        .await
        .unwrap();
        let plaintext = json!({"call_id": CALL, "seq": 0}).to_string();
        let accepted = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            konsensus_api::calls::admit_incoming(
                fx.state.storage.as_ref(),
                fx.state.identity.node_id(),
                &peer,
                404,
                Some(&plaintext),
            ),
        )
        .await;
        fx.wallet.capacity_resume.notify_one();
        accepted
            .expect("liquidity RPC blocked unrelated call transitions")
            .unwrap();
    };
    let ((status, body), ()) = tokio::join!(send(&fx, &token, 400, 7000, 0), accept_block);
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(fx
        .state
        .storage
        .call_get(&peer, CALL)
        .await
        .unwrap()
        .unwrap()
        .media_admitted(now));
}
