use super::*;
use konsensus_core::payloads::call::{HangupReason, Phase};
use konsensus_storage::{EncryptedStorage, SqliteStorage};

const CALL: &str = "11111111222243338444555555555555";

fn invoice_payee() -> String {
    create_test_bolt11(1_000)
        .parse::<lightning_invoice::Bolt11Invoice>()
        .unwrap()
        .recover_payee_pub_key()
        .to_string()
}

async fn send(fx: &Fx, token: &str, kind: u16, price: u64, seq: u32) -> (StatusCode, Value) {
    send_id(fx, token, kind, price, seq, CALL).await
}

async fn send_id(fx: &Fx, token: &str, kind: u16, price: u64, seq: u32, call_id: &str) -> (StatusCode, Value) {
    send_operation(fx, token, kind, price, seq, call_id, &uuid::Uuid::new_v4().to_string()).await
}

async fn send_operation(fx: &Fx, token: &str, kind: u16, price: u64, seq: u32, call_id: &str, operation_id: &str) -> (StatusCode, Value) {
    let body = if kind == 400 {
        json!({"v": 1, "call_id": call_id, "sdp": "offer", "media": "audio"})
    } else {
        json!({"v": 1, "call_id": call_id, "seq": seq})
    };
    send_request(fx, token, price, json!({
        "operation_id": operation_id, "recipient": fx.peer.to_hex(),
        "kind": kind, "plaintext": body.to_string(), "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })).await
}

async fn send_request(fx: &Fx, token: &str, price: u64, request: Value) -> (StatusCode, Value) {
    let prices = fx.state.peer_prices.clone();
    let peer = fx.peer;
    let quotes = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            prices.update_kind_price(peer, 400, 1_000, 850_000).await;
            prices.update_kind_price(peer, 404, price, 850_000).await;
            prices.update_kind_price(peer, 403, 0, 850_000).await;
        }
    });
    let result = fx.call("POST", "/api/v1/messages/compose", Some(request), Some(token)).await;
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
        .insert(fx.peer, invoice_payee());
    // Exercise the production encrypted call storage as well as the pairing file.
    let store = SqliteStorage::open(fx.tmp.path().join("calls.sqlite").to_str().unwrap())
        .await
        .unwrap();
    let peer = fx.peer;
    fx.state = Arc::new(AppState {
        storage: Arc::new(EncryptedStorage::new(store, &[7; 32])),
        transport: Arc::new(ConnectedStubTransport::new(
            vec![fx.peer],
            fx.state.invoice_requests.clone(),
        ).with_invoice_responder(move |_, amount| {
            let bolt11 = create_test_bolt11(amount);
            let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
            Some(konsensus_api::state::InvoiceResponseData {
                payment_hash: invoice.payment_hash().to_string(), recipient: peer, bolt11,
            })
        })),
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
        assert_eq!((hold.reserved_msat, hold.spent_msat), (420_000, 0));
        assert_eq!(fx.used(), 421_000); // offer plus the complete block hold
        answer(&fx).await;
        let (status, body) = send(&fx, &token, 404, 7_000, 0).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        // This end-path case has received its block ACK; delayed grants are
        // exercised separately and must retain their still-usable reservation.
        let block_id = konsensus_core::MessageId::from_hex(body["message_id"].as_str().unwrap()).unwrap();
        fx.state.storage.remove_pending_delivery(&block_id, &fx.peer).await.unwrap();
        let view = fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .unwrap();
        assert_eq!((view.spent_msat, view.remaining_msat), (7_000, 413_000));
        assert_eq!(fx.used(), 421_000);
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
        assert_eq!(calls[0]["reservation"]["max_call_minutes"], 60);
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
            if reason == HangupReason::Unpaid {
                // A stale Unpaid notice cannot revoke a paid media interval.
                let now = chrono::Utc::now().timestamp_millis() as u64;
                let mut entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
                entry.deadline_ms = now - 1;
                entry.paid_until_ms = Some(now - konsensus_core::payloads::call::CALL_BLOCK_GRACE_MS - 1);
                fx.state.storage.call_put(&fx.peer, CALL, &entry).await.unwrap();
            }
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
            fx.wallet.call_capacity.store(419_999, Ordering::SeqCst);
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
    let entry = rules::receive(None, 400, None, now).unwrap().device_fetched(now).unwrap();
    let entry = rules::commit(
        rules::reserve(Some(entry), 401, "answer", "hash", now).unwrap(),
        "answer",
        now,
    ).unwrap();
    fx.state
        .storage
        .call_put(&peer, CALL, &entry)
        .await
        .unwrap();
    fx.state.storage.record_call_block_invoice(&peer, CALL, 0, &[1; 32],
        entry.deadline_ms + rules::CALL_BLOCK_RESUME_MS).await.unwrap();
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
            async {
                konsensus_api::calls::prepare_incoming_block(
                    fx.state.storage.as_ref(), &peer, Some(&plaintext), &[1; 32],
                ).await.unwrap().commit().await
            },
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

#[tokio::test]
async fn harmless_block_refusal_preserves_live_call_and_hold() {
    let (fx, token) = prepared().await;
    assert_eq!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
    answer(&fx).await;
    let (status, body) = fx.call("POST", "/api/v1/messages/compose", Some(json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(),
        "kind": 404, "plaintext": json!({"v":1,"call_id":CALL,"seq":0}).to_string(),
        "max_total_msat": 1, "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })), Some(&token)).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap().phase, Phase::Live);
    assert!(!fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap().closed);
    assert_eq!(send(&fx, &token, 404, 7_000, 0).await.0, StatusCode::OK);
}

#[tokio::test]
async fn default_duration_cap_ends_at_paid_boundary_and_releases_hold() {
    let (fx, token) = prepared().await;
    assert_eq!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
    let status = serde_json::to_value(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap()).unwrap();
    assert_eq!(status["max_call_minutes"], 60);
    assert_eq!(status["reserved_msat"], 420_000);
    answer(&fx).await;
    assert_eq!(send(&fx, &token, 404, 7_000, 0).await.0, StatusCode::OK);
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let mut entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    entry.next_block_seq = 60;
    entry.paid_until_ms = Some(now + 10_000);
    entry.deadline_ms = now + 20_000;
    fx.state.storage.call_put(&fx.peer, CALL, &entry).await.unwrap();
    let (status, body) = send(&fx, &token, 404, 7_000, 60).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(body["reason"], "call_duration_cap");
    assert_eq!(fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap().phase, Phase::Live);
    konsensus_api::calls::maintain_calls(&fx.state, now + 10_000).await.unwrap();
    let ended = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert_eq!(ended.end_reason.unwrap().as_str(), "duration_cap");
    assert!(!ended.media_admitted(now + 10_000));
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap().closed);
    assert_eq!(fx.used(), 8_000);
}

#[tokio::test]
async fn broken_hold_cleanup_preserves_paid_response_and_other_expiry_notifications() {
    use konsensus_core::payloads::call as rules;
    let (mut fx, token) = prepared().await;
    let store = Arc::new(common::MemStorage::new());
    fx.state = Arc::new(AppState { storage: store.clone(), ..(*fx.state).clone() });
    assert_eq!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
    *store.fail_call_get_for.lock().unwrap() = Some(CALL.into());
    let other = "aaaaaaaa222243338444555555555555";
    let (status, body) = send_id(&fx, &token, 400, 7_000, 0, other).await;
    assert_eq!(status, StatusCode::OK, "paid response must survive cleanup failure: {body}");
    assert_eq!(fx.wallet.left(), 2_000);
    // The other hold must still release, even when the first hold cannot be read.
    let mut ended = fx.state.storage.call_get(&fx.peer, other).await.unwrap().unwrap();
    ended.phase = Phase::Ended;
    fx.state.storage.call_put(&fx.peer, other, &ended).await.unwrap();
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let notification_id = "bbbbbbbb222243338444555555555555";
    let ringing = rules::receive(None, 400, None, now - 31_000).unwrap().device_fetched(now - 31_000).unwrap();
    let pending = rules::reserve(Some(ringing), 401, "answer", "hash", now - 31_000).unwrap();
    let live = rules::commit(pending, "answer", now - 31_000).unwrap();
    fx.state.storage.call_put(&fx.peer, notification_id, &live).await.unwrap();
    konsensus_api::calls::maintain_calls(&fx.state, now).await.unwrap();
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), other).unwrap().closed);
    assert!(!fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap().closed);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let entry = fx.state.storage.call_get(&fx.peer, notification_id).await.unwrap().unwrap();
            if entry.unpaid_notice_used { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("broken hold stalled the expiry notification");
}

#[tokio::test]
async fn configured_duration_sizes_and_pins_the_hold() {
    for (minutes, reserved) in [(1, 7_000), (240, 1_680_000)] {
    let (mut fx, token) = prepared().await;
    fx.state = Arc::new(AppState { max_call_minutes: minutes, ..(*fx.state).clone() });
    assert_eq!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
    let hold = fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap();
    assert_eq!((hold.max_call_minutes, hold.reserved_msat), (minutes, reserved));
    answer(&fx).await;
    assert_eq!(send(&fx, &token, 404, 7_000, 0).await.0, StatusCode::OK);
    fx.state = Arc::new(AppState { max_call_minutes: 240, ..(*fx.state).clone() });
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let mut entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    entry.next_block_seq = u32::from(minutes);
    entry.paid_until_ms = Some(now + 10_000);
    entry.deadline_ms = now + 20_000;
    fx.state.storage.call_put(&fx.peer, CALL, &entry).await.unwrap();
    let (status, body) = send(&fx, &token, 404, 7_000, u32::from(minutes)).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(body["reason"], "call_duration_cap");
    konsensus_api::calls::maintain_calls(&fx.state, now + 10_000).await.unwrap();
    assert_eq!(fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap().end_reason.unwrap().as_str(), "duration_cap");
}
}

#[tokio::test]
async fn recovered_failed_block_ends_the_call_and_releases_the_hold() {
    for close_before_failure in [false, true] {
    let (mut fx, token) = prepared().await;
    assert_eq!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
    answer(&fx).await;
    let peer = fx.peer;
    let transport = ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            let bolt11 = create_test_bolt11(amount);
            let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
            Some(konsensus_api::state::InvoiceResponseData {
                payment_hash: invoice.payment_hash().to_string(), recipient: peer, bolt11,
            })
        });
    fx.state.peer_ln_pubkeys.lock().await.remove(&peer);
    fx.state = Arc::new(AppState { transport: Arc::new(transport), ..(*fx.state).clone() });
    fx.wallet.set(UNKNOWN);
    let (status, body) = send(&fx, &token, 404, 7_000, 0).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.state.storage.call_get(&peer, CALL).await.unwrap().unwrap().phase, Phase::Live);
    if close_before_failure {
        let hangup = json!({"v":1,"call_id":CALL,"reason":"hangup"}).to_string();
        konsensus_api::calls::admit_incoming(fx.state.storage.as_ref(), fx.state.identity.node_id(), &peer, 403, Some(&hangup)).await.unwrap();
        konsensus_api::calls::reconcile_call_spend(&fx.state, chrono::Utc::now().timestamp_millis() as u64).await.unwrap();
    }
    fx.wallet.set(FAILED);
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    konsensus_api::calls::maintain_calls(&fx.state, chrono::Utc::now().timestamp_millis() as u64).await.unwrap();
    assert_eq!(fx.state.storage.call_get(&peer, CALL).await.unwrap().unwrap().phase, Phase::Ended);
    assert!(fx.service.call_spend_status(&peer.to_hex(), CALL).unwrap().closed);
    assert_eq!(fx.used(), 1_000);
    let budget = fx.service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert_eq!(budget.breaker_status(chrono::Utc::now().timestamp()).consecutive_failures, 1);
    }
}

#[tokio::test]
async fn confirmed_failed_first_block_counts_as_one_payment_failure() {
    let (fx, token) = prepared().await;
    assert_eq!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
    answer(&fx).await;
    fx.wallet.set(FAILED);
    assert_ne!(send(&fx, &token, 404, 7_000, 0).await.0, StatusCode::OK);
    let budget = fx.service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert_eq!(budget.breaker_status(chrono::Utc::now().timestamp()).consecutive_failures, 1);
    assert_eq!(fx.used(), 1_000);
}


#[tokio::test]
async fn recovered_failure_cannot_repay_when_call_cleanup_write_fails() {
    let (mut fx, token) = prepared().await;
    let store = Arc::new(common::MemStorage::new());
    fx.state = Arc::new(AppState { storage: store.clone(), ..(*fx.state).clone() });
    assert_eq!(send(&fx, &token, 400, 7_000, 0).await.0, StatusCode::OK);
    answer(&fx).await;
    let peer = fx.peer;
    let transport = ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            let bolt11 = create_test_bolt11(amount);
            let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
            Some(konsensus_api::state::InvoiceResponseData {
                payment_hash: invoice.payment_hash().to_string(), recipient: peer, bolt11,
            })
        });
    fx.state.peer_ln_pubkeys.lock().await.remove(&peer);
    fx.state = Arc::new(AppState { transport: Arc::new(transport), ..(*fx.state).clone() });
    fx.wallet.set(UNKNOWN);
    let operation_id = uuid::Uuid::new_v4().to_string();
    assert_ne!(send_operation(&fx, &token, 404, 7_000, 0, CALL, &operation_id).await.0, StatusCode::OK);
    fx.wallet.set(FAILED);
    *store.fail_call_put_for.lock().unwrap() = Some(CALL.into());
    let attempts = fx.wallet.money();
    assert_ne!(send_operation(&fx, &token, 404, 7_000, 0, CALL, &operation_id).await.0, StatusCode::OK);
    assert_eq!(fx.wallet.money(), attempts, "cleanup failure must never authorize another payment");
    *store.fail_call_put_for.lock().unwrap() = None;
    konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
    konsensus_api::calls::maintain_calls(&fx.state, chrono::Utc::now().timestamp_millis() as u64).await.unwrap();
    assert_eq!(fx.state.storage.call_get(&peer, CALL).await.unwrap().unwrap().phase, Phase::Ended);
    assert!(fx.service.call_spend_status(&peer.to_hex(), CALL).unwrap().closed);
}

#[path = "calls_consent.rs"]
mod consent;
#[path = "calls_settlement.rs"]
mod settlement;

/// Codex FAIL on #472: a `call_not_reachable` refusal ends the caller's ringing
/// call so its unused whole-call hold is released at once, not at the ringing
/// deadline. The offer itself stays paid (unchanged admission rule).
#[tokio::test]
async fn unreachable_invite_ends_the_call_and_releases_its_hold() {
    let (fx, token) = prepared().await;
    let (status, body) = send(&fx, &token, 400, 7_000, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.used(), 421_000);
    let offer = konsensus_core::MessageId::from_hex(body["message_id"].as_str().unwrap()).unwrap();
    let ringing = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(ringing.phase, Phase::Ringing);
    assert!(konsensus_api::calls::end_unreachable_invite(
        fx.state.storage.as_ref(), fx.state.identity.node_id(), &fx.peer, &offer,
    ).await.unwrap());
    let ended = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!((ended.phase, ended.end_reason), (Phase::Ended, Some(HangupReason::Timeout)));
    konsensus_api::calls::reconcile_call_spend(&fx.state, chrono::Utc::now().timestamp_millis() as u64)
        .await
        .unwrap();
    assert_eq!(fx.used(), 1_000, "only the paid offer remains");
    // Another peer, or a second refusal, cannot end anything else.
    assert!(!konsensus_api::calls::end_unreachable_invite(
        fx.state.storage.as_ref(), fx.state.identity.node_id(), &fx.peer, &offer,
    ).await.unwrap());
}


/// Codex FAIL on #472 (round 2): a pending cancellation must not keep an
/// unreachable call ringing with its hold.
#[tokio::test]
async fn unreachable_invite_ends_the_call_even_with_a_pending_cancellation() {
    let (fx, token) = prepared().await;
    let (status, body) = send(&fx, &token, 400, 7_000, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let offer = konsensus_core::MessageId::from_hex(body["message_id"].as_str().unwrap()).unwrap();
    let mut ringing = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    ringing.pending = Some(konsensus_core::payloads::call::Pending {
        operation_id: "cancel".into(), kind: konsensus_core::kind::KIND_CALL_HANGUP, request_hash: "h".into(),
    });
    fx.state.storage.call_put(&fx.peer, CALL, &ringing).await.unwrap();
    assert!(konsensus_api::calls::end_unreachable_invite(
        fx.state.storage.as_ref(), fx.state.identity.node_id(), &fx.peer, &offer,
    ).await.unwrap());
    let ended = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(ended.phase, Phase::Ended);
    assert!(ended.pending.is_some(), "the cancellation's own mark is kept for its commit/release");
}

/// A stale refusal for an old offer never ends a newer call: the offer must be
/// recent enough to be the one now ringing.
#[tokio::test]
async fn stale_unreachable_refusal_cannot_end_a_newer_call() {
    let (fx, token) = prepared().await;
    let (status, body) = send(&fx, &token, 400, 7_000, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let offer = konsensus_core::MessageId::from_hex(body["message_id"].as_str().unwrap()).unwrap();
    let db = sqlx::SqlitePool::connect(&format!("sqlite://{}", fx.tmp.path().join("calls.sqlite").display()))
        .await
        .unwrap();
    sqlx::query("UPDATE outbox_operations SET created_at = 0 WHERE message_id = ?")
        .bind(offer.to_hex()).execute(&db).await.unwrap();
    assert!(!konsensus_api::calls::end_unreachable_invite(
        fx.state.storage.as_ref(), fx.state.identity.node_id(), &fx.peer, &offer,
    ).await.unwrap());
    assert_eq!(fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap().phase, Phase::Ringing);
}
