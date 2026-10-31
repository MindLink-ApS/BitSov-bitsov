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
    send_priced(fx, token, 1_000, price, request).await
}

async fn send_priced(fx: &Fx, token: &str, offer: u64, price: u64, request: Value) -> (StatusCode, Value) {
    let prices = fx.state.peer_prices.clone();
    let peer = fx.peer;
    let quotes = tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            prices.update_kind_price(peer, 400, offer, 850_000).await;
            prices.update_kind_price(peer, 404, price, 850_000).await;
            prices.update_kind_price(peer, 403, 0, 850_000).await;
        }
    });
    let result = fx.call("POST", "/api/v1/messages/compose", Some(request), Some(token)).await;
    quotes.abort();
    result
}

async fn prepared() -> (Fx, String) {
    let fx = call_ready(fixture().await).await;
    let mut terms = GrantTerms::new(5_000_000);
    terms.breakers.max_msat_per_10_minutes = 5_000_000;
    let token = fx.grant(None, terms).await;
    (fx, token)
}

/// A fixture with a callable contact and call storage; grants are left as they are.
async fn call_ready(mut fx: Fx) -> Fx {
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
    fx
}

/// A paired app under an owner-approved grant, whose per-payment cap is the
/// 6 sat messaging cap, calling a contact that charges 10 sat per block.
async fn approved_call(minutes: u16) -> (Fx, String) {
    approved_call_capped(false, 20_000, minutes).await
}

/// [`approved_call`] with the owner's requested per-payment cap, or with a
/// relation envelope whose per-act maximum is `cap`.
async fn approved_call_capped(relation: bool, cap: u64, minutes: u16) -> (Fx, String) {
    let fx = call_ready(fixture().await).await;
    let (mut fx, token) = super::messaging_cap::messaging_grant(fx, relation, cap).await;
    fx.state = Arc::new(AppState { max_call_minutes: minutes, ..(*fx.state).clone() });
    (fx, token)
}

/// A call signal under the node's ordinary routing ceiling (no explicit fee limit).
fn ordinary(fx: &Fx, kind: u16, seq: u32, consent: Option<u64>) -> Value {
    let plaintext = if kind == 400 {
        json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"})
    } else {
        json!({"v": 1, "call_id": CALL, "seq": seq})
    };
    json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(),
        "kind": kind, "plaintext": plaintext.to_string(), "max_routing_fee_msat": null,
        "max_block_msat": consent, "wait_ack_ms": 0,
    })
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
                "total"
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
    ).unwrap();
    fx.state
        .storage
        .call_put(&peer, CALL, &entry)
        .await
        .unwrap();
    fx.state.storage.record_call_block_invoice(&peer, CALL, 0, &[1; 32],
        entry.deadline_ms + rules::CALL_BLOCK_RESUME_MS).await.unwrap();
    let accept_block = async {
        // The offer first asks whether the contact is a direct channel peer;
        // release that query, then hold the call's own liquidity query.
        for query in 0..2 {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                fx.wallet.capacity_entered.notified(),
            )
            .await
            .unwrap();
            if query == 0 {
                fx.wallet.capacity_resume.notify_one();
            }
        }
        let plaintext = json!({"call_id": CALL, "seq": 0}).to_string();
        let accepted = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            async {
                konsensus_api::calls::prepare_incoming_block(
                    fx.state.storage.as_ref(), &peer, Some(&plaintext), &[1; 32],
                ).await.unwrap().commit(&konsensus_core::MessageId::from_bytes([0; 32])).await
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
    let ringing = rules::receive(None, 400, None, now - 31_000).unwrap();
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

#[tokio::test]
async fn approved_messaging_grant_pays_a_call_within_its_pinned_block_ceiling() {
    let (fx, token) = approved_call(10).await;
    let (status, body) = send_request(&fx, &token, 10_000, ordinary(&fx, 400, 0, Some(10_000))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hold = fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap();
    // 10 sat per block plus the 5 sat routing ceiling, for ten minutes.
    assert_eq!((hold.per_block_msat, hold.per_block_fee_msat), (10_000, 5_000));
    assert_eq!(hold.reserved_msat, 150_000);
    answer(&fx).await;
    let (status, body) = send_request(&fx, &token, 10_000, ordinary(&fx, 404, 0, None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hold = fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap();
    assert_eq!(hold.spent_msat, 10_000);
    assert_eq!(fx.wallet.money(), 2);
    assert_eq!(fx.wallet.left(), 11_000);
    // Messaging under the same grant keeps the 6 sat per-payment cap.
    fx.state.peer_prices.update_kind_price(fx.peer, 100, 7_000, 850_000).await;
    let (status, body) = fx.compose(&token).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert_eq!(fx.wallet.money(), 2);
    let (status, body) = fx.call("GET", "/api/v1/pair/grant", None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["grant"]["per_call_max_msat"], 6_000);
}

#[tokio::test]
async fn approved_messaging_grant_refuses_calls_above_their_ceiling_or_budget() {
    // Above the caller's consented block price: no hold, nothing paid.
    let (fx, token) = approved_call(10).await;
    let (status, body) = send_request(&fx, &token, 10_000, ordinary(&fx, 400, 0, Some(9_999))).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "call_price_above_consent");
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none());
    assert_eq!((fx.wallet.money(), fx.used()), (0, 0));
    // An offer whose all-in exceeds the call's pinned per-block ceiling.
    let (fx, token) = approved_call(10).await;
    let (status, body) =
        send_priced(&fx, &token, 11_000, 10_000, ordinary(&fx, 400, 0, None)).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert_eq!(fx.wallet.money(), 0);
    // A hold larger than the grant's remaining budget (60 minutes x 15 sat).
    let (fx, token) = approved_call(60).await;
    let (status, body) = send_request(&fx, &token, 10_000, ordinary(&fx, 400, 0, None)).await;
    assert_budget_exceeded(status, &body, "total");
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none());
    assert_eq!((fx.wallet.money(), fx.used()), (0, 0));
}

/// The grant's recorded usage for `fx.peer`, msat.
fn recipient_used(fx: &Fx) -> u64 {
    fx.service.reload_from_disk().unwrap().grants[0]
        .budget
        .as_ref()
        .and_then(|b| b.used_by_recipient.get(&fx.peer.to_hex()).copied())
        .unwrap_or(0)
}

/// Answer the next price queries with these prices at once. A query within
/// the throttle window reads the latest answer, which may be the last send's.
async fn reprice(fx: &Fx, offer: u64, block: u64) {
    fx.state.peer_prices.update_kind_price(fx.peer, 400, offer, 850_000).await;
    fx.state.peer_prices.update_kind_price(fx.peer, 404, block, 850_000).await;
}

/// A call with a 1 sat offer and a 10 sat block, under a zero routing fee.
async fn ten_sat_call(fx: &Fx, token: &str) -> (StatusCode, Value) {
    send(fx, token, 400, 10_000, 0).await
}

#[tokio::test]
async fn owner_chosen_per_payment_limit_refuses_a_larger_call_block_before_anything() {
    // The owner approved 1 sat per payment: a 10 sat block is above it.
    let (fx, token) = approved_call_capped(false, 1_000, 10).await;
    let (status, body) = ten_sat_call(&fx, &token).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none());
    assert_eq!((fx.wallet.money(), fx.used()), (0, 0));
    let (status, body) = fx.call("GET", "/api/v1/pair/grant", None, Some(&token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["grant"]["per_call_max_msat"], 1_000);
    // An owner who asked for 6 sat or more stores the messaging cap, which is
    // read as the imposed clamp: the same call is paid.
    let (fx, token) = approved_call_capped(false, 6_000, 10).await;
    let (status, body) = ten_sat_call(&fx, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hold = fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap();
    assert_eq!((hold.per_block_msat, hold.per_block_fee_msat, hold.reserved_msat), (10_000, 0, 100_000));
    assert_eq!(fx.wallet.money(), 1);
}

#[tokio::test]
async fn console_per_call_limit_binds_a_calls_block_ceiling() {
    let console = |fx: Fx| async move {
        let mut terms = GrantTerms::new(1_000_000).per_call(8_000);
        terms.breakers.max_msat_per_10_minutes = 5_000_000;
        let token = fx.grant(None, terms).await;
        (fx, token)
    };
    let (fx, token) = console(call_ready(fixture().await).await).await;
    let (status, body) = ten_sat_call(&fx, &token).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none());
    assert_eq!((fx.wallet.money(), fx.used()), (0, 0));
    // An 8 sat block fits the owner's 8 sat limit.
    reprice(&fx, 1_000, 8_000).await;
    let (status, body) = send(&fx, &token, 400, 8_000, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hold = fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap();
    assert_eq!((hold.per_block_msat, hold.reserved_msat), (8_000, 480_000));
    assert_eq!((fx.wallet.money(), fx.used()), (1, 481_000));
}

#[tokio::test]
async fn relation_envelope_per_act_maximum_still_bounds_each_call_payment() {
    let (fx, token) = approved_call_capped(true, 8_000, 10).await;
    let (status, body) = ten_sat_call(&fx, &token).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none());
    assert_eq!((fx.wallet.money(), fx.used()), (0, 0));
    // An envelope whose per-act maximum covers the block pays the call.
    let (fx, token) = approved_call_capped(true, 10_000, 10).await;
    let (status, body) = ten_sat_call(&fx, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap().reserved_msat, 100_000);
    assert_eq!(fx.wallet.money(), 1);
}

#[tokio::test]
async fn offer_refused_against_its_ceiling_leaves_no_hold_and_the_next_call_pays() {
    let (fx, token) = approved_call(10).await;
    // An 11 sat offer under a 10 sat block ceiling (zero routing fee).
    let request = json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(), "kind": 400,
        "plaintext": json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    });
    let (status, body) = send_priced(&fx, &token, 11_000, 10_000, request).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!((fx.used(), recipient_used(&fx)), (0, 0), "the hold was released");
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none_or(|hold| hold.closed));
    let budget = fx.service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert!(budget.pending.is_empty(), "{:?}", budget.pending);
    assert!(budget.call_reservations.values().all(|call| call.closed));
    // A legitimate call afterwards is paid in full.
    const NEXT: &str = "22222222333344448555666666666666";
    reprice(&fx, 1_000, 10_000).await;
    let (status, body) = send_id(&fx, &token, 400, 10_000, 0, NEXT).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hold = fx.service.call_spend_status(&fx.peer.to_hex(), NEXT).unwrap();
    assert!(!hold.closed);
    assert_eq!(hold.reserved_msat, 100_000);
    assert_eq!((fx.wallet.money(), fx.used(), recipient_used(&fx)), (1, 101_000, 101_000));
}

#[tokio::test]
async fn a_second_offer_for_the_same_call_is_refused_before_payment() {
    let (fx, token) = prepared().await;
    let (status, body) = send(&fx, &token, 400, 7_000, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Another operation offering the same call is refused by the call's own
    // state before any debit, so no second offer can be paid under its hold.
    let (status, body) = send(&fx, &token, 400, 7_000, 0).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "call_id_used", "{body}");
    assert_eq!(fx.wallet.money(), 1, "one offer payment: {body}");
    let budget = fx.service.reload_from_disk().unwrap().grants[0].budget.clone().unwrap();
    assert_eq!(budget.call_reservations.len(), 1, "one hold");
    assert_eq!(fx.used(), 421_000, "one offer plus one hold");
    assert_eq!(budget.breaker_status(chrono::Utc::now().timestamp()).payments_last_hour, 2);
}

#[tokio::test]
async fn direct_offer_whose_block_cannot_go_direct_is_refused_before_payment() {
    let (fx, token) = approved_call(10).await;
    // The direct channel carries the 1 sat offer, not a 10 sat block after it.
    *fx.wallet.channel_peer.lock().unwrap() = Some(invoice_payee());
    fx.wallet.call_capacity.store(1_000, Ordering::SeqCst);
    let (status, body) = send_request(&fx, &token, 10_000, ordinary(&fx, 400, 0, None)).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "call_block_not_direct", "{body}");
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none());
    assert_eq!((fx.wallet.money(), fx.used()), (0, 0));
    assert!(fx.wallet.fee_limits.lock().unwrap().is_empty());
    // A channel that carries the whole call: offer and blocks at a zero fee.
    fx.wallet.call_capacity.store(1_000_000, Ordering::SeqCst);
    let (status, body) = send_request(&fx, &token, 10_000, ordinary(&fx, 400, 0, None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let hold = fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap();
    assert_eq!((hold.per_block_msat, hold.per_block_fee_msat), (10_000, 0));
    answer(&fx).await;
    let (status, body) = send_request(&fx, &token, 10_000, ordinary(&fx, 404, 0, None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.wallet.money(), 2);
    let limits = fx.wallet.fee_limits.lock().unwrap().clone();
    assert!(!limits.is_empty() && limits.iter().all(|limit| *limit == 0), "{limits:?}");
}
