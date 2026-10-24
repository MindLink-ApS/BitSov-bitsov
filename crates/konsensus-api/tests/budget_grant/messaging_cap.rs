use super::*;
use konsensus_api::pairing::approval::ApprovalRequest;
use konsensus_api::pairing::device;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

async fn messaging_fixture(relation: bool, requested_cap: u64) -> (Fx, String) {
    let mut fx = fixture().await;
    let root = konsensus_core::OwnerApprovalKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "", &[9; 32],
    ).unwrap();
    let fingerprint = pairing::identity_fingerprint(&fx.state.identity.node_id().to_hex());
    fx.service = Arc::new(
        PairingService::open(fx.tmp.path(), fingerprint.clone(), true)
            .unwrap()
            .with_owner_approval_key(root.verifying_key())
            .with_owner_console(Box::new(fx.console.clone()))
            .without_stdout_code(),
    );
    fx.state = Arc::new(AppState {
        pairing: Some(fx.service.clone()),
        ..(*fx.state).clone()
    });
    let owner = if relation {
        fx.service.snapshot().clients[0].clone()
    } else {
        fx.service
            .create_ticket_remote_pairing(
                "owner",
                &hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()),
                &[2; 32],
            )
            .unwrap()
    };
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let sign = |msg: &str| hex::encode(key.sign(&rng, msg.as_bytes()).unwrap().as_ref());
    let op = fx
        .service
        .request_device_key(
            &owner.client_id,
            &public,
            "device",
            &sign(&device::registration_message(
                &fingerprint,
                &owner.client_id,
                &public,
            )),
        )
        .unwrap();
    let attestation = root.sign(
        device::owner_approval_message(&fingerprint, &owner.client_pubkey, owner.epoch, &public)
            .as_bytes(),
    );
    fx.service
        .approve_device_key(
            &op.op_id,
            &fx.console.owner_code(&op.op_id),
            &hex::encode(attestation.to_bytes()),
        )
        .unwrap();
    if relation {
        let intent = pairing::RelationIntent {
            device_key_id: op.key_id,
            peer: fx.peer.to_hex(),
            level: 1,
            budget_msat: 200_000,
            per_act_max_msat: requested_cap,
            window_secs: 3600,
            issued_at: chrono::Utc::now().timestamp(),
            nonce: "ab".repeat(16),
        };
        fx.service
            .apply_relation_intent(
                &fx.client_id,
                1,
                &intent,
                &sign(&device::intent_message(
                    &fingerprint,
                    &fx.client_id,
                    &intent,
                )),
            )
            .unwrap();
    } else {
        let approval = fx
            .service
            .request_owner_approval(
                &fx.client_id,
                1,
                ApprovalRequest::SpendGrant {
                    budget_msat: 200_000,
                    per_call_max_msat: requested_cap,
                    window_secs: 3600,
                    recipient: None,
                },
            )
            .unwrap();
        assert_eq!(approval.act_caps.as_ref().unwrap().message_all_in_msat, requested_cap.min(6_000));
        assert_eq!(approval.act_caps.as_ref().unwrap().room_member_all_in_msat, requested_cap.min(6_000));
        fx.service
            .approve_owner_request(
                &owner.client_id,
                owner.epoch,
                &approval.operation.op_id,
                &op.key_id,
                &sign(&approval.approval_message),
            )
            .unwrap();
    }
    let token = fx.token().await;
    (fx, token)
}

#[tokio::test]
async fn messaging_quotes_above_six_sats_never_pay_and_six_sats_pays() {
    // Isolate tracing's callsite cache from the parallel integration tests.
    const CHILD: &str = "BITSOV_MESSAGING_CAP_LOG_TEST";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "messaging_cap::messaging_quotes_above_six_sats_never_pay_and_six_sats_pays",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use tracing::instrument::WithSubscriber;
    let log = tempfile::NamedTempFile::new().unwrap();
    let writer = log.reopen().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.try_clone().unwrap())
        .finish();
    async {
    for relation in [true, false] {
        let (fx, token) = messaging_fixture(relation, 20_000).await;
        fx.state.peer_prices.update_kind_price(fx.peer, 100, 7_000, 850_000).await;
        let (status, body) = fx.compose(&token).await;
        assert_budget_exceeded(status, &body, "per_call");
        assert_eq!(body["error"], "This call exceeds the per-call spending limit. Nothing was paid.");
        assert_eq!(fx.wallet.money(), 0);
        assert_eq!(fx.used(), 0);
        fx.state.peer_prices.update_kind_price(fx.peer, 100, 6_000, 850_000).await;
        let (status, body) = fx.compose(&token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(fx.wallet.left(), 6_000);
        assert_eq!(fx.used(), 6_000);
        let (status, body) = fx.call("GET", "/api/v1/pair/grant", None, Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["grant"]["per_call_max_msat"], 6_000);
        assert_eq!(body["grant"]["budget_msat"], 200_000);
        // Reopening verifies the signed receipt and preserves the stored cap.
        let restarted = PairingService::open(fx.tmp.path(),
            pairing::identity_fingerprint(&fx.state.identity.node_id().to_hex()), true).unwrap()
            .with_owner_approval_key(konsensus_core::OwnerApprovalKey::from_mnemonic(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
                "", &[9;32]).unwrap().verifying_key());
        let view = restarted.grant_view_for(&fx.client_id).unwrap();
        assert_eq!(view.per_call_max_msat, 6_000);
        assert_eq!(view.budget_msat, 200_000);
    }
    }.with_subscriber(subscriber).await;
    let captured = std::fs::read_to_string(log.path()).unwrap();
    assert!(
        captured.lines().any(|line| line.contains("INFO")
            && line.contains("grant spend refused")
            && line.contains("reason=\"per_call\"")),
        "{captured}"
    );
}

#[tokio::test]
async fn messaging_grants_cannot_pay_invoices_or_keysend() {
    for relation in [true, false] {
        let (fx, token) = messaging_fixture(relation, 20_000).await;
        let (status, body) = fx.keysend(&token, PEER_LN, 1_000).await;
        assert_budget_exceeded(status, &body, "messaging_grant");
        let (status, body) = fx
            .call(
                "POST",
                "/api/v1/payments/pay",
                Some(json!({"bolt11": create_test_bolt11(1_000)})),
                Some(&token),
            )
            .await;
        assert_budget_exceeded(status, &body, "messaging_grant");
        assert_eq!(fx.wallet.money(), 0);
        assert_eq!(fx.used(), 0);
    }
}

#[tokio::test]
async fn console_grant_caps_messages_but_allows_twenty_sat_payments() {
    let fx = fixture().await;
    let token = fx
        .grant(None, GrantTerms::new(200_000).per_call(20_000))
        .await;
    fx.state
        .peer_prices
        .update_kind_price(fx.peer, 100, 7_000, 850_000)
        .await;
    let (status, body) = fx.compose(&token).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!(fx.used(), 0);
    let (status, body) = fx
        .call("GET", "/api/v1/pair/grant", None, Some(&token))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["grant"]["per_call_max_msat"], 6_000);
    assert_eq!(body["grant"]["payment_per_call_max_msat"], 20_000);
    assert_eq!(body["grant"]["act_caps"]["message_all_in_msat"], 6_000);
    assert_eq!(body["grant"]["act_caps"]["room_member_all_in_msat"], 6_000);
    let (status, body) = fx.keysend(&token, PEER_LN, 20_000).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/payments/pay",
            Some(json!({"bolt11": create_test_bolt11(20_000)})),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.wallet.left(), 40_000);
    assert_eq!(fx.used(), 40_000);
}

#[tokio::test]
async fn messaging_grants_preserve_tighter_approved_limits() {
    for relation in [true, false] {
        let (fx, token) = messaging_fixture(relation, 1_000).await;
        fx.state
            .peer_prices
            .update_kind_price(fx.peer, 100, 2_000, 850_000)
            .await;
        let (status, body) = fx.compose(&token).await;
        assert_budget_exceeded(status, &body, "per_call");
        assert_eq!(fx.wallet.money(), 0);
        fx.state
            .peer_prices
            .update_kind_price(fx.peer, 100, 1_000, 850_000)
            .await;
        let (status, body) = fx.compose(&token).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(fx.wallet.left(), 1_000);
    }
}

#[tokio::test]
async fn console_room_fanout_caps_each_member_and_reserves_one_total() {
    let mut fx = fixture().await;
    let mut members = Vec::new();
    for n in 0..2 {
        let identity = konsensus_core::NodeIdentity::from_mnemonic(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            &format!("room-peer-{n}"),
        )
        .unwrap();
        let peer = *identity.node_id();
        let peer_sm = konsensus_crypto::SessionManager::new(Arc::new(identity));
        fx.state
            .session_manager
            .initiate_session(&peer, &peer_sm.prekey_bundle().await)
            .await
            .unwrap();
        fx.state
            .peer_ln_pubkeys
            .lock()
            .await
            .insert(peer, PEER_LN.into());
        members.push(peer);
    }
    fx.state = Arc::new(AppState {
        transport: Arc::new(ConnectedStubTransport::new(
            members.clone(),
            fx.state.invoice_requests.clone(),
        )),
        ..(*fx.state).clone()
    });
    let owner = auth_header(&fx.state);
    let owner = owner.trim_start_matches("Bearer ");
    let (status, room) = fx
        .call(
            "POST",
            "/api/v1/rooms",
            Some(json!({"name":"capped fanout"})),
            Some(owner),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let id = room["id"].as_str().unwrap();
    for peer in &members {
        assert_eq!(
            fx.call(
                "POST",
                &format!("/api/v1/rooms/{id}/members"),
                Some(json!({"node_id":peer.to_hex()})),
                Some(owner)
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    let token = fx
        .grant(None, GrantTerms::new(200_000).per_call(6_000))
        .await;
    for peer in &members {
        fx.state
            .peer_prices
            .update_kind_price(*peer, 100, 6_001, 850_000)
            .await;
    }
    let body = json!({"recipient": id, "is_room": true, "kind": 100, "plaintext": "capped", "max_total_msat": 20_000});
    let (status, result) = fx
        .call(
            "POST",
            "/api/v1/messages/compose",
            Some(body.clone()),
            Some(&token),
        )
        .await;
    assert_budget_exceeded(status, &result, "per_call");
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!(fx.used(), 0);
    for peer in &members {
        fx.state
            .peer_prices
            .update_kind_price(*peer, 100, 6_000, 850_000)
            .await;
    }
    let (status, result) = fx
        .call("POST", "/api/v1/messages/compose", Some(body.clone()), Some(&token))
        .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(fx.wallet.left(), 12_000);
    assert_eq!(fx.used(), 12_000);
    // With routing fees the displayed room total is still checked atomically.
    for peer in &members {
        fx.state.peer_prices.update_kind_price(*peer, 100, 2_000, 850_000).await;
    }
    fx.wallet.fee.store(4_000, Ordering::SeqCst);
    let mut paid = body;
    paid["max_routing_fee_msat"] = json!(10_000);
    paid["max_total_msat"] = json!(11_999);
    let (status, _) = fx.call("POST", "/api/v1/messages/compose", Some(paid.clone()), Some(&token)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(fx.used(), 12_000);
    paid["max_total_msat"] = json!(12_000);
    let (status, result) = fx.call("POST", "/api/v1/messages/compose", Some(paid), Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert_eq!(result["max_routing_fee_msat"], 8_000);
    assert_eq!(fx.used(), 24_000);
}

#[tokio::test]
async fn message_fee_budget_is_cap_minus_price() {
    for (price, fee) in [(1_000, 5_000), (2_000, 4_000), (6_000, 0)] {
        let fx = fixture().await;
        let token = fx.grant(None, GrantTerms::new(100_000)).await;
        fx.state.peer_prices.update_kind_price(fx.peer, 100, price, 850_000).await;
        fx.wallet.fee.store(fee, Ordering::SeqCst);
        let (status, body) = fx.call("POST", "/api/v1/messages/compose", Some(json!({
            "recipient": fx.peer.to_hex(), "kind":100, "plaintext":"fee budget",
            "max_routing_fee_msat": 10_000
        })), Some(&token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["max_routing_fee_msat"], fee);
        assert_eq!(fx.used(), 6_000);
    }
}

#[tokio::test]
async fn liquidity_cannot_use_messaging_authority() {
    for relation in [true, false] {
        let (fx, _) = messaging_fixture(relation, 20_000).await;
        let result = fx.service.reserve_liquidity_fee(&fx.client_id, 1,
            vec![Charge {recipient: PEER_LN.into(), amount_msat: 1_000}]);
        assert!(matches!(result, Err(BudgetRefusal::MessagingGrant)), "{result:?}");
        assert_eq!(fx.used(), 0);
    }
}

#[tokio::test]
async fn message_route_over_remaining_fee_budget_refuses_without_spending() {
    for ldk in [false, true] {
    let fx = fixture().await;
    fx.wallet.ldk_route_refusal.store(ldk, Ordering::SeqCst);
    let token = fx.grant(None, GrantTerms::new(100_000)).await;
    fx.state.peer_prices.update_kind_price(fx.peer, 100, 2_000, 850_000).await;
    fx.wallet.fee.store(4_001, Ordering::SeqCst);
    let (status, body) = fx.call("POST", "/api/v1/messages/compose", Some(json!({
        "recipient": fx.peer.to_hex(), "kind":100, "plaintext":"too costly",
        "max_routing_fee_msat":10_000
    })), Some(&token)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "The route cannot fit within the approved message total. The message payment was not dispatched.");
    assert_eq!(fx.wallet.left(), 0);
    assert_eq!(fx.used(), 0);
    }
}

#[tokio::test]
async fn payment_keeps_its_five_sat_fee_floor_and_owner_limit() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(100_000).per_call(20_000)).await;
    fx.wallet.fee.store(5_000, Ordering::SeqCst);
    let (status, body) = fx.call("POST", "/api/v1/payments/keysend", Some(json!({
        "dest_pubkey": PEER_LN, "amount_msat":15_000, "max_routing_fee_msat":null
    })), Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["max_routing_fee_msat"], 5_000);
    assert_eq!(fx.used(), 20_000);
    let (status, body) = fx.call("POST", "/api/v1/payments/keysend", Some(json!({
        "dest_pubkey": PEER_LN, "amount_msat":15_001, "max_routing_fee_msat":null
    })), Some(&token)).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert_eq!(fx.used(), 20_000);
}

#[tokio::test]
async fn file_uses_remaining_message_fee_budget() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(100_000).per_call(3_000)).await;
    let path = lifecycle::upload_probe_file(&fx).await;
    fx.wallet.fee.store(2_000, Ordering::SeqCst);
    let (status, body) = fx.call("POST", &path, Some(json!({
        "recipient":fx.peer.to_hex(), "max_routing_fee_msat":null
    })), Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["max_routing_fee_msat"], 2_000);
    assert_eq!(fx.used(), 3_000);
}

#[tokio::test]
async fn early_total_cap_refusal_reports_the_message_fee_allowance() {
    for file in [false, true] {
        let fx = fixture().await;
        let token = fx.grant(None, GrantTerms::new(100_000).per_call(3_000)).await;
        let path = if file { lifecycle::upload_probe_file(&fx).await } else { "/api/v1/messages/compose".into() };
        let mut request = json!({"recipient":fx.peer.to_hex(), "max_total_msat":2_999, "max_routing_fee_msat":null});
        if !file {
            request["kind"] = json!(100);
            request["plaintext"] = json!("cap refusal");
        }
        let (status, body) = fx.call("POST", &path, Some(request), Some(&token)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["code"], "price_cap_exceeded");
        assert_eq!(body["max_routing_fee_msat"], 2_000);
        assert_eq!(fx.used(), 0);
        assert_eq!(fx.wallet.money(), 0);
    }
}
