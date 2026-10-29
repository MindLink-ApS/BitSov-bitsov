use super::*;

fn offer(fx: &Fx) -> Value {
    json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(),
        "kind": 400, "wait_ack_ms": 0, "max_routing_fee_msat": 0,
        "plaintext": json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"}).to_string(),
    })
}

#[tokio::test]
async fn offer_above_consent_creates_no_hold_and_sends_or_spends_nothing() {
    for (ceilings, reason) in [
        (json!({"max_block_msat": 6999}), "call_price_above_consent"),
        (json!({"max_hold_msat": 419999}), "call_hold_above_consent"),
        (
            json!({"max_block_msat": 7000, "max_hold_msat": 449999, "max_routing_fee_msat": 500}),
            "call_hold_above_consent",
        ),
        (json!({"max_block_msat": 0}), "call_price_above_consent"),
        (json!({"max_hold_msat": 0}), "call_hold_above_consent"),
    ] {
        let (mut fx, token) = prepared().await;
        let transport = Arc::new(ConnectedStubTransport::new(
            vec![fx.peer],
            fx.state.invoice_requests.clone(),
        ));
        fx.state = Arc::new(AppState {
            transport: transport.clone(),
            ..(*fx.state).clone()
        });
        let mut request = offer(&fx);
        request
            .as_object_mut()
            .unwrap()
            .extend(ceilings.as_object().unwrap().clone());
        let (status, body) = send_request(&fx, &token, 7000, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["code"], "not_dispatched", "{body}");
        assert_eq!(body["reason"], reason, "{body}");
        assert_eq!((fx.wallet.money(), fx.wallet.left(), fx.used()), (0, 0, 0));
        assert!(fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .is_none());
        assert!(fx
            .state
            .storage
            .call_get(&fx.peer, CALL)
            .await
            .unwrap()
            .is_none());
        assert!(transport.sent_envelopes.lock().unwrap().is_empty());
        let budget = fx.service.reload_from_disk().unwrap().grants[0]
            .budget
            .clone()
            .unwrap();
        assert!(budget.pending.is_empty());
        assert_eq!(
            budget
                .breaker_status(chrono::Utc::now().timestamp())
                .payments_last_hour,
            0
        );
    }
}

#[tokio::test]
async fn overflowing_offer_quote_still_returns_typed_consent_refusal() {
    for (ceilings, reason) in [
        (json!({"max_block_msat": 7000}), "call_price_above_consent"),
        (
            json!({"max_hold_msat": u64::MAX}),
            "call_hold_above_consent",
        ),
    ] {
        let (fx, token) = prepared().await;
        let mut request = offer(&fx);
        request
            .as_object_mut()
            .unwrap()
            .extend(ceilings.as_object().unwrap().clone());
        let (status, body) = send_request(&fx, &token, u64::MAX, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["reason"], reason, "{body}");
        assert_eq!((fx.wallet.money(), fx.used()), (0, 0));
        assert!(fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .is_none());
    }
}

#[tokio::test]
async fn offer_within_consent_accepts_equal_boundaries_and_absent_ceilings() {
    for ceilings in [
        json!({}),
        json!({"max_block_msat": 7000}),
        json!({"max_hold_msat": 420000}),
        json!({"max_block_msat": 7000, "max_hold_msat": 450000, "max_routing_fee_msat": 500}),
    ] {
        let (fx, token) = prepared().await;
        let mut request = offer(&fx);
        request
            .as_object_mut()
            .unwrap()
            .extend(ceilings.as_object().unwrap().clone());
        let expected_hold = if ceilings.get("max_routing_fee_msat").is_some() {
            450_000
        } else {
            420_000
        };
        let (status, body) = send_request(&fx, &token, 7000, request).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let hold = fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .unwrap();
        assert_eq!(
            (hold.reserved_msat, hold.spent_msat, hold.closed),
            (expected_hold, 0, false)
        );
        assert_eq!(
            (fx.wallet.money(), fx.wallet.left(), fx.used()),
            (1, 1000, expected_hold + 1000)
        );
    }
}

#[tokio::test]
async fn offer_consent_applies_to_owner_and_the_payable_minimum() {
    for owner in [false, true] {
        let (fx, token) = prepared().await;
        let token = if owner {
            konsensus_api::auth::create_token(
                &fx.state.identity.node_id().to_hex(),
                &fx.state.jwt_secret,
                Scope::all(),
            )
            .unwrap()
        } else {
            token
        };
        let mut request = offer(&fx);
        request["max_block_msat"] = json!(999);
        let (status, body) = send_request(&fx, &token, 1, request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["reason"], "call_price_above_consent", "{body}");
        assert_eq!((fx.wallet.money(), fx.used()), (0, 0));
        assert!(fx
            .service
            .call_spend_status(&fx.peer.to_hex(), CALL)
            .is_none());
    }
}
