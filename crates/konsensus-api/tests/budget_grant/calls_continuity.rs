//! Live-call continuity on the compose route (`[calls] call_continuity_v1`):
//! after the app's grant expires with no renewal, its fresh token has no
//! `spend`, yet it may pay the next minute blocks of the call it owns, drawing
//! only on that call's pinned hold. Nothing else on the route moves without
//! `spend`, and with the switch off the route refuses it as before.
use super::*;

const MINUTES: u16 = 3;
const BLOCK: u64 = 7_000;

/// A paired app under a live grant on a node with continuity `on`, in a live
/// call it placed (3 one-minute blocks pinned) with block 0 paid.
async fn live_call(on: bool) -> (Fx, String) {
    let mut fx = fixture().await;
    let fingerprint = fx.service.bound_fingerprint();
    fx.service = Arc::new(
        PairingService::open(fx.tmp.path(), fingerprint, true).unwrap()
            .with_owner_console(Box::new(fx.console.clone()))
            .without_stdout_code()
            .with_call_continuity(on),
    );
    fx.state = Arc::new(AppState { pairing: Some(Arc::clone(&fx.service)), ..(*fx.state).clone() });
    let mut fx = call_ready(fx).await;
    fx.state = Arc::new(AppState { max_call_minutes: MINUTES, ..(*fx.state).clone() });
    let mut terms = GrantTerms::new(5_000_000);
    terms.breakers.max_msat_per_10_minutes = 5_000_000;
    let token = fx.grant(None, terms).await;
    let (status, body) = send(&fx, &token, 400, BLOCK, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    answer(&fx).await;
    due(&fx).await;
    let (status, body) = send(&fx, &token, 404, BLOCK, 0).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    (fx, token)
}

/// Make the next block due now, as the clock would.
async fn due(fx: &Fx) {
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let mut entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    entry.paid_until_ms = Some(now + 1_000);
    entry.deadline_ms = now + 20_000;
    fx.state.storage.call_put(&fx.peer, CALL, &entry).await.unwrap();
}

/// The grant's window closes; the app's next token carries no `spend`.
async fn expire(fx: &Fx) -> String {
    fx.service.end_spend_windows_for_test(&fx.client_id);
    let token = fx.token_as(&fx.client_id, &fx.key).await;
    let claims = konsensus_api::auth::validate_token(&token, &fx.state.jwt_secret).unwrap();
    assert!(!claims.scp.contains(&konsensus_api::auth::Scope::Spend));
    token
}

fn hold(fx: &Fx) -> konsensus_api::spend_budget::CallSpendStatus {
    fx.service.call_spend_status(&fx.peer.to_hex(), CALL).unwrap()
}

#[tokio::test]
async fn after_expiry_a_no_spend_token_pays_its_own_call_blocks_up_to_the_pinned_limit() {
    let (fx, _) = live_call(true).await;
    let reserved = hold(&fx).reserved_msat;
    let token = expire(&fx).await;
    for seq in 1..u32::from(MINUTES) {
        due(&fx).await;
        let money = fx.wallet.money();
        let (status, body) = send(&fx, &token, 404, BLOCK, seq).await;
        assert_eq!(status, StatusCode::OK, "block {seq} after expiry: {body}");
        assert_eq!(fx.wallet.money(), money + 1, "block {seq}");
        assert_eq!(hold(&fx).spent_msat, BLOCK * u64::from(seq + 1));
    }
    // At the pinned minute limit the next block is refused, unpaid.
    due(&fx).await;
    let money = fx.wallet.money();
    let (status, _) = send(&fx, &token, 404, BLOCK, u32::from(MINUTES)).await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(fx.wallet.money(), money);
    // A higher price than pinned is never paid from the hold.
    let view = hold(&fx);
    assert!(view.spent_msat <= reserved);
    assert_eq!(view.spent_msat, BLOCK * u64::from(MINUTES));
    assert_eq!(view.remaining_msat, reserved - view.spent_msat, "only the closing reserve is still held");
    assert_eq!(fx.used(), reserved + 1_000, "the expired grant carries the offer and its hold, nothing more");
    assert_eq!(fx.wallet.left(), BLOCK * u64::from(MINUTES) + 1_000, "offer plus three blocks left the wallet");
    // The call ends: the rest of the hold is released once; the expired
    // grant then funds nothing and leaves the file.
    fx.state.storage.call_delete(&fx.peer, CALL).await.unwrap();
    for _ in 0..2 {
        konsensus_api::calls::reconcile_call_spend(&fx.state, chrono::Utc::now().timestamp_millis() as u64).await.unwrap();
    }
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none());
    assert!(fx.service.reload_from_disk().unwrap().grants.is_empty());
    assert_eq!(fx.wallet.left(), BLOCK * u64::from(MINUTES) + 1_000, "ending the call paid nothing more");
}

#[tokio::test]
async fn a_no_spend_token_moves_nothing_else_on_the_compose_route() {
    let (fx, _) = live_call(true).await;
    let token = expire(&fx).await;
    due(&fx).await;
    let money = fx.wallet.money();
    // Another call, a new call, a chat message, a hangup: refused, unpaid.
    let (status, body) = send_id(&fx, &token, 404, BLOCK, 1, "99999999888877776666555544443333").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send_id(&fx, &token, 400, BLOCK, 0, "99999999888877776666555544443333").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = message(&fx, &token, 1_000).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = fx.call("POST", "/api/v1/messages/compose", Some(json!({
        "recipient": fx.peer.to_hex(), "kind": 403, "max_routing_fee_msat": 0, "wait_ack_ms": 0,
        "plaintext": json!({"v": 1, "call_id": CALL, "reason": "hangup"}).to_string(),
    })), Some(&token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    // Another spend route keeps refusing it too.
    let (status, body) = fx.call("POST", "/api/v1/payments/pay", Some(json!({"bolt11": create_test_bolt11(1_000)})),
        Some(&token)).await;
    assert!(status == StatusCode::FORBIDDEN || status == StatusCode::NOT_FOUND, "{status} {body}");
    assert_eq!(fx.wallet.money(), money);
    // Its own call's block still goes through.
    let (status, body) = send(&fx, &token, 404, BLOCK, 1).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn revocation_epoch_identity_and_the_switch_end_no_spend_blocks() {
    // Switch off: the expired app's block is refused as before.
    let (fx, _) = live_call(false).await;
    let token = expire(&fx).await;
    due(&fx).await;
    let money = fx.wallet.money();
    let (status, body) = send(&fx, &token, 404, BLOCK, 1).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(fx.wallet.money(), money);

    for end in ["revoke", "epoch", "identity"] {
        let (fx, _) = live_call(true).await;
        let token = expire(&fx).await;
        due(&fx).await;
        match end {
            "revoke" => { fx.service.revoke_grants(Some(&fx.client_id)).unwrap(); }
            "epoch" => { fx.service.bump_epoch(&fx.client_id).unwrap(); }
            _ => fx.service.rebind_to_identity("another-identity").unwrap(),
        }
        let money = fx.wallet.money();
        let (status, body) = send(&fx, &token, 404, BLOCK, 1).await;
        assert!(status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED, "{end}: {status} {body}");
        assert_eq!(fx.wallet.money(), money, "{end}");
    }
}

#[tokio::test]
async fn a_renewal_mid_call_moves_the_hold_once_and_blocks_keep_one_ledger() {
    let (fx, _) = live_call(true).await;
    let reserved = hold(&fx).reserved_msat;
    let token = expire(&fx).await;
    due(&fx).await;
    assert_eq!(send(&fx, &token, 404, BLOCK, 1).await.0, StatusCode::OK);
    // The owner renews: the app's token has `spend` again, on the same hold.
    let renewed = fx.grant(None, GrantTerms::new(2_000_000)).await;
    let outstanding = reserved - 2 * BLOCK;
    assert_eq!(fx.used(), outstanding, "the renewal carries only what the hold still has");
    due(&fx).await;
    assert_eq!(send(&fx, &renewed, 404, BLOCK, 2).await.0, StatusCode::OK);
    let view = hold(&fx);
    assert_eq!(view.spent_msat, 3 * BLOCK);
    fx.state.storage.call_delete(&fx.peer, CALL).await.unwrap();
    konsensus_api::calls::reconcile_call_spend(&fx.state, chrono::Utc::now().timestamp_millis() as u64).await.unwrap();
    let view = hold(&fx);
    assert_eq!(view.spent_msat + view.released_msat, reserved);
    // Paid under the renewed grant: one block; the closing reserve came back.
    assert_eq!(fx.used(), BLOCK);
}

/// A paired app under a device relation grant for the contact on a node with
/// continuity on, in a live call (3 pinned minutes) with block 0 paid.
async fn relation_call() -> (Fx, String) {
    let fx = call_ready(fixture().await).await;
    let (mut fx, _, _) = super::super::messaging_cap::approved_grant(fx, true, 200_000, Some(20_000)).await;
    let fingerprint = fx.service.bound_fingerprint();
    fx.service = Arc::new(
        PairingService::open(fx.tmp.path(), fingerprint, true).unwrap()
            .with_owner_console(Box::new(fx.console.clone()))
            .without_stdout_code()
            .with_call_continuity(true),
    );
    fx.state = Arc::new(AppState {
        pairing: Some(Arc::clone(&fx.service)), max_call_minutes: MINUTES,
        ..(*fx.state).clone()
    });
    let token = fx.token().await;
    let (status, body) = send(&fx, &token, 400, BLOCK, 0).await;
    assert_eq!(status, StatusCode::OK, "live relation invite: {body}");
    answer(&fx).await;
    due(&fx).await;
    let (status, body) = send(&fx, &token, 404, BLOCK, 0).await;
    assert_eq!(status, StatusCode::OK, "live relation minute: {body}");
    (fx, token)
}

#[tokio::test]
async fn after_its_relation_window_an_admitted_call_pays_its_next_minutes_over_http() {
    let (fx, _) = relation_call().await;
    fx.service.end_recipient_windows_for_test(&fx.client_id);
    let token = expire(&fx).await;
    let binding = konsensus_api::auth::PairingBinding {
        client_id: fx.client_id.clone(), epoch: 1, fingerprint: fx.service.bound_fingerprint(),
    };
    assert!(fx.service.call_hold_live(&binding, &fx.peer.to_hex(), CALL));
    assert!(fx.service.owns_call_media(&binding, &fx.peer.to_hex(), CALL));
    for seq in 1..u32::from(MINUTES) {
        due(&fx).await;
        let money = fx.wallet.money();
        let (status, body) = send(&fx, &token, 404, BLOCK, seq).await;
        assert_eq!(status, StatusCode::OK, "funded relation minute {seq} after the window: {body}");
        assert_eq!(fx.wallet.money(), money + 1);
    }
    due(&fx).await;
    let money = fx.wallet.money();
    assert_ne!(send(&fx, &token, 404, BLOCK, u32::from(MINUTES)).await.0, StatusCode::OK);
    // Nothing new: another call is refused, and nothing was paid for it.
    let (status, _) = send_id(&fx, &token, 400, BLOCK, 0, "99999999888877776666555544443333").await;
    assert_ne!(status, StatusCode::OK);
    assert_eq!(fx.wallet.money(), money);
    let view = hold(&fx);
    assert_eq!(view.spent_msat, BLOCK * u64::from(MINUTES));
    assert!(view.spent_msat <= view.reserved_msat);
}

#[tokio::test]
async fn after_its_relation_window_a_revoked_call_pays_nothing_more() {
    let (fx, _) = relation_call().await;
    fx.service.end_recipient_windows_for_test(&fx.client_id);
    let token = expire(&fx).await;
    fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
    due(&fx).await;
    let money = fx.wallet.money();
    let (status, body) = send(&fx, &token, 404, BLOCK, 1).await;
    assert!(status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED, "{status} {body}");
    assert_eq!(fx.wallet.money(), money);
}
