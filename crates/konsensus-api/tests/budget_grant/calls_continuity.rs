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
    live_call_closing(on, 0).await
}

/// [`live_call`] whose callee quoted `closing` msat for a hangup at admission,
/// so the hold pins that much (at least 1 sat) as its closing reserve.
async fn live_call_closing(on: bool, closing: u64) -> (Fx, String) {
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
    fx.state.peer_prices.update_kind_price(fx.peer, 403, closing, 850_000).await;
    let (status, body) = send_priced_with_closing(&fx, &token, 1_000, BLOCK, closing, json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(), "kind": 400,
        "plaintext": json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })).await;
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

/// A hangup (403) of `call_id` with `reason`, priced like the call's closing signal.
async fn hangup_with(fx: &Fx, token: &str, call_id: &str, reason: Option<&str>) -> (StatusCode, Value) {
    let mut plaintext = json!({"v": 1, "call_id": call_id});
    if let Some(reason) = reason {
        plaintext["reason"] = json!(reason);
    }
    // Quote the hangup before the request starts: the background quote loop
    // only refreshes it, so the request never sees an older price.
    fx.state.peer_prices.update_kind_price(fx.peer, 403, 1_000, 850_000).await;
    send_priced_with_closing(fx, token, 1_000, BLOCK, 1_000, json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(), "kind": 403,
        "plaintext": plaintext.to_string(), "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })).await
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
    // Another call, a new call, a chat message, another call's hangup, a
    // hangup carrying a reason only the node itself sends: refused, unpaid.
    let (status, body) = send_id(&fx, &token, 404, BLOCK, 1, "99999999888877776666555544443333").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = send_id(&fx, &token, 400, BLOCK, 0, "99999999888877776666555544443333").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = message(&fx, &token, 1_000).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, body) = hangup_with(&fx, &token, "99999999888877776666555544443333", Some("hangup")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    for reason in ["unpaid", "duration_cap", "declined", "busy", "timeout", "failed"] {
        let (status, body) = hangup_with(&fx, &token, CALL, Some(reason)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{reason}: {body}");
    }
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

#[tokio::test]
async fn after_expiry_its_own_hangup_goes_out_once_from_the_closing_reserve_and_ends_the_minutes() {
    let (fx, _) = live_call(true).await;
    let reserved = hold(&fx).reserved_msat;
    let used = fx.used();
    let token = expire(&fx).await;
    due(&fx).await;
    let money = fx.wallet.money();
    let (status, body) = hangup_with(&fx, &token, CALL, Some("hangup")).await;
    assert_eq!(status, StatusCode::OK, "own hangup after expiry: {body}");
    assert_eq!(fx.wallet.money(), money + 1, "exactly one payment: the hangup");
    assert_eq!(fx.wallet.left(), 1_000 + BLOCK + 1_000, "offer, block 0 and the hangup left the wallet");
    // The hangup ended the call: its hold closed, paying block 0 and the
    // hangup and releasing the rest once; the expired grant then leaves.
    match fx.service.call_spend_status(&fx.peer.to_hex(), CALL) {
        Some(view) => {
            assert!(view.closed, "{view:?}");
            assert_eq!(view.spent_msat, BLOCK + 1_000, "block 0 and the hangup, both from the hold");
            assert_eq!(view.spent_msat + view.released_msat, reserved);
        }
        None => assert!(fx.service.reload_from_disk().unwrap().grants.is_empty()),
    }
    assert!(fx.used() <= used, "nothing new was reserved on the ended grant");
    let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(entry.phase, konsensus_core::payloads::call::Phase::Ended);
    let hangups = fx.state.storage.get_node_messages_of_kind(&fx.state.identity.node_id().to_hex(), 403, 10, None).await.unwrap();
    assert_eq!(hangups.len(), 1);
    assert_eq!(hangups[0].payment_proof.amount_msat, 1_000);

    // Its minutes stop; a second hangup, a hangup without a reason and an
    // offer are refused, and nothing more is paid.
    due(&fx).await;
    let money = fx.wallet.money();
    assert_ne!(send(&fx, &token, 404, BLOCK, 1).await.0, StatusCode::OK);
    assert_ne!(hangup_with(&fx, &token, CALL, Some("hangup")).await.0, StatusCode::OK);
    assert_ne!(hangup_with(&fx, &token, CALL, None).await.0, StatusCode::OK);
    let (status, body) = send_id(&fx, &token, 400, BLOCK, 0, "99999999888877776666555544443333").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(fx.wallet.money(), money);
    for _ in 0..2 {
        konsensus_api::calls::reconcile_call_spend(&fx.state, chrono::Utc::now().timestamp_millis() as u64).await.unwrap();
    }
    assert_eq!(fx.wallet.left(), 1_000 + BLOCK + 1_000, "offer, one block and one hangup left the wallet");
}

#[tokio::test]
async fn after_expiry_a_hangup_without_a_reason_is_the_same_single_hangup() {
    let (fx, _) = live_call(true).await;
    let token = expire(&fx).await;
    let money = fx.wallet.money();
    let (status, body) = hangup_with(&fx, &token, CALL, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.wallet.money(), money + 1);
    assert_ne!(hangup_with(&fx, &token, CALL, Some("hangup")).await.0, StatusCode::OK);
    assert_eq!(fx.wallet.money(), money + 1);
}

#[tokio::test]
async fn with_the_switch_off_or_the_grant_revoked_an_expired_app_still_cannot_hang_up() {
    let (fx, _) = live_call(false).await;
    let token = expire(&fx).await;
    let money = fx.wallet.money();
    let (status, body) = hangup_with(&fx, &token, CALL, Some("hangup")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(fx.wallet.money(), money);
    let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(entry.phase, konsensus_core::payloads::call::Phase::Live);

    let (fx, _) = live_call(true).await;
    let token = expire(&fx).await;
    fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
    let money = fx.wallet.money();
    let (status, body) = hangup_with(&fx, &token, CALL, Some("hangup")).await;
    assert!(status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED, "{status} {body}");
    assert_eq!(fx.wallet.money(), money);
}

#[tokio::test]
async fn after_expiry_a_hangup_priced_above_its_closing_reserve_is_refused_unpaid() {
    let (fx, _) = live_call(true).await;
    let token = expire(&fx).await;
    let money = fx.wallet.money();
    // The callee's hangup price is 2 sat before the request starts; the
    // reserve pinned at admission holds 1 sat.
    fx.state.peer_prices.update_kind_price(fx.peer, 403, 2_000, 850_000).await;
    assert_eq!(hold(&fx).reserved_msat - u64::from(MINUTES) * BLOCK, 1_000, "a 1 sat closing reserve");
    let (status, body) = send_priced_with_closing(&fx, &token, 1_000, BLOCK, 2_000, json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(), "kind": 403,
        "plaintext": json!({"v": 1, "call_id": CALL, "reason": "hangup"}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.wallet.money(), money, "nothing was paid");
    assert_eq!(hold(&fx).spent_msat, BLOCK);
    let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(entry.phase, konsensus_core::payloads::call::Phase::Live);
    assert!(entry.pending.is_none(), "the refused hangup holds no reservation");
}

/// The hangup's payment waits in the wallet while `change` runs, then resumes.
async fn hangup_across(fx: &Fx, token: &str, change: impl FnOnce()) -> (StatusCode, Value) {
    fx.wallet.pause_dispatch.store(true, Ordering::SeqCst);
    let (result, ()) = tokio::join!(hangup_with(fx, token, CALL, Some("hangup")), async {
        tokio::time::timeout(std::time::Duration::from_secs(5), fx.wallet.entered.notified())
            .await.expect("the hangup reached the wallet");
        change();
        fx.wallet.pause_dispatch.store(false, Ordering::SeqCst);
        fx.wallet.resume.notify_one();
    });
    result
}

#[tokio::test]
async fn after_expiry_a_hangup_admitted_before_a_revocation_or_new_pairing_epoch_is_not_paid() {
    for re_pair in [false, true] {
        let (fx, _) = live_call(true).await;
        let token = expire(&fx).await;
        let (money, left) = (fx.wallet.money(), fx.wallet.left());
        // Admitted and reserved on the app's binding; the owner revokes or
        // re-pairs while its payment is still in the wallet.
        let (status, body) = hangup_across(&fx, &token, || {
            if re_pair {
                fx.service.bump_epoch(&fx.client_id).unwrap();
            } else {
                fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
            }
        }).await;
        assert_ne!(status, StatusCode::OK, "re_pair={re_pair}: {body}");
        assert_eq!(fx.wallet.money(), money, "re_pair={re_pair}: the hangup was paid on a stale binding");
        assert_eq!(fx.wallet.left(), left, "re_pair={re_pair}");
    }
}

#[tokio::test]
async fn after_expiry_two_simultaneous_hangups_pay_the_closing_reserve_once() {
    let (fx, _) = live_call(true).await;
    let reserved = hold(&fx).reserved_msat;
    let token = expire(&fx).await;
    let (money, left) = (fx.wallet.money(), fx.wallet.left());
    // The first hangup to reach the wallet waits there while the other one
    // goes as far as it can; neither is a retry of the other.
    fx.wallet.pause_dispatch.store(true, Ordering::SeqCst);
    let done = AtomicUsize::new(0);
    let finish = |result: (StatusCode, Value)| {
        done.fetch_add(1, Ordering::SeqCst);
        result
    };
    let (one, two, ()) = tokio::join!(
        async { finish(hangup_with(&fx, &token, CALL, Some("hangup")).await) },
        async { finish(hangup_with(&fx, &token, CALL, None).await) },
        async {
            tokio::time::timeout(std::time::Duration::from_secs(5), fx.wallet.entered.notified())
                .await.expect("a hangup reached the wallet");
            // The other hangup must finish (refused) while the first is still
            // held in the wallet: if it could reach the wallet too, it would
            // wait there and this times out.
            let held = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while done.load(Ordering::SeqCst) < 1 {
                assert!(std::time::Instant::now() < held, "the second hangup was not settled while the first was in the wallet");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            fx.wallet.pause_dispatch.store(false, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            while done.load(Ordering::SeqCst) < 2 {
                assert!(std::time::Instant::now() < deadline, "the hangups did not finish");
                fx.wallet.resume.notify_waiters();
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        },
    );
    let paid = [&one, &two].iter().filter(|(status, _)| *status == StatusCode::OK).count();
    assert_eq!(paid, 1, "exactly one hangup is paid: {one:?} {two:?}");
    // The other one was refused, unsent, because the first was in flight.
    let refused = if one.0 == StatusCode::OK { &two } else { &one };
    assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{refused:?}");
    assert_eq!(refused.1["reason"], "call_signal_in_flight", "{refused:?}");
    assert_eq!(refused.1["code"], "not_dispatched", "{refused:?}");
    assert_eq!(fx.wallet.money(), money + 1, "one payment reached the wallet: {one:?} {two:?}");
    assert_eq!(fx.wallet.left(), left + 1_000, "at most one hangup price left the wallet");
    let hangups = fx.state.storage.get_node_messages_of_kind(&fx.state.identity.node_id().to_hex(), 403, 10, None).await.unwrap();
    assert_eq!(hangups.len(), 1);
    match fx.service.call_spend_status(&fx.peer.to_hex(), CALL) {
        Some(view) => {
            assert!(view.closed, "{view:?}");
            assert_eq!(view.spent_msat, BLOCK + 1_000, "block 0 and one hangup");
            assert_eq!(view.spent_msat + view.released_msat, reserved);
        }
        None => assert!(fx.service.reload_from_disk().unwrap().grants.is_empty()),
    }
    let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(entry.phase, konsensus_core::payloads::call::Phase::Ended);
}

#[tokio::test]
async fn after_expiry_a_hangup_quote_that_rises_above_the_closing_reserve_is_never_paid_above_it() {
    // Admission pinned a 1 sat closing reserve. The callee's hangup quote
    // then rises 1 msat above it: refused, unpaid, the call still live.
    let (fx, _) = live_call(true).await;
    let token = expire(&fx).await;
    assert_eq!(hold(&fx).reserved_msat - u64::from(MINUTES) * BLOCK, 1_000, "a 1 sat closing reserve");
    let (money, left) = (fx.wallet.money(), fx.wallet.left());
    fx.state.peer_prices.update_kind_price(fx.peer, 403, 1_001, 850_000).await;
    let (status, body) = send_priced_with_closing(&fx, &token, 1_000, BLOCK, 1_001, json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(), "kind": 403,
        "plaintext": json!({"v": 1, "call_id": CALL, "reason": "hangup"}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_closing_refusal(&body);
    assert_eq!(fx.wallet.money(), money, "a quote above the reserve is not paid: {body}");
    assert_eq!(fx.wallet.left(), left);
    assert_eq!(hold(&fx).spent_msat, BLOCK);
    let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(entry.phase, konsensus_core::payloads::call::Phase::Live);
    assert!(entry.pending.is_none(), "the refused hangup holds no reservation");

    // The background quote rises from 1 to 2 sat while the request runs:
    // whichever quote it reads, at most the 1 sat reserve leaves the wallet.
    let (fx, _) = live_call(true).await;
    let reserved = hold(&fx).reserved_msat;
    let token = expire(&fx).await;
    let left = fx.wallet.left();
    fx.state.peer_prices.update_kind_price(fx.peer, 403, 1_000, 850_000).await;
    let (status, body) = send_priced_with_closing(&fx, &token, 1_000, BLOCK, 2_000, json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(), "kind": 403,
        "plaintext": json!({"v": 1, "call_id": CALL, "reason": "hangup"}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })).await;
    let out = fx.wallet.left() - left;
    match out {
        0 => {
            assert_ne!(status, StatusCode::OK, "nothing left the wallet, so the hangup must not read as paid: {body}");
            assert_closing_refusal(&body);
        }
        1_000 => assert_eq!(status, StatusCode::OK, "{body}"),
        other => panic!("{other} msat left the wallet: {status} {body}"),
    }
    let spent = fx.service.call_spend_status(&fx.peer.to_hex(), CALL).map_or(BLOCK + out, |view| view.spent_msat);
    assert!(spent <= reserved && spent - BLOCK <= 1_000, "{spent}");
}

/// Every grant's recorded liability, in file order: total used, used per
/// recipient, and each outstanding reservation with what it holds per recipient.
type Liability = Vec<(u64, std::collections::BTreeMap<String, u64>, std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>>)>;

fn liability(fx: &Fx) -> Liability {
    fx.service.reload_from_disk().unwrap().grants.iter()
        .filter_map(|g| g.budget.as_ref())
        .map(|b| (b.used_msat, b.used_by_recipient.clone(), b.pending.clone()))
        .collect()
}

/// A hangup refused because its price and routing allowance exceed the
/// closing reserve, before anything was dispatched.
fn assert_closing_refusal(body: &Value) {
    assert_eq!(body["reason"], "call_price_changed", "{body}");
    assert_eq!(body["state"], "released", "{body}");
    assert!(body["payment_hash"].is_null(), "{body}");
}

/// The durable record of the operation a compose response names.
async fn operation(fx: &Fx, body: &Value) -> konsensus_storage::OutboxOperation {
    let id = body["operation_id"].as_str().unwrap_or_else(|| panic!("no operation id: {body}"));
    fx.state.storage.get_outbox_operation(id).await.unwrap().unwrap_or_else(|| panic!("no record of {id}"))
}

#[tokio::test]
async fn expired_relation_window_hangup_uses_only_its_closing_reserve_once() {
    // A relation-funded call keeps paying its minutes past its recipient
    // window, then hangs up after the window and the grant have both ended.
    let (fx, _) = relation_call().await;
    let reserved = hold(&fx).reserved_msat;
    assert_eq!(reserved - u64::from(MINUTES) * BLOCK, 1_000, "a 1 sat closing reserve");
    fx.service.end_recipient_windows_for_test(&fx.client_id);
    let token = expire(&fx).await;
    due(&fx).await;
    assert_eq!(send(&fx, &token, 404, BLOCK, 1).await.0, StatusCode::OK, "a minute past the window");
    // The one grant holds the call: two paid minutes plus the 8 sat the
    // hold still has (one minute and the closing reserve).
    let before = liability(&fx);
    let peer = fx.peer.to_hex();
    assert_eq!(before.len(), 1, "{before:?}");
    let (used, by_peer, pending) = &before[0];
    assert_eq!(by_peer.get(&peer), Some(used), "{before:?}");
    assert_eq!(*used, reserved + 1_000, "the offer and the whole hold: {before:?}");
    let held: u64 = pending.values().flat_map(|r| r.values()).sum();
    assert_eq!(held, reserved - 2 * BLOCK, "{before:?}");
    let (money, left) = (fx.wallet.money(), fx.wallet.left());

    // One msat above the closing reserve: refused, unpaid, every grant's
    // usage and every reservation exactly as it was.
    let (status, body) = hangup_with_fee(&fx, &token, 1_001, 0).await;
    assert_ne!(status, StatusCode::OK, "a hangup above the closing reserve: {body}");
    assert_closing_refusal(&body);
    assert_eq!((fx.wallet.money(), fx.wallet.left()), (money, left), "nothing was paid: {body}");
    assert_eq!(liability(&fx), before, "the refused hangup reserved nothing");
    let refused = operation(&fx, &body).await;
    assert_eq!((refused.state.as_str(), refused.settled_msat), ("released", 0));

    let (status, body) = hangup_with(&fx, &token, CALL, Some("hangup")).await;
    assert_eq!(status, StatusCode::OK, "own hangup after the relation window: {body}");
    assert_eq!(fx.wallet.money(), money + 1, "exactly one payment: the hangup");
    assert_eq!(fx.wallet.left(), left + 1_000, "only the closing reserve left the wallet");
    let sent = operation(&fx, &body).await;
    assert_eq!((sent.state.as_str(), sent.settled_msat), ("sent", 1_000));
    // The hangup closed the hold; the expired grant then funds nothing and
    // leaves the file, so no grant carries any usage or reservation.
    assert!(fx.service.call_spend_status(&peer, CALL).is_none());
    assert!(liability(&fx).is_empty(), "{:?}", liability(&fx));

    // A second hangup, a minute and a new call pay nothing.
    due(&fx).await;
    let (money, left) = (fx.wallet.money(), fx.wallet.left());
    assert_ne!(hangup_with(&fx, &token, CALL, Some("hangup")).await.0, StatusCode::OK);
    assert_ne!(hangup_with(&fx, &token, CALL, None).await.0, StatusCode::OK);
    assert_ne!(send(&fx, &token, 404, BLOCK, 2).await.0, StatusCode::OK);
    assert_ne!(send_id(&fx, &token, 400, BLOCK, 0, "99999999888877776666555544443333").await.0, StatusCode::OK);
    for _ in 0..2 {
        konsensus_api::calls::reconcile_call_spend(&fx.state, chrono::Utc::now().timestamp_millis() as u64).await.unwrap();
    }
    assert_eq!(fx.wallet.money(), money);
    assert_eq!(fx.wallet.left(), left);
    let hangups = fx.state.storage.get_node_messages_of_kind(&fx.state.identity.node_id().to_hex(), 403, 10, None).await.unwrap();
    assert_eq!(hangups.len(), 1);
}

#[tokio::test]
async fn expired_hangup_http_identity_or_pairing_removal_stops_dispatch() {
    for end in ["pairing", "identity"] {
        let (fx, _) = live_call(true).await;
        let token = expire(&fx).await;
        let (money, left) = (fx.wallet.money(), fx.wallet.left());
        // Admitted and reserved on the app's binding; the pairing is removed
        // or the node's identity replaced while its payment is in the wallet.
        let (status, body) = hangup_across(&fx, &token, || match end {
            "pairing" => fx.service.revoke(&fx.client_id).unwrap(),
            _ => fx.service.rebind_to_identity("another-identity").unwrap(),
        }).await;
        assert_ne!(status, StatusCode::OK, "{end}: {body}");
        assert_eq!(fx.wallet.money(), money, "{end}: the hangup was paid on a stale binding");
        assert_eq!(fx.wallet.left(), left, "{end}");
        // The wallet had the payment when authority changed, so its outcome
        // stays unknown and held through reconciliation: never released,
        // never settled, the call still live with that hangup pending.
        assert_eq!(body["state"], "payment_unknown", "{end}: {body}");
        assert_eq!(body["retry_allowed"], false, "{end}: {body}");
        // Held before reconciliation and after each full pass, the last included.
        assert_unknown_hangup_held(&fx, &body, &format!("{end} before reconciliation")).await;
        for round in 0..2 {
            konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
            konsensus_api::calls::reconcile_call_spend(&fx.state, chrono::Utc::now().timestamp_millis() as u64).await.unwrap();
            assert_unknown_hangup_held(&fx, &body, &format!("{end} after pass {}", round + 1)).await;
            assert_eq!((fx.wallet.money(), fx.wallet.left()), (money, left), "{end} pass {}: reconciliation paid nothing", round + 1);
        }
    }
}

/// The hangup whose payment outcome is unknown is still held, durably: never
/// released or settled, the call live with it pending, its funding kept.
async fn assert_unknown_hangup_held(fx: &Fx, body: &Value, at: &str) {
    let op = operation(fx, body).await;
    assert_eq!(op.operation_id.as_str(), body["operation_id"].as_str().unwrap(), "{at}");
    assert_eq!(op.state, "payment_unknown", "{at}");
    assert!(op.accounting_pending, "{at}");
    assert_eq!((op.settled_msat, op.payment_hash.as_deref()), (0, None), "{at}");
    let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(entry.phase, konsensus_core::payloads::call::Phase::Live, "{at}");
    assert_eq!(entry.pending.as_ref().map(|p| (p.operation_id.as_str(), p.kind)),
        Some((body["operation_id"].as_str().unwrap(), 403)), "{at}");
    let key = format!("{}:{CALL}", fx.peer.to_hex());
    assert!(fx.service.reload_from_disk().unwrap().call_spend_grants.contains_key(&key),
        "{at}: the call's funding record is kept");
}

#[tokio::test]
async fn expired_hangup_extreme_routing_or_price_never_wraps_past_the_reserve() {
    const CLOSING: u64 = 3_000;
    const FEE: u64 = 100;
    // A caller allowing u64::MAX of routing: the ordinary fee policy clamps it,
    // and the clamped fee on top of the price is still checked against the
    // reserve. A quote that would reach the reserve only with a smaller fee is
    // refused, unpaid. Then a callee quote of u64::MAX: price plus fee does not
    // fit in u64, so it must be refused, never wrapped to a small total.
    for (case, price, fee) in [("caller fee u64::MAX", CLOSING - FEE, u64::MAX), ("quote u64::MAX", u64::MAX, FEE)] {
        let overflow = price == u64::MAX;
        let (fx, _) = live_call_closing(true, CLOSING).await;
        let token = expire(&fx).await;
        let (money, left) = (fx.wallet.money(), fx.wallet.left());
        fx.wallet.fee.store(FEE, Ordering::SeqCst);
        let dispatched = fx.wallet.fee_limits.lock().unwrap().len();
        let before = liability(&fx);
        let (status, body) = hangup_with_fee(&fx, &token, price, fee).await;
        assert_ne!(status, StatusCode::OK, "{case}: {body}");
        if overflow {
            // Refused by the all-in sum itself, before any reservation.
            assert_eq!(body["code"], "price_cap_exceeded", "{case}: {body}");
            assert!(body["error"].as_str().unwrap_or("").contains("overflow"), "{case}: {body}");
        } else {
            // The policy clamped the fee; price plus that fee is over the reserve.
            assert_eq!((body["code"].as_str(), body["reason"].as_str()), (Some("budget_exceeded"), Some("per_call")), "{case}: {body}");
            assert_eq!(body["max_routing_fee_msat"], 5_000, "{case}: the clamped routing ceiling: {body}");
        }
        assert_eq!(fx.wallet.money(), money, "{case}: nothing was paid: {body}");
        assert_eq!(fx.wallet.left(), left, "{case}");
        assert_eq!(fx.wallet.fee_limits.lock().unwrap().len(), dispatched, "{case}: the wallet was never asked");
        assert_eq!(hold(&fx).spent_msat, BLOCK, "{case}");
        assert_eq!(liability(&fx), before, "{case}: the refused hangup reserved nothing");
        let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
        assert_eq!(entry.phase, konsensus_core::payloads::call::Phase::Live, "{case}");
        assert!(entry.pending.is_none(), "{case}: the refused hangup holds no reservation");
    }
}

/// A hangup priced `price` whose caller allows `fee` msat of routing.
async fn hangup_with_fee(fx: &Fx, token: &str, price: u64, fee: u64) -> (StatusCode, Value) {
    fx.state.peer_prices.update_kind_price(fx.peer, 403, price, 850_000).await;
    send_priced_with_closing(fx, token, 1_000, BLOCK, price, json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(), "kind": 403,
        "plaintext": json!({"v": 1, "call_id": CALL, "reason": "hangup"}).to_string(),
        "max_routing_fee_msat": fee, "wait_ack_ms": 0,
    })).await
}

#[tokio::test]
async fn expired_hangup_price_plus_routing_fee_is_bounded_over_http() {
    const FEE: u64 = 100;
    const CLOSING: u64 = 3_000;
    // Price plus routing fee exactly at a 3 sat closing reserve: paid.
    let (fx, _) = live_call_closing(true, CLOSING).await;
    let reserved = hold(&fx).reserved_msat;
    let closing = reserved - u64::from(MINUTES) * BLOCK;
    assert_eq!(closing, CLOSING, "the hangup quote at admission is the closing reserve");
    let token = expire(&fx).await;
    let (money, left) = (fx.wallet.money(), fx.wallet.left());
    fx.wallet.fee.store(FEE, Ordering::SeqCst);
    let (status, body) = hangup_with_fee(&fx, &token, closing - FEE, FEE).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.wallet.money(), money + 1);
    assert_eq!(fx.wallet.left(), left + closing - FEE, "the hangup price left the wallet");
    let limit = *fx.wallet.fee_limits.lock().unwrap().last().unwrap();
    assert!(limit <= FEE && closing - FEE + limit <= closing, "routing limit {limit}");
    // Settled at the price; the proof the callee got carries the price.
    let sent = operation(&fx, &body).await;
    assert_eq!((sent.state.as_str(), sent.settled_msat), ("sent", (closing - FEE) as i64));
    let hangups = fx.state.storage.get_node_messages_of_kind(&fx.state.identity.node_id().to_hex(), 403, 10, None).await.unwrap();
    assert_eq!(hangups.iter().map(|h| h.payment_proof.amount_msat).collect::<Vec<_>>(), [closing - FEE]);
    // The hold closed and the expired grant left with it: nothing more is held.
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none());
    assert!(liability(&fx).is_empty(), "{:?}", liability(&fx));
    assert_eq!(reserved, u64::from(MINUTES) * BLOCK + closing);

    // One msat above the reserve: refused, unpaid, nothing reserved, the call live.
    let (fx, _) = live_call_closing(true, CLOSING).await;
    let token = expire(&fx).await;
    let (money, left) = (fx.wallet.money(), fx.wallet.left());
    // The route would carry the allowed fee: only the reserve refuses it.
    fx.wallet.fee.store(FEE, Ordering::SeqCst);
    let dispatched = fx.wallet.fee_limits.lock().unwrap().len();
    let before = liability(&fx);
    let (status, body) = hangup_with_fee(&fx, &token, closing - FEE + 1, FEE).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_closing_refusal(&body);
    assert_eq!(fx.wallet.money(), money, "nothing was paid: {body}");
    assert_eq!(fx.wallet.left(), left);
    assert_eq!(fx.wallet.fee_limits.lock().unwrap().len(), dispatched, "the wallet was never asked");
    assert_eq!(hold(&fx).spent_msat, BLOCK);
    assert_eq!(liability(&fx), before, "the refused hangup reserved nothing");
    let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    assert_eq!(entry.phase, konsensus_core::payloads::call::Phase::Live);
    assert!(entry.pending.is_none(), "the refused hangup holds no reservation");
}
