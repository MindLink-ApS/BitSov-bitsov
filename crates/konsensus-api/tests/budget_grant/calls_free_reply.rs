//! Sending side of free call replies (`[calls] call_reply_free_v1`): the
//! callee's answer and its decline go out at no charge, with no grant debit,
//! no reservation and no invoice, only to a caller that advertised the switch
//! and only for a call this node is ringing for. Everything else, and the
//! same fixtures with the switch off, keep the paid path.
use super::*;

const FREE: &str = "Custom(\"call_reply_free_v1\")";

/// A paired app on a node with free replies `on`, ringing for an incoming
/// call `call_id` from the contact, which advertises `peer_caps`.
async fn ringing(on: bool, peer_caps: &[&str], call_id: &str) -> (Fx, String, Arc<ConnectedStubTransport>) {
    let (fx, token, transport) = awaiting_device(on, peer_caps, call_id).await;
    let fetched = fx.state.storage.call_get(&fx.peer, call_id).await.unwrap().unwrap()
        .device_fetched(konsensus_api::calls::now_ms()).unwrap();
    fx.state.storage.call_put(&fx.peer, call_id, &fetched).await.unwrap();
    (fx, token, transport)
}

/// As [`ringing`], before any device fetched the offer: the call waits for one.
async fn awaiting_device(on: bool, peer_caps: &[&str], call_id: &str) -> (Fx, String, Arc<ConnectedStubTransport>) {
    let (mut fx, token) = prepared().await;
    let peer = fx.peer;
    let transport = Arc::new(ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| {
            let bolt11 = create_test_bolt11(amount);
            let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
            Some(konsensus_api::state::InvoiceResponseData {
                payment_hash: invoice.payment_hash().to_string(), recipient: peer, bolt11,
            })
        }));
    transport.advertise(peer, peer_caps);
    fx.state = Arc::new(AppState { transport: transport.clone(), call_reply_free: on, ..(*fx.state).clone() });
    konsensus_api::calls::admit_incoming(fx.state.storage.as_ref(), fx.state.identity.node_id(), &fx.peer, 400,
        Some(&json!({"v": 1, "call_id": call_id, "sdp": "offer", "media": "audio"}).to_string())).await.unwrap();
    assert_eq!(fx.state.storage.call_get(&fx.peer, call_id).await.unwrap().unwrap().phase, Phase::AwaitingDevice);
    (fx, token, transport)
}

fn reply(fx: &Fx, kind: u16, call_id: &str, operation_id: &str) -> Value {
    let plaintext = if kind == 401 {
        json!({"v": 1, "call_id": call_id, "sdp": "answer"})
    } else {
        json!({"v": 1, "call_id": call_id, "reason": "declined"})
    };
    json!({
        "operation_id": operation_id, "recipient": fx.peer.to_hex(), "kind": kind,
        "plaintext": plaintext.to_string(), "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })
}

/// Everything that could show a charge: payments dispatched, invoices asked
/// for, the grant's spending and its open reservations.
fn ledger(fx: &Fx, transport: &ConnectedStubTransport) -> (usize, usize, u64, u64, usize) {
    let grant = fx.service.grant_view_for(&fx.client_id).unwrap();
    let pending = fx.service.snapshot().grants.iter()
        .filter_map(|g| g.budget.as_ref()).map(|b| b.pending.len()).sum();
    (fx.wallet.money(), transport.raw_frames.lock().unwrap().len(), grant.used_msat, fx.wallet.left(), pending)
}

fn sent(transport: &ConnectedStubTransport, kind: u16) -> Vec<konsensus_core::UkmEnvelope> {
    transport.sent_envelopes.lock().unwrap().iter().filter(|(_, e)| e.kind == kind).map(|(_, e)| e.clone()).collect()
}

#[tokio::test]
async fn offer_bound_answer_and_decline_cost_zero_without_grant() {
    for (kind, call_id) in [(401u16, CALL), (403, "22222222333344445555666666666666")] {
        let (fx, token, transport) = ringing(true, &[FREE], call_id).await;
        let before = ledger(&fx, &transport);
        let operation = uuid::Uuid::new_v4().to_string();
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, call_id, &operation)).await;
        assert_eq!(status, StatusCode::OK, "{kind}: {body}");
        assert_eq!(body["amount_msat"], 0, "{kind}: {body}");
        assert_eq!(ledger(&fx, &transport), before, "{kind}: a free reply moved money, asked an invoice or touched the grant");
        let out = sent(&transport, kind);
        assert_eq!(out.len(), 1, "{kind}");
        assert_eq!(out[0].payment_proof.amount_msat, 0);
        assert_eq!(out[0].references, vec![konsensus_core::payloads::call::free_reply_reference(call_id)]);
        let entry = fx.state.storage.call_get(&fx.peer, call_id).await.unwrap().unwrap();
        assert_eq!(entry.phase, if kind == 401 { Phase::Live } else { Phase::Ended }, "{kind}");

        // Reconciling the journal later never turns the free reply into a
        // payment or undoes it.
        konsensus_api::handlers::messages::reconcile_operations(&fx.state).await.unwrap();
        assert_eq!(ledger(&fx, &transport), before, "{kind}: reconciliation charged a free reply");
        assert_eq!(fx.state.storage.call_get(&fx.peer, call_id).await.unwrap().unwrap().phase, entry.phase);
        // A double tap is the same operation: still one reply, still free.
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, kind, call_id, &operation)).await;
        assert!(status == StatusCode::OK || status.is_client_error(), "{kind}: {status} {body}");
        assert_eq!(ledger(&fx, &transport), before, "{kind}: a repeated tap charged");
        let ids: std::collections::HashSet<_> = sent(&transport, kind).iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 1, "{kind}: a repeated tap made a second reply");
        // A new tap after the call left ringing is refused, not paid.
        let (status, _) = send_request(&fx, &token, 7_000, reply(&fx, kind, call_id, &uuid::Uuid::new_v4().to_string())).await;
        assert_ne!(status, StatusCode::OK);
        assert_eq!(ledger(&fx, &transport), before);
    }
}

#[tokio::test]
async fn a_free_reply_that_cannot_be_sent_is_never_retried_as_paid() {
    let (fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let before = ledger(&fx, &transport);
    // The caller went offline after advertising: nothing is paid instead.
    transport.connected.lock().unwrap().clear();
    let operation = uuid::Uuid::new_v4().to_string();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &operation)).await;
    assert_ne!(body["amount_msat"].as_u64().unwrap_or(0), 7_000, "{status} {body}");
    assert_eq!(ledger(&fx, &transport), before, "{status} {body}");
    let (_, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &operation)).await;
    assert_eq!(ledger(&fx, &transport), before, "a retry of a free reply paid: {body}");
}

#[tokio::test]
async fn without_both_switches_replies_are_paid_as_before() {
    // Switch off here (peer advertises), peer without it (switch on here):
    // the legacy paid answer, same fixture, same price, same invoice.
    for (on, caps) in [(false, &[FREE][..]), (true, &[][..]), (false, &[][..])] {
        let (fx, token, transport) = ringing(on, caps, CALL).await;
        let money = fx.wallet.money();
        let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &uuid::Uuid::new_v4().to_string())).await;
        assert_eq!(status, StatusCode::OK, "on={on} caps={caps:?}: {body}");
        assert_eq!(fx.wallet.money(), money + 1, "on={on} caps={caps:?}: the answer must be paid");
        let out = sent(&transport, 401);
        assert_eq!(out.len(), 1);
        assert!(out[0].payment_proof.amount_msat > 0);
        assert!(out[0].references.is_empty());
    }
    // A hangup that is not a decline is never free, even with both switches.
    let (fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let money = fx.wallet.money();
    let request = json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(), "kind": 403,
        "plaintext": json!({"v": 1, "call_id": CALL, "reason": "busy"}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    });
    let (status, body) = send_request(&fx, &token, 7_000, request).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.wallet.money(), money + 1);
    assert!(sent(&transport, 403)[0].payment_proof.amount_msat > 0);
}

#[tokio::test]
async fn status_advertises_free_call_replies_only_when_on() {
    for on in [false, true] {
        let (mut fx, _token) = prepared().await;
        fx.state = Arc::new(AppState { call_reply_free: on, ..(*fx.state).clone() });
        let owner = auth_header(&fx.state);
        let (status, body) = fx.call("GET", "/api/v1/status", None, Some(owner.trim_start_matches("Bearer "))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let listed = body["api_capabilities"].as_array().unwrap().contains(&json!("call_reply_free_v1"));
        assert_eq!(listed, on);
    }
}

#[tokio::test]
async fn a_decline_while_the_call_waits_for_a_device_is_free_too() {
    let (fx, token, transport) = awaiting_device(true, &[FREE], CALL).await;
    let before = ledger(&fx, &transport);
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 403, CALL, &uuid::Uuid::new_v4().to_string())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 0, "{body}");
    assert_eq!(ledger(&fx, &transport), before, "a decline before any device fetched the call charged");
    let out = sent(&transport, 403);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].payment_proof.amount_msat, 0);
    assert_eq!(out[0].references, vec![konsensus_core::payloads::call::free_reply_reference(CALL)]);
    assert_eq!(fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap().phase, Phase::Ended);
    // With the switch off the same decline is paid, as before.
    let (fx, token, transport) = awaiting_device(false, &[FREE], CALL).await;
    let money = fx.wallet.money();
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 403, CALL, &uuid::Uuid::new_v4().to_string())).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.wallet.money(), money + 1);
    assert!(sent(&transport, 403)[0].payment_proof.amount_msat > 0);
}

#[tokio::test]
async fn an_answer_after_the_ring_window_is_refused_not_paid() {
    let (fx, token, transport) = ringing(true, &[FREE], CALL).await;
    let mut entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    entry.deadline_ms = konsensus_api::calls::now_ms().saturating_sub(1);
    fx.state.storage.call_put(&fx.peer, CALL, &entry).await.unwrap();
    let before = ledger(&fx, &transport);
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &uuid::Uuid::new_v4().to_string())).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(ledger(&fx, &transport), before, "a late answer was paid: {body}");
    assert!(sent(&transport, 401).is_empty());
}

#[tokio::test]
async fn an_unreadable_call_state_refuses_the_reply_instead_of_paying_it() {
    let (mut fx, token, transport) = ringing(true, &[FREE], CALL).await;
    // Move the ringing call into storage whose second read of it fails: the
    // first read reserves the reply, the second decides whether it is free.
    let store = Arc::new(common::MemStorage::new());
    let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    konsensus_storage::Storage::call_put(store.as_ref(), &fx.peer, CALL, &entry).await.unwrap();
    let failing = Arc::clone(&store);
    *store.call_get_hook.lock().unwrap() = Some(Box::new(move || {
        let failing2 = Arc::clone(&failing);
        *failing.call_get_hook.lock().unwrap() = Some(Box::new(move || {
            *failing2.fail_call_get_for.lock().unwrap() = Some(CALL.into());
        }));
    }));
    fx.state = Arc::new(AppState { storage: store.clone(), ..(*fx.state).clone() });
    let before = ledger(&fx, &transport);
    let (status, body) = send_request(&fx, &token, 7_000, reply(&fx, 401, CALL, &uuid::Uuid::new_v4().to_string())).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "call_reply_unavailable", "{body}");
    assert_eq!(ledger(&fx, &transport), before, "an unreadable call state paid the reply: {body}");
    assert!(sent(&transport, 401).is_empty());
}
