//! Sending side of call-bound hangups (`[calls] call_hangup_invoice_v1`): a
//! hangup of a live call asks the peer for an invoice bound to that call and
//! pays only that invoice. A peer that answers "call ended", or does not
//! answer, is paid nothing; the call ends here with a terminal outcome. With
//! the switch off, or to a peer without the capability, the hangup is paid
//! exactly as before.
use super::*;
use konsensus_core::payloads::call::Side;

const HANGUP_CAP: &str = "Custom(\"call_hangup_invoice_v1\")";

#[derive(Clone, Copy)]
enum Peer {
    /// Issues the bound invoice.
    Issues,
    /// Answers that the call already ended there.
    Ended,
    /// Never answers the hangup's invoice request.
    Silent,
}

async fn signal(fx: &Fx, token: &str, request: Value) -> (StatusCode, Value) {
    send_priced_with_closing(fx, token, 1_000, 7_000, 1_000, request).await
}

fn hangup_request(fx: &Fx, operation_id: &str) -> Value {
    json!({
        "operation_id": operation_id, "recipient": fx.peer.to_hex(), "kind": 403,
        "plaintext": json!({"v": 1, "call_id": CALL, "reason": "hangup"}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    })
}

/// A paid, answered call with block zero paid: live on this (caller) node.
async fn live_call(on: bool, caps: &[&str], answer_as: Peer) -> (Fx, String, Arc<ConnectedStubTransport>) {
    live_call_with(on, caps, move |purpose| {
        if !purpose.starts_with(konsensus_core::payloads::call::CALL_HANGUP_INVOICE_PREFIX) {
            return None;
        }
        match answer_as {
            Peer::Issues => None,
            Peer::Ended => Some(Some(konsensus_api::invoice_refusal::CALL_HANGUP_ENDED.into())),
            Peer::Silent => Some(None),
        }
    }).await
}

/// [`live_call`] with the peer answering invoice requests through `refuser`.
async fn live_call_with(on: bool, caps: &[&str], refuser: impl Fn(&str) -> Option<Option<String>> + Send + Sync + 'static)
    -> (Fx, String, Arc<ConnectedStubTransport>) {
    let (mut fx, token) = prepared().await;
    let peer = fx.peer;
    let transport = Arc::new(ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
        .with_invoice_responder(move |_, amount| Some(invoice_for(peer, amount)))
        .with_invoice_refuser(refuser));
    transport.advertise(peer, caps);
    fx.state = Arc::new(AppState { transport: transport.clone(), call_hangup_invoice: on, ..(*fx.state).clone() });
    let offer = json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": peer.to_hex(), "kind": 400,
        "plaintext": json!({"v": 1, "call_id": CALL, "sdp": "offer", "media": "audio"}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    });
    let (status, body) = signal(&fx, &token, offer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    answer(&fx).await;
    let block = json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": peer.to_hex(), "kind": 404,
        "plaintext": json!({"v": 1, "call_id": CALL, "seq": 0}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    });
    let (status, body) = signal(&fx, &token, block).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(fx.state.storage.call_get(&peer, CALL).await.unwrap().unwrap().phase, Phase::Live);
    (fx, token, transport)
}

fn hangup_purposes(transport: &ConnectedStubTransport) -> Vec<String> {
    transport.invoice_purposes.lock().unwrap().iter()
        .filter(|p| p.starts_with(konsensus_core::payloads::call::CALL_HANGUP_INVOICE_PREFIX)).cloned().collect()
}

fn hangups_sent(transport: &ConnectedStubTransport) -> Vec<konsensus_core::UkmEnvelope> {
    transport.sent_envelopes.lock().unwrap().iter().filter(|(_, e)| e.kind == 403).map(|(_, e)| e.clone()).collect()
}

async fn phase(fx: &Fx) -> Phase {
    fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap().phase
}

/// The field case: the callee's node already ended the call (its media
/// detached), and the caller hangs up.
#[tokio::test]
async fn a_hangup_for_a_call_the_callee_already_ended_pays_nothing_and_ends_honestly() {
    let (fx, token, transport) = live_call(true, &[HANGUP_CAP], Peer::Ended).await;
    let money = fx.wallet.money();
    let operation = uuid::Uuid::new_v4().to_string();
    let (status, body) = signal(&fx, &token, hangup_request(&fx, &operation)).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "call_ended", "{body}");
    assert_eq!(body["retry_allowed"], false, "a call that is over is not retryable: {body}");
    assert_ne!(body["state"], "rejected_retryable", "{body}");
    assert_eq!(fx.wallet.money(), money, "nothing was paid: {body}");
    assert!(hangups_sent(&transport).is_empty(), "no hangup was sent");
    assert_eq!(hangup_purposes(&transport), vec![konsensus_core::payloads::call::hangup_invoice_purpose(CALL, Side::Caller)]);
    // The call ended here too: no media, and its hold is released.
    assert_eq!(phase(&fx).await, Phase::Ended);
    assert!(!fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap().media_admitted(konsensus_api::calls::now_ms()));
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none_or(|hold| hold.closed));

    // A retry, of the same operation or a new one, pays nothing and asks nothing.
    for operation in [operation, uuid::Uuid::new_v4().to_string()] {
        let (status, body) = signal(&fx, &token, hangup_request(&fx, &operation)).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert_eq!(fx.wallet.money(), money, "a retry paid: {body}");
        assert_eq!(hangup_purposes(&transport).len(), 1, "a retry asked again: {body}");
        assert!(hangups_sent(&transport).is_empty());
    }
}

#[tokio::test]
async fn a_hangup_whose_invoice_request_goes_unanswered_ends_the_call_without_paying() {
    let (fx, token, transport) = live_call(true, &[HANGUP_CAP], Peer::Silent).await;
    let money = fx.wallet.money();
    let (status, body) = signal(&fx, &token, hangup_request(&fx, &uuid::Uuid::new_v4().to_string())).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], "call_hangup_unanswered", "{body}");
    assert_eq!(body["retry_allowed"], false, "{body}");
    assert_eq!(fx.wallet.money(), money, "nothing was paid: {body}");
    assert!(hangups_sent(&transport).is_empty());
    assert_eq!(phase(&fx).await, Phase::Ended);
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_none_or(|hold| hold.closed), "the hold is released");
    // A retry, of the same operation or a new one, asks nothing and pays nothing.
    let operation = body["operation_id"].as_str().unwrap().to_string();
    for operation in [operation, uuid::Uuid::new_v4().to_string()] {
        let (status, body) = signal(&fx, &token, hangup_request(&fx, &operation)).await;
        assert_ne!(status, StatusCode::OK, "{body}");
        assert_eq!(fx.wallet.money(), money, "a retry paid: {body}");
        assert_eq!(hangup_purposes(&transport).len(), 1, "a retry asked again: {body}");
        assert!(hangups_sent(&transport).is_empty());
    }
}

/// "Call ended" is honoured only as the answer to a call-bound hangup's own
/// invoice request. The same answer to a block's invoice request is an
/// ordinary refusal: nothing paid, the call stays live, the block retryable.
#[tokio::test]
async fn a_hangup_ended_answer_to_a_block_invoice_request_never_ends_the_call() {
    let (fx, token, transport) = live_call_with(true, &[HANGUP_CAP], |purpose| {
        purpose.starts_with(&format!("{}{CALL}:1", konsensus_core::payloads::call::CALL_BLOCK_INVOICE_PREFIX))
            .then(|| Some(konsensus_api::invoice_refusal::CALL_HANGUP_ENDED.into()))
    }).await;
    // Make block 1 due now, as 40 s of wall clock would.
    let now = konsensus_api::calls::now_ms();
    let entry = fx.state.storage.call_get(&fx.peer, CALL).await.unwrap().unwrap();
    fx.state.storage.call_put(&fx.peer, CALL, &konsensus_core::payloads::call::CallEntry {
        paid_until_ms: Some(now + 10_000), deadline_ms: now + 20_000, ..entry
    }).await.unwrap();
    let money = fx.wallet.money();
    let block = json!({
        "operation_id": uuid::Uuid::new_v4().to_string(), "recipient": fx.peer.to_hex(), "kind": 404,
        "plaintext": json!({"v": 1, "call_id": CALL, "seq": 1}).to_string(),
        "max_routing_fee_msat": 0, "wait_ack_ms": 0,
    });
    let (status, body) = signal(&fx, &token, block).await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_ne!(body["reason"], "call_ended", "{body}");
    assert_ne!(body["retry_allowed"], false, "an ordinary refusal stays retryable: {body}");
    assert_eq!(fx.wallet.money(), money, "nothing was paid");
    assert!(transport.invoice_purposes.lock().unwrap().iter().any(|p| p.ends_with(&format!("{CALL}:1"))), "the block asked");
    assert_eq!(phase(&fx).await, Phase::Live, "the peer's answer did not end the call");
    assert!(fx.service.call_spend_status(&fx.peer.to_hex(), CALL).is_some_and(|hold| !hold.closed), "the hold stays open");
}

#[tokio::test]
async fn a_live_call_hangup_is_paid_once_through_the_bound_invoice() {
    let (fx, token, transport) = live_call(true, &[HANGUP_CAP], Peer::Issues).await;
    let money = fx.wallet.money();
    let operation = uuid::Uuid::new_v4().to_string();
    let (status, body) = signal(&fx, &token, hangup_request(&fx, &operation)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 1_000, "the ordinary hangup price: {body}");
    assert_eq!(fx.wallet.money(), money + 1, "paid once");
    // Through the call-bound invoice only: never keysend, never a generic invoice.
    assert_eq!(hangup_purposes(&transport), vec![konsensus_core::payloads::call::hangup_invoice_purpose(CALL, Side::Caller)]);
    assert!(!transport.invoice_purposes.lock().unwrap().contains(&konsensus_core::gate::service_invoice_purpose(403)));
    let sent = hangups_sent(&transport);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].payment_proof.amount_msat, 1_000);
    assert_eq!(phase(&fx).await, Phase::Ended);

    // A retry never pays twice: the same operation is answered from its
    // journal, and a new one finds the call over.
    for operation in [operation, uuid::Uuid::new_v4().to_string()] {
        let _ = signal(&fx, &token, hangup_request(&fx, &operation)).await;
        assert_eq!(fx.wallet.money(), money + 1, "a retry paid again");
        assert_eq!(hangup_purposes(&transport).len(), 1, "a retry asked for another invoice");
        let ids: std::collections::HashSet<_> = hangups_sent(&transport).iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 1, "a retry made a second hangup");
    }
}

#[tokio::test]
async fn without_the_switch_or_the_peers_capability_the_hangup_is_paid_as_before() {
    // Switch off here (the peer advertises), the peer without it (switch on
    // here), and both: today's hangup, even to a peer that would answer "ended".
    for (on, caps) in [(false, &[HANGUP_CAP][..]), (true, &[][..]), (false, &[][..])] {
        let (fx, token, transport) = live_call(on, caps, Peer::Ended).await;
        let money = fx.wallet.money();
        let (status, body) = signal(&fx, &token, hangup_request(&fx, &uuid::Uuid::new_v4().to_string())).await;
        assert_eq!(status, StatusCode::OK, "on={on} caps={caps:?}: {body}");
        assert_eq!(fx.wallet.money(), money + 1, "on={on} caps={caps:?}: the hangup is paid as before");
        assert!(hangup_purposes(&transport).is_empty(), "on={on} caps={caps:?}: no call-bound invoice was asked for");
        assert_eq!(hangups_sent(&transport).len(), 1);
        assert_eq!(phase(&fx).await, Phase::Ended);
    }
}

#[tokio::test]
async fn status_advertises_call_bound_hangups_only_when_on() {
    for on in [false, true] {
        let (mut fx, _token) = prepared().await;
        fx.state = Arc::new(AppState { call_hangup_invoice: on, ..(*fx.state).clone() });
        let owner = auth_header(&fx.state);
        let (status, body) = fx.call("GET", "/api/v1/status", None, Some(owner.trim_start_matches("Bearer "))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let listed = body["api_capabilities"].as_array().unwrap().contains(&json!("call_hangup_invoice_v1"));
        assert_eq!(listed, on);
    }
}
