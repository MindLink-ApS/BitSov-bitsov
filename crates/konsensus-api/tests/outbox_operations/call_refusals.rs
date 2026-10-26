use super::*;
use konsensus_core::payloads::call::{CallEntry, Pending, Phase, Side, MAX_OPEN_CALLS_PER_PEER};

const CALL: &str = "0123456789abcdef0123456789abcdef";

fn signal(kind: u16) -> String {
    let mut body = serde_json::json!({"v": 1, "call_id": CALL});
    match kind {
        400 => {
            body["media"] = "audio".into();
            body["sdp"] = "v=0".into();
        }
        401 => body["sdp"] = "v=0".into(),
        _ => unreachable!(),
    }
    body.to_string()
}

fn ringing() -> CallEntry {
    CallEntry {
        side: Side::Callee,
        phase: Phase::Ringing,
        deadline_ms: u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap() + 60_000,
        pending: None,
        paid_until_ms: None, next_block_seq: 0, end_reason: None,
    }
}

async fn post(f: &Fixture, kind: u16, plaintext: &str) -> (StatusCode, serde_json::Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&f.state))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"operation_id": f.id, "recipient": f.peer.to_hex(),
                "kind": kind, "plaintext": plaintext, "wait_ack_ms": 0})
            .to_string(),
        ))
        .unwrap();
    operation_reply(
        common::test_router(f.state.clone())
            .oneshot(request)
            .await
            .unwrap(),
    )
    .await
}

async fn assert_not_dispatched(f: &Fixture, kind: u16, plaintext: &str, reason: &str) {
    let (status, body) = post(f, kind, plaintext).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], reason, "{body}");
    assert!(f.db.get_outbox_operation(&f.id).await.unwrap().is_none());
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox_operations")
        .fetch_one(f.db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 0, "refusal must precede operation creation");
    assert_eq!(
        f.wallet.calls.load(Ordering::SeqCst),
        0,
        "no payment attempted"
    );
    assert!(f.wallet.list_payments(100).await.unwrap().is_empty());
    assert_eq!(body["code"], "not_dispatched", "{body}");
    assert!(body["error"]
        .as_str()
        .is_some_and(|error| !error.is_empty()));
}

#[tokio::test]
async fn call_id_used_is_not_dispatched() {
    let f = Fixture::new().await;
    f.db.call_put(&f.peer, CALL, &ringing()).await.unwrap();
    assert_not_dispatched(&f, 400, &signal(400), "call_id_used").await;
}

#[tokio::test]
async fn call_busy_is_not_dispatched() {
    let f = Fixture::new().await;
    for n in 0..MAX_OPEN_CALLS_PER_PEER {
        f.db.call_put(&f.peer, &format!("{n:032x}"), &ringing())
            .await
            .unwrap();
    }
    assert_not_dispatched(&f, 400, &signal(400), "call_busy").await;
}

#[tokio::test]
async fn call_signal_in_flight_is_not_dispatched() {
    let f = Fixture::new().await;
    let mut entry = ringing();
    entry.pending = Some(Pending {
        operation_id: uuid::Uuid::new_v4().to_string(),
        kind: 401,
        request_hash: "another-request".into(),
    });
    f.db.call_put(&f.peer, CALL, &entry).await.unwrap();
    assert_not_dispatched(&f, 401, &signal(401), "call_signal_in_flight").await;
}

#[tokio::test]
async fn call_signal_invalid_is_not_dispatched() {
    let f = Fixture::new().await;
    assert_not_dispatched(
        &f,
        400,
        r#"{"v":1,"call_id":"invalid"}"#,
        "call_signal_invalid",
    )
    .await;
}

#[tokio::test]
async fn call_not_live_is_not_dispatched() {
    let f = Fixture::new().await;
    assert_not_dispatched(&f, 401, &signal(401), "call_not_live").await;
}

#[tokio::test]
async fn an_expired_offer_with_an_uncertain_payment_is_not_claimed_not_dispatched() {
    let f = Fixture::new().await;
    let plaintext = signal(400);
    let digest = blake3::hash(
        &serde_json::to_vec(&(f.peer.to_hex(), 400u16, &plaintext, Vec::<String>::new())).unwrap(),
    )
    .to_hex()
    .to_string();
    let mut entry = ringing();
    entry.side = Side::Caller;
    entry.phase = Phase::Reserved;
    entry.deadline_ms = 1; // Expired, but its unresolved reservation must survive.
    entry.pending = Some(Pending {
        operation_id: f.id.clone(),
        kind: 400,
        request_hash: digest.clone(),
    });
    f.db.call_put(&f.peer, CALL, &entry).await.unwrap();
    let mut op =
        konsensus_storage::OutboxOperation::prepared(f.id.clone(), f.peer.to_hex(), 400, digest);
    op.state = "payment_unknown".into();
    assert!(f.db.insert_outbox_operation(&op).await.unwrap());

    let (status, body) = post(&f, 400, &plaintext).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], "call_id_used", "{body}");
    assert_ne!(
        body["code"], "not_dispatched",
        "a previous dispatch cannot be ruled out: {body}"
    );
    assert_eq!(f.op().await.state, "payment_unknown");
    assert_eq!(f.db.call_get(&f.peer, CALL).await.unwrap(), Some(entry));
    assert_eq!(
        f.wallet.calls.load(Ordering::SeqCst),
        0,
        "retry must not pay again"
    );
}
