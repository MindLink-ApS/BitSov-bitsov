mod common;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use konsensus_api::{
    auth::{self, Scope},
    AppState,
};
use konsensus_core::{
    payloads::call::{CallEntry, Pending, Phase, Side},
    NodeId,
};
use konsensus_storage::{OutboxOperation, SqliteStorage, Storage};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

async fn fixture() -> (Arc<AppState>, Arc<SqliteStorage>) {
    let store = Arc::new(SqliteStorage::in_memory().await.unwrap());
    (common::test_state_with_storage(store.clone()), store)
}

async fn get(state: &Arc<AppState>, query: &str, auth: Option<String>) -> (StatusCode, String) {
    let mut req = Request::builder().uri(format!("/api/v1/calls{query}"));
    if let Some(auth) = auth {
        req = req.header("authorization", auth);
    }
    let response = common::test_router(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    (
        response.status(),
        String::from_utf8(
            to_bytes(response.into_body(), 65536)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap(),
    )
}

fn entry(phase: Phase, side: Side, deadline_ms: u64, op: Option<&str>) -> CallEntry {
    CallEntry {
        phase,
        side,
        deadline_ms,
        paid_until_ms: None, next_block_seq: 0, end_reason: None,
        pending: op.map(|op| Pending {
            operation_id: op.into(),
            kind: 400,
            request_hash: "hash".into(),
        }),
    }
}

#[tokio::test]
async fn open_calls_keep_expired_unresolved_admission_and_isolate_peers_without_writes() {
    let (mut state, store) = fixture().await;
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let transport = Arc::new(common::ConnectedStubTransport::new(
        Vec::new(),
        state.invoice_requests.clone(),
    ));
    Arc::get_mut(&mut state).unwrap().lightning = wallet.clone();
    Arc::get_mut(&mut state).unwrap().transport = transport.clone();
    let mut events = state.ws_broadcast.subscribe();
    let mut delivery = state.ws_delivery_broadcast.subscribe();
    let peer = NodeId::from_bytes([11; 32]);
    let other = NodeId::from_bytes([12; 32]);
    let future = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap() + 60_000;
    let mut op =
        OutboxOperation::prepared("pending-offer".into(), peer.to_hex(), 400, "hash".into());
    op.state = "payment_unknown".into();
    op.created_at = 123456;
    store.insert_outbox_operation(&op).await.unwrap();
    let rows = [
        (
            "expired",
            entry(Phase::Reserved, Side::Caller, 1, Some("pending-offer")),
        ),
        (
            "incoming",
            entry(Phase::Ringing, Side::Callee, future, None),
        ),
        ("live", entry(Phase::Live, Side::Caller, future, None)),
        ("ended", entry(Phase::Ended, Side::Caller, future, None)),
        ("expired-paid", entry(Phase::Ringing, Side::Caller, 1, None)),
    ];
    for (id, e) in &rows {
        store.call_put(&peer, id, e).await.unwrap();
    }
    store
        .call_put(
            &other,
            "other",
            &entry(Phase::Ringing, Side::Callee, future, None),
        )
        .await
        .unwrap();
    // SQLite itself rejects any attempted write, including recovery/expiry cleanup.
    sqlx::query("PRAGMA query_only = ON")
        .execute(store.pool())
        .await
        .unwrap();
    for _ in 0..2 {
        let (status, body) = get(
            &state,
            &format!("?peer={peer}"),
            Some(common::auth_header(&state)),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!([
                {"id":"expired", "state":"ended", "direction":"outgoing", "unresolved_paid_admission":true, "created":123456, "op_id":"pending-offer", "paid_until_ms":null, "next_block_seq":0, "next_block_due_ms":null},
                {"id":"incoming", "state":"ringing", "direction":"incoming", "unresolved_paid_admission":false, "created":null, "op_id":null, "paid_until_ms":null, "next_block_seq":0, "next_block_due_ms":null},
                {"id":"live", "state":"live", "direction":"outgoing", "unresolved_paid_admission":false, "created":null, "op_id":null, "paid_until_ms":null, "next_block_seq":0, "next_block_due_ms":future - 10_000}
            ])
        );
    }
    for (id, e) in &rows {
        assert_eq!(store.call_get(&peer, id).await.unwrap().as_ref(), Some(e));
    }
    assert_eq!(
        store.get_outbox_operation(&op.operation_id).await.unwrap(),
        Some(op)
    );
    assert_eq!(
        store
            .call_counts(&peer, future - 60_000)
            .await
            .unwrap()
            .open_peer,
        3
    );
    let (status, body) = get(
        &state,
        &format!("?peer={other}"),
        Some(common::auth_header(&state)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()[0]["id"],
        "other"
    );
    let (status, body) = get(
        &state,
        &format!("?peer={}", NodeId::from_bytes([13; 32])),
        Some(common::auth_header(&state)),
    )
    .await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, "[]"));
    use konsensus_core::traits::lightning::LightningProvider;
    assert!(wallet.list_payments(100).await.unwrap().is_empty());
    assert!(transport.sent_envelopes.lock().unwrap().is_empty());
    assert!(transport.raw_frames.lock().unwrap().is_empty());
    assert!(matches!(
        events.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        delivery.try_recv(),
        Err(tokio::sync::broadcast::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn open_calls_are_bounded_and_prioritize_unresolved_blockers() {
    let (state, store) = fixture().await;
    let peer = NodeId::from_bytes([11; 32]);
    let future = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap() + 60_000;
    // Seed beyond normal admission bounds to prove the read is independently bounded.
    for n in 0..10 {
        store
            .call_put(
                &peer,
                &format!("a{n}"),
                &entry(Phase::Live, Side::Caller, future, None),
            )
            .await
            .unwrap();
    }
    store
        .call_put(
            &peer,
            "z-blocker",
            &entry(Phase::Reserved, Side::Caller, 1, Some("missing-journal")),
        )
        .await
        .unwrap();
    let (status, body) = get(
        &state,
        &format!("?peer={peer}"),
        Some(common::auth_header(&state)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["id"], "z-blocker");
    assert_eq!(rows[0]["unresolved_paid_admission"], true);
    assert_eq!(rows[0]["created"], Value::Null);
    assert_eq!(rows[0]["op_id"], "missing-journal");
}

#[tokio::test]
async fn open_calls_require_owner_read_scope_and_fixed_peer_errors() {
    let (state, _) = fixture().await;
    let query = format!("?peer={}", NodeId::from_bytes([11; 32]));
    let token = |sub: &str, scopes| {
        Some(format!(
            "Bearer {}",
            auth::create_token(sub, &state.jwt_secret, scopes).unwrap()
        ))
    };
    assert_eq!(get(&state, &query, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(
        get(&state, &query, Some("Bearer invalid".into())).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get(
            &state,
            &query,
            token(&state.identity.node_id().to_hex(), vec![Scope::Spend])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(
            &state,
            &query,
            token(&NodeId::from_bytes([99; 32]).to_hex(), vec![Scope::Read])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(
            &state,
            &query,
            token(&state.identity.node_id().to_hex(), vec![Scope::Read])
        )
        .await
        .0,
        StatusCode::OK
    );
    for query in [
        "",
        "?peer=",
        "?peer=not-a-node",
        "?peer=ab",
        "?peer=%3Csecret%3E",
        "?peer=a&peer=b",
    ] {
        let (status, body) = get(&state, query, Some(common::auth_header(&state))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap()["error"],
            "invalid peer id"
        );
    }
}

#[tokio::test]
async fn open_calls_do_not_invent_creation_metadata_from_unrelated_operations() {
    let inner = SqliteStorage::in_memory().await.unwrap();
    let store = Arc::new(konsensus_storage::EncryptedStorage::new(inner, &[7; 32]));
    let state = common::test_state_with_storage(store.clone());
    let peer = NodeId::from_bytes([11; 32]);
    let other = NodeId::from_bytes([12; 32]);
    for (id, recipient, kind, hash) in [
        ("wrong-peer", other.to_hex(), 400, "hash"),
        ("wrong-request", peer.to_hex(), 400, "different"),
        ("wrong-kind", peer.to_hex(), 401, "hash"),
        ("answer", peer.to_hex(), 401, "hash"),
    ] {
        let op = OutboxOperation::prepared(id.into(), recipient, kind, hash.into());
        store.insert_outbox_operation(&op).await.unwrap();
        let mut call = entry(Phase::Ringing, Side::Callee, 1, Some(id));
        if id == "answer" {
            call.pending.as_mut().unwrap().kind = 401;
        }
        store.call_put(&peer, id, &call).await.unwrap();
    }
    let (status, body) = get(
        &state,
        &format!("?peer={peer}"),
        Some(common::auth_header(&state)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        assert_eq!(row["created"], Value::Null);
        assert_eq!(row["op_id"], row["id"]);
        assert_eq!(row["unresolved_paid_admission"], true);
        assert_eq!(row["state"], "ended");
    }
}

#[tokio::test]
async fn expired_unpaid_reservations_still_block_admission_after_listing() {
    let (state, store) = fixture().await;
    let peer = NodeId::from_bytes([11; 32]);
    for n in 0..4 {
        store
            .call_put(
                &peer,
                &format!("{n:032x}"),
                &entry(Phase::Reserved, Side::Caller, 1, Some(&format!("op-{n}"))),
            )
            .await
            .unwrap();
    }
    let (status, body) = get(
        &state,
        &format!("?peer={peer}"),
        Some(common::auth_header(&state)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let rows: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(rows.len(), 4);
    assert!(rows
        .iter()
        .all(|row| row["unresolved_paid_admission"] == true && row["state"] == "ended"));
    let offer =
        r#"{"v":1,"call_id":"ffffffffffffffffffffffffffffffff","media":"audio","sdp":"v=0"}"#;
    let refusal = konsensus_api::calls::reserve_outgoing(
        store.as_ref(),
        state.identity.node_id(),
        &peer,
        400,
        offer,
        "new-op",
        "new-hash",
    )
    .await
    .unwrap_err();
    assert!(refusal.to_string().contains("too many calls"), "{refusal}");
    // The same admission remains available for another peer.
    konsensus_api::calls::reserve_outgoing(
        store.as_ref(),
        state.identity.node_id(),
        &NodeId::from_bytes([12; 32]),
        400,
        offer,
        "new-op",
        "new-hash",
    )
    .await
    .unwrap();
}
