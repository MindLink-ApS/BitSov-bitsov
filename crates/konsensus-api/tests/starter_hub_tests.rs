mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_storage::{starter::*, SqliteStorage, Storage};
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn operator_resolution_requires_admin_and_never_refunds_money() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let id = uuid::Uuid::new_v4();
    let invite = uuid::Uuid::new_v4();
    db.add_invite_issued(&konsensus_storage::InviteIssuedRecord {
        id: invite,
        invitee_pubkey: [2; 32],
        expiry_unix: 4_000_000_000,
        channel_size_hint_sats: None,
        addr: String::new(),
        max_fee_rate_sat_per_vb: None,
        channel_open_intent_expiry_unix: None,
        nonce: [3; 16],
        state: konsensus_storage::InviteState::Pending,
        created_at: 1,
        accepted_at: None,
        revoked_at: None,
    })
    .await
    .unwrap();
    let grant = StarterGrant::new(
        id.to_string(),
        "node".into(),
        "key".into(),
        "regtest".into(),
        invite.to_string(),
        100_000,
        10_000,
        100,
    );
    db.starter_update(
        StarterUpdate::Admit {
            grant,
            limits: StarterLimits {
                max_opens_per_day: 20,
                max_concurrent_opens: 4,
                lifetime_budget_sats: 2_000_000,
            },
        },
        Some(100),
    )
    .await
    .unwrap();
    db.starter_update(
        StarterUpdate::Claim {
            id: id.to_string(),
            operation: konsensus_storage::ChannelOpenOperation::pending(
                id.to_string(),
                "hash".into(),
                vec![],
            ),
        },
        Some(100),
    )
    .await
    .unwrap();
    db.resolve_channel_open_operation(&id.to_string(), "uncertain", None, None)
        .await
        .unwrap();
    let mut state = (*test_state()).clone();
    state.storage = db.clone();
    let state = Arc::new(state);
    let app = test_router(state.clone());
    let uri = format!("/api/v1/onboarding/starter-grants/{id}/resolve");
    let req = |auth: Option<String>, resolution: &str| {
        let mut req = Request::builder()
            .method("POST")
            .uri(&uri)
            .header("content-type", "application/json");
        if let Some(auth) = auth {
            req = req.header("authorization", auth);
        }
        req.body(Body::from(
            serde_json::json!({"resolution":resolution}).to_string(),
        ))
        .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(req(None, "charge"))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(req(Some(auth_header(&state)), "refund"))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(db.starter_counters().await.unwrap().inflight_count, 1);
    for _ in 0..2 {
        assert_eq!(
            app.clone()
                .oneshot(req(Some(auth_header(&state)), "charge"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
    let c = db.starter_counters().await.unwrap();
    assert_eq!((c.inflight_count, c.committed_sats), (0, 100_000));
}
