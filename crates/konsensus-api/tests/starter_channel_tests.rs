mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use konsensus_api::{
    auth,
    pairing::{self, PairingService},
};
use konsensus_storage::{SqliteStorage, Storage};
use std::sync::Arc;
use tower::ServiceExt;

fn paired(
    state: &mut konsensus_api::AppState,
    dir: &std::path::Path,
    scopes: Vec<auth::Scope>,
) -> String {
    let service = Arc::new(
        PairingService::open(
            dir,
            pairing::identity_fingerprint(&state.identity.node_id().to_hex()),
            false,
        )
        .unwrap()
        .without_stdout_code(),
    );
    let key = SigningKey::from_bytes(&[42; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let outcome = service.request_pairing("starter test", &pubkey).unwrap();
    let challenge =
        std::fs::read(service.dir().join(format!("challenge-{}", outcome.pair_id))).unwrap();
    let sig = hex::encode(
        key.sign(&PairingService::proof_message(
            &outcome.pair_id,
            &pubkey,
            &challenge,
        ))
        .to_bytes(),
    );
    let client = service
        .confirm_pairing(&outcome.pair_id, &sig, scopes)
        .unwrap();
    let challenge = service.issue_token_challenge(&client.client_id).unwrap();
    let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let token = service
        .issue_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            &client.client_id,
            &challenge,
            &sig,
        )
        .unwrap()
        .token;
    state.pairing = Some(service);
    format!("Bearer {token}")
}
fn post(token: &str, id: uuid::Uuid) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/v1/onboarding/starter-channel")
        .header("authorization", token)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"request_id":id}).to_string()))
        .unwrap()
}
#[tokio::test]
async fn paired_receive_is_required_before_any_persistence() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = (*test_state()).clone();
    state.storage = db.clone();
    let id = uuid::Uuid::new_v4();
    let admin = auth_header(&state);
    let app = test_router(Arc::new(state.clone()));
    assert_eq!(
        app.oneshot(post(&admin, id)).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let dir = tempfile::tempdir().unwrap();
    let token = paired(&mut state, dir.path(), vec![auth::Scope::Read]);
    assert_eq!(
        test_router(Arc::new(state.clone()))
            .oneshot(post(&token, id))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let dir2 = tempfile::tempdir().unwrap();
    let token = paired(&mut state, dir2.path(), pairing::default_pairing_scopes());
    let response = test_router(Arc::new(state))
        .oneshot(post(&token, id))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST); // disabled, proven no dispatch
    assert!(db.starter_request_current().await.unwrap().is_none());
}

use konsensus_core::traits::lightning::*;
struct ReadyLn;
#[async_trait::async_trait]
impl LightningProvider for ReadyLn {
    async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        panic!("newcomer API must not create invoices")
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        panic!("newcomer API must not spend")
    }
    async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        unimplemented!()
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    fn starter_network(&self) -> Option<String> {
        Some("regtest".into())
    }
}
#[tokio::test]
async fn paired_create_replay_conflict_and_changed_hub_are_durable() {
    use konsensus_api::handlers::starter_channel::{StarterConfig, StarterSettings};
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = (*test_state()).clone();
    state.storage = db.clone();
    state.lightning = Arc::new(ReadyLn);
    state.starter = StarterSettings {
        config: StarterConfig {
            enabled: true,
            hub_node_id: "08".repeat(32),
            allow_mainnet: false,
        },
        network: "regtest".into(),
        hub_ln_pubkey: "03".repeat(33),
        hub_ln_address: "127.0.0.1:9735".into(),
        hub_whitelisted: true,
        trust_no_reserve: true,
    };
    let hub = konsensus_core::NodeId::from_bytes([8; 32]);
    let transport = Arc::new(ConnectedStubTransport::new(
        vec![hub],
        Arc::clone(&state.invoice_requests),
    ));
    // NoiseTransport::peer_info exposes Capability via its Debug representation.
    transport.advertise(hub, &["Custom(\"starter_hub_v1\")"]);
    state.transport = transport.clone();
    let dir = tempfile::tempdir().unwrap();
    let token = paired(&mut state, dir.path(), pairing::default_pairing_scopes());
    let id = uuid::Uuid::new_v4();
    let app = test_router(Arc::new(state.clone()));
    let first = app.clone().oneshot(post(&token, id)).await.unwrap();
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    let replay = app.clone().oneshot(post(&token, id)).await.unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(first.into_body(), 10000)
            .await
            .unwrap(),
        axum::body::to_bytes(replay.into_body(), 10000)
            .await
            .unwrap()
    );
    assert_eq!(
        app.clone()
            .oneshot(post(&token, uuid::Uuid::new_v4()))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        app.clone()
            .oneshot(post(&token, uuid::Uuid::nil()))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let get = Request::builder()
        .uri(format!("/api/v1/onboarding/starter-channel/{id}"))
        .header("authorization", &token)
        .body(Body::empty())
        .unwrap();
    assert_eq!(app.oneshot(get).await.unwrap().status(), StatusCode::OK);
    state.starter.config.hub_node_id = "09".repeat(32);
    assert_eq!(
        test_router(Arc::new(state))
            .oneshot(post(&token, id))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(
        db.starter_request_current()
            .await
            .unwrap()
            .unwrap()
            .send_attempts,
        0
    );
}
#[test]
fn starter_startup_refuses_mainnet_testnet_unknown_and_non_ldk() {
    use konsensus_api::handlers::starter_channel::StarterConfig;
    let mut cfg = StarterConfig {
        enabled: true,
        ..Default::default()
    };
    for network in [
        Some("bitcoin"),
        Some("mainnet"),
        Some("testnet"),
        None,
        Some("garbage"),
    ] {
        assert!(cfg.validate(network, true).is_err());
    }
    assert!(cfg.validate(Some("signet"), false).is_err());
    assert!(cfg.validate(Some("signet"), true).is_ok());
    assert!(cfg.validate(Some("regtest"), true).is_ok());
    cfg.enabled = false;
    cfg.allow_mainnet = true;
    assert!(cfg.validate(Some("signet"), true).is_err());
}

#[tokio::test]
async fn error_metadata_no_persistence_and_revoked_pairing() {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = (*test_state()).clone();
    state.storage = db.clone();
    state.lightning = Arc::new(ReadyLn);
    let dir = tempfile::tempdir().unwrap();
    let token = paired(&mut state, dir.path(), pairing::default_pairing_scopes());
    for reason in [
        "starter_disabled",
        "network_not_allowed",
        "hub_not_configured",
        "trust_no_reserve_required",
    ] {
        state.starter.config.enabled = reason != "starter_disabled";
        state.starter.network = if reason == "network_not_allowed" {
            "bitcoin"
        } else {
            "regtest"
        }
        .into();
        if reason == "trust_no_reserve_required" {
            state.starter.config.hub_node_id = "08".repeat(32);
            state.starter.hub_ln_pubkey = "03".repeat(33);
            state.starter.hub_ln_address = "127.0.0.1:9735".into();
            state.starter.hub_whitelisted = true;
        }
        let response = test_router(Arc::new(state.clone()))
            .oneshot(post(&token, uuid::Uuid::new_v4()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 10000)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["code"], "not_dispatched");
        assert_eq!(body["reason"], reason);
        assert_eq!(body["retry_allowed"], true);
        assert!(db.starter_request_current().await.unwrap().is_none());
    }
    let claims =
        auth::validate_token(token.strip_prefix("Bearer ").unwrap(), &state.jwt_secret).unwrap();
    state
        .pairing
        .as_ref()
        .unwrap()
        .bump_epoch(&claims.cid.unwrap())
        .unwrap();
    assert_eq!(
        test_router(Arc::new(state))
            .oneshot(post(&token, uuid::Uuid::new_v4()))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn post_replay_rearms_current_child_but_get_does_not() {
    use konsensus_storage::starter_request::StarterRequest;
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = (*test_state()).clone();
    state.storage = db.clone();
    state.starter.config.hub_node_id = "08".repeat(32);
    state.starter.hub_ln_pubkey = "03".repeat(33);
    state.starter.network = "regtest".into();
    let dir = tempfile::tempdir().unwrap();
    let token = paired(&mut state, dir.path(), pairing::default_pairing_scopes());
    let id = uuid::Uuid::new_v4();
    let mut root = StarterRequest::new(
        id.to_string(),
        state.starter.config.hub_node_id.clone(),
        state.starter.hub_ln_pubkey.clone(),
        "regtest".into(),
        100,
    );
    db.starter_request_create(&root).await.unwrap();
    root.state = "refused".into();
    root.retry_allowed = true;
    root.retry_after_unix = Some(700);
    db.starter_request_save(&root).await.unwrap();
    let mut child = db
        .starter_request_retry(&id.to_string(), 700)
        .await
        .unwrap();
    child.send_attempts = 8;
    child.last_sent_at = Some(2000);
    db.starter_request_save(&child).await.unwrap();
    let app = test_router(Arc::new(state));
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/onboarding/starter-channel/{id}"))
                .header("authorization", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 10000)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body["operation_id"], child.request_id);
    assert_eq!(body["request_id"], id.to_string());
    assert_eq!(
        db.starter_request_current()
            .await
            .unwrap()
            .unwrap()
            .send_attempts,
        8
    );
    assert_eq!(
        app.oneshot(post(&token, id)).await.unwrap().status(),
        StatusCode::OK
    );
    let rearmed = db.starter_request_current().await.unwrap().unwrap();
    assert_eq!(rearmed.request_id, child.request_id);
    assert_eq!(rearmed.send_attempts, 0);
    assert_eq!(rearmed.original_request_id, Some(id.to_string()));
}
