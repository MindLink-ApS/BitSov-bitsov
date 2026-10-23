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
struct ReadyLn(&'static str);
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
        Some(self.0.into())
    }
}
#[tokio::test]
async fn paired_create_replay_conflict_and_changed_hub_are_durable() {
    use konsensus_api::handlers::starter_channel::{StarterConfig, StarterSettings};
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = (*test_state()).clone();
    state.storage = db.clone();
    state.lightning = Arc::new(ReadyLn("regtest"));
    state.starter = StarterSettings {
        config: StarterConfig {
            enabled: true,
            hub_node_id: "08".repeat(32),
            hub_alias: None,
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
    state.audit_log =
        Arc::new(konsensus_api::AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let token = paired(&mut state, dir.path(), pairing::default_pairing_scopes());
    let id = uuid::Uuid::new_v4();
    let app = test_router(Arc::new(state.clone()));
    let (first, second) = tokio::join!(
        app.clone().oneshot(post(&token, id)),
        app.clone().oneshot(post(&token, id))
    );
    let first = first.unwrap();
    let second = second.unwrap();
    let (first, concurrent_replay) = if first.status() == StatusCode::ACCEPTED {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(first.status(), StatusCode::ACCEPTED);
    assert_eq!(concurrent_replay.status(), StatusCode::OK);
    let replay = app.clone().oneshot(post(&token, id)).await.unwrap();
    let entries: Vec<serde_json::Value> = std::fs::read_to_string(state.audit_log.path())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|e: &serde_json::Value| e["event"] == "starter.requested")
        .collect();
    assert_eq!(entries.len(), 1);
    let claims =
        auth::validate_token(token.strip_prefix("Bearer ").unwrap(), &state.jwt_secret).unwrap();
    assert_eq!(entries[0]["actor"], claims.cid.unwrap());
    assert_eq!(entries[0]["detail"]["request_id"], id.to_string());
    assert_eq!(replay.status(), StatusCode::OK);
    let concurrent_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(concurrent_replay.into_body(), 10000)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(concurrent_body["hub_configured"], true);
    assert!(concurrent_body.get("hub_alias").is_none());
    let spend_replay = Request::builder()
        .method("POST")
        .uri("/api/v1/onboarding/starter-channel")
        .header("authorization", &token)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"request_id":id,"push_sats":1}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(spend_replay).await.unwrap().status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    for path in [
        "/api/v1/onboarding/starter-channel".to_string(),
        format!("/api/v1/onboarding/starter-channel/{id}"),
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let body = axum::body::to_bytes(response.into_body(), 10000)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains(&state.starter.config.hub_node_id));
    }
    assert_eq!(
        axum::body::to_bytes(first.into_body(), 10000)
            .await
            .unwrap(),
        axum::body::to_bytes(replay.into_body(), 10000)
            .await
            .unwrap()
    );
    let conflicting_id = uuid::Uuid::new_v4();
    assert_eq!(
        app.clone()
            .oneshot(post(&token, conflicting_id))
            .await
            .unwrap()
            .status(),
        StatusCode::CONFLICT
    );
    assert!(!state
        .audit_log
        .starter_pending()
        .contains(&conflicting_id.to_string()));
    let conflict_entries: Vec<serde_json::Value> = std::fs::read_to_string(state.audit_log.path())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|e: &serde_json::Value| e["detail"]["request_id"] == conflicting_id.to_string())
        .collect();
    assert_eq!(conflict_entries.len(), 1);
    assert_eq!(conflict_entries[0]["event"], "starter.request_conflict");
    let reopened = konsensus_api::AuditLog::open(state.audit_log.path()).unwrap();
    assert!(!reopened
        .starter_pending()
        .contains(&conflicting_id.to_string()));
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
    assert_eq!(
        app.clone().oneshot(get).await.unwrap().status(),
        StatusCode::OK
    );
    // A conflict is not a persisted terminal refusal. Its UUID can later be
    // accepted and must still log its actual hub outcome.
    let mut old = db
        .starter_request_get(&id.to_string())
        .await
        .unwrap()
        .unwrap();
    old.state = "refused".into();
    db.starter_request_save(&old).await.unwrap();
    assert_eq!(
        app.oneshot(post(&token, conflicting_id))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    let mut later = db
        .starter_request_get(&conflicting_id.to_string())
        .await
        .unwrap()
        .unwrap();
    later.state = "refused".into();
    later.reason = Some("invite_expired".into());
    db.starter_request_save(&later).await.unwrap();
    state.audit_log.starter_progress(&later).unwrap();
    let entries: Vec<serde_json::Value> = std::fs::read_to_string(state.audit_log.path())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .filter(|e: &serde_json::Value| {
            e["event"] == "starter.refused"
                && e["detail"]["request_id"] == conflicting_id.to_string()
        })
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["detail"]["reason"], "invite_expired");
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
    state.lightning = Arc::new(ReadyLn("regtest"));
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

#[tokio::test]
async fn provider_mainnet_with_signet_config_is_rejected_before_persistence() {
    use konsensus_api::handlers::starter_channel::{StarterConfig, StarterSettings};
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = (*test_state()).clone();
    state.storage = db.clone();
    state.lightning = Arc::new(ReadyLn("bitcoin"));
    state.starter = StarterSettings {
        config: StarterConfig {
            enabled: true,
            hub_node_id: "08".repeat(32),
            hub_alias: None,
            allow_mainnet: false,
        },
        network: "signet".into(),
        hub_ln_pubkey: "03".repeat(33),
        hub_ln_address: "127.0.0.1:9735".into(),
        hub_whitelisted: true,
        trust_no_reserve: true,
    };
    let dir = tempfile::tempdir().unwrap();
    let token = paired(&mut state, dir.path(), pairing::default_pairing_scopes());
    let response = test_router(Arc::new(state))
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
    assert_eq!(body["reason"], "network_not_allowed");
    assert!(db.starter_request_current().await.unwrap().is_none());
}

#[tokio::test]
async fn discovery_before_request_is_authenticated_and_contains_only_display_metadata() {
    let mut state = (*test_state()).clone();
    state.storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let dir = tempfile::tempdir().unwrap();
    let token = paired(&mut state, dir.path(), pairing::default_pairing_scopes());
    for configured in [false, true] {
        // Deserialize so this regression test compiles before hub_alias exists.
        state.starter.config = serde_json::from_value(serde_json::json!({
            "enabled": configured, "hub_node_id": "08".repeat(32),
            "hub_alias": "Signet starter"
        }))
        .unwrap();
        state.starter.hub_ln_pubkey = "03".repeat(33);
        state.starter.hub_ln_address = "private.example:9735".into();
        state.starter.hub_whitelisted = true;
        let app = test_router(Arc::new(state.clone()));
        for auth in [Some(token.clone()), Some(auth_header(&state)), None] {
            let mut req = Request::builder().uri("/api/v1/onboarding/starter-channel");
            if let Some(token) = &auth {
                req = req.header("authorization", token);
            }
            let response = app
                .clone()
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap();
            if auth.is_none() {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            } else {
                assert_eq!(response.status(), StatusCode::OK);
                let body: serde_json::Value = serde_json::from_slice(
                    &axum::body::to_bytes(response.into_body(), 10000)
                        .await
                        .unwrap(),
                )
                .unwrap();
                let expected = if configured {
                    serde_json::json!({"state":"not_requested", "hub_configured":true, "hub_alias":"Signet starter"})
                } else {
                    serde_json::json!({"state":"not_requested", "hub_configured":false})
                };
                assert_eq!(body, expected);
            }
        }
    }
}

#[tokio::test]
async fn starter_refuses_all_caller_supplied_cost_and_push_fields_before_persistence() {
    let mut state = (*test_state()).clone();
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    state.storage = db.clone();
    let dir = tempfile::tempdir().unwrap();
    let token = paired(&mut state, dir.path(), pairing::default_pairing_scopes());
    let app = test_router(Arc::new(state));
    for field in [
        "cost_sats",
        "cost_msat",
        "push_sats",
        "push_msat",
        "amount_sats",
        "fee_sats",
    ] {
        for amount in [
            serde_json::json!(1),
            serde_json::json!(0),
            serde_json::Value::Null,
        ] {
            let mut body = serde_json::json!({"request_id": uuid::Uuid::new_v4()});
            body[field] = amount;
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/onboarding/starter-channel")
                        .header("authorization", &token)
                        .header("content-type", "application/json")
                        .body(Body::from(body.to_string()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "{field}"
            );
            assert!(db.starter_request_current().await.unwrap().is_none());
        }
    }
}

#[test]
fn starter_activity_retains_origin_and_deduplicates_terminal_outcomes_across_restart() {
    use konsensus_api::AuditLog;
    use konsensus_storage::starter_request::StarterRequest;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut row = StarterRequest::new(
        uuid::Uuid::new_v4().to_string(),
        "08".repeat(32),
        "03".repeat(33),
        "regtest".into(),
        100,
    );
    {
        let audit = AuditLog::open(&path).unwrap();
        audit
            .starter_requested(&row.request_id, "paired-device-a")
            .unwrap();
        audit
            .starter_requested(&row.request_id, "paired-device-b")
            .unwrap();
    }
    row.state = "refused".into();
    row.reason = Some("hub_busy".into());
    {
        let audit = AuditLog::open(&path).unwrap();
        audit.starter_progress(&row).unwrap();
        audit.starter_progress(&row).unwrap();
    }
    let audit = AuditLog::open(&path).unwrap();
    audit.starter_progress(&row).unwrap();
    let mut child = StarterRequest::new(
        uuid::Uuid::new_v4().to_string(),
        row.hub_node_id.clone(),
        row.hub_ln_pubkey.clone(),
        "regtest".into(),
        700,
    );
    child.original_request_id = Some(row.request_id.clone());
    audit.starter_progress(&child).unwrap();
    child.state = "ready".into();
    child.verified_at = Some(800);
    audit.starter_progress(&child).unwrap();
    let entries: Vec<serde_json::Value> = std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(entries.len(), 4);
    assert!(entries
        .iter()
        .all(|e| e["actor"] == "paired-device-a"
            && e["detail"]["paired_device_id"] == "paired-device-a"));
    assert_eq!(entries[1]["event"], "starter.refused");
    assert_eq!(entries[1]["detail"]["reason"], "hub_busy");
    assert_eq!(entries[3]["event"], "starter.ready");
    assert_eq!(entries[3]["detail"]["request_id"], child.request_id);
    assert_eq!(entries[3]["detail"]["root_request_id"], row.request_id);
}

#[test]
fn starter_activity_survives_truncated_tail_and_a_revived_refusal() {
    use konsensus_api::AuditLog;
    use konsensus_storage::starter_request::StarterRequest;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    // Simulate a process dying during an unrelated audit append.
    std::fs::write(&path, [b'{', b'"', 0xf0, 0x9f]).unwrap();
    let mut row = StarterRequest::new(
        uuid::Uuid::new_v4().to_string(),
        "08".repeat(32),
        "03".repeat(33),
        "regtest".into(),
        100,
    );
    {
        let audit = AuditLog::open(&path).unwrap();
        audit
            .starter_requested(&row.request_id, "paired-device")
            .unwrap();
    }
    {
        let audit = AuditLog::open(&path).unwrap();
        row.state = "refused".into();
        row.reason = Some("hub_busy".into());
        audit.starter_progress(&row).unwrap();
        row.state = "requested".into(); // authenticated adoption revives this UUID
        row.reason = None;
        audit.starter_progress(&row).unwrap();
        assert_eq!(audit.starter_pending(), vec![row.request_id.clone()]);
    }
    let audit = AuditLog::open(&path).unwrap();
    assert_eq!(audit.starter_pending(), vec![row.request_id.clone()]);
    row.state = "refused".into();
    row.reason = Some("invite_expired".into());
    audit.starter_progress(&row).unwrap();
    audit.starter_progress(&row).unwrap();
    assert!(audit.starter_pending().is_empty());
    let entries: Vec<serde_json::Value> = std::fs::read(path)
        .unwrap()
        .split(|b| *b == b'\n')
        .filter_map(|l| serde_json::from_slice(l).ok())
        .collect();
    assert_eq!(entries.len(), 4);
    assert!(entries
        .iter()
        .all(|e| e["detail"]["paired_device_id"] == "paired-device"));
    assert_eq!(entries[3]["detail"]["reason"], "invite_expired");
}

#[tokio::test]
async fn unpaired_receive_token_writes_no_starter_audit() {
    let mut state = (*test_state()).clone();
    state.storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let dir = tempfile::tempdir().unwrap();
    state.audit_log =
        Arc::new(konsensus_api::AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        vec![auth::Scope::Receive],
    )
    .unwrap();
    let response = test_router(Arc::new(state.clone()))
        .oneshot(post(&format!("Bearer {token}"), uuid::Uuid::new_v4()))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(std::fs::read(state.audit_log.path()).unwrap().is_empty());
    assert!(state
        .storage
        .starter_request_current()
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn concurrent_fresh_requests_only_journal_the_winner() {
    use konsensus_api::handlers::starter_channel::{StarterConfig, StarterSettings};
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = (*test_state()).clone();
    state.storage = db.clone();
    state.lightning = Arc::new(ReadyLn("regtest"));
    state.starter = StarterSettings {
        config: StarterConfig {
            enabled: true,
            hub_node_id: "08".repeat(32),
            hub_alias: None,
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
    state.audit_log =
        Arc::new(konsensus_api::AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let token = paired(&mut state, dir.path(), pairing::default_pairing_scopes());

    let ids = [uuid::Uuid::new_v4(), uuid::Uuid::new_v4()];
    let app = test_router(Arc::new(state.clone()));
    let (a, b) = tokio::join!(
        app.clone().oneshot(post(&token, ids[0])),
        app.oneshot(post(&token, ids[1]))
    );
    let statuses = [a.unwrap().status(), b.unwrap().status()];
    assert!(statuses.contains(&StatusCode::ACCEPTED));
    assert!(statuses.contains(&StatusCode::CONFLICT));
    let winner = db.starter_request_current().await.unwrap().unwrap();
    assert_eq!(
        state.audit_log.starter_pending(),
        vec![winner.request_id.clone()]
    );
    let entries: Vec<serde_json::Value> = std::fs::read_to_string(state.audit_log.path())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["event"], "starter.requested");
    assert_eq!(entries[0]["detail"]["request_id"], winner.request_id);
    assert_eq!(entries[1]["event"], "starter.request_conflict");
}

#[tokio::test]
async fn starter_load_prunes_orphans_but_retains_durable_attribution() {
    use konsensus_api::AuditLog;
    use konsensus_storage::starter_request::StarterRequest;
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let orphan = uuid::Uuid::new_v4().to_string();
    let row = StarterRequest::new(
        uuid::Uuid::new_v4().to_string(),
        "08".repeat(32),
        "03".repeat(33),
        "regtest".into(),
        100,
    );
    {
        let log = AuditLog::open(&path).unwrap();
        log.starter_requested(&orphan, "orphan-device").unwrap();
        log.starter_requested(&row.request_id, "real-device")
            .unwrap();
    }
    db.starter_request_create(&row).await.unwrap();
    let log = AuditLog::open_with_starter_storage(&path, db.clone())
        .await
        .unwrap();
    assert_eq!(log.starter_pending(), vec![row.request_id.clone()]);
    let mut terminal = row;
    terminal.state = "refused".into();
    db.starter_request_save(&terminal).await.unwrap();
    log.starter_progress_async(&terminal).await.unwrap();
    let entries: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(entries.last().unwrap()["actor"], "real-device");
    // Historical evidence remains append-only, but never re-enters pending on load.
    let log = AuditLog::open_with_starter_storage(&path, db.clone())
        .await
        .unwrap();
    assert!(!log.starter_pending().contains(&orphan));
}

#[tokio::test]
async fn starter_reused_orphan_keeps_new_device_after_restart() {
    use konsensus_api::AuditLog;
    use konsensus_storage::starter_request::StarterRequest;
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let mut row = StarterRequest::new(
        uuid::Uuid::new_v4().to_string(),
        "08".repeat(32),
        "03".repeat(33),
        "regtest".into(),
        100,
    );
    AuditLog::open(&path)
        .unwrap()
        .starter_requested(&row.request_id, "orphan-device")
        .unwrap();
    let log = AuditLog::open_with_starter_storage(&path, db.clone())
        .await
        .unwrap();
    assert!(log.starter_pending().is_empty());
    log.starter_requested_async(&row.request_id, "new-device")
        .await
        .unwrap();
    db.starter_request_create(&row).await.unwrap();
    drop(log);
    let log = AuditLog::open_with_starter_storage(&path, db.clone())
        .await
        .unwrap();
    row.state = "refused".into();
    db.starter_request_save(&row).await.unwrap();
    log.starter_progress_async(&row).await.unwrap();
    let entries: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(entries.last().unwrap()["actor"], "new-device");
}
