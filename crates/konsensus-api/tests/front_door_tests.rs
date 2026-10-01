//! FrontDoorCard v1 owner API: publish, export link/QR, verify (no dial).
#![allow(dead_code)]
mod common;
use common::*;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use konsensus_api::auth;
use konsensus_api::handlers::introduction::IntroductionSettings;
use konsensus_api::state::AppState;
use konsensus_core::front_door::{
    FrontDoorCard, FrontDoorFields, FrontDoorPrices, FrontDoorProfile, ProfileKind, LINK_PREFIX,
};

fn settings(endpoint: Option<&str>) -> IntroductionSettings {
    IntroductionSettings::fixed(Some("regtest"), endpoint)
}

fn state_with(intro: IntroductionSettings) -> Arc<AppState> {
    let base = test_state();
    Arc::new(AppState {
        introduction: intro,
        ..(*base).clone()
    })
}

fn state_with_persist(intro: IntroductionSettings, dir: std::path::PathBuf) -> Arc<AppState> {
    let base = test_state();
    let own = base.identity.node_id().to_hex();
    Arc::new(AppState {
        introduction: intro,
        content_dir: Some(dir.clone()),
        front_door: konsensus_api::handlers::front_door::FrontDoorStore::load(
            Some(&dir),
            None,
            &own,
        ),
        ..(*base).clone()
    })
}

fn bearer(state: &AppState, scopes: Vec<auth::Scope>) -> String {
    let token = auth::create_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        scopes,
    )
    .unwrap();
    format!("Bearer {token}")
}

async fn call(
    state: &Arc<AppState>,
    method: &str,
    path: &str,
    bearer: String,
    body: Option<Value>,
) -> (StatusCode, Value, Option<String>) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", bearer)
        .header("content-type", "application/json");
    let body = body
        .map(|b| Body::from(b.to_string()))
        .unwrap_or_else(Body::empty);
    let response = test_router(state.clone())
        .oneshot(req.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cache = response
        .headers()
        .get("cache-control")
        .map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) })),
        cache,
    )
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn stranger_card(endpoint: &str, network: &str, issued_at: u64) -> FrontDoorCard {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    FrontDoorCard::issue_with_key(
        &key,
        FrontDoorFields {
            network: network.into(),
            endpoint: endpoint.into(),
            seq: 1,
            issued_at,
            prices: FrontDoorPrices {
                admission_msat: 100_000,
                message_msat: 10_000,
                page_msat: 1_000,
                price_epoch: 0,
            },
            profile: FrontDoorProfile {
                kind: ProfileKind::Person,
                display_name: "Ada".into(),
                tagline: "Builder".into(),
                about: "About Ada".into(),
                avatar: None,
            },
            cv: None,
            media: vec![],
            site: None,
            links: vec![],
        },
    )
    .unwrap()
}

#[tokio::test]
async fn get_missing_card_is_404() {
    let state = state_with(settings(Some("node.example.org:9000")));
    let (status, body, _) = call(
        &state,
        "GET",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Read]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(body.to_string().contains("front_door_missing"), "{body}");
}

#[tokio::test]
async fn admin_publishes_and_read_exports_link() {
    let state = state_with(settings(Some("node.example.org:9000")));
    let admin = bearer(&state, vec![auth::Scope::Admin]);
    let (status, body, cache) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        admin,
        Some(json!({
            "display_name": "Rasmus",
            "tagline": "BitSov",
            "about": "Mesh doorstep",
            "admission_msat": 50_000,
            "message_msat": 5_000,
            "page_msat": 1_000
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(body["card"]["v"], 1);
    assert_eq!(body["card"]["seq"], 1);
    assert_eq!(body["card"]["profile"]["display_name"], "Rasmus");
    assert_eq!(body["card"]["prices"]["admission_msat"], 50_000);
    let link = body["link"].as_str().unwrap();
    assert!(link.starts_with(LINK_PREFIX), "{link}");
    assert_eq!(body["qr_payload"], link);

    let (status, got, _) = call(
        &state,
        "GET",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Read]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["card"]["seq"], 1);
    assert_eq!(got["link"], link);

    // Update bumps seq.
    let (status, body2, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Admin]),
        Some(json!({
            "display_name": "Rasmus",
            "tagline": "Updated"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body2}");
    assert_eq!(body2["card"]["seq"], 2);
    assert_eq!(body2["card"]["profile"]["tagline"], "Updated");
}

#[tokio::test]
async fn put_needs_admin_get_and_verify_need_read() {
    let state = state_with(settings(Some("node.example.org:9000")));
    let (status, _, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "display_name": "X" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, _, _) = call(
        &state,
        "GET",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Receive]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let card = stranger_card("peer.example.org:9000", "regtest", now());
    let (status, _, _) = call(
        &state,
        "POST",
        "/api/v1/front-door/verify",
        bearer(&state, vec![auth::Scope::Receive]),
        Some(json!({ "card": card.to_link().unwrap() })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn no_card_without_endpoint_or_network() {
    let state = state_with(settings(None));
    let (status, body, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "X" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body.to_string().contains("front_door_unavailable: no_dialable_endpoint"),
        "{body}"
    );
}

#[tokio::test]
async fn verify_accepts_link_and_never_dials() {
    let state = state_with(settings(Some("node.example.org:9000")));
    let card = stranger_card("unresolved.invalid:9000", "regtest", now());
    let link = card.to_link().unwrap();
    let (status, body, cache) = call(
        &state,
        "POST",
        "/api/v1/front-door/verify",
        bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "card": link })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(body["card"]["profile"]["display_name"], "Ada");
    assert_eq!(body["verified"], true);
    assert_eq!(body["fresh"], true);
    assert!(body["link"].as_str().unwrap().starts_with(LINK_PREFIX));
}

#[tokio::test]
async fn verify_rejects_forged_signature() {
    let state = state_with(settings(Some("node.example.org:9000")));
    let mut card = stranger_card("peer.example.org:9000", "regtest", now());
    card.sig = "00".repeat(64);
    let (status, body, _) = call(
        &state,
        "POST",
        "/api/v1/front-door/verify",
        bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "card": card.to_link().unwrap() })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("front_door_invalid"), "{body}");
}

#[tokio::test]
async fn verify_rejects_unsigned_expired_card() {
    let state = state_with(settings(Some("node.example.org:9000")));
    let mut card = stranger_card(
        "peer.example.org:9000",
        "regtest",
        now().saturating_sub(8 * 24 * 3600),
    );
    card.profile.display_name = "Forged Name".into();
    card.sig = "00".repeat(64);
    let (status, body, _) = call(
        &state,
        "POST",
        "/api/v1/front-door/verify",
        bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "card": serde_json::to_string(&card).unwrap() })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("front_door_invalid"), "{body}");
    assert!(!body.to_string().contains("Forged Name"), "{body}");
}

#[tokio::test]
async fn verify_expired_but_signed_returns_verified_not_fresh() {
    let state = state_with(settings(Some("node.example.org:9000")));
    let card = stranger_card(
        "peer.example.org:9000",
        "regtest",
        now().saturating_sub(8 * 24 * 3600),
    );
    let (status, body, _) = call(
        &state,
        "POST",
        "/api/v1/front-door/verify",
        bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "card": card.to_link().unwrap() })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["verified"], true);
    assert_eq!(body["fresh"], false);
    assert_eq!(body["card"]["profile"]["display_name"], "Ada");
}

#[tokio::test]
async fn seq_survives_restart_via_pages_file() {
    let dir = tempfile::tempdir().unwrap();
    let intro = settings(Some("node.example.org:9000"));
    let state = state_with_persist(intro.clone(), dir.path().to_path_buf());
    let admin = bearer(&state, vec![auth::Scope::Admin]);
    let (status, body, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        admin,
        Some(json!({ "display_name": "Rasmus", "tagline": "one" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["card"]["seq"], 1);
    assert!(dir.path().join("front-door.json").exists());

    // Fresh AppState loading the same pages dir continues seq.
    let restarted = state_with_persist(intro, dir.path().to_path_buf());
    let (status, body2, _) = call(
        &restarted,
        "PUT",
        "/api/v1/front-door",
        bearer(&restarted, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "Rasmus", "tagline": "two" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body2}");
    assert_eq!(body2["card"]["seq"], 2, "{body2}");
    let (status, got, _) = call(
        &restarted,
        "GET",
        "/api/v1/front-door",
        bearer(&restarted, vec![auth::Scope::Read]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{got}");
    assert_eq!(got["card"]["seq"], 2);
    assert_eq!(got["card"]["profile"]["tagline"], "two");
}

#[tokio::test]
async fn status_advertises_front_door_v1() {
    let state = state_with(settings(None));
    let (status, body, _) = call(&state, "GET", "/api/v1/status", auth_header(&state), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["api_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c == "front_door_v1"),
        "{body}"
    );
}

/// Mesh meetings: this node lists the meeting capability for its own app.
#[tokio::test]
async fn status_advertises_call_meeting_v1() {
    let state = state_with(settings(None));
    let (status, body, _) = call(&state, "GET", "/api/v1/status", auth_header(&state), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["api_capabilities"].as_array().unwrap().iter().any(|c| c == "call_meeting_v1"), "{body}");
}

/// Browse (docs/protocol/BROWSE.md): the paid porch read is advertised.
#[tokio::test]
async fn status_advertises_porch_read_v1() {
    let state = state_with(settings(None));
    let (status, body, _) = call(&state, "GET", "/api/v1/status", auth_header(&state), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["api_capabilities"].as_array().unwrap().iter().any(|c| c == "porch_read_v1"), "{body}");
}

#[tokio::test]
async fn open_refuses_own_card_and_needs_local_consent() {
    let state = state_with(settings(Some("node.example.org:9000")));
    // Publish ours, then try to open it.
    let (_, body, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "Me" })),
    )
    .await;
    let link = body["link"].as_str().unwrap().to_string();
    let (status, resp, _) = call(
        &state,
        "POST",
        "/api/v1/front-door/open",
        bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "card": link })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert!(resp.to_string().contains("your own front door"), "{resp}");

    let local = stranger_card("127.0.0.1:9000", "regtest", now());
    let (status, resp, _) = call(
        &state,
        "POST",
        "/api/v1/front-door/open",
        bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "card": local.to_link().unwrap() })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{resp}");
    assert!(resp.to_string().contains("local_consent"), "{resp}");
}

#[tokio::test]
async fn corrupt_card_keeps_seq_floor() {
    let dir = tempfile::tempdir().unwrap();
    let intro = settings(Some("node.example.org:9000"));
    let state = state_with_persist(intro.clone(), dir.path().to_path_buf());
    let (status, body, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "Rasmus" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["card"]["seq"], 1);
    assert!(dir.path().join("front-door.seq").exists());

    // Tamper the card so signature fails, but leave seq visible in JSON.
    let path = dir.path().join("front-door.json");
    let mut card: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    card["profile"]["display_name"] = json!("Hax");
    card["sig"] = json!("00".repeat(64));
    card["seq"] = json!(7);
    std::fs::write(&path, serde_json::to_vec_pretty(&card).unwrap()).unwrap();

    let restarted = state_with_persist(intro, dir.path().to_path_buf());
    // Card must not load as ours.
    let (status, got, _) = call(
        &restarted,
        "GET",
        "/api/v1/front-door",
        bearer(&restarted, vec![auth::Scope::Read]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{got}");
    // Next publish continues past the salvaged floor, not at 1.
    let (status, body2, _) = call(
        &restarted,
        "PUT",
        "/api/v1/front-door",
        bearer(&restarted, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "Rasmus" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body2}");
    assert!(
        body2["card"]["seq"].as_u64().unwrap() >= 8,
        "expected seq >= 8 after floor 7, got {}",
        body2["card"]["seq"]
    );
}

#[tokio::test]
async fn foreign_card_is_ignored_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let intro = settings(Some("node.example.org:9000"));
    // Write a well-signed stranger card into our pages dir.
    let stranger = stranger_card("peer.example.org:9000", "regtest", now());
    std::fs::write(
        dir.path().join("front-door.json"),
        serde_json::to_vec_pretty(&stranger).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.path().join("front-door.seq"), b"3\n").unwrap();

    let state = state_with_persist(intro, dir.path().to_path_buf());
    let (status, got, _) = call(
        &state,
        "GET",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Read]),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{got}");
    // Seq floor from our seq file still applies; stranger seq is not adopted.
    let (status, body, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "Me" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["card"]["seq"], 4, "{body}");
    assert_eq!(
        body["card"]["node_id"],
        state.identity.node_id().to_hex(),
        "{body}"
    );
}

#[tokio::test]
async fn absurd_seq_floor_is_not_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let intro = settings(Some("node.example.org:9000"));
    let state = state_with_persist(intro.clone(), dir.path().to_path_buf());
    let (status, body, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "Rasmus" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["card"]["seq"], 1);

    // Hand-edit the floor to u64::MAX — without a cap, next publish saturates
    // and locks forever with SeqNotMonotonic.
    std::fs::write(dir.path().join("front-door.seq"), format!("{}\n", u64::MAX)).unwrap();

    let restarted = state_with_persist(intro, dir.path().to_path_buf());
    let (status, body2, _) = call(
        &restarted,
        "PUT",
        "/api/v1/front-door",
        bearer(&restarted, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "Rasmus" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body2}");
    let seq = body2["card"]["seq"].as_u64().unwrap();
    assert!(
        seq == 2,
        "expected publish to continue at 2 after refusing MAX floor, got {seq}"
    );
    // Poison is rewritten to the capped floor (own card seq).
    let floor_text = std::fs::read_to_string(dir.path().join("front-door.seq")).unwrap();
    let rewritten: u64 = floor_text.trim().parse().unwrap();
    assert_eq!(rewritten, seq, "seq file should track the issued card");
}

#[tokio::test]
async fn absurd_seq_floor_alone_starts_at_one() {
    let dir = tempfile::tempdir().unwrap();
    let intro = settings(Some("node.example.org:9000"));
    // No card — only a poisoned floor file.
    std::fs::write(dir.path().join("front-door.seq"), format!("{}\n", u64::MAX)).unwrap();

    let state = state_with_persist(intro, dir.path().to_path_buf());
    let (status, body, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "Me" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["card"]["seq"], 1,
        "refused MAX with no own card must start at seq 1, got {}",
        body["card"]["seq"]
    );
}

#[tokio::test]
async fn garbage_seq_file_is_ignored_and_publish_starts_at_one() {
    let dir = tempfile::tempdir().unwrap();
    let intro = settings(Some("node.example.org:9000"));
    // Hand-edited garbage — must not lock publishing and must not be adopted.
    std::fs::write(dir.path().join("front-door.seq"), b"not-a-number\n").unwrap();

    let state = state_with_persist(intro, dir.path().to_path_buf());
    let (status, body, _) = call(
        &state,
        "PUT",
        "/api/v1/front-door",
        bearer(&state, vec![auth::Scope::Admin]),
        Some(json!({ "display_name": "Me" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["card"]["seq"], 1,
        "garbage seq file must be ignored; expected seq 1, got {}",
        body["card"]["seq"]
    );
}

#[tokio::test]
async fn verify_fails_closed_without_network() {
    let state = state_with(IntroductionSettings::fixed(None, Some("node.example.org:9000")));
    let card = stranger_card("peer.example.org:9000", "regtest", now());
    let (status, body, _) = call(
        &state,
        "POST",
        "/api/v1/front-door/verify",
        bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "card": card.to_link().unwrap() })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body.to_string().contains("front_door_unavailable"),
        "{body}"
    );
    assert!(body.to_string().contains("Bitcoin network"), "{body}");
}

#[tokio::test]
async fn porch_card_page_price_has_one_sat_floor() {
    let state = state_with(settings(Some("node.example.org:9000")));
    for (requested, expected) in [
        (None, 1000),
        (Some(0), 1000),
        (Some(1), 1000),
        (Some(999), 1000),
        (Some(1000), 1000),
        (Some(3000), 1000),
    ] {
        let mut request =
            json!({"display_name": "Porch", "admission_msat": 1234, "message_msat": 5678});
        if let Some(price) = requested {
            request["page_msat"] = json!(price);
        }
        let (status, body, _) = call(
            &state,
            "PUT",
            "/api/v1/front-door",
            bearer(&state, vec![auth::Scope::Admin]),
            Some(request),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["card"]["prices"]["page_msat"], expected);
        assert_eq!(body["card"]["prices"]["admission_msat"], 1234);
        assert_eq!(body["card"]["prices"]["message_msat"], 5678);
        let card = FrontDoorCard::parse(body["link"].as_str().unwrap()).unwrap();
        card.verify_signature().unwrap();
        assert_eq!(card.prices.page_msat, expected);
    }
}

fn porch_pricing_state(base_price: u64, admission: u64) -> Arc<AppState> {
    let base = state_with(settings(Some("node.example.org:9000")));
    Arc::new(AppState {
        pricing: Arc::new(konsensus_pricing::StaticPricingEngine::new(
            konsensus_pricing::StaticPricingConfig {
                web_content_msat: base_price,
                ..Default::default()
            },
        )),
        gate: Arc::new(konsensus_core::gate::PaymentGate::with_config(
            konsensus_core::gate::GateConfig {
                min_admission_cost_msat: admission,
                ..Default::default()
            },
        )),
        ..(*base).clone()
    })
}

#[tokio::test]
async fn porch_card_uses_gate_web_content_price() {
    for (base, admission, expected) in [(1000, 2000, 2000), (5000, 0, 5000)] {
        let state = porch_pricing_state(base, admission);
        let (status, body, _) = call(
            &state,
            "PUT",
            "/api/v1/front-door",
            bearer(&state, vec![auth::Scope::Admin]),
            Some(json!({"display_name": "Porch", "page_msat": 3000})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["card"]["prices"]["page_msat"], expected);
        let card = FrontDoorCard::parse(body["link"].as_str().unwrap()).unwrap();
        card.verify_signature().unwrap();
        assert_eq!(card.prices.page_msat, expected);
    }
}

#[tokio::test]
async fn porch_stored_card_get_reprices_and_signs() {
    let state = porch_pricing_state(1000, 2000);
    let mut fields: FrontDoorFields = serde_json::from_value(json!({
        "network": "regtest", "endpoint": "node.example.org:9000",
        "seq": 1, "issued_at": now(),
        "prices": {"admission_msat": 1000, "message_msat": 1000,
                   "page_msat": 500, "price_epoch": 0},
        "profile": {"kind": "person", "display_name": "Legacy"}
    }))
    .unwrap();
    for base in [1000, 5000] {
        let state = Arc::new(AppState {
            pricing: Arc::new(konsensus_pricing::StaticPricingEngine::new(
                konsensus_pricing::StaticPricingConfig {
                    web_content_msat: base,
                    ..Default::default()
                },
            )),
            ..(*state).clone()
        });
        fields.seq += 1;
        let dir = tempfile::tempdir().unwrap();
        let legacy = FrontDoorCard::issue(&state.identity, fields.clone()).unwrap();
        std::fs::write(
            dir.path().join("front-door.json"),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let state = Arc::new(AppState {
            front_door: konsensus_api::handlers::front_door::FrontDoorStore::load(
                Some(dir.path()),
                None,
                &state.identity.node_id().to_hex(),
            ),
            ..(*state).clone()
        });
        let (status, body, _) = call(
            &state,
            "GET",
            "/api/v1/front-door",
            bearer(&state, vec![auth::Scope::Read]),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let expected = if base == 1000 { 2000 } else { 5000 };
        assert_eq!(body["card"]["prices"]["page_msat"], expected);
        let card = FrontDoorCard::parse(body["link"].as_str().unwrap()).unwrap();
        card.verify_signature().unwrap();
        assert_eq!(card.prices.page_msat, expected);
        assert!(card.seq > legacy.seq);
        assert_eq!(card.issued_at, legacy.issued_at);
        assert_eq!(card.expires_at, legacy.expires_at);
        assert_eq!(card.profile, legacy.profile);
        let reloaded = konsensus_api::handlers::front_door::FrontDoorStore::load(
            Some(dir.path()),
            None,
            &state.identity.node_id().to_hex(),
        );
        assert_eq!(reloaded.card.lock().await.as_ref(), Some(&card));
        let (_, again, _) = call(
            &state,
            "GET",
            "/api/v1/front-door",
            bearer(&state, vec![auth::Scope::Read]),
            None,
        )
        .await;
        assert_eq!(again["card"]["seq"], card.seq);
    }
}

#[tokio::test]
async fn porch_manifest_preview_uses_gate_price() {
    let dir = tempfile::tempdir().unwrap();
    for content_dir in [None, Some(dir.path().to_path_buf())] {
        let base = porch_pricing_state(1000, 2000);
        let state = Arc::new(AppState {
            content_dir,
            web_page_price_msat: Some(50),
            ..(*base).clone()
        });
        let (status, body, _) = call(
            &state,
            "GET",
            "/api/v1/content/manifest",
            bearer(&state, vec![auth::Scope::Read]),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["default_price_msat"], 2000);
    }
}
