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
use konsensus_core::front_door::{FrontDoorCard, FrontDoorFields, FrontDoorPrices, FrontDoorProfile, ProfileKind, LINK_PREFIX};

fn settings(endpoint: Option<&str>) -> IntroductionSettings {
    IntroductionSettings {
        network: Some("regtest".into()),
        endpoint: endpoint.map(Into::into),
    }
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
    let token =
        auth::create_token(&state.identity.node_id().to_hex(), &state.jwt_secret, scopes).unwrap();
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
        serde_json::from_slice(&bytes)
            .unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) })),
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
    assert!(body.to_string().contains("front_door_unavailable"), "{body}");
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
async fn verify_fails_closed_without_network() {
    let state = state_with(IntroductionSettings {
        network: None,
        endpoint: Some("node.example.org:9000".into()),
    });
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
    assert!(
        body.to_string().contains("Bitcoin network"),
        "{body}"
    );
}
