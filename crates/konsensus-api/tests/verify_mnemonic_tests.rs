mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use common::{auth_header, test_router, test_state};
use konsensus_api::AppState;
use konsensus_core::NodeIdentity;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PASSPHRASE: &str = "test recovery passphrase";

fn state_with_passphrase(passphrase: &str) -> Arc<AppState> {
    let mut state = test_state();
    let inner = Arc::get_mut(&mut state).unwrap();
    inner.has_identity_passphrase = !passphrase.is_empty();
    inner.identity = Arc::new(NodeIdentity::from_mnemonic(MNEMONIC, passphrase).unwrap());
    state
}

async fn verify(state: Arc<AppState>, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/verify-mnemonic")
        .header("content-type", "application/json")
        .header("authorization", auth_header(&state))
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = test_router(state).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
    // JSON rejections need not use the API's JSON error envelope.
    let body = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| Value::String(String::from_utf8(bytes.to_vec()).unwrap()));
    (status, body)
}

#[tokio::test]
async fn supplied_passphrase_matches_node_identity() {
    let state = state_with_passphrase(PASSPHRASE);
    let node_id = state.identity.node_id().to_hex();
    let (status, body) = verify(
        state,
        json!({"mnemonic": MNEMONIC, "passphrase": PASSPHRASE}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"node_id": node_id}));
}

#[tokio::test]
async fn wrong_passphrase_produces_a_mismatching_identity() {
    let state = state_with_passphrase(PASSPHRASE);
    let node_id = state.identity.node_id().to_hex();
    let (status, body) = verify(
        state,
        json!({"mnemonic": MNEMONIC, "passphrase": "wrong passphrase"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["node_id"].is_string());
    assert_ne!(body["node_id"], node_id);
    assert_eq!(body.as_object().unwrap().len(), 1);
}

#[tokio::test]
async fn omitted_passphrase_preserves_identity_without_a_passphrase() {
    let state = state_with_passphrase("");
    let node_id = state.identity.node_id().to_hex();
    let (status, body) = verify(state, json!({"mnemonic": MNEMONIC})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"node_id": node_id}));
}

#[tokio::test]
async fn missing_passphrase_is_refused_when_node_has_one() {
    for body in [
        json!({"mnemonic": MNEMONIC}),
        json!({"mnemonic": MNEMONIC, "passphrase": null}),
    ] {
        let (status, body) = verify(state_with_passphrase(PASSPHRASE), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("passphrase"));
        assert!(body["error"].as_str().unwrap().contains("required"));
        assert!(body.get("node_id").is_none());
        assert!(!body.to_string().contains(PASSPHRASE));
        assert!(!body.to_string().contains(MNEMONIC));
    }
}

#[tokio::test]
async fn explicit_empty_passphrase_derives_the_empty_passphrase_identity() {
    let expected = common::test_identity().node_id().to_hex();
    let (status, body) = verify(
        state_with_passphrase(PASSPHRASE),
        json!({"mnemonic": MNEMONIC, "passphrase": ""}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"node_id": expected}));
}

#[tokio::test]
async fn unknown_fields_are_still_rejected() {
    let (status, _) = verify(
        state_with_passphrase(PASSPHRASE),
        json!({"mnemonic": MNEMONIC, "passphrase": PASSPHRASE, "unexpected": true}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[test]
fn deserialized_passphrase_is_zeroizing_and_preserves_whitespace() {
    let request: konsensus_api::handlers::identity::VerifyMnemonicRequest =
        serde_json::from_value(json!({"mnemonic": MNEMONIC, "passphrase": "  secret  "})).unwrap();
    let passphrase: zeroize::Zeroizing<String> = request.passphrase.unwrap();
    assert_eq!(passphrase.as_str(), "  secret  ");
}
