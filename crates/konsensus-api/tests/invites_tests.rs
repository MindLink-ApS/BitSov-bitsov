//! ONB2: Inviter-side BitSov invite issuance endpoint tests.
//!
//! Covers the AI-review-mandated cases from PR #78 v1:
//! - Happy path (issue → storage round-trip → signature verifies)
//! - Bad hex pubkey → 400
//! - Wrong-length pubkey → 400
//! - Expired expiry_unix → 400
//! - Future-too-far expiry_unix → 400

mod common;
use common::*;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use ed25519_dalek::{Verifier, VerifyingKey};
use tower::ServiceExt;

use konsensus_api::build_router;
use konsensus_core::invite::{BitSovInvite, UnsignedBitSovInvite};
use konsensus_core::NodeId;
use konsensus_storage::{InviteIssuedRecord, InviteState, SqliteStorage, Storage};

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after UNIX_EPOCH")
        .as_secs()
}

const TEST_INVITER_ADDR: &str = "node.example.com:9735";

/// 32-byte test invitee pubkey, well-formed for hex parsing.
fn test_invitee_pubkey_hex() -> String {
    hex::encode([0xABu8; 32])
}

fn signed_invite_token_for_with_nonce(invitee_pubkey: [u8; 32], nonce: [u8; 16]) -> String {
    let unsigned = UnsignedBitSovInvite {
        version: 1,
        inviter_pubkey: [0x11; 32],
        invitee_pubkey,
        expiry_unix: now_unix() + 3600,
        channel_size_hint_sats: Some(42_000),
        addr: String::new(),
        max_fee_rate_sat_per_vb: None,
        channel_open_intent_expiry_unix: None,
        nonce,
    };
    let signer = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
    let signed = BitSovInvite::sign(
        UnsignedBitSovInvite {
            inviter_pubkey: signer.verifying_key().to_bytes(),
            ..unsigned
        },
        &signer,
    )
    .expect("sign invite");
    let bytes = serde_json::to_vec(&signed).expect("serialize invite");
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn signed_invite_token_for(invitee_pubkey: [u8; 32]) -> String {
    signed_invite_token_for_with_nonce(invitee_pubkey, [0x22; 16])
}

#[tokio::test]
async fn issue_invite_happy_path() {
    let state = test_state();
    let auth = auth_header(&state);
    let storage = Arc::clone(&state.storage);
    let inviter_pubkey = state.identity.ed25519_verifying_key().to_bytes();
    let app = build_router(Arc::clone(&state));

    let expiry = now_unix() + 3600; // 1 hour from now
    let invitee_hex = test_invitee_pubkey_hex();

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": invitee_hex,
                "expiry_unix": expiry,
                "channel_size_hint_sats": 50_000u32,
                "addr": TEST_INVITER_ADDR,
                "max_fee_rate_sat_per_vb": 42u32,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let invite_id = json["invite_id"].as_str().expect("invite_id present");
    let token_b64 = json["invite_token_b64"]
        .as_str()
        .expect("invite_token_b64 present");
    let invite_link = json["invite_link"].as_str().expect("invite_link present");
    assert!(invite_link.starts_with("bitsov://invite/"));
    assert!(invite_link.ends_with(token_b64));

    // Decode the token and verify the signature with the inviter's pubkey.
    let invite_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token_b64)
        .expect("base64 decode");
    let invite: BitSovInvite = serde_json::from_slice(&invite_json).expect("parse invite");

    assert_eq!(invite.version, 2);
    assert_eq!(invite.inviter_pubkey, inviter_pubkey);
    assert_eq!(invite.expiry_unix, expiry);
    assert_eq!(invite.channel_size_hint_sats, Some(50_000));
    assert_eq!(invite.addr, TEST_INVITER_ADDR);
    assert_eq!(invite.max_fee_rate_sat_per_vb, Some(42));
    assert_eq!(invite.channel_open_intent_expiry_unix, Some(expiry));

    // Signature verifies against the inviter's pubkey.
    let vkey = VerifyingKey::from_bytes(&inviter_pubkey).unwrap();
    let signature = ed25519_dalek::Signature::from_bytes(&invite.signature);
    let canonical = invite.canonical_bytes().expect("canonical_bytes ok");
    vkey.verify(&canonical, &signature)
        .expect("signature valid");

    // verify() against now must succeed (expiry > now, signature valid, version supported)
    invite.verify(now_unix()).expect("invite verifies");

    // Storage round-trip: find_invite_issued returns the row we just persisted.
    let id = uuid::Uuid::parse_str(invite_id).expect("uuid parse");
    let stored = storage
        .find_invite_issued(&id)
        .await
        .expect("storage query ok")
        .expect("row present");
    assert_eq!(stored.invitee_pubkey, [0xABu8; 32]);
    assert_eq!(stored.expiry_unix, expiry);
    assert_eq!(stored.state, InviteState::Pending);
    assert_eq!(stored.channel_size_hint_sats, Some(50_000));
    assert_eq!(stored.addr, TEST_INVITER_ADDR);
    assert_eq!(stored.max_fee_rate_sat_per_vb, Some(42));
    assert_eq!(stored.channel_open_intent_expiry_unix, Some(expiry));
}

#[tokio::test]
async fn invite_capabilities_reports_v2_ready() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/invites/capabilities")
        .header("authorization", &auth)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["default_version"], 2);
    assert_eq!(json["invite_v2_runtime_ready"], true);
    assert_eq!(json["invite_v2_storage_ready"], true);
    assert_eq!(json["invite_v2_ready"], true);
    assert_eq!(json["addr_column"], true);
    assert_eq!(json["max_fee_rate_sat_per_vb_column"], true);
    assert_eq!(json["channel_open_intent_expiry_unix_column"], true);
}

#[tokio::test]
async fn issue_invite_rejects_when_v2_storage_not_ready() {
    let base = test_state();
    let state = Arc::new(konsensus_api::state::AppState {
        storage: Arc::new(MemStorage::new_v1_only()),
        ..(*base).clone()
    });
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": test_invitee_pubkey_hex(),
                "expiry_unix": now_unix() + 3600,
                "channel_size_hint_sats": 50_000u32,
                "addr": TEST_INVITER_ADDR,
                "max_fee_rate_sat_per_vb": 42u32,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("invite v2 unavailable"));
}

#[tokio::test]
async fn issue_invite_rejects_self_invite_pubkey() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let self_pubkey_hex = hex::encode(state.identity.ed25519_verifying_key().to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": self_pubkey_hex,
                "expiry_unix": now_unix() + 3600,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issue_invite_rate_limited_per_auth_user() {
    let state = test_state();
    let auth = format!(
        "Bearer {}",
        konsensus_api::auth::create_token(
            &format!("rate-limit-user-{}", uuid::Uuid::new_v4()),
            &state.jwt_secret
        )
        .expect("token")
    );
    let app = build_router(Arc::clone(&state));
    let expiry = now_unix() + 3600;

    for i in 0..10u8 {
        let invitee_hex = hex::encode([i; 32]);
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/invites")
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "invitee_pubkey": invitee_hex,
                    "expiry_unix": expiry,
                    "addr": TEST_INVITER_ADDR,
                })
                .to_string(),
            ))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": hex::encode([0xFEu8; 32]),
                "expiry_unix": expiry,
                "addr": TEST_INVITER_ADDR,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn issue_invite_rejects_invalid_hex_pubkey() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let expiry = now_unix() + 3600;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": "not-valid-hex-XYZ",
                "expiry_unix": expiry,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issue_invite_rejects_wrong_length_pubkey() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let expiry = now_unix() + 3600;
    // Valid hex but only 16 bytes (32 chars), not 32 bytes (64 chars).
    let short_hex = hex::encode([0xCDu8; 16]);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": short_hex,
                "expiry_unix": expiry,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issue_invite_rejects_expired_expiry() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    let past_expiry = now_unix().saturating_sub(60); // 1 minute ago

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": test_invitee_pubkey_hex(),
                "expiry_unix": past_expiry,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issue_invite_rejects_expiry_too_far_in_future() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(state);

    // Beyond MAX_INVITE_LIFETIME_SECS (30 days).
    let too_far_expiry = now_unix() + 31 * 24 * 3600;

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": test_invitee_pubkey_hex(),
                "expiry_unix": too_far_expiry,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issue_invite_requires_auth() {
    let state = test_state();
    let app = build_router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": test_invitee_pubkey_hex(),
                "expiry_unix": now_unix() + 3600,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    // No bearer header → auth rejects.
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn invites_auto_whitelist() {
    let state = test_state();
    let auth = auth_header(&state);
    let storage = Arc::clone(&state.storage);
    let app = build_router(Arc::clone(&state));

    let expiry = now_unix() + 3600;
    let invitee_bytes = [0xABu8; 32];
    let invitee_hex = hex::encode(invitee_bytes);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": invitee_hex,
                "expiry_unix": expiry,
                "addr": TEST_INVITER_ADDR,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let invite_id = uuid::Uuid::parse_str(json["invite_id"].as_str().unwrap()).unwrap();

    let invitee_node_id = NodeId::from_bytes(invitee_bytes);
    let whitelisted = storage
        .get_peer(&invitee_node_id)
        .await
        .unwrap()
        .expect("invitee should be pre-whitelisted on invite issuance");
    assert_eq!(whitelisted.metadata["invite_ref"], invite_id.to_string());
    assert_eq!(whitelisted.metadata["whitelist_source"], "invite");
}

#[tokio::test]
async fn invites_auto_whitelist_atomic() {
    let storage = Arc::new(MemStorage::new());
    storage.fail_next_whitelist_write();
    let state = test_state_with_storage(Arc::clone(&storage) as Arc<dyn Storage>);
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let expiry = now_unix() + 3600;
    let invitee_bytes = [0xCDu8; 32];
    let invitee_hex = hex::encode(invitee_bytes);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "invitee_pubkey": invitee_hex,
                "expiry_unix": expiry,
                "addr": TEST_INVITER_ADDR,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let invites = storage.list_invites_issued().await.expect("list invites");
    assert!(
        invites.is_empty(),
        "invite row must be rolled back when whitelist write fails"
    );
}

#[tokio::test]
async fn invites_reissue_rejected_while_pending() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));

    let expiry = now_unix() + 3600;
    let invitee_hex = test_invitee_pubkey_hex();
    let mk_req = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/invites")
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "invitee_pubkey": invitee_hex,
                    "expiry_unix": expiry,
                    "addr": TEST_INVITER_ADDR,
                })
                .to_string(),
            ))
            .unwrap()
    };

    let first = app.clone().oneshot(mk_req()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let second = app.oneshot(mk_req()).await.unwrap();
    assert_eq!(second.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(second.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("pending invite already exists"));
}

#[tokio::test]
async fn invites_accept_happy_path() {
    let state = test_state();
    let auth = auth_header(&state);
    let storage = Arc::clone(&state.storage);
    let app = build_router(Arc::clone(&state));
    let token = signed_invite_token_for(state.identity.ed25519_verifying_key().to_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites/accept")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "token": token,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::ACCEPTED);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let inviter_hex = json["inviter_pubkey"].as_str().expect("inviter_pubkey");
    assert_eq!(json["channel_size_hint"], 42_000);

    let inviter = NodeId::from_hex(inviter_hex).expect("valid inviter hex");
    let peer = storage.get_peer(&inviter).await.expect("storage ok");
    assert!(
        peer.is_some(),
        "inviter should be persisted as whitelisted peer"
    );
}

#[tokio::test]
async fn invites_accept_rejects_wrong_invitee() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let token = signed_invite_token_for([0x99; 32]);

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites/accept")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "token": token,
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "wrong invitee");
}

#[tokio::test]
async fn invites_accept_replay_returns_409() {
    let state = test_state();
    let auth = auth_header(&state);
    let app = build_router(Arc::clone(&state));
    let token = signed_invite_token_for(state.identity.ed25519_verifying_key().to_bytes());

    let mk_req = || {
        Request::builder()
            .method("POST")
            .uri("/api/v1/invites/accept")
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "token": token,
                })
                .to_string(),
            ))
            .unwrap()
    };

    let resp1 = app.clone().oneshot(mk_req()).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::ACCEPTED);

    let resp2 = app.oneshot(mk_req()).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::CONFLICT);
    let body = axum::body::to_bytes(resp2.into_body(), 65536)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["error"], "already accepted");
}

#[tokio::test]
async fn invites_accept_rate_limit() {
    let state = test_state();
    let auth = format!(
        "Bearer {}",
        konsensus_api::auth::create_token(
            &format!("accept-rate-limit-user-{}", uuid::Uuid::new_v4()),
            &state.jwt_secret
        )
        .expect("token")
    );
    let app = build_router(Arc::clone(&state));
    let invitee = state.identity.ed25519_verifying_key().to_bytes();

    for i in 0..10u8 {
        let mut nonce = [0u8; 16];
        nonce[0] = i;
        let token = signed_invite_token_for_with_nonce(invitee, nonce);
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/invites/accept")
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "token": token,
                })
                .to_string(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
    }

    let mut nonce = [0u8; 16];
    nonce[0] = 0xFE;
    let token = signed_invite_token_for_with_nonce(invitee, nonce);
    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/invites/accept")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "token": token,
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(resp.headers().get("retry-after").unwrap(), "60");
}

#[tokio::test]
async fn sqlite_invites_round_trip_preserves_numeric_and_state_fields() {
    let storage = SqliteStorage::in_memory().await.expect("sqlite in-memory");
    let id = uuid::Uuid::new_v4();
    let record = InviteIssuedRecord {
        id,
        invitee_pubkey: [0x42u8; 32],
        expiry_unix: 1_893_456_789,
        channel_size_hint_sats: Some(21_000_000),
        addr: TEST_INVITER_ADDR.to_string(),
        max_fee_rate_sat_per_vb: Some(50),
        channel_open_intent_expiry_unix: Some(1_893_456_000),
        nonce: [0x99u8; 16],
        state: InviteState::Pending,
        created_at: 1_893_400_000,
        accepted_at: Some(1_893_400_100),
        revoked_at: None,
    };

    storage
        .add_invite_issued(&record)
        .await
        .expect("insert invite record");
    let loaded = storage
        .find_invite_issued(&id)
        .await
        .expect("query invite record")
        .expect("row exists");

    assert_eq!(loaded, record);
}
