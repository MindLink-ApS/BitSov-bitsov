//! The device-key flow over the real router: request → owner approves at the
//! control socket → signed intent → the token carries a recipient-bound spend.

#![allow(dead_code)]

mod common;

#[path = "common/owner_console.rs"]
mod owner_console;
use owner_console::OwnerConsole;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use tower::ServiceExt;

use konsensus_api::control::{self, ControlContext, ControlRequest, ControlResponse};
use konsensus_api::pairing::device::{intent_message, registration_message};
use konsensus_api::pairing::{self, PairingService, RelationIntent};
use konsensus_api::state::AppState;

use common::*;

const PEER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

async fn call(state: &Arc<AppState>, method: &str, uri: &str, body: Option<Value>, token: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let body = body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty);
    let response = test_router(state.clone()).oneshot(req.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes)})))
}

#[tokio::test]
async fn register_once_then_sign_per_peer_over_http() {
    register_device_over_http(false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn headless_register_once_then_sign_per_peer_over_http() {
    register_device_over_http(true).await;
}

struct NoOwnerTerminal;
impl std::io::Write for NoOwnerTerminal {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(6))
    }
    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
}

async fn register_device_over_http(headless: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let base = test_state();
    let fp = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let console = OwnerConsole::default();
    let owner = konsensus_core::OwnerApprovalKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", &[9u8; 32]).unwrap();
    let service = Arc::new(
        PairingService::open(tmp.path(), fp.clone(), true)
            .unwrap()
            .with_owner_console(if headless { Box::new(NoOwnerTerminal) } else { Box::new(console.clone()) })
            .without_stdout_code()
            .with_owner_config("/Users/owner/bitsov/konsensus.toml".into())
            .with_owner_approval_key(owner.verifying_key()),
    );
    let state = Arc::new(AppState { pairing: Some(Arc::clone(&service)), data_dir: Some(tmp.path().to_path_buf()), ..(*base).clone() });

    // Pair (the ceremony reads the challenge file) and get a paired token.
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let outcome = service.request_pairing("desktop app", &pubkey).unwrap();
    let challenge = std::fs::read(service.dir().join(format!("challenge-{}", outcome.pair_id))).unwrap();
    let sig = hex::encode(key.sign(&PairingService::proof_message(&outcome.pair_id, &pubkey, &challenge)).to_bytes());
    let client = service.confirm_pairing(&outcome.pair_id, &sig, pairing::default_pairing_scopes()).unwrap();
    let token = || async {
        let challenge = service.issue_token_challenge(&client.client_id).unwrap();
        let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
        let (status, body) = call(&state, "POST", "/api/v1/pair/token",
            Some(json!({"client_id": client.client_id, "challenge": challenge, "signature": sig})), None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    };
    let read = token().await;
    let read_token = read["token"].as_str().unwrap().to_string();

    // The device key (Secure Enclave on the Mac; ring here).
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let device = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(device.public_key().as_ref());
    let sign = |msg: &str| hex::encode(device.sign(&rng, msg.as_bytes()).unwrap().as_ref());

    let (status, reg) = call(&state, "POST", "/api/v1/pair/device-key", Some(json!({
        "public_key": public, "name": "MacBook", "proof": sign(&registration_message(&fp, &client.client_id, &public)),
    })), Some(&read_token)).await;
    assert_eq!(status, StatusCode::OK, "{reg}");
    let op_id = reg["op_id"].as_str().unwrap().to_string();
    assert_eq!(reg["owner_action"], format!("konsensus device approve --op {op_id} --config /Users/owner/bitsov/konsensus.toml"));
    let approval_path = service.dir().join(format!("owner-approval-{op_id}"));
    let code = if headless {
        std::fs::read_to_string(&approval_path).unwrap().lines()
            .find_map(|line| line.split_once("type this code when it asks: ").map(|(_, code)| code.to_string())).unwrap()
    } else {
        assert!(!approval_path.exists());
        console.owner_code(&op_id)
    };
    assert!(!reg.to_string().contains(&code), "the app never sees the owner code");

    // Pending until the owner approves at the socket; the app cannot.
    let status_path = format!("/api/v1/pair/device-key/{op_id}");
    let (_, pending) = call(&state, "GET", &status_path, None, Some(&read_token)).await;
    assert_eq!(pending["status"], "pending");
    let ctx = ControlContext {
        service: Arc::clone(&service),
        identity_fingerprint: fp.clone(),
        data_dir: tmp.path().to_path_buf(),
        mnemonic_path: tmp.path().join("mnemonic.txt"),
        replacement_guard: control::ReplacementGuard {
            layout: konsensus_api::bootstrap::DataDirLayout::new(tmp.path()),
            uses_identity_derived_keys: false,
            has_identity_passphrase: false,
        },
    };
    // The owner CLI signs the tuple the node describes.
    let tuple = match control::handle(&ctx, ControlRequest::Describe { op_id: op_id.clone() }) {
        ControlResponse::Describe { device: Some(t), .. } => t,
        other => panic!("{other:?}"),
    };
    assert_eq!((tuple.node.as_str(), tuple.client_pubkey.as_str(), tuple.device_public_key.as_str()), (fp.as_str(), pubkey.as_str(), public.as_str()));
    let owner_signature = hex::encode(owner.sign(pairing::device::owner_approval_message(
        &tuple.node, &tuple.client_pubkey, tuple.epoch, &tuple.device_public_key).as_bytes()).to_bytes());
    let reply = control::handle(&ctx, ControlRequest::ApproveDeviceKey { op_id: op_id.clone(), confirmation: code, owner_signature });
    assert!(matches!(reply, ControlResponse::Ok { .. }), "{reply:?}");
    let (_, done) = call(&state, "GET", &status_path, None, Some(&read_token)).await;
    assert_eq!(done["status"], "registered");
    assert!(!approval_path.exists());
    let (_, keys) = call(&state, "GET", "/api/v1/pair/device-keys", None, Some(&read_token)).await;
    assert_eq!(keys["device_keys"].as_array().unwrap().len(), 1, "{keys}");
    assert_eq!(keys["owner_control"], true);
    assert_eq!(keys["local_owner_device"], false);
    assert_eq!(
        (keys["node"].as_str(), keys["client_id"].as_str()),
        (Some(fp.as_str()), Some(client.client_id.as_str()))
    );

    // A bad signature is a 403 for this request, never a 401 that re-pairs.
    let key_id = reg["key_id"].as_str().unwrap().to_string();
    let intent = RelationIntent {
        device_key_id: key_id, peer: PEER.into(), level: 1, budget_msat: 200_000, per_act_max_msat: 20_000,
        window_secs: 86_400, issued_at: chrono::Utc::now().timestamp(), nonce: "0f".repeat(16),
    };
    let (status, body) = call(&state, "POST", "/api/v1/pair/relation-intent",
        Some(json!({"intent": intent, "signature": sign("something else")})), Some(&read_token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (_, none) = call(&state, "GET", "/api/v1/pair/grant", None, Some(&read_token)).await;
    assert!(none["grant"].is_null(), "{none}");

    let (status, body) = call(&state, "POST", "/api/v1/pair/relation-intent", Some(json!({
        "intent": intent, "signature": sign(&intent_message(&fp, &client.client_id, &intent)),
    })), Some(&read_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["grant"]["recipients_only"], true);

    // A fresh token now carries spend, and GET /pair/grant shows the envelope.
    let spend = token().await;
    assert!(spend["scopes"].as_array().unwrap().iter().any(|s| s == "spend"), "{spend}");
    let (_, grant) = call(&state, "GET", "/api/v1/pair/grant", None, Some(spend["token"].as_str().unwrap())).await;
    assert_eq!(grant["grant"]["per_recipient_msat"][PEER], 200_000, "{grant}");
    assert_eq!(grant["grant"]["per_act_max_by_recipient"][PEER], 20_000, "{grant}");

    // Cancel: a new registration request, withdrawn by the client.
    let other = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING,
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap().as_ref(), &rng).unwrap();
    let other_pub = hex::encode(other.public_key().as_ref());
    let proof = hex::encode(other.sign(&rng, registration_message(&fp, &client.client_id, &other_pub).as_bytes()).unwrap().as_ref());
    let (_, reg2) = call(&state, "POST", "/api/v1/pair/device-key",
        Some(json!({"public_key": other_pub, "name": "iPad", "proof": proof})), Some(&read_token)).await;
    let op2 = reg2["op_id"].as_str().unwrap();
    let (status, _) = call(&state, "DELETE", &format!("/api/v1/pair/device-key/{op2}"), None, Some(&read_token)).await;
    assert_eq!(status, StatusCode::OK);
    let (_, gone) = call(&state, "GET", &format!("/api/v1/pair/device-key/{op2}"), None, Some(&read_token)).await;
    assert_eq!(gone["status"], "absent");

    // Local restart retains the signer and accepts only a device delegation.
    let local = Arc::new(
        PairingService::open(tmp.path(), fp.clone(), false)
            .unwrap()
            .with_local_owner_device()
            .with_owner_signing_key(owner)
            .without_stdout_code(),
    );
    let local_state = Arc::new(AppState {
        pairing: Some(local.clone()),
        ..(*state).clone()
    });
    let (_, keys) = call(
        &local_state,
        "GET",
        "/api/v1/pair/device-keys",
        None,
        Some(&read_token),
    )
    .await;
    assert_eq!(keys["owner_device_count"], 1);
    let (status, reg) = call(
        &local_state,
        "POST",
        "/api/v1/pair/device-key",
        Some(json!({"public_key": other_pub, "name": "phone", "proof": proof})),
        Some(&read_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reg}");
    let op = reg["op_id"].as_str().unwrap();
    let msg = reg["delegation_message"].as_str().unwrap();
    assert!(msg.starts_with("bitsov-owner-delegation-v1\nnode:"));
    let (_, pending) = call(
        &local_state,
        "GET",
        &format!("/api/v1/pair/device-key/{op}"),
        None,
        Some(&read_token),
    )
    .await;
    assert_eq!(pending["delegation_message"], msg);
    let uri = format!("/api/v1/pair/device-key/{op}/delegate");
    let body = json!({"approver_key_id": intent.device_key_id, "signature": sign(msg)});
    let (status, _) = call(&local_state, "POST", &uri, Some(body.clone()), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(
        &local_state,
        "POST",
        &uri,
        Some(json!({"approver_key_id": intent.device_key_id, "signature": sign("wrong tuple")})),
        Some(&read_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(local.device_keys().len(), 1);
    let (status, approved) = call(
        &local_state,
        "POST",
        &uri,
        Some(body.clone()),
        Some(&read_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{approved}");
    assert_eq!(approved["status"], "registered");
    assert_eq!(approved["key_id"], reg["key_id"]);
    let (_, keys) = call(
        &local_state,
        "GET",
        "/api/v1/pair/device-keys",
        None,
        Some(&read_token),
    )
    .await;
    assert_eq!(keys["owner_device_count"], 2);
    let (status, _) = call(&local_state, "POST", &uri, Some(body), Some(&read_token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_plaintext_seed_node_says_why_touch_id_is_off() {
    let tmp = tempfile::tempdir().unwrap();
    let base = test_state();
    let fp = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let service = Arc::new(
        PairingService::open(tmp.path(), fp.clone(), true)
            .unwrap()
            .with_owner_console(Box::new(OwnerConsole::default()))
            .without_stdout_code()
            .with_device_authority_disabled(pairing::device::SEED_NOT_ENCRYPTED),
    );
    let state = Arc::new(AppState { pairing: Some(Arc::clone(&service)), data_dir: Some(tmp.path().to_path_buf()), ..(*base).clone() });
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let outcome = service.request_pairing("desktop app", &pubkey).unwrap();
    let challenge = std::fs::read(service.dir().join(format!("challenge-{}", outcome.pair_id))).unwrap();
    let sig = hex::encode(key.sign(&PairingService::proof_message(&outcome.pair_id, &pubkey, &challenge)).to_bytes());
    let client = service.confirm_pairing(&outcome.pair_id, &sig, pairing::default_pairing_scopes()).unwrap();
    let challenge = service.issue_token_challenge(&client.client_id).unwrap();
    let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let (_, tok) = call(&state, "POST", "/api/v1/pair/token",
        Some(json!({"client_id": client.client_id, "challenge": challenge, "signature": sig})), None).await;
    let token = tok["token"].as_str().unwrap();

    // The app can tell before trying.
    let (_, keys) = call(&state, "GET", "/api/v1/pair/device-keys", None, Some(token)).await;
    assert_eq!(keys["device_approvals"], "seed_not_encrypted", "{keys}");
    // And a request is refused with the same stable reason.
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let device = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(device.public_key().as_ref());
    let proof = hex::encode(device.sign(&rng, registration_message(&fp, &client.client_id, &public).as_bytes()).unwrap().as_ref());
    let (status, body) = call(&state, "POST", "/api/v1/pair/device-key",
        Some(json!({"public_key": public, "name": "MacBook", "proof": proof})), Some(token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reason"], "seed_not_encrypted", "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("Encrypt your recovery phrase"),
        "{body}"
    );
}

#[tokio::test]
async fn local_mode_reports_owner_count_and_requires_delegation() {
    let tmp = tempfile::tempdir().unwrap();
    let base = test_state();
    let fp = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let owner = PairingService::open(tmp.path(), fp.clone(), true)
        .unwrap()
        .without_stdout_code();
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let outcome = owner.request_pairing("desktop app", &pubkey).unwrap();
    let challenge =
        std::fs::read(owner.dir().join(format!("challenge-{}", outcome.pair_id))).unwrap();
    let sig = hex::encode(
        key.sign(&PairingService::proof_message(
            &outcome.pair_id,
            &pubkey,
            &challenge,
        ))
        .to_bytes(),
    );
    let client = owner
        .confirm_pairing(&outcome.pair_id, &sig, pairing::default_pairing_scopes())
        .unwrap();
    drop(owner);
    let service = Arc::new(
        PairingService::open(tmp.path(), fp, false)
            .unwrap()
            .with_local_owner_device()
            .with_owner_approval_key(SigningKey::from_bytes(&[14; 32]).verifying_key())
            .without_stdout_code(),
    );
    let state = Arc::new(AppState {
        pairing: Some(Arc::clone(&service)),
        data_dir: Some(tmp.path().to_path_buf()),
        ..(*base).clone()
    });
    let challenge = service.issue_token_challenge(&client.client_id).unwrap();
    let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let (_, tok) = call(
        &state,
        "POST",
        "/api/v1/pair/token",
        Some(json!({"client_id": client.client_id, "challenge": challenge, "signature": sig})),
        None,
    )
    .await;
    let token = tok["token"].as_str().unwrap();
    let (status, keys) = call(&state, "GET", "/api/v1/pair/device-keys", None, Some(token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(keys["owner_control"], false);
    assert_eq!(keys["local_owner_device"], true);
    assert_eq!(keys["device_approvals"], "enabled");
    assert_eq!(keys["owner_device_count"], 0);
    let (status, _) = call(
        &state,
        "POST",
        "/api/v1/pair/device-key",
        Some(json!({"public_key": "04", "name": "mac", "proof": "00"})),
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    for route in ["/api/v1/pair/device-key/op/approve"] {
        let (status, _) = call(&state, "POST", route, Some(json!({})), Some(token)).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    assert!(service.pending_device_keys().is_empty());
    assert!(service.device_keys().is_empty());
}
