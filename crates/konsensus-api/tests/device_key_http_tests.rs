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

async fn call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    call_router(test_router(state.clone()), method, uri, body, token).await
}

async fn remote_call(
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let router = konsensus_api::build_remote_router_with_limiter(
        state.clone(),
        Arc::new(konsensus_api::rate_limit::RateLimiter::new(10_000)),
    )
    .layer(axum::extract::connect_info::MockConnectInfo(
        "127.0.0.1:40001".parse::<std::net::SocketAddr>().unwrap(),
    ));
    call_router(router, method, uri, body, token).await
}

async fn enroll_call(
    remote: bool,
    state: &Arc<AppState>,
    method: &str,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    if remote {
        remote_call(state, method, uri, body, token).await
    } else {
        call(state, method, uri, body, token).await
    }
}

async fn call_router(
    router: axum::Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    token: Option<&str>,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let body = body
        .map(|b| Body::from(b.to_string()))
        .unwrap_or_else(Body::empty);
    let response = router.oneshot(req.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes)})),
    )
}

// Reopen durable authority as locked startup does. Password verification is
// injected here; the node locked_mode_tests cover real seed decryption/startup.
async fn assert_locked_restart(
    state: &Arc<AppState>,
    owner: ed25519_dalek::VerifyingKey,
    client: &pairing::PairedClient,
    device: &EcdsaKeyPair,
    key_id: &str,
    expected_ids: &[&str],
    expected_status: StatusCode,
) {
    use axum::extract::ConnectInfo;
    use konsensus_api::locked::{locked_router, unlock_message, LockedState, UnlockError};
    use konsensus_api::rate_limit::RemoteTunnelClients;
    let node_id = state.identity.node_id().to_hex();
    let service = Arc::new(
        PairingService::open(
            state.data_dir.as_ref().unwrap(),
            pairing::identity_fingerprint(&node_id),
            false,
        )
        .unwrap()
        .with_pairing_closed(),
    );
    let clients = Arc::new(RemoteTunnelClients::default());
    let peer: std::net::SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let _guard = clients.register(peer, client.client_id.clone());
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    let verified_node = node_id.clone();
    let router = locked_router(Arc::new(LockedState::new(
        node_id,
        service.clone(),
        clients,
        move |password| {
            if password == "contract-test-password" {
                Ok((verified_node.clone(), owner))
            } else {
                Err(UnlockError::Failed)
            }
        },
        tx,
    )));
    let request = |path: &str, body: Value| {
        Request::builder()
            .method("POST")
            .uri(path)
            .extension(ConnectInfo(peer))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    let response = router
        .clone()
        .oneshot(request("/api/v1/node/unlock/challenge", json!({})))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 16384)
        .await
        .unwrap();
    let challenge: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(challenge["key_ids"], json!(expected_ids));
    let message = unlock_message(
        &service.bound_fingerprint(),
        &client.client_id,
        client.epoch,
        key_id,
        challenge["challenge"].as_str().unwrap(),
        &hex::encode(service.box_transport_pubkey()),
    );
    let signature = hex::encode(
        device
            .sign(&ring::rand::SystemRandom::new(), message.as_bytes())
            .unwrap()
            .as_ref(),
    );
    let response = router
        .oneshot(request(
            "/api/v1/node/unlock",
            json!({
                "challenge": challenge["challenge"], "key_id": key_id,
                "signature": signature, "password": "contract-test-password",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), expected_status);
    if expected_status == StatusCode::NO_CONTENT {
        assert_eq!(rx.await.unwrap().as_str(), "contract-test-password");
    } else {
        assert!(
            rx.try_recv().is_err(),
            "unapproved key must never hand off the password"
        );
    }
}

#[tokio::test]
async fn register_once_then_sign_per_peer_over_http() {
    register_device_over_http(false, false).await;
}

#[cfg(unix)]
#[tokio::test]
async fn headless_register_once_then_sign_per_peer_over_http() {
    register_device_over_http(true, false).await;
}

#[tokio::test]
async fn tunnel_registration_console_approval_then_locked_restart_unlocks() {
    register_device_over_http(false, true).await;
}

struct NoOwnerTerminal;
impl std::io::Write for NoOwnerTerminal {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(6))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn register_device_over_http(headless: bool, remote: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let base = test_state();
    let fp = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let console = OwnerConsole::default();
    let owner = konsensus_core::OwnerApprovalKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", &[9u8; 32]).unwrap();
    let service = Arc::new(
        PairingService::open(tmp.path(), fp.clone(), true)
            .unwrap()
            .with_owner_console(if headless {
                Box::new(NoOwnerTerminal)
            } else {
                Box::new(console.clone())
            })
            .without_stdout_code()
            .with_owner_config("/Users/owner/bitsov/konsensus.toml".into())
            .with_owner_approval_key(owner.verifying_key()),
    );
    let state = Arc::new(AppState {
        pairing: Some(Arc::clone(&service)),
        data_dir: Some(tmp.path().to_path_buf()),
        ..(*base).clone()
    });

    // Pair (the ceremony reads the challenge file) and get a paired token.
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let outcome = service.request_pairing("desktop app", &pubkey).unwrap();
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
        .confirm_pairing(&outcome.pair_id, &sig, pairing::default_pairing_scopes())
        .unwrap();
    let token = || async {
        let challenge = service.issue_token_challenge(&client.client_id).unwrap();
        let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
        let (status, body) = call(
            &state,
            "POST",
            "/api/v1/pair/token",
            Some(json!({"client_id": client.client_id, "challenge": challenge, "signature": sig})),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    };
    let read = token().await;
    let read_token = read["token"].as_str().unwrap().to_string();

    // The device key (Secure Enclave on the Mac; ring here).
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let device =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(device.public_key().as_ref());
    let sign = |msg: &str| hex::encode(device.sign(&rng, msg.as_bytes()).unwrap().as_ref());

    let (status, reg) = enroll_call(remote, &state, "POST", "/api/v1/pair/device-key", Some(json!({
        "public_key": public, "name": "MacBook", "proof": sign(&registration_message(&fp, &client.client_id, &public)),
    })), Some(&read_token)).await;
    assert_eq!(status, StatusCode::OK, "{reg}");
    let op_id = reg["op_id"].as_str().unwrap().to_string();
    assert_eq!(
        reg["owner_action"],
        format!(
            "konsensus device approve --op {op_id} --config /Users/owner/bitsov/konsensus.toml"
        )
    );
    let approval_path = service.dir().join(format!("owner-approval-{op_id}"));
    let code = if headless {
        std::fs::read_to_string(&approval_path)
            .unwrap()
            .lines()
            .find_map(|line| {
                line.split_once("type this code when it asks: ")
                    .map(|(_, code)| code.to_string())
            })
            .unwrap()
    } else {
        assert!(!approval_path.exists());
        console.owner_code(&op_id)
    };
    assert!(
        !reg.to_string().contains(&code),
        "the app never sees the owner code"
    );

    // Pending until the owner approves at the socket; the app cannot.
    let status_path = format!("/api/v1/pair/device-key/{op_id}");
    let (_, pending) =
        enroll_call(remote, &state, "GET", &status_path, None, Some(&read_token)).await;
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
    let tuple = match control::handle(
        &ctx,
        ControlRequest::Describe {
            op_id: op_id.clone(),
        },
    ) {
        ControlResponse::Describe {
            device: Some(t), ..
        } => t,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        (
            tuple.node.as_str(),
            tuple.client_pubkey.as_str(),
            tuple.device_public_key.as_str()
        ),
        (fp.as_str(), pubkey.as_str(), public.as_str())
    );
    let owner_signature = hex::encode(
        owner
            .sign(
                pairing::device::owner_approval_message(
                    &tuple.node,
                    &tuple.client_pubkey,
                    tuple.epoch,
                    &tuple.device_public_key,
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    let reply = control::handle(
        &ctx,
        ControlRequest::ApproveDeviceKey {
            op_id: op_id.clone(),
            confirmation: code,
            owner_signature,
        },
    );
    assert!(matches!(reply, ControlResponse::Ok { .. }), "{reply:?}");
    let (_, done) = enroll_call(remote, &state, "GET", &status_path, None, Some(&read_token)).await;
    assert_eq!(done["status"], "registered");
    let key_id = reg["key_id"].as_str().unwrap();
    assert_locked_restart(
        &state,
        owner.verifying_key(),
        &client,
        &device,
        key_id,
        &[key_id],
        StatusCode::NO_CONTENT,
    )
    .await;
    assert!(!approval_path.exists());
    let (_, keys) = enroll_call(
        remote,
        &state,
        "GET",
        "/api/v1/pair/device-keys",
        None,
        Some(&read_token),
    )
    .await;
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
        device_key_id: key_id,
        peer: PEER.into(),
        level: 1,
        budget_msat: 200_000,
        per_act_max_msat: 20_000,
        window_secs: 86_400,
        issued_at: chrono::Utc::now().timestamp(),
        nonce: "0f".repeat(16),
    };
    let (status, body) = call(
        &state,
        "POST",
        "/api/v1/pair/relation-intent",
        Some(json!({"intent": intent, "signature": sign("something else")})),
        Some(&read_token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (_, none) = call(&state, "GET", "/api/v1/pair/grant", None, Some(&read_token)).await;
    assert!(none["grant"].is_null(), "{none}");

    let (status, body) = call(
        &state,
        "POST",
        "/api/v1/pair/relation-intent",
        Some(json!({
            "intent": intent, "signature": sign(&intent_message(&fp, &client.client_id, &intent)),
        })),
        Some(&read_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["grant"]["recipients_only"], true);

    // A fresh token now carries spend, and GET /pair/grant shows the envelope.
    let spend = token().await;
    assert!(
        spend["scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s == "spend"),
        "{spend}"
    );
    let (_, grant) = call(
        &state,
        "GET",
        "/api/v1/pair/grant",
        None,
        Some(spend["token"].as_str().unwrap()),
    )
    .await;
    assert_eq!(
        grant["grant"]["per_recipient_msat"][PEER], 200_000,
        "{grant}"
    );
    assert_eq!(
        grant["grant"]["per_act_max_by_recipient"][PEER], 20_000,
        "{grant}"
    );

    // Cancel: a new registration request, withdrawn by the client.
    let other = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref(),
        &rng,
    )
    .unwrap();
    let other_pub = hex::encode(other.public_key().as_ref());
    let proof = hex::encode(
        other
            .sign(
                &rng,
                registration_message(&fp, &client.client_id, &other_pub).as_bytes(),
            )
            .unwrap()
            .as_ref(),
    );
    let (_, reg2) = enroll_call(
        remote,
        &state,
        "POST",
        "/api/v1/pair/device-key",
        Some(json!({"public_key": other_pub, "name": "iPad", "proof": proof})),
        Some(&read_token),
    )
    .await;
    let op2 = reg2["op_id"].as_str().unwrap();
    let (status, _) = enroll_call(
        remote,
        &state,
        "DELETE",
        &format!("/api/v1/pair/device-key/{op2}"),
        None,
        Some(&read_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, gone) = enroll_call(
        remote,
        &state,
        "GET",
        &format!("/api/v1/pair/device-key/{op2}"),
        None,
        Some(&read_token),
    )
    .await;
    assert_eq!(gone["status"], "absent");

    // Local restart retains the signer and accepts only a device delegation.
    let owner_verifier = owner.verifying_key();
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
    // A second device has its own pairing, as it would after ticket enrollment.
    let second_signer = SigningKey::from_bytes(&[10; 32]);
    let second = local
        .create_ticket_remote_pairing(
            "second desktop",
            &hex::encode(second_signer.verifying_key().to_bytes()),
            &[20; 32],
        )
        .unwrap();
    let challenge = local.issue_token_challenge(&second.client_id).unwrap();
    let signature = hex::encode(second_signer.sign(challenge.as_bytes()).to_bytes());
    let (status, token) = call(
        &local_state,
        "POST",
        "/api/v1/pair/token",
        Some(
            json!({"client_id": second.client_id, "challenge": challenge, "signature": signature}),
        ),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{token}");
    let second_token = token["token"].as_str().unwrap();
    let proof = hex::encode(
        other
            .sign(
                &rng,
                registration_message(&fp, &second.client_id, &other_pub).as_bytes(),
            )
            .unwrap()
            .as_ref(),
    );
    let (status, reg) = call(
        &local_state,
        "POST",
        "/api/v1/pair/device-key",
        Some(json!({"public_key": other_pub, "name": "phone", "proof": proof})),
        Some(second_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reg}");
    let second_key_id = reg["key_id"].as_str().unwrap();
    assert_locked_restart(
        &local_state,
        owner_verifier,
        &second,
        &other,
        second_key_id,
        &[],
        StatusCode::FORBIDDEN,
    )
    .await;
    let op = reg["op_id"].as_str().unwrap();
    let msg = reg["delegation_message"].as_str().unwrap();
    assert!(msg.starts_with("bitsov-owner-delegation-v1\nnode:"));
    let (_, pending) = call(
        &local_state,
        "GET",
        &format!("/api/v1/pair/device-key/{op}"),
        None,
        Some(second_token),
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
    // key_ids is per pairing, not a node-wide list: both devices survive relock.
    assert_locked_restart(
        &local_state,
        owner_verifier,
        &client,
        &device,
        &intent.device_key_id,
        &[&intent.device_key_id],
        StatusCode::NO_CONTENT,
    )
    .await;
    assert_locked_restart(
        &local_state,
        owner_verifier,
        &second,
        &other,
        second_key_id,
        &[second_key_id],
        StatusCode::NO_CONTENT,
    )
    .await;
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
    let state = Arc::new(AppState {
        pairing: Some(Arc::clone(&service)),
        data_dir: Some(tmp.path().to_path_buf()),
        ..(*base).clone()
    });
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let outcome = service.request_pairing("desktop app", &pubkey).unwrap();
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
        .confirm_pairing(&outcome.pair_id, &sig, pairing::default_pairing_scopes())
        .unwrap();
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

    // The app can tell before trying.
    let (_, keys) = call(&state, "GET", "/api/v1/pair/device-keys", None, Some(token)).await;
    assert_eq!(keys["device_approvals"], "seed_not_encrypted", "{keys}");
    // And a request is refused with the same stable reason.
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let device =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(device.public_key().as_ref());
    let proof = hex::encode(
        device
            .sign(
                &rng,
                registration_message(&fp, &client.client_id, &public).as_bytes(),
            )
            .unwrap()
            .as_ref(),
    );
    let (status, body) = call(
        &state,
        "POST",
        "/api/v1/pair/device-key",
        Some(json!({"public_key": public, "name": "MacBook", "proof": proof})),
        Some(token),
    )
    .await;
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

#[tokio::test]
async fn pending_registration_cap_is_node_wide_and_cancel_frees_a_slot() {
    let dir = tempfile::tempdir().unwrap();
    let base = test_state();
    let fp = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let console = OwnerConsole::default();
    let service = Arc::new(
        PairingService::open(dir.path(), fp.clone(), true)
            .unwrap()
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code()
            .with_owner_approval_key(SigningKey::from_bytes(&[42; 32]).verifying_key()),
    );
    let state = Arc::new(AppState {
        pairing: Some(service.clone()),
        ..(*base).clone()
    });
    let rng = ring::rand::SystemRandom::new();
    let device = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_ASN1_SIGNING,
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref(),
        &rng,
    )
    .unwrap();
    let public = hex::encode(device.public_key().as_ref());
    let mut requests = Vec::new();
    for n in 0..9 {
        let signer = SigningKey::from_bytes(&[n + 1; 32]);
        let client = service
            .create_ticket_remote_pairing(
                "phone",
                &hex::encode(signer.verifying_key().to_bytes()),
                &[n + 1; 32],
            )
            .unwrap();
        let challenge = service.issue_token_challenge(&client.client_id).unwrap();
        let signature = hex::encode(signer.sign(challenge.as_bytes()).to_bytes());
        let token = service
            .issue_token(
                &state.identity.node_id().to_hex(),
                &state.jwt_secret,
                &client.client_id,
                &challenge,
                &signature,
            )
            .unwrap()
            .token;
        let proof = hex::encode(
            device
                .sign(
                    &rng,
                    registration_message(&fp, &client.client_id, &public).as_bytes(),
                )
                .unwrap()
                .as_ref(),
        );
        requests.push((
            token,
            json!({"public_key": public, "name": "phone", "proof": proof}),
        ));
    }
    let mut first_op = String::new();
    for (n, (token, body)) in requests.iter().take(8).enumerate() {
        let (status, reg) = enroll_call(
            n % 2 == 0,
            &state,
            "POST",
            "/api/v1/pair/device-key",
            Some(body.clone()),
            Some(token),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{reg}");
        if n == 0 {
            first_op = reg["op_id"].as_str().unwrap().into();
        }
    }
    let console_before = console.text();
    let (token, body) = &requests[8];
    for remote in [false, true] {
        let (status, response) = enroll_call(
            remote,
            &state,
            "POST",
            "/api/v1/pair/device-key",
            Some(body.clone()),
            Some(token),
        )
        .await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{response}");
    }
    assert_eq!(
        console.text(),
        console_before,
        "over-cap requests must not print owner challenges"
    );
    assert_eq!(service.pending_device_keys().len(), 8);
    let (status, _) = remote_call(
        &state,
        "DELETE",
        &format!("/api/v1/pair/device-key/{first_op}"),
        None,
        Some(&requests[0].0),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, reg) = remote_call(
        &state,
        "POST",
        "/api/v1/pair/device-key",
        Some(body.clone()),
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reg}");
    assert_eq!(service.pending_device_keys().len(), 8);

    // Reopen durable pending requests with elapsed timestamps, avoiding a
    // wall-clock sleep: replacement at capacity must still use only one slot.
    let path = service.dir().join("clients.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for pending in file["pending_device_keys"].as_array_mut().unwrap() {
        pending["expires_at"] = (chrono::Utc::now().timestamp() + 800).into();
    }
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    let reopen = || {
        let service = Arc::new(
            PairingService::open(dir.path(), fp.clone(), true)
                .unwrap()
                .with_owner_console(Box::new(console.clone()))
                .without_stdout_code()
                .with_owner_approval_key(SigningKey::from_bytes(&[42; 32]).verifying_key()),
        );
        Arc::new(AppState {
            pairing: Some(service),
            ..(*base).clone()
        })
    };
    let reopened = reopen();
    let (status, reg) = remote_call(
        &reopened,
        "POST",
        "/api/v1/pair/device-key",
        Some(body.clone()),
        Some(token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "replacement at capacity: {reg}");
    assert_eq!(
        reopened
            .pairing
            .as_ref()
            .unwrap()
            .pending_device_keys()
            .len(),
        8
    );
    // An expired request frees a slot for a different client after restart.
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    file["pending_device_keys"][0]["expires_at"] = 0.into();
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    let reopened = reopen();
    let (status, reg) = remote_call(
        &reopened,
        "POST",
        "/api/v1/pair/device-key",
        Some(requests[0].1.clone()),
        Some(&requests[0].0),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "expiry frees capacity: {reg}");
    assert_eq!(
        reopened
            .pairing
            .as_ref()
            .unwrap()
            .pending_device_keys()
            .len(),
        8
    );
}

#[tokio::test]
async fn tunnel_client_cannot_cancel_another_clients_pending_device_key() {
    let dir = tempfile::tempdir().unwrap();
    let base = test_state();
    let fp = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let service = Arc::new(
        PairingService::open(dir.path(), fp.clone(), true)
            .unwrap()
            .with_owner_console(Box::new(OwnerConsole::default()))
            .without_stdout_code()
            .with_owner_approval_key(SigningKey::from_bytes(&[42; 32]).verifying_key()),
    );
    let state = Arc::new(AppState {
        pairing: Some(service.clone()),
        ..(*base).clone()
    });
    let mut clients = Vec::new();
    for seed in [1, 2] {
        let signer = SigningKey::from_bytes(&[seed; 32]);
        let client = service
            .create_ticket_remote_pairing(
                "phone",
                &hex::encode(signer.verifying_key().to_bytes()),
                &[seed; 32],
            )
            .unwrap();
        let challenge = service.issue_token_challenge(&client.client_id).unwrap();
        let signature = hex::encode(signer.sign(challenge.as_bytes()).to_bytes());
        let token = service
            .issue_token(
                &state.identity.node_id().to_hex(),
                &state.jwt_secret,
                &client.client_id,
                &challenge,
                &signature,
            )
            .unwrap()
            .token;
        clients.push((client, token));
    }
    let (a, a_token) = &clients[0];
    let (_, b_token) = &clients[1];
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let device =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(device.public_key().as_ref());
    let proof = hex::encode(
        device
            .sign(
                &rng,
                registration_message(&fp, &a.client_id, &public).as_bytes(),
            )
            .unwrap()
            .as_ref(),
    );
    let (status, reg) = remote_call(
        &state,
        "POST",
        "/api/v1/pair/device-key",
        Some(json!({"public_key": public, "name": "phone", "proof": proof})),
        Some(a_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reg}");
    let op_id = reg["op_id"].as_str().unwrap();
    let path = format!("/api/v1/pair/device-key/{op_id}");
    assert_eq!(
        service.device_key_status(&a.client_id, op_id),
        pairing::DeviceKeyStatus::Pending
    );

    let unknown = remote_call(
        &state,
        "DELETE",
        "/api/v1/pair/device-key/unknown-operation",
        None,
        Some(b_token),
    )
    .await;
    assert_eq!(unknown.0, StatusCode::NOT_FOUND, "{:?}", unknown.1);
    let refused = remote_call(&state, "DELETE", &path, None, Some(b_token)).await;
    assert_eq!(refused.0, StatusCode::NOT_FOUND, "{:?}", refused.1);
    assert_eq!(refused, unknown, "another client's op must look unknown");

    let (status, pending) = remote_call(&state, "GET", &path, None, Some(a_token)).await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending["status"], "pending");
}

#[tokio::test]
async fn tunnel_keeps_approval_and_owner_management_routes_absent() {
    let dir = tempfile::tempdir().unwrap();
    let base = test_state();
    let service = Arc::new(
        PairingService::open(
            dir.path(),
            pairing::identity_fingerprint(&base.identity.node_id().to_hex()),
            true,
        )
        .unwrap(),
    );
    let signer = SigningKey::from_bytes(&[71; 32]);
    let client = service
        .create_ticket_remote_pairing(
            "phone",
            &hex::encode(signer.verifying_key().to_bytes()),
            &[72; 32],
        )
        .unwrap();
    let challenge = service.issue_token_challenge(&client.client_id).unwrap();
    let signature = hex::encode(signer.sign(challenge.as_bytes()).to_bytes());
    let token = service
        .issue_token(
            &base.identity.node_id().to_hex(),
            &base.jwt_secret,
            &client.client_id,
            &challenge,
            &signature,
        )
        .unwrap()
        .token;
    let state = Arc::new(AppState {
        pairing: Some(service),
        ..(*base).clone()
    });
    for (method, path) in [
        ("POST", "/api/v1/pair/device-key/op/delegate"),
        ("POST", "/api/v1/pair/device-key/op/approve"),
        ("DELETE", "/api/v1/pair/device-keys/key"),
        ("GET", "/api/v1/pair"),
        ("POST", "/api/v1/pair/revoke"),
        ("POST", "/api/v1/pair/window"),
        ("POST", "/api/v1/pair/request"),
        ("POST", "/api/v1/pair/confirm"),
        ("POST", "/api/v1/pair/relation-intent"),
        ("POST", "/api/v1/pair/first-contact-grant"),
        ("POST", "/api/v1/identity/replacement-request"),
        ("POST", "/api/v1/auth/local"),
        ("GET", "/metrics"),
    ] {
        for token in [None, Some(token.as_str())] {
            assert_eq!(
                remote_call(&state, method, path, Some(json!({})), token)
                    .await
                    .0,
                StatusCode::NOT_FOUND,
                "{method} {path}"
            );
        }
    }
}

// Pin the route declarations themselves: merging the full local device router
// would accidentally expose delegation, self-revocation and relation intents.
#[test]
fn remote_pairing_route_declarations_are_an_explicit_allowlist() {
    let source = include_str!("../src/handlers/pairing_routes.rs");
    let remote = source
        .split("pub fn remote_routes(")
        .nth(1)
        .unwrap()
        .split("#[cfg(test)]")
        .next()
        .unwrap();
    assert!(!remote.contains(".merge("));
    assert!(!remote.contains(".nest("));
    let compact: String = remote.chars().filter(|c| !c.is_whitespace()).collect();
    let declarations: Vec<_> = compact
        .split(".route(")
        .skip(1)
        .map(|route| {
            let mut depth = 1;
            let end = route
                .char_indices()
                .find_map(|(i, c)| {
                    match c {
                        '(' => depth += 1,
                        ')' => depth -= 1,
                        _ => {}
                    }
                    (depth == 0).then_some(i)
                })
                .unwrap();
            route[..end].trim_end_matches(',')
        })
        .collect();
    assert_eq!(
        declarations,
        vec![
            r#""/api/v1/pair/challenge",get(pair_challenge)"#,
            r#""/api/v1/pair/token",post(pair_token)"#,
            r#""/api/v1/pair/rotate",post(rotate_pairing)"#,
            r#""/api/v1/pair/elevation-request",post(elevation_request)"#,
            r#""/api/v1/pair/elevation/:op_id",get(elevation_status).delete(super::device_routes::cancel_elevation)"#,
            r#""/api/v1/pair/grant",get(own_grant)"#,
            r#""/api/v1/pair/first-contact-grant/:op_id",get(first_contact_status)"#,
            r#""/api/v1/pair/device-key",post(super::device_routes::request_device_key)"#,
            r#""/api/v1/pair/device-key/:op_id",get(super::device_routes::device_key_status).delete(super::device_routes::cancel_pending)"#,
            r#""/api/v1/pair/device-key/:op_id/finalize",post(super::device_routes::finalize_device_sas)"#,
            r#""/api/v1/pair/device-keys",get(super::device_routes::list_device_keys)"#,
        ]
    );
}

#[tokio::test]
async fn sas_enrollment_http_uses_server_noise_context_and_grants_no_authority() {
    use konsensus_api::rate_limit::{remote_tunnel_identity, RemoteTunnelClients};
    let dir = tempfile::tempdir().unwrap();
    let (claim, _) = konsensus_api::sas::initialize(dir.path()).unwrap();
    let base = test_state();
    let fp = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let owner = konsensus_core::OwnerApprovalKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", &[9; 32]).unwrap();
    let svc = Arc::new(
        PairingService::open(dir.path(), fp.clone(), true)
            .unwrap()
            .with_owner_console(Box::new(OwnerConsole::default()))
            .with_owner_approval_key(owner.verifying_key())
            .without_stdout_code(),
    );
    let signer = SigningKey::from_bytes(&[71; 32]);
    let client = svc
        .create_ticket_remote_pairing(
            "phone",
            &hex::encode(signer.verifying_key().to_bytes()),
            &[72; 32],
        )
        .unwrap();
    let challenge = svc.issue_token_challenge(&client.client_id).unwrap();
    let token = svc
        .issue_token(
            &base.identity.node_id().to_hex(),
            &base.jwt_secret,
            &client.client_id,
            &challenge,
            &hex::encode(signer.sign(challenge.as_bytes()).to_bytes()),
        )
        .unwrap()
        .token;
    let state = Arc::new(AppState {
        pairing: Some(svc.clone()),
        data_dir: Some(dir.path().into()),
        ..(*base).clone()
    });
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let sign = |message: &str| hex::encode(key.sign(&rng, message.as_bytes()).unwrap().as_ref());
    let body = json!({"sas_version":1,"public_key":public,"name":"phone","proof":sign(&registration_message(&fp, &client.client_id, &public))});
    let mut legacy = body.clone();
    legacy.as_object_mut().unwrap().remove("sas_version");
    assert!(remote_call(
        &state,
        "POST",
        "/api/v1/pair/device-key",
        Some(legacy),
        Some(&token)
    )
    .await
    .0
    .is_client_error());
    assert!(svc.pending_device_keys().is_empty());
    // A valid token and key without server-supplied Noise context cannot generate a nonce.
    assert_eq!(
        remote_call(
            &state,
            "POST",
            "/api/v1/pair/device-key",
            Some(body.clone()),
            Some(&token)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert!(svc.pending_device_keys().is_empty());
    let binding = konsensus_api::sas::NoiseBinding {
        handshake_hash: [73; 32],
        box_public_key: svc.box_transport_pubkey(),
        client_static: [72; 32],
    };
    let tunnels = Arc::new(RemoteTunnelClients::default());
    let peer: std::net::SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let _registration = tunnels.register_noise(peer, client.client_id.clone(), binding);
    let router = konsensus_api::build_remote_router_with_limiter(
        state.clone(),
        Arc::new(konsensus_api::rate_limit::RateLimiter::new(10_000)),
    )
    .layer(axum::middleware::from_fn_with_state(
        tunnels.clone(),
        remote_tunnel_identity,
    ))
    .layer(axum::extract::connect_info::MockConnectInfo(peer));
    let (status, pending) = call_router(
        router.clone(),
        "POST",
        "/api/v1/pair/device-key",
        Some(body),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{pending}");
    assert_eq!(pending["sas_version"], 1);
    assert!(pending["delegation_message"].is_null());
    let nonce: [u8; 16] = hex::decode(pending["box_nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let digest = konsensus_api::sas::digest(
        &binding,
        &key.public_key().as_ref().try_into().unwrap(),
        &nonce,
        &claim.commitment(),
    );
    let proof = sign(&pairing::device::sas_registration_message(
        &fp,
        &client.client_id,
        &public,
        &digest,
    ));
    let path = format!(
        "/api/v1/pair/device-key/{}/finalize",
        pending["op_id"].as_str().unwrap()
    );
    let body = json!({"sas_version":1,"sas_digest":digest.to_hex().to_string(),"proof":proof});
    assert_eq!(
        remote_call(&state, "POST", &path, Some(body.clone()), Some(&token))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call_router(router, "POST", &path, Some(body), Some(&token))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert!(svc.device_keys().is_empty());
    let mut secret = Vec::new();
    claim.write_local(&mut secret).unwrap();
    for forbidden in [
        String::from_utf8(secret).unwrap(),
        hex::encode(claim.commitment()),
        digest.to_hex().to_string(),
    ] {
        assert!(!pending.to_string().contains(&forbidden));
    }
}
