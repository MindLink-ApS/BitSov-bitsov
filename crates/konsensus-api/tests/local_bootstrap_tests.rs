use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use konsensus_api::{
    bootstrap::{self, BootstrapState, DataDirLayout, LocalOwnerHooks},
    pairing::{self, PairingService},
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

fn setup(dir: &std::path::Path) -> (Arc<BootstrapState>, String, String) {
    setup_mode(dir, false)
}

fn setup_mode(dir: &std::path::Path, enroll_device: bool) -> (Arc<BootstrapState>, String, String) {
    let pairing = Arc::new(
        PairingService::open(dir, String::new(), false)
            .unwrap()
            .without_stdout_code(),
    );
    let key = SigningKey::from_bytes(&[9; 32]);
    let public = hex::encode(key.verifying_key().to_bytes());
    let req = pairing.request_pairing("app", &public).unwrap();
    let challenge =
        std::fs::read(pairing.dir().join(format!("challenge-{}", req.pair_id))).unwrap();
    let sig = hex::encode(
        key.sign(&PairingService::proof_message(
            &req.pair_id,
            &public,
            &challenge,
        ))
        .to_bytes(),
    );
    let client = pairing
        .confirm_pairing(&req.pair_id, &sig, pairing::bootstrap_pairing_scopes())
        .unwrap();
    let state = Arc::new(
        BootstrapState::new(DataDirLayout::new(dir), pairing)
            .with_local_owner(test_hooks(enroll_device)),
    );
    let challenge = state
        .pairing
        .issue_token_challenge(&client.client_id)
        .unwrap();
    let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let token = state
        .pairing
        .issue_bootstrap_token(&state.jwt_secret, &client.client_id, &challenge, &sig)
        .unwrap()
        .token;
    (state, token, client.client_id)
}

fn test_hooks(enroll_device: bool) -> LocalOwnerHooks {
    LocalOwnerHooks {
        encrypt_seed: Box::new(|phrase, staging| {
            // Real authenticated encryption; production node hook is covered separately.
            use ring::aead;
            let key = aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, &[7; 32]).unwrap(),
            );
            let mut bytes = phrase.as_bytes().to_vec();
            key.seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key([0; 12]),
                aead::Aad::empty(),
                &mut bytes,
            )
            .unwrap();
            let path = staging.join("mnemonic.enc");
            std::fs::write(&path, bytes)?;
            Ok(path)
        }),
        sign_owner_approval: Box::new(|phrase, _, msg| {
            Ok(hex::encode(
                konsensus_core::OwnerApprovalKey::from_mnemonic(phrase, "", &[8; 32])
                    .unwrap()
                    .sign(msg.as_bytes())
                    .to_bytes(),
            ))
        }),
        enroll_device,
    }
}

async fn call(
    state: &Arc<BootstrapState>,
    token: &str,
    method: &str,
    path: &str,
    body: Value,
) -> (StatusCode, Value) {
    let response = bootstrap::build_bootstrap_router(state.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())),
    )
}

fn snapshot(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let path = e.unwrap().path();
        if path.is_dir() {
            out.extend(snapshot(&path));
        } else {
            out.push((path.clone(), std::fs::read(path).unwrap()));
        }
    }
    out.sort();
    out
}

fn finalize_body(p: &Value) -> Value {
    let words: Vec<_> = p["mnemonic"].as_str().unwrap().split_whitespace().collect();
    json!({"ceremony_id": p["ceremony_id"], "backup_words": p["backup_check"].as_array().unwrap().iter().map(|i| words[i.as_u64().unwrap() as usize]).collect::<Vec<_>>()})
}

#[tokio::test]
async fn pending_is_memory_only_and_finalize_is_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, _) = setup(dir.path());
    let (status, response) = call(&state, "", "GET", "/api/v1/bootstrap/state", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["state"], "bootstrap");
    assert_eq!(response["can_create"], true);
    assert_eq!(response["can_restore"], true);
    assert!(response.get("refusal").is_none());
    let before = snapshot(dir.path());
    let (status, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(before, snapshot(dir.path()));
    assert_eq!(
        call(
            &state,
            &token,
            "POST",
            "/api/v1/identity/create-pending",
            json!({})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let body = finalize_body(&p);
    let (status, response) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/finalize",
        body.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(response.get("mnemonic").is_none());
    assert!(dir.path().join("identity/mnemonic.enc").exists());
    for (path, bytes) in snapshot(dir.path()) {
        assert_ne!(path.extension().and_then(|s| s.to_str()), Some("txt"));
        assert!(!bytes
            .windows(p["mnemonic"].as_str().unwrap().len())
            .any(|w| w == p["mnemonic"].as_str().unwrap().as_bytes()));
    }
    assert!(state.is_committed());
    let (status, response) = call(&state, "", "GET", "/api/v1/bootstrap/state", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["state"], "initialized");
    assert_eq!(response["can_create"], false);
    assert_eq!(response["can_restore"], false);
    assert!(response.get("refusal").is_none());
    assert_eq!(
        call(&state, &token, "POST", "/api/v1/identity/finalize", body)
            .await
            .0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn cancel_and_three_bad_backups_discard_without_writes() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, _) = setup(dir.path());
    let before = snapshot(dir.path());
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    let bad = json!({"ceremony_id": p["ceremony_id"], "backup_words": ["wrong", "wrong", "wrong"]});
    for expected in [
        StatusCode::BAD_REQUEST,
        StatusCode::BAD_REQUEST,
        StatusCode::GONE,
    ] {
        assert_eq!(
            call(
                &state,
                &token,
                "POST",
                "/api/v1/identity/finalize",
                bad.clone()
            )
            .await
            .0,
            expected
        );
    }
    assert_eq!(before, snapshot(dir.path()));
    let (_, next) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_ne!(p["mnemonic"], next["mnemonic"]);
    let path = format!(
        "/api/v1/identity/pending/{}",
        next["ceremony_id"].as_str().unwrap()
    );
    assert_eq!(
        call(&state, &token, "DELETE", &path, json!({})).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(before, snapshot(dir.path()));
    drop(state);
    assert_eq!(before, snapshot(dir.path()));
}

#[tokio::test(start_paused = true)]
async fn expiry_never_reuses_phrase() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, _) = setup(dir.path());
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    tokio::time::advance(std::time::Duration::from_secs(1801)).await;
    assert_eq!(
        call(
            &state,
            &token,
            "POST",
            "/api/v1/identity/finalize",
            finalize_body(&p)
        )
        .await
        .0,
        StatusCode::GONE
    );
    let (_, next) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_ne!(p["mnemonic"], next["mnemonic"]);
}

#[tokio::test]
async fn local_routes_absent_without_hooks_and_password_body_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let pairing = Arc::new(PairingService::open(dir.path(), String::new(), false).unwrap());
    let state = Arc::new(BootstrapState::new(DataDirLayout::new(dir.path()), pairing));
    for path in [
        "/api/v1/identity/create-pending",
        "/api/v1/identity/finalize",
        "/api/v1/identity/mnemonic",
    ] {
        assert_eq!(
            call(&state, "", "POST", path, json!({})).await.0,
            StatusCode::NOT_FOUND
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let (state, token, _) = setup(dir.path());
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    let mut body = finalize_body(&p);
    body["password"] = json!("must-not-be-accepted");
    assert_eq!(
        call(&state, &token, "POST", "/api/v1/identity/finalize", body)
            .await
            .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert!(!state.is_committed());
}

fn device_body(p: &Value, client: &str) -> (Value, ring::signature::EcdsaKeyPair) {
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let fingerprint = pairing::identity_fingerprint(p["node_id"].as_str().unwrap());
    let msg = pairing::device::registration_message(&fingerprint, client, &public);
    let proof = hex::encode(key.sign(&rng, msg.as_bytes()).unwrap().as_ref());
    let mut body = finalize_body(p);
    body["device"] = json!({"public_key": public, "name": "This Mac", "proof": proof});
    (body, key)
}

#[tokio::test]
async fn enrollment_requires_device_and_bound_possession_before_writing() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, client) = setup_mode(dir.path(), true);
    let before = snapshot(dir.path());
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_eq!(
        call(
            &state,
            &token,
            "POST",
            "/api/v1/identity/finalize",
            finalize_body(&p)
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let (body, key) = device_body(&p, &client);
    let mut wrong = body.clone();
    wrong["device"]["proof"] = json!("deadbeef");
    assert_eq!(
        call(
            &state,
            &token,
            "POST",
            "/api/v1/identity/finalize",
            wrong.clone()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let msg = pairing::device::registration_message(
        "another-node",
        &client,
        body["device"]["public_key"].as_str().unwrap(),
    );
    wrong["device"]["proof"] = json!(hex::encode(
        key.sign(&ring::rand::SystemRandom::new(), msg.as_bytes())
            .unwrap()
            .as_ref()
    ));
    assert_eq!(
        call(&state, &token, "POST", "/api/v1/identity/finalize", wrong)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(before, snapshot(dir.path()));
    let foreign = state.finalize(
        "other-client",
        serde_json::from_value(body.clone()).unwrap(),
        bootstrap::CommitFault::None,
    );
    assert_eq!(foreign.err().unwrap().0, StatusCode::FORBIDDEN);
    let (status, response) = call(&state, &token, "POST", "/api/v1/identity/finalize", body).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    let keys = state.pairing.device_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].enrolled_by, "local_first_run");
    let fingerprint = pairing::identity_fingerprint(p["node_id"].as_str().unwrap());
    let owner = konsensus_core::OwnerApprovalKey::from_mnemonic(
        p["mnemonic"].as_str().unwrap(),
        "",
        &[8; 32],
    )
    .unwrap();
    let msg = pairing::device::owner_approval_message(
        &fingerprint,
        &keys[0].client_pubkey,
        keys[0].epoch,
        &keys[0].public_key,
    );
    pairing::device::verify_owner_approval(&owner.verifying_key(), &msg, &keys[0].owner_approval)
        .unwrap();
    assert_eq!(response["device_key_id"], keys[0].key_id);
    // Reopen actual persisted records; authority is derived, never loaded from disk.
    let live = PairingService::open(dir.path(), fingerprint.clone(), false)
        .unwrap()
        .with_local_owner_device()
        .with_owner_approval_key(owner.verifying_key());
    let intent = pairing::RelationIntent {
        device_key_id: keys[0].key_id.clone(),
        peer: "aa".repeat(32),
        level: 1,
        budget_msat: 100_000,
        per_act_max_msat: 10_000,
        window_secs: 3600,
        issued_at: chrono::Utc::now().timestamp(),
        nonce: "ab".repeat(16),
    };
    let msg = pairing::device::intent_message(&fingerprint, &client, &intent);
    let sig = hex::encode(
        key.sign(&ring::rand::SystemRandom::new(), msg.as_bytes())
            .unwrap()
            .as_ref(),
    );
    live.apply_relation_intent(&client, keys[0].epoch, &intent, &sig)
        .unwrap();
    live.reserve_spend(
        &client,
        keys[0].epoch,
        vec![konsensus_api::spend_budget::Charge {
            recipient: intent.peer.clone(),
            amount_msat: 1000,
        }],
    )
    .unwrap();
    drop(live);
    let no_flag = PairingService::open(dir.path(), fingerprint, false).unwrap();
    assert!(matches!(
        no_flag.apply_relation_intent(&client, keys[0].epoch, &intent, &sig),
        Err(pairing::PairingError::OwnerChannelUnavailable)
    ));
}

#[tokio::test]
async fn faults_never_write_plaintext_or_install_device_before_rename() {
    for fault in [
        bootstrap::CommitFault::AbortBeforeRename,
        bootstrap::CommitFault::AbortAfterRename,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (state, token, client) = setup_mode(dir.path(), true);
        let (_, p) = call(
            &state,
            &token,
            "POST",
            "/api/v1/identity/create-pending",
            json!({}),
        )
        .await;
        let (body, _) = device_body(&p, &client);
        let result = state.finalize(&client, serde_json::from_value(body).unwrap(), fault);
        assert_eq!(result.err().unwrap().0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(state.pairing.device_keys().is_empty());
        assert!(!state.layout.marker().exists());
        for (path, bytes) in snapshot(dir.path()) {
            assert_ne!(path.extension().and_then(|s| s.to_str()), Some("txt"));
            assert!(!bytes
                .windows(p["mnemonic"].as_str().unwrap().len())
                .any(|w| w == p["mnemonic"].as_str().unwrap().as_bytes()));
        }
        let probe = bootstrap::DataDirProbe::inspect(&state.layout).unwrap();
        let (status, response) =
            call(&state, "", "GET", "/api/v1/bootstrap/state", json!({})).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["local_owner"]["pending"], false);
        if fault == bootstrap::CommitFault::AbortBeforeRename {
            assert_eq!(response["state"], "bootstrap");
            assert_eq!(response["can_create"], true);
            assert_eq!(response["can_restore"], true);
            assert!(response.get("refusal").is_none());
            assert_eq!(
                bootstrap::classify(&probe),
                bootstrap::StartupMode::Bootstrap
            );
            assert_eq!(probe.stray_staging.len(), 1);
            let (_, fresh) = call(
                &state,
                &token,
                "POST",
                "/api/v1/identity/create-pending",
                json!({}),
            )
            .await;
            assert_ne!(fresh["mnemonic"], p["mnemonic"]);
        } else {
            // This unauthenticated probe must not expose disk or repair diagnostics.
            assert_eq!(
                response,
                json!({
                    "state": "refused",
                    "can_create": false,
                    "can_restore": false,
                    "local_owner": {
                        "available": true,
                        "enroll_device": true,
                        "pending": false
                    }
                })
            );
            match bootstrap::classify(&probe) {
                bootstrap::StartupMode::Refuse(r) => {
                    assert_eq!(r.reason, "identity_without_marker")
                }
                other => panic!("{other:?}"),
            }
            assert_eq!(
                call(
                    &state,
                    &token,
                    "POST",
                    "/api/v1/identity/create-pending",
                    json!({})
                )
                .await
                .0,
                StatusCode::CONFLICT
            );
        }
    }
}

#[tokio::test]
async fn device_install_failure_reports_refusal_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, client) = setup_mode(dir.path(), true);
    let mut hooks = test_hooks(true);
    // The device installer rejects an empty owner approval after the rename.
    hooks.sign_owner_approval = Box::new(|_, _, _| Ok(String::new()));
    let state = Arc::new(Arc::try_unwrap(state).ok().unwrap().with_local_owner(hooks));
    let (status, pending) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (body, _) = device_body(&pending, &client);
    let (status, _) = call(&state, &token, "POST", "/api/v1/identity/finalize", body).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(state.layout.identity_dir().join("mnemonic.enc").exists());
    assert!(!state.layout.marker().exists());
    assert!(!state.is_committed());
    assert!(state.pairing.device_keys().is_empty());

    let (status, response) = call(&state, "", "GET", "/api/v1/bootstrap/state", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(response["local_owner"]["pending"], false);
    // This unauthenticated probe must not expose disk or repair diagnostics.
    assert_eq!(
        response,
        json!({
            "state": "refused",
            "can_create": false,
            "can_restore": false,
            "local_owner": {
                "available": true,
                "enroll_device": true,
                "pending": false
            }
        })
    );
    assert!(matches!(
        state.transition(
            pending["mnemonic"].as_str().unwrap(),
            bootstrap::CommitFault::None,
        ),
        Err(bootstrap::CommitError::Conflict)
    ));
}

#[tokio::test]
async fn concurrent_finalize_has_exactly_one_commit() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, client) = setup_mode(dir.path(), true);
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    let (body, _) = device_body(&p, &client);
    let barrier = std::sync::Barrier::new(6);
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..6)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    state
                        .finalize(
                            &client,
                            serde_json::from_value(body.clone()).unwrap(),
                            bootstrap::CommitFault::None,
                        )
                        .map(|_| StatusCode::OK)
                        .unwrap_or_else(|e| e.0)
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|s| **s == StatusCode::OK).count(), 1);
        assert!(results
            .iter()
            .all(|s| *s == StatusCode::OK || *s == StatusCode::CONFLICT));
    });
    assert_eq!(state.pairing.device_keys().len(), 1);
    assert!(bootstrap::DataDirProbe::inspect(&state.layout)
        .unwrap()
        .stray_staging
        .is_empty());
    let path = format!(
        "/api/v1/identity/pending/{}",
        p["ceremony_id"].as_str().unwrap()
    );
    assert_eq!(
        call(&state, &token, "DELETE", &path, json!({})).await.0,
        StatusCode::CONFLICT
    );
}

#[tokio::test]
async fn lost_create_response_can_cancel_current_without_revealing_phrase() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, _) = setup(dir.path());
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    let (_, status) = call(&state, "", "GET", "/api/v1/bootstrap/state", json!({})).await;
    assert_eq!(status["local_owner"]["pending"], true);
    assert!(!status.to_string().contains(p["mnemonic"].as_str().unwrap()));
    assert_eq!(
        call(
            &state,
            &token,
            "DELETE",
            "/api/v1/identity/pending/current",
            json!({})
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let (_, fresh) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_ne!(fresh["mnemonic"], p["mnemonic"]);
}

#[tokio::test]
async fn local_auth_device_rejection_and_no_legacy_bypass() {
    use konsensus_api::auth::{self, Scope};
    let dir = tempfile::tempdir().unwrap();
    let (state, token, client) = setup(dir.path());
    for bad in [
        String::new(),
        auth::create_token("node", &state.jwt_secret, vec![Scope::Identity]).unwrap(),
    ] {
        assert_eq!(
            call(
                &state,
                &bad,
                "POST",
                "/api/v1/identity/create-pending",
                json!({})
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
    }
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    let (body, _) = device_body(&p, &client);
    assert_eq!(
        call(&state, &token, "POST", "/api/v1/identity/finalize", body)
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(&state, &token, "POST", "/api/v1/identity/create", json!({}))
            .await
            .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        call(
            &state,
            &token,
            "POST",
            "/api/v1/identity/restore",
            json!({"mnemonic": p["mnemonic"]})
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    for path in [
        "/api/v1/identity/mnemonic",
        "/api/v1/health",
        "/api/v1/pair/device-key",
    ] {
        assert_eq!(
            call(&state, &token, "GET", path, json!({})).await.0,
            StatusCode::NOT_FOUND
        );
    }
    assert!(!state.layout.identity_dir().exists());
}

#[tokio::test]
async fn encrypted_marker_is_last_after_device_and_config_hook() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, client) = setup_mode(dir.path(), true);
    let layout = state.layout.clone();
    let pairing = state.pairing.clone();
    let state = Arc::new(
        Arc::try_unwrap(state)
            .ok()
            .unwrap()
            .with_before_marker(move |outcome| {
                assert!(!layout.marker().exists());
                assert!(layout.identity_dir().join("mnemonic.enc").exists());
                assert_eq!(pairing.device_keys().len(), 1);
                assert!(!pairing.list_clients()[0]
                    .scopes
                    .contains(&konsensus_api::auth::Scope::Identity));
                std::fs::write(
                    layout.data_dir.join("aligned-path"),
                    outcome.mnemonic_path.to_str().unwrap(),
                )?;
                Ok(())
            }),
    );
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    let (body, _) = device_body(&p, &client);
    assert_eq!(
        call(&state, &token, "POST", "/api/v1/identity/finalize", body)
            .await
            .0,
        StatusCode::OK
    );
    assert!(state.layout.marker().exists());
    assert_eq!(
        std::fs::read_to_string(dir.path().join("aligned-path")).unwrap(),
        state
            .layout
            .identity_dir()
            .join("mnemonic.enc")
            .to_str()
            .unwrap()
    );
}

#[derive(Clone)]
struct CapturedLog(Arc<std::sync::Mutex<Vec<u8>>>);
impl std::io::Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn pending_finalize_never_log_phrase_words() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, _) = setup(dir.path());
    let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = CapturedLog(bytes.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_target(false)
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || captured.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tracing::info!("CAPTURE_SENTINEL");
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_eq!(
        call(
            &state,
            &token,
            "POST",
            "/api/v1/identity/finalize",
            finalize_body(&p)
        )
        .await
        .0,
        StatusCode::OK
    );
    let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    assert!(output.contains("CAPTURE_SENTINEL"));
    for word in p["mnemonic"].as_str().unwrap().split_whitespace() {
        assert!(!output.contains(word), "mnemonic word leaked");
    }
}

#[tokio::test]
async fn cancellation_during_commit_is_conflict() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, client) = setup(dir.path());
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let release = Arc::new(std::sync::Barrier::new(2));
    let wait = release.clone();
    let state = Arc::new(
        Arc::try_unwrap(state)
            .ok()
            .unwrap()
            .with_before_marker(move |_| {
                started_tx.send(()).unwrap();
                wait.wait();
                Ok(())
            }),
    );
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    let body = finalize_body(&p);
    let worker = state.clone();
    let handle = std::thread::spawn(move || {
        worker
            .finalize(
                &client,
                serde_json::from_value(body).unwrap(),
                bootstrap::CommitFault::None,
            )
            .is_ok()
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    // Binding was already retired by rebind. Direct handler invocation is
    // unnecessary: HTTP must refuse and cannot discard the committing phrase.
    let status = call(
        &state,
        &token,
        "DELETE",
        "/api/v1/identity/pending/current",
        json!({}),
    )
    .await
    .0;
    release.wait();
    assert!(handle.join().unwrap());
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn epoch_change_before_install_prevents_marker_and_owner_record() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, client) = setup_mode(dir.path(), true);
    let pairing = state.pairing.clone();
    let client_to_revoke = client.clone();
    let mut hooks = test_hooks(true);
    let sign = hooks.sign_owner_approval;
    hooks.sign_owner_approval = Box::new(move |phrase, node, message| {
        pairing.bump_epoch(&client_to_revoke).unwrap();
        sign(phrase, node, message)
    });
    let state = Arc::new(Arc::try_unwrap(state).ok().unwrap().with_local_owner(hooks));
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    let (body, _) = device_body(&p, &client);
    assert_eq!(
        call(&state, &token, "POST", "/api/v1/identity/finalize", body)
            .await
            .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(!state.layout.marker().exists());
    assert!(state.pairing.device_keys().is_empty());
}

#[tokio::test]
async fn encryption_failure_never_falls_back_or_writes_marker() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, _) = setup(dir.path());
    let mut hooks = test_hooks(false);
    hooks.encrypt_seed = Box::new(|_, _| {
        Err(bootstrap::CommitError::Io(
            "injected encryption failure".into(),
        ))
    });
    let state = Arc::new(Arc::try_unwrap(state).ok().unwrap().with_local_owner(hooks));
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_eq!(
        call(
            &state,
            &token,
            "POST",
            "/api/v1/identity/finalize",
            finalize_body(&p)
        )
        .await
        .0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(!state.layout.marker().exists());
    assert!(!state.layout.identity_dir().exists());
    assert!(snapshot(dir.path())
        .iter()
        .all(|(path, _)| path.file_name().unwrap() != "mnemonic.txt"));
    let (_, status) = call(&state, "", "GET", "/api/v1/bootstrap/state", json!({})).await;
    assert_eq!(status["local_owner"]["pending"], false);
}

#[tokio::test]
async fn shutdown_with_pending_leaves_no_identity() {
    let dir = tempfile::tempdir().unwrap();
    let (state, token, _) = setup(dir.path());
    let before = snapshot(dir.path());
    let (status, _) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    drop(state);
    assert_eq!(before, snapshot(dir.path()));
    assert_eq!(
        bootstrap::classify(
            &bootstrap::DataDirProbe::inspect(&DataDirLayout::new(dir.path())).unwrap()
        ),
        bootstrap::StartupMode::Bootstrap
    );
}

#[tokio::test]
async fn another_authenticated_client_cannot_finalize_or_cancel() {
    use konsensus_api::auth;
    let dir = tempfile::tempdir().unwrap();
    let (state, token, _) = setup_mode(dir.path(), true);
    // Bootstrap normally closes after one pairing. Exercise the binding even
    // when two authenticated records are present (e.g. a legacy pairing file).
    let path = state.pairing.dir().join("clients.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut other = file["clients"][0].clone();
    other["client_id"] = json!("another-client");
    file["clients"].as_array_mut().unwrap().push(other.clone());
    std::fs::write(path, file.to_string()).unwrap();
    let mut state = Arc::try_unwrap(state).ok().unwrap();
    state.pairing = Arc::new(PairingService::open(dir.path(), String::new(), false).unwrap());
    let other_token = auth::create_bootstrap_token(
        &state.jwt_secret,
        pairing::bootstrap_pairing_scopes(),
        "another-client",
        other["epoch"].as_u64().unwrap(),
    )
    .unwrap();
    let state = Arc::new(state);
    let before = snapshot(dir.path());
    let (_, p) = call(
        &state,
        &token,
        "POST",
        "/api/v1/identity/create-pending",
        json!({}),
    )
    .await;
    assert_eq!(
        call(
            &state,
            &other_token,
            "POST",
            "/api/v1/identity/finalize",
            finalize_body(&p)
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &state,
            &other_token,
            "DELETE",
            "/api/v1/identity/pending/current",
            json!({})
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let client = state.pairing.list_clients()[0].client_id.clone();
    let (body, _) = device_body(&p, &client);
    assert_eq!(
        call(&state, &token, "POST", "/api/v1/identity/finalize", body)
            .await
            .0,
        StatusCode::FORBIDDEN,
        "enrollment requires exactly one client"
    );
    assert_eq!(before, snapshot(dir.path()));
}

// ── Remote first run (P2): password only through the box-static tunnel ──

const REMOTE_PASSWORD: &str = "remote-first-run-tunnel-secret";
const TUNNEL_PEER: &str = "127.0.0.1:40001";

/// Owner key derived from the password the hook actually received.
fn remote_owner_key(phrase: &str, password: &str) -> konsensus_core::OwnerApprovalKey {
    konsensus_core::OwnerApprovalKey::from_mnemonic(
        phrase,
        "",
        blake3::hash(password.as_bytes()).as_bytes(),
    )
    .unwrap()
}

fn remote_hooks(password: zeroize::Zeroizing<String>) -> LocalOwnerHooks {
    let password = Arc::new(password);
    let mut hooks = test_hooks(false);
    hooks.sign_owner_approval = Box::new(move |phrase, _, msg| {
        Ok(hex::encode(
            remote_owner_key(phrase, &password)
                .sign(msg.as_bytes())
                .to_bytes(),
        ))
    });
    hooks
}

struct Remote {
    state: Arc<BootstrapState>,
    token: String,
    client: String,
    tunnel: Arc<konsensus_api::rate_limit::RemoteTunnelClients>,
    _registration: konsensus_api::rate_limit::RemoteTunnelRegistration,
}

fn setup_remote(dir: &std::path::Path) -> Remote {
    let pairing = Arc::new(
        PairingService::open(dir, String::new(), false)
            .unwrap()
            .without_stdout_code(),
    );
    let key = SigningKey::from_bytes(&[9; 32]);
    let public = hex::encode(key.verifying_key().to_bytes());
    let client = pairing
        .create_bootstrap_ticket_pairing("phone", &public, &[0x55; 32])
        .unwrap();
    assert_eq!(client.scopes, pairing::bootstrap_pairing_scopes());
    assert!(
        !pairing.pairing_open(),
        "a ticket never opens the local window"
    );
    // Bootstrap tickets pair exactly one first client.
    let second = hex::encode(SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes());
    assert!(matches!(
        pairing.create_bootstrap_ticket_pairing("other", &second, &[0x56; 32]),
        Err(pairing::PairingError::Closed)
    ));
    let tunnel = Arc::new(konsensus_api::rate_limit::RemoteTunnelClients::default());
    let registration = tunnel.register(TUNNEL_PEER.parse().unwrap(), client.client_id.clone());
    let state = Arc::new(
        BootstrapState::new(DataDirLayout::new(dir), pairing).with_remote_owner(
            bootstrap::RemoteOwner {
                hooks: Box::new(|password| Ok(remote_hooks(password))),
                tunnel: tunnel.clone(),
            },
        ),
    );
    let challenge = state
        .pairing
        .issue_token_challenge(&client.client_id)
        .unwrap();
    let sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let token = state
        .pairing
        .issue_bootstrap_token(&state.jwt_secret, &client.client_id, &challenge, &sig)
        .unwrap()
        .token;
    Remote {
        state,
        token,
        client: client.client_id,
        tunnel,
        _registration: registration,
    }
}

async fn call_via(
    state: &Arc<BootstrapState>,
    token: &str,
    path: &str,
    body: Value,
    peer: Option<&str>,
) -> (StatusCode, Value) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    if let Some(peer) = peer {
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo::<std::net::SocketAddr>(
                peer.parse().unwrap(),
            ));
    }
    let response = bootstrap::build_bootstrap_router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned())),
    )
}

fn commitment(password: &str) -> Value {
    json!({"password_commitment": blake3::hash(password.as_bytes()).to_hex().to_string()})
}

#[tokio::test]
async fn remote_first_run_password_is_tunnel_only_and_committed() {
    let dir = tempfile::tempdir().unwrap();
    let r = setup_remote(dir.path());
    let tunnel = Some(TUNNEL_PEER);
    let (_, status) = call(&r.state, "", "GET", "/api/v1/bootstrap/state", json!({})).await;
    assert_eq!(
        status,
        json!({"state": "bootstrap", "can_create": true, "can_restore": false,
               "local_owner": {"available": true, "enroll_device": true, "pending": false, "tunnel_password": true}})
    );
    // No startup password: legacy create/restore would write a plaintext seed.
    for path in ["/api/v1/identity/create", "/api/v1/identity/restore"] {
        assert_eq!(
            call_via(&r.state, &r.token, path, json!({}), tunnel)
                .await
                .0,
            StatusCode::NOT_FOUND
        );
    }
    let before = snapshot(dir.path());
    let pending_path = "/api/v1/identity/create-pending";
    // Loopback and an unregistered internal peer are not the tunnel.
    for peer in [None, Some("127.0.0.1:40002")] {
        let (status, body) = call_via(
            &r.state,
            &r.token,
            pending_path,
            commitment(REMOTE_PASSWORD),
            peer,
        )
        .await;
        assert_eq!(
            (status, body),
            (StatusCode::BAD_REQUEST, json!("tunnel_required"))
        );
    }
    for bad in ["zz".repeat(32), "AB".repeat(32), "ab".into()] {
        let (status, body) = call_via(
            &r.state,
            &r.token,
            pending_path,
            json!({"password_commitment": bad}),
            tunnel,
        )
        .await;
        assert_eq!(
            (status, body),
            (
                StatusCode::BAD_REQUEST,
                json!("invalid_password_commitment")
            )
        );
    }
    let (status, p) = call_via(
        &r.state,
        &r.token,
        pending_path,
        commitment(REMOTE_PASSWORD),
        tunnel,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{p}");
    assert_eq!(before, snapshot(dir.path()));

    let finalize = "/api/v1/identity/finalize";
    let (mut body, device) = device_body(&p, &r.client);
    body["password"] = json!(REMOTE_PASSWORD);
    // The loopback path refuses a password before reading the body.
    for peer in [None, Some("127.0.0.1:40002")] {
        let (status, response) = call_via(&r.state, &r.token, finalize, body.clone(), peer).await;
        assert_eq!(
            (status, response),
            (StatusCode::BAD_REQUEST, json!("tunnel_required"))
        );
    }
    let mut missing = body.clone();
    missing.as_object_mut().unwrap().remove("password");
    assert_eq!(
        call_via(&r.state, &r.token, finalize, missing, tunnel).await,
        (StatusCode::BAD_REQUEST, json!("invalid_finalize_body"))
    );
    let mut no_device = body.clone();
    no_device.as_object_mut().unwrap().remove("device");
    assert_eq!(
        call_via(&r.state, &r.token, finalize, no_device, tunnel).await,
        (
            StatusCode::BAD_REQUEST,
            json!("device_requirement_mismatch")
        )
    );
    let mut empty = body.clone();
    empty["password"] = json!("");
    assert_eq!(
        call_via(&r.state, &r.token, finalize, empty, tunnel).await,
        (StatusCode::BAD_REQUEST, json!("password_required"))
    );
    let mut wrong = body.clone();
    wrong["password"] = json!("not-the-committed-password");
    assert_eq!(
        call_via(&r.state, &r.token, finalize, wrong, tunnel).await,
        (
            StatusCode::BAD_REQUEST,
            json!("password_commitment_mismatch")
        )
    );
    assert!(!r.state.is_committed());
    assert_eq!(before, snapshot(dir.path()));
    let (_, status) = call(&r.state, "", "GET", "/api/v1/bootstrap/state", json!({})).await;
    assert_eq!(status["local_owner"]["pending"], true);

    let (status, response) = call_via(&r.state, &r.token, finalize, body, tunnel).await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert!(r.state.is_committed());
    assert!(dir.path().join("identity/mnemonic.enc").exists());
    assert!(!dir.path().join("identity/mnemonic.txt").exists());
    let phrase = p["mnemonic"].as_str().unwrap();
    for (_, bytes) in snapshot(dir.path()) {
        for secret in [phrase, REMOTE_PASSWORD] {
            assert!(!bytes.windows(secret.len()).any(|w| w == secret.as_bytes()));
        }
    }
    assert!(!response.to_string().contains(REMOTE_PASSWORD));

    let keys = r.state.pairing.device_keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].enrolled_by, "remote_first_run");
    assert_eq!(
        keys[0].public_key,
        hex::encode(ring::signature::KeyPair::public_key(&device).as_ref())
    );
    let node_id = p["node_id"].as_str().unwrap();
    let fingerprint = pairing::identity_fingerprint(node_id);
    let msg = pairing::device::owner_approval_message(
        &fingerprint,
        &keys[0].client_pubkey,
        keys[0].epoch,
        &keys[0].public_key,
    );
    pairing::device::verify_owner_approval(
        &remote_owner_key(phrase, REMOTE_PASSWORD).verifying_key(),
        &msg,
        &keys[0].owner_approval,
    )
    .unwrap();

    // Commit strips identity authority but keeps the tunnel binding, and
    // publishes the signed box key a locked restart verifies.
    let clients = r.state.pairing.list_clients();
    assert_eq!(clients[0].scopes, pairing::default_pairing_scopes());
    assert_eq!(clients[0].identity_fingerprint, fingerprint);
    assert_eq!(
        r.state
            .pairing
            .validate_remote_transport(&[0x55; 32])
            .unwrap()
            .client_id,
        r.client
    );
    let metadata: Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("identity/identity.json")).unwrap())
            .unwrap();
    assert_eq!(metadata["node_id"], node_id);
    assert_eq!(metadata["identity_fingerprint"], fingerprint);
    assert!(metadata["committed_at"].is_i64());
    let box_key = hex::encode(r.state.pairing.box_transport_pubkey());
    assert_eq!(metadata["box_transport_pubkey"], box_key);
    assert_eq!(response["box_transport_pubkey"], box_key);
    assert_eq!(response["client_id"], r.client);
    assert_eq!(response["epoch"], keys[0].epoch);
    assert_eq!(response["transport_pubkey"], metadata["transport_pubkey"]);
    assert_eq!(
        response["transport_signature"],
        metadata["transport_signature"]
    );
    assert_eq!(
        response["box_transport_signature"],
        metadata["box_transport_signature"]
    );
    let identity = konsensus_core::NodeIdentity::from_mnemonic(phrase, "").unwrap();
    use base64::Engine as _;
    let signature = ed25519_dalek::Signature::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(metadata["box_transport_signature"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    identity
        .ed25519_verifying_key()
        .verify_strict(
            konsensus_api::remote_access::box_transport_proof_message(node_id, &box_key).as_bytes(),
            &signature,
        )
        .unwrap();
    // Bootstrap pairing authority is closed for good once an identity is bound.
    let late = hex::encode(SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes());
    assert!(r
        .state
        .pairing
        .create_bootstrap_ticket_pairing("late", &late, &[0x57; 32])
        .is_err());
}

#[tokio::test]
async fn remote_first_run_rejects_foreign_tunnel_and_repeated_wrong_passwords() {
    let dir = tempfile::tempdir().unwrap();
    let r = setup_remote(dir.path());
    // A tunnel registered to another pairing cannot carry this client's token.
    let _other = r
        .tunnel
        .register("127.0.0.1:40003".parse().unwrap(), "another-client".into());
    let pending_path = "/api/v1/identity/create-pending";
    assert_eq!(
        call_via(
            &r.state,
            &r.token,
            pending_path,
            commitment(REMOTE_PASSWORD),
            Some("127.0.0.1:40003")
        )
        .await,
        (StatusCode::BAD_REQUEST, json!("tunnel_required"))
    );
    let (_, p) = call_via(
        &r.state,
        &r.token,
        pending_path,
        commitment(REMOTE_PASSWORD),
        Some(TUNNEL_PEER),
    )
    .await;
    let (mut body, _) = device_body(&p, &r.client);
    body["password"] = json!("wrong");
    let before = snapshot(dir.path());
    for expected in [
        (
            StatusCode::BAD_REQUEST,
            json!("password_commitment_mismatch"),
        ),
        (
            StatusCode::BAD_REQUEST,
            json!("password_commitment_mismatch"),
        ),
        (StatusCode::GONE, json!("ceremony_lost")),
    ] {
        assert_eq!(
            call_via(
                &r.state,
                &r.token,
                "/api/v1/identity/finalize",
                body.clone(),
                Some(TUNNEL_PEER)
            )
            .await,
            expected
        );
    }
    body["password"] = json!(REMOTE_PASSWORD);
    assert_eq!(
        call_via(
            &r.state,
            &r.token,
            "/api/v1/identity/finalize",
            body,
            Some(TUNNEL_PEER)
        )
        .await,
        (StatusCode::GONE, json!("ceremony_lost"))
    );
    assert!(!r.state.is_committed());
    assert_eq!(before, snapshot(dir.path()));
    assert!(matches!(
        r.state.transition(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            bootstrap::CommitFault::None
        ),
        Err(bootstrap::CommitError::Conflict)
    ));
    assert_eq!(before, snapshot(dir.path()));
}

#[tokio::test]
async fn sas_version_requires_committed_device_and_completed_noise() {
    let dir = tempfile::tempdir().unwrap();
    let r = setup_remote(dir.path());
    let mut request = commitment(REMOTE_PASSWORD);
    request["sas_version"] = json!(1);
    let (status, _) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/create-pending",
        request.clone(),
        Some(TUNNEL_PEER),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    request["device"] = json!({"public_key": format!("04{}", "11".repeat(64)), "name": "phone"});
    let (status, _) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/create-pending",
        request,
        Some(TUNNEL_PEER),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

fn sas_binding(r: &Remote) -> konsensus_api::sas::NoiseBinding {
    konsensus_api::sas::NoiseBinding {
        handshake_hash: [0x19; 32],
        box_public_key: r.state.pairing.box_transport_pubkey(),
        client_static: [0x55; 32],
    }
}
fn sas_device() -> ring::signature::EcdsaKeyPair {
    use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap()
}
fn sas_create(key: &ring::signature::EcdsaKeyPair) -> Value {
    use ring::signature::KeyPair;
    let mut request = commitment(REMOTE_PASSWORD);
    request["sas_version"] = json!(1);
    request["device"] =
        json!({"public_key": hex::encode(key.public_key().as_ref()), "name": "SAS phone"});
    request
}
fn sas_finalize(
    r: &Remote,
    p: &Value,
    key: &ring::signature::EcdsaKeyPair,
    code: &konsensus_api::sas::ClaimCode,
) -> Value {
    use ring::signature::KeyPair;
    let nonce: [u8; 16] = hex::decode(p["box_nonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let digest = konsensus_api::sas::digest(
        &sas_binding(r),
        &key.public_key().as_ref().try_into().unwrap(),
        &nonce,
        &code.commitment(),
    );
    let message = pairing::device::sas_registration_message(
        &pairing::identity_fingerprint(p["node_id"].as_str().unwrap()),
        &r.client,
        &public,
        &digest,
    );
    let proof = hex::encode(
        key.sign(&ring::rand::SystemRandom::new(), message.as_bytes())
            .unwrap()
            .as_ref(),
    );
    let mut body = finalize_body(p);
    body["password"] = json!(REMOTE_PASSWORD);
    body["sas_version"] = json!(1);
    body["sas_digest"] = json!(digest.to_hex().to_string());
    body["device"] = json!({"public_key": public, "name": "SAS phone", "proof": proof});
    body
}

async fn approve_on_box(r: &Remote, body: &Value) {
    use axum::extract::ConnectInfo;
    use bootstrap::setup::{router, SetupPage};
    let page = Arc::new(SetupPage::new(
        Some(r.state.clone()),
        None,
        vec!["bitsov.local".into()],
        "Box".into(),
        "SETUP".into(),
    ));
    let peer = ConnectInfo("192.168.1.2:9000".parse::<std::net::SocketAddr>().unwrap());
    let mut req = Request::builder()
        .uri("/")
        .header("host", "bitsov.local")
        .body(Body::empty())
        .unwrap();
    req.extensions_mut().insert(peer);
    let response = router(page.clone()).oneshot(req).await.unwrap();
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let html = String::from_utf8(
        axum::body::to_bytes(response.into_body(), 100000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let csrf = html
        .split("const csrf = '")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap();
    let mut req = Request::builder()
        .method("POST")
        .uri("/setup/approve")
        .header("host", "bitsov.local")
        .header("cookie", cookie)
        .header("x-csrf-token", csrf)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"ceremony_id":body["ceremony_id"],"sas_digest":body["sas_digest"]}).to_string(),
        ))
        .unwrap();
    req.extensions_mut().insert(peer);
    assert_eq!(
        router(page).oneshot(req).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn claim_code_refuses_remote_legacy_before_any_sas_attempt() {
    let dir = tempfile::tempdir().unwrap();
    konsensus_api::sas::initialize(dir.path()).unwrap();
    let r = setup_remote(dir.path());
    let (status, _) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/create-pending",
        commitment(REMOTE_PASSWORD),
        Some(TUNNEL_PEER),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!r.state.is_committed());
}

#[tokio::test]
async fn claim_code_also_blocks_an_already_pending_legacy_finalize() {
    let dir = tempfile::tempdir().unwrap();
    let r = setup_remote(dir.path());
    let (status, p) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/create-pending",
        commitment(REMOTE_PASSWORD),
        Some(TUNNEL_PEER),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    konsensus_api::sas::initialize(dir.path()).unwrap();
    let (mut body, _) = device_body(&p, &r.client);
    body["password"] = json!(REMOTE_PASSWORD);
    assert_eq!(
        call_via(
            &r.state,
            &r.token,
            "/api/v1/identity/finalize",
            body,
            Some(TUNNEL_PEER)
        )
        .await,
        (StatusCode::FORBIDDEN, json!("sas_required"))
    );
    assert!(!r.state.is_committed());
    assert!(!dir.path().join("NODE_INITIALIZED").exists());
}

#[tokio::test]
async fn sas_finalize_waits_for_box_approval() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _) = konsensus_api::sas::initialize(dir.path()).unwrap();
    let r = setup_remote(dir.path());
    let _guard = r.tunnel.register_noise(
        TUNNEL_PEER.parse().unwrap(),
        r.client.clone(),
        sas_binding(&r),
    );
    let key = sas_device();
    let (status, p) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/create-pending",
        sas_create(&key),
        Some(TUNNEL_PEER),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/finalize",
        sas_finalize(&r, &p, &key, &code),
        Some(TUNNEL_PEER),
    )
    .await;
    assert_eq!(
        (status, body),
        (StatusCode::CONFLICT, json!("box_approval_pending"))
    );
    assert!(!r.state.is_committed());
    assert!(!dir.path().join("NODE_INITIALIZED").exists());
}

#[tokio::test]
async fn sas_remote_round_trip_binds_device_and_never_returns_claim_material() {
    let logs = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = CapturedLog(logs.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    let _capture = tracing::subscriber::set_default(subscriber);
    tracing::info!("SAS_CAPTURE_SENTINEL");
    let dir = tempfile::tempdir().unwrap();
    let (code, _) = konsensus_api::sas::initialize(dir.path()).unwrap();
    let r = setup_remote(dir.path());
    let _guard = r.tunnel.register_noise(
        TUNNEL_PEER.parse().unwrap(),
        r.client.clone(),
        sas_binding(&r),
    );
    let key = sas_device();
    let (status, p) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/create-pending",
        sas_create(&key),
        Some(TUNNEL_PEER),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{p}");
    assert_eq!(p["sas_version"], 1);
    assert_eq!(p["box_nonce"].as_str().unwrap().len(), 32);
    assert!(p["expires_at"].as_i64().unwrap() <= chrono::Utc::now().timestamp() + 900);
    let mut secret = Vec::new();
    code.write_local(&mut secret).unwrap();
    for forbidden in [
        String::from_utf8(secret).unwrap(),
        hex::encode(code.commitment()),
        "sas_digest".into(),
    ] {
        assert!(!p.to_string().contains(&forbidden));
    }
    // A second request cannot replace or reveal another nonce.
    assert_eq!(
        call_via(
            &r.state,
            &r.token,
            "/api/v1/identity/create-pending",
            sas_create(&key),
            Some(TUNNEL_PEER)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    let body = sas_finalize(&r, &p, &key, &code);
    approve_on_box(&r, &body).await;
    let (status, result) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/finalize",
        body,
        Some(TUNNEL_PEER),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    assert!(r.state.is_committed());
    let captured = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
    assert!(captured.contains("SAS_CAPTURE_SENTINEL"));
    let mut secret = Vec::new();
    code.write_local(&mut secret).unwrap();
    assert!(!captured.contains(std::str::from_utf8(&secret).unwrap()));
    assert!(!captured.contains(&hex::encode(code.commitment())));
}

#[tokio::test]
async fn sas_three_mismatches_or_cancels_close_setup_including_legacy_downgrade() {
    for cancel in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (code, _) = konsensus_api::sas::initialize(dir.path()).unwrap();
        let r = setup_remote(dir.path());
        let _guard = r.tunnel.register_noise(
            TUNNEL_PEER.parse().unwrap(),
            r.client.clone(),
            sas_binding(&r),
        );
        let key = sas_device();
        let mut nonces = std::collections::HashSet::new();
        for attempt in 0..3 {
            let (status, p) = call_via(
                &r.state,
                &r.token,
                "/api/v1/identity/create-pending",
                sas_create(&key),
                Some(TUNNEL_PEER),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{p}");
            assert!(nonces.insert(p["box_nonce"].clone().to_string()));
            if cancel {
                assert_eq!(
                    call(
                        &r.state,
                        &r.token,
                        "DELETE",
                        &format!(
                            "/api/v1/identity/pending/{}",
                            p["ceremony_id"].as_str().unwrap()
                        ),
                        json!({})
                    )
                    .await
                    .0,
                    StatusCode::NO_CONTENT
                );
            } else {
                let mut body = sas_finalize(&r, &p, &key, &code);
                match attempt {
                    0 => {
                        body.as_object_mut().unwrap().remove("sas_digest");
                    }
                    1 => body["sas_digest"] = json!("00".repeat(32)),
                    _ => body["device"]["public_key"] = json!(format!("04{}", "22".repeat(64))),
                }
                assert_eq!(
                    call_via(
                        &r.state,
                        &r.token,
                        "/api/v1/identity/finalize",
                        body,
                        Some(TUNNEL_PEER)
                    )
                    .await
                    .0,
                    StatusCode::BAD_REQUEST
                );
            }
            assert!(!r.state.is_committed());
        }
        for request in [sas_create(&key), commitment(REMOTE_PASSWORD)] {
            let (status, body) = call_via(
                &r.state,
                &r.token,
                "/api/v1/identity/create-pending",
                request,
                Some(TUNNEL_PEER),
            )
            .await;
            assert_eq!(
                (status, body),
                (StatusCode::FORBIDDEN, json!("setup_closed"))
            );
        }
        // A process restart resets the attempt budget (the protected code stays).
        let restarted = Arc::new(
            BootstrapState::new(DataDirLayout::new(dir.path()), r.state.pairing.clone())
                .with_remote_owner(bootstrap::RemoteOwner {
                    hooks: Box::new(|password| Ok(remote_hooks(password))),
                    tunnel: r.tunnel.clone(),
                }),
        );
        let challenge = restarted.pairing.issue_token_challenge(&r.client).unwrap();
        let signature = hex::encode(
            SigningKey::from_bytes(&[9; 32])
                .sign(challenge.as_bytes())
                .to_bytes(),
        );
        let token = restarted
            .pairing
            .issue_bootstrap_token(&restarted.jwt_secret, &r.client, &challenge, &signature)
            .unwrap()
            .token;
        assert_eq!(
            call_via(
                &restarted,
                &token,
                "/api/v1/identity/create-pending",
                sas_create(&key),
                Some(TUNNEL_PEER)
            )
            .await
            .0,
            StatusCode::OK
        );
    }
}

#[tokio::test(start_paused = true)]
async fn sas_expires_after_fifteen_minutes_and_cannot_finalize_on_another_noise_session() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _) = konsensus_api::sas::initialize(dir.path()).unwrap();
    let r = setup_remote(dir.path());
    let _guard = r.tunnel.register_noise(
        TUNNEL_PEER.parse().unwrap(),
        r.client.clone(),
        sas_binding(&r),
    );
    tokio::time::advance(std::time::Duration::from_secs(840)).await;
    let key = sas_device();
    let (_, p) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/create-pending",
        sas_create(&key),
        Some(TUNNEL_PEER),
    )
    .await;
    assert!(p["expires_at"].as_i64().unwrap() <= chrono::Utc::now().timestamp() + 60);
    let body = sas_finalize(&r, &p, &key, &code);
    let mut changed = sas_binding(&r);
    changed.handshake_hash[0] ^= 1;
    let _other = r.tunnel.register_noise(
        "127.0.0.1:49999".parse().unwrap(),
        r.client.clone(),
        changed,
    );
    assert_eq!(
        call_via(
            &r.state,
            &r.token,
            "/api/v1/identity/finalize",
            body.clone(),
            Some("127.0.0.1:49999")
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    tokio::time::advance(std::time::Duration::from_secs(900)).await;
    assert_eq!(
        call_via(
            &r.state,
            &r.token,
            "/api/v1/identity/finalize",
            body,
            Some(TUNNEL_PEER)
        )
        .await
        .0,
        StatusCode::GONE
    );
    assert!(!r.state.is_committed());
}

#[tokio::test]
async fn sas_noise_binding_is_rechecked_after_a_delayed_finalize_body() {
    let dir = tempfile::tempdir().unwrap();
    let (code, _) = konsensus_api::sas::initialize(dir.path()).unwrap();
    let r = setup_remote(dir.path());
    let _guard = r.tunnel.register_noise(
        TUNNEL_PEER.parse().unwrap(),
        r.client.clone(),
        sas_binding(&r),
    );
    let mut changed = sas_binding(&r);
    changed.handshake_hash[0] ^= 1;
    let peer: std::net::SocketAddr = "127.0.0.1:49999".parse().unwrap();
    let _other = r.tunnel.register_noise(peer, r.client.clone(), changed);
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let body = Body::from_stream(futures::stream::once(async move {
        started_tx.send(()).unwrap();
        Ok::<_, std::io::Error>(rx.await.unwrap())
    }));
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/identity/finalize")
        .header("authorization", format!("Bearer {}", r.token))
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    request
        .extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));
    let router = bootstrap::build_bootstrap_router(r.state.clone());
    let task = tokio::spawn(async move { router.oneshot(request).await.unwrap() });
    started_rx.await.unwrap();
    let key = sas_device();
    let (_, p) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/create-pending",
        sas_create(&key),
        Some(TUNNEL_PEER),
    )
    .await;
    tx.send(sas_finalize(&r, &p, &key, &code).to_string())
        .unwrap();
    assert_eq!(task.await.unwrap().status(), StatusCode::FORBIDDEN);
    assert!(!r.state.is_committed());
}

#[tokio::test(start_paused = true)]
async fn sas_boot_window_cannot_be_reopened_after_expiry() {
    let dir = tempfile::tempdir().unwrap();
    konsensus_api::sas::initialize(dir.path()).unwrap();
    let r = setup_remote(dir.path());
    let _guard = r.tunnel.register_noise(
        TUNNEL_PEER.parse().unwrap(),
        r.client.clone(),
        sas_binding(&r),
    );
    tokio::time::advance(std::time::Duration::from_secs(900)).await;
    let (status, _) = call_via(
        &r.state,
        &r.token,
        "/api/v1/identity/create-pending",
        sas_create(&sas_device()),
        Some(TUNNEL_PEER),
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
}
