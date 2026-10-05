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
            assert_eq!(response["state"], "refused");
            assert_eq!(response["can_create"], false);
            assert_eq!(response["can_restore"], false);
            assert_eq!(response["refusal"]["reason"], "identity_without_marker");
            assert!(response["refusal"]["repair"]
                .as_str()
                .unwrap()
                .contains("konsensus repair mark-initialized"));
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
    assert_eq!(response["state"], "refused");
    assert_eq!(response["can_create"], false);
    assert_eq!(response["can_restore"], false);
    assert_eq!(response["local_owner"]["pending"], false);
    assert_eq!(response["refusal"]["reason"], "identity_without_marker");
    assert!(response["refusal"]["repair"]
        .as_str()
        .unwrap()
        .contains("konsensus repair mark-initialized"));
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
