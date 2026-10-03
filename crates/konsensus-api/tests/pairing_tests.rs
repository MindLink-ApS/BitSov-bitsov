//! The pairing ceremony on the live router, and the absence of every HTTP path
//! that could write a grant or consume an approval (#76).
//!
//! HTTP cases use `oneshot`; WebSocket cases use disposable loopback port 0
//! listeners and socket cases use temp directories. No live node is started.

mod common;

#[path = "common/owner_console.rs"]
mod owner_console;
use owner_console::OwnerConsole;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use tower::ServiceExt;

use konsensus_api::auth::Scope;
use konsensus_api::control;
use konsensus_api::pairing::{self, PairingService};
use konsensus_api::state::AppState;

use common::{auth_header, test_router, test_state_with_data_dir};

const REPLACEMENT_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn state_with_pairing(
    dir: &std::path::Path,
    owner_control: bool,
) -> (Arc<AppState>, Arc<PairingService>, OwnerConsole) {
    let console = OwnerConsole::default();
    let base = test_state_with_data_dir(dir.to_path_buf());
    let fingerprint = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let service = Arc::new(
        PairingService::open(dir, fingerprint, owner_control)
            .unwrap()
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code(),
    );
    let state = Arc::new(AppState {
        pairing: Some(Arc::clone(&service)),
        ..(*base).clone()
    });
    (state, service, console)
}

#[test]
fn rotating_client_key_clears_remote_transport_binding() {
    let dir = tempfile::tempdir().unwrap();
    let (_, service, _) = state_with_pairing(dir.path(), false);
    let old_key = SigningKey::from_bytes(&[0x51; 32]);
    let old_pubkey = hex::encode(old_key.verifying_key().to_bytes());
    let transport = [0x52; 32];
    let paired = service
        .create_verified_remote_pairing("remote", &old_pubkey, &transport)
        .unwrap();
    assert_eq!(
        service
            .validate_remote_transport(&transport)
            .unwrap()
            .client_id,
        paired.client_id
    );

    let new_key = SigningKey::from_bytes(&[0x53; 32]);
    let new_pubkey = hex::encode(new_key.verifying_key().to_bytes());
    let proof = format!("bitsov-pair-rotate-v1:{}:{}", paired.client_id, new_pubkey);
    let rotated = service
        .rotate_client_key(
            &paired.client_id,
            &new_pubkey,
            &hex::encode(old_key.sign(proof.as_bytes()).to_bytes()),
        )
        .unwrap();

    assert!(rotated.remote_transport_pubkey.is_none());
    assert!(service.validate_remote_transport(&transport).is_err());
}

async fn post(
    app: &axum::Router,
    uri: &str,
    body: serde_json::Value,
    token: Option<&str>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    if status.is_server_error() {
        // Surface the reason: a bare 500 in a security test is useless.
        panic!(
            "{uri} returned {status}: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
    (status, json)
}

/// Run the whole ceremony as a well-behaved app: request, read the protected
/// challenge, sign it, confirm, then exchange the client key for a token.
async fn pair_and_token(
    app: &axum::Router,
    service: &PairingService,
    key: &SigningKey,
) -> (String, String) {
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let (status, json) = post(
        app,
        "/api/v1/pair/request",
        serde_json::json!({"client_name": "desktop app", "client_pubkey": pubkey}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let pair_id = json["pair_id"].as_str().unwrap().to_string();

    let challenge = std::fs::read(service.dir().join(format!("challenge-{pair_id}"))).unwrap();
    let sig = hex::encode(
        key.sign(&PairingService::proof_message(
            &pair_id, &pubkey, &challenge,
        ))
        .to_bytes(),
    );
    let (status, json) = post(
        app,
        "/api/v1/pair/confirm",
        serde_json::json!({"pair_id": pair_id, "signature": sig}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let client_id = json["client_id"].as_str().unwrap().to_string();

    let challenge = service.issue_token_challenge(&client_id).unwrap();
    let token_sig = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let (status, json) = post(
        app,
        "/api/v1/pair/token",
        serde_json::json!({
            "client_id": client_id,
            "challenge": challenge,
            "signature": token_sig
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    (client_id, json["token"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn live_pairing_flows_never_mint_admin() {
    // POST /peers grants a live connection privilege. Pairing must never
    // confer the Admin scope that authorizes it, even with an owner grant.
    assert!(!pairing::grantable_scopes().contains(&Scope::Admin));
    // `front_door` publishes the node's own card only; see front_door_scope_tests.
    assert_eq!(pairing::grantable_scopes(), &[Scope::Spend, Scope::FrontDoor]);

    for owner_control in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let (state, service, console) = state_with_pairing(tmp.path(), owner_control);
        let app = test_router(state.clone());
        let key = SigningKey::from_bytes(&[22u8; 32]);
        let (client_id, token) = pair_and_token(&app, &service, &key).await;
        let claims = konsensus_api::auth::validate_token(&token, &state.jwt_secret).unwrap();
        assert!(!claims.scp.contains(&Scope::Admin));
        assert_eq!(claims.scp, vec![Scope::Read, Scope::Receive]);

        for scopes in [vec!["admin"], vec!["spend", "admin"]] {
            let (status, _) = post(
                &app,
                "/api/v1/pair/elevation-request",
                serde_json::json!({"scopes": scopes}),
                Some(&token),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
        assert!(service.reload_from_disk().unwrap().grants.is_empty());

        let mut tokens = vec![token];
        if owner_control {
            // Positive control: a real owner-approved Spend grant works,
            // but it must not confer Admin as a side effect.
            let op = service
                .create_elevation_request(&client_id, vec![Scope::Spend])
                .unwrap();
            service
                .grant_elevation(
                    &op.op_id,
                    &console.confirmation(&pairing::grant_confirmation_phrase(&op)),
                    konsensus_api::spend_budget::GrantTerms::new(100_000),
                )
                .unwrap();
            let challenge = service.issue_token_challenge(&client_id).unwrap();
            let (status, json) = post(
                &app,
                "/api/v1/pair/token",
                serde_json::json!({
                    "client_id": client_id,
                    "challenge": challenge,
                    "signature": hex::encode(key.sign(challenge.as_bytes()).to_bytes())
                }),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            let token = json["token"].as_str().unwrap().to_string();
            let claims = konsensus_api::auth::validate_token(&token, &state.jwt_secret).unwrap();
            assert!(claims.scp.contains(&Scope::Spend));
            assert!(!claims.scp.contains(&Scope::Admin));
            tokens.push(token);
        }

        for token in tokens {
            let (status, _) = post(
                &app,
                "/api/v1/peers",
                serde_json::json!({"node_id": "ab".repeat(32), "addr": "127.0.0.1:9735"}),
                Some(&token),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN);
        }
    }
}

#[tokio::test]
async fn bootstrap_pairing_never_mints_admin() {
    use konsensus_api::bootstrap::{build_bootstrap_router, BootstrapState, DataDirLayout};

    let tmp = tempfile::tempdir().unwrap();
    let service = Arc::new(
        PairingService::open(tmp.path(), String::new(), false)
            .unwrap()
            .without_stdout_code(),
    );
    let state = Arc::new(BootstrapState::new(
        DataDirLayout::new(tmp.path()),
        service.clone(),
    ));
    let app = build_bootstrap_router(state.clone());
    let key = SigningKey::from_bytes(&[23u8; 32]);
    let (_, token) = pair_and_token(&app, &service, &key).await;
    let claims = konsensus_api::auth::validate_token(&token, &state.jwt_secret).unwrap();
    assert!(!claims.scp.contains(&Scope::Admin));
    assert_eq!(claims.scp, vec![Scope::Read, Scope::Receive, Scope::Identity]);
}

#[tokio::test]
async fn ceremony_pairs_and_issues_a_bound_token() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, service, _console) = state_with_pairing(tmp.path(), false);
    let app = test_router(state);
    let key = SigningKey::from_bytes(&[21u8; 32]);

    let (client_id, token) = pair_and_token(&app, &service, &key).await;

    // POSITIVE CONTROL: the paired token works on a read route, and carries
    // exactly the default scopes (policy lock A) — no more.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/identity")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let durable = service.reload_from_disk().unwrap();
    assert_eq!(durable.clients.len(), 1);
    assert_eq!(durable.clients[0].scopes, pairing::default_pairing_scopes());
    assert!(!durable.clients[0].scopes.contains(&Scope::Spend));

    // A spend route refuses this token: being paired does not widen the app.
    let (status, _) = post(
        &app,
        "/api/v1/payments/close-channel",
        serde_json::json!({"channel_id": "ab"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Revocation is immediate, not at expiry: bumping the epoch rejects the
    // outstanding token outright rather than downgrading it.
    service.bump_epoch(&client_id).unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/identity")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn loopback_attacker_without_data_dir_read_cannot_pair() {
    // The in-scope attacker: it can reach loopback but cannot read `data_dir`.
    let tmp = tempfile::tempdir().unwrap();
    let (state, service, _console) = state_with_pairing(tmp.path(), false);
    let app = test_router(state);
    let key = SigningKey::from_bytes(&[33u8; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());

    // `/pair/request` succeeds and yields NOTHING usable: no challenge, no
    // short code. The code is a stdout tripwire; handing it over HTTP would
    // hand it to exactly this caller.
    let (status, json) = post(
        &app,
        "/api/v1/pair/request",
        serde_json::json!({"client_name": "evil page", "client_pubkey": pubkey}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json.get("challenge").is_none());
    assert!(json.get("short_code").is_none());
    let pair_id = json["pair_id"].as_str().unwrap().to_string();

    // The challenge file is owner-only, and 32 bytes of CSPRNG output.
    let challenge_path = service.dir().join(format!("challenge-{pair_id}"));
    let challenge = std::fs::read(&challenge_path).unwrap();
    assert_eq!(challenge.len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&challenge_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o600,
            "the challenge file is the control; it must be 0600"
        );
    }

    // Guessing the challenge fails.
    let guessed = [0u8; 32];
    let sig = hex::encode(
        key.sign(&PairingService::proof_message(&pair_id, &pubkey, &guessed))
            .to_bytes(),
    );
    let (status, _) = post(
        &app,
        "/api/v1/pair/confirm",
        serde_json::json!({"pair_id": pair_id, "signature": sig}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // EFFECT: no pairing was recorded, and the attempt was single-use — the
    // pending request is burned, so the same pair_id cannot be retried.
    assert!(service.reload_from_disk().unwrap().clients.is_empty());
    let sig2 = hex::encode(
        key.sign(&PairingService::proof_message(
            &pair_id, &pubkey, &challenge,
        ))
        .to_bytes(),
    );
    let (status, _) = post(
        &app,
        "/api/v1/pair/confirm",
        serde_json::json!({"pair_id": pair_id, "signature": sig2}),
        None,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a burned pairing request must not be retryable even with the right challenge"
    );

    // POSITIVE CONTROL: a client that CAN read the data directory pairs
    // successfully, so the refusals above are the threat model working rather
    // than the ceremony being broken for everyone.
    let (_client_id, _token) = pair_and_token(&app, &service, &key).await;
    assert_eq!(service.reload_from_disk().unwrap().clients.len(), 1);
}

#[tokio::test]
async fn pairing_is_closed_once_a_client_is_paired() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, service, _console) = state_with_pairing(tmp.path(), false);
    let app = test_router(state);
    let key = SigningKey::from_bytes(&[44u8; 32]);
    pair_and_token(&app, &service, &key).await;

    // Otherwise an attacker sits on `/pair/request` forever waiting for a
    // moment of weakness.
    let other = SigningKey::from_bytes(&[45u8; 32]);
    let (status, _) = post(
        &app,
        "/api/v1/pair/request",
        serde_json::json!({
            "client_name": "second app",
            "client_pubkey": hex::encode(other.verifying_key().to_bytes())
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // POSITIVE CONTROL: an owner-opened window reopens it.
    service.open_pairing_window(std::time::Duration::from_secs(30));
    let (status, _) = post(
        &app,
        "/api/v1/pair/request",
        serde_json::json!({
            "client_name": "second app",
            "client_pubkey": hex::encode(other.verifying_key().to_bytes())
        }),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn http_elevation_write_paths_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, service, console) = state_with_pairing(tmp.path(), true);
    let app = test_router(state);
    let key = SigningKey::from_bytes(&[55u8; 32]);
    let (client_id, token) = pair_and_token(&app, &service, &key).await;

    // The app MAY create a pending request (positive control) …
    let (status, json) = post(
        &app,
        "/api/v1/pair/elevation-request",
        serde_json::json!({"scopes": ["spend"]}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let op_id = json["op_id"].as_str().unwrap().to_string();
    assert!(json["owner_action"]
        .as_str()
        .unwrap()
        .contains("konsensus grant"));

    // … and MAY read its status …
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/pair/elevation/{op_id}"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // … and there is NO path by which it writes the grant. Every plausible
    // spelling is absent from the router, with a paired token AND with the
    // strongest key-proof token the node issues.
    let key_proof = auth_header(&test_state_with_data_dir(tmp.path().to_path_buf()))
        .trim_start_matches("Bearer ")
        .to_string();

    let write_paths = [
        "/api/v1/pair/grant",
        "/api/v1/pair/elevation/approve",
        "/api/v1/pair/elevation/consume",
        "/api/v1/pair/elevation-grant",
        "/api/v1/pair/elevate",
        "/api/v1/identity/restore",
        "/api/v1/identity/replacement-approve",
        "/api/v1/identity/replacement-consume",
        "/api/v1/control/grant",
        "/api/v1/control",
    ];
    for path in write_paths {
        for tok in [Some(token.as_str()), Some(key_proof.as_str()), None] {
            let (status, _) = post(
                &app,
                path,
                serde_json::json!({"op_id": op_id, "confirmation": "GRANT spend TO x"}),
                tok,
            )
            .await;
            // 404 (no such path) or 405 (the path exists as a READ route and
            // has no write handler) are both proof that no write handler is
            // mounted. Anything else would mean the router accepted it.
            assert!(
                status == StatusCode::NOT_FOUND || status == StatusCode::METHOD_NOT_ALLOWED,
                "POST {path} must have no write handler on the HTTP router, got {status}"
            );
        }
    }

    // EFFECT: after all of that, no grant exists and the pairing still holds
    // exactly its default scopes.
    let durable = service.reload_from_disk().unwrap();
    assert!(
        durable.grants.is_empty(),
        "no grant may be written over HTTP"
    );
    assert_eq!(durable.clients[0].scopes, pairing::default_pairing_scopes());
    assert_eq!(
        durable.pending_elevations.len(),
        1,
        "the request itself is durable"
    );

    // POSITIVE CONTROL: the owner channel — and only it — writes the grant.
    let ctx = control::ControlContext {
        service: Arc::clone(&service),
        identity_fingerprint: service.bound_fingerprint(),
        data_dir: tmp.path().to_path_buf(),
        mnemonic_path: tmp.path().join("mnemonic.txt"),
        replacement_guard: control::ReplacementGuard {
            layout: konsensus_api::bootstrap::DataDirLayout::new(tmp.path()),
            uses_identity_derived_keys: false,
            has_identity_passphrase: false,
        },
    };
    let op = service
        .snapshot()
        .pending_elevations
        .into_iter()
        .find(|e| e.op_id == op_id)
        .unwrap();
    let resp = control::handle(
        &ctx,
        control::ControlRequest::Grant {
            op_id: op_id.clone(),
            confirmation: console.confirmation(&pairing::grant_confirmation_phrase(&op)),
            terms: konsensus_api::spend_budget::GrantTerms::new(1_000_000),
        },
    );
    assert!(
        matches!(resp, control::ControlResponse::Ok { .. }),
        "{resp:?}"
    );
    let durable = service.reload_from_disk().unwrap();
    assert_eq!(durable.grants.len(), 1);
    assert_eq!(durable.grants[0].client_id, client_id);
}

#[tokio::test]
async fn http_restore_after_owner_approval_has_no_effect() {
    // The regression this must never lose: even with a pending replacement the
    // OWNER has already approved, HTTP cannot consume it and cannot write
    // identity material. Not with a paired token, not with the strongest
    // key-proof token the node issues, not unauthenticated.
    let tmp = tempfile::tempdir().unwrap();
    let (state, service, console) = state_with_pairing(tmp.path(), true);
    let app = test_router(Arc::clone(&state));
    let key = SigningKey::from_bytes(&[66u8; 32]);
    let (client_id, token) = pair_and_token(&app, &service, &key).await;

    // The app requests replacement (allowed: creates a pending record only).
    let (status, json) = post(
        &app,
        "/api/v1/identity/replacement-request",
        serde_json::json!({"mnemonic": REPLACEMENT_MNEMONIC}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let op_id = json["op_id"].as_str().unwrap().to_string();

    // The OWNER approves it at the control socket.
    let approval = service.replacement_approval(&op_id).unwrap();
    service
        .approve_replacement(
            &op_id,
            &console.confirmation(&pairing::replacement_confirmation_phrase(&approval)),
        )
        .unwrap();
    assert!(service.replacement_approval(&op_id).unwrap().approved);

    // Now every HTTP attempt to cash that approval in.
    let key_proof = auth_header(&state)
        .trim_start_matches("Bearer ")
        .to_string();
    for tok in [Some(token.as_str()), Some(key_proof.as_str()), None] {
        for body in [
            serde_json::json!({"mnemonic": REPLACEMENT_MNEMONIC, "op_id": op_id}),
            serde_json::json!({"mnemonic": REPLACEMENT_MNEMONIC}),
        ] {
            let (status, _) = post(&app, "/api/v1/identity/restore", body, tok).await;
            assert_eq!(
                status,
                StatusCode::NOT_FOUND,
                "HTTP must have no identity-replacement route at all"
            );
        }
    }

    // EFFECTS, which is the whole point of this test:
    // 1. the approval was NOT consumed — it is still there, still approved;
    let durable = service.reload_from_disk().unwrap();
    assert_eq!(durable.replacement_approvals.len(), 1);
    assert!(durable.replacement_approvals[0].approved);
    assert_eq!(durable.replacement_approvals[0].op_id, op_id);
    // 2. no identity material was written anywhere;
    assert!(!tmp.path().join("mnemonic.txt").exists());
    assert!(!tmp.path().join("identity").exists());
    // 3. no grant was written and no pairing scope changed.
    assert!(durable.grants.is_empty());
    assert_eq!(durable.clients[0].scopes, pairing::default_pairing_scopes());

    // POSITIVE CONTROL: the owner control socket consumes the same approval
    // exactly once and writes the identity material. The refusals above are
    // the channel separation, not a broken approval.
    let ctx = control::ControlContext {
        service: Arc::clone(&service),
        identity_fingerprint: service.bound_fingerprint(),
        data_dir: tmp.path().to_path_buf(),
        mnemonic_path: tmp.path().join("mnemonic.txt"),
        replacement_guard: control::ReplacementGuard {
            layout: konsensus_api::bootstrap::DataDirLayout::new(tmp.path()),
            uses_identity_derived_keys: false,
            has_identity_passphrase: false,
        },
    };
    let resp = control::handle(
        &ctx,
        control::ControlRequest::ApproveReplacement {
            op_id: op_id.clone(),
            confirmation: console
                .confirmation(&pairing::replacement_confirmation_phrase(&approval)),
            mnemonic: zeroize::Zeroizing::new(REPLACEMENT_MNEMONIC.to_string()),
        },
    );
    assert!(
        matches!(resp, control::ControlResponse::Ok { .. }),
        "{resp:?}"
    );
    assert_eq!(
        std::fs::read_to_string(tmp.path().join("mnemonic.txt")).unwrap(),
        REPLACEMENT_MNEMONIC
    );
    let durable = service.reload_from_disk().unwrap();
    assert!(
        durable.replacement_approvals.is_empty(),
        "the owner channel consumes the approval"
    );
    assert_eq!(durable.clients[0].client_id, client_id);
}

#[cfg(unix)]
#[tokio::test]
async fn owner_control_socket_permissions() {
    let tmp = tempfile::tempdir().unwrap();
    let (_state, service, _console) = state_with_pairing(tmp.path(), true);
    let ctx = Arc::new(control::ControlContext {
        service: Arc::clone(&service),
        identity_fingerprint: service.bound_fingerprint(),
        data_dir: tmp.path().to_path_buf(),
        mnemonic_path: tmp.path().join("mnemonic.txt"),
        replacement_guard: control::ReplacementGuard {
            layout: konsensus_api::bootstrap::DataDirLayout::new(tmp.path()),
            uses_identity_derived_keys: false,
            has_identity_passphrase: false,
        },
    });

    let server = control::ControlServer::bind(tmp.path(), Arc::clone(&ctx)).unwrap();
    let path = server.path().to_path_buf();
    assert_eq!(path, tmp.path().join("control.sock"));

    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "the owner control socket must be owner-only — it is the channel that writes grants"
    );

    // POSITIVE CONTROL: it actually serves the owner. A socket with the right
    // mode that answers nothing would pass a permissions-only assertion.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(server.serve(shutdown_rx));
    let resp = control::send(&path, &control::ControlRequest::Status)
        .await
        .unwrap();
    assert!(
        matches!(resp, control::ControlResponse::Status { .. }),
        "{resp:?}"
    );

    // A stale socket file does not permanently disable the owner channel.
    let _ = shutdown_tx.send(true);
    let _ = handle.await;
    std::fs::write(&path, b"stale").ok();
    let reborn = control::ControlServer::bind(tmp.path(), ctx).unwrap();
    assert_eq!(reborn.path(), path);
}

#[cfg(unix)]
#[tokio::test]
async fn same_uid_socket_client_cannot_self_grant_from_public_information() {
    let tmp = tempfile::tempdir().unwrap();
    let (state, service, console) = state_with_pairing(tmp.path(), true);
    let app = test_router(Arc::clone(&state));
    let (client_id, token) =
        pair_and_token(&app, &service, &SigningKey::from_bytes(&[61; 32])).await;
    let (status, response) = post(
        &app,
        "/api/v1/pair/elevation-request",
        serde_json::json!({"scopes": ["spend"]}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let op_id = response["op_id"].as_str().unwrap().to_owned();
    let context = Arc::new(control::ControlContext {
        service: Arc::clone(&service),
        identity_fingerprint: service.bound_fingerprint(),
        data_dir: tmp.path().to_path_buf(),
        mnemonic_path: tmp.path().join("mnemonic.txt"),
        replacement_guard: control::ReplacementGuard {
            layout: konsensus_api::bootstrap::DataDirLayout::new(tmp.path()),
            uses_identity_derived_keys: false,
            has_identity_passphrase: false,
        },
    });
    let server = control::ControlServer::bind(tmp.path(), context).unwrap();
    let path = server.path().to_path_buf();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(server.serve(rx));
    let description = control::send(
        &path,
        &control::ControlRequest::Describe {
            op_id: op_id.clone(),
        },
    )
    .await
    .unwrap();
    let label = match &description {
        control::ControlResponse::Describe {
            confirmation_label, ..
        } => confirmation_label.clone(),
        other => panic!("{other:?}"),
    };
    let phrase = console.confirmation(&label);
    let nonce = phrase.split(" CODE ").nth(1).unwrap();
    let socket_status = control::send(&path, &control::ControlRequest::Status)
        .await
        .unwrap();
    for public in [
        response.to_string(),
        serde_json::to_string(&description).unwrap(),
        serde_json::to_string(&socket_status).unwrap(),
        std::fs::read_to_string(service.dir().join("clients.json")).unwrap(),
    ] {
        assert!(
            !public.contains(nonce),
            "owner nonce leaked to a client-readable surface"
        );
    }
    for guessed in [label.clone(), format!("{label} CODE {}", "00".repeat(32))] {
        let denied = control::send(
            &path,
            &control::ControlRequest::Grant {
                op_id: op_id.clone(),
                confirmation: guessed,
                terms: konsensus_api::spend_budget::GrantTerms::new(1_000_000),
            },
        )
        .await
        .unwrap();
        assert!(matches!(denied, control::ControlResponse::Error { .. }));
        let durable = service.reload_from_disk().unwrap();
        assert!(durable.grants.is_empty());
        assert_eq!(durable.clients[0].scopes, pairing::default_pairing_scopes());
        assert!(!tmp.path().join("mnemonic.txt").exists());
    }
    let approved = control::send(
        &path,
        &control::ControlRequest::Grant {
            op_id: op_id.clone(),
            confirmation: phrase.clone(),
            terms: konsensus_api::spend_budget::GrantTerms::new(1_000_000),
        },
    )
    .await
    .unwrap();
    assert!(matches!(approved, control::ControlResponse::Ok { .. }));
    assert_eq!(
        service.reload_from_disk().unwrap().grants[0].client_id,
        client_id
    );
    let replay = control::send(
        &path,
        &control::ControlRequest::Grant {
            op_id,
            confirmation: phrase,
            terms: konsensus_api::spend_budget::GrantTerms::new(1_000_000),
        },
    )
    .await
    .unwrap();
    assert!(matches!(replay, control::ControlResponse::Error { .. }));
    assert_eq!(service.reload_from_disk().unwrap().grants.len(), 1);
    stop.send(true).unwrap();
    task.await.unwrap();
}

async fn ws_connect(
    addr: std::net::SocketAddr,
    token: &str,
    subprotocol: bool,
) -> (u16, tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (query, header) = if subprotocol {
        (
            String::new(),
            format!("Sec-WebSocket-Protocol: bitsov.v1, bitsov.jwt.{token}\r\n"),
        )
    } else {
        (format!("?token={token}"), String::new())
    };
    stream.write_all(format!("GET /api/v1/ws{query} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{header}\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !response.ends_with(b"\r\n\r\n") {
            response.push(stream.read_u8().await.unwrap());
            assert!(response.len() < 8192);
        }
    })
    .await
    .unwrap();
    let status = std::str::from_utf8(&response)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, stream)
}

async fn read_ws_text(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        assert_eq!(stream.read_u8().await.unwrap(), 0x81);
        let size = stream.read_u8().await.unwrap();
        assert!(size <= 126, "unmasked, bounded fixture frame");
        let size = if size == 126 {
            stream.read_u16().await.unwrap() as usize
        } else {
            size as usize
        };
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn websocket_pairing_binding_blocks_upgrade_and_post_revocation_plaintext() {
    use tokio::io::AsyncReadExt;
    for mutation in ["revoke", "epoch", "identity"] {
        let tmp = tempfile::tempdir().unwrap();
        let (state, service, _console) = state_with_pairing(tmp.path(), false);
        let app = test_router(Arc::clone(&state));
        let (client_id, token) =
            pair_and_token(&app, &service, &SigningKey::from_bytes(&[62; 32])).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
                .await
                .unwrap();
        });
        let (status, mut socket) = ws_connect(addr, &token, false).await;
        assert_eq!(
            status, 101,
            "positive control must reach the real upgrade handler"
        );
        let (status, subprotocol_socket) = ws_connect(addr, &token, true).await;
        assert_eq!(status, 101);
        drop(subprotocol_socket);
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while state.ws_broadcast.receiver_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let envelope = konsensus_core::UkmEnvelopeBuilder::new(
            100,
            *state.identity.node_id(),
            konsensus_core::types::Recipient::Node(*state.identity.node_id()),
            vec![],
            konsensus_core::PaymentProof::new([0; 32], [0; 32], 0),
        )
        .build();
        let message = Arc::new(konsensus_api::state::WsMessage {
            envelope,
            plaintext: Some("plaintext-before-revocation".into()),
        });
        state.ws_broadcast.send(Arc::clone(&message)).unwrap();
        assert!(read_ws_text(&mut socket)
            .await
            .contains("plaintext-before-revocation"));
        match mutation {
            "revoke" => service.revoke(&client_id).unwrap(),
            "epoch" => {
                service.bump_epoch(&client_id).unwrap();
            }
            _ => service
                .rebind_to_identity("replacement-fingerprint")
                .unwrap(),
        }
        for subprotocol in [false, true] {
            assert_eq!(
                ws_connect(addr, &token, subprotocol).await.0,
                401,
                "{mutation}"
            );
        }
        state.ws_broadcast.send(message).unwrap();
        let mut byte = [0; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(3), socket.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "revoked stream received a frame: {read:?}"
        );
        server.abort();
        let _ = server.await;
    }
}

// Paired staging stays ephemeral even with an active spend grant.
#[tokio::test]
async fn paired_staging_never_writes_permanent_storage() {
    use base64::Engine;
    use konsensus_storage::{SqliteStorage, Storage};
    let tmp = tempfile::tempdir().unwrap();
    let (base, service, console) = state_with_pairing(tmp.path(), true);
    let db_path = tmp.path().join("staging.sqlite");
    let storage = Arc::new(SqliteStorage::open(db_path.to_str().unwrap()).await.unwrap());
    let state = Arc::new(AppState { storage: storage.clone(), ..(*base).clone() });
    let app = test_router(state.clone());
    let key = SigningKey::from_bytes(&[93u8; 32]);
    let (client_id, read_token) = pair_and_token(&app, &service, &key).await;
    let body = serde_json::json!({"filename":"stage.bin", "data_b64":base64::engine::general_purpose::STANDARD.encode(vec![7u8; 1024*1024])});
    assert_eq!(post(&app, "/api/v1/files", body.clone(), Some(&read_token)).await.0, StatusCode::FORBIDDEN);
    let op = service.create_elevation_request(&client_id, vec![Scope::Spend]).unwrap();
    service.grant_elevation(&op.op_id, &console.confirmation(&pairing::grant_confirmation_phrase(&op)), konsensus_api::spend_budget::GrantTerms::new(100_000)).unwrap();
    let challenge = service.issue_token_challenge(&client_id).unwrap();
    let issued = service.issue_token(&state.identity.node_id().to_hex(), &state.jwt_secret, &client_id, &challenge, &hex::encode(key.sign(challenge.as_bytes()).to_bytes())).unwrap();
    let before = state.lightning.get_balance_msat().await.unwrap();
    let mut ids = Vec::new();
    for _ in 0..8 {
        let (status, uploaded) = post(&app, "/api/v1/files", body.clone(), Some(&issued.token)).await;
        assert_eq!(status, StatusCode::OK);
        ids.push(uploaded["file_id"].as_str().unwrap().to_string());
    }
    assert_eq!(post(&app, "/api/v1/files", body.clone(), Some(&issued.token)).await.0, StatusCode::TOO_MANY_REQUESTS);
    assert!(storage.list_files(100).await.unwrap().is_empty(), "paired staging must never enter permanent storage");
    service.revoke(&client_id).unwrap();
    assert_eq!(post(&app, "/api/v1/files", body, Some(&issued.token)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(state.lightning.get_balance_msat().await.unwrap(), before);
    let owner = konsensus_api::auth::AuthUser { node_id:state.identity.node_id().to_hex(), scopes:vec![Scope::Admin], pairing:None };
    let mut staging = state.file_staging.lock().unwrap();
    staging.sweep(&state);
    assert!(ids.iter().all(|id| staging.get(&state, &owner, id).is_none()), "revocation sweep removes abandoned files");
}

#[tokio::test]
async fn membrane_ws_requires_local_pairing_and_rechecks_revocation() {
    use tokio::io::AsyncReadExt;
    for mode in ["remote", "missing", "unpaired", "no_read", "local"] {
        let tmp = tempfile::tempdir().unwrap();
        let (state, service, _console) = state_with_pairing(tmp.path(), false);
        let app = test_router(state.clone());
        let (client, paired) =
            pair_and_token(&app, &service, &SigningKey::from_bytes(&[73; 32])).await;
        let token = if mode == "unpaired" {
            auth_header(&state).trim_start_matches("Bearer ").to_owned()
        } else if mode == "no_read" {
            let binding = &service.list_clients()[0];
            konsensus_api::auth::create_paired_token(
                &state.identity.node_id().to_hex(),
                &state.jwt_secret,
                vec![Scope::Receive],
                &client,
                binding.epoch,
                &service.bound_fingerprint(),
            )
            .unwrap()
        } else {
            paired
        };
        let app = match mode {
            "remote" => app.layer(axum::Extension(axum::extract::ConnectInfo(
                "203.0.113.1:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))),
            "missing" => app,
            _ => app.layer(axum::Extension(axum::extract::ConnectInfo(
                "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service())
                .await
                .unwrap();
        });
        let (status, mut socket) = ws_connect(addr, &token, true).await;
        if mode != "local" {
            assert_eq!(status, 403, "{mode}");
        } else {
            assert_eq!(status, 101);
            let envelope = konsensus_core::UkmEnvelopeBuilder::new(
                100,
                *state.identity.node_id(),
                konsensus_core::types::Recipient::Node(*state.identity.node_id()),
                vec![],
                konsensus_core::PaymentProof::new([0; 32], [0; 32], 0),
            )
            .build();
            // An application ping is handled only after all event subscriptions exist.
            use tokio::io::AsyncWriteExt;
            socket.write_all(&[0x89, 0x80, 0, 0, 0, 0]).await.unwrap();
            assert_eq!(socket.read_u8().await.unwrap(), 0x8a);
            assert_eq!(socket.read_u8().await.unwrap(), 0);
            state.audit_log.membrane().admitted(&envelope, true);
            let event: serde_json::Value =
                serde_json::from_str(&read_ws_text(&mut socket).await).unwrap();
            assert_eq!(event["type"], "membrane");
            service.revoke(&client).unwrap();
            state.audit_log.membrane().admitted(&envelope, true);
            let mut byte = [0; 1];
            let result =
                tokio::time::timeout(std::time::Duration::from_secs(3), socket.read(&mut byte))
                    .await
                    .unwrap();
            assert!(
                matches!(result, Ok(0) | Err(_)),
                "revoked membrane frame: {result:?}"
            );
        }
        server.abort();
        let _ = server.await;
    }
}

async fn staging_previous_grant_isolation(revoke_before_regrant: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let (state, service, console) = state_with_pairing(tmp.path(), true);
    let app = test_router(state.clone());
    let key = SigningKey::from_bytes(&[94u8; 32]);
    let (client_id, _) = pair_and_token(&app, &service, &key).await;
    let grant = || {
        let op = service
            .create_elevation_request(&client_id, vec![Scope::Spend])
            .unwrap();
        service
            .grant_elevation(
                &op.op_id,
                &console.confirmation(&pairing::grant_confirmation_phrase(&op)),
                konsensus_api::spend_budget::GrantTerms::new(100_000),
            )
            .unwrap()
    };
    let issue_token = || {
        let challenge = service.issue_token_challenge(&client_id).unwrap();
        service
            .issue_token(
                &state.identity.node_id().to_hex(),
                &state.jwt_secret,
                &client_id,
                &challenge,
                &hex::encode(key.sign(challenge.as_bytes()).to_bytes()),
            )
            .unwrap()
            .token
    };
    let original = grant();
    let token = issue_token();
    let balance = state.lightning.get_balance_msat().await.unwrap();
    let (status, uploaded) = post(
        &app,
        "/api/v1/files",
        serde_json::json!({"filename":"old-grant.txt", "data_b64":"b2xkIGdyYW50"}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let id = uploaded["file_id"].as_str().unwrap();
    if revoke_before_regrant {
        assert_eq!(service.revoke_grants(Some(&client_id)).unwrap(), 1);
    }
    let replacement = grant();
    assert_ne!(original.op_id, replacement.op_id);
    assert_eq!(
        original.epoch, replacement.epoch,
        "grant replacement is not client rotation"
    );
    let replacement_token = issue_token();
    // Sweep explicitly: cleanup should invalidate bytes owned by the old grant,
    // even when no request happened during the revoke/regrant interval.
    state.file_staging.lock().unwrap().sweep(&state);
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/files/{id}"))
                .header("authorization", format!("Bearer {replacement_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(state.lightning.get_balance_msat().await.unwrap(), balance);
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "replacement grant must not inherit previous grant's staged bytes: {}",
        String::from_utf8_lossy(&body)
    );
}

#[tokio::test]
async fn staging_replacement_grant_cannot_read_previous_grant_blob() {
    staging_previous_grant_isolation(false).await;
}

#[tokio::test]
async fn staging_revoked_then_regranted_blob_stays_revoked() {
    staging_previous_grant_isolation(true).await;
}

// Exercise the actual remote route selection in memory; no listener or live node.
fn remote_app(state: Arc<AppState>) -> axum::Router {
    use axum::extract::connect_info::MockConnectInfo;
    konsensus_api::build_remote_router(state)
        .layer(MockConnectInfo("127.0.0.1:50000".parse::<std::net::SocketAddr>().unwrap()))
}

#[tokio::test]
async fn remote_elevation_asks_reads_and_cancels_without_granting() {
    let dir = tempfile::tempdir().unwrap();
    let (state, service, _) = state_with_pairing(dir.path(), true);
    let key = SigningKey::from_bytes(&[91; 32]);
    let (client_id, token) = pair_and_token(&test_router(state.clone()), &service, &key).await;
    let app = remote_app(state);
    let (status, body) = post(&app, "/api/v1/pair/elevation-request",
        serde_json::json!({"scopes": ["spend"], "budget": {"budget_msat": 10000}}), Some(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let op = body["op_id"].as_str().unwrap();
    for (method, path) in [
        ("GET", format!("/api/v1/pair/elevation/{op}")),
        ("GET", "/api/v1/pair/grant".into()),
        ("DELETE", format!("/api/v1/pair/elevation/{op}")),
    ] {
        let response = app.clone().oneshot(Request::builder().method(method).uri(&path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{method} {path}");
        let bytes = axum::body::to_bytes(response.into_body(), 65536).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if method == "GET" && path.ends_with(op) { assert_eq!(value["status"], "pending"); }
        if path.ends_with("/grant") { assert!(value["grant"].is_null()); }
    }
    assert!(service.grant_view_for(&client_id).is_none());
}

#[tokio::test]
async fn remote_elevation_routes_require_auth_and_approval_routes_are_absent() {
    let dir = tempfile::tempdir().unwrap();
    let (state, _, _) = state_with_pairing(dir.path(), true);
    let app = remote_app(state.clone());
    for (method, path) in [
        ("POST", "/api/v1/pair/elevation-request"),
        ("GET", "/api/v1/pair/elevation/unknown"),
        ("DELETE", "/api/v1/pair/elevation/unknown"),
        ("GET", "/api/v1/pair/grant"),
    ] {
        let response = app.clone().oneshot(Request::builder().method(method).uri(path)
            .header("content-type", "application/json").body(Body::from("{}"))
            .unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{method} {path}");
    }
    // Even an owner token cannot reach an approval handler through this router.
    let owner = konsensus_api::auth::create_token(&state.identity.node_id().to_hex(),
        &state.jwt_secret, Scope::all()).unwrap();
    for path in [
        "/api/v1/pair/grant", "/api/v1/pair/elevation/unknown",
        "/api/v1/pair/elevation/unknown/grant", "/api/v1/pair/approve",
        "/api/v1/pair/first-contact-grant", "/api/v1/pair/relation-intent",
        "/api/v1/pair/device-key/request", "/api/v1/identity/approve-replacement",
    ] {
        let (status, _) = post(&app, path, serde_json::json!({}), Some(&owner)).await;
        assert!(matches!(status, StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED), "{path}: {status}");
    }
}

#[tokio::test]
async fn elevation_status_is_private_on_remote_and_loopback() {
    for remote in [false, true] {
        for owner_control in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (state, service, console) = state_with_pairing(dir.path(), owner_control);
            let local = test_router(state.clone());
            let (a, token_a) = pair_and_token(&local, &service, &SigningKey::from_bytes(&[81; 32])).await;
            service.open_pairing_window(std::time::Duration::from_secs(30));
            let (_, token_b) = pair_and_token(&local, &service, &SigningKey::from_bytes(&[82; 32])).await;
            let app = if remote { remote_app(state) } else { local };
            for scope in [Scope::Spend, Scope::FrontDoor] {
                let op = service.create_elevation_request(&a, vec![scope]).unwrap();
                for phase in 0..2 {
                    for (token, id, expected) in [
                        (&token_a, op.op_id.as_str(), StatusCode::OK),
                        (&token_b, op.op_id.as_str(), StatusCode::NOT_FOUND),
                        (&token_b, "unknown", StatusCode::NOT_FOUND),
                    ] {
                        let response = app.clone().oneshot(Request::builder()
                            .uri(format!("/api/v1/pair/elevation/{id}"))
                            .header("authorization", format!("Bearer {token}"))
                            .body(Body::empty()).unwrap()).await.unwrap();
                        assert_eq!(response.status(), expected, "remote={remote} owner={owner_control} phase={phase}");
                        let bytes = axum::body::to_bytes(response.into_body(), 65536).await.unwrap();
                        if expected == StatusCode::NOT_FOUND {
                            assert!(String::from_utf8_lossy(&bytes).contains("no such pending operation"));
                        } else {
                            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                            assert_eq!(body["status"], if phase == 0 { "pending" } else { "granted" });
                        }
                    }
                    if !owner_control || phase == 1 { break; }
                    let code = console.owner_code(&op.op_id);
                    if scope == Scope::Spend {
                        service.grant_elevation(&op.op_id, &code, konsensus_api::spend_budget::GrantTerms::new(1000)).unwrap();
                    } else {
                        service.grant_front_door(&op.op_id, &code, 60).unwrap();
                    }
                }
            }
            if owner_control {
                let op = service.create_elevation_request(&a, vec![Scope::Spend]).unwrap();
                for _ in 0..3 {
                    let _ = service.grant_elevation(&op.op_id, "WRONG",
                        konsensus_api::spend_budget::GrantTerms::new(1000));
                }
                for (token, expected) in [(&token_a, StatusCode::OK), (&token_b, StatusCode::NOT_FOUND)] {
                    let response = app.clone().oneshot(Request::builder()
                        .uri(format!("/api/v1/pair/elevation/{}", op.op_id))
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty()).unwrap()).await.unwrap();
                    assert_eq!(response.status(), expected);
                    if expected == StatusCode::OK {
                        let bytes = axum::body::to_bytes(response.into_body(), 65536).await.unwrap();
                        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                        assert_eq!(body["status"], "lost");
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn pending_elevation_cap_is_per_client_and_releases_cancelled_slots() {
    let dir = tempfile::tempdir().unwrap();
    let (state, service, _) = state_with_pairing(dir.path(), true);
    let app = test_router(state);
    let (a, token_a) = pair_and_token(&app, &service, &SigningKey::from_bytes(&[83; 32])).await;
    service.open_pairing_window(std::time::Duration::from_secs(30));
    let (b, _) = pair_and_token(&app, &service, &SigningKey::from_bytes(&[84; 32])).await;
    let mut ops = Vec::new();
    for _ in 0..4 {
        ops.push(service.create_elevation_request(&a, vec![Scope::Spend]).unwrap());
    }
    let (status, _) = post(&app, "/api/v1/pair/elevation-request",
        serde_json::json!({"scopes":["spend"]}), Some(&token_a)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(service.reload_from_disk().unwrap().pending_elevations.len(), 4);
    service.create_elevation_request(&b, vec![Scope::Spend]).unwrap();
    service.cancel_pending(&a, &ops[0].op_id).unwrap();
    service.create_elevation_request(&a, vec![Scope::Spend]).unwrap();
}
