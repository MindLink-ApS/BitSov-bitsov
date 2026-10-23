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

fn token_challenge_client(service: &PairingService, seed: u8) -> (String, SigningKey) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    service.open_pairing_window(std::time::Duration::from_secs(60));
    let paired = service
        .create_verified_remote_pairing(
            &format!("client-{seed}"),
            &hex::encode(key.verifying_key().to_bytes()),
            &[seed; 32],
        )
        .unwrap();
    (paired.client_id, key)
}

fn fill_token_challenges(service: &PairingService, client_id: &str) -> Vec<String> {
    (0..8)
        .map(|_| service.issue_token_challenge(client_id).unwrap())
        .collect()
}

fn fresh_pairing_service() -> (tempfile::TempDir, PairingService) {
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), String::new(), false).unwrap();
    (dir, service)
}

fn client_pubkey(seed: u8) -> String {
    hex::encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn challenge_file(service: &PairingService, pair_id: &str) -> std::path::PathBuf {
    service.dir().join(format!("challenge-{pair_id}"))
}

#[test]
fn pending_pairing_per_source_quota_replaces_own_oldest() {
    let (_dir, service) = fresh_pairing_service();
    let first = client_pubkey(1);
    let second = client_pubkey(2);
    let mut first_ids = Vec::new();
    for _ in 0..pairing::MAX_PENDING_PAIRINGS_PER_SOURCE {
        first_ids.push(service.request_pairing("a", &first).unwrap().pair_id);
    }
    let replaced = service
        .request_pairing("a", &first.to_ascii_uppercase())
        .unwrap();
    assert_ne!(replaced.pair_id, first_ids[0]);
    assert!(
        !challenge_file(&service, &first_ids[0]).exists(),
        "the oldest request from this key is replaced"
    );
    for id in &first_ids[1..] {
        assert!(challenge_file(&service, id).exists(), "{id} must stay");
    }
    // Signature parsing runs before the pending lookup, so the probe must be a
    // well-formed signature. A short hex string never reaches UnknownPending.
    let error = service
        .confirm_pairing(
            &first_ids[0],
            &"00".repeat(64),
            pairing::default_pairing_scopes(),
        )
        .unwrap_err();
    assert!(
        matches!(error, pairing::PairingError::UnknownPending),
        "replaced request must be gone, got {error:?}"
    );
    let other = service.request_pairing("b", &second).unwrap();
    assert!(challenge_file(&service, &other.pair_id).exists());
    assert!(challenge_file(&service, &replaced.pair_id).exists());
    let kept = std::fs::read(challenge_file(&service, &replaced.pair_id)).unwrap();
    let key = SigningKey::from_bytes(&[1; 32]);
    let message = PairingService::proof_message(&replaced.pair_id, &first, &kept);
    service
        .confirm_pairing(
            &replaced.pair_id,
            &hex::encode(key.sign(&message).to_bytes()),
            pairing::default_pairing_scopes(),
        )
        .unwrap();
}

#[test]
fn pending_pairing_global_cap_rejects_a_new_key_and_lets_an_existing_key_replace() {
    let (_dir, service) = fresh_pairing_service();
    let mut ids = Vec::new();
    for seed in 1..=pairing::MAX_PENDING_PAIRINGS as u8 {
        ids.push(
            service
                .request_pairing("n", &client_pubkey(seed))
                .unwrap()
                .pair_id,
        );
    }
    assert!(matches!(
        service.request_pairing("overflow", &client_pubkey(33)),
        Err(pairing::PairingError::TooManyPending)
    ));
    let refreshed = service
        .request_pairing("n", &client_pubkey(1))
        .unwrap()
        .pair_id;
    assert_ne!(refreshed, ids[0]);
    assert!(!challenge_file(&service, &ids[0]).exists());
    assert!(challenge_file(&service, &ids[1]).exists());
    assert!(challenge_file(&service, &refreshed).exists());
    assert!(matches!(
        service.request_pairing("overflow", &client_pubkey(34)),
        Err(pairing::PairingError::TooManyPending)
    ));
}

#[test]
fn token_challenges_client_cap_leaves_room_for_another_client() {
    let dir = tempfile::tempdir().unwrap();
    let (_, service, _) = state_with_pairing(dir.path(), false);
    let (a, _) = token_challenge_client(&service, 1);
    let (b, _) = token_challenge_client(&service, 2);
    fill_token_challenges(&service, &a);
    service.issue_token_challenge(&a).unwrap();
    fill_token_challenges(&service, &b);
}

#[test]
fn token_challenges_global_cap_and_revocation_release() {
    let dir = tempfile::tempdir().unwrap();
    let (state, service, _) = state_with_pairing(dir.path(), false);
    let clients: Vec<_> = (1..=17)
        .map(|seed| token_challenge_client(&service, seed))
        .collect();
    let challenges: Vec<_> = clients[..16]
        .iter()
        .map(|(client, _)| fill_token_challenges(&service, client))
        .collect();
    let b = &clients[16].0;
    assert!(matches!(
        service.issue_token_challenge(b),
        Err(pairing::PairingError::TooManyPending)
    ));

    let (a, a_key) = &clients[0];
    service.revoke(a).unwrap();
    assert!(matches!(
        service.issue_token_challenge(a),
        Err(pairing::PairingError::UnknownClient)
    ));
    // All eight revoked slots are available immediately, but the global cap holds.
    fill_token_challenges(&service, b);
    let (repaired_a, _) = token_challenge_client(&service, 1);
    assert_eq!(&repaired_a, a);
    assert!(matches!(
        service.issue_token_challenge(a),
        Err(pairing::PairingError::TooManyPending)
    ));
    // Re-pairing the same key must not resurrect a pre-revocation challenge.
    assert!(matches!(
        service.issue_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            a,
            &challenges[0][0],
            &hex::encode(a_key.sign(challenges[0][0].as_bytes()).to_bytes()),
        ),
        Err(pairing::PairingError::UnknownPending)
    ));
    // Revoking A leaves another client's existing challenges usable at capacity.
    let (other, other_key) = &clients[1];
    service
        .issue_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            other,
            &challenges[1][0],
            &hex::encode(other_key.sign(challenges[1][0].as_bytes()).to_bytes()),
        )
        .unwrap();
    service.issue_token_challenge(a).unwrap();
}

#[test]
fn token_challenges_consumption_releases_client_slot() {
    let dir = tempfile::tempdir().unwrap();
    let (state, service, _) = state_with_pairing(dir.path(), false);
    let (a, key) = token_challenge_client(&service, 1);
    let challenges = fill_token_challenges(&service, &a);
    service
        .issue_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            &a,
            &challenges[0],
            &hex::encode(key.sign(challenges[0].as_bytes()).to_bytes()),
        )
        .unwrap();
    service.issue_token_challenge(&a).unwrap();
    // Consuming a slot means the refill need not evict the next oldest.
    service
        .issue_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            &a,
            &challenges[1],
            &hex::encode(key.sign(challenges[1].as_bytes()).to_bytes()),
        )
        .unwrap();
}

fn local_challenge_request(client_id: &str, key: &SigningKey, timestamp: i64) -> Request<Body> {
    let message = format!("bitsov-pair-challenge-v1:{client_id}:{timestamp}");
    Request::builder()
        .uri(format!("/api/v1/pair/challenge?client_id={client_id}"))
        .header(
            "authorization",
            format!(
                "PairChallenge {timestamp}:{}",
                hex::encode(key.sign(message.as_bytes()).to_bytes())
            ),
        )
        .body(Body::empty())
        .unwrap()
}

async fn challenge_response(
    app: &axum::Router,
    request: Request<Body>,
) -> (StatusCode, serde_json::Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn get_token_challenge(
    app: &axum::Router,
    client_id: &str,
) -> (StatusCode, serde_json::Value) {
    challenge_response(
        app,
        Request::builder()
            .uri(format!("/api/v1/pair/challenge?client_id={client_id}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
}

async fn own_token_challenge(
    app: &axum::Router,
    client_id: &str,
    key: &SigningKey,
) -> (StatusCode, serde_json::Value) {
    challenge_response(
        app,
        local_challenge_request(client_id, key, chrono::Utc::now().timestamp()),
    )
    .await
}

#[tokio::test]
async fn token_challenges_local_replay_is_401_but_fresh_proof_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let (state, service, _) = state_with_pairing(dir.path(), false);
    let (client, key) = token_challenge_client(&service, 1);
    let local = test_router(state);
    let bootstrap = konsensus_api::bootstrap::build_bootstrap_router(Arc::new(
        konsensus_api::bootstrap::BootstrapState::new(
            konsensus_api::bootstrap::DataDirLayout::new(dir.path()),
            service,
        ),
    ));
    let timestamp = chrono::Utc::now().timestamp();
    for (offset, app) in [&local, &bootstrap].into_iter().enumerate() {
        let timestamp = timestamp + offset as i64;
        assert_eq!(
            challenge_response(app, local_challenge_request(&client, &key, timestamp))
                .await
                .0,
            StatusCode::OK
        );
        // Both routers share the memo. Hex casing cannot make a fresh proof.
        for replay_app in [&local, &bootstrap] {
            let mut request = local_challenge_request(&client, &key, timestamp);
            let header = request.headers()["authorization"].to_str().unwrap();
            let signature = header
                .strip_prefix("PairChallenge ")
                .unwrap()
                .to_uppercase();
            request.headers_mut().insert(
                "authorization",
                format!("PairChallenge {signature}").parse().unwrap(),
            );
            assert_eq!(
                challenge_response(replay_app, request).await.0,
                StatusCode::UNAUTHORIZED
            );
        }
    }
}

#[tokio::test]
async fn token_challenges_local_proof_uses_cors_allowed_authorization_header() {
    let dir = tempfile::tempdir().unwrap();
    let (state, service, _) = state_with_pairing(dir.path(), false);
    let (client, key) = token_challenge_client(&service, 1);
    let app = test_router(Arc::new(AppState {
        cors_enabled: true,
        ..(*state).clone()
    }));
    let preflight = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri(format!("/api/v1/pair/challenge?client_id={client}"))
                .header("origin", "http://localhost:1420")
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", "authorization")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(preflight.status().is_success());
    assert_eq!(
        preflight.headers()["access-control-allow-origin"],
        "http://localhost:1420"
    );
    assert!(preflight.headers()["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .contains("authorization"));
    let mut request = local_challenge_request(&client, &key, chrono::Utc::now().timestamp());
    request
        .headers_mut()
        .insert("origin", "http://localhost:1420".parse().unwrap());
    assert_eq!(challenge_response(&app, request).await.0, StatusCode::OK);
}

#[tokio::test]
async fn token_challenges_local_live_and_bootstrap_require_client_proof() {
    let dir = tempfile::tempdir().unwrap();
    let (state, service, _) = state_with_pairing(dir.path(), false);
    let (a, key_a) = token_challenge_client(&service, 1);
    let (_, key_b) = token_challenge_client(&service, 2);
    let bootstrap = konsensus_api::bootstrap::build_bootstrap_router(Arc::new(
        konsensus_api::bootstrap::BootstrapState::new(
            konsensus_api::bootstrap::DataDirLayout::new(dir.path()),
            service.clone(),
        ),
    ));
    let now = chrono::Utc::now().timestamp();
    for (offset, app) in [test_router(state.clone()), bootstrap]
        .into_iter()
        .enumerate()
    {
        for _ in 0..8 {
            assert_eq!(
                get_token_challenge(&app, &a).await.0,
                StatusCode::UNAUTHORIZED
            );
            assert_eq!(
                own_token_challenge(&app, &a, &key_b).await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        for timestamp in [0, chrono::Utc::now().timestamp() + 3600] {
            assert_eq!(
                challenge_response(&app, local_challenge_request(&a, &key_a, timestamp))
                    .await
                    .0,
                StatusCode::UNAUTHORIZED
            );
        }
        let (status, body) = challenge_response(
            &app,
            local_challenge_request(&a, &key_a, now + offset as i64),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let challenge = body["challenge"].as_str().unwrap();
        service
            .issue_token(
                &state.identity.node_id().to_hex(),
                &state.jwt_secret,
                &a,
                challenge,
                &hex::encode(key_a.sign(challenge.as_bytes()).to_bytes()),
            )
            .unwrap();
    }
    fill_token_challenges(&service, &a);
}

// The extension is server-owned; wire headers cannot create it.
fn noise_app(app: axum::Router, client_id: &str) -> axum::Router {
    app.layer(axum::Extension(
        konsensus_api::rate_limit::AuthenticatedNoise {
            client_id: client_id.to_string().into(),
            binding: konsensus_api::sas::NoiseBinding {
                handshake_hash: [1; 32],
                client_static: [2; 32],
                box_public_key: [3; 32],
            },
        },
    ))
}

#[tokio::test]
async fn token_challenges_caller_b_cannot_spend_a_slots() {
    let dir = tempfile::tempdir().unwrap();
    let (state, service, _) = state_with_pairing(dir.path(), false);
    let (a, a_key) = token_challenge_client(&service, 1);
    let (b, _) = token_challenge_client(&service, 2);
    let remote = remote_app(state.clone());
    let b_app = noise_app(remote.clone(), &b);
    for app in [&b_app, &remote, &test_router(state.clone())] {
        for _ in 0..8 {
            assert_eq!(
                get_token_challenge(app, &a).await.0,
                StatusCode::UNAUTHORIZED
            );
        }
    }
    let a_app = noise_app(remote, &a);
    let (status, body) = get_token_challenge(&a_app, &a).await;
    assert_eq!(status, StatusCode::OK);
    let challenge = body["challenge"].as_str().unwrap();
    service
        .issue_token(
            &state.identity.node_id().to_hex(),
            &state.jwt_secret,
            &a,
            challenge,
            &hex::encode(a_key.sign(challenge.as_bytes()).to_bytes()),
        )
        .unwrap();
    fill_token_challenges(&service, &a);
}

#[tokio::test]
async fn token_challenges_remote_bootstrap_uses_registered_noise_peer() {
    use axum::extract::connect_info::MockConnectInfo;
    use konsensus_api::bootstrap::{
        build_bootstrap_router, BootstrapState, DataDirLayout, RemoteOwner,
    };
    use konsensus_api::rate_limit::RemoteTunnelClients;
    let dir = tempfile::tempdir().unwrap();
    let (_, service, _) = state_with_pairing(dir.path(), false);
    let (a, key_a) = token_challenge_client(&service, 1);
    let (b, _) = token_challenge_client(&service, 2);
    let tunnel = Arc::new(RemoteTunnelClients::default());
    let peer_a: std::net::SocketAddr = "127.0.0.1:50001".parse().unwrap();
    let peer_b: std::net::SocketAddr = "127.0.0.1:50002".parse().unwrap();
    let binding = konsensus_api::sas::NoiseBinding {
        handshake_hash: [1; 32],
        client_static: [2; 32],
        box_public_key: [3; 32],
    };
    let _a = tunnel.register_noise(peer_a, a.clone(), binding);
    let _b = tunnel.register_noise(peer_b, b, binding);
    let state = Arc::new(
        BootstrapState::new(DataDirLayout::new(dir.path()), service.clone()).with_remote_owner(
            RemoteOwner {
                hooks: Box::new(|_| panic!("challenge route must not call owner hooks")),
                tunnel,
            },
        ),
    );
    let app = build_bootstrap_router(state.clone());
    let b_app = app.clone().layer(MockConnectInfo(peer_b));
    for attacker in [&app, &b_app] {
        for _ in 0..8 {
            assert_eq!(
                get_token_challenge(attacker, &a).await.0,
                StatusCode::UNAUTHORIZED
            );
        }
        // Even a local proof cannot bypass the remote-only transport binding.
        assert_eq!(
            own_token_challenge(attacker, &a, &key_a).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    let a_app = app.layer(MockConnectInfo(peer_a));
    let (status, body) = get_token_challenge(&a_app, &a).await;
    assert_eq!(status, StatusCode::OK);
    let challenge = body["challenge"].as_str().unwrap();
    service
        .issue_bootstrap_token(
            &state.jwt_secret,
            &a,
            challenge,
            &hex::encode(key_a.sign(challenge.as_bytes()).to_bytes()),
        )
        .unwrap();
    fill_token_challenges(&service, &a);
}

#[tokio::test]
async fn token_challenges_http_isolation_and_private_429_body() {
    let dir = tempfile::tempdir().unwrap();
    let (state, service, _) = state_with_pairing(dir.path(), false);
    let local = test_router(state.clone());
    let bootstrap = konsensus_api::bootstrap::build_bootstrap_router(Arc::new(
        konsensus_api::bootstrap::BootstrapState::new(
            konsensus_api::bootstrap::DataDirLayout::new(dir.path()),
            service.clone(),
        ),
    ));
    let remote = remote_app(state);
    let (a, key_a) = token_challenge_client(&service, 1);
    let (b, key_b) = token_challenge_client(&service, 2);
    let a_remote = noise_app(remote.clone(), &a);
    for _ in 0..8 {
        assert_eq!(get_token_challenge(&a_remote, &a).await.0, StatusCode::OK);
    }
    let now = chrono::Utc::now().timestamp();
    for (offset, app) in [&local, &bootstrap, &a_remote].into_iter().enumerate() {
        assert_eq!(
            challenge_response(
                app,
                local_challenge_request(&a, &key_a, now + offset as i64)
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    for (offset, app) in [&local, &bootstrap, &noise_app(remote.clone(), &b)]
        .into_iter()
        .enumerate()
    {
        assert_eq!(
            challenge_response(
                app,
                local_challenge_request(&b, &key_b, now + offset as i64)
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    for _ in 0..5 {
        service.issue_token_challenge(&b).unwrap();
    }
    for seed in 3..=16 {
        let (client, _) = token_challenge_client(&service, seed);
        fill_token_challenges(&service, &client);
    }
    // At the global cap A can still replace its own oldest slot; C cannot
    // displace anyone else's challenges. All routers keep the static 429 body.
    let (c, key_c) = token_challenge_client(&service, 17);
    let expected = serde_json::json!({"code": 429, "error": "too many pending pairing requests"});
    for (offset, app) in [&local, &bootstrap, &a_remote].into_iter().enumerate() {
        assert_eq!(
            challenge_response(
                app,
                local_challenge_request(&a, &key_a, now + 3 + offset as i64)
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    for app in [&local, &bootstrap, &noise_app(remote, &c)] {
        let (status, body) = own_token_challenge(app, &c, &key_c).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(body, expected);
    }
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

    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    let server = control::ControlServer::bind(tmp.path(), Arc::clone(&ctx)).unwrap();
    let path = server.path().to_path_buf();
    assert_eq!(path, tmp.path().join("control.sock"));

    let dir_mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        dir_mode, 0o700,
        "the data directory must be owner-only before the control socket is reachable"
    );
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
async fn malformed_control_requests_never_echo_input() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let tmp = tempfile::tempdir().unwrap();
    let (_, service, _) = state_with_pairing(tmp.path(), true);
    let ctx = Arc::new(control::ControlContext {
        identity_fingerprint: service.bound_fingerprint(),
        service,
        data_dir: tmp.path().to_path_buf(),
        mnemonic_path: tmp.path().join("unused-mnemonic"),
        replacement_guard: control::ReplacementGuard {
            layout: konsensus_api::bootstrap::DataDirLayout::new(tmp.path()),
            uses_identity_derived_keys: false,
            has_identity_passphrase: false,
        },
    });
    let server = control::ControlServer::bind(tmp.path(), ctx).unwrap();
    let stream = tokio::net::UnixStream::connect(server.path())
        .await
        .unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(server.serve(rx));
    let (read, mut write) = stream.into_split();
    let mut lines = BufReader::new(read).lines();
    for input in [
        r#"{"op":"PRIVATE_UNKNOWN_OPERATION"}"#,
        r#"{"op":"add-peer","node_id":"ab","addr":"127.0.0.1:9735","PRIVATE_UNKNOWN_FIELD":"PRIVATE_VALUE"}"#,
        r#"{"op":"open-window","seconds":"PRIVATE_BAD_TYPE"}"#,
        r#"{"op":"approve-replacement","mnemonic":"PRIVATE_TRUNCATED"#,
    ] {
        write
            .write_all(format!("{input}\n").as_bytes())
            .await
            .unwrap();
        let response = lines.next_line().await.unwrap().unwrap();
        assert!(!response.contains("PRIVATE_"), "input leaked: {response}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response).unwrap(),
            serde_json::json!({
                "result": "error",
                "message": "malformed_control_request: invalid control request"
            })
        );
    }
    // A malformed line must not prevent the owner from using the connection.
    write.write_all(b"{\"op\":\"status\"}\n").await.unwrap();
    assert!(matches!(
        serde_json::from_str::<control::ControlResponse>(
            &lines.next_line().await.unwrap().unwrap()
        )
        .unwrap(),
        control::ControlResponse::Status { .. }
    ));
    drop(write);
    drop(lines);
    stop.send(true).unwrap();
    task.await.unwrap();
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
        let app = konsensus_api::build_router_for_addr(state.clone(), addr);
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Preserve the test router's fallback for the rate-limit extractor;
        // LocalConnection still requires actual ConnectInfo, not this mock.
        let app = konsensus_api::build_router_for_addr(state.clone(), addr)
            .layer(axum::extract::connect_info::MockConnectInfo(
                "127.0.0.1:50000".parse::<std::net::SocketAddr>().unwrap(),
            ));
        let app = match mode {
            "remote" => app.layer(axum::Extension(axum::extract::ConnectInfo(
                "203.0.113.1:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))),
            "missing" => app,
            _ => app.layer(axum::Extension(axum::extract::ConnectInfo(
                "127.0.0.1:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))),
        };
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
                if !owner_control {
                    let (status, body) = post(&app, "/api/v1/pair/elevation-request",
                        serde_json::json!({"scopes": [scope.as_str()]}), Some(&token_a)).await;
                    assert_eq!(status, StatusCode::CONFLICT);
                    assert!(body.to_string().contains("owner_approval_unavailable"));
                    assert!(service.snapshot().pending_elevations.is_empty());
                    continue;
                }
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
                let cancelled = service.create_elevation_request(&a, vec![Scope::Spend]).unwrap();
                service.cancel_pending(&a, &cancelled.op_id).unwrap();
                // Voluntary withdrawal removes the operation entirely; neither
                // client can subsequently query it (unlike lockout's lost status).
                for token in [&token_a, &token_b] {
                    let response = app.clone().oneshot(Request::builder()
                        .uri(format!("/api/v1/pair/elevation/{}", cancelled.op_id))
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty()).unwrap()).await.unwrap();
                    assert_eq!(response.status(), StatusCode::NOT_FOUND, "cancelled request privacy");
                }
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

struct NoOwnerTerminal;

impl std::io::Write for NoOwnerTerminal {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(6))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
#[tokio::test]
async fn headless_elevation_uses_protected_file_and_grants_over_socket() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let base = test_state_with_data_dir(tmp.path().to_path_buf());
    let service = Arc::new(
        PairingService::open(
            tmp.path(),
            pairing::identity_fingerprint(&base.identity.node_id().to_hex()),
            true,
        )
        .unwrap()
        .with_owner_console(Box::new(NoOwnerTerminal))
        .without_stdout_code(),
    );
    let app = test_router(Arc::new(AppState {
        pairing: Some(service.clone()),
        ..(*base).clone()
    }));
    let (client, token) = pair_and_token(&app, &service, &SigningKey::from_bytes(&[92; 32])).await;
    let (status, body) = post(
        &app,
        "/api/v1/pair/elevation-request",
        serde_json::json!({"scopes": ["spend"]}),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let op_id = body["op_id"].as_str().unwrap();
    let path = service.dir().join(format!("owner-approval-{op_id}"));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(service.dir())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let text = std::fs::read_to_string(&path).unwrap();
    let phrase = text.lines().find(|l| l.starts_with("GRANT ")).unwrap();
    let code = text
        .lines()
        .find_map(|l| {
            l.split_once("type this code when it asks: ")
                .map(|(_, c)| c)
        })
        .unwrap();
    assert!(!body.to_string().contains(code));
    assert!(!body.to_string().contains(phrase));
    assert!(!std::fs::read_to_string(service.dir().join("clients.json"))
        .unwrap()
        .contains(code));
    let context = Arc::new(control::ControlContext {
        service: service.clone(),
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
    let socket = server.path().to_path_buf();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(server.serve(rx));
    let status = control::send(&socket, &control::ControlRequest::Status)
        .await
        .unwrap();
    assert!(!serde_json::to_string(&status).unwrap().contains(code));
    let granted = control::send(
        &socket,
        &control::ControlRequest::Grant {
            op_id: op_id.to_string(),
            confirmation: code.to_string(),
            terms: konsensus_api::spend_budget::GrantTerms::new(1000),
        },
    )
    .await
    .unwrap();
    assert!(matches!(granted, control::ControlResponse::Ok { .. }));
    assert!(!path.exists(), "consumed codes must be removed");
    assert!(matches!(
        service.elevation_status(&client, op_id).unwrap(),
        pairing::ElevationStatus::Granted
    ));
    stop.send(true).unwrap();
    task.await.unwrap();
}

#[tokio::test]
async fn headless_elevation_without_owner_delivery_returns_conflict() {
    for owner_control in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let base = test_state_with_data_dir(tmp.path().to_path_buf());
        let service = Arc::new(
            PairingService::open(
                tmp.path(),
                pairing::identity_fingerprint(&base.identity.node_id().to_hex()),
                owner_control,
            )
            .unwrap()
            .with_owner_console(Box::new(NoOwnerTerminal))
            .without_stdout_code(),
        );
        let app = test_router(Arc::new(AppState {
            pairing: Some(service.clone()),
            ..(*base).clone()
        }));
        let (_, token) = pair_and_token(&app, &service, &SigningKey::from_bytes(&[93; 32])).await;
        // No directory to deliver into; keep the service/token live in memory.
        std::fs::rename(service.dir(), tmp.path().join("unavailable")).unwrap();
        let (status, body) = post(
            &app,
            "/api/v1/pair/elevation-request",
            serde_json::json!({"scopes": ["spend"]}),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(body.to_string().contains("owner_approval_unavailable"));
        assert!(service.snapshot().pending_elevations.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn headless_output_child() {
    let Some(dir) = std::env::var_os("BITSOV_HEADLESS_TEST_DIR") else {
        return;
    };
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(std::io::stdout)
        .init();
    let service = PairingService::open(std::path::Path::new(&dir), "test".into(), true)
        .unwrap()
        .with_owner_console(Box::new(NoOwnerTerminal));
    let key = SigningKey::from_bytes(&[97; 32]);
    let client = service
        .create_verified_remote_pairing(
            "test",
            &hex::encode(key.verifying_key().to_bytes()),
            &[98; 32],
        )
        .unwrap();
    service
        .create_elevation_request(&client.client_id, vec![Scope::Spend])
        .unwrap();
    let owner = konsensus_core::OwnerApprovalKey::from_seed(&[7; 64], &[9; 32]).unwrap();
    let service = service.with_owner_approval_key(owner.verifying_key());
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let proof = hex::encode(key.sign(&rng, pairing::device::registration_message("test", &client.client_id, &public).as_bytes()).unwrap().as_ref());
    service.request_device_key(&client.client_id, &public, "device", &proof).unwrap();
    // Simulate process death so the parent can inspect the private code files.
    std::mem::forget(service);
}

#[cfg(unix)]
#[test]
fn headless_codes_never_reach_stdout_stderr_or_tracing() {
    let dir = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "headless_output_child", "--nocapture"])
        .env("BITSOV_HEADLESS_TEST_DIR", dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let paths: Vec<_> = std::fs::read_dir(dir.path().join("pairing"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("owner-approval-")
        })
        .collect();
    assert_eq!(paths.len(), 2);
    for path in paths {
        let text = std::fs::read_to_string(&path).unwrap();
        let phrase = text.lines().find(|l| l.contains(" CODE ")).unwrap();
        let nonce = phrase.split_once(" CODE ").unwrap().1;
        let code = text
            .lines()
            .find_map(|l| {
                l.split_once("type this code when it asks: ")
                    .map(|(_, c)| c)
            })
            .unwrap();
        for bytes in [&output.stdout, &output.stderr] {
            let captured = String::from_utf8_lossy(bytes);
            assert!(!captured.contains(nonce));
            assert!(!captured.contains(code));
            assert!(!captured.contains(&code.replace('-', "")));
        }
        assert!(
            String::from_utf8_lossy(&output.stdout).contains(&path.display().to_string()),
            "only the path is announced"
        );
    }
}

#[cfg(unix)]
#[test]
fn headless_front_door_can_be_granted_without_spend() {
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), "test".into(), true)
        .unwrap().with_owner_console(Box::new(NoOwnerTerminal));
    let key = SigningKey::from_bytes(&[95; 32]);
    let client = service.create_verified_remote_pairing("test", &hex::encode(key.verifying_key().to_bytes()), &[96; 32]).unwrap();
    let op = service
        .create_elevation_request(&client.client_id, vec![Scope::FrontDoor])
        .unwrap();
    let path = service.dir().join(format!("owner-approval-{}", op.op_id));
    let text = std::fs::read_to_string(&path).unwrap();
    let phrase = text
        .lines()
        .find(|line| line.starts_with("GRANT "))
        .unwrap();
    service.grant_front_door(&op.op_id, phrase, 60).unwrap();
    assert!(!path.exists());
    assert!(service.snapshot().grants.is_empty());
    assert_eq!(service.snapshot().front_door_grants.len(), 1);
}

#[tokio::test]
async fn headless_device_and_replacement_without_delivery_return_conflict() {
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    for device_request in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let base = test_state_with_data_dir(tmp.path().to_path_buf());
        let fp = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
        let owner = konsensus_core::OwnerApprovalKey::from_seed(&[7; 64], &[9; 32]).unwrap();
        let service = Arc::new(PairingService::open(tmp.path(), fp.clone(), true).unwrap()
            .with_owner_console(Box::new(NoOwnerTerminal)).without_stdout_code()
            .with_owner_approval_key(owner.verifying_key()));
        let app = test_router(Arc::new(AppState { pairing: Some(service.clone()), ..(*base).clone() }));
        let (client, token) = pair_and_token(&app, &service, &SigningKey::from_bytes(&[93; 32])).await;
        let (route, body) = if device_request {
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
            let public = hex::encode(key.public_key().as_ref());
            let proof = hex::encode(key.sign(&rng, pairing::device::registration_message(&fp, &client, &public).as_bytes()).unwrap().as_ref());
            // No protected-file delivery, but the paired token is still live.
            std::fs::rename(service.dir(), tmp.path().join("unavailable")).unwrap();
            ("/api/v1/pair/device-key", serde_json::json!({"public_key": public, "name": "device", "proof": proof}))
        } else {
            ("/api/v1/identity/replacement-request", serde_json::json!({"mnemonic": REPLACEMENT_MNEMONIC}))
        };
        let (status, body) = post(&app, route, body, Some(&token)).await;
        assert_eq!(status, StatusCode::CONFLICT, "{route}: {body}");
        assert!(body.to_string().contains("owner_approval_unavailable"));
        assert!(service.pending_device_keys().is_empty());
        assert!(service.snapshot().replacement_approvals.is_empty());
        if !device_request {
            assert!(body.to_string().contains("identity replacement requires an owner terminal"));
        }
    }
}

#[cfg(unix)]
#[path = "common/peer_admission.rs"]
mod peer_admission_probe;

#[cfg(unix)]
#[tokio::test]
async fn owner_peer_add_requires_matching_services_and_audits_admission() {
    for mode in ["no-state", "disabled", "mismatch", "admit"] {
        let tmp = tempfile::tempdir().unwrap();
        let (base, service, _console) = state_with_pairing(tmp.path(), mode != "disabled");
        let transport = Arc::new(peer_admission_probe::AdmissionTransport {
            storage: base.storage.clone(),
            registry: base.peer_registry.clone(),
            calls: std::sync::Mutex::new(vec![]),
            dial_started: Default::default(),
            finish_dial: Default::default(),
            live: Default::default(),
            dial: "refused",
            supervised_addrs: Default::default(),
        });
        let state = Arc::new(AppState {
            transport: transport.clone(),
            audit_log: Arc::new(
                konsensus_api::audit::AuditLog::open(tmp.path().join("audit.jsonl")).unwrap(),
            ),
            ..(*base).clone()
        });
        let context_service = if mode == "mismatch" {
            let other = tempfile::tempdir().unwrap();
            state_with_pairing(other.path(), true).1
        } else {
            service
        };
        let ctx = Arc::new(control::ControlContext {
            identity_fingerprint: context_service.bound_fingerprint(),
            service: context_service,
            data_dir: tmp.path().to_path_buf(),
            mnemonic_path: tmp.path().join("mnemonic.txt"),
            replacement_guard: control::ReplacementGuard {
                layout: konsensus_api::bootstrap::DataDirLayout::new(tmp.path()),
                uses_identity_derived_keys: false,
                has_identity_passphrase: false,
            },
        });
        let request = || control::ControlRequest::AddPeer {
            node_id: "ab".repeat(32),
            addr: "127.0.0.1:9735".into(),
            label: Some("Dad".into()),
        };
        assert!(
            matches!(control::handle(&ctx, request()), control::ControlResponse::Error { message } if message.contains("requires the running node"))
        );
        let server = control::ControlServer::bind(tmp.path(), ctx).unwrap();
        let path = server.path().to_path_buf();
        let server = if mode == "no-state" {
            server
        } else {
            server.with_approval_state(state.clone())
        };
        let (stop, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(server.serve(rx));
        let response = control::send(&path, &request()).await.unwrap();
        stop.send(true).unwrap();
        task.await.unwrap();
        if mode != "admit" {
            assert!(
                matches!(response, control::ControlResponse::Error { message } if message.contains("requires the running node"))
            );
            assert!(state.storage.list_peers().await.unwrap().is_empty());
            assert!(transport.calls.lock().unwrap().is_empty());
            continue;
        }
        assert!(
            matches!(response, control::ControlResponse::Ok { detail } if detail.contains("not reachable yet") && detail.contains("keeps retrying") && detail.contains(&state.identity.node_id().to_hex()))
        );
        assert_eq!(
            *transport.calls.lock().unwrap(),
            ["whitelist", "dial", "supervise"]
        );
        let audit = std::fs::read_to_string(state.audit_log.path()).unwrap();
        let event: serde_json::Value = audit
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
            .find(|e| e["event"] == "peer.added")
            .unwrap();
        assert_eq!(event["actor"], state.identity.node_id().to_hex());
        assert_eq!(event["detail"]["source"], "owner_control");
        assert_eq!(event["detail"]["peer_node_id"], "ab".repeat(32));
        assert_eq!(event["detail"]["label"], "Dad");
        assert_eq!(event["detail"]["connected"], false);
        let app = test_router(state.clone());
        let (_, token) = pair_and_token(
            &app,
            state.pairing.as_ref().unwrap(),
            &SigningKey::from_bytes(&[61; 32]),
        )
        .await;
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/peers")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let peers: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(peers[0]["node_id"], "ab".repeat(32));
        assert_eq!(peers[0]["connected"], false);
    }
}
