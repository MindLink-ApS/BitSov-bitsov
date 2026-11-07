//! `GET /api/v1/owner/claim-code`: the box claim code reaches only a loopback
//! owner console session or an enrolled owner device, and only while a
//! claim-bound enrollment is waiting for it. Never the tunnel, a plain
//! pairing, the LAN, the logs or the audit trail.

#![allow(dead_code)]

mod common;

#[path = "common/owner_console.rs"]
mod owner_console;
use owner_console::OwnerConsole;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use tower::ServiceExt;

use konsensus_api::auth;
use konsensus_api::pairing::device::{
    owner_approval_message, registration_message, sas_registration_message,
};
use konsensus_api::pairing::{self, PairingService};
use konsensus_api::rate_limit::{remote_tunnel_identity, RemoteTunnelClients};
use konsensus_api::state::AppState;

use common::*;

const PATH: &str = "/api/v1/owner/claim-code";

struct Device {
    key: EcdsaKeyPair,
    public: String,
}

/// A live, claimed box with one enrolled owner device and one plain pairing.
struct OwnerBox {
    dir: tempfile::TempDir,
    state: Arc<AppState>,
    svc: Arc<PairingService>,
    fp: String,
    owner: pairing::PairedClient,
    owner_token: String,
    phone: pairing::PairedClient,
    phone_token: String,
    phone_binding: konsensus_api::sas::NoiseBinding,
    console_token: String,
    claim: String,
    rng: ring::rand::SystemRandom,
}

impl OwnerBox {
    fn device(&self) -> Device {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &self.rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &self.rng)
                .unwrap();
        let public = hex::encode(key.public_key().as_ref());
        Device { key, public }
    }
    fn sign(&self, key: &EcdsaKeyPair, msg: &str) -> String {
        hex::encode(key.sign(&self.rng, msg.as_bytes()).unwrap().as_ref())
    }
    /// The phone starts a claim-bound (SAS v1) enrollment over its tunnel.
    fn start_claim(&self) -> (String, Device, [u8; 16]) {
        let device = self.device();
        let proof = self.sign(
            &device.key,
            &registration_message(&self.fp, &self.phone.client_id, &device.public),
        );
        let op = self
            .svc
            .request_device_key_versioned(
                &self.phone.client_id,
                &device.public,
                "phone",
                &proof,
                Some(1),
                Some(self.phone_binding),
            )
            .unwrap();
        let nonce: [u8; 16] = hex::decode(op.box_nonce().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        (op.op_id, device, nonce)
    }
    fn finish_claim(
        &self,
        op_id: &str,
        device: &Device,
        nonce: &[u8; 16],
        claim: &str,
    ) -> Result<(), pairing::PairingError> {
        let mut commitment = blake3::Hasher::new();
        commitment.update(b"bitsov-claim-code-v1");
        commitment.update(claim.as_bytes());
        let digest = konsensus_api::sas::digest(
            &self.phone_binding,
            &device.key.public_key().as_ref().try_into().unwrap(),
            nonce,
            commitment.finalize().as_bytes(),
        );
        let proof = self.sign(
            &device.key,
            &sas_registration_message(&self.fp, &self.phone.client_id, &device.public, &digest),
        );
        self.svc.confirm_device_sas(
            &self.phone.client_id,
            op_id,
            &self.phone_binding,
            &digest.to_hex(),
            &proof,
        )
    }
    fn local_router(&self, source: &str) -> axum::Router {
        konsensus_api::build_router(self.state.clone())
            .layer(MockConnectInfo(source.parse::<SocketAddr>().unwrap()))
    }
    fn remote_router(&self) -> axum::Router {
        let tunnels = Arc::new(RemoteTunnelClients::default());
        let peer: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let binding = konsensus_api::sas::NoiseBinding {
            handshake_hash: [93; 32],
            box_public_key: self.svc.box_transport_pubkey(),
            client_static: [92; 32],
        };
        // Leak the guard: the registration must outlive this test's requests.
        std::mem::forget(tunnels.register_noise(peer, self.owner.client_id.clone(), binding));
        konsensus_api::build_remote_router_with_limiter(
            self.state.clone(),
            Arc::new(konsensus_api::rate_limit::RateLimiter::new(10_000)),
        )
        .layer(axum::middleware::from_fn_with_state(
            tunnels,
            remote_tunnel_identity,
        ))
        .layer(MockConnectInfo(peer))
    }
}

async fn get(router: axum::Router, token: Option<&str>) -> (StatusCode, Value, Option<String>) {
    get_at(router, token, Some("127.0.0.1:3141"), None).await
}

async fn get_at(
    router: axum::Router,
    token: Option<&str>,
    host: Option<&str>,
    origin: Option<&str>,
) -> (StatusCode, Value, Option<String>) {
    let mut req = Request::builder().method("GET").uri(PATH);
    if let Some(host) = host {
        req = req.header("host", host);
    }
    if let Some(origin) = origin {
        req = req.header("origin", origin);
    }
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let response = router
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cache = response
        .headers()
        .get("cache-control")
        .map(|v| v.to_str().unwrap().to_owned());
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!({"raw": String::from_utf8_lossy(&bytes)})),
        cache,
    )
}

fn owner_box(seed: u8) -> OwnerBox {
    let dir = tempfile::tempdir().unwrap();
    let base = test_state();
    // A distinct identity per test keeps the per-actor limiter buckets apart.
    let (_, identity) = konsensus_core::NodeIdentity::generate().unwrap();
    let identity = Arc::new(identity);
    let node_id = identity.node_id().to_hex();
    let fp = pairing::identity_fingerprint(&node_id);
    let owner_key = konsensus_core::OwnerApprovalKey::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
        &[seed; 32],
    )
    .unwrap();
    let console = OwnerConsole::default();
    let svc = PairingService::open(dir.path(), fp.clone(), true)
        .unwrap()
        .with_owner_approval_key(owner_key.verifying_key())
        .with_owner_console(Box::new(console.clone()))
        .without_stdout_code();
    let owner_signing = SigningKey::from_bytes(&[seed; 32]);
    let owner = svc
        .create_ticket_remote_pairing(
            "owner",
            &hex::encode(owner_signing.verifying_key().to_bytes()),
            &[seed.wrapping_add(1); 32],
        )
        .unwrap();
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let proof = hex::encode(
        key.sign(
            &rng,
            registration_message(&fp, &owner.client_id, &public).as_bytes(),
        )
        .unwrap()
        .as_ref(),
    );
    let op = svc
        .request_device_key(&owner.client_id, &public, "owner", &proof)
        .unwrap();
    svc.approve_device_key(
        &op.op_id,
        &console.owner_code(&op.op_id),
        &hex::encode(
            owner_key
                .sign(
                    owner_approval_message(&fp, &owner.client_pubkey, owner.epoch, &public)
                        .as_bytes(),
                )
                .to_bytes(),
        ),
    )
    .unwrap();
    let phone_signing = SigningKey::from_bytes(&[seed.wrapping_add(2); 32]);
    let phone = svc
        .create_ticket_remote_pairing(
            "phone",
            &hex::encode(phone_signing.verifying_key().to_bytes()),
            &[seed.wrapping_add(3); 32],
        )
        .unwrap();
    drop(svc);
    let svc = Arc::new(
        PairingService::open(dir.path(), fp.clone(), true)
            .unwrap()
            .with_local_owner_device()
            .with_owner_signing_key(owner_key)
            .without_stdout_code(),
    );
    svc.configure_owner_tickets(&identity, vec!["127.0.0.1:9737".into()])
        .unwrap();
    let (claim, created) = konsensus_api::sas::initialize(dir.path()).unwrap();
    assert!(created);
    let mut claim_bytes = Vec::new();
    claim.write_local(&mut claim_bytes).unwrap();
    let claim = String::from_utf8(claim_bytes).unwrap();
    let state = Arc::new(AppState {
        identity: Arc::clone(&identity),
        pairing: Some(svc.clone()),
        data_dir: Some(dir.path().into()),
        audit_log: Arc::new(
            konsensus_api::audit::AuditLog::open(dir.path().join("audit.jsonl")).unwrap(),
        ),
        ..(*base).clone()
    });
    let token_for = |client: &pairing::PairedClient, signing: &SigningKey| {
        let challenge = svc.issue_token_challenge(&client.client_id).unwrap();
        svc.issue_token(
            &node_id,
            &state.jwt_secret,
            &client.client_id,
            &challenge,
            &hex::encode(signing.sign(challenge.as_bytes()).to_bytes()),
        )
        .unwrap()
        .token
    };
    let owner_token = token_for(&owner, &owner_signing);
    let phone_token = token_for(&phone, &phone_signing);
    let console_token =
        auth::create_token(&node_id, &state.jwt_secret, auth::Scope::loopback_only()).unwrap();
    let phone_binding = konsensus_api::sas::NoiseBinding {
        handshake_hash: [seed.wrapping_add(4); 32],
        box_public_key: svc.box_transport_pubkey(),
        client_static: [seed.wrapping_add(3); 32],
    };
    OwnerBox {
        dir,
        state,
        svc,
        fp,
        owner,
        owner_token,
        phone,
        phone_token,
        phone_binding,
        console_token,
        claim,
        rng,
    }
}

#[tokio::test]
async fn console_session_and_owner_device_see_the_code_only_while_a_claim_is_pending() {
    let b = owner_box(10);
    let (status, body, cache) =
        get(b.local_router("127.0.0.1:50000"), Some(&b.console_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"state": "claimed"}));
    assert_eq!(cache.as_deref(), Some("no-store"));

    let (op_id, device, nonce) = b.start_claim();
    let before = chrono::Utc::now().timestamp();
    for token in [&b.console_token, &b.owner_token] {
        let (status, body, cache) = get(b.local_router("[::1]:50000"), Some(token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["state"], "open");
        assert_eq!(body["code"].as_str().unwrap(), b.claim);
        assert_eq!(body["code"].as_str().unwrap().len(), 18);
        assert_eq!(body["device_name"], "phone");
        let expires_at = body["expires_at"].as_i64().unwrap();
        assert!(
            expires_at > before && expires_at <= before + 15 * 60 + 1,
            "{expires_at}"
        );
        assert_eq!(cache.as_deref(), Some("no-store"));
    }
    // The code the owner read is exactly what the phone needs to finalize.
    let shown = get(b.local_router("127.0.0.1:50000"), Some(&b.console_token))
        .await
        .1;
    b.finish_claim(&op_id, &device, &nonce, shown["code"].as_str().unwrap())
        .unwrap();
    let (status, body, _) = get(b.local_router("127.0.0.1:50000"), Some(&b.owner_token)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"state": "claimed"}));
}

#[tokio::test]
async fn unauthenticated_peer_lan_and_tunnel_requests_are_refused() {
    let b = owner_box(20);
    let (op_id, device, nonce) = b.start_claim();
    // Error envelopes carry a numeric `code` (the HTTP status); the claim code
    // is a string, and no refusal may carry it or any claim state.
    let refused = |body: &Value| {
        assert!(body["code"].as_str().is_none(), "{body}");
        assert!(body.get("state").is_none(), "{body}");
        assert!(!body.to_string().contains(&b.claim), "{body}");
    };
    // No token.
    let (status, body, _) = get(b.local_router("127.0.0.1:50000"), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    refused(&body);
    // A plain paired client (read/receive, no enrolled owner device): the peer
    // that is itself asking for the code.
    let (status, body, _) = get(b.local_router("127.0.0.1:50000"), Some(&b.phone_token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reason"], "owner_device_required");
    refused(&body);
    // A bootstrap-era token is not a live session.
    let (status, body, _) = get(b.local_router("127.0.0.1:50000"), Some("not-a-token")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    refused(&body);
    // The owner's own token from a LAN source, with and without a token.
    for token in [Some(b.owner_token.as_str()), Some(b.console_token.as_str())] {
        let (status, body, _) = get(b.local_router("192.168.1.9:50000"), token).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["reason"], "owner_console_only");
        refused(&body);
    }
    // The remote router never mounts the route, even for the enrolled owner
    // on its authenticated tunnel.
    let (status, body, _) = get(b.remote_router(), Some(&b.owner_token)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    refused(&body);
    // A bridged request that somehow reached the local router is still refused.
    let bridged = b.local_router("127.0.0.1:50000").layer(axum::Extension(
        konsensus_api::rate_limit::AuthenticatedNoise {
            client_id: b.owner.client_id.clone().into(),
            binding: b.phone_binding,
        },
    ));
    let (status, body, _) = get(bridged, Some(&b.owner_token)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["reason"], "owner_console_only");
    refused(&body);
    // None of the refusals consumed the pending claim.
    b.finish_claim(&op_id, &device, &nonce, &b.claim).unwrap();
}

#[tokio::test]
async fn foreign_host_or_origin_hides_the_code_and_does_not_spend_the_actor_budget() {
    let b = owner_box(21);
    let _pending = b.start_claim();
    let token = b.console_token.as_str();
    for (host, origin) in [
        (None, None),
        (Some("attacker.example:3141"), None),
        (Some("127.0.0.1:9"), None),
        (Some("127.0.0.1:3141"), Some("http://attacker.example:3141")),
        (Some("127.0.0.1:3141"), Some("null")),
    ] {
        let (status, body, cache) =
            get_at(b.local_router("127.0.0.1:50000"), Some(token), host, origin).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{host:?} {origin:?} {body}");
        let code = body["code"].as_str().unwrap();
        assert!(
            code == "local_host_forbidden" || code == "local_origin_forbidden",
            "{body}"
        );
        assert!(body.get("state").is_none(), "{body}");
        assert!(!body.to_string().contains(&b.claim), "{body}");
        assert_eq!(cache.as_deref(), Some("no-store"));
    }
    // Header refusals run before the per-actor limiter, so the owner still
    // has the full five reads.
    for i in 0..5 {
        let (status, body, _) = get(b.local_router("127.0.0.1:50000"), Some(token)).await;
        assert_eq!(status, StatusCode::OK, "read {i}: {body}");
        assert_eq!(body["code"], b.claim);
    }
    let (status, body, _) = get(b.local_router("[::1]:50000"), Some(token)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(!body.to_string().contains(&b.claim), "{body}");
    // A case-insensitive allowed Host still shows the code to the other actor.
    let (status, body, _) = get_at(
        b.local_router("127.0.0.1:50000"),
        Some(&b.owner_token),
        Some("LOCALHOST:3141"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["code"], b.claim);
}

#[tokio::test]
async fn closed_after_three_sas_mismatches_and_unavailable_without_a_claim_file() {
    let b = owner_box(30);
    for _ in 0..3 {
        let (op_id, device, nonce) = b.start_claim();
        assert!(matches!(
            b.finish_claim(&op_id, &device, &nonce, "AAAAAAAAAAAAAAAAAA"),
            Err(pairing::PairingError::BadProof)
        ));
    }
    let (status, body, cache) =
        get(b.local_router("127.0.0.1:50000"), Some(&b.console_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"state": "closed"}));
    assert_eq!(cache.as_deref(), Some("no-store"));

    // A box without a claim-code file (pre-N3) has nothing to show.
    let legacy = tempfile::tempdir().unwrap();
    let state = Arc::new(AppState {
        data_dir: Some(legacy.path().into()),
        ..(*b.state).clone()
    });
    let router = konsensus_api::build_router(state).layer(MockConnectInfo(
        "127.0.0.1:50000".parse::<SocketAddr>().unwrap(),
    ));
    let (status, body, _) = get(router, Some(&b.console_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"state": "unavailable"}));
}

#[tokio::test]
async fn rate_limit_holds_per_owner_actor() {
    let b = owner_box(40);
    let _pending = b.start_claim();
    for i in 0..5 {
        let (status, body, _) =
            get(b.local_router("127.0.0.1:50000"), Some(&b.console_token)).await;
        assert_eq!(status, StatusCode::OK, "read {i}: {body}");
        assert_eq!(body["state"], "open");
    }
    let (status, body, cache) =
        get(b.local_router("127.0.0.1:50000"), Some(&b.console_token)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(!body.to_string().contains(&b.claim));
    assert_eq!(cache.as_deref(), Some("no-store"));
    // The limiter is per actor, so the throttled console does not lock out
    // the enrolled owner device, and refusals do not count against it.
    let (status, body, _) = get(b.local_router("127.0.0.1:50000"), Some(&b.owner_token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "open");
}

#[tokio::test]
async fn code_is_never_logged_or_audited() {
    // Isolate the tracing subscriber from parallel tests' callsite caches.
    const CHILD: &str = "BITSOV_CLAIM_CODE_LOG_TEST";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "code_is_never_logged_or_audited", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    use tracing::instrument::WithSubscriber;
    let log = tempfile::NamedTempFile::new().unwrap();
    let writer = log.reopen().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.try_clone().unwrap())
        .finish();
    let b = owner_box(50);
    let claim = b.claim.clone();
    let audit = b.dir.path().join("audit.jsonl");
    async {
        let _pending = b.start_claim();
        let (status, body, cache) =
            get(b.local_router("127.0.0.1:50000"), Some(&b.console_token)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["code"], claim);
        assert_eq!(cache.as_deref(), Some("no-store"));
        tracing::info!("deliberate test-only marker");
        let (status, _, _) = get(b.local_router("10.0.0.2:50000"), Some(&b.owner_token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (status, _, _) = get(b.local_router("127.0.0.1:50000"), Some(&b.phone_token)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
    .with_subscriber(subscriber)
    .await;
    let captured = std::fs::read_to_string(log.path()).unwrap();
    // The subscriber works: the test's own marker is there, but the handler
    // and middleware never put the code into a tracing event or span.
    assert!(
        captured.contains("deliberate test-only marker"),
        "{captured}"
    );
    assert!(!captured.contains(&claim), "{captured}");
    assert!(
        captured.contains("GET /api/v1/owner/claim-code"),
        "the request span must still be traced by path: {captured}"
    );
    let audited = std::fs::read_to_string(audit).unwrap();
    assert!(audited.contains("owner.claim_code_viewed"), "{audited}");
    assert!(!audited.contains(&claim), "{audited}");
    assert!(!audited.contains("\"code\""), "{audited}");
}
