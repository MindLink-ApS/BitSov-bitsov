//! Locked authority is device possession AND password-derived owner approval.
use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
    Router,
};
use ed25519_dalek::{Signer, SigningKey};
use konsensus_api::{
    locked::{locked_router, unlock_message, LockedState, UnlockError},
    pairing::{
        device::{owner_approval_message, DeviceKey},
        identity_fingerprint, PairedClient, PairingFile, PairingService,
    },
    rate_limit::RemoteTunnelClients,
};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde_json::{json, Value};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tower::ServiceExt;
use zeroize::Zeroizing;

struct Fixture {
    _dir: tempfile::TempDir,
    pairing: Arc<PairingService>,
    clients: Arc<RemoteTunnelClients>,
    router: Router,
    rx: tokio::sync::oneshot::Receiver<Zeroizing<String>>,
    device: EcdsaKeyPair,
    keys: Vec<DeviceKey>,
}
impl Fixture {
    fn new(forged: bool) -> Self {
        Self::with_hook(forged, || {})
    }
    fn with_hook(forged: bool, hook: impl Fn() + Send + Sync + 'static) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let device =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap();
        let owner = SigningKey::from_bytes(&[9; 32]);
        let fingerprint = identity_fingerprint("node");
        let mut file = PairingFile::default();
        for n in 0..5 {
            let id = format!("client{n}");
            let public_key = hex::encode(device.public_key().as_ref());
            let key = DeviceKey {
                key_id: format!("key{n}"),
                client_id: id.clone(),
                public_key: public_key.clone(),
                name: "phone".into(),
                registered_at: 1,
                epoch: 1,
                client_pubkey: format!("pub{n}"),
                owner_approval: if forged {
                    "00".repeat(64)
                } else {
                    hex::encode(
                        owner
                            .sign(
                                owner_approval_message(
                                    &fingerprint,
                                    &format!("pub{n}"),
                                    1,
                                    &public_key,
                                )
                                .as_bytes(),
                            )
                            .to_bytes(),
                    )
                },
                enrolled_by: "console".into(),
            };
            file.device_keys.push(key);
            file.clients.push(PairedClient {
                client_id: id,
                name: "phone".into(),
                client_pubkey: format!("pub{n}"),
                remote_transport_pubkey: None,
                scopes: vec![],
                epoch: 1,
                identity_fingerprint: fingerprint.clone(),
                created_at: 1,
                last_seen: None,
            });
        }
        std::fs::create_dir(dir.path().join("pairing")).unwrap();
        std::fs::write(
            dir.path().join("pairing/clients.json"),
            serde_json::to_vec(&file).unwrap(),
        )
        .unwrap();
        let pairing = Arc::new(
            PairingService::open(dir.path(), fingerprint, false)
                .unwrap()
                .with_pairing_closed(),
        );
        let clients = Arc::new(RemoteTunnelClients::default());
        let (tx, rx) = tokio::sync::oneshot::channel();
        let state = Arc::new(LockedState::new(
            "node".into(),
            pairing.clone(),
            clients.clone(),
            move |password| {
                hook();
                if password == "unlock-test-secret" {
                    Ok(("node".into(), owner.verifying_key()))
                } else {
                    Err(UnlockError::Failed)
                }
            },
            tx,
        ));
        let router = locked_router(state);
        Self {
            _dir: dir,
            pairing,
            clients,
            router,
            rx,
            device,
            keys: file.device_keys,
        }
    }
    async fn request(
        &self,
        client: Option<usize>,
        method: &str,
        path: &str,
        body: Value,
    ) -> (StatusCode, String) {
        let peer: SocketAddr = "127.0.0.1:40001".parse().unwrap();
        let _guard = client.map(|n| self.clients.register(peer, format!("client{n}")));
        let response = self
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .extension(ConnectInfo(peer))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 16384).await.unwrap();
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!text.contains("unlock-test-secret"));
        (status, text)
    }
    async fn challenge(&self, client: usize) -> String {
        let (status, text) = self
            .request(
                Some(client),
                "POST",
                "/api/v1/node/unlock/challenge",
                json!({}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let body: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(body["key_ids"], json!([format!("key{client}")]));
        assert_eq!(body["challenge"].as_str().unwrap().len(), 64);
        body["challenge"].as_str().unwrap().into()
    }
    fn body(&self, client: usize, challenge: &str, password: &str) -> Value {
        let key = &self.keys[client];
        let message = unlock_message(
            &self.pairing.bound_fingerprint(),
            &key.client_id,
            key.epoch,
            &key.key_id,
            challenge,
            &hex::encode(self.pairing.box_transport_pubkey()),
        );
        let sig = self
            .device
            .sign(&ring::rand::SystemRandom::new(), message.as_bytes())
            .unwrap();
        json!({"challenge": challenge, "key_id": key.key_id, "signature": hex::encode(sig.as_ref()), "password": password})
    }
    async fn unlock(&self, client: usize, body: Value) -> StatusCode {
        self.request(Some(client), "POST", "/api/v1/node/unlock", body)
            .await
            .0
    }
}

#[tokio::test]
async fn locked_router_allowlist_and_tunnel_only_unlock() {
    let f = Fixture::new(false);
    for path in [
        "/api/v1/health",
        "/health",
        "/auth/local",
        "/api/v1/auth/local",
        "/api/v1/pair/request",
        "/api/v1/pair/confirm",
        "/api/v1/pair/token",
        "/api/v1/pair/device-keys",
        "/api/v1/pair/device-key",
        "/api/v1/pair/device-key/op",
        "/api/v1/pair/device-key/op/delegate",
        "/api/v1/pair/device-keys/key",
        "/api/v1/status",
        "/ws",
        "/metrics",
    ] {
        for method in ["GET", "POST", "DELETE"] {
            for client in [None, Some(0)] {
                assert_eq!(
                    f.request(client, method, path, json!({})).await.0,
                    StatusCode::NOT_FOUND,
                    "{method} {path}, paired={}",
                    client.is_some()
                );
            }
        }
    }
    assert_eq!(
        f.request(None, "GET", "/livez", json!({})).await.0,
        StatusCode::OK
    );
    let (status, lock) = f.request(None, "GET", "/api/v1/node/lock", json!({})).await;
    assert_eq!(status, StatusCode::OK);
    let lock: Value = serde_json::from_str(&lock).unwrap();
    assert_eq!(lock["state"], "locked");
    assert_eq!(lock["attempts_left"], 20);
    assert!(lock["hosted_by"].is_null());
    for path in ["/api/v1/node/unlock/challenge", "/api/v1/node/unlock"] {
        assert_eq!(
            f.request(None, "POST", path, json!({})).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    assert!(!f.pairing.pairing_open());
    f.pairing.open_pairing_window(Duration::from_secs(60));
    assert!(!f.pairing.pairing_open());
    let empty = tempfile::tempdir().unwrap();
    assert!(
        !PairingService::open(empty.path(), "fingerprint".into(), false)
            .unwrap()
            .with_pairing_closed()
            .pairing_open()
    );
}

#[tokio::test(start_paused = true)]
async fn challenges_are_single_use_expire_and_bind_client_and_epoch() {
    let f = Fixture::new(false);
    let c = f.challenge(0).await;
    assert_eq!(
        f.unlock(1, f.body(0, &c, "unlock-test-secret")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        f.unlock(0, f.body(0, &c, "unlock-test-secret")).await,
        StatusCode::UNAUTHORIZED
    );
    let c = f.challenge(0).await;
    tokio::time::advance(Duration::from_secs(120)).await;
    assert_eq!(
        f.unlock(0, f.body(0, &c, "unlock-test-secret")).await,
        StatusCode::UNAUTHORIZED
    );
    let c = f.challenge(0).await;
    f.pairing.bump_epoch("client0").unwrap();
    assert_eq!(
        f.unlock(0, f.body(0, &c, "unlock-test-secret")).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn forged_owner_approval_never_hands_off_password() {
    let mut f = Fixture::new(true);
    let c = f.challenge(0).await;
    assert_eq!(
        f.unlock(0, f.body(0, &c, "unlock-test-secret")).await,
        StatusCode::FORBIDDEN
    );
    assert!(matches!(
        f.rx.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
    ));
    assert!(f
        .request(None, "GET", "/api/v1/node/lock", json!({}))
        .await
        .1
        .contains("locked"));
}

#[tokio::test]
async fn valid_unlock_hands_off_once_and_returns_no_secret() {
    let f = Fixture::new(false);
    let c = f.challenge(0).await;
    assert_eq!(
        f.unlock(0, f.body(0, &c, "unlock-test-secret")).await,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        f.unlock(0, f.body(0, &c, "unlock-test-secret")).await,
        StatusCode::CONFLICT
    );
    assert_eq!(f.rx.await.unwrap().as_str(), "unlock-test-secret");
}

#[tokio::test(start_paused = true)]
async fn failures_are_per_key_with_sliding_window_and_process_ceiling() {
    let f = Fixture::new(false);
    for client in 0..4 {
        for attempt in 0..5 {
            let c = f.challenge(client).await;
            assert_eq!(
                f.unlock(client, f.body(client, &c, "wrong")).await,
                if attempt == 4 {
                    StatusCode::TOO_MANY_REQUESTS
                } else {
                    StatusCode::UNAUTHORIZED
                }
            );
        }
        if client == 0 {
            let c = f.challenge(0).await;
            assert_eq!(
                f.unlock(0, f.body(0, &c, "unlock-test-secret")).await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
    }
    tokio::time::advance(Duration::from_secs(901)).await;
    assert_eq!(
        f.request(Some(4), "POST", "/api/v1/node/unlock/challenge", json!({}))
            .await
            .0,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test(start_paused = true)]
async fn device_window_recovers_without_resetting_total() {
    let f = Fixture::new(false);
    for _ in 0..5 {
        let c = f.challenge(0).await;
        f.unlock(0, f.body(0, &c, "wrong")).await;
    }
    tokio::time::advance(Duration::from_secs(900)).await;
    let c = f.challenge(0).await;
    assert_eq!(
        f.unlock(0, f.body(0, &c, "unlock-test-secret")).await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn device_possession_is_required_before_password_verification() {
    let f = Fixture::with_hook(false, || panic!("must verify device first"));
    let c = f.challenge(0).await;
    let mut body = f.body(0, &c, "unlock-test-secret");
    body["signature"] = "00".into();
    assert_eq!(f.unlock(0, body).await, StatusCode::UNAUTHORIZED);
    let c = f.challenge(0).await;
    let mut body = f.body(0, &c, "unlock-test-secret");
    body["key_id"] = "key1".into();
    assert_eq!(f.unlock(0, body).await, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_unlock_has_one_204_one_409() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let release = barrier.clone();
    let f = Arc::new(Fixture::with_hook(false, move || {
        entered_tx.send(()).unwrap();
        release.wait();
    }));
    let c = f.challenge(0).await;
    let body = f.body(0, &c, "unlock-test-secret");
    let f1 = f.clone();
    let first_body = body.clone();
    let first = tokio::spawn(async move { f1.unlock(0, first_body).await });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(10)).unwrap())
        .await
        .unwrap();
    let second = f.unlock(0, body).await;
    barrier.wait();
    assert_eq!(second, StatusCode::CONFLICT);
    assert_eq!(first.await.unwrap(), StatusCode::NO_CONTENT);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_during_verification_drops_handoff_and_keeps_single_flight() {
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let release = barrier.clone();
    let f = Fixture::with_hook(false, move || {
        entered_tx.send(()).unwrap();
        release.wait();
    });
    let c = f.challenge(0).await;
    let peer: SocketAddr = "127.0.0.1:40001".parse().unwrap();
    let _guard = f.clients.register(peer, "client0".into());
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/node/unlock")
        .extension(ConnectInfo(peer))
        .body(Body::from(f.body(0, &c, "unlock-test-secret").to_string()))
        .unwrap();
    let router = f.router.clone();
    let task = tokio::spawn(async move { router.oneshot(request).await });
    tokio::task::spawn_blocking(move || entered_rx.recv_timeout(Duration::from_secs(10)).unwrap())
        .await
        .unwrap();
    task.abort();
    let _ = task.await;
    assert_eq!(
        f.unlock(0, f.body(0, &c, "unlock-test-secret")).await,
        StatusCode::CONFLICT
    );
    drop(f.rx); // The service's receiver disappears during shutdown.
    barrier.wait(); // The detached Argon2 task can only drop its zeroizing password.
}

#[tokio::test]
async fn signature_binds_node_box_epoch_key_and_challenge() {
    let f = Fixture::with_hook(false, || panic!("invalid binding must not decrypt"));
    for field in ["node", "box", "epoch", "key", "challenge"] {
        let c = f.challenge(0).await;
        let mut body = f.body(0, &c, "unlock-test-secret");
        // Hand-written wire format is deliberately independent of unlock_message.
        let node = if field == "node" {
            "other-node".to_owned()
        } else {
            f.pairing.bound_fingerprint()
        };
        let box_key = if field == "box" {
            "other-box".to_owned()
        } else {
            hex::encode(f.pairing.box_transport_pubkey())
        };
        let epoch = if field == "epoch" { 2 } else { 1 };
        let key = if field == "key" { "key1" } else { "key0" };
        let challenge = if field == "challenge" {
            "other-challenge"
        } else {
            &c
        };
        let message = format!("bitsov-node-unlock-v1\nnode:{node}\nclient:client0\nepoch:{epoch}\nkey:{key}\nchallenge:{challenge}\nbox_transport:{box_key}");
        body["signature"] = hex::encode(
            f.device
                .sign(&ring::rand::SystemRandom::new(), message.as_bytes())
                .unwrap()
                .as_ref(),
        )
        .into();
        let status = f.unlock(0, body).await;
        assert!(matches!(
            status,
            StatusCode::UNAUTHORIZED | StatusCode::TOO_MANY_REQUESTS
        ));
    }
}
