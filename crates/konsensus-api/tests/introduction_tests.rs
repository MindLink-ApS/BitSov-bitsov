//! K1 slice 1: the signed introduction and dialing from one.
//! An introduction is never admission: opening one dials unprivileged,
//! whitelists nothing, stores nothing and pays nothing.
#![allow(dead_code)]
mod common;
use common::*;

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use konsensus_api::auth;
use konsensus_api::handlers::introduction::IntroductionSettings;
use konsensus_api::state::AppState;
use konsensus_core::introduction::{first_contact_prices, Introduction, IntroductionFields, Reach};
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::NodeId;
use konsensus_core::UkmEnvelope;

/// Records every connect and whitelist change; refuses like a closed mesh
/// when `closed` is set.
#[derive(Default)]
struct Recorder {
    connects: Mutex<Vec<(NodeId, String)>>,
    whitelisted: Mutex<Vec<NodeId>>,
    supervised: Mutex<Vec<NodeId>>,
    closed: bool,
}

#[async_trait]
impl MessageTransport for Recorder {
    async fn send(&self, _: &NodeId, _: &UkmEnvelope) -> Result<(), TransportError> {
        Ok(())
    }
    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        futures::future::pending().await
    }
    async fn connect(&self, peer: &NodeId, addr: &str) -> Result<(), TransportError> {
        if self.closed {
            return Err(TransportError::Rejected(format!("peer {} not in whitelist", peer.to_hex())));
        }
        self.connects.lock().unwrap().push((*peer, addr.to_string()));
        Ok(())
    }
    async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> {
        Ok(())
    }
    async fn is_connected(&self, _: &NodeId) -> bool {
        false
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        Vec::new()
    }
    async fn add_to_whitelist(&self, peer: &NodeId) {
        self.whitelisted.lock().unwrap().push(*peer);
    }
    async fn supervise_peer(&self, peer: &NodeId, _: &str) {
        self.supervised.lock().unwrap().push(*peer);
    }
}

fn settings(endpoint: Option<&str>) -> IntroductionSettings {
    IntroductionSettings { network: Some("regtest".into()), endpoint: endpoint.map(Into::into) }
}

fn state_with(transport: Arc<Recorder>, intro: IntroductionSettings) -> Arc<AppState> {
    let base = test_state();
    Arc::new(AppState { transport, introduction: intro, ..(*base).clone() })
}

fn bearer(state: &AppState, scopes: Vec<auth::Scope>) -> String {
    let token = auth::create_token(&state.identity.node_id().to_hex(), &state.jwt_secret, scopes).unwrap();
    format!("Bearer {token}")
}

async fn call(state: &Arc<AppState>, method: &str, path: &str, bearer: String, body: Option<Value>) -> (StatusCode, Value, Option<String>) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", bearer)
        .header("content-type", "application/json");
    let body = body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty);
    let response = test_router(state.clone()).oneshot(req.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let cache = response.headers().get("cache-control").map(|v| v.to_str().unwrap().to_string());
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) })), cache)
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// A stranger's card, as their node would sign it.
fn stranger_card(endpoint: &str, network: &str, issued_at: u64) -> Introduction {
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    Introduction::issue_with_key(
        &key,
        IntroductionFields {
            network: network.into(),
            endpoint: endpoint.into(),
            admission_msat: 100_000,
            message_msat: 10_000,
            price_epoch: 0,
            issued_at,
            intro_id: [9; 16],
        },
    )
    .unwrap()
}

#[tokio::test]
async fn read_scope_gets_a_signed_card_of_this_node() {
    let state = state_with(Arc::default(), settings(Some("node.example.org:9000")));
    let (status, body, cache) = call(&state, "GET", "/api/v1/introduction", bearer(&state, vec![auth::Scope::Read]), None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    let card: Introduction = serde_json::from_value(body["card"].clone()).unwrap();
    card.verify(now(), "regtest").expect("the node's own card verifies");
    assert_eq!(card.node().unwrap(), *state.identity.node_id());
    assert_eq!(card.endpoint, "node.example.org:9000");
    assert_eq!(card.reach, Reach::Public);
    // StubPricing charges 10 msat per chat: the card shows what the stateless quote would.
    assert_eq!((card.admission_msat, card.message_msat), first_contact_prices(10));
    assert!(card.expires_at - card.issued_at <= 600);
    let link = body["link"].as_str().unwrap();
    assert!(link.starts_with("bitsov://introduce#"));
    assert_eq!(Introduction::parse(link).unwrap(), card);
    // Fresh id per card: nothing is a durable credential.
    let (_, again, _) = call(&state, "GET", "/api/v1/introduction", bearer(&state, vec![auth::Scope::Read]), None).await;
    assert_ne!(again["card"]["intro_id"], body["card"]["intro_id"]);
}

#[tokio::test]
async fn no_card_without_a_dialable_endpoint_or_network() {
    let state = state_with(Arc::default(), settings(None));
    let (status, body, _) = call(&state, "GET", "/api/v1/introduction", bearer(&state, vec![auth::Scope::Read]), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body.to_string().contains("advertised_addr"), "{body}");

    let state = state_with(Arc::default(), IntroductionSettings { network: None, endpoint: Some("a.example:1".into()) });
    let (status, _, _) = call(&state, "GET", "/api/v1/introduction", bearer(&state, vec![auth::Scope::Read]), None).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn introduction_routes_need_a_token_and_read_is_enough() {
    let state = state_with(Arc::default(), settings(Some("node.example.org:9000")));
    let resp = test_router(state.clone())
        .oneshot(Request::builder().uri("/api/v1/introduction").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let card = stranger_card("127.0.0.1:9735", "regtest", now());
    let open = |bearer: String| {
        let state = state.clone();
        let body = json!({ "card": card.to_link(), "allow_local": true });
        async move { call(&state, "POST", "/api/v1/introduction/open", bearer, Some(body)).await.0 }
    };
    // A paired app holds read + receive before any budget: that is enough to dial.
    assert_eq!(open(bearer(&state, vec![auth::Scope::Read])).await, StatusCode::OK);
    assert_eq!(open(bearer(&state, vec![auth::Scope::Receive])).await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn open_dials_unprivileged_and_admits_nothing() {
    let transport = Arc::new(Recorder::default());
    let state = state_with(transport.clone(), settings(Some("node.example.org:9000")));
    let card = stranger_card("127.0.0.1:9735", "regtest", now());
    let (status, body, _) = call(&state, "POST", "/api/v1/introduction/open", bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "card": card.to_link(), "allow_local": true }))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["node_id"], card.node_id);
    assert_eq!(body["dialed"], "127.0.0.1:9735");
    assert_eq!(*transport.connects.lock().unwrap(), vec![(card.node().unwrap(), "127.0.0.1:9735".to_string())]);
    // Never admission: no whitelist entry, no supervision, no stored peer or registry entry.
    assert!(transport.whitelisted.lock().unwrap().is_empty());
    assert!(transport.supervised.lock().unwrap().is_empty());
    assert!(state.storage.list_peers().await.unwrap().is_empty());
    assert!(state.peer_registry.read().await.get(&card.node().unwrap()).is_none());
}

#[tokio::test]
async fn open_refuses_bad_cards_before_dialing() {
    let transport = Arc::new(Recorder::default());
    let state = state_with(transport.clone(), settings(Some("node.example.org:9000")));
    let spend = || bearer(&state, vec![auth::Scope::Read]);

    let mut tampered = stranger_card("127.0.0.1:9735", "regtest", now());
    tampered.admission_msat = 1;
    let expired = stranger_card("127.0.0.1:9735", "regtest", now() - 601);
    let other_net = stranger_card("127.0.0.1:9735", "signet", now());
    let mut swapped = stranger_card("127.0.0.1:9735", "regtest", now());
    swapped.endpoint = "127.0.0.1:9999".into();
    let own = Introduction::issue(&state.identity, IntroductionFields {
        network: "regtest".into(), endpoint: "127.0.0.1:9000".into(), admission_msat: 1000,
        message_msat: 1000, price_epoch: 0, issued_at: now(), intro_id: [1; 16],
    }).unwrap();

    for (name, text) in [
        ("tampered price", tampered.to_link()),
        ("expired", expired.to_link()),
        ("wrong network", other_net.to_link()),
        ("swapped endpoint", swapped.to_link()),
        ("own card", own.to_link()),
        ("garbage", "bitsov://introduce#not-a-card".into()),
        ("oversize", "A".repeat(4096)),
    ] {
        let (status, body, _) = call(&state, "POST", "/api/v1/introduction/open", spend(), Some(json!({ "card": text }))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}: {body}");
        assert!(body.to_string().contains("introduction_invalid"), "{name}: {body}");
    }
    assert!(transport.connects.lock().unwrap().is_empty(), "nothing was dialed");
}

#[tokio::test]
async fn a_closed_mesh_node_refuses_rather_than_whitelisting() {
    let transport = Arc::new(Recorder { closed: true, ..Default::default() });
    let state = state_with(transport.clone(), settings(Some("node.example.org:9000")));
    let card = stranger_card("127.0.0.1:9735", "regtest", now());
    let (status, body, _) = call(&state, "POST", "/api/v1/introduction/open", bearer(&state, vec![auth::Scope::Read]),
        Some(json!({ "card": card.to_link(), "allow_local": true }))).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("introduction_closed_mesh"), "{body}");
    assert!(transport.whitelisted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn status_advertises_introduction_v1() {
    let state = state_with(Arc::default(), settings(None));
    let (status, body, _) = call(&state, "GET", "/api/v1/status", auth_header(&state), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["api_capabilities"].as_array().unwrap().iter().any(|c| c == "introduction_v1"), "{body}");
}

#[tokio::test]
async fn verify_is_read_only_and_never_dials_or_stores() {
    let transport = Arc::new(Recorder::default());
    let state = state_with(transport.clone(), settings(Some("node.example.org:9000")));
    // A nonexistent DNS name also verifies: verification must never resolve it.
    let card = stranger_card("unresolved.invalid:9000", "regtest", now());
    let (status, body, cache) = call(&state, "POST", "/api/v1/introduction/verify",
        bearer(&state, vec![auth::Scope::Read]), Some(json!({"card": card.to_link()}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(cache.as_deref(), Some("no-store"));
    assert_eq!(body["card"]["node_id"], card.node_id);
    assert!(transport.connects.lock().unwrap().is_empty());
    assert!(transport.whitelisted.lock().unwrap().is_empty());
    assert!(transport.supervised.lock().unwrap().is_empty());
    assert!(state.storage.list_peers().await.unwrap().is_empty());
    assert!(state.peer_registry.read().await.get(&card.node().unwrap()).is_none());
    let (status, _, _) = call(&state, "POST", "/api/v1/introduction/verify",
        bearer(&state, vec![auth::Scope::Receive]), Some(json!({"card": card.to_link()}))).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn local_dial_requires_reader_consent() {
    let transport = Arc::new(Recorder::default());
    let state = state_with(transport.clone(), settings(Some("node.example.org:9000")));
    for endpoint in ["127.0.0.1:9735", "10.0.0.1:9000", "[::1]:9000", "[::ffff:192.168.1.1]:9000"] {
        let card = stranger_card(endpoint, "regtest", now());
        for body in [json!({"card": card.to_link()}), json!({"card": card.to_link(), "allow_local": false})] {
            let (status, response, _) = call(&state, "POST", "/api/v1/introduction/open",
                bearer(&state, vec![auth::Scope::Read]), Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{endpoint}: {response}");
            assert!(response.to_string().contains("local_consent_required"), "{response}");
            assert!(transport.connects.lock().unwrap().is_empty());
        }
    }
}

#[tokio::test]
async fn forged_weak_key_and_malformed_endpoints_never_dial() {
    use ed25519_dalek::Signer;
    let transport = Arc::new(Recorder::default());
    let state = state_with(transport.clone(), settings(Some("node.example.org:9000")));
    let key = ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]);
    let mut weak = stranger_card("127.0.0.1:9735", "regtest", now());
    let mut point = [0u8; 32];
    point[0] = 1;
    let mut sig = [0u8; 64];
    sig[0] = 1;
    weak.node_id = hex::encode(point);
    weak.sig = hex::encode(sig);
    let mut inputs = vec![weak.to_link()];
    weak.endpoint = "127.0.0.1:9999".into();
    weak.message_msat = 1;
    inputs.push(weak.to_link());
    inputs.push(stranger_card("127.0.0.1:9735", "regtest", now() - 601).to_link());
    let mut tampered = stranger_card("127.0.0.1:9735", "regtest", now());
    tampered.message_msat += 1;
    inputs.push(tampered.to_link());
    for endpoint in ["127.0.0.1:0", "127.0.0.1:65536", "127.0.0.1:+9000", "user@127.0.0.1:9000",
        "169.254.169.254:80", "[fe80::1]:9000", "http://127.0.0.1:9000", "127.0.0.1:9000/admin"] {
        let mut card = stranger_card("127.0.0.1:9735", "regtest", now());
        card.endpoint = endpoint.into();
        card.sig = hex::encode(key.sign(blake3::hash(&card.canonical_bytes().unwrap()).as_bytes()).to_bytes());
        inputs.push(card.to_link());
    }
    let mut too_long = stranger_card("127.0.0.1:9735", "regtest", now());
    too_long.endpoint = format!("{}:9000", "a".repeat(256));
    inputs.push(serde_json::to_string(&too_long).unwrap());
    for input in inputs {
        for route in ["/api/v1/introduction/verify", "/api/v1/introduction/open"] {
            let body = if route.ends_with("/open") { json!({"card": input, "allow_local": true}) } else { json!({"card": input}) };
            let (status, response, _) = call(&state, "POST", route,
                bearer(&state, vec![auth::Scope::Read]), Some(body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{route}: {response}");
        }
    }
    assert!(transport.connects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn paired_read_client_can_verify_and_explicitly_open_without_a_spend_grant() {
    use ed25519_dalek::Signer;
    use konsensus_api::pairing::{identity_fingerprint, PairingService};
    let dir = tempfile::tempdir().unwrap();
    let transport = Arc::new(Recorder::default());
    let base = state_with(transport.clone(), settings(Some("node.example.org:9000")));
    let service = Arc::new(PairingService::open(
        dir.path(), identity_fingerprint(&base.identity.node_id().to_hex()), false,
    ).unwrap().without_stdout_code());
    let key = ed25519_dalek::SigningKey::from_bytes(&[53; 32]);
    let public = hex::encode(key.verifying_key().to_bytes());
    let request = service.request_pairing("introduction reader", &public).unwrap();
    let challenge = std::fs::read(service.dir().join(format!("challenge-{}", request.pair_id))).unwrap();
    let proof = key.sign(&PairingService::proof_message(&request.pair_id, &public, &challenge));
    let client = service.confirm_pairing(&request.pair_id, &hex::encode(proof.to_bytes()),
        vec![auth::Scope::Read, auth::Scope::Receive]).unwrap();
    let token = auth::create_paired_token(&base.identity.node_id().to_hex(), &base.jwt_secret,
        client.scopes, &client.client_id, client.epoch, &service.bound_fingerprint()).unwrap();
    let state = Arc::new(AppState { pairing: Some(service), ..(*base).clone() });
    let card = stranger_card("127.0.0.1:9735", "regtest", now());
    let (status, body, _) = call(&state, "POST", "/api/v1/introduction/verify",
        format!("Bearer {token}"), Some(json!({"card": card.to_link()}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(transport.connects.lock().unwrap().is_empty());
    let (status, body, _) = call(&state, "POST", "/api/v1/introduction/open",
        format!("Bearer {token}"), Some(json!({"card": card.to_link(), "allow_local": true}))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(transport.connects.lock().unwrap().len(), 1);
    assert!(transport.whitelisted.lock().unwrap().is_empty());
    assert!(state.storage.list_peers().await.unwrap().is_empty());
}
