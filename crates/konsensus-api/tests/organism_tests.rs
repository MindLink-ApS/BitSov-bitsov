//! N1 `GET /api/v1/energy` and N2 `GET /api/v1/membrane` + outbound membrane
//! events: shape, read scope, bounds, and no secret on the wire.
#![allow(dead_code)]
mod common;
use common::*;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tower::ServiceExt;

use konsensus_api::auth;
use konsensus_api::state::AppState;
use konsensus_core::gate::GateRejection;
use konsensus_core::types::{NodeId, Recipient};
use konsensus_core::{PaymentProof, UkmEnvelope, UkmEnvelopeBuilder};

const PREIMAGE: [u8; 32] = [0x5C; 32];

fn envelope(sender: NodeId, recipient: Recipient, amount_msat: u64, age_ms: u64) -> UkmEnvelope {
    let hash: [u8; 32] = Sha256::digest(PREIMAGE).into();
    let now = u64::try_from(chrono::Utc::now().timestamp_millis()).unwrap();
    UkmEnvelopeBuilder::new(
        100,
        sender,
        recipient,
        format!("SEALED-{amount_msat}-{age_ms}").into_bytes(),
        PaymentProof::new(hash, PREIMAGE, amount_msat),
    )
    .timestamp(now - age_ms)
    .build()
}

async fn get(state: &Arc<AppState>, path: &str, bearer: Option<String>) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .uri(path)
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
        ));
    if let Some(b) = bearer {
        req = req.header("authorization", b);
    }
    let response = test_router(state.clone())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1_000_000)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) })),
    )
}

fn bearer_with(state: &AppState, scopes: Vec<auth::Scope>) -> String {
    let service = state.pairing.as_ref().unwrap();
    let client = &service.list_clients()[0];
    let token = auth::create_paired_token(
        &state.identity.node_id().to_hex(),
        &state.jwt_secret,
        scopes,
        &client.client_id,
        client.epoch,
        &service.bound_fingerprint(),
    )
    .unwrap();
    format!("Bearer {token}")
}

// ── N1 energy ───────────────────────────────────────────────────────────

#[tokio::test]
async fn energy_sums_the_nodes_own_paid_messages_per_counterparty() {
    let (_tmp, state) = paired_state();
    let me = *state.identity.node_id();
    let maya = NodeId::from_bytes([0x33; 32]);
    let josh = NodeId::from_bytes([0x44; 32]);
    for env in [
        envelope(maya, Recipient::Node(me), 20_000, 60_000),
        envelope(maya, Recipient::Node(me), 20_000, 120_000),
        envelope(me, Recipient::Node(maya), 5_000, 180_000),
        envelope(me, Recipient::Node(josh), 7_000, 3 * 3_600_000),
        envelope(josh, Recipient::Node(me), 1_000, 3 * 86_400_000), // outside 24h
    ] {
        state.storage.store_message(&env).await.unwrap();
    }

    let (status, body) = get(
        &state,
        "/api/v1/energy?window=24h",
        Some(bearer_with(&state, vec![auth::Scope::Read])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["window"], "24h");
    assert_eq!(body["bucket_ms"], 3_600_000);
    assert_eq!(
        body["totals"],
        json!({ "in_msat": 40_000, "out_msat": 12_000, "in_count": 2, "out_count": 2 })
    );
    let first = &body["counterparties"][0];
    assert_eq!(first["counterparty"], maya.to_hex());
    assert_eq!(
        (first["in_msat"].as_u64(), first["out_msat"].as_u64()),
        (Some(40_000), Some(5_000))
    );
    assert!(body["buckets"].as_array().unwrap().len() <= 24);
    assert_eq!(body["truncated"], false);

    let (_, week) = get(
        &state,
        "/api/v1/energy?window=7d",
        Some(bearer_with(&state, vec![auth::Scope::Read])),
    )
    .await;
    assert_eq!(
        week["totals"]["in_msat"], 41_000,
        "7d includes the older receipt"
    );

    let (_, hour) = get(
        &state,
        "/api/v1/energy?window=1h",
        Some(bearer_with(&state, vec![auth::Scope::Read])),
    )
    .await;
    assert_eq!(hour["totals"]["out_msat"], 5_000);
}

#[tokio::test]
async fn energy_response_carries_no_payment_secret_or_payload() {
    let (_tmp, state) = paired_state();
    let me = *state.identity.node_id();
    let env = envelope(
        NodeId::from_bytes([0x33; 32]),
        Recipient::Node(me),
        20_000,
        1_000,
    );
    state.storage.store_message(&env).await.unwrap();
    let (_, body) = get(
        &state,
        "/api/v1/energy",
        Some(bearer_with(&state, vec![auth::Scope::Read])),
    )
    .await;
    let text = body.to_string();
    for secret in [
        hex::encode(PREIMAGE),
        hex::encode(env.payment_proof.payment_hash),
        hex::encode(&env.ciphertext),
        "SEALED".to_string(),
        env.id.to_hex(),
    ] {
        assert!(!text.contains(&secret), "energy leaked {secret}: {text}");
    }
}

#[tokio::test]
async fn energy_rejects_unknown_window() {
    let (_tmp, state) = paired_state();
    let (status, _) = get(
        &state,
        "/api/v1/energy?window=30d",
        Some(bearer_with(&state, vec![auth::Scope::Read])),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn energy_and_membrane_demand_read_scope() {
    let (_tmp, state) = paired_state();
    for path in ["/api/v1/energy", "/api/v1/membrane"] {
        let (anon, _) = get(&state, path, None).await;
        assert_eq!(anon, StatusCode::UNAUTHORIZED, "{path} without a token");
        let (no_read, _) = get(
            &state,
            path,
            Some(bearer_with(&state, vec![auth::Scope::Receive])),
        )
        .await;
        assert_eq!(no_read, StatusCode::FORBIDDEN, "{path} without read scope");
        let (read, body) = get(
            &state,
            path,
            Some(bearer_with(&state, vec![auth::Scope::Read])),
        )
        .await;
        assert_eq!(read, StatusCode::OK, "{path} with read scope: {body}");
    }
}

// ── N2 membrane ─────────────────────────────────────────────────────────

#[tokio::test]
async fn membrane_reads_the_bounded_ring_newest_first() {
    let (_tmp, state) = paired_state();
    let me = *state.identity.node_id();
    let stranger = NodeId::from_bytes([0x77; 32]);
    let env = envelope(stranger, Recipient::Node(me), 0, 1_000);
    let log = state.audit_log.membrane();
    for _ in 0..(konsensus_api::membrane::MEMBRANE_CAPACITY + 25) {
        log.refused(
            &env,
            &GateRejection::InsufficientPayment {
                required_msat: 20_000,
                paid_msat: 0,
            },
        );
    }
    let paid = envelope(stranger, Recipient::Node(me), 20_000, 1_000);
    log.admitted(&paid, true);

    let (status, body) = get(
        &state,
        "/api/v1/membrane?limit=100000",
        Some(bearer_with(&state, vec![auth::Scope::Read])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = body["events"].as_array().unwrap();
    assert_eq!(
        events.len(),
        konsensus_api::membrane::MEMBRANE_CAPACITY,
        "never more than the ring holds"
    );
    assert_eq!(body["capacity"], konsensus_api::membrane::MEMBRANE_CAPACITY);
    assert_eq!(
        body["totals"]["refused"],
        konsensus_api::membrane::MEMBRANE_CAPACITY + 25
    );
    assert_eq!(body["totals"]["first_contacts"], 1);

    let newest = &events[0];
    assert_eq!(newest["verdict"], "admitted");
    assert_eq!(newest["first_contact"], true);
    assert_eq!(newest["counterparty"], stranger.to_hex());
    let refusal = &events[1];
    assert_eq!(refusal["code"], "unpaid");
    assert_eq!(refusal["required_msat"], 20_000);

    let (_, two) = get(
        &state,
        "/api/v1/membrane?limit=2",
        Some(bearer_with(&state, vec![auth::Scope::Read])),
    )
    .await;
    assert_eq!(two["events"].as_array().unwrap().len(), 2);

    let text = body.to_string();
    for secret in [
        hex::encode(PREIMAGE),
        hex::encode(paid.payment_proof.payment_hash),
        "SEALED".to_string(),
    ] {
        assert!(!text.contains(&secret), "membrane leaked {secret}");
    }
}

#[tokio::test]
async fn unverified_refusal_names_no_one_over_http() {
    let (_tmp, state) = paired_state();
    let me = *state.identity.node_id();
    let claimed = NodeId::from_bytes([0x99; 32]);
    let env = envelope(claimed, Recipient::Node(me), 20_000, 1_000);
    state
        .audit_log
        .membrane()
        .refused(&env, &GateRejection::InvalidSignature("forged".into()));
    let (_, body) = get(
        &state,
        "/api/v1/membrane",
        Some(bearer_with(&state, vec![auth::Scope::Read])),
    )
    .await;
    assert_eq!(body["events"][0]["code"], "bad_signature");
    assert!(body["events"][0].get("counterparty").is_none());
    assert!(!body.to_string().contains(&claimed.to_hex()));
}

#[tokio::test]
async fn capped_send_refusal_is_an_outbound_membrane_event() {
    let lightning = Arc::new(CountingLightning::default());
    let mut state = test_state_with_lightning(lightning.clone());
    let peer = setup_e2ee_session(&state.session_manager).await;
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(ConnectedStubTransport::new(
        vec![peer],
        state.invoice_requests.clone(),
    ));
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(peer, "02aaaa".repeat(5));
    let mut rx = state.audit_log.membrane().subscribe();

    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/messages/compose")
                .header("authorization", auth_header(&state))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "recipient": peer.to_hex(), "kind": 100, "plaintext": "private words", "max_total_msat": 999 })
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(lightning.money(), 0);

    let event = rx.try_recv().expect("an outbound membrane event");
    let v = serde_json::to_value(event.as_ref()).unwrap();
    assert_eq!(v["type"], "membrane");
    assert_eq!(v["direction"], "outbound");
    assert_eq!(v["code"], "price_cap_exceeded");
    assert_eq!(v["cap_msat"], 999);
    assert_eq!(v["counterparty"], peer.to_hex());
    assert!(
        !v.to_string().contains("private words"),
        "plaintext never enters the membrane"
    );

    // A request that fails for an ordinary reason is not a membrane decision.
    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/messages/compose")
                .header("authorization", auth_header(&state))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "recipient": peer.to_hex(), "kind": 100, "plaintext": "" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn status_advertises_energy_and_membrane() {
    let (_tmp, state) = paired_state();
    let (status, body) = get(
        &state,
        "/api/v1/status",
        Some(bearer_with(&state, vec![auth::Scope::Read])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let caps = body["api_capabilities"].as_array().unwrap();
    assert!(caps.contains(&json!("energy_v1")), "{caps:?}");
    assert!(caps.contains(&json!("membrane_v1")), "{caps:?}");
    assert!(caps.contains(&json!("spend_budget_grant_v1")), "{caps:?}");
}

fn paired_state() -> (tempfile::TempDir, Arc<AppState>) {
    use ed25519_dalek::{Signer, SigningKey};
    use konsensus_api::pairing::{self, PairingService};
    let tmp = tempfile::tempdir().unwrap();
    let base = test_state();
    let service = Arc::new(
        PairingService::open(
            tmp.path(),
            pairing::identity_fingerprint(&base.identity.node_id().to_hex()),
            false,
        )
        .unwrap()
        .without_stdout_code(),
    );
    let key = SigningKey::from_bytes(&[71; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    let request = service.request_pairing("test", &pubkey).unwrap();
    let challenge =
        std::fs::read(service.dir().join(format!("challenge-{}", request.pair_id))).unwrap();
    let signature = hex::encode(
        key.sign(&PairingService::proof_message(
            &request.pair_id,
            &pubkey,
            &challenge,
        ))
        .to_bytes(),
    );
    service
        .confirm_pairing(
            &request.pair_id,
            &signature,
            pairing::default_pairing_scopes(),
        )
        .unwrap();
    (
        tmp,
        Arc::new(AppState {
            pairing: Some(service),
            ..(*base).clone()
        }),
    )
}

#[tokio::test]
async fn organism_requires_loopback_current_pairing_and_read() {
    let (_tmp, state) = paired_state();
    let paired = bearer_with(&state, vec![auth::Scope::Read]);
    for path in ["/api/v1/energy", "/api/v1/membrane"] {
        for peer in [None, Some("203.0.113.7:1234"), Some("[2001:db8::1]:1234")] {
            let mut req = Request::builder()
                .uri(path)
                .header("authorization", &paired)
                .header("x-forwarded-for", "127.0.0.1");
            if let Some(addr) = peer {
                req = req.extension(axum::extract::ConnectInfo(
                    addr.parse::<std::net::SocketAddr>().unwrap(),
                ));
            }
            let response = test_router(state.clone())
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{path} {peer:?}");
        }
        assert_eq!(
            get(&state, path, Some(auth_header(&state))).await.0,
            StatusCode::FORBIDDEN,
            "unpaired owner"
        );
        for addr in ["127.0.0.1:1234", "[::1]:1234"] {
            let response = test_router(state.clone())
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .extension(axum::extract::ConnectInfo(
                            addr.parse::<std::net::SocketAddr>().unwrap(),
                        ))
                        .header("authorization", &paired)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }
    let service = state.pairing.as_ref().unwrap();
    service
        .revoke(&service.list_clients()[0].client_id)
        .unwrap();
    for path in ["/api/v1/energy", "/api/v1/membrane"] {
        assert_eq!(
            get(&state, path, Some(paired.clone())).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
}

#[tokio::test]
async fn cap_refusal_never_retains_unvalidated_text() {
    let state = test_state();
    for recipient in [
        "PRIVATE PLAINTEXT lnbc1invoice".to_string(),
        "X".repeat(100_000),
    ] {
        let response = test_router(state.clone()).oneshot(Request::builder().method("POST").uri("/api/v1/messages")
            .header("authorization", auth_header(&state)).header("content-type", "application/json")
            .body(Body::from(json!({"recipient":recipient,"kind":100,"ciphertext":"","payment_hash":"","preimage":"","amount_msat":1000,"max_total_msat":0}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let events = state.audit_log.membrane().read(None, 500).0;
        assert!(events[0].counterparty.is_none());
        assert!(serde_json::to_vec(events[0].as_ref()).unwrap().len() < 1024);
    }
}

#[tokio::test]
async fn file_cap_refusal_emits_one_event_without_payment() {
    let lightning = Arc::new(CountingLightning::default());
    let state = test_state_with_lightning(lightning.clone());
    let peer = NodeId::from_bytes([0x33; 32]);
    let file = konsensus_storage::FileRecord {
        id: "test-file".into(),
        filename: "hi.txt".into(),
        mime_type: "text/plain".into(),
        size_bytes: 2,
        blake3_hash: "unused".into(),
        sender: state.identity.node_id().to_hex(),
        message_id: None,
        data: vec![],
        created_at: "test".into(),
    };
    state.storage.store_file(&file).await.unwrap();
    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/files/test-file/send")
                .header("authorization", auth_header(&state))
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"recipient":peer.to_hex(),"max_total_msat":0}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let (events, totals) = state.audit_log.membrane().read(None, 500);
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].code,
        konsensus_api::membrane::Code::PriceCapExceeded
    );
    assert_eq!(
        events[0].counterparty.as_deref(),
        Some(peer.to_hex().as_str())
    );
    assert_eq!(totals.outbound_refused, 1);
    assert_eq!((lightning.money(), lightning.invoices()), (0, 0));
}

#[test]
fn energy_excludes_future_rows() {
    use konsensus_api::handlers::organism::{aggregate, Window};
    let now = 86_400_000;
    let rows = [konsensus_storage::EnergyRow {
        sender: "bb".into(),
        recipient_type: "node".into(),
        recipient_id: "aa".into(),
        timestamp_ms: now + 300_000,
        amount_msat: 1000,
    }];
    assert_eq!(
        aggregate(&rows, "aa", Window::Hour, now, false)
            .totals
            .in_msat,
        0
    );
}
