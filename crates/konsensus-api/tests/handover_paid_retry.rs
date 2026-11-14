mod common;

use axum::{body::Body, http::{Request, StatusCode}};
use common::*;
use konsensus_core::{NodeIdentity, kind::KIND_CHAT};
use konsensus_crypto::{PlaintextCacheCipher, SessionManager, ratchet_message_from_bytes};
use konsensus_storage::{SqliteStorage, Storage};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

async fn compose(state: &Arc<konsensus_api::state::AppState>, peer: konsensus_core::NodeId, operation: &str, plaintext: &str) -> (StatusCode, Value) {
    let response = test_router(state.clone()).oneshot(Request::builder()
        .method("POST").uri("/api/v1/messages/compose")
        .header("authorization", auth_header(state)).header("content-type", "application/json")
        .body(Body::from(json!({"operation_id": operation, "recipient": peer.to_hex(), "kind": KIND_CHAT,
            "plaintext": plaintext, "max_total_msat": 2000, "max_routing_fee_msat": 1000, "wait_ack_ms": 0}).to_string())).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 100_000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn retry_after_loss(stored: bool, cache: bool) {
    let lightning = Arc::new(CountingLightning::default());
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let mut state = test_state_with_lightning_and_storage(lightning.clone(), db.clone());
    let bid = *state.identity.node_id();
    let aid = loop {
        let (_, identity) = NodeIdentity::generate().unwrap();
        if identity.node_id().as_bytes() < bid.as_bytes() { break Arc::new(identity); }
    };
    let a_id = *aid.node_id();
    let a = if stored { SessionManager::with_store(aid, Arc::new(FlakySessionStore::default())) } else { SessionManager::new(aid) };
    let b = Arc::new(if stored { SessionManager::with_store(state.identity.clone(), Arc::new(FlakySessionStore::default())) } else { SessionManager::new(state.identity.clone()) });
    let transport = Arc::new(ConnectedStubTransport::new(vec![a_id], state.invoice_requests.clone()));
    let inner = Arc::get_mut(&mut state).unwrap();
    inner.session_manager = b.clone();
    inner.transport = transport.clone();
    inner.plaintext_cipher = cache.then(|| Arc::new(PlaintextCacheCipher::new(&[7; 32])));
    state.peer_ln_pubkeys.lock().await.insert(a_id, konsensus_api::state::PeerLightningKey::Verified("02aaaa".repeat(5)));

    let init = a.initiate_session(&bid, &b.prekey_bundle().await).await.unwrap();
    b.accept_session(&a_id, &init).await.unwrap();
    a.confirm_session(&bid).await;
    b.decrypt(&a_id, &a.encrypt(&bid, b"ratchet-init").await.unwrap()).await.unwrap();
    let operation = uuid::Uuid::new_v4().to_string();
    let (status, first_response) = compose(&state, a_id, &operation, "paid recovery message").await;
    assert_eq!(status, StatusCode::OK, "{first_response}");
    assert_eq!(lightning.money(), 1);
    let old = transport.sent_envelopes.lock().unwrap()[0].1.clone();
    assert!(a.remove_session(&bid).await);
    let init = a.reinitiate_session(&bid, &b.prekey_bundle().await).await.unwrap();
    b.reaccept_session(&a_id, &init).await.unwrap();
    // The recipient's pre-acceptance deferral is authenticated by the ordinary
    // delivery-confirmation handler; record the resulting durable state here.
    assert!(db.reject_pending(&old.id, &a_id, &bid, "session_handover: session recovering", false).await.unwrap());
    let deferred = db.get_outbox_operation(&operation).await.unwrap().unwrap();
    for _ in 0..2 {
        let (status, body) = compose(&state, a_id, &operation, "paid recovery message").await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["reason"], "session_handover", "{body}");
        assert_eq!(body["state"], "rejected_retryable", "{body}");
        assert_eq!(body["retry_allowed"], true, "{body}");
        assert_eq!(db.get_outbox_operation(&operation).await.unwrap().unwrap(), deferred);
        assert_eq!(lightning.money(), 1);
        assert_eq!(transport.sent_envelopes.lock().unwrap().len(), 1);
    }
    // A different request cannot use the existing payment or mutate its row.
    let (status, _) = compose(&state, a_id, &operation, "different message").await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(db.get_outbox_operation(&operation).await.unwrap().unwrap(), deferred);

    a.confirm_session(&bid).await;
    b.decrypt(&a_id, &a.encrypt(&bid, b"ratchet-init").await.unwrap()).await.unwrap();
    let (status, body) = compose(&state, a_id, &operation, "paid recovery message").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(lightning.money(), 1, "retry must reuse the first payment");
    let sent = transport.sent_envelopes.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    let replacement = &sent[1].1;
    assert_ne!(replacement.id, old.id);
    assert_eq!(replacement.payment_proof, old.payment_proof);
    assert_eq!(a.decrypt(&bid, &ratchet_message_from_bytes(&replacement.ciphertext).unwrap()).await.unwrap(), b"paid recovery message");
    assert_eq!(db.count_pending_deliveries().await.unwrap(), 1);
    assert!(db.get_message(&old.id).await.unwrap().is_none());
    assert!(!db.acknowledge_pending(&old.id, &a_id, &bid).await.unwrap());
    if let Some(cipher) = &state.plaintext_cipher {
        let cached = db.get_message_plaintext(&replacement.id).await.unwrap().unwrap();
        assert_eq!(cipher.decrypt(&replacement.id.to_hex(), &cached).unwrap(), b"paid recovery message");
    }
    assert!(db.acknowledge_pending(&replacement.id, &a_id, &bid).await.unwrap());
    let (status, body) = compose(&state, a_id, &operation, "paid recovery message").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], true);
    assert_eq!(lightning.money(), 1);
    assert_eq!(transport.sent_envelopes.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn paid_handover_retry_without_session_store() { retry_after_loss(false, true).await; }

#[tokio::test]
async fn paid_handover_retry_with_session_store() { retry_after_loss(true, true).await; }

#[tokio::test]
async fn paid_handover_retry_without_plaintext_cache() { retry_after_loss(true, false).await; }
