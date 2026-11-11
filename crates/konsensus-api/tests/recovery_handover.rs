//! Application sends during recovery use real session managers on both sides.
mod common;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_core::{payloads::call as rules, NodeIdentity};
use konsensus_crypto::{ratchet_message_from_bytes, SessionManager};
use konsensus_storage::{SqliteStorage, Storage};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

const CALL: &str = "0123456789abcdef0123456789abcdef";

async fn compose(
    state: &Arc<konsensus_api::state::AppState>,
    peer: konsensus_core::NodeId,
    kind: u16,
    transport: &ConnectedStubTransport,
) -> (StatusCode, Value) {
    let plaintext = if kind == 404 {
        json!({"call_id":CALL,"seq":0}).to_string()
    } else {
        "first recovery message".into()
    };
    let response = test_router(state.clone()).oneshot(Request::builder()
        .method("POST").uri("/api/v1/messages/compose")
        .header("authorization", auth_header(state)).header("content-type", "application/json")
        .body(Body::from(json!({"operation_id":uuid::Uuid::new_v4().to_string(),"recipient":peer.to_hex(),"kind":kind,
            "plaintext":plaintext,"max_total_msat":2000,"max_routing_fee_msat":1000,"wait_ack_ms":0}).to_string())).unwrap());
    let quote = async {
        loop {
            let queried = transport.raw_frames.lock().unwrap().iter().any(|bytes| {
                matches!(
                    konsensus_message::wire::Frame::from_bytes(bytes).unwrap(),
                    konsensus_message::wire::Frame::PriceQuery { kind: 404 }
                )
            });
            if queried {
                state
                    .peer_prices
                    .update_kind_price(peer, 404, 1000, 850_000)
                    .await;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    };
    let response = if kind == 404 {
        tokio::select! { result = response => result.unwrap(), _ = quote => unreachable!() }
    } else {
        response.await.unwrap()
    };
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 100_000)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn recovery(stored: bool) {
    let lightning = Arc::new(CountingLightning::default());
    let mut state = test_state_with_lightning(lightning.clone());
    let bid = *state.identity.node_id();
    let aid = loop {
        let (_, identity) = NodeIdentity::generate().unwrap();
        if identity.node_id().as_bytes() < bid.as_bytes() {
            break Arc::new(identity);
        }
    };
    let a_id = *aid.node_id();
    let a = if stored {
        SessionManager::with_store(aid, Arc::new(FlakySessionStore::default()))
    } else {
        SessionManager::new(aid)
    };
    let b = Arc::new(if stored {
        SessionManager::with_store(
            state.identity.clone(),
            Arc::new(FlakySessionStore::default()),
        )
    } else {
        SessionManager::new(state.identity.clone())
    });
    let transport = Arc::new(ConnectedStubTransport::new(
        vec![a_id],
        state.invoice_requests.clone(),
    ));
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let now = chrono::Utc::now().timestamp_millis() as u64;
    let call = rules::receive(
        Some(
            rules::commit(
                rules::reserve(None, 400, "offer", "hash", now).unwrap(),
                "offer",
                now,
            )
            .unwrap(),
        ),
        401,
        None,
        now,
    )
    .unwrap();
    db.call_put(&a_id, CALL, &call).await.unwrap();
    let inner = Arc::get_mut(&mut state).unwrap();
    inner.storage = db;
    inner.session_manager = b.clone();
    inner.transport = transport.clone();
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(a_id, "02aaaa".repeat(5));
    // The test drives X3DH and acknowledgement explicitly; no scheduler or sleep
    // decides which side has switched.
    let init = a
        .initiate_session(&bid, &b.prekey_bundle().await)
        .await
        .unwrap();
    b.accept_session(&a_id, &init).await.unwrap();
    assert!(a.confirm_session(&bid).await);
    b.decrypt(&a_id, &a.encrypt(&bid, b"ratchet-init").await.unwrap())
        .await
        .unwrap();
    a.decrypt(&bid, &b.encrypt(&a_id, b"reply").await.unwrap())
        .await
        .unwrap();
    assert!(a.remove_session(&bid).await);
    let init = a
        .reinitiate_session(&bid, &b.prekey_bundle().await)
        .await
        .unwrap();
    b.reaccept_session(&a_id, &init).await.unwrap();
    for confirmed in [false, true] {
        if confirmed {
            assert!(a.confirm_session(&bid).await);
        }
        // Repeated attempts with no Ack model its loss. Confirmation alone must
        // not permit B to send while A's RatchetInit is still outstanding.
        for _ in 0..2 {
            for kind in [0, 404] {
                let (status, body) = compose(&state, a_id, kind, &transport).await;
                assert_eq!(
                    lightning.money(),
                    0,
                    "stored={stored}, confirmed={confirmed}, kind={kind}: {body}"
                );
                assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
                assert_eq!(body["code"], "not_dispatched", "{body}");
                assert_eq!(body["reason"], "session_handover", "{body}");
                assert_eq!(body["retry_allowed"], true, "{body}");
                assert_eq!(body["state"], "released", "{body}");
            }
        }
    }
    assert_eq!(lightning.invoices(), 0);
    assert!(transport.sent_envelopes.lock().unwrap().is_empty());
    assert!(!transport
        .raw_frames
        .lock()
        .unwrap()
        .iter()
        .any(|bytes| matches!(
            konsensus_message::wire::Frame::from_bytes(bytes).unwrap(),
            konsensus_message::wire::Frame::RequestInvoice { .. }
        )));
    b.decrypt(&a_id, &a.encrypt(&bid, b"ratchet-init").await.unwrap())
        .await
        .unwrap();
    let (status, body) = compose(&state, a_id, 0, &transport).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(lightning.money(), 1, "one send after handover");
    let envelopes = transport.sent_envelopes.lock().unwrap().clone();
    assert_eq!(envelopes.len(), 1);
    assert_eq!(
        a.decrypt(
            &bid,
            &ratchet_message_from_bytes(&envelopes[0].1.ciphertext).unwrap()
        )
        .await
        .unwrap(),
        b"first recovery message"
    );
}

#[tokio::test]
async fn first_send_during_recovery_without_store() {
    recovery(false).await;
}
#[tokio::test]
async fn first_send_during_recovery_with_store() {
    recovery(true).await;
}
