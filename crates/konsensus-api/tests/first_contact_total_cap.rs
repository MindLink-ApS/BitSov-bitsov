//! A payment to a peer without an open session needs a stated total cap, for
//! the owner's own key as well as for paired devices. Without one, nothing is
//! requested or paid; a cap of 0 is a cap ("pay nothing new").
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_api::{auth, state::InvoiceResponseData};
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_lightning::shared_mock::SharedMockProvider;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;

/// One owner compose to a connected peer with no session. Returns status, body,
/// the invoice requests the peer saw and the msat the owner spent.
async fn owner_compose(kind: u16, plaintext: &str, cap: Option<u64>) -> (StatusCode, serde_json::Value, usize, u64) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.db");
    let payer = Arc::new(SharedMockProvider::new(&path, "a", 100_000).unwrap());
    let payee = Arc::new(SharedMockProvider::new(&path, "b", 0).unwrap());
    let mut state = common::test_state_with_lightning(payer.clone());
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let requests = Arc::new(AtomicUsize::new(0));
    let counted = requests.clone();
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone()).with_invoice_responder(
            move |request_id, _| {
                counted.fetch_add(1, Ordering::SeqCst);
                let invoice = futures::executor::block_on(
                    payee.create_invoice(2000, &format!("konsensus:{request_id}:message=2000"), 55),
                )
                .unwrap();
                Some(InvoiceResponseData { recipient: peer, bolt11: invoice.bolt11, payment_hash: invoice.payment_hash })
            },
        ),
    );
    let token = auth::create_token(&state.identity.node_id().to_hex(), &state.jwt_secret, auth::Scope::all()).unwrap();
    let mut body = serde_json::json!({"recipient": peer.to_hex(), "kind": kind, "plaintext": plaintext});
    if let Some(cap) = cap {
        body["max_total_msat"] = cap.into();
    }
    let response = common::test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/messages/compose")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 16_384).await.unwrap();
    let spent = 100_000 - payer.get_balance_msat().await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default(), requests.load(Ordering::SeqCst), spent)
}

#[tokio::test]
async fn owner_first_contact_without_cap_is_refused_before_any_invoice() {
    let (status, body, requests, spent) = owner_compose(0, "hello stranger", None).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "price_cap_exceeded", "{body}");
    assert_eq!(body["reason"], "total_cap_required", "{body}");
    assert!(body["error"].as_str().unwrap().contains("max_total_msat"), "{body}");
    assert_eq!(requests, 0, "no invoice was requested");
    assert_eq!(spent, 0, "nothing was paid");
}

#[tokio::test]
async fn owner_first_contact_zero_cap_pays_nothing() {
    // 0 is a stated cap ("pay nothing new"): it passes the presence check and
    // is then too small for any admission, so nothing is paid.
    let (status, body, _, spent) = owner_compose(0, "hello stranger", Some(0)).await;
    assert_ne!(body["reason"], "total_cap_required", "{body}");
    assert!(!status.is_success(), "{body}");
    assert_eq!(spent, 0, "nothing was paid");
}

#[tokio::test]
async fn owner_call_offer_to_a_stranger_pays_nothing() {
    // Calls go only to contacts, so an uncapped call offer never reaches a
    // first-contact payment either way.
    let offer = serde_json::json!({"v": 1, "call_id": "0123456789abcdef0123456789abcdef", "media": "audio", "sdp": "v=0 offer"});
    let (status, body, requests, spent) =
        owner_compose(konsensus_core::kind::KIND_CALL_INVITE, &offer.to_string(), None).await;
    assert!(!status.is_success(), "{body}");
    assert_eq!(requests, 0, "no invoice was requested");
    assert_eq!(spent, 0, "nothing was paid");
}
