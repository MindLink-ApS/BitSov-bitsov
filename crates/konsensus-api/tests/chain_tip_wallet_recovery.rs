//! Established free sends need no chain tip or wallet payment. Positive prices
//! need an observation shared through payment preparation and refreshed after
//! waits; never pay a peer's price checked only against height zero.
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::{body::Body, http::Request, response::IntoResponse};
use konsensus_api::state::AppState;
use konsensus_core::traits::chain::ChainProvider;
use konsensus_core::traits::lightning::*;
use konsensus_storage::models::Room;
use tower::ServiceExt;

/// Not money-ready on the first poll, ready on every later one.
#[derive(Default)]
struct RecoveringWallet {
    polls: AtomicUsize,
    remain_unready: bool,
    inner: common::CountingLightning,
}

#[async_trait]
impl LightningProvider for RecoveringWallet {
    async fn pay_invoice_with_fee_limit(&self, invoice: &str, cap: u64) -> Result<PaymentDetails, LightningError> {
        self.inner.pay_invoice_with_fee_limit(invoice, cap).await
    }
    async fn money_ready(&self) -> bool {
        let recovered = self.polls.fetch_add(1, Ordering::SeqCst) != 0;
        recovered && !self.remain_unready
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn create_invoice(&self, amount: u64, description: &str, expiry: u32) -> Result<Invoice, LightningError> {
        self.inner.create_invoice(amount, description, expiry).await
    }
    async fn pay_invoice(&self, invoice: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.pay_invoice(invoice).await
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.get_payment_status(hash).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.inner.get_balance_msat().await
    }
    async fn keysend_with_fee_limit(&self, dest: &str, amount: u64, memo: Option<&str>, cap: u64) -> Result<PaymentDetails, LightningError> {
        self.inner.keysend_with_fee_limit(dest, amount, memo, cap).await
    }
}

async fn send(is_room: bool, chain: Arc<dyn ChainProvider>, peer_price: u64) -> (Arc<RecoveringWallet>, u16, serde_json::Value) {
    send_with_wallet(is_room, chain, peer_price, Arc::new(RecoveringWallet::default())).await
}

async fn send_with_wallet(is_room: bool, chain: Arc<dyn ChainProvider>, peer_price: u64, wallet: Arc<RecoveringWallet>) -> (Arc<RecoveringWallet>, u16, serde_json::Value) {
    let base = common::test_state_with_lightning(wallet.clone());
    let peer = common::setup_e2ee_session_with_mnemonic(
        &base.session_manager,
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    )
    .await;
    let transport = Arc::new(common::ConnectedStubTransport::new(vec![peer], base.invoice_requests.clone()));
    let pricing = if peer_price == 0 { Arc::new(FreePricing) as Arc<dyn konsensus_core::traits::pricing::PricingEngine> } else { base.pricing.clone() };
    let state = Arc::new(AppState { transport, chain, pricing, ..(*base).clone() });
    state.peer_ln_pubkeys.lock().await.insert(peer, "02aaaa".repeat(5));
    // Valid for one block from height 1: expired by any real tip, still
    // within its wall-clock age, and "valid" against height 0.
    if peer_price > 0 {
        state.peer_prices.update(peer, std::collections::HashMap::from([("communication".to_string(), peer_price)]), 1, 1, 0.0).await;
    }
    let recipient = if is_room {
        let room = Room::new("recovering wallet".into(), *state.identity.node_id());
        state.storage.create_room(&room).await.unwrap();
        state.storage.add_room_member(&room.id, &peer).await.unwrap();
        room.id.to_string()
    } else {
        peer.to_hex()
    };
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&state))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": recipient, "is_room": is_room, "kind": 1,
                "plaintext": "wallet recovery", "wait_ack_ms": 0,
            })
            .to_string(),
        ))
        .unwrap();
    let response = common::test_router(state).oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 65_536).await.unwrap();
    (wallet, status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn a_wallet_that_becomes_ready_mid_send_still_needs_a_chain_tip() {
    for is_room in [false, true] {
        let chain = Arc::new(common::TipDownChain::down());
        let (wallet, status, body) = send(is_room, chain.clone(), 2_000).await;
        common::assert_chain_not_ready(status, &body);
        assert!(wallet.polls.load(Ordering::SeqCst) >= 2, "room={is_room}: readiness changed mid-send");
        assert_eq!(chain.reads(), 1, "room={is_room}: the price to pay asked for a tip");
        assert_eq!(wallet.inner.money(), 0, "room={is_room}: nothing paid");
        assert_eq!(wallet.inner.invoices(), 0);
    }
}

#[tokio::test]
async fn an_established_paid_chat_refuses_without_a_tip() {
    for is_room in [false, true] {
        let wallet = Arc::new(RecoveringWallet { polls: AtomicUsize::new(1), ..Default::default() });
        let chain = Arc::new(common::TipDownChain::down());
        let (wallet, status, body) = send_with_wallet(is_room, chain.clone(), 2_000, wallet).await;
        common::assert_chain_not_ready(status, &body);
        assert_eq!(chain.reads(), 1);
        assert_eq!(wallet.inner.money(), 0);
        assert_eq!(wallet.inner.invoices(), 0);
    }
}

#[tokio::test]
async fn with_a_tip_the_expired_peer_table_is_not_paid() {
    for is_room in [false, true] {
        let chain = Arc::new(common::TipDownChain::after(usize::MAX));
        let (wallet, _, body) = send(is_room, chain.clone(), 2_000).await;
        // The quote and payment share one observation.
        assert_eq!(chain.reads(), 1, "room={is_room}");
        // Re-quoted at the real tip, the peer's expired 2 000 msat table is
        // no longer its price.
        assert_ne!(body["amount_msat"], 2_000, "room={is_room}: {body}");
        if let Some(outcomes) = body["member_outcomes"].as_array() {
            assert!(outcomes.iter().all(|o| o["amount_msat"] != 2_000), "{body}");
        }
        let _ = wallet;
    }
}

/// Own price 0 for every kind.
struct FreePricing;

#[async_trait]
impl konsensus_core::traits::pricing::PricingEngine for FreePricing {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get_price_msat(&self, _: u16) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        Ok(0)
    }
    async fn get_category_price_msat(
        &self,
        _: konsensus_core::kind::KindCategory,
    ) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        Ok(0)
    }
}

/// The connected stub, plus: the peer's price table arrives while the paid
/// admission proof is being re-sent. Valid for one block from height 1.
struct AnsweringTransport {
    inner: Arc<common::ConnectedStubTransport>,
    prices: Arc<konsensus_pricing::PeerPriceCache>,
}

#[async_trait]
impl konsensus_core::traits::transport::MessageTransport for AnsweringTransport {
    async fn send(&self, peer: &konsensus_core::NodeId, envelope: &konsensus_core::UkmEnvelope) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.prices
            .update(*peer, std::collections::HashMap::from([("communication".to_string(), 2_000)]), 1, 1, 0.0)
            .await;
        self.inner.send(peer, envelope).await
    }
    async fn recv(&self) -> Result<konsensus_core::UkmEnvelope, konsensus_core::traits::transport::TransportError> {
        self.inner.recv().await
    }
    async fn connect(&self, peer: &konsensus_core::NodeId, addr: &str) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.connect(peer, addr).await
    }
    async fn disconnect(&self, peer: &konsensus_core::NodeId) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.disconnect(peer).await
    }
    async fn is_connected(&self, peer: &konsensus_core::NodeId) -> bool {
        self.inner.is_connected(peer).await
    }
    async fn connected_since(&self, peer: &konsensus_core::NodeId) -> Option<std::time::Instant> {
        self.inner.connected_since(peer).await
    }
    async fn connected_peers(&self) -> Vec<konsensus_core::NodeId> {
        self.inner.connected_peers().await
    }
    async fn send_raw_frame(&self, peer: &konsensus_core::NodeId, frame: &[u8]) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.send_raw_frame(peer, frame).await
    }
}

/// A send resuming an admission paid before (journaled, without the target's
/// quote) looks up the target's price for this message. The send began with
/// the wallet not money-ready, so it read no tip: the lookup reads one, and
/// without one it is refused, never checked against height 0 (which would
/// accept the table that arrived meanwhile, expired at any real tip).
#[tokio::test]
async fn a_resumed_admission_checks_the_target_price_against_a_real_tip() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Arc::new(RecoveringWallet::default());
    let base = common::test_state_with_data_dir(dir.path().to_path_buf());
    let peer = konsensus_core::NodeId::from_bytes([0x5a; 32]);
    let stub = Arc::new(common::ConnectedStubTransport::new(vec![peer], base.invoice_requests.clone()));
    let transport = Arc::new(AnsweringTransport { inner: stub.clone(), prices: base.peer_prices.clone() });
    let chain = Arc::new(common::TipDownChain::down());
    let state = Arc::new(AppState {
        lightning: wallet.clone(),
        transport,
        chain: chain.clone(),
        pricing: Arc::new(FreePricing),
        ..(*base).clone()
    });
    // The admission paid before: settled, its proof not yet sent, no quote kept.
    let envelope = konsensus_core::UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        *state.identity.node_id(),
        konsensus_core::Recipient::Node(peer),
        vec![],
        konsensus_core::PaymentProof::new([0x11; 32], [0x22; 32], 1_000),
    )
    .build();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let journal = dir.path().join("admission-attempts");
    std::fs::create_dir_all(&journal).unwrap();
    std::fs::write(
        journal.join(peer.to_hex()),
        serde_json::to_vec(&serde_json::json!({
            "dispatch_started": true, "payment_hash": "11".repeat(32), "amount_msat": 1_000,
            "quote": null, "envelope": envelope, "settled_at_unix": now, "proof_delivered": false,
        }))
        .unwrap(),
    )
    .unwrap();

    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&state))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"recipient": peer.to_hex(), "kind": konsensus_core::kind::KIND_CHAT, "plaintext": "resumed", "wait_ack_ms": 0}).to_string(),
        ))
        .unwrap();
    let response = common::test_router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 65_536).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    // A ready wallet checks the initial quote, even when its own price is
    // zero. The earlier admission journal is left for a later retry.
    common::assert_chain_not_ready(status, &body);
    assert!(stub.sent_envelopes.lock().unwrap().is_empty(), "{body}");
    assert!(journal.join(peer.to_hex()).exists());
    assert_eq!(chain.reads(), 1);
    assert_eq!(wallet.inner.money(), 0);
    assert_eq!(wallet.inner.invoices(), 0);
}

/// The connected stub, plus: a porch quote request is answered at once with a
/// 2 000 msat page price.
struct PorchTransport {
    inner: Arc<common::ConnectedStubTransport>,
    ours: konsensus_core::NodeId,
}

#[async_trait]
impl konsensus_core::traits::transport::MessageTransport for PorchTransport {
    async fn send(&self, p: &konsensus_core::NodeId, e: &konsensus_core::UkmEnvelope) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.send(p, e).await
    }
    async fn recv(&self) -> Result<konsensus_core::UkmEnvelope, konsensus_core::traits::transport::TransportError> {
        self.inner.recv().await
    }
    async fn connect(&self, p: &konsensus_core::NodeId, a: &str) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.connect(p, a).await
    }
    async fn disconnect(&self, p: &konsensus_core::NodeId) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.disconnect(p).await
    }
    async fn is_connected(&self, p: &konsensus_core::NodeId) -> bool {
        self.inner.is_connected(p).await
    }
    async fn connected_since(&self, p: &konsensus_core::NodeId) -> Option<std::time::Instant> {
        self.inner.connected_since(p).await
    }
    async fn connected_peers(&self) -> Vec<konsensus_core::NodeId> {
        self.inner.connected_peers().await
    }
    async fn peer_info(&self, p: &konsensus_core::NodeId) -> Option<konsensus_core::traits::ConnectedPeerInfo> {
        self.inner.peer_info(p).await
    }
    async fn send_raw_frame(&self, p: &konsensus_core::NodeId, bytes: &[u8]) -> Result<(), konsensus_core::traits::transport::TransportError> {
        if let Ok(konsensus_message::Frame::PorchQuoteRequest { request_id, path }) = konsensus_message::Frame::from_bytes(bytes) {
            konsensus_api::handlers::browse::receive_quote(
                self.ours, *p, request_id, path,
                konsensus_core::payloads::content::PageStatus::Ok, Some(2_000), false,
            );
        }
        self.inner.send_raw_frame(p, bytes).await
    }
}

/// A porch page request is always paid. Begun while the wallet was not ready
/// (no tip read), it still asks for no porch quote and pays nothing without a
/// usable tip, even with a responsive porch and a wallet ready by then.
#[tokio::test]
async fn a_porch_page_request_without_a_chain_tip_asks_and_pays_nothing() {
    let wallet = Arc::new(RecoveringWallet::default());
    let base = common::test_state_with_lightning(wallet.clone());
    let peer = common::setup_e2ee_session(&base.session_manager).await;
    let stub = Arc::new(
        common::ConnectedStubTransport::new(vec![peer], base.invoice_requests.clone()).with_invoice_responder(move |_, amount| {
            let bolt11 = common::create_test_bolt11(amount);
            let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
            Some(konsensus_api::state::InvoiceResponseData { recipient: peer, payment_hash: invoice.payment_hash().to_string(), bolt11 })
        }),
    );
    stub.advertise(peer, &["Custom(\"porch_quote_v1\")"]);
    let transport = Arc::new(PorchTransport { inner: stub.clone(), ours: *base.identity.node_id() });
    let chain = Arc::new(common::TipDownChain::down());
    let state = Arc::new(AppState { transport, chain: chain.clone(), ..(*base).clone() });
    let plaintext = serde_json::json!({"request_id": "page", "path": "/front-door.json", "method": "GET", "accept": []}).to_string();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&state))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"recipient": peer.to_hex(), "kind": konsensus_core::kind::KIND_PAGE_REQUEST, "plaintext": plaintext, "wait_ack_ms": 0}).to_string(),
        ))
        .unwrap();
    let response = common::test_router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 65_536).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    common::assert_chain_not_ready(status, &body);
    let quotes = stub.raw_frames.lock().unwrap().iter()
        .filter(|f| matches!(konsensus_message::Frame::from_bytes(f), Ok(konsensus_message::Frame::PorchQuoteRequest { .. })))
        .count();
    assert_eq!(quotes, 0, "no porch quote asked");
    assert_eq!(chain.reads(), 1);
    assert_eq!(wallet.inner.money(), 0);
    assert!(stub.sent_envelopes.lock().unwrap().is_empty());
}

/// The connected stub, plus: the recipient promotes the paid admission (a
/// session appears) when the proof is re-sent.
struct PromotingTransport {
    inner: Arc<common::ConnectedStubTransport>,
    sessions: Arc<konsensus_crypto::SessionManager>,
}

#[async_trait]
impl konsensus_core::traits::transport::MessageTransport for PromotingTransport {
    async fn send(&self, peer: &konsensus_core::NodeId, envelope: &konsensus_core::UkmEnvelope) -> Result<(), konsensus_core::traits::transport::TransportError> {
        if !self.sessions.can_send(peer).await {
            assert_eq!(common::setup_e2ee_session(&self.sessions).await, *peer);
        }
        self.inner.send(peer, envelope).await
    }
    async fn recv(&self) -> Result<konsensus_core::UkmEnvelope, konsensus_core::traits::transport::TransportError> {
        self.inner.recv().await
    }
    async fn connect(&self, peer: &konsensus_core::NodeId, addr: &str) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.connect(peer, addr).await
    }
    async fn disconnect(&self, peer: &konsensus_core::NodeId) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.disconnect(peer).await
    }
    async fn is_connected(&self, peer: &konsensus_core::NodeId) -> bool {
        self.inner.is_connected(peer).await
    }
    async fn connected_since(&self, peer: &konsensus_core::NodeId) -> Option<std::time::Instant> {
        self.inner.connected_since(peer).await
    }
    async fn connected_peers(&self) -> Vec<konsensus_core::NodeId> {
        self.inner.connected_peers().await
    }
    async fn send_raw_frame(&self, peer: &konsensus_core::NodeId, frame: &[u8]) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.send_raw_frame(peer, frame).await
    }
}

/// A send resuming a paid admission whose journal kept the target's quote
/// (2 000 msat for chat): once its wallet is ready, even the initial own
/// price of 0 requires a tip before resuming the earlier admission.
#[tokio::test]
async fn a_resumed_admission_with_a_kept_quote_pays_nothing_without_a_tip() {
    let dir = tempfile::tempdir().unwrap();
    let wallet = Arc::new(RecoveringWallet::default());
    let base = common::test_state_with_data_dir(dir.path().to_path_buf());
    let peer = *konsensus_core::identity::NodeIdentity::from_mnemonic("zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong", "").unwrap().node_id();
    let stub = Arc::new(common::ConnectedStubTransport::new(vec![peer], base.invoice_requests.clone()));
    let transport = Arc::new(PromotingTransport { inner: stub.clone(), sessions: base.session_manager.clone() });
    let chain = Arc::new(common::TipDownChain::down());
    let state = Arc::new(AppState {
        lightning: wallet.clone(),
        transport,
        chain: chain.clone(),
        pricing: Arc::new(FreePricing),
        ..(*base).clone()
    });
    state.peer_ln_pubkeys.lock().await.insert(peer, "02aaaa".repeat(5));
    let envelope = konsensus_core::UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        *state.identity.node_id(),
        konsensus_core::Recipient::Node(peer),
        vec![],
        konsensus_core::PaymentProof::new([0x11; 32], [0x22; 32], 1_000),
    )
    .build();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let journal = dir.path().join("admission-attempts");
    std::fs::create_dir_all(&journal).unwrap();
    std::fs::write(
        journal.join(peer.to_hex()),
        serde_json::to_vec(&serde_json::json!({
            "dispatch_started": true, "payment_hash": "11".repeat(32), "amount_msat": 1_000,
            "quote": [konsensus_core::kind::KIND_CHAT, 2_000], "envelope": envelope,
            "settled_at_unix": now, "proof_delivered": false,
        }))
        .unwrap(),
    )
    .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&state))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"recipient": peer.to_hex(), "kind": konsensus_core::kind::KIND_CHAT, "plaintext": "resumed", "wait_ack_ms": 0}).to_string(),
        ))
        .unwrap();
    let response = common::test_router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 65_536).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    common::assert_chain_not_ready(status, &body);
    assert!(stub.sent_envelopes.lock().unwrap().is_empty(), "{body}");
    assert!(journal.join(peer.to_hex()).exists());
    assert_eq!(chain.reads(), 1);
    assert_eq!(wallet.inner.money(), 0, "the new message was not paid");
    assert_eq!(wallet.inner.invoices(), 0);
}

/// The payment chokepoint on its own: a paid send through the shared payment
/// path (as calendar sends use it), with no other tip check before it, does not
/// pay without a usable tip.
#[tokio::test]
async fn the_payment_path_itself_needs_a_chain_tip() {
    let wallet = Arc::new(common::CountingLightning::default());
    let base = common::test_state_with_lightning(wallet.clone());
    let peer = konsensus_core::NodeId::from_bytes([0x6b; 32]);
    let stub = Arc::new(common::ConnectedStubTransport::new(vec![peer], base.invoice_requests.clone()));
    let chain = Arc::new(common::TipDownChain::down());
    let state = Arc::new(AppState { transport: stub.clone(), chain: chain.clone(), ..(*base).clone() });
    state.peer_ln_pubkeys.lock().await.insert(peer, "02aaaa".repeat(5));
    let error = konsensus_api::handlers::messages::create_payment_proof(&state, 2_000, &peer).await.unwrap_err();
    assert!(error.to_string().contains("the chain source has no current tip"), "{error}");
    assert_eq!(chain.reads(), 1);
    assert_eq!(wallet.money(), 0);
    assert_eq!(wallet.invoices(), 0);
    assert!(stub.raw_frames.lock().unwrap().is_empty(), "no invoice requested");
    // With a tip, the same call pays.
    let state = Arc::new(AppState { chain: Arc::new(common::StubChain), ..(*state).clone() });
    konsensus_api::handlers::messages::create_payment_proof(&state, 2_000, &peer).await.unwrap();
    assert_eq!(wallet.money(), 1);
}


#[tokio::test]
async fn an_established_free_chat_delivers_without_a_tip() {
    for is_room in [false, true] {
        for initially_ready in [false, true] {
            for chain in [common::TipDownChain::down(), common::TipDownChain::zero()] {
                let wallet = Arc::new(RecoveringWallet { polls: AtomicUsize::new(usize::from(initially_ready)), ..Default::default() });
                let chain = Arc::new(chain);
                let (wallet, status, body) = send_with_wallet(is_room, chain.clone(), 0, wallet).await;
                assert_eq!(status, 200, "room={is_room}, ready={initially_ready}: {body}");
                assert_eq!(body["delivered"], true, "{body}");
                assert_eq!(body["amount_msat"], 0, "{body}");
                assert_eq!(chain.reads(), 0);
                assert_eq!(wallet.inner.money(), 0);
                assert_eq!(wallet.inner.invoices(), 0);
            }
        }
    }
}

#[tokio::test]
async fn a_free_quote_does_not_read_a_usable_tip_either() {
    for is_room in [false, true] {
        let chain = Arc::new(common::TipDownChain::after(usize::MAX));
        let (wallet, status, body) = send(is_room, chain.clone(), 0).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["amount_msat"], 0, "{body}");
        assert_eq!(wallet.inner.money(), 0);
        assert_eq!(chain.reads(), 0);
    }
}

struct WaitingTransport {
    inner: Arc<common::ConnectedStubTransport>,
    delay_invoice: bool,
    delay: std::time::Duration,
}

#[async_trait]
impl konsensus_core::traits::transport::MessageTransport for WaitingTransport {
    async fn send(&self, p: &konsensus_core::NodeId, e: &konsensus_core::UkmEnvelope) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.send(p, e).await
    }
    async fn recv(&self) -> Result<konsensus_core::UkmEnvelope, konsensus_core::traits::transport::TransportError> {
        self.inner.recv().await
    }
    async fn connect(&self, p: &konsensus_core::NodeId, a: &str) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.connect(p, a).await
    }
    async fn disconnect(&self, p: &konsensus_core::NodeId) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.disconnect(p).await
    }
    async fn is_connected(&self, p: &konsensus_core::NodeId) -> bool {
        if !self.delay_invoice {
            tokio::time::advance(self.delay).await;
        }
        self.inner.is_connected(p).await
    }
    async fn connected_peers(&self) -> Vec<konsensus_core::NodeId> {
        self.inner.connected_peers().await
    }
    async fn send_raw_frame(&self, p: &konsensus_core::NodeId, bytes: &[u8]) -> Result<(), konsensus_core::traits::transport::TransportError> {
        if self.delay_invoice {
            tokio::time::advance(self.delay).await;
        }
        self.inner.send_raw_frame(p, bytes).await
    }
}

#[tokio::test(start_paused = true)]
async fn a_payment_refreshes_its_tip_after_waiting() {
    for delay_invoice in [false, true] {
        for (seconds, good_reads, pays, reads) in [(1, 1, true, 1), (31, 1, false, 2), (31, 2, true, 2)] {
            let wallet = Arc::new(common::CountingLightning::default());
            let base = common::test_state_with_lightning(wallet.clone());
            let peer = konsensus_core::NodeId::from_bytes([0x6c; 32]);
            let stub = Arc::new(common::ConnectedStubTransport::new(vec![peer], base.invoice_requests.clone())
                .with_invoice_responder(move |_, amount| {
                    let bolt11 = common::create_test_bolt11(amount);
                    let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
                    Some(konsensus_api::state::InvoiceResponseData { recipient: peer, payment_hash: invoice.payment_hash().to_string(), bolt11 })
                }));
            let transport = Arc::new(WaitingTransport { inner: stub, delay_invoice, delay: std::time::Duration::from_secs(seconds) });
            let chain = Arc::new(common::TipDownChain::after(good_reads));
            let state = Arc::new(AppState { transport, chain: chain.clone(), ..(*base).clone() });
            if !delay_invoice {
                state.peer_ln_pubkeys.lock().await.insert(peer, "02aaaa".repeat(5));
            }
            let result = konsensus_api::handlers::messages::create_payment_proof(&state, 2_000, &peer).await;
            assert_eq!(result.is_ok(), pays, "invoice={delay_invoice}, delay={seconds}: {:?}", result.as_ref().err());
            if !pays {
                let response = result.unwrap_err().into_response();
                let status = response.status().as_u16();
                let bytes = axum::body::to_bytes(response.into_body(), 65_536).await.unwrap();
                common::assert_chain_not_ready(status, &serde_json::from_slice(&bytes).unwrap());
            }
            assert_eq!(wallet.money(), usize::from(pays));
            assert_eq!(chain.reads(), reads);
        }
    }
}


async fn journal_wait(cancel_refresh: bool) {
    for keysend in [false, true] {
        let wallet = Arc::new(common::CountingLightning::default());
        let storage = Arc::new(common::MemStorage::new());
        let base = common::test_state_with_lightning_and_storage(wallet.clone(), storage.clone());
        let peer = common::setup_e2ee_session(&base.session_manager).await;
        let transport = Arc::new(common::ConnectedStubTransport::new(vec![peer], base.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                let bolt11 = common::create_test_bolt11(amount);
                let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
                Some(konsensus_api::state::InvoiceResponseData { recipient: peer, payment_hash: invoice.payment_hash().to_string(), bolt11 })
            }));
        let chain = Arc::new(common::TipDownChain::after(usize::MAX));
        let state = Arc::new(AppState { transport, chain: chain.clone(), ..(*base).clone() });
        if keysend {
            state.peer_ln_pubkeys.lock().await.insert(peer, "02aaaa".repeat(5));
        }
        let gate = Arc::new(common::PeerWriteGate::default());
        *storage.outbox_dispatch_gate.lock().unwrap() = Some(gate.clone());
        let operation = uuid::Uuid::new_v4().to_string();
        let post = |state: Arc<AppState>| {
            let request = Request::builder().method("POST").uri("/api/v1/messages/compose")
                .header("authorization", common::auth_header(&state)).header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"operation_id": operation, "recipient": peer.to_hex(), "kind": 0,
                    "plaintext": "journal wait", "wait_ack_ms": 0}).to_string())).unwrap();
            async move { common::test_router(state).oneshot(request).await.unwrap() }
        };
        let sending = tokio::spawn(post(state.clone()));
        gate.entered.notified().await;
        tokio::time::advance(std::time::Duration::from_secs(31)).await;
        chain.ok_reads.store(0, Ordering::SeqCst);
        let read_gate = Arc::new(common::PeerWriteGate::default());
        if cancel_refresh {
            *chain.read_gate.lock().unwrap() = Some(read_gate.clone());
        }
        gate.release.notify_one();
        if cancel_refresh {
            read_gate.entered.notified().await;
            sending.abort();
            assert!(sending.await.unwrap_err().is_cancelled());
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let op = state.storage.get_outbox_operation(&operation).await.unwrap().unwrap();
                    let data: serde_json::Value = serde_json::from_slice(&op.recovery).unwrap();
                    if data["dispatched"] == false { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }).await.expect("cancelled preparation clears dispatch intent");
        } else {
            let response = sending.await.unwrap();
            let status = response.status().as_u16();
            let bytes = axum::body::to_bytes(response.into_body(), 65_536).await.unwrap();
            common::assert_chain_not_ready(status, &serde_json::from_slice(&bytes).unwrap());
        }
        assert_eq!(wallet.money(), 0);
        assert_eq!(chain.reads(), 2);
        chain.ok_reads.store(usize::MAX, Ordering::SeqCst);
        let response = post(state).await;
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(wallet.money(), 1, "the same operation can pay after recovery");
    }
}


#[tokio::test(start_paused = true)]
async fn a_journal_wait_refreshes_the_tip_and_keeps_the_operation_retryable() {
    journal_wait(false).await;
}

#[tokio::test(start_paused = true)]
async fn cancelling_a_pending_tip_refresh_keeps_the_operation_retryable() {
    journal_wait(true).await;
}


#[tokio::test]
async fn an_unready_wallet_can_deliver_an_established_free_chat_without_a_tip() {
    for is_room in [false, true] {
        for available in [false, true] {
            let wallet = Arc::new(RecoveringWallet { remain_unready: true, ..Default::default() });
            let chain = Arc::new(common::TipDownChain::after(if available { usize::MAX } else { 0 }));
            let (wallet, status, body) = send_with_wallet(is_room, chain.clone(), 0, wallet).await;
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["delivered"], true, "{body}");
            assert_eq!(body["amount_msat"], 0);
            assert_eq!(wallet.inner.money(), 0);
            assert_eq!(wallet.inner.invoices(), 0);
            assert_eq!(chain.reads(), 0);
        }
    }
}


#[tokio::test]
async fn a_free_payment_proof_needs_no_tip_or_wallet_payment() {
    let wallet = Arc::new(common::CountingLightning::default());
    let base = common::test_state_with_lightning(wallet.clone());
    let chain = Arc::new(common::TipDownChain::down());
    let state = Arc::new(AppState { chain: chain.clone(), ..(*base).clone() });
    let peer = konsensus_core::NodeId::from_bytes([0x6d; 32]);
    let (_, _, amount) = konsensus_api::handlers::messages::create_payment_proof(&state, 0, &peer).await.unwrap();
    assert_eq!(amount, 0);
    assert_eq!(chain.reads(), 0);
    assert_eq!(wallet.money(), 0);
    assert_eq!(wallet.invoices(), 0);
}
