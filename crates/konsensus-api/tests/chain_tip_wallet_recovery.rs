//! A send that starts while the wallet is not money-ready reads no chain tip.
//! If the wallet becomes ready before payment, a price to pay must still be
//! checked against a real tip: never against height 0, which skips the block
//! validity of a peer's price table.
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use axum::{body::Body, http::Request};
use konsensus_api::state::AppState;
use konsensus_core::traits::chain::ChainProvider;
use konsensus_core::traits::lightning::*;
use konsensus_storage::models::Room;
use tower::ServiceExt;

/// Not money-ready on the first poll, ready on every later one.
#[derive(Default)]
struct RecoveringWallet {
    polls: AtomicUsize,
    inner: common::CountingLightning,
}

#[async_trait]
impl LightningProvider for RecoveringWallet {
    async fn money_ready(&self) -> bool {
        self.polls.fetch_add(1, Ordering::SeqCst) != 0
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

async fn send(is_room: bool, chain: Arc<dyn ChainProvider>) -> (Arc<RecoveringWallet>, u16, serde_json::Value) {
    let wallet = Arc::new(RecoveringWallet::default());
    let base = common::test_state_with_lightning(wallet.clone());
    let peer = common::setup_e2ee_session_with_mnemonic(
        &base.session_manager,
        "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
    )
    .await;
    let transport = Arc::new(common::ConnectedStubTransport::new(vec![peer], base.invoice_requests.clone()));
    let state = Arc::new(AppState { transport, chain, ..(*base).clone() });
    state.peer_ln_pubkeys.lock().await.insert(peer, "02aaaa".repeat(5));
    // Valid for one block from height 1: expired by any real tip, still
    // within its wall-clock age, and "valid" against height 0.
    state
        .peer_prices
        .update(peer, std::collections::HashMap::from([("communication".to_string(), 2_000)]), 1, 1, 0.0)
        .await;
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
        let (wallet, status, body) = send(is_room, chain.clone()).await;
        common::assert_chain_not_ready(status, &body);
        assert!(wallet.polls.load(Ordering::SeqCst) >= 2, "room={is_room}: readiness changed mid-send");
        assert_eq!(chain.reads(), 1, "room={is_room}: the price to pay asked for a tip");
        assert_eq!(wallet.inner.money(), 0, "room={is_room}: nothing paid");
        assert_eq!(wallet.inner.invoices(), 0);
    }
}

#[tokio::test]
async fn with_a_tip_the_expired_peer_table_is_not_paid() {
    for is_room in [false, true] {
        let chain = Arc::new(common::TipDownChain::after(usize::MAX));
        let (wallet, _, body) = send(is_room, chain.clone()).await;
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
    // The earlier admission stays paid; this send stops at the missing tip,
    // reported through the existing settled-but-not-sent outcome.
    assert_eq!((status, body["code"].as_str()), (502, Some("payment_settled_send_incomplete")), "{body}");
    assert!(body["error"].as_str().unwrap().contains("the chain source has no current tip"), "{body}");
    assert_eq!(body["amount_msat"], 0, "{body}");
    // It got as far as the resumed admission (the paid proof went out again)
    // and then asked for the tip, once.
    assert_eq!(stub.sent_envelopes.lock().unwrap().len(), 1, "{body}");
    assert_eq!(chain.reads(), 1);
    assert_eq!(wallet.inner.money(), 0);
    assert_eq!(wallet.inner.invoices(), 0);
}
