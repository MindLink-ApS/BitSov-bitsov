//! Free established chats remain available with chain-aware local pricing.
//! Cached peer prices still enforce their payment floor during chain outages.
mod common;

use std::sync::Arc;

use axum::{body::Body, http::Request};
use konsensus_api::state::AppState;
use konsensus_core::kind::KIND_CHAT;
use konsensus_pricing::{ChainAwarePricingConfig, ChainAwarePricingEngine, StaticPricingConfig};
use konsensus_storage::models::Room;
use tower::ServiceExt;

#[tokio::test]
async fn established_chat_prices_with_a_chain_outage() {
    for is_room in [false, true] {
        for (base_price, peer_price, delivers, reads) in [
            (0, None, true, 0),
            (2_000, Some(0), false, 1),
            (2_000, None, false, 1),
            (2_000, Some(2_000), false, 1),
        ] {
            let wallet = Arc::new(common::CountingLightning::default());
            let base = common::test_state_with_lightning(wallet.clone());
            let peer = common::setup_e2ee_session(&base.session_manager).await;
            let transport = Arc::new(common::ConnectedStubTransport::new(vec![peer], base.invoice_requests.clone()));
            let chain = Arc::new(common::TipDownChain::down());
            let pricing = Arc::new(ChainAwarePricingEngine::new(ChainAwarePricingConfig {
                base: StaticPricingConfig { chat_msat: base_price, ..Default::default() },
                ..Default::default()
            }, chain.clone()));
            let state = Arc::new(AppState { transport: transport.clone(), chain: chain.clone(), pricing, ..(*base).clone() });
            state.peer_ln_pubkeys.lock().await.insert(peer, konsensus_api::state::PeerLightningKey::Verified("02aaaa".repeat(5)));
            if let Some(price) = peer_price {
                state.peer_prices.update(peer, std::collections::HashMap::from([("communication".to_string(), price)]), 850_000, 144, 0.0).await;
            }
            let recipient = if is_room {
                let room = Room::new("free chat".into(), *state.identity.node_id());
                state.storage.create_room(&room).await.unwrap();
                state.storage.add_room_member(&room.id, &peer).await.unwrap();
                room.id.to_string()
            } else {
                peer.to_hex()
            };
            let request = Request::builder().method("POST").uri("/api/v1/messages/compose")
                .header("authorization", common::auth_header(&state)).header("content-type", "application/json")
                .body(Body::from(serde_json::json!({
                    "recipient": recipient, "is_room": is_room, "kind": KIND_CHAT,
                    "plaintext": "free chat", "wait_ack_ms": 0,
                }).to_string())).unwrap();
            let response = common::test_router(state).oneshot(request).await.unwrap();
            let status = response.status().as_u16();
            let bytes = axum::body::to_bytes(response.into_body(), 65_536).await.unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            if delivers {
                assert_eq!(status, 200, "room={is_room}, base={base_price}, peer={peer_price:?}: {body}");
                assert_eq!(body["delivered"], true, "{body}");
                assert_eq!(body["amount_msat"], 0, "{body}");
                assert_eq!(transport.sent_envelopes.lock().unwrap().len(), 1);
            } else {
                common::assert_chain_not_ready(status, &body);
                assert!(transport.sent_envelopes.lock().unwrap().is_empty());
            }
            assert_eq!(chain.reads(), reads);
            assert_eq!(wallet.money(), 0);
            assert_eq!(wallet.invoices(), 0);
            assert!(transport.raw_frames.lock().unwrap().is_empty(), "no invoice requested");
        }
    }
}
