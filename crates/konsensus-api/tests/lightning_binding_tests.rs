//! A contact is paid by keysend only at a Lightning key their identity signed.
//! An unsigned key (older peer) refuses the payment with a fixed reason and
//! pays nothing by any path.
mod common;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures::stream::BoxStream;
use konsensus_api::handlers::messages::create_payment_proof;
use konsensus_api::state::PeerLightningKey;
use konsensus_core::lightning_binding::{REASON_CONTACT_MUST_UPDATE, REASON_DESTINATION_MISMATCH};
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails,
};
use konsensus_core::NodeIdentity;
use konsensus_lightning::{MockLightningProvider, RecoveringLightning};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

type PeerLnKeys = Arc<
    tokio::sync::Mutex<std::collections::HashMap<konsensus_core::types::NodeId, PeerLightningKey>>,
>;

/// The stock mock, recording every keysend destination. It can also rewrite a
/// peer's binding while a keysend is in flight, to model a rotation that
/// lands between the destination check and the backend call.
struct RecordingLightning {
    backend: MockLightningProvider,
    keysend_destinations: Mutex<Vec<String>>,
    rotate_during_keysend:
        Mutex<Option<(PeerLnKeys, konsensus_core::types::NodeId, PeerLightningKey)>>,
    rotate_on_subscribe:
        Mutex<Option<(PeerLnKeys, konsensus_core::types::NodeId, PeerLightningKey)>>,
}

impl RecordingLightning {
    fn new() -> Self {
        Self {
            backend: MockLightningProvider::new(),
            keysend_destinations: Mutex::new(Vec::new()),
            rotate_during_keysend: Mutex::new(None),
            rotate_on_subscribe: Mutex::new(None),
        }
    }

    /// Arm the next settlement subscription to replace `peer`'s binding with
    /// `next`. `try_keysend` subscribes after its early destination check and
    /// before the dispatch bookkeeping, so this lands a change exactly in the
    /// window between the caller's check and the backend call.
    fn rotate_before_dispatch(
        &self,
        map: PeerLnKeys,
        peer: konsensus_core::types::NodeId,
        next: PeerLightningKey,
    ) {
        *self.rotate_on_subscribe.lock().unwrap() = Some((map, peer, next));
    }

    /// Arm the next keysend to replace `peer`'s binding with `next` after the
    /// destination has been authorized and before the backend sees it.
    fn rotate_during_next_keysend(
        &self,
        map: PeerLnKeys,
        peer: konsensus_core::types::NodeId,
        next: PeerLightningKey,
    ) {
        *self.rotate_during_keysend.lock().unwrap() = Some((map, peer, next));
    }

    fn destinations(&self) -> Vec<String> {
        self.keysend_destinations.lock().unwrap().clone()
    }

    async fn payments(&self) -> usize {
        self.backend.list_payments(100).await.unwrap().len()
    }
}

#[async_trait]
impl LightningProvider for RecordingLightning {
    async fn create_invoice(
        &self,
        amount: u64,
        description: &str,
        expiry: u32,
    ) -> Result<Invoice, LightningError> {
        self.backend
            .create_invoice(amount, description, expiry)
            .await
    }

    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        self.backend.pay_invoice(bolt11).await
    }

    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        cap: u64,
    ) -> Result<PaymentDetails, LightningError> {
        self.backend.pay_invoice_with_fee_limit(bolt11, cap).await
    }

    async fn keysend_with_fee_limit(
        &self,
        destination: &str,
        amount: u64,
        memo: Option<&str>,
        cap: u64,
    ) -> Result<PaymentDetails, LightningError> {
        self.keysend_destinations
            .lock()
            .unwrap()
            .push(destination.to_owned());
        let rotation = self.rotate_during_keysend.lock().unwrap().take();
        if let Some((map, peer, next)) = rotation {
            map.lock().await.insert(peer, next);
        }
        self.backend
            .keysend_with_fee_limit(destination, amount, memo, cap)
            .await
    }

    fn outgoing_payment_updates(&self) -> Option<BoxStream<'static, String>> {
        let rotation = self.rotate_on_subscribe.lock().unwrap().take();
        if let Some((map, peer, next)) = rotation {
            map.try_lock()
                .expect("binding map is not locked while subscribing")
                .insert(peer, next);
        }
        self.backend.outgoing_payment_updates()
    }

    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        self.backend.get_payment_status(hash).await
    }

    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.backend.get_balance_msat().await
    }

    async fn is_available(&self) -> bool {
        true
    }
}

struct Fixture {
    backend: Arc<RecordingLightning>,
    lightning: Arc<dyn LightningProvider>,
    state: Arc<konsensus_api::AppState>,
    peer: konsensus_core::types::NodeId,
}

/// A connected peer whose node never answers an invoice request: any attempt
/// to take the invoice path fails the test instead of paying.
async fn fixture() -> Fixture {
    let backend = Arc::new(RecordingLightning::new());
    let wrapped: Arc<dyn LightningProvider> = backend.clone();
    let lightning: Arc<dyn LightningProvider> = Arc::new(
        RecoveringLightning::new(
            move || {
                let backend = wrapped.clone();
                async move { Ok(backend) }
            },
            Default::default(),
        )
        .await
        .unwrap(),
    );
    tokio::task::yield_now().await;
    assert!(lightning.money_ready().await);
    let mut state = common::test_state_with_lightning(lightning.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    // An established E2EE session, as with any contact the owner has spoken to.
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state
        .session_manager
        .initiate_session(&peer, &target.prekey_bundle().await)
        .await
        .unwrap();
    let transport = common::ConnectedStubTransport::new(vec![peer], state.invoice_requests.clone())
        .with_invoice_responder(|_, _| panic!("no path may ask this contact for an invoice"));
    Arc::get_mut(&mut state).unwrap().transport = Arc::new(transport);
    Fixture {
        backend,
        lightning,
        state,
        peer,
    }
}

fn ln_key(prefix: &str) -> String {
    format!("{prefix}{}", "aa".repeat(32))
}

#[tokio::test]
async fn keysend_pays_the_identity_bound_key() {
    let fx = fixture().await;
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Verified(ln_key("02")));

    let (_, _, amount) = create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap();

    assert_eq!(amount, 2_000);
    assert_eq!(
        fx.backend.destinations(),
        vec![ln_key("02")],
        "keysend went to the signed key only"
    );
    assert_eq!(fx.backend.payments().await, 1);
    fx.lightning.shutdown().await.unwrap();
}

#[tokio::test]
async fn unsigned_key_refuses_payment_and_pays_nothing() {
    let fx = fixture().await;
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Unsigned);
    let before = fx.backend.get_balance_msat().await.unwrap();

    let err = create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains(REASON_CONTACT_MUST_UPDATE),
        "{err}"
    );
    assert!(
        fx.backend.destinations().is_empty(),
        "no keysend was dispatched"
    );
    assert_eq!(fx.backend.payments().await, 0, "no payment by any path");
    assert_eq!(fx.backend.get_balance_msat().await.unwrap(), before);
    assert!(
        fx.state.invoice_requests.lock().await.is_empty(),
        "no invoice was requested"
    );
    fx.lightning.shutdown().await.unwrap();
}

#[tokio::test]
async fn rotated_binding_moves_keysend_to_the_new_key() {
    let fx = fixture().await;
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Verified(ln_key("02")));
    create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap();

    // The session handler stores the newly signed key; payments follow it.
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Verified(ln_key("03")));
    create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap();

    assert_eq!(fx.backend.destinations(), vec![ln_key("02"), ln_key("03")]);
    fx.lightning.shutdown().await.unwrap();
}

/// The destination is authorized immediately before dispatch. A rotation that
/// lands while the backend call is in flight does not redirect that payment;
/// it was authorized to a key the identity signed, and the next payment
/// follows the new binding.
#[tokio::test]
async fn rotation_during_dispatch_pays_the_key_that_was_authorized() {
    let fx = fixture().await;
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Verified(ln_key("02")));
    fx.backend.rotate_during_next_keysend(
        fx.state.peer_ln_pubkeys.clone(),
        fx.peer,
        PeerLightningKey::Verified(ln_key("03")),
    );

    create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap();
    create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap();

    assert_eq!(fx.backend.destinations(), vec![ln_key("02"), ln_key("03")]);
    assert_eq!(fx.backend.payments().await, 2);
    fx.lightning.shutdown().await.unwrap();
}

/// A removal that lands while the backend call is in flight does not cancel
/// the authorized payment either; the next payment is refused.
#[tokio::test]
async fn removal_during_dispatch_refuses_only_the_next_payment() {
    let fx = fixture().await;
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Verified(ln_key("02")));
    fx.backend.rotate_during_next_keysend(
        fx.state.peer_ln_pubkeys.clone(),
        fx.peer,
        PeerLightningKey::Unsigned,
    );

    create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap();
    let err = create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains(REASON_CONTACT_MUST_UPDATE),
        "{err}"
    );
    assert_eq!(fx.backend.destinations(), vec![ln_key("02")]);
    assert_eq!(fx.backend.payments().await, 1);
    fx.lightning.shutdown().await.unwrap();
}

/// A rotation that lands between the caller's check and the backend call
/// (while the dispatch bookkeeping awaits) refuses the payment instead of
/// paying the key the identity no longer signs. Nothing is dispatched, and the
/// next payment follows the new binding.
#[tokio::test]
async fn rotation_before_dispatch_refuses_and_pays_nothing() {
    let fx = fixture().await;
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Verified(ln_key("02")));
    fx.backend.rotate_before_dispatch(
        fx.state.peer_ln_pubkeys.clone(),
        fx.peer,
        PeerLightningKey::Verified(ln_key("03")),
    );

    let err = create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains(REASON_DESTINATION_MISMATCH),
        "{err}"
    );
    assert!(
        fx.backend.destinations().is_empty(),
        "nothing reached the backend"
    );
    assert_eq!(fx.backend.payments().await, 0);

    create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap();
    assert_eq!(fx.backend.destinations(), vec![ln_key("03")]);
    fx.lightning.shutdown().await.unwrap();
}

/// The same window, with the binding becoming unsigned: refused with the
/// update reason, no keysend, no invoice.
#[tokio::test]
async fn unsigned_before_dispatch_refuses_and_pays_nothing() {
    let fx = fixture().await;
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Verified(ln_key("02")));
    fx.backend.rotate_before_dispatch(
        fx.state.peer_ln_pubkeys.clone(),
        fx.peer,
        PeerLightningKey::Unsigned,
    );

    let err = create_payment_proof(&fx.state, 2_000, &fx.peer)
        .await
        .unwrap_err();

    assert!(
        err.to_string().contains(REASON_CONTACT_MUST_UPDATE),
        "{err}"
    );
    assert!(fx.backend.destinations().is_empty());
    assert_eq!(fx.backend.payments().await, 0);
    assert!(fx.state.invoice_requests.lock().await.is_empty());
    fx.lightning.shutdown().await.unwrap();
}

/// Through a durable operation the dispatch bookkeeping writes the journal
/// before the backend is polled. A rotation in that window is refused with
/// the fixed reason, the journal is rolled back to not dispatched, and a
/// fresh operation pays the new key.
#[tokio::test]
async fn rotation_before_dispatch_in_operation_refuses_and_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let db: Arc<dyn konsensus_storage::Storage> = Arc::new(
        konsensus_storage::SqliteStorage::open(dir.path().join("ops.db").to_str().unwrap())
            .await
            .unwrap(),
    );
    let mut fx = fixture().await;
    Arc::get_mut(&mut fx.state).unwrap().storage = db;
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Verified(ln_key("02")));
    fx.backend.rotate_before_dispatch(
        fx.state.peer_ln_pubkeys.clone(),
        fx.peer,
        PeerLightningKey::Verified(ln_key("03")),
    );
    let auth = common::auth_header(&fx.state);
    let app = common::test_router(Arc::clone(&fx.state));
    let request = |operation_id: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/messages/compose")
            .header("authorization", &auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "operation_id": operation_id,
                    "recipient": fx.peer.to_hex(),
                    "kind": 1,
                    "plaintext": "hello",
                    "wait_ack_ms": 0
                })
                .to_string(),
            ))
            .unwrap()
    };
    let body = |resp: axum::response::Response| async {
        serde_json::from_slice::<serde_json::Value>(
            &axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap()
    };

    let rotated_op = uuid::Uuid::new_v4().to_string();
    let fresh_op = uuid::Uuid::new_v4().to_string();
    let first = app.clone().oneshot(request(&rotated_op)).await.unwrap();
    let status = first.status();
    let first = body(first).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{first}");
    assert_eq!(first["reason"], REASON_DESTINATION_MISMATCH);
    assert_eq!(first["accepted"], false);
    assert!(
        fx.backend.destinations().is_empty(),
        "nothing reached the backend"
    );
    assert_eq!(fx.backend.payments().await, 0);

    let second = app.oneshot(request(&fresh_op)).await.unwrap();
    let status = second.status();
    let second = body(second).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_eq!(fx.backend.destinations(), vec![ln_key("03")]);
    assert_eq!(fx.backend.payments().await, 1);
    fx.lightning.shutdown().await.unwrap();
}

#[tokio::test]
async fn compose_to_unsigned_contact_returns_fixed_reason() {
    let fx = fixture().await;
    fx.state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(fx.peer, PeerLightningKey::Unsigned);
    let auth = common::auth_header(&fx.state);
    let app = common::test_router(Arc::clone(&fx.state));

    let req = Request::builder()
        .method("POST")
        .uri("/api/v1/messages/compose")
        .header("authorization", &auth)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "recipient": fx.peer.to_hex(),
                "kind": 1,
                "plaintext": "hello"
            })
            .to_string(),
        ))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();

    let status = resp.status();
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body["code"], "peer_not_ready");
    assert_eq!(body["reason"], REASON_CONTACT_MUST_UPDATE);
    assert!(fx.backend.destinations().is_empty());
    assert_eq!(fx.backend.payments().await, 0);
    fx.lightning.shutdown().await.unwrap();
}
