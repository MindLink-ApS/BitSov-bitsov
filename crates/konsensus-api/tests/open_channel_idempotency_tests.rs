//! #331: `open-channel` idempotency via `operation_id`. In-process, no money.
mod common;
use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_core::traits::lightning::*;
use konsensus_storage::{SqliteStorage, Storage};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tower::ServiceExt;

const PEER: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OP: &str = "6f1c9a52-6c8e-4c1e-9f3b-2d6a0e7b5c41";

/// First open fails as configured; the channel may still appear (a timeout).
#[derive(Default)]
struct OpenBackend {
    opens: AtomicUsize,
    /// Errors returned by the next opens, in order; empty means success.
    failures: Mutex<Vec<LightningError>>,
    /// Whether a failed open still created the channel (a lost response).
    open_despite_failure: bool,
    channels: Mutex<Vec<ChannelInfo>>,
}

impl OpenBackend {
    fn failing(error: LightningError, open_despite_failure: bool) -> Self {
        Self {
            failures: Mutex::new(vec![error]),
            open_despite_failure,
            ..Default::default()
        }
    }
    fn opens(&self) -> usize {
        self.opens.load(Ordering::SeqCst)
    }
    fn open(&self, peer: &str, amount: u64) -> Result<ChannelOpenResult, LightningError> {
        let n = self.opens.fetch_add(1, Ordering::SeqCst) + 1;
        let failure = {
            let mut f = self.failures.lock().unwrap();
            (!f.is_empty()).then(|| f.remove(0))
        };
        let channel_id = format!("{n:064x}");
        if failure.is_none() || self.open_despite_failure {
            self.channels.lock().unwrap().push(ChannelInfo {
                channel_id: channel_id.clone(),
                user_channel_id: Some(n.to_string()),
                funding_txo: None,
                peer_pubkey: peer.into(),
                capacity_msat: amount * 1000,
                local_balance_msat: amount * 1000,
                remote_balance_msat: 0,
                active: false,
                short_channel_id: None,
            });
        }
        if let Some(e) = failure {
            return Err(e);
        }
        Ok(ChannelOpenResult {
            user_channel_id: Some(n.to_string()),
            funding_txo: None,
            channel_id,
            funding_txid: Some("ab".repeat(32)),
            status: ChannelOpenStatus::Opening,
            funding_fee: None,
        })
    }
}

#[async_trait]
impl LightningProvider for OpenBackend {
    async fn create_invoice(&self, a: u64, d: &str, e: u32) -> Result<Invoice, LightningError> {
        StubLightning.create_invoice(a, d, e).await
    }
    async fn pay_invoice(&self, i: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.pay_invoice(i).await
    }
    async fn get_payment_status(&self, h: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.get_payment_status(h).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        Ok(self.channels.lock().unwrap().clone())
    }
    async fn open_channel_with_status(
        &self,
        peer: &str,
        _addr: &str,
        amount: u64,
        _announce: bool,
        _rate: Option<f32>,
    ) -> Result<ChannelOpenResult, LightningError> {
        self.open(peer, amount)
    }
    async fn open_channel_with_funding(
        &self,
        peer: &str,
        _addr: &str,
        amount: u64,
        _announce: bool,
        _options: FundingOptions,
        _push_msat: Option<u64>,
    ) -> Result<ChannelOpenResult, LightningError> {
        self.open(peer, amount)
    }
}

fn timeout() -> LightningError {
    LightningError::Backend(
        "channel 00: funding transaction unavailable after 60s; outcome uncertain; inspect channel before retrying".into(),
    )
}

async fn open(
    backend: Arc<dyn LightningProvider>,
    storage: Arc<dyn Storage>,
    extra: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let state = test_state_with_lightning_and_storage(backend, storage);
    let auth = auth_header(&state);
    let mut body = serde_json::json!({"peer_pubkey": PEER, "peer_addr": "127.0.0.1:9735", "amount_sats": 50000});
    body.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    let response = test_router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/payments/open-channel")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!({"text": String::from_utf8_lossy(&bytes)}));
    (status, json)
}

async fn sqlite() -> Arc<dyn Storage> {
    Arc::new(SqliteStorage::in_memory().await.unwrap())
}

#[tokio::test]
async fn retry_after_timeout_never_opens_a_second_channel_even_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.db");
    let backend = Arc::new(OpenBackend::failing(timeout(), true));
    let storage: Arc<dyn Storage> =
        Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
    let op = serde_json::json!({"operation_id": OP});

    let (status, body) = open(backend.clone(), storage.clone(), op.clone()).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(backend.opens(), 1);

    let (status, body) = open(backend.clone(), storage.clone(), op.clone()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "outcome_uncertain");
    assert_eq!(body["operation_id"], OP);
    assert_eq!(body["replayed"], true);
    assert!(body["last_error"]
        .as_str()
        .unwrap()
        .contains("outcome uncertain"));
    assert_eq!(
        body["peer_channels"].as_array().unwrap().len(),
        1,
        "the timed-out channel is reported"
    );
    assert_eq!(backend.opens(), 1, "the retry did not dispatch");

    // The record is durable: a restarted node still refuses to reopen.
    drop(storage);
    let storage: Arc<dyn Storage> =
        Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
    let (status, body) = open(backend.clone(), storage, op).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "outcome_uncertain");
    assert_eq!(backend.opens(), 1);
    assert_eq!(backend.channels.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn retry_after_success_returns_the_recorded_channel() {
    let backend = Arc::new(OpenBackend::default());
    let storage = sqlite().await;
    let op = serde_json::json!({"operation_id": OP, "funding_priority": "fast"});
    let (status, first) = open(backend.clone(), storage.clone(), op.clone()).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["operation_id"], OP);
    assert!(first.get("replayed").is_none());
    let (status, again) = open(backend.clone(), storage, op).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["replayed"], true);
    assert_eq!(again["channel_id"], first["channel_id"]);
    assert_eq!(again["user_channel_id"], first["user_channel_id"]);
    assert_eq!(again["funding_txid"], first["funding_txid"]);
    assert_eq!(backend.opens(), 1);
}

#[tokio::test]
async fn same_operation_id_with_different_parameters_is_409() {
    let backend = Arc::new(OpenBackend::failing(timeout(), true));
    let storage = sqlite().await;
    let (status, _) = open(
        backend.clone(),
        storage.clone(),
        serde_json::json!({"operation_id": OP}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    for changed in [
        serde_json::json!({"operation_id": OP, "amount_sats": 50001}),
        serde_json::json!({"operation_id": OP, "announce": true}),
        serde_json::json!({"operation_id": OP, "peer_addr": "127.0.0.1:9736"}),
        serde_json::json!({"operation_id": OP, "push_sats": 1}),
        serde_json::json!({"operation_id": OP, "fee_rate_sat_per_vb": 2.0}),
    ] {
        let (status, body) = open(backend.clone(), storage.clone(), changed.clone()).await;
        assert_eq!(status, StatusCode::CONFLICT, "{changed}: {body}");
        assert_eq!(body["code"], "operation_mismatch");
    }
    // Also after a recorded success.
    let backend_ok = Arc::new(OpenBackend::default());
    let other = "0b9f5a2e-1c3d-4e5f-8a6b-7c8d9e0f1a2b";
    let (status, _) = open(
        backend_ok.clone(),
        storage.clone(),
        serde_json::json!({"operation_id": other}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = open(
        backend_ok.clone(),
        storage,
        serde_json::json!({"operation_id": other, "amount_sats": 60000}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        backend.opens() + backend_ok.opens(),
        2,
        "a mismatch never dispatches"
    );
}

#[tokio::test]
async fn proven_non_dispatch_releases_the_operation_id() {
    let backend = Arc::new(OpenBackend::failing(
        LightningError::PaymentNotDispatched("insufficient funds".into()),
        false,
    ));
    let storage = sqlite().await;
    let op = serde_json::json!({"operation_id": OP});
    let (status, body) = open(backend.clone(), storage.clone(), op.clone()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched");
    assert!(storage
        .get_channel_open_operation(OP)
        .await
        .unwrap()
        .is_none());
    let (status, body) = open(backend.clone(), storage, op).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(backend.opens(), 2);
    assert_eq!(backend.channels.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn without_operation_id_behaviour_is_unchanged() {
    // MemStorage has no channel-open records: the default path never needs them.
    let backend = Arc::new(OpenBackend::default());
    for _ in 0..2 {
        let (status, body) = open(
            backend.clone(),
            Arc::new(MemStorage::new()),
            serde_json::json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("operation_id").is_none());
        assert!(body.get("replayed").is_none());
        assert_eq!(body["status"], "opening");
    }
    assert_eq!(backend.opens(), 2, "each request without an id opens");
    let failing = Arc::new(OpenBackend::failing(timeout(), true));
    let (status, _) = open(
        failing.clone(),
        Arc::new(MemStorage::new()),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    let (status, _) = open(
        failing.clone(),
        Arc::new(MemStorage::new()),
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        failing.opens(),
        2,
        "without an id a retry opens again, as before"
    );
}

#[tokio::test]
async fn invalid_ids_and_preview_refuse_before_dispatch() {
    let backend = Arc::new(OpenBackend::default());
    let storage = sqlite().await;
    let (status, body) = open(
        backend.clone(),
        storage.clone(),
        serde_json::json!({"operation_id": "nope"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let (status, body) = open(
        backend.clone(),
        storage,
        serde_json::json!({"operation_id": OP, "dry_run": true}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched");
    assert_eq!(backend.opens(), 0);
}

#[tokio::test]
async fn status_advertises_channel_open_operations() {
    let state =
        test_state_with_lightning_and_storage(Arc::new(OpenBackend::default()), sqlite().await);
    let request = Request::builder()
        .uri("/api/v1/status")
        .header("authorization", auth_header(&state))
        .body(Body::empty())
        .unwrap();
    let response = test_router(state).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(body["api_capabilities"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("channel_open_operations_v1")));
}
