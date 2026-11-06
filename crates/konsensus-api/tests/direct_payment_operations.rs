//! Payment truth on the owner API: `POST /payments/pay` and `/payments/keysend`
//! answer `202 in_flight` until the backend reports a final state, require a
//! client `request_id`, and never dispatch twice under one id.

mod common;

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use common::*;
use konsensus_api::state::AppState;
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus,
};
use konsensus_storage::{SqliteStorage, Storage};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tower::ServiceExt;

const DEST: &str = "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

/// What the backend does with the next dispatch, and what it reports on polls.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    /// Settles synchronously.
    Settle,
    /// Dispatches, then stays in flight on every poll.
    InFlight,
    /// Dispatches, then reports a positive failure.
    Failed,
    /// Dispatches, then loses the response; polls say in flight.
    Unknown,
    /// Refuses before anything leaves.
    Refused,
}

struct Wallet {
    mode: Mutex<Mode>,
    dispatches: AtomicUsize,
    /// Outgoing payments the backend knows: hash → (amount, preimage).
    outgoing: Mutex<HashMap<String, (u64, String)>>,
    /// Test gates: while armed, a dispatch (or the next status read) signals
    /// that it was entered and parks until the test releases it.
    gate_dispatch: std::sync::atomic::AtomicBool,
    dispatch_entered: tokio::sync::Notify,
    dispatch_gate: tokio::sync::Semaphore,
    gate_status: std::sync::atomic::AtomicBool,
    status_entered: tokio::sync::Notify,
    status_gate: tokio::sync::Semaphore,
}

impl Wallet {
    fn new(mode: Mode) -> Arc<Self> {
        Arc::new(Self {
            mode: Mutex::new(mode),
            dispatches: AtomicUsize::new(0),
            outgoing: Mutex::new(HashMap::new()),
            gate_dispatch: std::sync::atomic::AtomicBool::new(false),
            dispatch_entered: tokio::sync::Notify::new(),
            dispatch_gate: tokio::sync::Semaphore::new(0),
            gate_status: std::sync::atomic::AtomicBool::new(false),
            status_entered: tokio::sync::Notify::new(),
            status_gate: tokio::sync::Semaphore::new(0),
        })
    }
    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }
    fn mode(&self) -> Mode {
        *self.mode.lock().unwrap()
    }
    fn dispatches(&self) -> usize {
        self.dispatches.load(Ordering::SeqCst)
    }
    fn details(hash: &str, amount: u64, preimage: &str, status: PaymentStatus) -> PaymentDetails {
        PaymentDetails {
            payment_hash: hash.into(),
            preimage: (status == PaymentStatus::Settled).then(|| preimage.into()),
            amount_msat: amount,
            status,
            direction: PaymentDirection::Outgoing,
            timestamp: 1_700_000_000,
            memo: None,
            fee_msat: Some(0),
        }
    }
    async fn dispatch(
        &self,
        hash: String,
        amount: u64,
        preimage: String,
    ) -> Result<PaymentDetails, LightningError> {
        self.dispatches.fetch_add(1, Ordering::SeqCst);
        if self.gate_dispatch.load(Ordering::SeqCst) {
            self.dispatch_entered.notify_one();
            self.dispatch_gate.acquire().await.unwrap().forget();
        }
        tokio::task::yield_now().await;
        let mode = self.mode();
        if mode == Mode::Refused {
            return Err(LightningError::PaymentNotDispatched("local refusal".into()));
        }
        self.outgoing
            .lock()
            .unwrap()
            .insert(hash.clone(), (amount, preimage.clone()));
        match mode {
            Mode::Settle => Ok(Self::details(
                &hash,
                amount,
                &preimage,
                PaymentStatus::Settled,
            )),
            Mode::InFlight => Ok(Self::details(
                &hash,
                amount,
                &preimage,
                PaymentStatus::InFlight,
            )),
            Mode::Failed => Ok(Self::details(
                &hash,
                amount,
                &preimage,
                PaymentStatus::Failed,
            )),
            Mode::Unknown => Err(LightningError::Connection(
                "response lost after dispatch".into(),
            )),
            Mode::Refused => unreachable!(),
        }
    }
}

#[async_trait]
impl LightningProvider for Wallet {
    async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        unreachable!()
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        unreachable!("unbounded pay_invoice must never be used")
    }
    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        _: u64,
    ) -> Result<PaymentDetails, LightningError> {
        let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
        let hash = invoice.payment_hash().to_string();
        let amount = invoice.amount_milli_satoshis().unwrap();
        self.dispatch(hash, amount, "cc".repeat(32)).await
    }
    async fn keysend(
        &self,
        _: &str,
        _: u64,
        _: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        unreachable!("unbounded keysend must never be used")
    }
    async fn keysend_with_fee_limit(
        &self,
        _: &str,
        amount: u64,
        _: Option<&str>,
        _: u64,
    ) -> Result<PaymentDetails, LightningError> {
        let preimage: [u8; 32] = rand::random();
        let hash = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(preimage));
        self.dispatch(hash, amount, hex::encode(preimage)).await
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        if self.gate_status.swap(false, Ordering::SeqCst) {
            self.status_entered.notify_one();
            self.status_gate.acquire().await.unwrap().forget();
        }
        let known = self.outgoing.lock().unwrap().get(hash).cloned();
        let Some((amount, preimage)) = known else {
            return Err(LightningError::PaymentNotFound(hash.into()));
        };
        let status = match self.mode() {
            Mode::Settle => PaymentStatus::Settled,
            Mode::InFlight | Mode::Unknown => PaymentStatus::InFlight,
            Mode::Failed => PaymentStatus::Failed,
            Mode::Refused => return Err(LightningError::PaymentNotFound(hash.into())),
        };
        Ok(Self::details(hash, amount, &preimage, status))
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn money_ready(&self) -> bool {
        true
    }
}

async fn post(state: &Arc<AppState>, route: &str, body: Value) -> (StatusCode, Value) {
    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/api/v1/payments/{route}"))
                .header("authorization", auth_header(state))
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 16384)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"error": String::from_utf8_lossy(&bytes)})),
    )
}

fn pay_body(id: &str, bolt11: &str) -> Value {
    json!({"request_id": id, "bolt11": bolt11})
}

fn keysend_body(id: &str) -> Value {
    json!({"request_id": id, "dest_pubkey": DEST, "amount_msat": 1000})
}

fn assert_in_flight(body: &Value, route: &str, id: &str) {
    assert_eq!(body["status"], "in_flight", "{body}");
    assert_eq!(body["preimage"], "", "{body}");
    assert!(body.get("fee_paid_msat").is_none(), "{body}");
    assert_eq!(body["request_id"], id, "{body}");
    assert_eq!(
        body["operation_id"],
        format!("{route}:owner:{id}"),
        "{body}"
    );
    assert!(
        body["message"].as_str().unwrap().contains("Not settled"),
        "{body}"
    );
}

fn assert_settled(body: &Value, route: &str, id: &str) {
    assert_eq!(body["status"], "settled", "{body}");
    assert_eq!(body["preimage"].as_str().unwrap().len(), 64, "{body}");
    assert_eq!(body["payment_hash"].as_str().unwrap().len(), 64, "{body}");
    assert_eq!(body["amount_msat"], 1000, "{body}");
    assert_eq!(body["request_id"], id, "{body}");
    assert_eq!(
        body["operation_id"],
        format!("{route}:owner:{id}"),
        "{body}"
    );
    assert!(body.get("message").is_none(), "{body}");
}

#[tokio::test]
async fn missing_request_id_is_400_and_dispatches_nothing() {
    let wallet = Wallet::new(Mode::Settle);
    let state = test_state_with_lightning(wallet.clone());
    for (route, body) in [
        ("pay", json!({"bolt11": create_test_bolt11(1000)})),
        ("keysend", json!({"dest_pubkey": DEST, "amount_msat": 1000})),
        (
            "pay",
            json!({"request_id": "", "bolt11": create_test_bolt11(1000)}),
        ),
        (
            "keysend",
            json!({"request_id": "has space", "dest_pubkey": DEST, "amount_msat": 1000}),
        ),
    ] {
        let (status, response) = post(&state, route, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{route}: {response}");
        assert!(
            response["error"].as_str().unwrap().contains("request_id"),
            "{route}: {response}"
        );
    }
    assert_eq!(wallet.dispatches(), 0);
}

#[tokio::test]
async fn in_flight_pay_is_202_until_the_backend_settles_it() {
    let wallet = Wallet::new(Mode::InFlight);
    let state = test_state_with_lightning(wallet.clone());
    let bolt11 = create_test_bolt11(1000);
    let (status, body) = post(&state, "pay", pay_body("inflight-pay", &bolt11)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_in_flight(&body, "pay", "inflight-pay");
    assert_eq!(body["payment_hash"].as_str().unwrap().len(), 64);
    assert!(body.get("replayed").is_none());
    assert_eq!(wallet.dispatches(), 1);

    // Still in flight: the retry is the same operation, nothing dispatched.
    let (status, body) = post(&state, "pay", pay_body("inflight-pay", &bolt11)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_in_flight(&body, "pay", "inflight-pay");
    assert_eq!(body["replayed"], true);
    assert_eq!(wallet.dispatches(), 1);

    // The backend settles: the retry reports it with the proof, once recorded
    // the receipt answers without a backend read.
    wallet.set(Mode::Settle);
    let (status, body) = post(&state, "pay", pay_body("inflight-pay", &bolt11)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_settled(&body, "pay", "inflight-pay");
    assert_eq!(body["preimage"], "cc".repeat(32));
    assert_eq!(body["replayed"], true);
    let row = state
        .storage
        .get_channel_open_operation("pay:owner:inflight-pay")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.state, "opened");
    wallet.set(Mode::Refused);
    let (status, body) = post(&state, "pay", pay_body("inflight-pay", &bolt11)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_settled(&body, "pay", "inflight-pay");
    assert_eq!(wallet.dispatches(), 1);
}

#[tokio::test]
async fn in_flight_keysend_is_202_and_a_failed_outcome_is_an_error() {
    let wallet = Wallet::new(Mode::InFlight);
    let state = test_state_with_lightning(wallet.clone());
    let (status, body) = post(&state, "keysend", keysend_body("inflight-ks")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_in_flight(&body, "keysend", "inflight-ks");
    assert_eq!(body["payment_hash"].as_str().unwrap().len(), 64);
    assert_eq!(wallet.dispatches(), 1);

    wallet.set(Mode::Failed);
    let (status, body) = post(&state, "keysend", keysend_body("inflight-ks")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"], "keysend payment failed before settlement");
    assert!(body["max_routing_fee_msat"].is_number(), "{body}");
    // Final: a later poll would say settled, but the record does not change.
    wallet.set(Mode::Settle);
    let (status, body) = post(&state, "keysend", keysend_body("inflight-ks")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(wallet.dispatches(), 1);
}

#[tokio::test]
async fn repeated_request_id_dispatches_once_sequentially_concurrently_and_across_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payments.db");
    let db = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
    let wallet = Wallet::new(Mode::Settle);
    let state = test_state_with_lightning_and_storage(wallet.clone(), db);
    let bolt11 = create_test_bolt11(1000);

    let (status, first) = post(&state, "pay", pay_body("once", &bolt11)).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_settled(&first, "pay", "once");
    assert!(first.get("replayed").is_none());
    let (status, again) = post(&state, "pay", pay_body("once", &bolt11)).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["replayed"], true);
    assert_eq!(again["payment_hash"], first["payment_hash"]);
    assert_eq!(again["preimage"], first["preimage"]);
    assert_eq!(wallet.dispatches(), 1);

    // Concurrent retries of one id while the first attempt is in flight.
    wallet.set(Mode::InFlight);
    let posts = (0..8).map(|_| post(&state, "keysend", keysend_body("burst")));
    let results = futures::future::join_all(posts).await;
    for (status, body) in &results {
        assert_eq!(*status, StatusCode::ACCEPTED, "{body}");
        assert_eq!(body["status"], "in_flight", "{body}");
    }
    assert_eq!(wallet.dispatches(), 2);
    wallet.set(Mode::Settle);
    let (status, body) = post(&state, "keysend", keysend_body("burst")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_settled(&body, "keysend", "burst");
    assert_eq!(wallet.dispatches(), 2);

    // Restart: the records outlive the process; the wallet would pay again.
    drop(state);
    let db = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
    let state = test_state_with_lightning_and_storage(wallet.clone(), db);
    let (status, body) = post(&state, "pay", pay_body("once", &bolt11)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["replayed"], true);
    assert_eq!(body["payment_hash"], first["payment_hash"]);
    let (status, body) = post(&state, "keysend", keysend_body("burst")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["replayed"], true);
    assert_eq!(wallet.dispatches(), 2);
}

#[tokio::test]
async fn same_id_with_other_parameters_is_409_and_never_pays() {
    let wallet = Wallet::new(Mode::Settle);
    let state = test_state_with_lightning(wallet.clone());
    let bolt11 = create_test_bolt11(1000);
    let (status, _) = post(&state, "pay", pay_body("bound", &bolt11)).await;
    assert_eq!(status, StatusCode::OK);
    for body in [
        pay_body("bound", &create_test_bolt11_with_hash(1000, [0xdd; 32])),
        json!({"request_id": "bound", "bolt11": bolt11, "max_routing_fee_msat": 1}),
    ] {
        let (status, response) = post(&state, "pay", body).await;
        assert_eq!(status, StatusCode::CONFLICT, "{response}");
        assert_eq!(response["code"], "operation_mismatch");
    }
    // Ids are per route: the same id is a different keysend operation.
    let (status, _) = post(&state, "keysend", keysend_body("bound")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wallet.dispatches(), 2);
}

#[tokio::test]
async fn refusal_before_dispatch_frees_the_id_and_a_failure_binds_it() {
    let wallet = Wallet::new(Mode::Refused);
    let state = test_state_with_lightning(wallet.clone());
    let bolt11 = create_test_bolt11(1000);
    let (status, body) = post(&state, "pay", pay_body("refused", &bolt11)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched");
    assert!(state
        .storage
        .get_channel_open_operation("pay:owner:refused")
        .await
        .unwrap()
        .is_none());
    wallet.set(Mode::Settle);
    let (status, body) = post(&state, "pay", pay_body("refused", &bolt11)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_settled(&body, "pay", "refused");
    assert_eq!(wallet.dispatches(), 2);

    wallet.set(Mode::Failed);
    let (status, body) = post(&state, "keysend", keysend_body("failed")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"], "keysend payment failed before settlement");
    wallet.set(Mode::Settle);
    let (status, body) = post(&state, "keysend", keysend_body("failed")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(wallet.dispatches(), 3);
    let (status, _) = post(&state, "keysend", keysend_body("failed-2")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(wallet.dispatches(), 4);
}

#[tokio::test]
async fn ambiguous_outcome_is_its_error_and_the_retry_reads_backend_truth() {
    let wallet = Wallet::new(Mode::Unknown);
    let state = test_state_with_lightning(wallet.clone());
    let bolt11 = create_test_bolt11(1000);
    let (status, body) = post(&state, "pay", pay_body("lost", &bolt11)).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(wallet.dispatches(), 1);
    // Not final yet: the retry is 202, carries the hash, and does not pay.
    let (status, body) = post(&state, "pay", pay_body("lost", &bolt11)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_in_flight(&body, "pay", "lost");
    assert_eq!(body["payment_hash"].as_str().unwrap().len(), 64);
    assert!(body["last_error"].is_string(), "{body}");
    wallet.set(Mode::Settle);
    let (status, body) = post(&state, "pay", pay_body("lost", &bolt11)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_settled(&body, "pay", "lost");
    assert_eq!(wallet.dispatches(), 1);

    // A keysend has no hash before the backend answers: it stays unresolved.
    wallet.set(Mode::Unknown);
    let (status, _) = post(&state, "keysend", keysend_body("lost-ks")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    wallet.set(Mode::Settle);
    let (status, body) = post(&state, "keysend", keysend_body("lost-ks")).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["payment_hash"], "");
    assert_eq!(wallet.dispatches(), 2);
}

#[tokio::test]
async fn an_incoming_record_under_the_same_hash_is_not_settlement() {
    // A self-payment's invoice (or someone else paying it) is an incoming
    // record under the same hash; it must never turn an unsettled outgoing
    // payment into "settled".
    struct Mirror(Arc<Wallet>);
    #[async_trait]
    impl LightningProvider for Mirror {
        async fn create_invoice(&self, a: u64, d: &str, e: u32) -> Result<Invoice, LightningError> {
            self.0.create_invoice(a, d, e).await
        }
        async fn pay_invoice(&self, b: &str) -> Result<PaymentDetails, LightningError> {
            self.0.pay_invoice(b).await
        }
        async fn pay_invoice_with_fee_limit(
            &self,
            b: &str,
            c: u64,
        ) -> Result<PaymentDetails, LightningError> {
            self.0.pay_invoice_with_fee_limit(b, c).await
        }
        async fn keysend_with_fee_limit(
            &self,
            d: &str,
            a: u64,
            m: Option<&str>,
            c: u64,
        ) -> Result<PaymentDetails, LightningError> {
            self.0.keysend_with_fee_limit(d, a, m, c).await
        }
        async fn get_payment_status(&self, h: &str) -> Result<PaymentDetails, LightningError> {
            let mut details = self.0.get_payment_status(h).await?;
            details.direction = PaymentDirection::Incoming;
            details.status = PaymentStatus::Settled;
            details.preimage = Some("cc".repeat(32));
            Ok(details)
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(0)
        }
        async fn is_available(&self) -> bool {
            true
        }
        async fn money_ready(&self) -> bool {
            true
        }
    }
    let wallet = Wallet::new(Mode::InFlight);
    let state = test_state_with_lightning(Arc::new(Mirror(wallet.clone())));
    let bolt11 = create_test_bolt11(1000);
    for _ in 0..2 {
        let (status, body) = post(&state, "pay", pay_body("mirror", &bolt11)).await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        assert_in_flight(&body, "pay", "mirror");
    }
    assert_eq!(wallet.dispatches(), 1);
}

#[tokio::test]
async fn status_advertises_direct_payment_operations() {
    let state = test_state_with_lightning(Wallet::new(Mode::Settle));
    let response = test_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/api/v1/status")
                .header("authorization", auth_header(&state))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), 65536)
            .await
            .unwrap(),
    )
    .unwrap();
    assert!(
        body["api_capabilities"]
            .as_array()
            .unwrap()
            .contains(&json!("direct_payment_operations_v1")),
        "{body}"
    );
}

/// A replay that read a pending row, then waited on the backend, must not
/// attach its result to a row that was freed by a refusal and re-created for
/// another request under the same id. The unpaid replacement never becomes
/// "settled", and its own outcome still gets recorded.
#[tokio::test]
async fn stale_replay_cannot_finalize_a_reused_id_with_another_requests_receipt() {
    let wallet = Wallet::new(Mode::Settle);
    let storage = Arc::new(MemStorage::new());
    let state = test_state_with_lightning_and_storage(wallet.clone(), storage.clone());
    let first = create_test_bolt11(1000);
    let replacement = create_test_bolt11_with_hash(1000, [0xdd; 32]);
    // The backend knows `first` as settled from an earlier, unrelated operation.
    let (status, paid) = post(&state, "pay", pay_body("earlier", &first)).await;
    assert_eq!(status, StatusCode::OK, "{paid}");

    // A: pay `first` under "reuse"; parks inside the backend before it is refused.
    wallet.set(Mode::Refused);
    wallet.gate_dispatch.store(true, Ordering::SeqCst);
    let a = tokio::spawn({
        let state = state.clone();
        let first = first.clone();
        async move { post(&state, "pay", pay_body("reuse", &first)).await }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        wallet.dispatch_entered.notified(),
    )
    .await
    .unwrap();
    // B: a retry of A reads the pending row, then parks in its status read.
    wallet.gate_status.store(true, Ordering::SeqCst);
    let b = tokio::spawn({
        let state = state.clone();
        let first = first.clone();
        async move { post(&state, "pay", pay_body("reuse", &first)).await }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        wallet.status_entered.notified(),
    )
    .await
    .unwrap();
    // A is refused before dispatch: the id is freed.
    wallet.dispatch_gate.add_permits(1);
    let (status, body) = a.await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched");
    // C: "reuse" now names a different invoice; its row is pending while B is
    // still waiting on the backend.
    let c = tokio::spawn({
        let state = state.clone();
        let replacement = replacement.clone();
        async move { post(&state, "pay", pay_body("reuse", &replacement)).await }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        wallet.dispatch_entered.notified(),
    )
    .await
    .unwrap();
    // B learns `first` settled (the backend reports the earlier payment), but
    // the row it read is gone: no write, no 200.
    wallet.set(Mode::Settle);
    // B's outcome write fails outright: a storage error proves nothing about
    // the fence, so B must still validate the binding before answering.
    storage.fail_next_outcome_write();
    wallet.status_gate.add_permits(1);
    let (status, body) = b.await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_ne!(body["status"], "settled", "{body}");
    let row = state
        .storage
        .get_channel_open_operation("pay:owner:reuse")
        .await
        .unwrap()
        .expect("C's pending row");
    assert_eq!(row.state, "pending", "{row:?}");
    assert!(row.result.is_none(), "{row:?}");
    // C is refused too: the unpaid replacement is never settled, and the id is free.
    wallet.set(Mode::Refused);
    wallet.dispatch_gate.add_permits(1);
    let (status, body) = c.await.unwrap();
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(state
        .storage
        .get_channel_open_operation("pay:owner:reuse")
        .await
        .unwrap()
        .is_none());
    wallet.gate_dispatch.store(false, Ordering::SeqCst);
    // A retry of C pays its own invoice and records its own receipt.
    wallet.set(Mode::Settle);
    let (status, body) = post(&state, "pay", pay_body("reuse", &replacement)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_settled(&body, "pay", "reuse");
    assert_ne!(body["payment_hash"], paid["payment_hash"], "{body}");
    assert!(body.get("replayed").is_none(), "{body}");
    let (status, again) = post(&state, "pay", pay_body("reuse", &replacement)).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["payment_hash"], body["payment_hash"]);
    assert_eq!(again["replayed"], true);
    assert_eq!(wallet.dispatches(), 4);
}

/// A storage error on a replay's outcome write is not a fence result. The
/// replay answers from backend truth only after the authoritative row shows
/// its own binding, and the fenced retry persists the receipt afterwards.
#[tokio::test]
async fn outcome_write_failure_on_replay_validates_the_binding_before_answering() {
    let wallet = Wallet::new(Mode::InFlight);
    let storage = Arc::new(MemStorage::new());
    let state = test_state_with_lightning_and_storage(wallet.clone(), storage.clone());
    let bolt11 = create_test_bolt11(1000);
    let (status, body) = post(&state, "pay", pay_body("flaky", &bolt11)).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(wallet.dispatches(), 1);

    wallet.set(Mode::Settle);
    storage.fail_next_outcome_write();
    let (status, body) = post(&state, "pay", pay_body("flaky", &bolt11)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_settled(&body, "pay", "flaky");
    assert_eq!(body["replayed"], true);
    assert_eq!(wallet.dispatches(), 1);
    // The retry lands the same fenced write a moment later.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let row = storage
            .get_channel_open_operation("pay:owner:flaky")
            .await
            .unwrap()
            .unwrap();
        if row.state == "opened" {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{row:?}");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    wallet.set(Mode::Refused);
    let (status, body) = post(&state, "pay", pay_body("flaky", &bolt11)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_settled(&body, "pay", "flaky");
    assert_eq!(wallet.dispatches(), 1);
}
