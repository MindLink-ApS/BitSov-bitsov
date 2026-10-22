mod common;

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails,
};
use konsensus_storage::{ChannelOpenOperation, SqliteStorage, Storage};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::Semaphore;
use tower::ServiceExt;

const ID: &str = "2abe1acf-5844-4824-ae48-575db0ec7561";
const ADDRESS: &str = "bcrt1qstubfundingaddress0000000000000000000000";
const TXID: &str = "abababababababababababababababababababababababababababababababab";

#[derive(Clone, Copy)]
enum Outcome {
    Sent,
    Unconfirmed,
    Refused,
    NotReady,
    Unknown,
    UnknownWithTxid,
}

struct Wallet {
    calls: AtomicUsize,
    started: Semaphore,
    proceed: Semaphore,
    outcome: Outcome,
    ready_barrier: Option<tokio::sync::Barrier>,
}

impl Wallet {
    fn new(outcome: Outcome, blocked: bool) -> Arc<Self> {
        Arc::new(Self {
            calls: AtomicUsize::new(0),
            started: Semaphore::new(0),
            proceed: Semaphore::new(if blocked { 0 } else { 32 }),
            outcome,
            ready_barrier: None,
        })
    }
}

#[async_trait]
impl LightningProvider for Wallet {
    async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        unreachable!()
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        unreachable!()
    }
    async fn pay_invoice_with_fee_limit(
        &self,
        _: &str,
        _: u64,
    ) -> Result<PaymentDetails, LightningError> {
        unreachable!()
    }
    async fn keysend_with_fee_limit(
        &self,
        _: &str,
        _: u64,
        _: Option<&str>,
        _: u64,
    ) -> Result<PaymentDetails, LightningError> {
        unreachable!()
    }
    async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        unreachable!()
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn money_ready(&self) -> bool {
        if let Some(barrier) = &self.ready_barrier {
            barrier.wait().await;
        }
        true
    }
    async fn send_onchain(
        &self,
        address: &str,
        amount: u64,
        rate: Option<f32>,
    ) -> Result<String, LightningError> {
        assert_eq!((address, amount, rate), (ADDRESS, 10_000, Some(5.0)));
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.started.add_permits(1);
        self.proceed.acquire().await.unwrap().forget();
        match self.outcome {
            Outcome::Sent => Ok(TXID.into()),
            Outcome::Unconfirmed => Err(LightningError::BroadcastUnconfirmed { txid: TXID.into() }),
            Outcome::Refused => Err(LightningError::PaymentNotDispatched(
                "invalid address".into(),
            )),
            Outcome::NotReady => Err(LightningError::NotReady),
            Outcome::Unknown => Err(LightningError::Backend("connection lost".into())),
            Outcome::UnknownWithTxid => Err(LightningError::Backend(format!(
                "transaction {TXID} accepted but wallet reservation update failed: disk failure"
            ))),
        }
    }
}

fn body() -> Value {
    json!({"request_id": ID, "address": ADDRESS, "amount_sats": 10_000, "fee_rate_sat_per_vb": 5.0})
}

async fn post(app: axum::Router, auth: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/payments/send-onchain")
                .header("authorization", auth)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({"error": String::from_utf8_lossy(&bytes)})),
    )
}

async fn setup(wallet: Arc<Wallet>) -> (tempfile::TempDir, axum::Router, String) {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(
        SqliteStorage::open(dir.path().join("operations.db").to_str().unwrap())
            .await
            .unwrap(),
    );
    let state = common::test_state_with_lightning_and_storage(wallet, db);
    let auth = common::auth_header(&state);
    (dir, common::test_router(state), auth)
}

// Replays during a blocked send must return promptly without calling the wallet again.
#[tokio::test]
async fn concurrent_same_id_dispatches_once_and_replays_original_result() {
    let wallet = Wallet::new(Outcome::Sent, true);
    let (_dir, app, auth) = setup(wallet.clone()).await;
    let first = tokio::spawn({
        let app = app.clone();
        let auth = auth.clone();
        async move { post(app, &auth, body()).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), wallet.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let mut replays = Vec::new();
    for _ in 0..8 {
        let app = app.clone();
        let auth = auth.clone();
        replays.push(tokio::spawn(async move { post(app, &auth, body()).await }));
    }
    for replay in replays {
        let (status, receipt) = tokio::time::timeout(std::time::Duration::from_secs(5), replay)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(receipt["request_id"], ID);
        assert_eq!(receipt["status"], "pending");
    }
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    wallet.proceed.add_permits(1);
    let original = first.await.unwrap();
    assert_eq!(original.0, StatusCode::OK);
    assert_eq!(original.1["txid"], TXID);
    assert_eq!(post(app, &auth, body()).await, original);
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
}

// Every money-affecting field is bound, including an omitted estimator override.
#[tokio::test]
async fn different_body_is_refused_without_dispatch() {
    let wallet = Wallet::new(Outcome::Sent, false);
    let (_dir, app, auth) = setup(wallet.clone()).await;
    assert_eq!(post(app.clone(), &auth, body()).await.0, StatusCode::OK);
    for (field, value) in [
        ("address", json!("bcrt1qdifferent")),
        ("amount_sats", json!(20_000)),
        ("fee_rate_sat_per_vb", json!(6.0)),
        ("fee_rate_sat_per_vb", Value::Null),
    ] {
        let mut changed = body();
        changed[field] = value;
        let (status, response) = post(app.clone(), &auth, changed).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(response["code"], "operation_mismatch");
    }
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
}

// A durable record with no receipt is not proof that dispatch never happened.
#[tokio::test]
async fn crash_left_pending_row_is_retained_without_resending() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("operations.db");
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let request = serde_json::to_vec(&json!({"address": ADDRESS, "amount_sats": 10_000,
        "fee_rate_sat_per_vb_bits": 5.0_f32.to_bits()}))
    .unwrap();
    let op = ChannelOpenOperation::pending(
        format!("send-onchain:{ID}"),
        hex::encode(Sha256::digest(&request)),
        request,
    );
    assert!(db.insert_channel_open_operation(&op).await.unwrap());
    drop(db); // Simulate loss of all process state immediately after the durable insert.
    let wallet = Wallet::new(Outcome::Sent, false);
    for _ in 0..2 {
        let db = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
        let state = common::test_state_with_lightning_and_storage(wallet.clone(), db);
        let auth = common::auth_header(&state);
        let (status, receipt) = post(common::test_router(state), &auth, body()).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(receipt["status"], "pending");
        assert_eq!(receipt["request_id"], ID);
        assert!(receipt.get("txid").is_none());
    }
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn terminal_and_uncertain_outcomes_survive_restart_without_redispatch() {
    for (outcome, expected) in [
        (Outcome::Sent, StatusCode::OK),
        (Outcome::Unconfirmed, StatusCode::ACCEPTED),
        (Outcome::Unknown, StatusCode::ACCEPTED),
        (Outcome::UnknownWithTxid, StatusCode::ACCEPTED),
    ] {
        let wallet = Wallet::new(outcome, false);
        let (dir, app, auth) = setup(wallet.clone()).await;
        let original = post(app, &auth, body()).await;
        assert_eq!(original.0, expected);
        let db = Arc::new(
            SqliteStorage::open(dir.path().join("operations.db").to_str().unwrap())
                .await
                .unwrap(),
        );
        let state = common::test_state_with_lightning_and_storage(wallet.clone(), db);
        let auth = common::auth_header(&state);
        assert_eq!(
            post(common::test_router(state), &auth, body()).await,
            original
        );
        assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn disconnected_client_does_not_cancel_outcome_recording() {
    let wallet = Wallet::new(Outcome::Sent, true);
    let (_dir, app, auth) = setup(wallet.clone()).await;
    let request = tokio::spawn({
        let app = app.clone();
        let auth = auth.clone();
        async move { post(app, &auth, body()).await }
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), wallet.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    wallet.proceed.add_permits(1);
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let (status, receipt) = post(app.clone(), &auth, body()).await;
            if status == StatusCode::OK {
                assert_eq!(receipt["txid"], TXID);
                break;
            }
            assert_eq!(status, StatusCode::ACCEPTED);
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn invalid_id_and_invalid_fee_never_dispatch_but_legacy_requests_still_work() {
    let wallet = Wallet::new(Outcome::Sent, false);
    let (_dir, app, auth) = setup(wallet.clone()).await;
    for id in [
        "not-a-uuid",
        "00000000-0000-0000-0000-000000000000",
        "2abe1acf-5844-1824-ae48-575db0ec7561",
        "2abe1acf-5844-7824-ae48-575db0ec7561",
        "2abe1acf-5844-4824-0e48-575db0ec7561",
    ] {
        let mut invalid = body();
        invalid["request_id"] = json!(id);
        assert_eq!(
            post(app.clone(), &auth, invalid).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    for rate in [0.0, -1.0, 0.5, 10_001.0] {
        let mut invalid = body();
        invalid["fee_rate_sat_per_vb"] = json!(rate);
        assert_eq!(
            post(app.clone(), &auth, invalid).await.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
    let mut legacy = body();
    legacy.as_object_mut().unwrap().remove("request_id");
    assert_eq!(
        post(app.clone(), &auth, legacy.clone()).await.0,
        StatusCode::OK
    );
    assert_eq!(post(app, &auth, legacy).await.0, StatusCode::OK);
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 2);
}

// Losing the pre-dispatch record must prevent any wallet call and hide DB details.
#[tokio::test]
async fn durable_record_failure_never_dispatches_or_leaks_db_details() {
    let wallet = Wallet::new(Outcome::Sent, false);
    let (dir, app, auth) = setup(wallet.clone()).await;
    let pool = sqlx::SqlitePool::connect(&format!(
        "sqlite:{}",
        dir.path().join("operations.db").display()
    ))
    .await
    .unwrap();
    sqlx::query("CREATE TRIGGER fail_operation_write BEFORE INSERT ON channel_open_operations BEGIN SELECT RAISE(FAIL, 'private database details'); END")
        .execute(&pool).await.unwrap();
    let (status, response) = post(app, &auth, body()).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(!response.to_string().contains("private database details"));
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 0);
}

// Returning 500 after broadcast hides the txid and encourages a second send.
#[tokio::test]
async fn receipt_failure_returns_txid_and_retries_persistence_without_resending() {
    for (outcome, expected) in [
        (Outcome::Sent, StatusCode::OK),
        (Outcome::Unconfirmed, StatusCode::ACCEPTED),
    ] {
        let wallet = Wallet::new(outcome, false);
        let (dir, app, auth) = setup(wallet.clone()).await;
        let path = dir.path().join("operations.db");
        let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path.display()))
            .await
            .unwrap();
        sqlx::query("CREATE TRIGGER fail_operation_write BEFORE UPDATE ON channel_open_operations BEGIN SELECT RAISE(FAIL, 'simulated disk failure'); END")
            .execute(&pool).await.unwrap();
        let original = post(app.clone(), &auth, body()).await;
        assert_eq!(original.0, expected);
        assert_eq!(original.1["txid"], TXID);
        assert_eq!(original.1["request_id"], ID);
        let pending = post(app.clone(), &auth, body()).await;
        assert_eq!(pending.0, StatusCode::ACCEPTED);
        assert_eq!(pending.1["status"], "pending");
        assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
        sqlx::query("DROP TRIGGER fail_operation_write")
            .execute(&pool)
            .await
            .unwrap();
        let db = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if db
                    .get_channel_open_operation(&format!("send-onchain:{ID}"))
                    .await
                    .unwrap()
                    .unwrap()
                    .result
                    .is_some()
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        drop(app);
        let state = common::test_state_with_lightning_and_storage(wallet.clone(), db);
        let auth = common::auth_header(&state);
        assert_eq!(
            post(common::test_router(state), &auth, body()).await,
            original
        );
        assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn proven_refusal_releases_id_for_retry_after_restart() {
    for (outcome, expected) in [
        (Outcome::Refused, StatusCode::BAD_REQUEST),
        (Outcome::NotReady, StatusCode::SERVICE_UNAVAILABLE),
    ] {
        let wallet = Wallet::new(outcome, false);
        let (dir, app, auth) = setup(wallet.clone()).await;
        assert_eq!(post(app, &auth, body()).await.0, expected);
        assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
        let db = Arc::new(
            SqliteStorage::open(dir.path().join("operations.db").to_str().unwrap())
                .await
                .unwrap(),
        );
        assert!(db
            .get_channel_open_operation(&format!("send-onchain:{ID}"))
            .await
            .unwrap()
            .is_none());
        let ready_wallet = Wallet::new(Outcome::Sent, false);
        let state = common::test_state_with_lightning_and_storage(ready_wallet.clone(), db);
        let auth = common::auth_header(&state);
        let app = common::test_router(state);
        let original = post(app.clone(), &auth, body()).await;
        assert_eq!(original.0, StatusCode::OK);
        assert_eq!(post(app, &auth, body()).await, original);
        assert_eq!(ready_wallet.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn refusal_release_failure_keeps_pending_row_and_never_resends() {
    for outcome in [Outcome::Refused, Outcome::NotReady] {
        let wallet = Wallet::new(outcome, false);
        let (dir, app, auth) = setup(wallet.clone()).await;
        let path = dir.path().join("operations.db");
        let pool = sqlx::SqlitePool::connect(&format!("sqlite:{}", path.display()))
            .await
            .unwrap();
        sqlx::query("CREATE TRIGGER fail_release BEFORE DELETE ON channel_open_operations BEGIN SELECT RAISE(FAIL, 'simulated disk failure'); END")
            .execute(&pool).await.unwrap();
        let (status, _) = post(app.clone(), &auth, body()).await;
        assert!(status == StatusCode::BAD_REQUEST || status == StatusCode::SERVICE_UNAVAILABLE);
        sqlx::query("DROP TRIGGER fail_release")
            .execute(&pool)
            .await
            .unwrap();
        for _ in 0..2 {
            let (status, response) = post(app.clone(), &auth, body()).await;
            assert_eq!(status, StatusCode::ACCEPTED);
            assert_eq!(response["status"], "pending");
        }
        assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn ambiguous_error_keeps_txid_in_durable_row() {
    let wallet = Wallet::new(Outcome::UnknownWithTxid, false);
    let (dir, app, auth) = setup(wallet.clone()).await;
    assert_eq!(post(app, &auth, body()).await.0, StatusCode::ACCEPTED);
    let db = SqliteStorage::open(dir.path().join("operations.db").to_str().unwrap())
        .await
        .unwrap();
    let op = db
        .get_channel_open_operation(&format!("send-onchain:{ID}"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(op.state, "uncertain");
    assert!(op.last_error.unwrap().contains(TXID));
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn null_request_id_uses_legacy_path_without_retry_protection() {
    let wallet = Wallet::new(Outcome::Sent, false);
    let (dir, app, auth) = setup(wallet.clone()).await;
    let mut request = body();
    request["request_id"] = Value::Null;
    for _ in 0..2 {
        let (status, response) = post(app.clone(), &auth, request.clone()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response["txid"], TXID);
        assert!(response.get("request_id").is_none());
    }
    let pool = sqlx::SqlitePool::connect(&format!(
        "sqlite:{}",
        dir.path().join("operations.db").display()
    ))
    .await
    .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM channel_open_operations")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn canonical_uuid_replays_and_cannot_collide_with_channel_open() {
    let wallet = Wallet::new(Outcome::Sent, false);
    let (dir, app, auth) = setup(wallet.clone()).await;
    let db = SqliteStorage::open(dir.path().join("operations.db").to_str().unwrap())
        .await
        .unwrap();
    let channel =
        ChannelOpenOperation::pending(ID.into(), "channel request hash".into(), b"{}".to_vec());
    assert!(db.insert_channel_open_operation(&channel).await.unwrap());
    let original = post(app.clone(), &auth, body()).await;
    assert_eq!(original.0, StatusCode::OK);
    let mut equivalent = body();
    equivalent["request_id"] = ID.to_ascii_uppercase().into();
    assert_eq!(post(app, &auth, equivalent).await, original);
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        db.get_channel_open_operation(ID).await.unwrap().unwrap(),
        channel
    );
}

// The readiness barrier ensures both requests observed no row before either inserts.
// Removing the insert-loser return would dispatch both sends and fail the count.
#[tokio::test]
async fn concurrent_new_requests_race_the_durable_insert_and_send_once() {
    let mut wallet = Wallet::new(Outcome::Sent, false);
    Arc::get_mut(&mut wallet).unwrap().ready_barrier = Some(tokio::sync::Barrier::new(2));
    let (_dir, app, auth) = setup(wallet.clone()).await;
    let (a, b) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            post(app.clone(), &auth, body()),
            post(app.clone(), &auth, body())
        )
    })
    .await
    .unwrap();
    assert_eq!(wallet.calls.load(Ordering::SeqCst), 1);
    assert!(a.0 == StatusCode::OK || b.0 == StatusCode::OK);
    for (status, receipt) in [a, b] {
        assert!(status == StatusCode::OK || status == StatusCode::ACCEPTED);
        assert_eq!(receipt["request_id"], ID);
        if status == StatusCode::OK {
            assert_eq!(receipt["txid"], TXID);
        }
    }
}
