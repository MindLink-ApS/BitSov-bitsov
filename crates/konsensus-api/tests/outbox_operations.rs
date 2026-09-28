#![allow(dead_code)]
mod common;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use konsensus_core::{traits::lightning::LightningProvider, NodeIdentity};
use konsensus_storage::SqliteStorage;
use std::sync::Arc;
use tower::ServiceExt;

#[tokio::test]
async fn concurrent_operation_posts_pay_once_and_mismatch_never_pays() {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(
        SqliteStorage::open(dir.path().join("outbox.db").to_str().unwrap())
            .await
            .unwrap(),
    );
    let wallet = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let mut state = common::test_state_with_lightning(wallet.clone());
    let (_, identity) = NodeIdentity::generate().unwrap();
    let peer = *identity.node_id();
    let target = konsensus_crypto::SessionManager::new(Arc::new(identity));
    state
        .session_manager
        .initiate_session(&peer, &target.prekey_bundle().await)
        .await
        .unwrap();
    state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(peer, format!("02{}", "ab".repeat(32)));
    let transport = Arc::new(common::ConnectedStubTransport::new(
        vec![peer],
        state.invoice_requests.clone(),
    ));
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.storage = db;
    mutable.transport = transport;
    let token = common::auth_header(&state);
    let app = common::test_router(state.clone());
    let id = uuid::Uuid::new_v4().to_string();
    let request = |text: &str| {
        Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization", &token).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"operation_id":id,"recipient":peer.to_hex(),"kind":1,"plaintext":text,"wait_ack_ms":0}).to_string())).unwrap()
    };
    let (a, b) = tokio::join!(
        app.clone().oneshot(request("hello")),
        app.clone().oneshot(request("hello"))
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.status(), StatusCode::OK);
    assert_eq!(b.status(), StatusCode::OK);
    let json = |r: axum::response::Response| async {
        serde_json::from_slice::<serde_json::Value>(
            &axum::body::to_bytes(r.into_body(), 8192).await.unwrap(),
        )
        .unwrap()
    };
    let a = json(a).await;
    let b = json(b).await;
    assert_eq!(a["message_id"], b["message_id"]);
    assert_eq!(a["operation_id"], id);
    assert_eq!(wallet.list_payments(100).await.unwrap().len(), 1);
    let mismatch = app.clone().oneshot(request("different")).await.unwrap();
    assert_eq!(mismatch.status(), StatusCode::CONFLICT);
    assert_eq!(json(mismatch).await["code"], "operation_mismatch");
    let status = app
        .oneshot(
            Request::builder()
                .uri(format!("/api/v1/messages/operations/{id}"))
                .header("authorization", &token)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(json(status).await["operation_id"], id);
    assert_eq!(wallet.list_payments(100).await.unwrap().len(), 1);
}

use konsensus_api::state::AppState;
use konsensus_core::{
    traits::lightning::{Invoice, LightningError, PaymentDetails, PaymentStatus},
    NodeId,
};
use konsensus_storage::Storage;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

struct Wallet {
    inner: konsensus_lightning::MockLightningProvider,
    calls: AtomicUsize,
    mode: AtomicU8,
    pool: sqlx::SqlitePool,
}
#[async_trait::async_trait]
impl LightningProvider for Wallet {
    async fn money_ready(&self) -> bool {
        if self.mode.load(Ordering::SeqCst) == 6 {
            return futures::future::pending().await;
        }
        true
    }
    async fn create_invoice(&self, a: u64, d: &str, e: u32) -> Result<Invoice, LightningError> {
        self.inner.create_invoice(a, d, e).await
    }
    async fn pay_invoice(&self, b: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.pay_invoice(b).await
    }
    async fn keysend_with_fee_limit(
        &self,
        dest: &str,
        amount: u64,
        memo: Option<&str>,
        fee: u64,
    ) -> Result<PaymentDetails, LightningError> {
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM outbox_operations WHERE state = 'paying' AND json_extract(CAST(recovery AS TEXT), '$.dispatched') = 1 AND json_extract(CAST(recovery AS TEXT), '$.draft.id') IS NOT NULL").fetch_one(&self.pool).await.unwrap();
        assert_eq!(rows, 1, "durable draft must precede dispatch");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.mode.load(Ordering::SeqCst) == 1 {
            self.inner.defer_next_keysend_settlement(0).await;
        }
        let mut details = self
            .inner
            .keysend_with_fee_limit(dest, amount, memo, fee)
            .await?;
        match self.mode.load(Ordering::SeqCst) {
            1 => {
                details.status = PaymentStatus::InFlight;
                details.preimage = None;
            }
            3 => return Err(LightningError::Backend("lost dispatch response".into())),
            4 => return futures::future::pending().await,
            _ => {}
        }
        Ok(details)
    }
    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        fee: u64,
    ) -> Result<PaymentDetails, LightningError> {
        let invoice: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
        let saved: Option<String> =
            sqlx::query_scalar("SELECT payment_hash FROM outbox_operations WHERE state = 'paying'")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        assert_eq!(
            saved.as_deref(),
            Some(invoice.payment_hash().to_string().as_str()),
            "invoice hash must be durable before dispatch"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        let details = self.inner.pay_invoice_with_fee_limit(bolt11, fee).await?;
        if self.mode.load(Ordering::SeqCst) == 4 {
            return futures::future::pending().await;
        }
        Ok(details)
    }
    async fn get_payment_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        let mut details = self.inner.get_payment_status(hash).await?;
        match self.mode.load(Ordering::SeqCst) {
            1 => {
                details.status = PaymentStatus::InFlight;
                details.preimage = None;
            }
            2 => {
                details.status = PaymentStatus::Failed;
                details.preimage = None;
            }
            5 => { details.preimage = Some("00".repeat(32)); }
            7 => { details.preimage = None; }
            8 => { details.preimage = Some("not hex".into()); }
            9 => { details.preimage = Some("cd".repeat(31)); }
            _ => {}
        }
        Ok(details)
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        self.inner.get_balance_msat().await
    }
    async fn is_available(&self) -> bool {
        true
    }
}
struct Fixture {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
    db: Arc<SqliteStorage>,
    wallet: Arc<Wallet>,
    state: Arc<AppState>,
    peer: NodeId,
    id: String,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("operations.db");
        let db = Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap());
        let wallet = Arc::new(Wallet {
            inner: konsensus_lightning::MockLightningProvider::new(),
            calls: AtomicUsize::new(0),
            mode: AtomicU8::new(0),
            pool: db.pool().clone(),
        });
        let mut state = common::test_state_with_lightning(wallet.clone());
        let peer = common::setup_e2ee_session(&state.session_manager).await;
        state
            .peer_ln_pubkeys
            .lock()
            .await
            .insert(peer, format!("02{}", "ab".repeat(32)));
        let transport = Arc::new(common::ConnectedStubTransport::new(
            vec![peer],
            state.invoice_requests.clone(),
        ));
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.storage = db.clone();
        mutable.transport = transport;
        Self {
            _dir: dir,
            path,
            db,
            wallet,
            state,
            peer,
            id: uuid::Uuid::new_v4().to_string(),
        }
    }
    async fn restart(&mut self) {
        let db = Arc::new(
            SqliteStorage::open(self.path.to_str().unwrap())
                .await
                .unwrap(),
        );
        let mut state = common::test_state_with_lightning(self.wallet.clone());
        let transport = Arc::new(common::ConnectedStubTransport::new(
            vec![self.peer],
            state.invoice_requests.clone(),
        ));
        let mutable = Arc::get_mut(&mut state).unwrap();
        mutable.storage = db.clone();
        mutable.transport = transport;
        mutable.identity = self.state.identity.clone();
        // Deliberately no sending ratchet and no known Lightning pubkey. Recovery
        // must use the stored ciphertext/proof, never call encrypt or keysend.
        self.db = db;
        self.state = state;
    }
    fn request(&self) -> Request<Body> {
        Request::builder().method("POST").uri("/api/v1/messages/compose")
            .header("authorization", common::auth_header(&self.state)).header("content-type","application/json")
            .body(Body::from(serde_json::json!({"operation_id":self.id,"recipient":self.peer.to_hex(),"kind":1,"plaintext":"crash test","wait_ack_ms":0}).to_string())).unwrap()
    }
    async fn post(&self) -> (StatusCode, serde_json::Value) {
        let response = common::test_router(self.state.clone())
            .oneshot(self.request())
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 16384)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }
    async fn op(&self) -> konsensus_storage::OutboxOperation {
        self.db
            .get_outbox_operation(&self.id)
            .await
            .unwrap()
            .unwrap()
    }
}

#[tokio::test]
async fn storage_crash_boundaries_recover_paid_ciphertext_without_repaying() {
    for (boundary, trigger) in [
        ("settlement journal", "BEFORE UPDATE ON outbox_operations WHEN NEW.payment_hash IS NOT NULL AND OLD.payment_hash IS NULL"),
        ("proof journal", "BEFORE UPDATE ON outbox_operations WHEN json_extract(CAST(NEW.recovery AS TEXT), '$.envelope_ready') = 1"),
        ("message insertion", "BEFORE INSERT ON messages"),
        ("pending insertion", "BEFORE INSERT ON pending_deliveries"),
        ("paid transition", "BEFORE UPDATE ON outbox_operations WHEN NEW.state = 'paid'"),
        ("send intent", "BEFORE UPDATE ON pending_deliveries"),
        ("sent transition", "BEFORE UPDATE ON outbox_operations WHEN NEW.state = 'sent'"),
    ] {
        let mut f = Fixture::new().await;
        sqlx::raw_sql(&format!("CREATE TRIGGER crash {trigger} BEGIN SELECT RAISE(ABORT, 'crash boundary'); END")).execute(f.db.pool()).await.unwrap();
        let (_, body) = f.post().await;
        assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1, "{boundary}: {body}");
        let original_id = f.op().await.message_id;
        sqlx::raw_sql("DROP TRIGGER crash").execute(f.db.pool()).await.unwrap();
        f.restart().await;
        konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
        let (status, receipt) = f.post().await;
        if boundary == "settlement journal" {
            assert_eq!(status, StatusCode::CONFLICT, "untrackable keysend must stay blocked: {receipt}");
            assert_eq!(receipt["code"], "payment_unresolved");
        } else {
            assert_eq!(status, StatusCode::OK, "{boundary}: {receipt}");
            assert_eq!(receipt["message_id"].as_str(), original_id.as_deref());
            assert_eq!(f.db.count_pending_deliveries().await.unwrap(), 1);
        }
        assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1, "{boundary} must never repay");
    }
}

#[tokio::test]
async fn cancellation_after_dispatch_reconciles_on_restart_and_ack_is_final() {
    let mut f = Fixture::new().await;
    f.wallet.mode.store(1, Ordering::SeqCst);
    let app = common::test_router(f.state.clone());
    let request = f.request();
    let job = tokio::spawn(async move { app.oneshot(request).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if f.db
                .get_outbox_operation(&f.id)
                .await
                .unwrap()
                .is_some_and(|p| p.payment_hash.is_some())
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    let original_id = f.op().await.message_id;
    f.restart().await;
    f.wallet.mode.store(0, Ordering::SeqCst);
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    let (status, receipt) = f.post().await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["message_id"].as_str(), original_id.as_deref());
    let id = konsensus_core::MessageId::from_hex(original_id.as_deref().unwrap()).unwrap();
    assert!(f
        .db
        .acknowledge_pending(&id, &f.peer, f.state.identity.node_id())
        .await
        .unwrap());
    f.restart().await;
    let (status, receipt) = f.post().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(receipt["accepted"], true);
    assert_eq!(receipt["state"], "acked");
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.db.count_pending_deliveries().await.unwrap(), 0);
}

#[tokio::test]
async fn untrackable_dispatch_is_not_retry_permission() {
    let mut f = Fixture::new().await;
    f.wallet.mode.store(3, Ordering::SeqCst);
    let _ = f.post().await;
    f.restart().await;
    for _ in 0..3 {
        let (status, body) = f.post().await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(body["retry_allowed"], false);
        assert_eq!(body["state"], "payment_unknown");
    }
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancelled_before_dispatch_can_retry_same_operation() {
    let mut f = Fixture::new().await;
    f.wallet.mode.store(6, Ordering::SeqCst);
    let old_sessions = f.state.session_manager.clone();
    let old_keys = f.state.peer_ln_pubkeys.clone();
    let app = common::test_router(f.state.clone());
    let request = f.request();
    let job = tokio::spawn(async move { app.oneshot(request).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if f.db
                .get_outbox_operation(&f.id)
                .await
                .unwrap()
                .is_some_and(|p| p.state == "paying")
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    job.abort();
    let _ = job.await;
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 0);
    f.restart().await;
    Arc::get_mut(&mut f.state).unwrap().session_manager = old_sessions;
    Arc::get_mut(&mut f.state).unwrap().peer_ln_pubkeys = old_keys;
    f.wallet.mode.store(0, Ordering::SeqCst);
    let (status, receipt) = f.post().await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn recovery_never_resends_legacy_connection_admission() {
    use konsensus_core::{PaymentProof, Recipient, UkmEnvelopeBuilder};
    let f = Fixture::new().await;
    let env = UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        *f.state.identity.node_id(),
        Recipient::Node(f.peer),
        b"konsensus:admission:v1".to_vec(),
        PaymentProof::new([0; 32], [0; 32], 1000),
    )
    .build();
    f.db.store_message(&env).await.unwrap();
    f.db.queue_pending_delivery(&env.id, &f.peer).await.unwrap();
    let mut op = konsensus_storage::OutboxOperation::prepared(
        format!("legacy:{}:{}", env.id, f.peer),
        f.peer.to_hex(),
        env.kind,
        String::new(),
    );
    op.state = "paid".into();
    op.message_id = Some(env.id.to_hex());
    f.db.insert_outbox_operation(&op).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    let op =
        f.db.get_outbox_operation(&op.operation_id)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(
        op.attempts, 0,
        "generic recovery must never dispatch admission proofs"
    );
    assert_eq!(op.state, "failed_paid");
}

#[tokio::test]
async fn confirmed_failed_payment_releases_and_invalid_settled_proof_reports_paid_amount() {
    for failure in [2, 5, 7, 8, 9] {
        let mut f = Fixture::new().await;
        f.wallet.mode.store(1, Ordering::SeqCst);
        let old_sessions = f.state.session_manager.clone();
        let old_keys = f.state.peer_ln_pubkeys.clone();
        let app = common::test_router(f.state.clone());
        let request = f.request();
        let job = tokio::spawn(async move { app.oneshot(request).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if f.db
                    .get_outbox_operation(&f.id)
                    .await
                    .unwrap()
                    .is_some_and(|p| p.payment_hash.is_some())
                {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        job.abort();
        let _ = job.await;
        f.restart().await;
        f.wallet.mode.store(failure, Ordering::SeqCst);
        konsensus_api::handlers::messages::reconcile_operations(&f.state)
            .await
            .unwrap();
        if failure == 2 {
            assert_eq!(f.op().await.state, "released");
            Arc::get_mut(&mut f.state).unwrap().session_manager = old_sessions;
            Arc::get_mut(&mut f.state).unwrap().peer_ln_pubkeys = old_keys;
            f.wallet.mode.store(0, Ordering::SeqCst);
            let (status, body) = f.post().await;
            assert_eq!(status, StatusCode::OK, "{body}");
            assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 2);
        } else {
            assert_eq!(f.op().await.state, "payment_unknown");
            assert_eq!(f.op().await.settled_msat, 1000);
            assert_eq!(f.post().await.0, StatusCode::CONFLICT);
            assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
            // A contradictory later backend status must not erase settlement
            // evidence and turn the missing-proof condition into retry permission.
            f.wallet.mode.store(2, Ordering::SeqCst);
            konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
            assert_eq!(f.op().await.state, "payment_unknown");
            f.wallet.mode.store(0, Ordering::SeqCst);
            konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
            assert_eq!(f.op().await.state, "sent");
            assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn recovery_repolls_cached_settlement_without_proof() {
    let mut f = Fixture::new().await;
    // The mock's deferred path stores payments by their pollable raw hash.
    f.wallet.inner.defer_next_keysend_settlement(0).await;
    sqlx::raw_sql("CREATE TRIGGER crash BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'before paid commit'); END").execute(f.db.pool()).await.unwrap();
    let _ = f.post().await;
    sqlx::raw_sql("DROP TRIGGER crash").execute(f.db.pool()).await.unwrap();
    let mut op = f.op().await;
    let mut data: serde_json::Value = serde_json::from_slice(&op.recovery).unwrap();
    data["envelope_ready"] = false.into();
    data["settlement"]["preimage"] = serde_json::Value::Null;
    op.recovery = serde_json::to_vec(&data).unwrap();
    op.state = "payment_unknown".into();
    op.settled_msat = 0; // record() can persist settlement before the amount receipt
    assert!(f.db.update_outbox_operation(&op).await.unwrap());
    f.restart().await;
    f.wallet.mode.store(2, Ordering::SeqCst);
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert_eq!(f.op().await.state, "payment_unknown");
    assert_eq!(f.op().await.settled_msat, 1000);
    f.wallet.mode.store(0, Ordering::SeqCst);
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert_eq!(f.op().await.state, "sent");
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn recovery_missing_draft_stays_unknown_until_draft_restored() {
    for ready in [false, true] {
        let mut f = Fixture::new().await;
        sqlx::raw_sql("CREATE TRIGGER crash BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'before paid commit'); END").execute(f.db.pool()).await.unwrap();
        let _ = f.post().await;
        sqlx::raw_sql("DROP TRIGGER crash").execute(f.db.pool()).await.unwrap();
        let mut op = f.op().await;
        let mut data: serde_json::Value = serde_json::from_slice(&op.recovery).unwrap();
        let draft = data["draft"].take();
        data["envelope_ready"] = ready.into();
        op.recovery = serde_json::to_vec(&data).unwrap();
        op.state = "paying".into();
        assert!(f.db.update_outbox_operation(&op).await.unwrap());
        f.restart().await;
        konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
        assert_eq!(f.op().await.state, "payment_unknown");
        assert_eq!(f.op().await.settled_msat, 1000);
        assert_eq!(f.post().await.0, StatusCode::CONFLICT);
        let mut op = f.op().await;
        data["draft"] = draft;
        op.recovery = serde_json::to_vec(&data).unwrap();
        assert!(f.db.update_outbox_operation(&op).await.unwrap());
        konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
        assert_eq!(f.op().await.state, "sent");
        assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn recovery_offline_backoff_is_exponential_capped_and_survives_restart() {
    let mut f = Fixture::new().await;
    Arc::get_mut(&mut f.state).unwrap().transport = Arc::new(ReceiptTransport {
        db: f.db.clone(), peer: f.peer, fail_write: true,
    });
    assert_eq!(f.post().await.0, StatusCode::OK);
    assert_eq!(f.op().await.state, "paid");
    let attempts = f.op().await.attempts;
    for delay in [15_000, 30_000, 60_000, 120_000, 240_000, 300_000, 300_000] {
        f.restart().await;
        Arc::get_mut(&mut f.state).unwrap().transport = Arc::new(common::StubTransport);
        let before = chrono::Utc::now().timestamp_millis();
        konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
        let op = f.op().await;
        assert_eq!(op.state, "paid");
        assert_eq!(op.attempts, attempts, "offline recovery must not mark a send intent");
        let data: serde_json::Value = serde_json::from_slice(&op.recovery).unwrap();
        let due = data["resend_after_ms"].as_i64().unwrap();
        assert!(due >= before + delay && due <= chrono::Utc::now().timestamp_millis() + delay);
        konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
        assert_eq!(f.op().await.version, op.version, "no per-tick retry bookkeeping");
        // Move just the persisted deadline into the past; no wall-clock sleeps.
        sqlx::query("UPDATE outbox_operations SET recovery = CAST(json_set(CAST(recovery AS TEXT), '$.resend_after_ms', 0) AS BLOB)")
            .execute(f.db.pool()).await.unwrap();
    }
    f.restart().await; // connected again
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert_eq!(f.op().await.state, "sent");
    let data: serde_json::Value = serde_json::from_slice(&f.op().await.recovery).unwrap();
    assert_eq!(data["resend_delay_ms"], 0);
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
}

struct ReceiptTransport {
    db: Arc<SqliteStorage>,
    peer: NodeId,
    fail_write: bool,
}
#[async_trait::async_trait]
impl konsensus_core::traits::transport::MessageTransport for ReceiptTransport {
    async fn send(
        &self,
        peer: &NodeId,
        env: &konsensus_core::UkmEnvelope,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        if self.fail_write {
            return Err(konsensus_core::traits::transport::TransportError::Other(
                "injected write failure".into(),
            ));
        }
        assert!(self
            .db
            .acknowledge_pending(&env.id, peer, &env.sender)
            .await
            .unwrap());
        Ok(())
    }
    async fn recv(
        &self,
    ) -> Result<konsensus_core::UkmEnvelope, konsensus_core::traits::transport::TransportError>
    {
        futures::future::pending().await
    }
    async fn connect(
        &self,
        _: &NodeId,
        _: &str,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        Ok(())
    }
    async fn disconnect(
        &self,
        _: &NodeId,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        Ok(())
    }
    async fn is_connected(&self, peer: &NodeId) -> bool {
        peer == &self.peer
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        vec![self.peer]
    }
}

#[tokio::test]
async fn immediate_ack_wins_and_failed_transport_stays_paid() {
    for fail_write in [false, true] {
        let mut f = Fixture::new().await;
        Arc::get_mut(&mut f.state).unwrap().transport = Arc::new(ReceiptTransport {
            db: f.db.clone(),
            peer: f.peer,
            fail_write,
        });
        let (status, receipt) = f.post().await;
        assert_eq!(status, StatusCode::OK, "{receipt}");
        assert_eq!(receipt["accepted"], !fail_write);
        assert_eq!(receipt["delivered"], !fail_write);
        assert_eq!(receipt["state"], if fail_write { "paid" } else { "acked" });
        assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn rejections_preserve_receipt_and_never_repay() {
    for terminal in [false, true] {
        let mut f = Fixture::new().await;
        assert_eq!(f.post().await.0, StatusCode::OK);
        let op = f.op().await;
        let id = konsensus_core::MessageId::from_hex(op.message_id.as_deref().unwrap()).unwrap();
        assert!(f
            .db
            .reject_pending(
                &id,
                &f.peer,
                f.state.identity.node_id(),
                if terminal {
                    "InvalidSignature"
                } else {
                    "storage error"
                },
                terminal
            )
            .await
            .unwrap());
        f.restart().await;
        let (status, receipt) = f.post().await;
        if terminal {
            assert_eq!(status, StatusCode::CONFLICT, "{receipt}");
            assert_eq!(receipt["state"], "failed_paid");
            assert_eq!(receipt["retry_allowed"], false);
        } else {
            assert_eq!(status, StatusCode::OK, "{receipt}");
            assert_eq!(receipt["state"], "rejected_retryable");
            sqlx::query("UPDATE pending_deliveries SET retry_after_ms = 0")
                .execute(f.db.pool())
                .await
                .unwrap();
            let (status, receipt) = f.post().await;
            assert_eq!(status, StatusCode::OK, "{receipt}");
            assert_eq!(receipt["state"], "sent");
        }
        assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn invoice_hash_saved_before_dispatch_recovers_a_lost_settlement_response() {
    let mut f = Fixture::new().await;
    f.state.peer_ln_pubkeys.lock().await.clear();
    let peer = f.peer;
    let payee = Arc::new(konsensus_lightning::MockLightningProvider::new());
    let transport =
        common::ConnectedStubTransport::new(vec![peer], f.state.invoice_requests.clone())
            .with_invoice_responder(move |_, amount| {
                let invoice =
                    futures::executor::block_on(payee.create_invoice(amount, "crash invoice", 60))
                        .unwrap();
                Some(konsensus_api::state::InvoiceResponseData {
                    recipient: peer,
                    bolt11: invoice.bolt11,
                    payment_hash: invoice.payment_hash,
                })
            });
    Arc::get_mut(&mut f.state).unwrap().transport = Arc::new(transport);
    f.wallet.mode.store(4, Ordering::SeqCst);
    let app = common::test_router(f.state.clone());
    let request = f.request();
    let job = tokio::spawn(async move { app.oneshot(request).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while f.wallet.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        // Backend ledger is independent of the request task; wait until it settled.
        loop {
            let op = f.op().await;
            if f.wallet
                .inner
                .get_payment_status(op.payment_hash.as_deref().unwrap())
                .await
                .is_ok()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    job.abort();
    let _ = job.await;
    let before = f.op().await;
    assert!(before.payment_hash.is_some());
    f.restart().await;
    f.wallet.mode.store(0, Ordering::SeqCst);
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    let (status, receipt) = f.post().await;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["message_id"].as_str(), before.message_id.as_deref());
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn compose_schema_accepts_old_clients_and_rejects_unknown_fields() {
    let body = serde_json::json!({"recipient":"peer","kind":1,"plaintext":"old client"});
    let request: konsensus_api::handlers::messages::ComposeRequest =
        serde_json::from_value(body.clone()).unwrap();
    assert!(request.operation_id.is_none());
    assert!(request.wait_ack_ms.is_none());
    let mut future = body;
    future["unknown_future_field"] = true.into();
    assert!(
        serde_json::from_value::<konsensus_api::handlers::messages::ComposeRequest>(future)
            .is_err()
    );
}
