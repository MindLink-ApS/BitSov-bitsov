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
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

struct Wallet {
    inner: konsensus_lightning::MockLightningProvider,
    calls: AtomicUsize,
    mode: AtomicU8,
    pause_next_status_poll: AtomicBool,
    status_poll_started: tokio::sync::Notify,
    pool: sqlx::SqlitePool,
    /// Park the next `money_ready` until `ready_continue` (Codex delta3 probe).
    pause_next_ready: AtomicBool,
    ready_started: tokio::sync::Notify,
    ready_continue: tokio::sync::Notify,
}
#[async_trait::async_trait]
impl LightningProvider for Wallet {
    async fn money_ready(&self) -> bool {
        if self.pause_next_ready.swap(false, Ordering::SeqCst) {
            self.ready_started.notify_one();
            self.ready_continue.notified().await;
        }
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
        if self.pause_next_status_poll.swap(false, Ordering::SeqCst) {
            self.status_poll_started.notify_one();
            return futures::future::pending().await;
        }
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
            pause_next_status_poll: AtomicBool::new(false),
            status_poll_started: tokio::sync::Notify::new(),
            pool: db.pool().clone(),
            pause_next_ready: AtomicBool::new(false),
            ready_started: tokio::sync::Notify::new(),
            ready_continue: tokio::sync::Notify::new(),
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
        f.wallet.pause_next_status_poll.store(true, Ordering::SeqCst);
        let old_sessions = f.state.session_manager.clone();
        let old_keys = f.state.peer_ln_pubkeys.clone();
        let app = common::test_router(f.state.clone());
        let request = f.request();
        let job = tokio::spawn(async move { app.oneshot(request).await });
        // A visible hash can precede another journal write. Aborting then can
        // leave SQLx's SQLite worker writing after the task has stopped, racing
        // recovery's version CAS. Park in the wallet poll instead: all earlier
        // checkpoints have completed and no further write can start.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            f.wallet.status_poll_started.notified(),
        )
        .await
        .expect("compose must reach the post-checkpoint payment status poll");
        assert_eq!(f.op().await.state, "paying");
        assert!(f.op().await.payment_hash.is_some());
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
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

/// Settled backend status without a usable preimage must fail closed: never
/// repay, never terminalize as failed_paid, and remain payment_unknown across
/// restart while the proof is still missing.
#[tokio::test]
async fn recovery_settled_without_preimage_stays_payment_unknown_across_restart() {
    let mut f = Fixture::new().await;
    f.wallet.mode.store(1, Ordering::SeqCst);
    f.wallet.pause_next_status_poll.store(true, Ordering::SeqCst);
    let app = common::test_router(f.state.clone());
    let request = f.request();
    let job = tokio::spawn(async move { app.oneshot(request).await });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        f.wallet.status_poll_started.notified(),
    )
    .await
    .expect("compose must reach the post-checkpoint payment status poll");
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);

    f.restart().await;
    f.wallet.mode.store(7, Ordering::SeqCst); // Settled, preimage absent
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    assert_eq!(f.op().await.state, "payment_unknown");
    assert_eq!(
        f.op().await.last_error.as_deref(),
        Some("settled payment has no valid proof")
    );
    assert_ne!(f.op().await.state, "failed_paid");
    assert_eq!(f.post().await.0, StatusCode::CONFLICT);
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);

    f.restart().await;
    f.wallet.mode.store(7, Ordering::SeqCst);
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    assert_eq!(f.op().await.state, "payment_unknown");
    assert_eq!(f.post().await.0, StatusCode::CONFLICT);
    assert_eq!(
        f.wallet.calls.load(Ordering::SeqCst),
        1,
        "restart must never dispatch another payment"
    );
}

/// Missing encrypted draft after settlement must fail closed the same way.
#[tokio::test]
async fn recovery_missing_draft_stays_payment_unknown_across_restart() {
    let mut f = Fixture::new().await;
    sqlx::raw_sql("CREATE TRIGGER crash BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'before paid commit'); END")
        .execute(f.db.pool())
        .await
        .unwrap();
    let _ = f.post().await;
    sqlx::raw_sql("DROP TRIGGER crash")
        .execute(f.db.pool())
        .await
        .unwrap();
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);

    let mut op = f.op().await;
    let mut data: serde_json::Value = serde_json::from_slice(&op.recovery).unwrap();
    data["draft"] = serde_json::Value::Null;
    data["envelope_ready"] = false.into();
    op.recovery = serde_json::to_vec(&data).unwrap();
    op.state = "paying".into();
    assert!(f.db.update_outbox_operation(&op).await.unwrap());

    f.restart().await;
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    assert_eq!(f.op().await.state, "payment_unknown");
    assert_eq!(
        f.op().await.last_error.as_deref(),
        Some("settled payment missing encrypted draft")
    );
    assert_ne!(f.op().await.state, "failed_paid");
    assert_eq!(f.post().await.0, StatusCode::CONFLICT);
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);

    f.restart().await;
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    assert_eq!(f.op().await.state, "payment_unknown");
    assert_eq!(f.post().await.0, StatusCode::CONFLICT);
    assert_eq!(
        f.wallet.calls.load(Ordering::SeqCst),
        1,
        "restart must never dispatch another payment"
    );
}

/// A paid row whose envelope was lost cannot be resent and must fail closed
/// without authorizing another payment.
#[tokio::test]
async fn recover_paid_missing_envelope_moves_to_payment_unknown() {
    use konsensus_core::{PaymentProof, Recipient, UkmEnvelopeBuilder};
    let mut f = Fixture::new().await;
    let env = UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        *f.state.identity.node_id(),
        Recipient::Node(f.peer),
        b"ciphertext".to_vec(),
        PaymentProof::new([1; 32], [2; 32], 1000),
    )
    .build();
    let mut op = konsensus_storage::OutboxOperation::prepared(
        f.id.clone(),
        f.peer.to_hex(),
        env.kind,
        "request-hash".into(),
    );
    op.state = "paid".into();
    op.message_id = Some(env.id.to_hex());
    op.payment_hash = Some(hex::encode(env.payment_proof.payment_hash));
    op.settled_msat = 1000;
    op.accounting_pending = false;
    op.recovery = serde_json::to_vec(&serde_json::json!({
        "dispatched": true,
        "envelope_ready": true,
        "expected_msat": 1000,
        "fee_ceiling_msat": 0,
        "admission_msat": 0,
    }))
    .unwrap();
    assert!(f.db.insert_outbox_operation(&op).await.unwrap());
    // Deliberately do not store the envelope.
    f.restart().await;
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    assert_eq!(f.op().await.state, "payment_unknown");
    assert_eq!(
        f.op().await.last_error.as_deref(),
        Some("paid envelope missing")
    );
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 0);
}

/// Pre-fix rows that terminalized incomplete settlement as failed_paid must
/// reopen to payment_unknown (still no repay) when the client retries.
#[tokio::test]
async fn mistagged_failed_paid_incomplete_settlement_reopens_to_payment_unknown() {
    let mut f = Fixture::new().await;
    sqlx::raw_sql("CREATE TRIGGER crash BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'before paid commit'); END")
        .execute(f.db.pool())
        .await
        .unwrap();
    let _ = f.post().await;
    sqlx::raw_sql("DROP TRIGGER crash")
        .execute(f.db.pool())
        .await
        .unwrap();
    let mut op = f.op().await;
    let mut data: serde_json::Value = serde_json::from_slice(&op.recovery).unwrap();
    data["settlement"]["preimage"] = serde_json::Value::Null;
    data["envelope_ready"] = false.into();
    op.recovery = serde_json::to_vec(&data).unwrap();
    op.state = "failed_paid".into();
    op.last_error = Some("settled payment has no valid proof".into());
    assert!(f.db.update_outbox_operation(&op).await.unwrap());

    f.restart().await;
    f.wallet.mode.store(7, Ordering::SeqCst);
    let (status, body) = f.post().await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "payment_unresolved");
    assert_eq!(f.op().await.state, "payment_unknown");
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
}

/// Compaction retains payment_hash/settled_msat but clears dispatched flags.
/// A client retry of a compacted mistagged failed_paid must 409 without a
/// second keysend — compaction is retention, not re-payment authorization.
#[tokio::test]
async fn compacted_mistagged_failed_paid_retry_never_repays() {
    let mut f = Fixture::new().await;
    sqlx::raw_sql("CREATE TRIGGER crash BEFORE INSERT ON messages BEGIN SELECT RAISE(ABORT, 'before paid commit'); END")
        .execute(f.db.pool())
        .await
        .unwrap();
    let _ = f.post().await;
    sqlx::raw_sql("DROP TRIGGER crash")
        .execute(f.db.pool())
        .await
        .unwrap();
    let mut op = f.op().await;
    let mut data: serde_json::Value = serde_json::from_slice(&op.recovery).unwrap();
    data["settlement"]["preimage"] = serde_json::Value::Null;
    data["envelope_ready"] = false.into();
    op.recovery = serde_json::to_vec(&data).unwrap();
    op.state = "failed_paid".into();
    op.last_error = Some("settled payment has no valid proof".into());
    assert!(f.db.update_outbox_operation(&op).await.unwrap());
    assert!(op.settled_msat > 0 || op.payment_hash.is_some());

    // Age past retention so the real compact_terminal_operations sweep runs.
    sqlx::query("UPDATE outbox_operations SET updated_at = 0")
        .execute(f.db.pool())
        .await
        .unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    let compacted = f.op().await;
    assert!(compacted.recovery_compacted, "must use real compaction sweep");
    assert_eq!(compacted.state, "failed_paid");
    let pay_before = f.wallet.calls.load(Ordering::SeqCst);

    f.restart().await;
    f.wallet.mode.store(7, Ordering::SeqCst);
    let (status, body) = f.post().await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "failed_paid", "{body}");
    assert_eq!(f.op().await.state, "failed_paid");
    assert_eq!(
        f.wallet.calls.load(Ordering::SeqCst),
        pay_before,
        "compacted mistagged failed_paid must never dispatch another keysend"
    );
}

/// Peer reachability scripted by the test. Every write is counted; a
/// successful one is acknowledged like a real recipient would.
struct PacedTransport {
    db: Arc<SqliteStorage>,
    peer: NodeId,
    online: AtomicBool,
    fail_write: AtomicBool,
    generation: std::sync::Mutex<std::time::Instant>,
    writes: AtomicUsize,
}
impl PacedTransport {
    fn install(f: &mut Fixture, online: bool, fail_write: bool) -> Arc<Self> {
        let transport = Arc::new(Self {
            db: f.db.clone(),
            peer: f.peer,
            online: AtomicBool::new(online),
            fail_write: AtomicBool::new(fail_write),
            generation: std::sync::Mutex::new(std::time::Instant::now()),
            writes: AtomicUsize::new(0),
        });
        Arc::get_mut(&mut f.state).unwrap().transport = transport.clone();
        transport

    }
    fn reconnect(&self) {
        *self.generation.lock().unwrap() = std::time::Instant::now();
        self.online.store(true, Ordering::SeqCst);
    }
}
#[async_trait::async_trait]
impl konsensus_core::traits::transport::MessageTransport for PacedTransport {
    async fn send(
        &self,
        peer: &NodeId,
        env: &konsensus_core::UkmEnvelope,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if !self.online.load(Ordering::SeqCst) || self.fail_write.load(Ordering::SeqCst) {
            return Err(konsensus_core::traits::transport::TransportError::NotConnected(
                "peer unreachable".into(),
            ));
        }
        assert!(self.db.acknowledge_pending(&env.id, peer, &env.sender).await.unwrap());
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
        peer == &self.peer && self.online.load(Ordering::SeqCst)
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        if self.online.load(Ordering::SeqCst) { vec![self.peer] } else { Vec::new() }
    }
    async fn connected_since(&self, peer: &NodeId) -> Option<std::time::Instant> {
        self.is_connected(peer)
            .await
            .then(|| *self.generation.lock().unwrap())
    }
}

const SWEEP: std::time::Duration = std::time::Duration::from_secs(15);

/// Pins the paused clock: a running blocking task inhibits Tokio's
/// auto-advance, so SQLite round-trips cannot fire sqlx pool timeouts and
/// only explicit `advance` calls move time.
struct PinnedClock(std::sync::mpsc::Sender<()>);
fn pin_clock() -> PinnedClock {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    tokio::task::spawn_blocking(move || rx.recv());
    PinnedClock(tx)
}

/// One production sweep tick, then the 15 s interval in paused Tokio time.
async fn sweep(f: &Fixture) {
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    tokio::time::advance(SWEEP).await;
}

/// The paid row, its envelope and its pending delivery are exactly as compose left them.
async fn assert_paid_untouched(f: &Fixture, paid: &konsensus_storage::OutboxOperation) {
    let op = f.op().await;
    assert_eq!(op.state, "paid");
    assert_eq!(op.payment_hash, paid.payment_hash);
    assert_eq!(op.settled_msat, paid.settled_msat);
    assert_eq!(op.recovery, paid.recovery, "pacing never rewrites the recovery journal");
    let id = konsensus_core::MessageId::from_hex(op.message_id.as_deref().unwrap()).unwrap();
    assert!(f.db.get_message(&id).await.unwrap().is_some(), "paid envelope retained");
    assert!(
        f.db.get_pending_for_peer(&f.peer).await.unwrap().iter().any(|(p, _)| p == &id),
        "pending delivery retained"
    );
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1, "never re-pays");
}

#[tokio::test(start_paused = true)]
async fn failing_resends_back_off_exponentially_to_a_ten_minute_cap() {
    let _clock = pin_clock();
    let mut f = Fixture::new().await;
    let transport = PacedTransport::install(&mut f, true, true);
    assert_eq!(f.post().await.0, StatusCode::OK);
    let paid = f.op().await;
    assert_eq!(paid.state, "paid");
    let start = tokio::time::Instant::now();
    let mut attempts = Vec::new();
    // Two hours of 15 s sweeps: 480 resends without backoff.
    for _ in 0..480 {
        let before = transport.writes.load(Ordering::SeqCst);
        let at = tokio::time::Instant::now() - start;
        sweep(&f).await;
        if transport.writes.load(Ordering::SeqCst) > before {
            attempts.push(at);
        }
    }
    let gaps: Vec<_> = attempts.windows(2).map(|w| w[1] - w[0]).collect();
    for (i, gap) in gaps.iter().enumerate() {
        let base = (SWEEP * (1 << i.min(10))).min(std::time::Duration::from_secs(600));
        // Jitter spans [base/2, base]; sweeps round the retry up to the next tick.
        assert!(*gap >= base / 2 && *gap <= base + SWEEP, "gap {i}: {gap:?} vs base {base:?}");
    }
    assert!(gaps.iter().any(|g| *g > std::time::Duration::from_secs(300)), "{gaps:?}");
    assert!(gaps.iter().all(|g| *g <= std::time::Duration::from_secs(615)), "{gaps:?}");
    assert!(attempts.len() < 30, "{} resends in two hours", attempts.len());
    assert_paid_untouched(&f, &paid).await;
    // Jitter decorrelates operations: another backlog entry must not retry in lockstep.
    assert!(gaps.windows(2).any(|w| w[0] != w[1]));
}

#[tokio::test(start_paused = true)]
async fn offline_peer_gets_no_resends_and_reconnect_delivers_on_the_next_sweep() {
    let _clock = pin_clock();
    let mut f = Fixture::new().await;
    let transport = PacedTransport::install(&mut f, true, true);
    assert_eq!(f.post().await.0, StatusCode::OK);
    let paid = f.op().await;
    // Back off to the cap while the peer is up but unreachable…
    for _ in 0..120 {
        sweep(&f).await;
    }
    let writes = transport.writes.load(Ordering::SeqCst);
    while transport.writes.load(Ordering::SeqCst) == writes {
        sweep(&f).await;
    }
    // …then, right after a capped attempt (next one ≥ 5 min out), it drops
    // off entirely: no writes and no row changes.
    transport.online.store(false, Ordering::SeqCst);
    transport.fail_write.store(false, Ordering::SeqCst);
    let writes = transport.writes.load(Ordering::SeqCst);
    let version = f.op().await.version;
    for _ in 0..10 {
        sweep(&f).await;
    }
    assert_eq!(transport.writes.load(Ordering::SeqCst), writes, "nothing is sent while offline");
    assert_eq!(f.op().await.version, version, "offline sweeps never write the row");
    assert_paid_untouched(&f, &paid).await;
    // Reconnect: the very next sweep delivers, ignoring the pending backoff.
    transport.reconnect();
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert_eq!(transport.writes.load(Ordering::SeqCst), writes + 1);
    assert_eq!(f.op().await.state, "acked");
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1, "never re-pays");
}

#[tokio::test(start_paused = true)]
async fn new_connection_generation_resets_backoff_immediately() {
    let _clock = pin_clock();
    let mut f = Fixture::new().await;
    let transport = PacedTransport::install(&mut f, true, true);
    assert_eq!(f.post().await.0, StatusCode::OK);
    let paid = f.op().await;
    for _ in 0..120 {
        sweep(&f).await;
    }
    // Same connection, backed off: a sweep right after an attempt is a no-op.
    let writes = transport.writes.load(Ordering::SeqCst);
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert!(transport.writes.load(Ordering::SeqCst) <= writes + 1);
    let writes = transport.writes.load(Ordering::SeqCst);
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert_eq!(transport.writes.load(Ordering::SeqCst), writes, "backed off on the same connection");
    // A reconnect between sweeps is seen through the connection generation.
    tokio::time::advance(std::time::Duration::from_millis(1)).await;
    transport.reconnect();
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert_eq!(transport.writes.load(Ordering::SeqCst), writes + 1, "retried on reconnect");
    assert_paid_untouched(&f, &paid).await;
    // Still failing on the new connection: the schedule restarts from the base.
    tokio::time::advance(SWEEP).await;
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert_eq!(transport.writes.load(Ordering::SeqCst), writes + 2);
    transport.fail_write.store(false, Ordering::SeqCst);
    tokio::time::advance(SWEEP * 2).await;
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert_eq!(f.op().await.state, "acked");
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1, "never re-pays");
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

#[tokio::test]
async fn recovered_terminal_history_leaves_the_recovery_scan() {
    let f = Fixture::new().await;
    assert_eq!(f.post().await.0, StatusCode::OK);
    let original = f.op().await;
    let message =
        konsensus_core::MessageId::from_hex(original.message_id.as_ref().unwrap()).unwrap();
    assert!(f
        .db
        .acknowledge_pending(&message, &f.peer, f.state.identity.node_id())
        .await
        .unwrap());
    for i in 0..1000 {
        let mut op = original.clone();
        op.operation_id = format!("history-{i}");
        op.state = if i % 2 == 0 { "acked" } else { "failed_paid" }.into();
        assert!(f.db.insert_outbox_operation(&op).await.unwrap());
    }
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    assert!(
        f.db.list_recoverable_operations().await.unwrap().is_empty(),
        "resolved history must not be decoded on every recovery sweep"
    );
    assert_eq!(f.post().await.0, StatusCode::OK);
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn terminal_retention_keeps_duplicate_post_and_receipt_binding() {
    let mut f = Fixture::new().await;
    assert_eq!(f.post().await.0, StatusCode::OK);
    let op = f.op().await;
    let id = konsensus_core::MessageId::from_hex(op.message_id.as_ref().unwrap()).unwrap();
    let env = f.db.get_message(&id).await.unwrap().unwrap();
    // A receipt represents the independent #103 acceptance authority. Its
    // binding must remain usable after sender recovery material is compacted.
    assert!(f
        .db
        .acknowledge_pending(&id, &f.peer, f.state.identity.node_id())
        .await
        .unwrap());
    f.db.delete_message(&id).await.unwrap();
    assert_eq!(
        f.db.accept_paid_envelope(&env).await.unwrap(),
        konsensus_storage::PaidAcceptance::Accepted
    );
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    let before = f.post().await;
    sqlx::query("UPDATE outbox_operations SET updated_at = 0")
        .execute(f.db.pool())
        .await
        .unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&f.state)
        .await
        .unwrap();
    let data: serde_json::Value = serde_json::from_slice(&f.op().await.recovery).unwrap();
    assert!(
        data["draft"].is_null(),
        "old terminal drafts must be compacted"
    );
    assert!(data["settlement"].is_null());
    f.db.delete_message(&id).await.unwrap();
    f.restart().await;
    assert_eq!(
        f.post().await,
        before,
        "permanent tombstone preserves the receipt response"
    );
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.db.accept_paid_envelope(&env).await.unwrap(),
        konsensus_storage::PaidAcceptance::AlreadyAccepted
    );
    let mut changed = env.clone();
    changed.kind += 1;
    assert_eq!(
        f.db.accept_paid_envelope(&changed).await.unwrap(),
        konsensus_storage::PaidAcceptance::PaymentReused
    );
    assert!(f.db.get_message(&id).await.unwrap().is_none());
}

/// Fable N1 (#131 delta): a call offer whose payment was dispatched but not
/// resolved when compose was cut off (crash, cancel, app gave up) stays
/// reserved through startup recovery; when the background reconciler later
/// finds it paid, it commits the call before resending, so the callee's
/// answer is admitted without a same-operation re-POST, and nothing is paid
/// twice.
#[tokio::test]
async fn background_reconcile_commits_a_paid_call_offer_before_resending() {
    use konsensus_core::payloads::call::Phase;
    let f = Fixture::new().await;
    let peer = f.peer;
    let prices = f.state.peer_prices.clone();
    // The callee answers every call price query.
    let answering = tokio::spawn(async move {
        loop {
            prices.update_kind_price(peer, 400, 10_000, 100).await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    });
    let call = format!("{:032x}", 0xca11_u128);
    let offer = format!(r#"{{"v":1,"call_id":"{call}","media":"audio","sdp":"v=0"}}"#);
    let answer = format!(r#"{{"v":1,"call_id":"{call}","sdp":"v=0"}}"#);
    // Dispatched, but the wallet cannot say yet whether it settled.
    f.wallet.mode.store(1, Ordering::SeqCst);
    let request = Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&f.state)).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"operation_id": f.id, "recipient": peer.to_hex(), "kind": 400, "plaintext": offer, "wait_ack_ms": 0}).to_string()))
        .unwrap();
    let app = common::test_router(f.state.clone());
    let job = tokio::spawn(async move { app.oneshot(request).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while f.db.get_outbox_operation(&f.id).await.unwrap().is_none_or(|op| op.payment_hash.is_none()) {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    job.abort();
    assert!(job.await.unwrap_err().is_cancelled());
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
    // Startup recovery keeps an ambiguous reservation; nobody is rung yet.
    assert_eq!(konsensus_api::calls::recover(f.db.as_ref()).await.unwrap(), (0, 0));
    assert_eq!(f.db.call_get(&peer, &call).await.unwrap().unwrap().phase, Phase::Reserved);
    // It settles. The app only polls; the background sweep resolves it.
    f.wallet.mode.store(0, Ordering::SeqCst);
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    let state = f.op().await.state;
    assert!(matches!(state.as_str(), "paid" | "sent" | "acked"), "{state}");
    let entry = f.db.call_get(&peer, &call).await.unwrap().unwrap();
    assert_eq!((entry.phase, entry.pending), (Phase::Ringing, None), "committed by the sweep");
    konsensus_api::calls::admit_incoming(f.db.as_ref(), &own(), &peer, 401, Some(&answer)).await.unwrap();
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1, "paid once");
    answering.abort();
}

// ── Codex delta2 (#131, FAIL at 088d198): the four probes as regressions ──

fn call_request(f: &Fixture, op: &str, call: &str, sdp: &str, wait: u64) -> Request<Body> {
    Request::builder().method("POST").uri("/api/v1/messages/compose")
        .header("authorization", common::auth_header(&f.state)).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"operation_id": op, "recipient": f.peer.to_hex(), "kind": 400,
            "plaintext": format!(r#"{{"v":1,"call_id":"{call}","media":"audio","sdp":"{sdp}"}}"#), "wait_ack_ms": wait}).to_string()))
        .unwrap()
}

fn answer_call_prices(f: &Fixture) -> tokio::task::JoinHandle<()> {
    let (prices, peer) = (f.state.peer_prices.clone(), f.peer);
    tokio::spawn(async move {
        loop {
            prices.update_kind_price(peer, 400, 10_000, 100).await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
}

async fn until_dispatched(f: &Fixture) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while f.db.get_outbox_operation(&f.id).await.unwrap().is_none_or(|op| op.payment_hash.is_none()) {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

/// Probe `codex_review_uppercase_uuid_loses_paid_call_and_allows_second_charge`,
/// fixed: an uppercase operation id is canonicalized before the reservation,
/// so the paid offer commits under the journal's key, rings, and the same
/// call id cannot be paid for again.
#[tokio::test]
async fn an_uppercase_operation_id_commits_the_paid_call_under_one_key() {
    use konsensus_core::payloads::call::Phase;
    let f = Fixture::new().await;
    let answering = answer_call_prices(&f);
    let call = format!("{:032x}", 0xc011_u128);
    let raw = "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF";
    let response = common::test_router(f.state.clone()).oneshot(call_request(&f, raw, &call, "v=0", 0)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
    assert!(f.db.get_outbox_operation(&raw.to_lowercase()).await.unwrap().is_some());
    let entry = f.db.call_get(&f.peer, &call).await.unwrap().expect("paid call state kept");
    assert_eq!((entry.phase, entry.pending), (Phase::Ringing, None));
    let answer = format!(r#"{{"v":1,"call_id":"{call}","sdp":"v=0"}}"#);
    konsensus_api::calls::admit_incoming(f.db.as_ref(), &own(), &f.peer, 401, Some(&answer)).await.unwrap();
    let response = common::test_router(f.state.clone()).oneshot(call_request(&f, &f.id, &call, "v=0", 0)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1, "the same call id is never paid twice");
    answering.abort();
}

/// Probe `codex_review_concurrent_mismatch_releases_winners_ambiguous_call`,
/// fixed: two concurrent requests sharing the operation id and call id but
/// not the payload never share a reservation. The loser is refused
/// (operation_mismatch) and neither commits nor releases the winner's
/// still-ambiguous reservation, so no other operation can take that call id.
#[tokio::test]
async fn a_concurrent_mismatch_never_touches_the_winners_reservation() {
    use konsensus_core::payloads::call::Phase;
    for _ in 0..8 {
        let f = Fixture::new().await;
        let answering = answer_call_prices(&f);
        let call = format!("{:032x}", 0xc014_u128);
        f.wallet.mode.store(1, Ordering::SeqCst);
        let (app_a, req_a) = (common::test_router(f.state.clone()), call_request(&f, &f.id, &call, "v=0", 0));
        let (app_b, req_b) = (common::test_router(f.state.clone()), call_request(&f, &f.id, &call, "v=1", 0));
        let job_a = tokio::spawn(async move { app_a.oneshot(req_a).await });
        let job_b = tokio::spawn(async move { app_b.oneshot(req_b).await });
        until_dispatched(&f).await;
        let offer_a = format!(r#"{{"v":1,"call_id":"{call}","media":"audio","sdp":"v=0"}}"#);
        let digest_a = blake3::hash(&serde_json::to_vec(&(f.peer.to_hex(), 400u16, &offer_a, Vec::<String>::new())).unwrap()).to_hex().to_string();
        let winner_hash = f.op().await.request_hash;
        let (winner, loser) = if winner_hash == digest_a { (job_a, job_b) } else { (job_b, job_a) };
        winner.abort();
        let _ = winner.await;
        let response = loser.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let json: serde_json::Value = serde_json::from_slice(&axum::body::to_bytes(response.into_body(), 65536).await.unwrap()).unwrap();
        assert_eq!(json["code"], "operation_mismatch");
        assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
        let entry = f.db.call_get(&f.peer, &call).await.unwrap().expect("winner's reservation kept");
        let pending = entry.pending.expect("still reserved while ambiguous");
        assert_eq!((entry.phase, pending.operation_id.as_str(), pending.request_hash.as_str()), (Phase::Reserved, f.id.as_str(), winner_hash.as_str()));
        assert!(konsensus_api::calls::reserve_outgoing(f.db.as_ref(), &own(), &f.peer, 400, &offer_a, &uuid::Uuid::new_v4().to_string(), "other").await.is_err());
        answering.abort();
    }
}

/// Probe `codex_review_retry_resends_before_committing_call`, fixed: a
/// same-operation retry that reconciles the ambiguous payment commits the
/// call before resending, so an answer arriving right after the resend is
/// admitted.
#[tokio::test]
async fn a_retry_that_finds_the_offer_paid_commits_before_resending() {
    use konsensus_core::payloads::call::Phase;
    let f = Fixture::new().await;
    let answering = answer_call_prices(&f);
    let call = format!("{:032x}", 0xc012_u128);
    f.wallet.mode.store(1, Ordering::SeqCst);
    let (app, req) = (common::test_router(f.state.clone()), call_request(&f, &f.id, &call, "v=0", 0));
    let first = tokio::spawn(async move { app.oneshot(req).await });
    until_dispatched(&f).await;
    first.abort();
    assert!(first.await.unwrap_err().is_cancelled());
    f.wallet.mode.store(0, Ordering::SeqCst);
    let (app, req) = (common::test_router(f.state.clone()), call_request(&f, &f.id, &call, "v=0", 3000));
    let retry = tokio::spawn(async move { app.oneshot(req).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while f.op().await.state != "sent" {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(f.db.call_get(&f.peer, &call).await.unwrap().unwrap().phase, Phase::Ringing, "committed before the resend");
    let answer = format!(r#"{{"v":1,"call_id":"{call}","sdp":"v=0"}}"#);
    konsensus_api::calls::admit_incoming(f.db.as_ref(), &own(), &f.peer, 401, Some(&answer)).await.unwrap();
    assert_eq!(retry.await.unwrap().unwrap().status(), StatusCode::OK);
    assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1);
    answering.abort();
}

/// Probe `codex_review_failed_refusal_cleanup_exposes_signal_through_resync`,
/// fixed: the receive path holds a call signal before its paid acceptance.
/// When the refusal cleanup fails (or the node crashes before it), the held
/// signal stays out of history, duplicate acceptance and resync; the startup
/// sweep then withdraws it for good. A fresh hold is left to its live handler.
#[tokio::test]
async fn a_refused_signal_whose_cleanup_failed_stays_invisible_and_is_withdrawn() {
    use konsensus_core::{PaymentProof, Recipient, UkmEnvelopeBuilder};
    let mut f = Fixture::new().await;
    let cipher = Arc::new(konsensus_crypto::plaintext_cache::PlaintextCacheCipher::new(&[1; 32]));
    Arc::get_mut(&mut f.state).unwrap().plaintext_cipher = Some(cipher.clone());
    let me = Recipient::Node(*f.state.identity.node_id());
    let text = format!(r#"{{"v":1,"call_id":"{:032x}","candidate":"x"}}"#, 0xc013_u128);
    let env = UkmEnvelopeBuilder::new(402, f.peer, me, vec![], PaymentProof::new([2; 32], [3; 32], 1000)).build();
    // As the receive path does it: hold, paid acceptance, plaintext, admission.
    assert!(konsensus_api::calls::hold_incoming(f.db.as_ref(), &env).await.unwrap());
    assert_eq!(f.db.accept_paid_envelope(&env).await.unwrap(), konsensus_storage::PaidAcceptance::Accepted);
    f.db.store_message_plaintext(&env.id, &cipher.encrypt(text.as_bytes()).unwrap()).await.unwrap();
    assert!(konsensus_api::calls::admit_incoming(f.db.as_ref(), &own(), &f.peer, 402, Some(&text)).await.is_err());
    sqlx::raw_sql("CREATE TRIGGER cleanup_failure BEFORE DELETE ON messages BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END").execute(f.db.pool()).await.unwrap();
    assert!(f.db.reject_accepted_envelope(&env).await.is_err());
    sqlx::raw_sql("DROP TRIGGER cleanup_failure").execute(f.db.pool()).await.unwrap();
    // Still held: invisible everywhere, even across periodic recovery.
    konsensus_api::calls::recover(f.db.as_ref()).await.unwrap();
    konsensus_api::handlers::messages::reconcile_operations(&f.state).await.unwrap();
    assert_eq!(konsensus_api::calls::withdraw_held(f.db.as_ref(), false).await.unwrap(), 0, "a fresh hold is left to its handler");
    assert!(!f.db.get_messages_for_recipient(&me, 100, None).await.unwrap().iter().any(|e| e.id == env.id));
    assert!(f.db.get_message(&env.id).await.unwrap().is_none());
    assert!(f.db.get_message_plaintext(&env.id).await.unwrap().is_none());
    assert!(!f.db.is_paid_envelope_accepted(&env).await.unwrap(), "no duplicate ACK for a held signal");
    let mut ws = f.state.ws_broadcast.subscribe();
    let req = Request::builder().method("POST").uri("/api/v1/messages/resync")
        .header("authorization", common::auth_header(&f.state)).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"phase": "fulfill", "peer_id": f.peer.to_hex(), "message_ids": [env.id.to_hex()]}).to_string()))
        .unwrap();
    let _ = common::test_router(f.state.clone()).oneshot(req).await.unwrap();
    assert!(ws.try_recv().is_err(), "a held signal never reaches WS");
    // Startup: withdrawn for good; a resend is not re-accepted.
    assert_eq!(konsensus_api::calls::withdraw_held(f.db.as_ref(), true).await.unwrap(), 1);
    assert!(!f.db.call_admission_held(&env.id).await.unwrap());
    assert!(!matches!(
        f.db.accept_paid_envelope(&env).await.unwrap(),
        konsensus_storage::PaidAcceptance::Accepted | konsensus_storage::PaidAcceptance::AlreadyAccepted
    ));
    // A crash between acceptance and admission fails closed the same way.
    let crashed = UkmEnvelopeBuilder::new(402, f.peer, me, vec![], PaymentProof::new([4; 32], [5; 32], 1000)).build();
    assert!(konsensus_api::calls::hold_incoming(f.db.as_ref(), &crashed).await.unwrap());
    assert_eq!(f.db.accept_paid_envelope(&crashed).await.unwrap(), konsensus_storage::PaidAcceptance::Accepted);
    assert!(f.db.get_message(&crashed.id).await.unwrap().is_none());
    assert_eq!(konsensus_api::calls::withdraw_held(f.db.as_ref(), true).await.unwrap(), 1);
    assert!(!f.db.is_paid_envelope_accepted(&crashed).await.unwrap());
    // An admitted signal is released and visible; a later hold never hides it.
    let admitted = UkmEnvelopeBuilder::new(0, f.peer, me, b"x".to_vec(), PaymentProof::new([6; 32], [7; 32], 1000)).build();
    assert!(konsensus_api::calls::hold_incoming(f.db.as_ref(), &admitted).await.unwrap());
    assert_eq!(f.db.accept_paid_envelope(&admitted).await.unwrap(), konsensus_storage::PaidAcceptance::Accepted);
    f.db.call_admission_release(&admitted.id).await.unwrap();
    assert!(!konsensus_api::calls::hold_incoming(f.db.as_ref(), &admitted).await.unwrap(), "stored messages are never held again");
    assert!(f.db.get_message(&admitted.id).await.unwrap().is_some());
}

/// Codex delta3 probe `same_request_cap_race`, fixed: two concurrent requests
/// for the same operation and the same call payload, one capped below the
/// price and one uncapped, run one after the other under the operation lock.
/// The capped one is refused and releases only its own reservation; the
/// uncapped one then reserves, pays once and rings, and the answer is admitted.
#[tokio::test]
async fn a_capped_refusal_never_releases_the_uncapped_same_request_reservation() {
    use konsensus_core::payloads::call::Phase;
    for _ in 0..30 {
        let f = Fixture::new().await;
        let answering = answer_call_prices(&f);
        let call = format!("{:032x}", 0xca1199_u128);
        let request = |cap: Option<u64>| {
            Request::builder().method("POST").uri("/api/v1/messages/compose")
                .header("authorization", common::auth_header(&f.state)).header("content-type", "application/json")
                .body(Body::from(serde_json::json!({"operation_id": f.id, "recipient": f.peer.to_hex(), "kind": 400,
                    "plaintext": format!(r#"{{"v":1,"call_id":"{call}","media":"audio","sdp":"v=0"}}"#),
                    "max_total_msat": cap, "wait_ack_ms": 0}).to_string()))
                .unwrap()
        };
        f.wallet.pause_next_ready.store(true, Ordering::SeqCst);
        let (app_a, req_a) = (common::test_router(f.state.clone()), request(Some(1)));
        let a = tokio::spawn(async move { app_a.oneshot(req_a).await.unwrap() });
        tokio::time::timeout(std::time::Duration::from_secs(5), f.wallet.ready_started.notified()).await.unwrap();
        let (app_b, req_b) = (common::test_router(f.state.clone()), request(None));
        let b = tokio::spawn(async move { app_b.oneshot(req_b).await.unwrap() });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        f.wallet.ready_continue.notify_one();
        let (ra, rb) = tokio::time::timeout(std::time::Duration::from_secs(10), async { (a.await.unwrap(), b.await.unwrap()) }).await.unwrap();
        assert_ne!(ra.status(), StatusCode::OK, "the capped request is refused");
        let status_b = rb.status();
        let body_b = axum::body::to_bytes(rb.into_body(), 65536).await.unwrap();
        assert_eq!(status_b, StatusCode::OK, "{}", String::from_utf8_lossy(&body_b));
        assert_eq!(f.wallet.calls.load(Ordering::SeqCst), 1, "paid once");
        let entry = f.db.call_get(&f.peer, &call).await.unwrap().expect("the paid call keeps its state");
        assert_eq!((entry.phase, entry.pending), (Phase::Ringing, None));
        let answer = format!(r#"{{"v":1,"call_id":"{call}","sdp":"v=0"}}"#);
        konsensus_api::calls::admit_incoming(f.db.as_ref(), &own(), &f.peer, 401, Some(&answer)).await.unwrap();
        answering.abort();
    }
}

/// This node's own id in these tests: never one of the peers.
fn own() -> konsensus_core::types::NodeId {
    konsensus_core::types::NodeId::from_bytes([0xee; 32])
}
