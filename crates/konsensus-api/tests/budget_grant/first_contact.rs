use super::*;
use konsensus_lightning::shared_mock::SharedMockProvider;

type FirstContactFixture = (Fx, Arc<SharedMockProvider>, Arc<SharedMockProvider>, Arc<AtomicUsize>);

async fn stranger(establish: bool) -> FirstContactFixture {
    let mut fx = fixture().await;
    let path = fx.tmp.path().join("lightning.db");
    let sender = Arc::new(SharedMockProvider::new(&path, "sender", 100_000).unwrap());
    let target = Arc::new(SharedMockProvider::new(&path, "target", 0).unwrap());
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    fx.peer = *identity.node_id();
    let peer = fx.peer;
    let requests = Arc::new(AtomicUsize::new(0));
    let count = requests.clone();
    let recipient = target.clone();
    let session = fx.state.session_manager.clone();
    let handshake = Arc::new(std::sync::Mutex::new(establish.then_some(identity)));
    let transport = ConnectedStubTransport::new(vec![peer], fx.state.invoice_requests.clone())
        .with_invoice_responder(move |request_id, _| {
            count.fetch_add(1, Ordering::SeqCst);
            let invoice = futures::executor::block_on(recipient.create_invoice(2000,
                &format!("konsensus:{request_id}:message=2000"), 55)).unwrap();
            if let Some(identity) = handshake.lock().unwrap().take() {
                let recipient = recipient.clone();
                let session = session.clone();
                tokio::spawn(async move {
                    while recipient.get_balance_msat().await.unwrap() == 0 { tokio::task::yield_now().await; }
                    let target_session = konsensus_crypto::SessionManager::new(Arc::new(identity));
                    session.initiate_session(&peer, &target_session.prekey_bundle().await).await.unwrap();
                });
            }
            Some(konsensus_api::state::InvoiceResponseData { recipient: peer, bolt11: invoice.bolt11, payment_hash: invoice.payment_hash })
        });
    fx.state = Arc::new(AppState { lightning: sender.clone(), transport: Arc::new(transport), ..(*fx.state).clone() });
    (fx, sender, target, requests)
}

/// The owner's one-time OK for this stranger (#85): without it a budget never
/// pays a first contact, whatever the cap. Its own refusals (a cap the budget
/// cannot cover) are left for the send to report.
async fn confirm(fx: &Fx, _token: &str, cap: u64) {
    fx.owner_confirm(&fx.peer.to_hex(), cap).await;
}

async fn send(fx: &Fx, token: &str, cap: u64) -> (StatusCode, Value) {
    confirm(fx, token, cap).await;
    fx.call("POST", "/api/v1/messages/compose", Some(json!({"recipient":fx.peer.to_hex(),"kind":0,"plaintext":"first contact","max_total_msat":cap})), Some(token)).await
}

#[tokio::test]
async fn aggregate_budget_refusal_precedes_quote_and_emits_membrane_event() {
    let (fx, sender, _, requests) = stranger(false).await;
    let token = fx.grant(None, GrantTerms::new(3999)).await;
    let (status, body) = send(&fx, &token, 4000).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "budget_exceeded");
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(fx.used(), 0);
    assert_eq!(sender.get_balance_msat().await.unwrap(), 100_000);
    let (_, totals) = fx.state.audit_log.membrane().read(None, 500);
    assert_eq!(totals.outbound_refused, 1);
}

#[tokio::test]
async fn target_cap_refusal_releases_aggregate_budget_and_emits_membrane_event() {
    let (fx, sender, _, _) = stranger(false).await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, body) = send(&fx, &token, 3999).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "price_cap_exceeded");
    assert_eq!(fx.used(), 0);
    assert_eq!(sender.get_balance_msat().await.unwrap(), 100_000);
    let (_, totals) = fx.state.audit_log.membrane().read(None, 500);
    assert_eq!(totals.outbound_refused, 1);
}

#[tokio::test]
async fn both_legs_resolve_one_aggregate_reservation() {
    let (mut fx, sender, _, _) = stranger(true).await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    let (status, body) = send(&fx, &token, 6000).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 4000);
    assert_eq!(sender.get_balance_msat().await.unwrap(), 96_000);
    fx.restart();
    assert_eq!(fx.used(), 4000);
    assert!(fx.service.snapshot().grants[0].budget.as_ref().unwrap().pending.is_empty());
}

fn journal(fx: &Fx, reservation: &konsensus_api::spend_budget::Reservation, hash: &str) {
    let dir = fx.tmp.path().join("admission-attempts");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(fx.peer.to_hex()), serde_json::to_vec(&json!({
        "payment_hash": hash, "amount_msat": 2000, "quote":[0,2000], "envelope":null,
        "original_reservation": reservation, "message_may_have_dispatched":false
    })).unwrap()).unwrap();
}

fn reserve(fx: &Fx, amount: u64) -> konsensus_api::spend_budget::Reservation {
    let epoch = fx.service.snapshot().clients.iter().find(|c| c.client_id == fx.client_id).unwrap().epoch;
    fx.service.reserve_spend(&fx.client_id, epoch, vec![Charge { recipient:fx.peer.to_hex(), amount_msat:amount }]).unwrap()
}

#[tokio::test]
async fn unknown_prior_attempt_does_not_charge_polling_retries() {
    let (mut fx, sender, _, requests) = stranger(false).await;
    let token = fx.grant(None, GrantTerms::new(20_000)).await;
    let original = reserve(&fx, 6000);
    journal(&fx, &original, &"fe".repeat(32));
    for _ in 0..3 {
        fx.restart();
        let (status, body) = send(&fx, &token, 4000).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert!(body["error"].as_str().unwrap().contains("outcome unknown"), "{body}");
        assert_eq!(fx.used(), 6000, "only the original unknown attempt remains reserved");
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(sender.get_balance_msat().await.unwrap(), 100_000);
}

#[tokio::test(start_paused = true)]
async fn settled_prior_attempt_reconciles_original_once_across_restart() {
    let (mut fx, sender, target, requests) = stranger(false).await;
    let token = fx.grant(None, GrantTerms::new(20_000)).await;
    let original = reserve(&fx, 6000);
    let invoice = target.create_invoice(2000, "prior", 55).await.unwrap();
    sender.pay_invoice(&invoice.bolt11).await.unwrap();
    journal(&fx, &original, &invoice.payment_hash);
    for _ in 0..2 {
        fx.restart();
        let (status, body) = send(&fx, &token, 4000).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert_eq!(body["amount_msat"], 0, "retry did not pay again");
        assert_eq!(fx.used(), 2000);
    }
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(sender.get_balance_msat().await.unwrap(), 98_000);
}

#[tokio::test]
async fn revoking_grant_while_admission_quote_is_pending_prevents_payment() {
    let (mut fx, sender, target, _) = stranger(false).await;
    fx.state = Arc::new(AppState {
        transport: Arc::new(ConnectedStubTransport::new(vec![fx.peer], fx.state.invoice_requests.clone())),
        ..(*fx.state).clone()
    });
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    confirm(&fx, &token, 4000).await;
    let state = fx.state.clone();
    let peer = fx.peer;
    let request = tokio::spawn(async move {
        call(&state, "POST", "/api/v1/messages/compose",
            Some(json!({"recipient":peer.to_hex(),"kind":0,"plaintext":"revoke","max_total_msat":4000})), Some(&token)).await
    });
    let (id, response) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let mut pending = fx.state.invoice_requests.lock().await;
            if let Some(id) = pending.keys().next().cloned() {
                break (id.clone(), pending.remove(&id).unwrap());
            }
            drop(pending);
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    assert_eq!(fx.used(), 4000, "aggregate must already be durably reserved");
    fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
    let invoice = target.create_invoice(2000, &format!("konsensus:{id}:message=2000"), 55).await.unwrap();
    response.send(Ok(konsensus_api::state::InvoiceResponseData { recipient:peer, bolt11:invoice.bolt11, payment_hash:invoice.payment_hash })).unwrap();
    let (status, body) = request.await.unwrap();
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "budget_exceeded");
    assert_eq!(sender.get_balance_msat().await.unwrap(), 100_000);
}

#[tokio::test(start_paused = true)]
async fn old_admission_never_charges_replacement_grant() {
    let (mut fx, sender, target, requests) = stranger(false).await;
    fx.grant(None, GrantTerms::new(10_000)).await;
    let original = reserve(&fx, 6000);
    let invoice = target.create_invoice(2000, "prior grant", 55).await.unwrap();
    sender.pay_invoice(&invoice.bolt11).await.unwrap();
    journal(&fx, &original, &invoice.payment_hash);
    let token = fx.grant(None, GrantTerms::new(20_000)).await;
    fx.restart();
    let (status, body) = send(&fx, &token, 4000).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["amount_msat"], 0);
    assert_eq!(fx.used(), 0, "a new grant cannot inherit the old admission debit");
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(sender.get_balance_msat().await.unwrap(), 98_000);
}

#[tokio::test(start_paused = true)]
async fn unknown_second_leg_keeps_original_aggregate_reserved_after_restart() {
    let (mut fx, sender, target, requests) = stranger(false).await;
    let token = fx.grant(None, GrantTerms::new(20_000)).await;
    let original = reserve(&fx, 6000);
    let invoice = target.create_invoice(2000, "before cancellation", 55).await.unwrap();
    sender.pay_invoice(&invoice.bolt11).await.unwrap();
    journal(&fx, &original, &invoice.payment_hash);
    let path = fx.tmp.path().join("admission-attempts").join(fx.peer.to_hex());
    let mut attempt: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    // Models cancellation after the durable message-dispatch marker: knowing
    // admission settled cannot establish the outcome of the second payment.
    attempt["message_may_have_dispatched"] = json!(true);
    std::fs::write(path, serde_json::to_vec(&attempt).unwrap()).unwrap();
    fx.restart();
    let (status, body) = send(&fx, &token, 4000).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(fx.used(), 6000);
    assert_eq!(requests.load(Ordering::SeqCst), 0);
    assert_eq!(sender.get_balance_msat().await.unwrap(), 98_000);
}


async fn prior_admission_refusal_emits_membrane_event(refuse_budget: bool) {
    let (mut fx, sender, target, _) = stranger(false).await;
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    fx.peer = *identity.node_id();
    let peer = fx.peer;
    let transport = Arc::new(ConnectedStubTransport::new(
        vec![peer],
        fx.state.invoice_requests.clone(),
    ));
    fx.state = Arc::new(AppState {
        transport: transport.clone(),
        ..(*fx.state).clone()
    });
    let token = fx.grant(None, GrantTerms::new(20_000)).await;
    let original = reserve(&fx, 6000);
    let invoice = target
        .create_invoice(2000, "prior settled admission", 55)
        .await
        .unwrap();
    sender.pay_invoice(&invoice.bolt11).await.unwrap();
    journal(&fx, &original, &invoice.payment_hash);
    let session = fx.state.session_manager.clone();
    let service = fx.service.clone();
    let client_id = fx.client_id.clone();
    let establish = tokio::spawn(async move {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !transport.sent_envelopes.lock().unwrap().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("prior admission proof was redelivered");
        if refuse_budget {
            service.revoke_grants(Some(&client_id)).unwrap();
        }
        let target_session = konsensus_crypto::SessionManager::new(Arc::new(identity));
        session
            .initiate_session(&peer, &target_session.prekey_bundle().await)
            .await
            .unwrap();
    });
    let (status, body) = send(&fx, &token, if refuse_budget { 4000 } else { 1000 }).await;
    establish.await.unwrap();
    assert_eq!(
        sender.get_balance_msat().await.unwrap(),
        98_000,
        "retry made no new payment"
    );
    assert_eq!(
        fx.used(),
        if refuse_budget { 0 } else { 2000 },
        "retry must not charge a new payment"
    );
    let (_, totals) = fx.state.audit_log.membrane().read(None, 500);
    assert_eq!(
        totals.outbound_refused, 1,
        "refusal before any payment by this retry must emit N2; status={status}, body={body}"
    );
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(
        body["code"],
        if refuse_budget {
            "budget_exceeded"
        } else {
            "price_cap_exceeded"
        }
    );
}

#[tokio::test]
async fn prior_admission_cap_refusal_emits_membrane_event_without_new_payment() {
    prior_admission_refusal_emits_membrane_event(false).await;
}

#[tokio::test]
async fn prior_admission_budget_refusal_emits_membrane_event_without_new_payment() {
    prior_admission_refusal_emits_membrane_event(true).await;
}
// A failed operation journal must not create an unpaid admission guard.
#[tokio::test]
async fn failed_admission_operation_journal_does_not_poison_unpaid_retry() {
    use konsensus_storage::Storage;
    use konsensus_storage::SqliteStorage;
    for mode in ["failed_write", "committed_write", "other_operation"] {
    let (mut fx, sender, _target, requests) = stranger(true).await;
    let db = Arc::new(SqliteStorage::open(fx.tmp.path().join("review113.db").to_str().unwrap()).await.unwrap());
    fx.state = Arc::new(AppState { storage: db.clone(), ..(*fx.state).clone() });
    let token = fx.grant(None, GrantTerms::new(20_000)).await;
    let id = uuid::Uuid::new_v4().to_string();
    let mut request = json!({"operation_id":id,"recipient":fx.peer.to_hex(),"kind":0,"plaintext":"operation write failure","max_total_msat":6000,"wait_ack_ms":0});
    sqlx::raw_sql("CREATE TRIGGER review113_crash BEFORE UPDATE ON outbox_operations WHEN NEW.admission_payment_hash IS NOT NULL BEGIN SELECT RAISE(ABORT, 'review113 admission journal failure'); END").execute(db.pool()).await.unwrap();
    confirm(&fx, &token, 6000).await;
    let first = fx.call("POST", "/api/v1/messages/compose", Some(request.clone()), Some(&token)).await;
    assert_eq!(first.0, StatusCode::INTERNAL_SERVER_ERROR, "{first:?}");
    assert_eq!(requests.load(Ordering::SeqCst), 1);
    assert_eq!(sender.get_balance_msat().await.unwrap(), 100_000, "no Lightning dispatch occurred");
    assert_eq!(fx.used(), 0, "known unpaid reservation released");
    let op = db.get_outbox_operation(&id).await.unwrap().unwrap();
    assert_eq!(op.state, "prepared");
    assert!(op.admission_payment_hash.is_none());
    sqlx::raw_sql("DROP TRIGGER review113_crash").execute(db.pool()).await.unwrap();
    // False dispatch marker survives both failed and committed SQL writes.
    // In other_operation mode the prior fields are not yet visible: cleanup
    // must still fence the old version against a late cancelled SQL update.
    let stale = op.clone();
    if mode == "committed_write" {
        let journal: Value = serde_json::from_slice(&std::fs::read(fx.tmp.path().join("admission-attempts").join(fx.peer.to_hex())).unwrap()).unwrap();
        assert_eq!(journal["dispatch_started"], false);
        let mut op = op;
        let mut data: Value = serde_json::from_slice(&op.recovery).unwrap();
        data["admission_pending"] = true.into();
        data["admission_expected_msat"] = journal["amount_msat"].clone();
        data["admission_reservation"] = journal["original_reservation"].clone();
        op.admission_payment_hash = Some(journal["payment_hash"].as_str().unwrap().into());
        op.recovery = serde_json::to_vec(&data).unwrap();
        op.state = "payment_unknown".into();
        assert!(db.update_outbox_operation(&op).await.unwrap());
        fx.restart();
    }
    if mode == "other_operation" { request["operation_id"] = uuid::Uuid::new_v4().to_string().into(); }
    confirm(&fx, &token, 6000).await;
    let retry = fx.call("POST", "/api/v1/messages/compose", Some(request), Some(&token)).await;
    assert_eq!(retry.0, StatusCode::OK, "known undispatched admission must recover after its failed write: {retry:?}");
    assert_eq!(sender.get_balance_msat().await.unwrap(), 96_000);
    assert_eq!(fx.used(), 4000);
    if mode == "other_operation" {
        assert!(!db.update_outbox_operation(&stale).await.unwrap(), "late cancelled SQL writer must be fenced");
        assert_eq!(db.get_outbox_operation(&id).await.unwrap().unwrap().state, "prepared");
    }
    }
}

/// Preserve real admission settlement; interrupt only the selected wallet call.
struct RefusingLeg {
    inner: Arc<SharedMockProvider>,
    calls: AtomicUsize,
    leg: usize,
    unknown: bool,
}
#[async_trait]
impl LightningProvider for RefusingLeg {
    async fn create_invoice(&self, a: u64, d: &str, e: u32) -> Result<Invoice, LightningError> {
        self.inner.create_invoice(a, d, e).await
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        panic!("uncapped payment")
    }
    async fn pay_invoice_with_fee_limit(&self, b: &str, fee: u64) -> Result<PaymentDetails, LightningError> {
        if self.calls.fetch_add(1, Ordering::SeqCst) == self.leg {
            return if self.unknown {
                Err(LightningError::Backend("not dispatched (untrusted backend text)".into()))
            } else {
                Err(LightningError::PaymentNotDispatched("route exceeds fee ceiling".into()))
            };
        }
        self.inner.pay_invoice_with_fee_limit(b, fee).await
    }
    async fn get_payment_status(&self, h: &str) -> Result<PaymentDetails, LightningError> {
        self.inner.get_payment_status(h).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> { self.inner.get_balance_msat().await }
    async fn is_available(&self) -> bool { true }
}

#[tokio::test]
async fn first_contact_non_dispatch_preserves_partial_settlement_and_unknown_holds() {
    for (leg, unknown, expected_used) in [(0, false, 0), (0, true, 6000), (1, false, 2000), (1, true, 6000)] {
        let (mut fx, sender, _, _) = stranger(leg == 1).await;
        let wallet = Arc::new(RefusingLeg { inner: sender, calls: AtomicUsize::new(0), leg, unknown });
        fx.state = Arc::new(AppState {
            lightning: wallet.clone(),
            storage: Arc::new(konsensus_storage::SqliteStorage::open(fx.tmp.path().join("outbox.db").to_str().unwrap()).await.unwrap()),
            ..(*fx.state).clone()
        });
        let token = fx.grant(None, GrantTerms::new(10000)).await;
        let (status, body) = send(&fx, &token, 6000).await;
        if leg == 0 && !unknown {
            assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
            assert_eq!(body["code"], "not_dispatched");
            assert_eq!(body["state"], "prepared");
        } else {
            assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
            assert_ne!(body["code"], "not_dispatched", "a paid admission or unknown leg prevents an aggregate non-dispatch claim");
        }
        assert_eq!(fx.used(), expected_used, "{body}");
        for _ in 0..2 {
            super::not_dispatched::recover(&mut fx).await;
            assert_eq!(fx.used(), expected_used, "recovery must retain paid admissions and unknown attempts");
        }
        assert_eq!(wallet.calls.load(Ordering::SeqCst), leg + 1);
    }
}
