//! K1 × G1: delegation cannot approve gifts. Owner-approved gifts use the
//! sponsor purse; legacy grant-backed operations still reconcile after restart.
use super::*;
use konsensus_api::handlers::introduction::IntroductionSettings;
use konsensus_api::handlers::sponsor::SponsorPolicy;
use konsensus_lightning::shared_mock::SharedMockProvider;

const GIFT: u64 = 20_000;
const FEE: u64 = 1_000;

fn intro(port: u16) -> IntroductionSettings {
    IntroductionSettings { network: Some("regtest".into()), endpoint: Some(format!("127.0.0.1:{port}")) }
}

/// The owner's node (sponsoring on) with a paired app holding `budget`, and a
/// newcomer node on its own mock wallet. Returns the app's token and the
/// kit's candidate, frozen and ready for approval.
async fn kit(budget: u64) -> (Fx, String, Value) {
    let mut fx = fixture().await;
    fx.state = Arc::new(AppState {
        sponsor: SponsorPolicy::new(true, GIFT, FEE, 1_000_000, 2).unwrap(),
        introduction: intro(9001),
        ..(*fx.state).clone()
    });
    let token = fx.grant(None, GrantTerms::new(budget)).await;
    let path = fx.tmp.path().join("newcomer-ln.db");
    let (_, identity) = konsensus_core::identity::NodeIdentity::generate().unwrap();
    let base = test_state_with_lightning(Arc::new(SharedMockProvider::new(&path, "newcomer", 0).unwrap()));
    let newcomer = Arc::new(AppState { identity: Arc::new(identity), introduction: intro(9002), ..(*base).clone() });
    let newcomer_token = konsensus_api::auth::create_token(
        &newcomer.identity.node_id().to_hex(), &newcomer.jwt_secret, Scope::all()).unwrap();

    let (s, offer) = fx.call("POST", "/api/v1/sponsor/offer", None, Some(&token)).await;
    assert_eq!(s, StatusCode::OK, "{offer}");
    let (s, ask) = call(&newcomer, "POST", "/api/v1/sponsor/request", Some(json!({"link": offer["link"]})), Some(&newcomer_token)).await;
    assert_eq!(s, StatusCode::OK, "{ask}");
    let (s, cand) = fx.call("POST", "/api/v1/sponsor/candidate", Some(json!({"request": ask["request"]})), Some(&token)).await;
    assert_eq!(s, StatusCode::OK, "{cand}");
    (fx, token, cand)
}

fn approval(cand: &Value) -> Value {
    json!({"intro_id":cand["intro_id"], "code":cand["code"],
        "newcomer":cand["newcomer"], "payment_hash":cand["payment_hash"],
        "gift_msat":cand["gift_msat"], "fee_max_msat":cand["fee_max_msat"]})
}

async fn owner_approve(fx: &Fx, cand: &Value) -> (StatusCode, Value) {
    let owner = auth_header(&fx.state);
    approve(fx, owner.trim_start_matches("Bearer "), cand).await
}

// Old versions could dispatch against G1. Seed their durable state so the
// reconciliation contract remains tested without enabling new paired approval.
async fn legacy_unknown(fx: &Fx) {
    let path = fx.state.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let epoch = fx.service.snapshot().clients.iter().find(|c| c.client_id == fx.client_id).unwrap().epoch;
    let recipient = ledger["kits"][0]["candidate"]["newcomer_ln"].as_str().unwrap().to_owned();
    let reservation = fx.service.reserve_spend(&fx.client_id, epoch, vec![Charge { recipient, amount_msat: GIFT }]).unwrap();
    ledger["kits"][0]["state"] = json!("unknown");
    ledger["kits"][0]["reserved_msat"] = json!(GIFT + FEE);
    ledger["kits"][0]["fresh_payment_hash"] = json!(true);
    ledger["kits"][0]["grant_reservation"] = serde_json::to_value(reservation).unwrap();
    std::fs::write(path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    fx.wallet.set(UNKNOWN);
    assert!(fx.wallet.pay_invoice_with_fee_limit(ledger["kits"][0]["candidate"]["bolt11"].as_str().unwrap(), FEE).await.is_err());
}

async fn approve(fx: &Fx, token: &str, cand: &Value) -> (StatusCode, Value) {
    fx.call("POST", "/api/v1/sponsor/approve", Some(approval(cand)), Some(token)).await
}

async fn kit_state(fx: &Fx, token: &str) -> (Value, Value) {
    let (_, status) = fx.call("GET", "/api/v1/sponsor", None, Some(token)).await;
    (status["kits"][0]["state"].clone(), status["purse_used_msat"].clone())
}

#[tokio::test]
async fn a_grant_that_cannot_cover_the_gift_pays_nothing() {
    let (fx, token, cand) = kit(GIFT - 1).await;
    let (s, body) = approve(&fx, &token, &cand).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("sponsor_owner_approval_required"));
    assert_eq!(fx.wallet.money(), 0, "nothing dispatched");
    assert_eq!(kit_state(&fx, &token).await, (json!("candidate"), json!(0)), "the kit waits, nothing reserved");
}

#[tokio::test]
async fn regression_g1_alone_cannot_approve_a_sponsor_gift() {
    let (fx, token, cand) = kit(50_000).await;
    let (s, body) = approve(&fx, &token, &cand).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("sponsor_owner_approval_required"), "{body}");
    assert_eq!(fx.used(), 0);
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!(kit_state(&fx, &token).await, (json!("candidate"), json!(0)));
}

#[tokio::test]
async fn an_unknown_outcome_stays_reserved_and_blocks_a_new_kit() {
    let (fx, token, cand) = kit(50_000).await;
    fx.wallet.set(UNKNOWN);
    let (s, body) = owner_approve(&fx, &cand).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "unknown");
    assert_eq!(kit_state(&fx, &token).await, (json!("unknown"), json!(GIFT + FEE)), "gift + fee ceiling stay held");
    let (s, body) = fx.call("POST", "/api/v1/sponsor/offer", None, Some(&token)).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(body.to_string().contains("sponsor_kit_open"), "{body}");
}

#[tokio::test]
async fn an_owner_payment_failure_closes_the_kit_without_debiting_a_grant() {
    let (fx, token, cand) = kit(50_000).await;
    fx.wallet.set(FAILED);
    let (s, body) = owner_approve(&fx, &cand).await;
    assert_ne!(s, StatusCode::OK, "{body}");
    assert_eq!(kit_state(&fx, &token).await, (json!("failed"), json!(0)));
    assert_eq!(fx.used(), 0, "owner approval never debits the paired grant");
    // Single use: a failed kit is not retried; the sponsor makes a new offer.
    let (s, _) = owner_approve(&fx, &cand).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn regression_definitive_reconcile_releases_grant_hold_after_restart() {
    let (mut fx, _token, cand) = kit(50_000).await;
    legacy_unknown(&fx).await;
    assert_eq!(fx.used(), GIFT);
    fx.restart();
    fx.wallet.set(FAILED);
    let token = fx.token().await;
    let (s, body) = fx.call("POST", &format!("/api/v1/sponsor/kits/{}/reconcile", cand["intro_id"].as_str().unwrap()), None, Some(&token)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "failed");
    assert_eq!(fx.used(), 0, "definitively failed sponsor operation must release G1 hold; pending={:?}", fx.service.snapshot().grants[0].budget.as_ref().unwrap().pending);
    fx.restart();
    let token = fx.token().await;
    let (s, _) = fx.call("POST", &format!("/api/v1/sponsor/kits/{}/reconcile", cand["intro_id"].as_str().unwrap()), None, Some(&token)).await;
    assert_eq!(s, StatusCode::OK, "terminal reconciliation is idempotent after restart");
    assert_eq!(fx.used(), 0);
}

#[tokio::test]
async fn sponsor_journal_failure_never_dispatches() {
    let (fx, _token, cand) = kit(50_000).await;
    let dir = fx.state.data_dir.as_ref().unwrap().join("sponsor");
    std::fs::create_dir(dir.join("kits.json.tmp")).unwrap();
    let (s, _) = owner_approve(&fx, &cand).await;
    assert_ne!(s, StatusCode::OK);
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!(fx.used(), 0);
    assert!(fx.service.snapshot().grants[0].budget.as_ref().unwrap().pending.is_empty());
}

#[tokio::test]
async fn cancelled_owner_dispatch_retains_its_purse_reservation_for_restart() {
    let (mut fx, _token, cand) = kit(50_000).await;
    fx.wallet.pause_dispatch.store(true, Ordering::SeqCst);
    let state = fx.state.clone();
    let request = approval(&cand);
    let token = auth_header(&fx.state).trim_start_matches("Bearer ").to_owned();
    let pending = tokio::spawn(async move {
        call(&state, "POST", "/api/v1/sponsor/approve", Some(request), Some(&token)).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while fx.wallet.waiting.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    let ledger: Value = serde_json::from_slice(&std::fs::read(fx.state.data_dir.as_ref().unwrap().join("sponsor/kits.json")).unwrap()).unwrap();
    assert!(ledger["kits"][0]["grant_reservation"].is_null());
    assert_eq!(ledger["kits"][0]["reserved_msat"], GIFT + FEE);
    assert_eq!(fx.wallet.money(), 0, "reservation exists before first dispatch");
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    fx.restart();
    assert_eq!(fx.used(), 0);
    assert_eq!(kit_state(&fx, &fx.token().await).await.1, GIFT + FEE);
    fx.wallet.set(FAILED);
    let token = fx.token().await;
    let (s, body) = fx.call("POST", &format!("/api/v1/sponsor/kits/{}/reconcile", cand["intro_id"].as_str().unwrap()), None, Some(&token)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(fx.used(), 0);
}

#[tokio::test]
async fn reconciliation_needs_read_authority_but_never_a_new_spend_grant() {
    let (fx, _token, cand) = kit(50_000).await;
    fx.wallet.set(UNKNOWN);
    assert_eq!(owner_approve(&fx, &cand).await.0, StatusCode::OK);
    fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
    fx.wallet.set(FAILED);
    let read_token = fx.token().await;
    let (s, body) = fx.call("POST", &format!("/api/v1/sponsor/kits/{}/reconcile", cand["intro_id"].as_str().unwrap()), None, Some(&read_token)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "failed");
    assert_eq!(fx.wallet.money(), 1, "reconciliation never sends another payment");
}

#[tokio::test]
async fn paired_approval_is_refused_before_parsing_the_funding_intent() {
    let (fx, token, cand) = kit(50_000).await;
    let (s, body) = fx.call("POST", "/api/v1/sponsor/approve",
        Some(json!({"intro_id":cand["intro_id"], "code":cand["code"]})), Some(&token)).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("sponsor_owner_approval_required"), "{body}");
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!(fx.used(), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn owner_socket_gift_checks_every_field_and_refuses_replay() {
    let (fx, token, cand) = kit(50_000).await;
    let server = control::ControlServer::bind(fx.tmp.path(), Arc::new(fx.control())).unwrap()
        .with_approval_state(fx.state.clone());
    let path = server.path().to_owned();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(server.serve(rx));
    let mut body = approval(&cand);
    body["op"] = json!("approve-gift");
    for (field, wrong) in [("intro_id", json!("wrong")), ("newcomer", json!("ff".repeat(32))),
        ("payment_hash", json!("ff".repeat(32))), ("gift_msat", json!(GIFT + 1)),
        ("fee_max_msat", json!(FEE + 1)), ("code", json!("bad"))] {
        let mut bad = body.clone();
        bad[field] = wrong;
        let req = serde_json::from_value(bad).unwrap();
        assert!(matches!(control::send(&path, &req).await.unwrap(), ControlResponse::Error { .. }));
        assert_eq!(fx.wallet.money(), 0, "mismatch must not dispatch");
        assert_eq!(kit_state(&fx, &token).await, (json!("candidate"), json!(0)));
    }
    let req = serde_json::from_value(body).unwrap();
    assert!(matches!(control::send(&path, &req).await.unwrap(), ControlResponse::Ok { .. }));
    let paid = fx.wallet.money();
    assert!(paid > 0);
    assert!(matches!(control::send(&path, &req).await.unwrap(), ControlResponse::Error { .. }));
    assert_eq!(fx.wallet.money(), paid, "replay must not dispatch twice");
    assert_eq!(fx.used(), 0, "owner gift uses sponsor purse, never paired budget");
    assert_eq!(approve(&fx, &token, &cand).await.0, StatusCode::CONFLICT);
    stop.send(true).unwrap();
    task.await.unwrap();
}
