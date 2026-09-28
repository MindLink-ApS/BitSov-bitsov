//! K1 slice 2 × G1: a paired app approving a sponsor gift is debited against
//! its owner-granted budget as well as the node's sponsor purse; outcomes
//! settle, release or stay reserved on both.
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

async fn approve(fx: &Fx, token: &str, cand: &Value) -> (StatusCode, Value) {
    fx.call("POST", "/api/v1/sponsor/approve", Some(json!({"intro_id": cand["intro_id"], "code": cand["code"]})), Some(token)).await
}

async fn kit_state(fx: &Fx, token: &str) -> (Value, Value) {
    let (_, status) = fx.call("GET", "/api/v1/sponsor", None, Some(token)).await;
    (status["kits"][0]["state"].clone(), status["purse_used_msat"].clone())
}

#[tokio::test]
async fn a_grant_that_cannot_cover_the_gift_pays_nothing() {
    let (fx, token, cand) = kit(GIFT - 1).await;
    let (s, body) = approve(&fx, &token, &cand).await;
    // A grant's per-call maximum defaults to its total: refused as per_call.
    assert_budget_exceeded(s, &body, "per_call");
    assert_eq!(fx.wallet.money(), 0, "nothing dispatched");
    assert_eq!(kit_state(&fx, &token).await, (json!("candidate"), json!(0)), "the kit waits, nothing reserved");
}

#[tokio::test]
async fn a_settled_gift_is_debited_once_from_the_grant() {
    let (fx, token, cand) = kit(50_000).await;
    let (s, body) = approve(&fx, &token, &cand).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "funded");
    assert_eq!(fx.used(), GIFT);
    assert_eq!(fx.wallet.money(), 1);
    assert_eq!(kit_state(&fx, &token).await, (json!("funded"), json!(GIFT)));
}

#[tokio::test]
async fn an_unknown_outcome_stays_reserved_and_blocks_a_new_kit() {
    let (fx, token, cand) = kit(50_000).await;
    fx.wallet.set(UNKNOWN);
    let (s, body) = approve(&fx, &token, &cand).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "unknown");
    assert_eq!(kit_state(&fx, &token).await, (json!("unknown"), json!(GIFT + FEE)), "gift + fee ceiling stay held");
    let (s, body) = fx.call("POST", "/api/v1/sponsor/offer", None, Some(&token)).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(body.to_string().contains("sponsor_kit_open"), "{body}");
}

#[tokio::test]
async fn a_failed_payment_closes_the_kit_and_releases_both_holds() {
    let (fx, token, cand) = kit(50_000).await;
    fx.wallet.set(FAILED);
    let (s, body) = approve(&fx, &token, &cand).await;
    assert_ne!(s, StatusCode::OK, "{body}");
    assert_eq!(kit_state(&fx, &token).await, (json!("failed"), json!(0)));
    assert_eq!(fx.used(), 0, "the grant debit is released");
    // Single use: a failed kit is not retried; the sponsor makes a new offer.
    let (s, _) = approve(&fx, &token, &cand).await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn regression_definitive_reconcile_releases_grant_hold_after_restart() {
    let (mut fx, token, cand) = kit(50_000).await;
    fx.wallet.set(UNKNOWN);
    let (s, body) = approve(&fx, &token, &cand).await;
    assert_eq!(s, StatusCode::OK, "{body}");
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
async fn sponsor_journal_failure_never_orphans_a_grant_debit_or_dispatches() {
    let (fx, token, cand) = kit(50_000).await;
    let dir = fx.state.data_dir.as_ref().unwrap().join("sponsor");
    std::fs::create_dir(dir.join("kits.json.tmp")).unwrap();
    let (s, _) = approve(&fx, &token, &cand).await;
    assert_ne!(s, StatusCode::OK);
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!(fx.used(), 0);
    assert!(fx.service.snapshot().grants[0].budget.as_ref().unwrap().pending.is_empty());
}

#[tokio::test]
async fn cancelled_dispatch_retains_its_durable_grant_reference_for_restart() {
    let (mut fx, token, cand) = kit(50_000).await;
    fx.wallet.pause_dispatch.store(true, Ordering::SeqCst);
    let state = fx.state.clone();
    let request = json!({"intro_id":cand["intro_id"], "code":cand["code"]});
    let pending = tokio::spawn(async move {
        call(&state, "POST", "/api/v1/sponsor/approve", Some(request), Some(&token)).await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while fx.wallet.waiting.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    }).await.unwrap();
    let ledger: Value = serde_json::from_slice(&std::fs::read(fx.state.data_dir.as_ref().unwrap().join("sponsor/kits.json")).unwrap()).unwrap();
    let id = ledger["kits"][0]["grant_reservation"]["id"].as_str().unwrap();
    assert!(fx.service.snapshot().grants[0].budget.as_ref().unwrap().pending.contains_key(id));
    assert_eq!(fx.wallet.money(), 0, "reference exists before first dispatch");
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    fx.restart();
    assert_eq!(fx.used(), GIFT);
    fx.wallet.set(FAILED);
    let token = fx.token().await;
    let (s, body) = fx.call("POST", &format!("/api/v1/sponsor/kits/{}/reconcile", cand["intro_id"].as_str().unwrap()), None, Some(&token)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(fx.used(), 0);
}

#[tokio::test]
async fn reconciliation_needs_read_authority_but_never_a_new_spend_grant() {
    let (fx, token, cand) = kit(50_000).await;
    fx.wallet.set(UNKNOWN);
    assert_eq!(approve(&fx, &token, &cand).await.0, StatusCode::OK);
    fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
    fx.wallet.set(FAILED);
    let read_token = fx.token().await;
    let (s, body) = fx.call("POST", &format!("/api/v1/sponsor/kits/{}/reconcile", cand["intro_id"].as_str().unwrap()), None, Some(&read_token)).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "failed");
    assert_eq!(fx.wallet.money(), 1, "reconciliation never sends another payment");
}
