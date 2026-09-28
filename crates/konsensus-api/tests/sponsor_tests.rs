//! K1 slice 2: capped sponsor sats, two nodes on one shared mock ledger.
//! The gift is real (mock) bitcoin into the newcomer's own wallet; its hash
//! is funding-only; every cap is node-enforced; nothing is a free lane.
#![allow(dead_code)]
mod common;
use common::*;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::{json, Value};
use tower::ServiceExt;

use konsensus_api::handlers::introduction::IntroductionSettings;
use konsensus_api::handlers::sponsor::SponsorPolicy;
use konsensus_api::state::AppState;
use konsensus_core::gate::{NonceStore, PaidReplay};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::sponsor::FundingRequest;
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::types::{MessageId, Nonce};
use konsensus_lightning::shared_mock::SharedMockProvider;

const GIFT: u64 = 20_000; // 20 sats: small, so a 1,000-sat mock purse pays several kits.
const FEE: u64 = 1_000;

struct Pair {
    _dir: tempfile::TempDir,
    sponsor: Arc<AppState>,
    newcomer: Arc<AppState>,
    sponsor_ln: Arc<SharedMockProvider>,
    newcomer_ln: Arc<SharedMockProvider>,
}

fn policy(purse_msat: u64, kits_per_day: u32) -> SponsorPolicy {
    SponsorPolicy::new(true, GIFT, FEE, purse_msat, kits_per_day).unwrap()
}

async fn pair(policy: SponsorPolicy) -> Pair {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.db");
    let sponsor_ln = Arc::new(SharedMockProvider::new(&ledger, "sponsor", 1_000_000).unwrap());
    let newcomer_ln = Arc::new(SharedMockProvider::new(&ledger, "newcomer", 0).unwrap());
    let intro = |port: u16| IntroductionSettings { network: Some("regtest".into()), endpoint: Some(format!("127.0.0.1:{port}")) };
    let base = test_state_with_lightning(sponsor_ln.clone());
    let sponsor_dir = dir.path().join("sponsor-node");
    let sponsor = Arc::new(AppState {
        introduction: intro(9001),
        sponsor: policy,
        data_dir: Some(sponsor_dir),
        ..(*base).clone()
    });
    // The newcomer: its own identity, wallet and a real SQLite receipt table.
    let (_, identity) = NodeIdentity::generate().unwrap();
    let storage = Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let nbase = test_state_with_lightning(newcomer_ln.clone());
    let newcomer = Arc::new(AppState {
        identity: Arc::new(identity),
        storage,
        introduction: intro(9002),
        data_dir: Some(dir.path().join("newcomer-node")),
        ..(*nbase).clone()
    });
    Pair { _dir: dir, sponsor, newcomer, sponsor_ln, newcomer_ln }
}

async fn call(state: &Arc<AppState>, method: &str, path: &str, body: Option<Value>) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", auth_header(state))
        .header("content-type", "application/json");
    let body = body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty);
    let resp = test_router(state.clone()).oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(json!({ "raw": String::from_utf8_lossy(&bytes) })))
}

fn approval(candidate: &Value) -> Value {
    json!({
        "intro_id": candidate["intro_id"], "code": candidate["code"],
        "newcomer": candidate["newcomer"], "payment_hash": candidate["payment_hash"],
        "gift_msat": candidate["gift_msat"], "fee_max_msat": candidate["fee_max_msat"],
    })
}

/// Offer → request → candidate: what the two people see before approval.
async fn up_to_candidate(p: &Pair) -> (Value, Value) {
    let (s, offer) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    assert_eq!(s, StatusCode::OK, "{offer}");
    let (s, ask) = call(&p.newcomer, "POST", "/api/v1/sponsor/request", Some(json!({ "link": offer["link"] }))).await;
    assert_eq!(s, StatusCode::OK, "{ask}");
    let (s, cand) = call(&p.sponsor, "POST", "/api/v1/sponsor/candidate", Some(json!({ "request": ask["request"] }))).await;
    assert_eq!(s, StatusCode::OK, "{cand}");
    (ask, cand)
}

#[tokio::test]
async fn the_gift_arrives_after_one_approval_with_the_matching_code() {
    let p = pair(policy(1_000_000, 2)).await;
    let (s, offer) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    assert_eq!(s, StatusCode::OK, "{offer}");
    let link = offer["link"].as_str().unwrap();
    assert!(link.starts_with("bitsov://introduce#") && link.contains('.'), "card + offer: {link}");
    assert_eq!(offer["gift_msat"], GIFT);

    let (s, ask) = call(&p.newcomer, "POST", "/api/v1/sponsor/request", Some(json!({ "link": link }))).await;
    assert_eq!(s, StatusCode::OK, "{ask}");
    assert_eq!(ask["amount_msat"], GIFT);
    let (s, cand) = call(&p.sponsor, "POST", "/api/v1/sponsor/candidate", Some(json!({ "request": ask["request"] }))).await;
    assert_eq!(s, StatusCode::OK, "{cand}");
    assert_eq!(cand["code"], ask["code"], "both screens show the same six digits");
    assert_eq!(cand["newcomer"], p.newcomer.identity.node_id().to_hex());

    // A wrong code pays nothing.
    let before = p.newcomer_ln.get_balance_msat().await.unwrap();
    let wrong = if cand["code"] == "000000" { "111111" } else { "000000" };
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some({ let mut body = approval(&cand); body["code"] = json!(wrong); body })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), before);

    let (s, paid) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await;
    assert_eq!(s, StatusCode::OK, "{paid}");
    assert_eq!(paid["state"], "funded");
    assert_eq!(paid["paid_msat"], GIFT);
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), before + GIFT, "real sats in the newcomer's own wallet");

    let hash = ask["payment_hash"].as_str().unwrap();
    let (s, st) = call(&p.newcomer, "GET", &format!("/api/v1/sponsor/request/{hash}"), None).await;
    assert_eq!((s, st["state"].clone(), st["amount_msat"].clone()), (StatusCode::OK, json!("received"), json!(GIFT)));

    // Single use: the same kit never pays twice.
    let (s, again) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await;
    assert_eq!(s, StatusCode::CONFLICT, "{again}");
    let (_, status) = call(&p.sponsor, "GET", "/api/v1/sponsor", None).await;
    assert_eq!(status["purse_used_msat"], GIFT);
    assert_eq!(status["kits_today"], 1);
    assert_eq!(status["kits"][0]["candidate"]["bolt11"], "", "the read leaves invoices out");
}

#[tokio::test]
async fn the_gift_hash_is_funding_only_and_never_admits_a_message() {
    let p = pair(policy(1_000_000, 2)).await;
    let (ask, cand) = up_to_candidate(&p).await;
    call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await;
    // The sponsor learned the preimage by paying. The newcomer's gate must
    // still refuse that payment as a message proof: it is a used receipt.
    let hash: [u8; 32] = hex::decode(ask["payment_hash"].as_str().unwrap()).unwrap().try_into().unwrap();
    let adapter = konsensus_storage::StorageNonceAdapter::new(p.newcomer.storage.clone());
    let reuse = adapter
        .check_and_store_paid(&Nonce::from_bytes([7; 24]), &hash, p.sponsor.identity.node_id(), &MessageId::from_bytes([9; 32]))
        .await
        .unwrap();
    assert!(matches!(reuse, PaidReplay::PaymentReused), "{reuse:?}");
    // Control: an unrelated payment is still accepted by the same store.
    let fresh = adapter
        .check_and_store_paid(&Nonce::from_bytes([8; 24]), &[0x42; 32], p.sponsor.identity.node_id(), &MessageId::from_bytes([10; 32]))
        .await
        .unwrap();
    assert!(matches!(fresh, PaidReplay::Accepted), "{fresh:?}");
}

#[tokio::test]
async fn one_kit_at_a_time_and_the_daily_count_and_purse_hold() {
    // Purse for exactly two kits; two kits a day.
    let p = pair(policy(2 * (GIFT + FEE), 2)).await;
    let (s, _) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    assert_eq!(s, StatusCode::OK);
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(body.to_string().contains("sponsor_kit_open"), "{body}");

    // Cancel it, then run two funded kits.
    let (_, status) = call(&p.sponsor, "GET", "/api/v1/sponsor", None).await;
    let open_id = status["kits"][0]["intro_id"].as_str().unwrap().to_string();
    let (s, _) = call(&p.sponsor, "POST", &format!("/api/v1/sponsor/kits/{open_id}/cancel"), None).await;
    assert_eq!(s, StatusCode::OK);
    for _ in 0..2 {
        let (_, cand) = up_to_candidate(&p).await;
        let (s, paid) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await;
        assert_eq!((s, paid["state"].clone()), (StatusCode::OK, json!("funded")), "{paid}");
    }
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(body.to_string().contains("sponsor_daily_limit"), "{body}");
}

#[tokio::test]
async fn the_purse_refuses_a_kit_it_cannot_cover() {
    // Room for one kit only, although three a day would be allowed... two max.
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (_, cand) = up_to_candidate(&p).await;
    call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await;
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(body.to_string().contains("sponsor_purse_exhausted"), "{body}");
}

#[tokio::test]
async fn a_kit_takes_one_candidate_and_checks_every_binding() {
    let p = pair(policy(1_000_000, 2)).await;
    let (s, offer) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    assert_eq!(s, StatusCode::OK);
    let (_, ask) = call(&p.newcomer, "POST", "/api/v1/sponsor/request", Some(json!({ "link": offer["link"] }))).await;
    let request = FundingRequest::parse(ask["request"].as_str().unwrap()).unwrap();

    // Tampered after signing: refused.
    let mut forged = request.clone();
    forged.amount_msat = GIFT - 1;
    let (s, _) = call(&p.sponsor, "POST", "/api/v1/sponsor/candidate", Some(json!({ "request": forged.to_link() }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    // A different newcomer, correctly signed, but its invoice pays someone else.
    let (_, other) = NodeIdentity::generate().unwrap();
    let offer_rec = konsensus_core::sponsor::SponsorOffer::decode(offer["link"].as_str().unwrap().rsplit_once('.').unwrap().1).unwrap();
    let substituted = FundingRequest::sign(other.ed25519_signing_key(), &offer_rec, [2; 33], GIFT, request.payment_hash, request.expires_at, request.bolt11.clone()).unwrap();
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/candidate", Some(json!({ "request": substituted.to_link() }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("not payable to the key"), "{body}");

    // The real one, twice (idempotent), then a second, different candidate: refused.
    for _ in 0..2 {
        let (s, _) = call(&p.sponsor, "POST", "/api/v1/sponsor/candidate", Some(json!({ "request": ask["request"] }))).await;
        assert_eq!(s, StatusCode::OK);
    }
    let (_, ask2) = call(&p.newcomer, "POST", "/api/v1/sponsor/request", Some(json!({ "link": offer["link"] }))).await;
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/candidate", Some(json!({ "request": ask2["request"] }))).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(body.to_string().contains("sponsor_candidate_exists"), "{body}");
}

#[tokio::test]
async fn off_by_default_and_no_offer_means_no_request() {
    let p = pair(SponsorPolicy::default()).await;
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert!(body.to_string().contains("sponsor_disabled"), "{body}");
    // A plain card (no offer) cannot be turned into a funding request.
    let (_, plain) = call(&p.sponsor, "GET", "/api/v1/introduction", None).await;
    let (s, body) = call(&p.newcomer, "POST", "/api/v1/sponsor/request", Some(json!({ "link": plain["link"] }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.to_string().contains("offers no starter bitcoin"), "{body}");
}

#[tokio::test]
async fn policy_is_clamped_to_the_spec_ceilings() {
    assert!(SponsorPolicy::new(true, 50_000_001, 0, 100_000_000, 2).is_err(), "per kit");
    assert!(SponsorPolicy::new(true, 20_000_000, 100_001, 100_000_000, 2).is_err(), "fee");
    assert!(SponsorPolicy::new(true, 20_000_000, 100_000, 100_000_001, 2).is_err(), "purse");
    assert!(SponsorPolicy::new(true, 20_000_000, 100_000, 100_000_000, 3).is_err(), "kits a day");
    assert!(SponsorPolicy::new(true, 20_000_000, 100_000, 10_000_000, 2).is_err(), "purse below one kit");
    assert!(SponsorPolicy::new(true, 20_000_000, 100_000, 100_000_000, 2).is_ok());
}

#[tokio::test]
async fn regression_lowered_policy_applies_to_pending_candidate() {
    let p = pair(policy(1_000_000, 2)).await;
    let (_, cand) = up_to_candidate(&p).await;
    // Owner lowers gift from 20 to 1 sat and purse from 1000 to 2 sats
    // before this candidate has ever been approved.
    let restarted = Arc::new(AppState {
        sponsor: SponsorPolicy::new(true, 1_000, 1_000, 2_000, 2).unwrap(),
        ..(*p.sponsor).clone()
    });
    let (s, paid) = call(&restarted, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await;
    let (_, st) = call(&restarted, "GET", "/api/v1/sponsor", None).await;
    assert!(s != StatusCode::OK && st["purse_used_msat"].as_u64().unwrap() <= 2_000,
        "old unapproved candidate spent beyond new purse: response={paid}, status={st}");
}

#[tokio::test]
async fn regression_old_unknown_reservation_and_late_settlement_remain_in_purse() {
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (ask, cand) = up_to_candidate(&p).await;
    let path = p.sponsor.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    // Persist an honest old unresolved reservation as if the process resumed
    // after a >24h outage, with payment settlement only becoming known now.
    ledger["kits"][0]["approved_at"] = json!(now - 86_401);
    ledger["kits"][0]["state"] = json!("unknown");
    ledger["kits"][0]["reserved_msat"] = json!(GIFT + FEE);
    std::fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    let (_, before) = call(&p.sponsor, "GET", "/api/v1/sponsor", None).await;
    let request = FundingRequest::parse(ask["request"].as_str().unwrap()).unwrap();
    p.sponsor_ln.pay_invoice(&request.bolt11).await.unwrap();
    let (s, settled) = call(&p.sponsor, "POST", &format!("/api/v1/sponsor/kits/{}/reconcile", cand["intro_id"].as_str().unwrap()), None).await;
    assert_eq!(s, StatusCode::OK, "{settled}");
    let (_, after) = call(&p.sponsor, "GET", "/api/v1/sponsor", None).await;
    let (offer_status, offer) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    assert!(before["purse_used_msat"] == GIFT + FEE && after["purse_used_msat"] == GIFT && offer_status == StatusCode::CONFLICT,
       "unknown exposure aged out and today's settlement frees purse: before={before}, after={after}, new_offer={offer}");
}

struct FeeProvider(Arc<SharedMockProvider>);
#[async_trait::async_trait]
impl LightningProvider for FeeProvider {
    async fn create_invoice(&self, a:u64, d:&str, e:u32) -> Result<konsensus_core::traits::lightning::Invoice,konsensus_core::traits::lightning::LightningError> { self.0.create_invoice(a,d,e).await }
    async fn pay_invoice(&self, b:&str) -> Result<konsensus_core::traits::lightning::PaymentDetails,konsensus_core::traits::lightning::LightningError> {
       let mut result = self.0.pay_invoice(b).await?;
       result.fee_msat = Some(FEE + 1);
       Ok(result)
    }
    async fn get_payment_status(&self,h:&str)->Result<konsensus_core::traits::lightning::PaymentDetails,konsensus_core::traits::lightning::LightningError>{self.0.get_payment_status(h).await}
    async fn get_balance_msat(&self)->Result<u64,konsensus_core::traits::lightning::LightningError>{self.0.get_balance_msat().await}
    async fn keysend(&self,d:&str,a:u64,m:Option<&str>)->Result<konsensus_core::traits::lightning::PaymentDetails,konsensus_core::traits::lightning::LightningError>{self.0.keysend(d,a,m).await}
    async fn is_available(&self)->bool{true}
}
#[tokio::test]
async fn regression_route_fee_is_bounded_before_dispatch() {
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (_, cand) = up_to_candidate(&p).await;
    let before = p.newcomer_ln.get_balance_msat().await.unwrap();
    let state = Arc::new(AppState { lightning: Arc::new(FeeProvider(p.sponsor_ln.clone())), ..(*p.sponsor).clone() });
    let (s, paid) = call(&state, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await;
    let (_, st) = call(&state,"GET","/api/v1/sponsor",None).await;
    assert!(s != StatusCode::OK && st["purse_used_msat"].as_u64().unwrap() <= GIFT + FEE,
       "payment backend received no cap; oversized fee accepted: paid={paid}, status={st}");
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), before, "unbounded backend must never dispatch");
}

#[tokio::test]
async fn regression_signed_request_expiry_is_enforced_at_approval() {
    let p = pair(policy(1_000_000, 2)).await;
    let (_, offer) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    let (_, ask) = call(&p.newcomer, "POST", "/api/v1/sponsor/request", Some(json!({"link":offer["link"]}))).await;
    let original = FundingRequest::parse(ask["request"].as_str().unwrap()).unwrap();
    let offer_rec = konsensus_core::sponsor::SponsorOffer::decode(offer["link"].as_str().unwrap().rsplit_once('.').unwrap().1).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let short = FundingRequest::sign(p.newcomer.identity.ed25519_signing_key(), &offer_rec, original.newcomer_ln, original.amount_msat, original.payment_hash, now + 2, original.bolt11).unwrap();
    let (s, cand) = call(&p.sponsor,"POST","/api/v1/sponsor/candidate",Some(json!({"request":short.to_link()}))).await;
    assert_eq!(s,StatusCode::OK,"{cand}");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let (s, paid) = call(&p.sponsor,"POST","/api/v1/sponsor/approve",Some(approval(&cand))).await;
    assert_ne!(s,StatusCode::OK,"expired signed request still pays: {paid}");
}

/// A zero-fee mock route whose fee report can be temporarily unavailable.
struct ReportedFeeProvider {
    inner: Arc<SharedMockProvider>,
    fee: std::sync::atomic::AtomicU64,
    cap: std::sync::atomic::AtomicU64,
    pause: std::sync::atomic::AtomicBool,
    waiting: std::sync::atomic::AtomicBool,
    resume: tokio::sync::Notify,
    pause_lookup: bool,
}
#[async_trait::async_trait]
impl LightningProvider for ReportedFeeProvider {
    async fn create_invoice(&self, a:u64, d:&str, e:u32) -> Result<konsensus_core::traits::lightning::Invoice,konsensus_core::traits::lightning::LightningError> { self.inner.create_invoice(a,d,e).await }
    async fn pay_invoice(&self, _: &str) -> Result<konsensus_core::traits::lightning::PaymentDetails,konsensus_core::traits::lightning::LightningError> { panic!("unbounded dispatch forbidden") }
    async fn pay_invoice_with_fee_limit(&self, b:&str, cap:u64) -> Result<konsensus_core::traits::lightning::PaymentDetails,konsensus_core::traits::lightning::LightningError> {
        self.cap.store(cap, std::sync::atomic::Ordering::SeqCst);
        if self.pause.load(std::sync::atomic::Ordering::SeqCst) {
            self.waiting.store(true, std::sync::atomic::Ordering::SeqCst);
            self.resume.notified().await;
        }
        let mut paid = self.inner.pay_invoice(b).await?;
        let fee = self.fee.load(std::sync::atomic::Ordering::SeqCst);
        paid.fee_msat = (fee != u64::MAX).then_some(fee);
        Ok(paid)
    }
    async fn get_payment_status(&self,h:&str)->Result<konsensus_core::traits::lightning::PaymentDetails,konsensus_core::traits::lightning::LightningError>{
        if self.pause_lookup {
            self.waiting.store(true, std::sync::atomic::Ordering::SeqCst);
            self.resume.notified().await;
        }
        if self.pause.load(std::sync::atomic::Ordering::SeqCst)
            && self.waiting.load(std::sync::atomic::Ordering::SeqCst) {
            // A definitive prior attempt for this invoice is not the outcome
            // of the currently paused new dispatch.
            return Ok(konsensus_core::traits::lightning::PaymentDetails {
                payment_hash: h.into(), preimage: None, amount_msat: GIFT,
                status: konsensus_core::traits::lightning::PaymentStatus::Failed,
                direction: konsensus_core::traits::lightning::PaymentDirection::Outgoing,
                timestamp: 1, memo: None, fee_msat: Some(0),
            });
        }
        let mut paid = self.inner.get_payment_status(h).await?;
        let fee = self.fee.load(std::sync::atomic::Ordering::SeqCst);
        paid.fee_msat = (fee != u64::MAX).then_some(fee);
        Ok(paid)
    }
    async fn get_balance_msat(&self)->Result<u64,konsensus_core::traits::lightning::LightningError>{self.inner.get_balance_msat().await}
    async fn keysend(&self,d:&str,a:u64,m:Option<&str>)->Result<konsensus_core::traits::lightning::PaymentDetails,konsensus_core::traits::lightning::LightningError>{self.inner.keysend(d,a,m).await}
    async fn is_available(&self)->bool{true}
}

#[tokio::test]
async fn missing_fee_keeps_maximum_reserved_across_restart_and_window_rollover() {
    use std::sync::atomic::Ordering;
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (_, candidate) = up_to_candidate(&p).await;
    let wallet = Arc::new(ReportedFeeProvider { inner: p.sponsor_ln.clone(), fee: u64::MAX.into(), cap: u64::MAX.into(), pause: false.into(), waiting: false.into(), resume: tokio::sync::Notify::new(), pause_lookup: false });
    let state = Arc::new(AppState { lightning: wallet.clone(), ..(*p.sponsor).clone() });
    let (s, paid) = call(&state, "POST", "/api/v1/sponsor/approve", Some(approval(&candidate))).await;
    assert_eq!(s, StatusCode::OK, "{paid}");
    assert_eq!(wallet.cap.load(Ordering::SeqCst), FEE, "exact approved fee cap reaches backend");
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), GIFT);
    let path = state.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    ledger["kits"][0]["approved_at"] = json!(1);
    std::fs::write(path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    let restarted = Arc::new((*state).clone());
    let (_, status) = call(&restarted,"GET","/api/v1/sponsor",None).await;
    assert_eq!(status["purse_used_msat"], GIFT + FEE);
    assert_eq!(call(&restarted,"POST","/api/v1/sponsor/offer",None).await.0, StatusCode::CONFLICT);
    let reconcile = format!("/api/v1/sponsor/kits/{}/reconcile", candidate["intro_id"].as_str().unwrap());
    call(&restarted,"POST",&reconcile,None).await;
    assert_eq!(call(&restarted,"GET","/api/v1/sponsor",None).await.1["purse_used_msat"], GIFT + FEE);
    wallet.fee.store(0, Ordering::SeqCst);
    assert_eq!(call(&restarted,"POST",&reconcile,None).await.0, StatusCode::OK);
    assert_eq!(call(&restarted,"GET","/api/v1/sponsor",None).await.1["purse_used_msat"], GIFT);
}

#[tokio::test]
async fn concurrent_approvals_dispatch_exactly_one_capped_gift() {
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (_, candidate) = up_to_candidate(&p).await;
    let requests = (0..16).map(|_| call(&p.sponsor,"POST","/api/v1/sponsor/approve",
        Some(approval(&candidate))));
    let results = futures::future::join_all(requests).await;
    assert_eq!(results.iter().filter(|(s,_)| *s == StatusCode::OK).count(), 1);
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), GIFT);
    assert_eq!(call(&p.sponsor,"GET","/api/v1/sponsor",None).await.1["purse_used_msat"], GIFT);
}

#[tokio::test]
async fn reconciliation_cannot_release_a_live_dispatch_from_an_older_failed_record() {
    use std::sync::atomic::Ordering;
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (_, candidate) = up_to_candidate(&p).await;
    let wallet = Arc::new(ReportedFeeProvider {
        inner: p.sponsor_ln.clone(), fee: 0.into(), cap: u64::MAX.into(),
        pause: true.into(), waiting: false.into(), resume: tokio::sync::Notify::new(), pause_lookup: false,
    });
    let state = Arc::new(AppState { lightning: wallet.clone(), ..(*p.sponsor).clone() });
    let sending = state.clone();
    let body = approval(&candidate);
    let task = tokio::spawn(async move { call(&sending,"POST","/api/v1/sponsor/approve",Some(body)).await });
    tokio::time::timeout(std::time::Duration::from_secs(5),async {
        while !wallet.waiting.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
    }).await.unwrap();
    let reconcile = format!("/api/v1/sponsor/kits/{}/reconcile", candidate["intro_id"].as_str().unwrap());
    let (_, current) = call(&state,"POST",&reconcile,None).await;
    let (offer_status, _) = call(&state,"POST","/api/v1/sponsor/offer",None).await;
    wallet.pause.store(false,Ordering::SeqCst);
    wallet.resume.notify_one();
    let (paid_status, paid) = task.await.unwrap();
    assert_eq!(current["state"], "paying", "old failure cannot resolve a still-running dispatch");
    assert_eq!(offer_status, StatusCode::CONFLICT, "keep purse reserved while the first transfer can still dispatch");
    assert_eq!(paid_status, StatusCode::OK, "{paid}");
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), GIFT);
    assert_eq!(call(&state,"GET","/api/v1/sponsor",None).await.1["purse_used_msat"], GIFT);
}

#[tokio::test]
async fn legacy_funded_kits_without_a_settlement_time_are_reconciled_before_reuse() {
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (_, candidate) = up_to_candidate(&p).await;
    let (s, paid) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(approval(&candidate))).await;
    assert_eq!(s, StatusCode::OK, "{paid}");
    let path = p.sponsor.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    // The previous version used approval time even for a late settlement
    // and could not distinguish an unknown fee from a known zero fee.
    ledger["kits"][0].as_object_mut().unwrap().remove("settled_at");
    ledger["kits"][0]["approved_at"] = json!(1);
    std::fs::write(path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    let restarted = Arc::new((*p.sponsor).clone());
    let (_, status) = call(&restarted,"GET","/api/v1/sponsor",None).await;
    assert_eq!(status["purse_used_msat"], GIFT + FEE);
    assert_eq!(call(&restarted,"POST","/api/v1/sponsor/offer",None).await.0, StatusCode::CONFLICT);
    let reconcile = format!("/api/v1/sponsor/kits/{}/reconcile", candidate["intro_id"].as_str().unwrap());
    assert_eq!(call(&restarted,"POST",&reconcile,None).await.0, StatusCode::OK);
    assert_eq!(call(&restarted,"GET","/api/v1/sponsor",None).await.1["purse_used_msat"], GIFT);
}


#[tokio::test]
async fn legacy_ambiguous_failure_cannot_release_the_purse_after_restart() {
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (ask, candidate) = up_to_candidate(&p).await;
    let path = p.sponsor.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    ledger["kits"][0]["state"] = json!("unknown");
    ledger["kits"][0]["approved_at"] = json!(1);
    ledger["kits"][0]["reserved_msat"] = json!(GIFT + FEE);
    std::fs::write(path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    let wallet = Arc::new(ReportedFeeProvider {
        inner: p.sponsor_ln.clone(), fee: 0.into(), cap: u64::MAX.into(),
        pause: true.into(), waiting: true.into(), resume: tokio::sync::Notify::new(), pause_lookup: false,
    });
    let restarted = Arc::new(AppState { lightning: wallet.clone(), ..(*p.sponsor).clone() });
    let reconcile = format!("/api/v1/sponsor/kits/{}/reconcile", candidate["intro_id"].as_str().unwrap());
    // Same-second timestamps cannot distinguish two attempts. There is no
    // durable proof that the failed provider record belongs to this approval.
    let (status, body) = call(&restarted, "POST", &reconcile, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["state"], "unknown", "an ambiguous failure must retain the hold");
    assert_eq!(call(&restarted, "GET", "/api/v1/sponsor", None).await.1["purse_used_msat"], GIFT + FEE);
    assert_eq!(call(&restarted, "POST", "/api/v1/sponsor/offer", None).await.0, StatusCode::CONFLICT);
    let request = FundingRequest::parse(ask["request"].as_str().unwrap()).unwrap();
    p.sponsor_ln.pay_invoice(&request.bolt11).await.unwrap();
    wallet.pause.store(false, std::sync::atomic::Ordering::SeqCst);
    let (_, settled) = call(&restarted, "POST", &reconcile, None).await;
    assert_eq!(settled["state"], "funded", "the late settlement must still be recorded");
    assert_eq!(call(&restarted, "GET", "/api/v1/sponsor", None).await.1["purse_used_msat"], GIFT);
}

#[tokio::test]
async fn approval_refuses_an_invoice_with_an_existing_outgoing_attempt() {
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (ask, candidate) = up_to_candidate(&p).await;
    let request = FundingRequest::parse(ask["request"].as_str().unwrap()).unwrap();
    p.sponsor_ln.pay_invoice(&request.bolt11).await.unwrap();
    let (status, _) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve",
        Some(approval(&candidate))).await;
    assert_ne!(status, StatusCode::OK, "a prior attempt must not be claimed as this gift");
    assert_eq!(call(&p.sponsor, "GET", "/api/v1/sponsor", None).await.1["purse_used_msat"], 0);
}

#[tokio::test]
async fn regression_wrong_invoice_network_must_be_rejected() {
    let p = pair(policy(1_000_000, 2)).await;
    let (_, offer) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    let offer_rec = konsensus_core::sponsor::SponsorOffer::decode(offer["link"].as_str().unwrap().rsplit_once('.').unwrap().1).unwrap();
    let bolt11 = create_test_bolt11(GIFT);
    let invoice = bolt11.parse::<lightning_invoice::Bolt11Invoice>().unwrap();
    assert_eq!(invoice.currency(), lightning_invoice::Currency::BitcoinTestnet);
    assert_eq!(offer_rec.network, "regtest");
    let payee = invoice.payee_pub_key().copied().unwrap_or_else(|| invoice.recover_payee_pub_key());
    let hash = hex::decode(invoice.payment_hash().to_string()).unwrap().try_into().unwrap();
    let request = FundingRequest::sign(p.newcomer.identity.ed25519_signing_key(), &offer_rec, payee.serialize(), GIFT, hash, offer_rec.expires_at, bolt11).unwrap();
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/candidate", Some(json!({"request": request.to_link()}))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "foreign-network invoice was frozen: {body}");
    let (_, status) = call(&p.sponsor, "GET", "/api/v1/sponsor", None).await;
    assert_eq!(status["kits"][0]["state"], "offered");
    assert!(status["kits"][0]["candidate"].is_null());
}


#[tokio::test]
async fn regression_observed_expiry_is_terminal_and_persisted() {
    let p = pair(policy(1_000_000, 2)).await;
    let (_, cand) = up_to_candidate(&p).await;
    let path = p.sponsor.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    ledger["kits"][0]["expires_at"] = json!(1);
    std::fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    let (s, status) = call(&p.sponsor, "GET", "/api/v1/sponsor", None).await;
    assert_eq!(s, StatusCode::OK, "{status}");
    assert_eq!(status["kits"][0]["state"], "expired");
    let persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted["kits"][0]["state"], "expired");
    assert!(persisted["last_observed_time"].as_u64().unwrap() > 1);
    let restarted = Arc::new((*p.sponsor).clone());
    assert_eq!(call(&restarted, "POST", "/api/v1/sponsor/offer", None).await.0, StatusCode::OK);
    assert_eq!(call(&restarted, "POST", "/api/v1/sponsor/approve",
        Some(approval(&cand))).await.0, StatusCode::CONFLICT);
}

#[tokio::test]
async fn regression_approval_refuses_multiple_active_kits() {
    let p = pair(policy(1_000_000, 2)).await;
    let (_, cand) = up_to_candidate(&p).await;
    let path = p.sponsor.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut second = ledger["kits"][0].clone();
    second["intro_id"] = json!("ee".repeat(16));
    second["state"] = json!("offered");
    second["candidate"] = Value::Null;
    ledger["kits"].as_array_mut().unwrap().push(second);
    std::fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve",
        Some(approval(&cand))).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(body.to_string().contains("sponsor_kit_open"), "{body}");
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), 0);
}

#[tokio::test]
async fn owner_approval_binds_every_funding_intent_field() {
    let p = pair(policy(1_000_000, 2)).await;
    let (_, cand) = up_to_candidate(&p).await;
    for (field, changed) in [
        ("intro_id", json!("ff".repeat(16))),
        ("newcomer", json!("ff".repeat(32))),
        ("payment_hash", json!("ff".repeat(32))),
        ("gift_msat", json!(GIFT + 1)),
        ("fee_max_msat", json!(FEE + 1)),
    ] {
        let mut body = approval(&cand);
        body[field] = changed;
        let (s, error) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(body)).await;
        assert!(s == StatusCode::BAD_REQUEST || s == StatusCode::NOT_FOUND, "{field}: {error}");
        let (_, status) = call(&p.sponsor, "GET", "/api/v1/sponsor", None).await;
        assert_eq!(status["purse_used_msat"], 0);
        assert_eq!(status["kits"][0]["state"], "candidate");
        assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), 0);
    }
    assert_eq!(call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await.0, StatusCode::OK);
    let restarted = Arc::new((*p.sponsor).clone());
    assert_eq!(call(&restarted, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await.0, StatusCode::CONFLICT);
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), GIFT);
}

#[tokio::test]
async fn persisted_future_time_refuses_approval_after_restart_without_paying() {
    let p = pair(policy(1_000_000, 2)).await;
    let (_, cand) = up_to_candidate(&p).await;
    let path = p.sponsor.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    // Represents a previously observed time, followed by restart with a lower wall clock.
    let floor = cand["expires_at"].as_u64().unwrap() + 1;
    ledger["last_observed_time"] = json!(floor);
    std::fs::write(&path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    let restarted = Arc::new((*p.sponsor).clone());
    let (s, body) = call(&restarted, "POST", "/api/v1/sponsor/approve", Some(approval(&cand))).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    let persisted: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(persisted["last_observed_time"], floor);
    assert_eq!(persisted["kits"][0]["state"], "expired", "even a refusal persists expiration");
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), 0);
}

#[tokio::test]
async fn configured_network_requires_its_exact_invoice_currency() {
    use bitcoin::hashes::{sha256, Hash};
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
    let networks = [("bitcoin", Currency::Bitcoin), ("testnet", Currency::BitcoinTestnet),
        ("signet", Currency::Signet), ("regtest", Currency::Regtest)];
    for (network, expected) in &networks {
        for (_, currency) in &networks {
            let p = pair(policy(1_000_000, 2)).await;
            let state = Arc::new(AppState {
                introduction: IntroductionSettings { network: Some((*network).into()), endpoint: Some("127.0.0.1:9001".into()) },
                ..(*p.sponsor).clone()
            });
            let (s, offer) = call(&state, "POST", "/api/v1/sponsor/offer", None).await;
            assert_eq!(s, StatusCode::OK, "{offer}");
            let offer = konsensus_core::sponsor::SponsorOffer::decode(offer["link"].as_str().unwrap().rsplit_once('.').unwrap().1).unwrap();
            let invoice = InvoiceBuilder::new(currency.clone()).description("network binding".into())
                .payment_hash(sha256::Hash::hash(&[42; 32])).payment_secret(PaymentSecret([42; 32]))
                .current_timestamp().min_final_cltv_expiry_delta(18).amount_milli_satoshis(GIFT)
                .build_signed(|hash| secp256k1::Secp256k1::new().sign_ecdsa_recoverable(hash,
                    &secp256k1::SecretKey::from_slice(&[1; 32]).unwrap())).unwrap();
            let request = FundingRequest::sign(p.newcomer.identity.ed25519_signing_key(), &offer,
                invoice.recover_payee_pub_key().serialize(), GIFT,
                hex::decode(invoice.payment_hash().to_string()).unwrap().try_into().unwrap(),
                offer.expires_at, invoice.to_string()).unwrap();
            let (s, body) = call(&state, "POST", "/api/v1/sponsor/candidate", Some(json!({"request":request.to_link()}))).await;
            let (_, status) = call(&state, "GET", "/api/v1/sponsor", None).await;
            if currency == expected {
                assert_eq!(s, StatusCode::OK, "{network} {currency:?}: {body}");
                assert_eq!(status["kits"][0]["state"], "candidate");
            } else {
                assert_eq!(s, StatusCode::BAD_REQUEST, "{network} {currency:?}: {body}");
                assert!(status["kits"][0]["candidate"].is_null());
            }
        }
    }
}

#[tokio::test]
async fn expired_candidate_resubmission_persists_terminal_expiry_even_on_refusal() {
    let p = pair(policy(1_000_000, 2)).await;
    let (_, offer) = call(&p.sponsor, "POST", "/api/v1/sponsor/offer", None).await;
    let (_, ask) = call(&p.newcomer, "POST", "/api/v1/sponsor/request", Some(json!({"link":offer["link"]}))).await;
    let original = FundingRequest::parse(ask["request"].as_str().unwrap()).unwrap();
    let offer = konsensus_core::sponsor::SponsorOffer::decode(offer["link"].as_str().unwrap().rsplit_once('.').unwrap().1).unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let short = FundingRequest::sign(p.newcomer.identity.ed25519_signing_key(), &offer,
        original.newcomer_ln, GIFT, original.payment_hash, now + 2, original.bolt11).unwrap();
    let body = json!({"request":short.to_link()});
    let (s, candidate) = call(&p.sponsor, "POST", "/api/v1/sponsor/candidate", Some(body.clone())).await;
    assert_eq!(s, StatusCode::OK, "{candidate}");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let (s, error) = call(&p.sponsor, "POST", "/api/v1/sponsor/candidate", Some(body)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{error}");
    let path = p.sponsor.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let ledger: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(ledger["kits"][0]["state"], "expired", "an early refusal must record observed expiry");
    assert!(ledger["last_observed_time"].as_u64().unwrap() >= now + 2);
}

#[tokio::test]
async fn time_floor_advanced_during_preflight_prevents_dispatch() {
    use std::sync::atomic::Ordering;
    let p = pair(policy(GIFT + FEE, 2)).await;
    let (_, candidate) = up_to_candidate(&p).await;
    let wallet = Arc::new(ReportedFeeProvider {
        inner: p.sponsor_ln.clone(), fee: 0.into(), cap: u64::MAX.into(),
        pause: false.into(), waiting: false.into(), resume: tokio::sync::Notify::new(), pause_lookup: true,
    });
    let state = Arc::new(AppState { lightning: wallet.clone(), ..(*p.sponsor).clone() });
    let sending = state.clone();
    let body = approval(&candidate);
    let pending = tokio::spawn(async move { call(&sending, "POST", "/api/v1/sponsor/approve", Some(body)).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !wallet.waiting.load(Ordering::SeqCst) { tokio::task::yield_now().await; }
    }).await.unwrap();
    let path = state.data_dir.as_ref().unwrap().join("sponsor/kits.json");
    let mut ledger: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(ledger["kits"][0]["state"], "paying");
    // Model another observation while lookup is pending; the actual wall
    // clock remains earlier than the deadline when lookup resumes.
    ledger["last_observed_time"] = json!(candidate["expires_at"].as_u64().unwrap() + 1);
    std::fs::write(path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    wallet.resume.notify_one();
    let (s, body) = pending.await.unwrap();
    assert_ne!(s, StatusCode::OK, "{body}");
    assert_eq!(wallet.cap.load(Ordering::SeqCst), u64::MAX, "backend pay was never invoked");
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), 0);
    let (_, status) = call(&state, "GET", "/api/v1/sponsor", None).await;
    assert_eq!(status["kits"][0]["state"], "failed");
    assert_eq!(status["purse_used_msat"], 0);
}
