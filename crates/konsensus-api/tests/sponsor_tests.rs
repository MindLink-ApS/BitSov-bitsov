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
    let (s, body) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(json!({ "intro_id": cand["intro_id"], "code": wrong }))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), before);

    let (s, paid) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(json!({ "intro_id": cand["intro_id"], "code": cand["code"] }))).await;
    assert_eq!(s, StatusCode::OK, "{paid}");
    assert_eq!(paid["state"], "funded");
    assert_eq!(paid["paid_msat"], GIFT);
    assert_eq!(p.newcomer_ln.get_balance_msat().await.unwrap(), before + GIFT, "real sats in the newcomer's own wallet");

    let hash = ask["payment_hash"].as_str().unwrap();
    let (s, st) = call(&p.newcomer, "GET", &format!("/api/v1/sponsor/request/{hash}"), None).await;
    assert_eq!((s, st["state"].clone(), st["amount_msat"].clone()), (StatusCode::OK, json!("received"), json!(GIFT)));

    // Single use: the same kit never pays twice.
    let (s, again) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(json!({ "intro_id": cand["intro_id"], "code": cand["code"] }))).await;
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
    call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(json!({ "intro_id": cand["intro_id"], "code": cand["code"] }))).await;
    // The sponsor learned the preimage by paying. The newcomer's gate must
    // still refuse that payment as a message proof: it is a used receipt.
    let hash: [u8; 32] = hex::decode(ask["payment_hash"].as_str().unwrap()).unwrap().try_into().unwrap();
    let adapter = konsensus_storage::StorageNonceAdapter::new(p.newcomer.storage.clone());
    let reuse = adapter
        .check_and_store_paid(&Nonce::from_bytes([7; 24]), &hash, p.sponsor.identity.node_id(), &MessageId::from_bytes([9; 32]))
        .await
        .unwrap();
    assert!(matches!(reuse, PaidReplay::PaymentReused { .. }), "{reuse:?}");
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
        let (s, paid) = call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(json!({ "intro_id": cand["intro_id"], "code": cand["code"] }))).await;
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
    call(&p.sponsor, "POST", "/api/v1/sponsor/approve", Some(json!({ "intro_id": cand["intro_id"], "code": cand["code"] }))).await;
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
