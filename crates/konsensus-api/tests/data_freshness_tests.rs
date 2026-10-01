//! G-STALENESS-MARKER: `BitSov-Data-As-Of` / `BitSov-Data-Stale` on the six
//! pinned read routes (`/payments/balance`, `/payments/channels`, `/health`,
//! `/messages`, `/pricing`, `/peers`).
//!
//! Every test drives the production router in-process (`oneshot`, no socket,
//! no port) with stub/mock providers only.

mod common;
use common::*;

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Utc};
use tower::ServiceExt;

use konsensus_api::state::AppState;
use konsensus_core::traits::chain::{
    BlockHeader, ChainError, ChainProvider, FeeEstimate, TrustLevel,
};
use konsensus_core::traits::lightning::{
    ChannelInfo, Invoice, LightningError, LightningProvider, PaymentDetails, WalletSync,
};
use konsensus_pricing::{ChainAwarePricingConfig, ChainAwarePricingEngine, FeeRateSnapshot};

const AS_OF: &str = "bitsov-data-as-of";
const STALE: &str = "bitsov-data-stale";

// ─── Helpers ────────────────────────────────────────────────────────

struct Reply {
    status: StatusCode,
    as_of: Option<String>,
    stale: Option<String>,
    json: serde_json::Value,
}

async fn get(state: Arc<AppState>, uri: &str, authed: bool) -> Reply {
    let mut req = Request::builder().uri(uri);
    if authed {
        req = req.header("authorization", auth_header(&state));
    }
    let resp = test_router(state)
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .map(|v| v.to_str().expect("header is ASCII").to_string())
    };
    let (as_of, stale) = (header(AS_OF), header(STALE));
    let status = resp.status();
    let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    let json = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    Reply {
        status,
        as_of,
        stale,
        json,
    }
}

/// Parse `BitSov-Data-As-Of` and assert the wire form: RFC 3339, UTC written
/// as `Z`, whole seconds, not in the future.
fn parse_as_of(raw: &str) -> DateTime<Utc> {
    assert_eq!(
        raw.len(),
        "2026-09-27T08:20:00Z".len(),
        "unexpected form: {raw}"
    );
    assert!(raw.ends_with('Z'), "must be UTC with a `Z` suffix: {raw}");
    let parsed = DateTime::parse_from_rfc3339(raw)
        .unwrap_or_else(|e| panic!("not RFC 3339 ({e}): {raw}"))
        .with_timezone(&Utc);
    assert!(parsed <= Utc::now(), "as-of is in the future: {raw}");
    parsed
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn with_lightning(lightning: Arc<dyn LightningProvider>) -> Arc<AppState> {
    test_state_with_lightning(lightning)
}

fn with_chain(chain: Arc<dyn ChainProvider>) -> Arc<AppState> {
    let mut state = (*test_state()).clone();
    state.chain = chain;
    Arc::new(state)
}

fn with_chain_aware_pricing(
    engine: ChainAwarePricingEngine,
    chain: Arc<dyn ChainProvider>,
) -> Arc<AppState> {
    let mut state = (*test_state()).clone();
    state.chain = chain;
    state.pricing = Arc::new(engine);
    Arc::new(state)
}

/// Lightning stub whose wallet figures come from a local cache with a given
/// sync status (the LDK shape). Everything else delegates to `StubLightning`.
struct SyncedLightning(WalletSync);

#[async_trait]
impl LightningProvider for SyncedLightning {
    async fn create_invoice(&self, a: u64, d: &str, e: u32) -> Result<Invoice, LightningError> {
        StubLightning.create_invoice(a, d, e).await
    }
    async fn pay_invoice(&self, b: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.pay_invoice(b).await
    }
    async fn get_payment_status(&self, h: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.get_payment_status(h).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        StubLightning.get_balance_msat().await
    }
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        StubLightning.list_channels().await
    }
    async fn is_available(&self) -> bool {
        true
    }
    async fn wallet_sync(&self) -> WalletSync {
        self.0
    }
}

/// Lightning stub whose wallet reads fail.
struct FailingLightning;

#[async_trait]
impl LightningProvider for FailingLightning {
    async fn create_invoice(&self, a: u64, d: &str, e: u32) -> Result<Invoice, LightningError> {
        StubLightning.create_invoice(a, d, e).await
    }
    async fn pay_invoice(&self, b: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.pay_invoice(b).await
    }
    async fn get_payment_status(&self, h: &str) -> Result<PaymentDetails, LightningError> {
        StubLightning.get_payment_status(h).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Err(LightningError::Backend("wallet unreachable".into()))
    }
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        Err(LightningError::Backend("wallet unreachable".into()))
    }
    async fn is_available(&self) -> bool {
        false
    }
}

/// Chain backend that is down: every query fails and it reports unsynced.
struct DownChain;

#[async_trait]
impl ChainProvider for DownChain {
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::ServerTrust
    }
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        Err(ChainError::NotAvailable("down".into()))
    }
    async fn get_block_header(&self, _h: u64) -> Result<BlockHeader, ChainError> {
        Err(ChainError::NotAvailable("down".into()))
    }
    async fn estimate_fee(&self, _t: u32) -> Result<FeeEstimate, ChainError> {
        Err(ChainError::NotAvailable("down".into()))
    }
    async fn is_tx_confirmed(&self, _txid: &str, _c: u32) -> Result<bool, ChainError> {
        Err(ChainError::NotAvailable("down".into()))
    }
    async fn is_synced(&self) -> bool {
        false
    }
}

fn keys(v: &serde_json::Value) -> Vec<String> {
    let mut k: Vec<String> = v
        .as_object()
        .expect("object body")
        .keys()
        .cloned()
        .collect();
    k.sort();
    k
}

// ─── /payments/balance ──────────────────────────────────────────────

#[tokio::test]
async fn balance_live_backend_is_as_of_the_read_and_not_stale() {
    let before = Utc::now() - chrono::Duration::seconds(1);
    let r = get(test_state(), "/api/v1/payments/balance", true).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json, serde_json::json!({"balance_msat": 100_000_000}));
    let as_of = parse_as_of(r.as_of.as_deref().expect("as-of header on 200"));
    assert!(as_of >= before, "live read must be stamped at read time");
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn balance_recently_synced_wallet_is_as_of_the_sync() {
    let synced = unix_now() - 30;
    let r = get(
        with_lightning(Arc::new(SyncedLightning(WalletSync::SyncedAt(synced)))),
        "/api/v1/payments/balance",
        true,
    )
    .await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json, serde_json::json!({"balance_msat": 100_000_000}));
    assert_eq!(
        parse_as_of(r.as_of.as_deref().unwrap()).timestamp() as u64,
        synced
    );
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn balance_wallet_sync_past_bound_is_marked_stale() {
    let synced = unix_now() - 3600;
    let r = get(
        with_lightning(Arc::new(SyncedLightning(WalletSync::SyncedAt(synced)))),
        "/api/v1/payments/balance",
        true,
    )
    .await;

    assert_eq!(
        r.status,
        StatusCode::OK,
        "stale data is still served, not a 503"
    );
    assert_eq!(r.json, serde_json::json!({"balance_msat": 100_000_000}));
    assert_eq!(
        parse_as_of(r.as_of.as_deref().unwrap()).timestamp() as u64,
        synced
    );
    assert_eq!(r.stale.as_deref(), Some("1"));
}

#[tokio::test]
async fn balance_never_synced_wallet_has_no_as_of_and_is_stale() {
    let r = get(
        with_lightning(Arc::new(SyncedLightning(WalletSync::NeverSynced))),
        "/api/v1/payments/balance",
        true,
    )
    .await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.as_of, None, "no time is known for never-synced data");
    assert_eq!(r.stale.as_deref(), Some("1"));
}

#[tokio::test]
async fn balance_sync_time_ahead_of_node_clock_is_clamped_to_now() {
    let r = get(
        with_lightning(Arc::new(SyncedLightning(WalletSync::SyncedAt(
            unix_now() + 3600,
        )))),
        "/api/v1/payments/balance",
        true,
    )
    .await;

    // parse_as_of asserts not-in-the-future.
    parse_as_of(r.as_of.as_deref().unwrap());
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn balance_error_response_carries_no_freshness_headers() {
    let r = get(
        with_lightning(Arc::new(FailingLightning)),
        "/api/v1/payments/balance",
        true,
    )
    .await;

    assert!(!r.status.is_success());
    assert_eq!(r.as_of, None);
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn balance_unauthenticated_is_still_401_without_headers() {
    let r = get(test_state(), "/api/v1/payments/balance", false).await;

    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.as_of, None);
    assert_eq!(r.stale, None);
}

// ─── /payments/channels ─────────────────────────────────────────────

#[tokio::test]
async fn channels_live_backend_is_as_of_the_read_and_not_stale() {
    let before = Utc::now() - chrono::Duration::seconds(1);
    let r = get(test_state(), "/api/v1/payments/channels", true).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json, serde_json::json!([]));
    assert!(parse_as_of(r.as_of.as_deref().unwrap()) >= before);
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn channels_wallet_sync_past_bound_is_marked_stale() {
    let synced = unix_now() - 3600;
    let r = get(
        with_lightning(Arc::new(SyncedLightning(WalletSync::SyncedAt(synced)))),
        "/api/v1/payments/channels",
        true,
    )
    .await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json, serde_json::json!([]));
    assert_eq!(
        parse_as_of(r.as_of.as_deref().unwrap()).timestamp() as u64,
        synced
    );
    assert_eq!(r.stale.as_deref(), Some("1"));
}

#[tokio::test]
async fn channels_recently_synced_wallet_is_not_stale() {
    let synced = unix_now() - 30;
    let r = get(
        with_lightning(Arc::new(SyncedLightning(WalletSync::SyncedAt(synced)))),
        "/api/v1/payments/channels",
        true,
    )
    .await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        parse_as_of(r.as_of.as_deref().unwrap()).timestamp() as u64,
        synced
    );
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn channels_error_response_carries_no_freshness_headers() {
    let r = get(
        with_lightning(Arc::new(FailingLightning)),
        "/api/v1/payments/channels",
        true,
    )
    .await;

    assert!(!r.status.is_success());
    assert_eq!(r.as_of, None);
    assert_eq!(r.stale, None);
}

// ─── /health ────────────────────────────────────────────────────────

#[tokio::test]
async fn health_with_block_height_is_as_of_the_chain_read() {
    let before = Utc::now() - chrono::Duration::seconds(1);
    let r = get(test_state(), "/api/v1/health", false).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        keys(&r.json),
        [
            "block_height",
            "chain_backend",
            "connected_peers",
            "e2ee_sessions",
            "lightning_available",
            "lightning_backend",
            "lightning_payment_capable",
            "pending_deliveries",
            "status",
            "uptime_secs",
            "version",
        ]
    );
    assert_eq!(r.json["block_height"], 850_000);
    assert!(parse_as_of(r.as_of.as_deref().unwrap()) >= before);
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn health_without_block_height_omits_both_headers() {
    let r = get(with_chain(Arc::new(DownChain)), "/api/v1/health", false).await;

    assert_eq!(r.status, StatusCode::OK);
    assert!(
        r.json.get("block_height").is_none(),
        "body unchanged: height omitted"
    );
    assert_eq!(r.json["status"], "ok");
    assert_eq!(r.as_of, None);
    assert_eq!(r.stale, None);
}

// ─── /peers ─────────────────────────────────────────────────────────

#[tokio::test]
async fn peers_is_as_of_the_registry_read() {
    let before = Utc::now() - chrono::Duration::seconds(1);
    let r = get(test_state(), "/api/v1/peers", true).await;

    assert_eq!(r.status, StatusCode::OK);
    assert!(r.json.is_array(), "body shape unchanged: bare array");
    assert!(parse_as_of(r.as_of.as_deref().unwrap()) >= before);
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn peers_unauthenticated_carries_no_freshness_headers() {
    let r = get(test_state(), "/api/v1/peers", false).await;

    assert_ne!(r.status, StatusCode::OK);
    assert_eq!(r.as_of, None);
    assert_eq!(r.stale, None);
}

// ─── /messages ──────────────────────────────────────────────────────

#[tokio::test]
async fn messages_is_as_of_the_store_read() {
    let before = Utc::now() - chrono::Duration::seconds(1);
    let r = get(test_state(), "/api/v1/messages", true).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json, serde_json::json!([]));
    assert!(parse_as_of(r.as_of.as_deref().unwrap()) >= before);
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn messages_with_stored_message_keeps_body_shape() {
    let state = test_state();
    store_test_envelope(&state).await;
    let r = get(state, "/api/v1/messages", true).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json.as_array().expect("bare array").len(), 1);
    parse_as_of(r.as_of.as_deref().unwrap());
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn messages_bad_query_error_carries_no_freshness_headers() {
    let r = get(test_state(), "/api/v1/messages?peer=not-a-uuid", true).await;

    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.as_of, None);
    assert_eq!(r.stale, None);
}

// ─── /pricing ───────────────────────────────────────────────────────

const PRICING_KEYS: [&str; 7] = [
    "block_height",
    "difficulty_epoch_position",
    "mode",
    "peer_tables_cached",
    "prices",
    "trust_level",
    "valid_blocks",
];

#[tokio::test]
async fn pricing_static_engine_is_as_of_the_read_and_not_stale() {
    let before = Utc::now() - chrono::Duration::seconds(1);
    let r = get(test_state(), "/api/v1/pricing", true).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(keys(&r.json), PRICING_KEYS);
    assert_eq!(r.json["mode"], "static");
    assert!(parse_as_of(r.as_of.as_deref().unwrap()) >= before);
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn pricing_chain_aware_fresh_cache_is_as_of_the_chain_fetch() {
    let before = Utc::now() - chrono::Duration::seconds(1);
    let chain: Arc<dyn ChainProvider> = Arc::new(StubChain);
    let engine =
        ChainAwarePricingEngine::new(ChainAwarePricingConfig::default(), Arc::clone(&chain));
    let r = get(
        with_chain_aware_pricing(engine, chain),
        "/api/v1/pricing",
        true,
    )
    .await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["mode"], "chain_aware");
    assert!(parse_as_of(r.as_of.as_deref().unwrap()) >= before);
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn pricing_chain_aware_with_chain_down_and_no_cache_is_stale() {
    let before = Utc::now() - chrono::Duration::seconds(1);
    let chain: Arc<dyn ChainProvider> = Arc::new(DownChain);
    let engine =
        ChainAwarePricingEngine::new(ChainAwarePricingConfig::default(), Arc::clone(&chain));
    let r = get(
        with_chain_aware_pricing(engine, chain),
        "/api/v1/pricing",
        true,
    )
    .await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["mode"], "chain_aware");
    assert_eq!(r.json["block_height"], 0);
    // Prices fell back to the static table the node really charges right now.
    assert!(parse_as_of(r.as_of.as_deref().unwrap()) >= before);
    assert_eq!(r.stale.as_deref(), Some("1"));
}

#[tokio::test]
async fn pricing_chain_aware_with_chain_down_and_expired_cache_is_as_of_that_cache() {
    let chain: Arc<dyn ChainProvider> = Arc::new(DownChain);
    let config = ChainAwarePricingConfig {
        cache_ttl: Duration::from_secs(120),
        ..ChainAwarePricingConfig::default()
    };
    let engine = ChainAwarePricingEngine::new(config, Arc::clone(&chain));
    engine
        .seed_ema(FeeRateSnapshot {
            targets: [(6u32, 5.0f64)].into_iter().collect(),
            block_height: 850_000,
            timestamp_secs: unix_now(),
        })
        .await;
    let r = get(
        with_chain_aware_pricing(engine, chain),
        "/api/v1/pricing",
        true,
    )
    .await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(
        r.json["ema_fee_rate"], 5.0,
        "fee fields come from the old cache"
    );
    let as_of = parse_as_of(r.as_of.as_deref().unwrap());
    assert!(
        as_of <= Utc::now() - chrono::Duration::seconds(119),
        "as-of must be the cache fetch time, not now: {as_of}"
    );
    assert_eq!(r.stale.as_deref(), Some("1"));
}

/// Synced chain whose fee estimates fail for the listed targets only.
struct FeeFailsFor(Vec<u32>);

#[async_trait]
impl ChainProvider for FeeFailsFor {
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::ServerTrust
    }
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        Ok(850_000)
    }
    async fn get_block_header(&self, h: u64) -> Result<BlockHeader, ChainError> {
        StubChain.get_block_header(h).await
    }
    async fn estimate_fee(&self, t: u32) -> Result<FeeEstimate, ChainError> {
        if self.0.contains(&t) {
            return Err(ChainError::NotAvailable("fee estimate down".into()));
        }
        Ok(FeeEstimate {
            sat_per_vbyte: 9.0,
            target_blocks: t,
        })
    }
    async fn is_tx_confirmed(&self, _txid: &str, _c: u32) -> Result<bool, ChainError> {
        Ok(false)
    }
    async fn is_synced(&self) -> bool {
        true
    }
}

/// Seed targets 6 and 144 (already `cache_ttl` old), then serve `/pricing`
/// from a synced chain whose fee estimate fails for `failing`.
async fn pricing_with_seed_and_fee_failures(failing: Vec<u32>) -> Reply {
    let chain: Arc<dyn ChainProvider> = Arc::new(FeeFailsFor(failing));
    let config = ChainAwarePricingConfig {
        cache_ttl: Duration::from_secs(120),
        category_fee_targets: [("files_media".to_string(), 144u32)].into_iter().collect(),
        ..ChainAwarePricingConfig::default()
    };
    let engine = ChainAwarePricingEngine::new(config, Arc::clone(&chain));
    engine
        .seed_ema(FeeRateSnapshot {
            targets: [(6u32, 5.0f64), (144u32, 2.0f64)].into_iter().collect(),
            block_height: 850_000,
            timestamp_secs: unix_now(),
        })
        .await;
    get(
        with_chain_aware_pricing(engine, chain),
        "/api/v1/pricing",
        true,
    )
    .await
}

#[tokio::test]
async fn pricing_synced_chain_with_all_fee_estimates_failing_keeps_the_old_as_of() {
    let r = pricing_with_seed_and_fee_failures(vec![6, 144]).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["ema_fee_rate"], 5.0, "seeded value reused");
    let as_of = parse_as_of(r.as_of.as_deref().unwrap());
    assert!(
        as_of <= Utc::now() - chrono::Duration::seconds(119),
        "reused values must not get a fresh as-of: {as_of}"
    );
    assert_eq!(r.stale.as_deref(), Some("1"));
}

#[tokio::test]
async fn pricing_synced_chain_with_one_fee_estimate_failing_keeps_the_old_as_of() {
    let r = pricing_with_seed_and_fee_failures(vec![144]).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.json["fee_rates_by_target"]["6"]["raw_sat_per_vbyte"], 9.0);
    assert_eq!(
        r.json["fee_rates_by_target"]["144"]["ema_sat_per_vbyte"], 2.0,
        "seeded value reused for the failing target"
    );
    let as_of = parse_as_of(r.as_of.as_deref().unwrap());
    assert!(
        as_of <= Utc::now() - chrono::Duration::seconds(119),
        "as-of is the oldest served value, not the fresh one: {as_of}"
    );
    assert_eq!(r.stale.as_deref(), Some("1"));
}

#[tokio::test]
async fn pricing_unauthenticated_is_still_401_without_headers() {
    let r = get(test_state(), "/api/v1/pricing", false).await;

    assert_eq!(r.status, StatusCode::UNAUTHORIZED);
    assert_eq!(r.as_of, None);
    assert_eq!(r.stale, None);
}

// ─── Scope: only the five pinned routes ─────────────────────────────

#[tokio::test]
async fn unpinned_read_route_does_not_carry_the_header() {
    let r = get(test_state(), "/api/v1/status", true).await;

    assert_eq!(r.status, StatusCode::OK);
    assert_eq!(r.as_of, None);
    assert_eq!(r.stale, None);
}

#[tokio::test]
async fn owner_status_reports_chain_view_without_exposing_it_on_public_health() {
    let dir = tempfile::tempdir().unwrap();
    let cookie = dir.path().join("cookie");
    std::fs::write(&cookie, "user:STATUS_SECRET").unwrap();
    let rpc: konsensus_chain::BitcoindConfig = serde_json::from_value(serde_json::json!({
        "rpc_host":"127.0.0.1", "rpc_port":1, "cookie_file":cookie
    })).unwrap();
    let cases: Vec<(Arc<dyn ChainProvider>, &str, &str)> = vec![
        (Arc::new(konsensus_chain::BitcoindProvider::new(rpc).unwrap()), "bitcoind", "trustless"),
        (Arc::new(konsensus_chain::EsploraProvider::new(konsensus_chain::EsploraConfig::custom(
            "http://127.0.0.1:1".into(), TrustLevel::ServerTrust,
        )).unwrap()), "esplora", "third_party"),
    ];
    for (chain, backend, trust) in cases {
        let mut state = test_state();
        let s = Arc::get_mut(&mut state).unwrap();
        s.chain = chain;
        s.chain_backend = backend.into();
        let response = get(state.clone(), "/api/v1/status", true).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.json["chain_view"], serde_json::json!({
            "backend":backend, "trust_level":trust, "host":"127.0.0.1"
        }));
        assert!(!response.json.to_string().contains("STATUS_SECRET"));
        let public = get(state.clone(), "/api/v1/health", false).await;
        assert!(public.json.get("chain_view").is_none());
        assert_eq!(get(state, "/api/v1/status", false).await.status, StatusCode::UNAUTHORIZED);
    }
}
