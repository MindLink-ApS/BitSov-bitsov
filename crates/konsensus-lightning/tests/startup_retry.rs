//! Exercise the real LDK startup fee barrier with disposable mainnet wallets
//! and loopback HTTP only. No bitcoind, public endpoint, or funds are needed.
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use axum::{extract::State, http::StatusCode, routing::get, Router};
use konsensus_core::traits::lightning::{LightningError, LightningProvider};
use konsensus_lightning::{LdkConfig, LdkProvider};

struct Fixture {
    url: String,
    requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
    background_requests: Arc<AtomicUsize>,
}

impl Fixture {
    // Preflight succeeds, then `failures` actual startup requests fail.
    async fn new(failures: usize, empty: bool) -> Self {
        Self::with_delay(failures, empty, Duration::ZERO).await
    }

    async fn with_delay(failures: usize, empty: bool, delay: Duration) -> Self {
        let requests = Arc::new(AtomicUsize::new(0));
        let background_requests = Arc::new(AtomicUsize::new(0));
        let background = Arc::clone(&background_requests);
        let app = Router::new()
            .route(
                "/fee-estimates",
                get(move |State(requests): State<Arc<AtomicUsize>>| async move {
                    let n = requests.fetch_add(1, Ordering::SeqCst);
                    if n == 1 {
                        tokio::time::sleep(delay).await;
                    }
                    if n > 0 && n <= failures {
                        (StatusCode::BAD_GATEWAY, "unavailable")
                    } else if empty {
                        (StatusCode::OK, "{}")
                    } else {
                        (StatusCode::OK, "{\"1\":10.0,\"6\":5.0,\"144\":2.0}")
                    }
                }),
            )
            .fallback(move || {
                background.fetch_add(1, Ordering::SeqCst);
                // Nonempty body models a transport failure. An empty HTTP body is
                // invalid data to LDK and selects its five-minute persistent retry.
                async { (StatusCode::NOT_FOUND, "unavailable") }
            })
            .with_state(Arc::clone(&requests));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            url,
            requests,
            task,
            background_requests,
        }
    }

    async fn wait_for(&self, count: usize) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.requests.load(Ordering::SeqCst) < count {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn config(dir: &tempfile::TempDir, url: &str) -> LdkConfig {
    LdkConfig {
        tower: Default::default(),
        forward_to_private_channels: false,
        our_to_self_delay_blocks: None,
        lsps2_service: Default::default(),
        channel_peers: None,
        esplora_sync_intervals: Default::default(),
        logging: Default::default(),
        electrum: None,
        bitcoind: None,
        liquidity: Default::default(),
        storage_dir: dir.path().join("ldk"),
        scb_backup_dir: None,
        scb_rotation_count: 3,
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        passphrase: None,
        network: "bitcoin".into(),
        esplora_url: url.into(),
        esplora_url_fallback: None, credentials_file: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transient_fee_failure_recovers_and_preserves_identity() {
    let server = Fixture::new(1, false).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, &server.url);
    let startup = tokio::spawn(LdkProvider::new(cfg.clone()));
    server.wait_for(2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!startup.is_finished(), "must stay unready during retry");
    assert_eq!(
        server.background_requests.load(Ordering::SeqCst),
        0,
        "wallet/background sync must not start before usable fees"
    );
    let provider = startup.await.unwrap().unwrap();
    assert!(provider.node().status().is_running);
    let identity = provider.node().node_id();
    let log = std::fs::read_to_string(cfg.storage_dir.join("ldk_node.log")).unwrap();
    let attempts: Vec<_> = log
        .lines()
        .filter(|line| line.contains("Starting up LDK Node with node ID"))
        .collect();
    assert_eq!(attempts.len(), 2);
    assert!(attempts
        .iter()
        .all(|line| line.contains(&identity.to_string())));
    assert_eq!(
        log.matches("Startup complete.").count(),
        1,
        "start tasks exactly once"
    );
    provider.shutdown().await.unwrap();
    drop(provider);
    let restarted = LdkProvider::new(cfg).await.unwrap();
    assert_eq!(restarted.node().node_id(), identity);
    restarted.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistent_fee_failure_is_bounded_and_actionable() {
    let server = Fixture::new(usize::MAX, false).await;
    let dir = tempfile::tempdir().unwrap();
    let result = tokio::time::timeout(
        Duration::from_secs(65),
        LdkProvider::new(config(&dir, &server.url)),
    )
    .await
    .unwrap();
    let err = result.expect_err("unreachable chain must not become ready");
    assert!(
        err.to_string().contains("BOOT_CHAIN_SOURCE_UNAVAILABLE"),
        "{err}"
    );
    assert!(err.to_string().contains("Check your connection"), "{err}");
    assert!(matches!(
        err,
        LightningError::ChainSourceUnavailable { attempts: 5, .. }
    ));
    assert_eq!(
        server.requests.load(Ordering::SeqCst),
        6,
        "one preflight plus five real attempts"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_during_backoff_stops_retries_and_allows_identity_reuse() {
    let server = Fixture::new(1, false).await;
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, &server.url);
    let startup = tokio::spawn(LdkProvider::new(cfg.clone()));
    server.wait_for(2).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let log = std::fs::read_to_string(cfg.storage_dir.join("ldk_node.log")).unwrap();
    let identity = log
        .split("Starting up LDK Node with node ID ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    startup.abort();
    assert!(matches!(startup.await, Err(err) if err.is_cancelled()));
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(
        server.requests.load(Ordering::SeqCst),
        2,
        "cancel must not leave retry or sync tasks"
    );
    assert_eq!(server.background_requests.load(Ordering::SeqCst), 0);
    let provider = LdkProvider::new(cfg).await.unwrap();
    assert_eq!(provider.node().node_id().to_string(), identity);
    assert!(provider.node().status().is_running);
    provider.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_primary_failure_uses_configured_fallback() {
    let primary = Fixture::new(usize::MAX, false).await;
    let fallback = Fixture::new(0, false).await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir, &primary.url);
    cfg.esplora_url_fallback = Some(fallback.url.clone());
    let provider = LdkProvider::new(cfg.clone()).await.unwrap();
    assert!(provider.node().status().is_running);
    assert_eq!(
        primary.requests.load(Ordering::SeqCst),
        2,
        "do not re-probe a failing primary"
    );
    assert!(fallback.requests.load(Ordering::SeqCst) >= 1);
    let log = std::fs::read_to_string(cfg.storage_dir.join("ldk_node.log")).unwrap();
    let attempts: Vec<_> = log
        .lines()
        .filter(|line| line.contains("Starting up LDK Node with node ID"))
        .collect();
    assert_eq!(attempts.len(), 2);
    assert!(
        attempts
            .iter()
            .all(|line| line.contains(&provider.node().node_id().to_string())),
        "fallback rebuild must preserve the original identity"
    );
    assert_eq!(log.matches("Startup complete.").count(), 1);
    provider.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_local_config_fails_before_network_io() {
    let server = Fixture::new(0, false).await;
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir, &server.url);
    cfg.listening_address = Some("invalid address".into());
    let err = LdkProvider::new(cfg).await.err().unwrap();
    assert!(err.to_string().contains("BOOT_INVALID_CONFIG"), "{err}");
    assert_eq!(server.requests.load(Ordering::SeqCst), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_mainnet_fee_data_never_becomes_ready() {
    let server = Fixture::new(0, true).await;
    let dir = tempfile::tempdir().unwrap();
    let err = LdkProvider::new(config(&dir, &server.url))
        .await
        .err()
        .unwrap();
    assert!(
        err.to_string().contains("BOOT_CHAIN_SOURCE_UNAVAILABLE"),
        "{err}"
    );
    assert_eq!(server.requests.load(Ordering::SeqCst), 6);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_fee_timeout_after_healthy_preflight_recovers() {
    let server = Fixture::with_delay(0, false, Duration::from_secs(6)).await;
    let dir = tempfile::tempdir().unwrap();
    let started = std::time::Instant::now();
    let provider = LdkProvider::new(config(&dir, &server.url)).await.unwrap();
    assert!(
        started.elapsed() >= Duration::from_secs(5),
        "exercise LDK's real timeout"
    );
    assert!(provider.node().status().is_running);
    assert!(
        server.requests.load(Ordering::SeqCst) >= 3,
        "the timed-out fee fetch must be retried"
    );
    provider.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_endpoint_is_config_error_without_exposing_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let err = LdkProvider::new(config(&dir, "ftp://user:secret@example.com/private"))
        .await
        .err()
        .unwrap();
    assert!(err.to_string().contains("BOOT_INVALID_CONFIG"), "{err}");
    assert!(!err.to_string().contains("secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn occupied_listening_port_is_config_error_without_retry() {
    let server = Fixture::new(0, false).await;
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir, &server.url);
    cfg.listening_address = Some(occupied.local_addr().unwrap().to_string());
    let err = LdkProvider::new(cfg.clone()).await.err().unwrap();
    assert!(err.to_string().contains("BOOT_INVALID_CONFIG"), "{err}");
    assert!(err.to_string().contains("available port"), "{err}");
    let log = std::fs::read_to_string(cfg.storage_dir.join("ldk_node.log")).unwrap();
    assert_eq!(log.matches("Starting up LDK Node with node ID").count(), 1);
    assert!(!log.contains("Startup complete."));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_in_flight_fee_timeout_does_not_leave_startup_work() {
    let server = Fixture::with_delay(0, false, Duration::from_secs(6)).await;
    let dir = tempfile::tempdir().unwrap();
    let startup = tokio::spawn(LdkProvider::new(config(&dir, &server.url)));
    server.wait_for(2).await;
    startup.abort();
    let joined = tokio::time::timeout(Duration::from_secs(7), startup)
        .await
        .unwrap();
    assert!(matches!(joined, Err(err) if err.is_cancelled()));
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(server.requests.load(Ordering::SeqCst), 2);
    assert_eq!(server.background_requests.load(Ordering::SeqCst), 0);
}

/// Exercise recovery across the *exhausted* startup boundary, including real
/// mainnet genesis wallet synchronization. All HTTP and all funds are local/empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_boot_recovers_after_sync_without_duplicate_ldk_tasks() {
    use std::sync::{atomic::AtomicBool, Mutex};
    use konsensus_lightning::RecoveringLightning;
    let fees_live = Arc::new(AtomicBool::new(false));
    let chain_live = Arc::new(AtomicBool::new(false));
    let fee_flag = fees_live.clone();
    let chain_flag = chain_live.clone();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin);
    let hash = genesis.block_hash().to_string();
    let header = hex::encode(bitcoin::consensus::serialize(&genesis.header));
    let app = Router::new().fallback(move |uri: axum::http::Uri| {
        let fees = fee_flag.load(Ordering::SeqCst);
        let chain = chain_flag.load(Ordering::SeqCst);
        let hash = hash.clone();
        let header = header.clone();
        async move {
            let path = uri.path();
            if path == "/fee-estimates" {
                return if fees { (StatusCode::OK, "{\"1\":10.0,\"6\":5.0,\"144\":2.0}".into()) }
                    else { (StatusCode::BAD_GATEWAY, "offline".into()) };
            }
            if !chain { return (StatusCode::BAD_GATEWAY, "offline".into()); }
            let body = if path == "/blocks/tip/hash" || path == "/block-height/0" { hash }
                else if path == "/blocks/tip/height" { "0".into() }
                else if path.ends_with("/header") { header }
                else if path.starts_with("/scripthash/") { "[]".into() }
                else if path.ends_with("/status") { "{\"in_best_chain\":true,\"height\":0,\"next_best\":null}".into() }
                else if path == "/blocks" || path == "/blocks/0" { format!("[{{\"id\":\"{hash}\",\"height\":0,\"version\":1,\"timestamp\":1231006505,\"tx_count\":1,\"size\":285,\"weight\":1140,\"merkle_root\":\"{}\",\"previousblockhash\":null,\"mediantime\":1231006505,\"nonce\":2083236893,\"bits\":486604799,\"difficulty\":1.0}}]", "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b") }
                else { return (StatusCode::NOT_FOUND, format!("unsupported fixture path: {path}")); };
            (StatusCode::OK, body)
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let cfg = config(&dir, &url);
    let store = cfg.storage_dir.clone();
    let started = Arc::new(Mutex::new(Vec::<Arc<LdkProvider>>::new()));
    let providers = started.clone();
    let provider = RecoveringLightning::new(move || {
        let cfg = cfg.clone();
        let providers = providers.clone();
        async move {
            let p = Arc::new(LdkProvider::new(cfg).await?);
            providers.lock().unwrap().push(p.clone());
            Ok(p as Arc<dyn LightningProvider>)
        }
    }, Default::default()).await.unwrap();
    assert!(!provider.money_ready().await);
    assert_eq!(provider.readiness().await.state, "offline");
    assert!(matches!(provider.pay_invoice("unused").await, Err(LightningError::NotReady)));
    assert!(matches!(provider.create_invoice(1000, "offline", 60).await, Err(LightningError::NotReady)));
    assert!(matches!(provider.keysend("unused", 1000, None).await, Err(LightningError::NotReady)));
    assert!(matches!(provider.open_channel("unused", "unused", 1000, false, None).await, Err(LightningError::NotReady)));
    assert!(matches!(provider.close_channel("unused", false).await, Err(LightningError::NotReady)));
    fees_live.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(15), async {
        while started.lock().unwrap().is_empty() { tokio::time::sleep(Duration::from_millis(50)).await; }
    }).await.unwrap();
    assert!(!provider.money_ready().await, "fees alone must not enable money");
    chain_live.store(true, Ordering::SeqCst);
    let backend = started.lock().unwrap()[0].clone();
    tokio::task::spawn_blocking(move || backend.node().sync_wallets()).await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !provider.money_ready().await { tokio::time::sleep(Duration::from_millis(50)).await; }
    }).await.unwrap();
    // A failed attempt after fresh successful syncs is diagnostic only. The
    // original timestamp/baseline readiness predicate still admits invoices.
    chain_live.store(false, Ordering::SeqCst);
    let backend = started.lock().unwrap()[0].clone();
    let sync_backend = backend.clone();
    assert!(tokio::task::spawn_blocking(move || sync_backend.node().sync_wallets())
        .await.unwrap().is_err());
    assert!(backend.chain_sync_status().is_some());
    assert!(backend.money_ready().await, "fresh prior syncs still satisfy readiness");
    assert!(provider.money_ready().await);
    let invoice = provider.create_invoice(1000, "recovered", 60).await.unwrap();
    assert!(!invoice.bolt11.is_empty());
    for _ in 0..100 { assert!(provider.readiness().await.money_ready); }
    assert_eq!(started.lock().unwrap().len(), 1, "one backend successfully started");
    let log = std::fs::read_to_string(store.join("ldk_node.log")).unwrap();
    assert_eq!(log.matches("Startup complete.").count(), 1);
    let identities: Vec<_> = log.lines().filter_map(|line| line.split("Starting up LDK Node with node ID ").nth(1))
        .map(|rest| rest.split_whitespace().next().unwrap()).collect();
    assert!(identities.len() >= 6);
    assert!(identities.iter().all(|id| *id == identities[0]), "retry changed Lightning identity");
    let states: Vec<_> = provider.readiness().await.events.into_iter().map(|e| e.state).collect();
    assert_eq!(states, ["offline", "retrying", "synchronizing", "ready"]);
    provider.shutdown().await.unwrap();
    assert!(!provider.money_ready().await);
    provider.shutdown().await.unwrap();
    server.abort();
}

#[path = "support/outbound_guard.rs"]
mod outbound_guard;

/// Every outbound DNS/connect attempt is guarded, including the vendored
/// default Esplora host and destinations absent from this configuration.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bitcoind_sync_failure_is_visible_and_never_contacts_esplora_or_fallback() {
    let Ok(core_url) = std::env::var("BITSOV_GUARD_CORE") else {
        let core = Fixture::new(0, false).await; // RPC POST returns 404.
        let primary = Fixture::new(0, false).await;
        let fallback = Fixture::new(0, false).await;
        let guard_dir = tempfile::tempdir().unwrap();
        outbound_guard::run(
            "bitcoind_sync_failure_is_visible_and_never_contacts_esplora_or_fallback",
            guard_dir.path(), &core.url, &primary.url, &fallback.url,
        ).await;
        assert!(core.background_requests.load(Ordering::SeqCst) > 1);
        for explorer in [&primary, &fallback] {
            assert_eq!(explorer.requests.load(Ordering::SeqCst), 0);
            assert_eq!(explorer.background_requests.load(Ordering::SeqCst), 0);
        }
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cookie = dir.path().join("cookie");
    std::fs::write(&cookie, "user:NO_FALLBACK_SECRET").unwrap();
    let mut cfg = config(&dir, &std::env::var("BITSOV_GUARD_PRIMARY").unwrap());
    cfg.network = "regtest".into();
    cfg.esplora_url_fallback = Some(std::env::var("BITSOV_GUARD_FALLBACK").unwrap());
    cfg.bitcoind = Some(serde_json::from_value(serde_json::json!({
        "rpc_host": "127.0.0.1",
        "rpc_port": core_url.rsplit(':').next().unwrap().parse::<u16>().unwrap(),
        "cookie_file": cookie,
    })).unwrap());
    // Regtest permits unavailable fee estimates, allowing the real background
    // listener sync to start and fail against this disposable RPC fixture.
    let provider = tokio::time::timeout(Duration::from_secs(20), LdkProvider::new(cfg))
        .await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while provider.chain_sync_status().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    assert!(provider.node().status().is_running);
    assert!(!provider.money_ready().await);
    let failure = provider.chain_sync_status().unwrap();
    let json = serde_json::to_value(failure).unwrap();
    assert_eq!(json["state"], "stalled");
    assert_eq!(json["last_error_kind"], "sync_failed");
    assert!(json["since"].as_u64().unwrap() > 0);
    assert!(!json.to_string().contains("NO_FALLBACK_SECRET"));
    // Observe a new RPC attempt after the stalled diagnostic, not just startup
    // traffic. The guard records connections from all LDK background threads.
    let requests = outbound_guard::connection_count();
    tokio::time::timeout(Duration::from_secs(10), async {
        while outbound_guard::connection_count() == requests {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    assert_eq!(provider.chain_sync_status(), Some(failure));
    assert!(!provider.money_ready().await);
    provider.shutdown().await.unwrap();
}

#[path = "../../konsensus-chain/tests/support/electrum_fixture.rs"]
mod electrum_fixture;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn electrum_sync_failure_is_visible_and_never_contacts_esplora_or_fallback() {
    let Ok(endpoint) = std::env::var("BITSOV_GUARD_ENDPOINT") else {
        let electrum =
            electrum_fixture::Fixture::new(|request| match request["method"].as_str().unwrap() {
                "server.version" => serde_json::json!({"result":["bitsov-fixture", "1.4"]}),
                "blockchain.estimatefee" => serde_json::json!({"result":0.00002}),
                _ => serde_json::json!({"error":{"code":-1,"message":"ELECTRUM_REMOTE_SECRET"}}),
            })
            .await;
        let primary = Fixture::new(0, false).await;
        let fallback = Fixture::new(0, false).await;
        let guard_dir = tempfile::tempdir().unwrap();
        outbound_guard::run(
            "electrum_sync_failure_is_visible_and_never_contacts_esplora_or_fallback",
            guard_dir.path(),
            &electrum.url,
            &primary.url,
            &fallback.url,
        )
        .await;
        let requests = electrum.requests.lock().unwrap();
        assert!(requests
            .iter()
            .any(|r| r["method"] == "blockchain.estimatefee"));
        assert!(requests
            .iter()
            .any(|r| r["method"] == "blockchain.headers.subscribe"));
        for explorer in [&primary, &fallback] {
            assert_eq!(explorer.requests.load(Ordering::SeqCst), 0);
            assert_eq!(explorer.background_requests.load(Ordering::SeqCst), 0);
        }
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir, &std::env::var("BITSOV_GUARD_PRIMARY").unwrap());
    cfg.network = "regtest".into();
    cfg.esplora_url_fallback = Some(std::env::var("BITSOV_GUARD_FALLBACK").unwrap());
    cfg.electrum =
        Some(serde_json::from_value(serde_json::json!({"server_url":endpoint})).unwrap());
    let provider = tokio::time::timeout(Duration::from_secs(20), LdkProvider::new(cfg.clone()))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while provider.chain_sync_status().is_none() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(provider.node().status().is_running);
    assert!(!provider.money_ready().await);
    let failure = provider.chain_sync_status().unwrap();
    let json = serde_json::to_value(failure).unwrap();
    assert_eq!(json["state"], "stalled");
    assert_eq!(json["last_error_kind"], "sync_failed");
    assert!(json["since"].as_u64().unwrap() > 0);
    assert!(!json.to_string().contains("ELECTRUM_REMOTE_SECRET"));
    // Explicit retry exercises both wallets and preserves the first-failure time.
    let _ = provider.node().sync_wallets();
    assert_eq!(provider.chain_sync_status(), Some(failure));
    assert!(!provider.money_ready().await);
    provider.shutdown().await.unwrap();
    drop(provider);

    // Invalid programmatic configs fail closed before any network or fallback.
    cfg.electrum.as_mut().unwrap().server_url.clear();
    assert!(matches!(
        LdkProvider::new(cfg).await,
        Err(LightningError::InvalidStartupConfig(_))
    ));
}

/// A selected Electrum that fails its startup fee barrier must not fall back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn electrum_startup_failure_never_contacts_esplora_or_fallback() {
    let Ok(endpoint) = std::env::var("BITSOV_GUARD_ENDPOINT") else {
        let electrum = electrum_fixture::Fixture::new(|request| {
            if request["method"] == "server.version" {
                serde_json::json!({"result":["bitsov-fixture", "1.4"]})
            } else {
                serde_json::json!({"error":{"code":-1,"message":"ELECTRUM_REMOTE_SECRET"}})
            }
        })
        .await;
        let primary = Fixture::new(0, false).await;
        let fallback = Fixture::new(0, false).await;
        let guard_dir = tempfile::tempdir().unwrap();
        outbound_guard::run(
            "electrum_startup_failure_never_contacts_esplora_or_fallback",
            guard_dir.path(),
            &electrum.url,
            &primary.url,
            &fallback.url,
        )
        .await;
        assert!(electrum
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r["method"] == "blockchain.estimatefee"));
        for explorer in [&primary, &fallback] {
            assert_eq!(explorer.requests.load(Ordering::SeqCst), 0);
            assert_eq!(explorer.background_requests.load(Ordering::SeqCst), 0);
        }
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    // Bitcoin's strict fee barrier, but every connection goes to the fake TCP
    // server: this is not a mainnet node and no chain or funds are involved.
    let mut cfg = config(&dir, &std::env::var("BITSOV_GUARD_PRIMARY").unwrap());
    cfg.esplora_url_fallback = Some(std::env::var("BITSOV_GUARD_FALLBACK").unwrap());
    cfg.electrum =
        Some(serde_json::from_value(serde_json::json!({"server_url":endpoint})).unwrap());
    let error = tokio::time::timeout(Duration::from_secs(20), LdkProvider::new(cfg.clone()))
        .await
        .unwrap()
        .unwrap_err();
    match error {
        LightningError::ChainSourceUnavailable {
            service,
            cause,
            attempts,
            ..
        } => {
            assert_eq!(service, "electrum");
            assert_eq!(attempts, 1);
            assert!(!cause.contains("ELECTRUM_REMOTE_SECRET"));
        }
        other => panic!("unexpected startup error: {other}"),
    }
    // Ambiguous programmatic selection must fail validation, even when one
    // backend would otherwise work. No credentials file is read in this case.
    cfg.bitcoind = Some(
        serde_json::from_value(serde_json::json!({
            "rpc_host":"127.0.0.1", "rpc_port":1, "cookie_file":"unused-cookie",
        }))
        .unwrap(),
    );
    let before = outbound_guard::connection_count();
    assert!(matches!(
        LdkProvider::new(cfg).await,
        Err(LightningError::InvalidStartupConfig(_))
    ));
    assert_eq!(outbound_guard::connection_count(), before);
}
