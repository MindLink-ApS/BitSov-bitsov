//! Each chain source must be on the configured network before it serves any
//! chain data. Loopback fixtures only; no node or public endpoint is used.
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};

use axum::{extract::State, http::StatusCode, routing::get, routing::post, Json, Router};
use bitcoin::Network;
use konsensus_chain::{
    BitcoindConfig, BitcoindProvider, ElectrumConfig, ElectrumProvider, EsploraConfig,
    EsploraProvider, NetworkCheck,
};
use konsensus_core::traits::chain::{ChainProvider, TrustLevel};
use serde_json::{json, Value};

#[path = "support/electrum_fixture.rs"]
mod electrum_fixture;

fn genesis(network: Network) -> bitcoin::Block {
    bitcoin::blockdata::constants::genesis_block(network)
}

/// A loopback port with nothing listening on it.
async fn closed_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

async fn serve(app: Router) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (port, task)
}

fn assert_mismatch(check: NetworkCheck, configured: &str, source: &str, reported: &str) {
    let NetworkCheck::Mismatch(mismatch) = check else {
        panic!("expected a mismatch, got {check:?}");
    };
    let text = mismatch.to_string();
    assert!(
        text.contains(&format!("configured network is {configured}")),
        "{text}"
    );
    assert!(
        text.contains(&format!("the {source} chain source is on {reported}")),
        "{text}"
    );
}

// ── Bitcoin Core ────────────────────────────────────────────────────────

type CoreChain = Arc<Mutex<Option<&'static str>>>;
type Calls = Arc<Mutex<Vec<String>>>;

struct Core {
    port: u16,
    chain: CoreChain,
    methods: Calls,
    _dir: tempfile::TempDir,
    cookie: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
}

impl Core {
    /// `chain = None` answers every request with HTTP 503 (Core unreachable).
    async fn new(chain: Option<&'static str>) -> Self {
        let chain = Arc::new(Mutex::new(chain));
        let methods = Arc::new(Mutex::new(Vec::new()));
        let state = (Arc::clone(&chain), Arc::clone(&methods));
        let app = Router::new()
            .route(
                "/",
                post(
                    |State((chain, methods)): State<(CoreChain, Calls)>,
                     Json(request): Json<Value>| async move {
                        let Some(chain) = *chain.lock().unwrap() else {
                            return Err(StatusCode::SERVICE_UNAVAILABLE);
                        };
                        let method = request["method"].as_str().unwrap().to_owned();
                        methods.lock().unwrap().push(method.clone());
                        let result = match method.as_str() {
                            "getblockchaininfo" => json!({
                                "chain": chain, "blocks": 101, "headers": 101,
                                "initialblockdownload": false,
                            }),
                            "getblockcount" => json!(101),
                            _ => panic!("unexpected RPC {method}"),
                        };
                        Ok(Json(json!({"result": result, "error": null, "id": 1})))
                    },
                ),
            )
            .with_state(state);
        let (port, task) = serve(app).await;
        let dir = tempfile::tempdir().unwrap();
        let cookie = dir.path().join(".cookie");
        std::fs::write(&cookie, "user:pass\n").unwrap();
        Self {
            port,
            chain,
            methods,
            _dir: dir,
            cookie,
            task,
        }
    }

    fn provider(&self, port: u16, network: Network) -> BitcoindProvider {
        let config: BitcoindConfig = serde_json::from_value(
            json!({"rpc_host": "127.0.0.1", "rpc_port": port, "cookie_file": self.cookie}),
        )
        .unwrap();
        BitcoindProvider::new(config).unwrap().with_network(network)
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn bitcoind_on_the_configured_network_is_verified_and_serves_data() {
    for (chain, network) in [
        ("main", Network::Bitcoin),
        ("test", Network::Testnet),
        ("testnet4", Network::Testnet4),
        ("signet", Network::Signet),
        ("regtest", Network::Regtest),
    ] {
        let core = Core::new(Some(chain)).await;
        let provider = core.provider(core.port, network);
        assert_eq!(provider.verify_network().await, NetworkCheck::Verified);
        assert_eq!(provider.get_block_height().await.unwrap(), 101);
        assert!(provider.is_synced().await);
        // Verified once; no further identity calls.
        assert_eq!(
            core.methods.lock().unwrap().as_slice(),
            ["getblockchaininfo", "getblockcount", "getblockchaininfo"]
        );
    }
}

#[tokio::test]
async fn bitcoind_on_another_network_is_refused_and_serves_nothing() {
    for (chain, configured, configured_name, reported_name) in [
        ("main", Network::Signet, "signet", "bitcoin (mainnet)"),
        ("signet", Network::Bitcoin, "bitcoin (mainnet)", "signet"),
        (
            "testnet4",
            Network::Testnet,
            "testnet (testnet3)",
            "testnet4",
        ),
        ("regtest", Network::Signet, "signet", "regtest"),
        (
            "liquidv1",
            Network::Bitcoin,
            "bitcoin (mainnet)",
            "an unrecognised network",
        ),
    ] {
        let core = Core::new(Some(chain)).await;
        let provider = core.provider(core.port, configured);
        assert_mismatch(
            provider.verify_network().await,
            configured_name,
            "bitcoind",
            reported_name,
        );
        let error = provider.get_block_height().await.unwrap_err().to_string();
        assert!(error.contains("network mismatch"), "{error}");
        assert!(!provider.is_synced().await);
        assert!(provider.estimate_fee(6).await.is_err());
        // Only the identity call reached Core; nothing after the refusal.
        assert_eq!(
            core.methods.lock().unwrap().as_slice(),
            ["getblockchaininfo"]
        );
    }
}

#[tokio::test]
async fn bitcoind_unreachable_is_not_ready_and_verified_on_reconnect() {
    let core = Core::new(None).await;
    let closed = core.provider(closed_port().await, Network::Signet);
    assert_eq!(closed.verify_network().await, NetworkCheck::Unavailable);
    assert!(closed.get_block_height().await.is_err());
    assert!(!closed.is_synced().await);

    // HTTP failure: unavailable, then the source answers on the wrong chain.
    let provider = core.provider(core.port, Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Unavailable);
    assert!(!provider.is_synced().await);
    *core.chain.lock().unwrap() = Some("main");
    assert!(!provider.is_synced().await);
    assert_mismatch(
        provider.verify_network().await,
        "signet",
        "bitcoind",
        "bitcoin (mainnet)",
    );
    // The refusal holds even if the source later answers on signet.
    *core.chain.lock().unwrap() = Some("signet");
    assert!(provider.get_block_height().await.is_err());

    // A source that comes back on the right chain becomes ready as before.
    let core = Core::new(None).await;
    let provider = core.provider(core.port, Network::Signet);
    assert!(!provider.is_synced().await);
    *core.chain.lock().unwrap() = Some("signet");
    assert!(provider.is_synced().await);
    assert_eq!(provider.verify_network().await, NetworkCheck::Verified);
}

#[tokio::test]
async fn bitcoind_without_a_configured_network_is_unchanged() {
    let core = Core::new(Some("main")).await;
    let config: BitcoindConfig = serde_json::from_value(
        json!({"rpc_host": "127.0.0.1", "rpc_port": core.port, "cookie_file": core.cookie}),
    )
    .unwrap();
    let provider = BitcoindProvider::new(config).unwrap();
    assert_eq!(provider.verify_network().await, NetworkCheck::NotConfigured);
    assert_eq!(provider.get_block_height().await.unwrap(), 101);
    assert_eq!(core.methods.lock().unwrap().as_slice(), ["getblockcount"]);
}

// ── Electrum ────────────────────────────────────────────────────────────

async fn electrum(network: Network) -> electrum_fixture::Fixture {
    let header = bitcoin::consensus::encode::serialize_hex(&genesis(network).header);
    electrum_fixture::Fixture::new(move |request| match request["method"].as_str().unwrap() {
        "blockchain.block.header" => {
            assert_eq!(request["params"][0], 0);
            json!({"result": header})
        }
        "blockchain.headers.subscribe" => json!({"result": {"height": 101, "hex": header}}),
        method => panic!("unexpected Electrum method {method}"),
    })
    .await
}

fn electrum_provider(url: &str, network: Network) -> ElectrumProvider {
    ElectrumProvider::new(ElectrumConfig {
        server_url: url.into(),
        operator: Default::default(),
    })
    .unwrap()
    .with_network(network)
}

fn methods(fixture: &electrum_fixture::Fixture) -> Vec<String> {
    fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .map(|r| r["method"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn electrum_on_the_configured_network_is_verified_and_serves_data() {
    for network in [
        Network::Bitcoin,
        Network::Testnet,
        Network::Testnet4,
        Network::Signet,
        Network::Regtest,
    ] {
        let server = electrum(network).await;
        let provider = electrum_provider(&server.url, network);
        assert_eq!(provider.verify_network().await, NetworkCheck::Verified);
        assert_eq!(provider.get_block_height().await.unwrap(), 101);
        assert!(provider.is_synced().await);
        assert_eq!(
            methods(&server),
            [
                "blockchain.block.header",
                "blockchain.headers.subscribe",
                "blockchain.headers.subscribe"
            ]
        );
    }
}

#[tokio::test]
async fn electrum_on_another_network_is_refused_and_serves_nothing() {
    for (served, configured, configured_name, reported_name) in [
        (
            Network::Bitcoin,
            Network::Signet,
            "signet",
            "bitcoin (mainnet)",
        ),
        (
            Network::Signet,
            Network::Bitcoin,
            "bitcoin (mainnet)",
            "signet",
        ),
        (
            Network::Testnet4,
            Network::Testnet,
            "testnet (testnet3)",
            "testnet4",
        ),
    ] {
        let server = electrum(served).await;
        let provider = electrum_provider(&server.url, configured);
        assert_mismatch(
            provider.verify_network().await,
            configured_name,
            "electrum",
            reported_name,
        );
        assert!(provider.get_block_height().await.is_err());
        assert!(!provider.is_synced().await);
        assert_eq!(methods(&server), ["blockchain.block.header"]);
    }
}

#[tokio::test]
async fn electrum_unreachable_is_not_ready() {
    let url = format!("tcp://127.0.0.1:{}", closed_port().await);
    let provider = electrum_provider(&url, Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Unavailable);
    assert!(provider.get_block_height().await.is_err());
    assert!(!provider.is_synced().await);
}

// ── Esplora ─────────────────────────────────────────────────────────────

struct Explorer {
    url: String,
    up: Arc<AtomicBool>,
    tip_requests: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Explorer {
    async fn new(network: Network) -> Self {
        let up = Arc::new(AtomicBool::new(true));
        let tip_requests = Arc::new(AtomicUsize::new(0));
        let hash = genesis(network).block_hash().to_string();
        let app =
            Router::new()
                .route(
                    "/api/block-height/0",
                    get(
                        |State((up, _, hash)): State<(
                            Arc<AtomicBool>,
                            Arc<AtomicUsize>,
                            String,
                        )>| async move {
                            if up.load(Ordering::SeqCst) {
                                Ok(hash)
                            } else {
                                Err(StatusCode::SERVICE_UNAVAILABLE)
                            }
                        },
                    ),
                )
                .route(
                    "/api/blocks/tip/height",
                    get(
                        |State((up, tips, _)): State<(
                            Arc<AtomicBool>,
                            Arc<AtomicUsize>,
                            String,
                        )>| async move {
                            tips.fetch_add(1, Ordering::SeqCst);
                            if up.load(Ordering::SeqCst) {
                                Ok("101")
                            } else {
                                Err(StatusCode::SERVICE_UNAVAILABLE)
                            }
                        },
                    ),
                )
                .with_state((Arc::clone(&up), Arc::clone(&tip_requests), hash));
        let (port, task) = serve(app).await;
        Self {
            url: format!("http://127.0.0.1:{port}"),
            up,
            tip_requests,
            task,
        }
    }
}

impl Drop for Explorer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn esplora_provider(primary: &str, fallbacks: &[&str], network: Network) -> EsploraProvider {
    EsploraProvider::with_fallbacks(
        EsploraConfig::custom(primary.into(), TrustLevel::ServerTrust),
        fallbacks.iter().map(|url| url.to_string()).collect(),
    )
    .unwrap()
    .with_network(network)
}

#[tokio::test]
async fn esplora_on_the_configured_network_is_verified_and_serves_data() {
    for network in [
        Network::Bitcoin,
        Network::Testnet,
        Network::Testnet4,
        Network::Signet,
        Network::Regtest,
    ] {
        let primary = Explorer::new(network).await;
        let fallback = Explorer::new(network).await;
        let provider = esplora_provider(&primary.url, &[&fallback.url], network);
        assert_eq!(provider.verify_network().await, NetworkCheck::Verified);
        assert_eq!(provider.get_block_height().await.unwrap(), 101);
        assert!(provider.is_synced().await);
    }
}

#[tokio::test]
async fn esplora_on_another_network_is_refused_without_fallback() {
    let primary = Explorer::new(Network::Bitcoin).await;
    let fallback = Explorer::new(Network::Signet).await;
    let provider = esplora_provider(&primary.url, &[&fallback.url], Network::Signet);
    assert_mismatch(
        provider.verify_network().await,
        "signet",
        "esplora",
        "bitcoin (mainnet)",
    );
    assert!(provider.get_block_height().await.is_err());
    assert!(!provider.is_synced().await);
    assert_eq!(primary.tip_requests.load(Ordering::SeqCst), 0);
    assert_eq!(
        fallback.tip_requests.load(Ordering::SeqCst),
        0,
        "no fallback"
    );

    // A wrong-network fallback refuses the provider too: it could be failed over to.
    let primary = Explorer::new(Network::Signet).await;
    let fallback = Explorer::new(Network::Testnet4).await;
    let provider = esplora_provider(&primary.url, &[&fallback.url], Network::Signet);
    assert_mismatch(
        provider.verify_network().await,
        "signet",
        "esplora",
        "testnet4",
    );
    assert!(provider.get_block_height().await.is_err());
    assert_eq!(primary.tip_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn esplora_unreachable_is_not_ready_and_checked_before_failover() {
    let url = format!("http://127.0.0.1:{}", closed_port().await);
    let provider = esplora_provider(&url, &[], Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Unavailable);
    assert!(provider.get_block_height().await.is_err());
    assert!(!provider.is_synced().await);

    // Primary up on signet, fallback down: usable as before, not fully verified.
    let primary = Explorer::new(Network::Signet).await;
    let fallback = Explorer::new(Network::Bitcoin).await;
    fallback.up.store(false, Ordering::SeqCst);
    let provider = esplora_provider(&primary.url, &[&fallback.url], Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Unavailable);
    assert_eq!(provider.get_block_height().await.unwrap(), 101);

    // The primary drops and the fallback returns on mainnet: checked before
    // its first use, refused, and the provider serves nothing from then on.
    primary.up.store(false, Ordering::SeqCst);
    fallback.up.store(true, Ordering::SeqCst);
    let provider = esplora_provider(&primary.url, &[&fallback.url], Network::Signet);
    let error = provider.get_block_height().await.unwrap_err().to_string();
    assert!(error.contains("network mismatch"), "{error}");
    assert_eq!(fallback.tip_requests.load(Ordering::SeqCst), 0);
    primary.up.store(true, Ordering::SeqCst);
    assert!(provider.get_block_height().await.is_err());
    assert!(matches!(
        provider.verify_network().await,
        NetworkCheck::Mismatch(_)
    ));
}
