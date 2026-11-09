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
                            "getblockchaininfo" => {
                                let mut info = json!({
                                    "chain": chain, "blocks": 101, "headers": 101,
                                    "initialblockdownload": false,
                                });
                                if chain.is_empty() {
                                    // A reply that names no chain.
                                    info.as_object_mut().unwrap().remove("chain");
                                }
                                info
                            }
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
    electrum_on(Arc::new(Mutex::new(network))).await
}

/// An Electrum server whose chain can be swapped between connections.
async fn electrum_on(network: Arc<Mutex<Network>>) -> electrum_fixture::Fixture {
    electrum_fixture::Fixture::new(move |request| {
        let header =
            bitcoin::consensus::encode::serialize_hex(&genesis(*network.lock().unwrap()).header);
        match request["method"].as_str().unwrap() {
            "blockchain.block.header" => {
                assert_eq!(request["params"][0], 0);
                json!({"result": header})
            }
            "blockchain.headers.subscribe" => json!({"result": {"height": 101, "hex": header}}),
            method => panic!("unexpected Electrum method {method}"),
        }
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
        // Every query is a new connection, and each one is checked first.
        assert_eq!(
            methods(&server),
            [
                "blockchain.block.header",
                "blockchain.block.header",
                "blockchain.headers.subscribe",
                "blockchain.block.header",
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

#[derive(Clone)]
struct ExplorerState {
    network: Arc<Mutex<Network>>,
    up: Arc<AtomicBool>,
    serves_header: Arc<AtomicBool>,
    tip_requests: Arc<AtomicUsize>,
}

struct Explorer {
    url: String,
    port: u16,
    state: ExplorerState,
    up: Arc<AtomicBool>,
    tip_requests: Arc<AtomicUsize>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

fn explorer_app(state: ExplorerState) -> Router {
    fn available(state: &ExplorerState) -> Result<(), StatusCode> {
        if state.up.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
    Router::new()
        .route(
            "/api/block-height/0",
            get(|State(state): State<ExplorerState>| async move {
                available(&state)?;
                Ok::<_, StatusCode>(
                    genesis(*state.network.lock().unwrap())
                        .block_hash()
                        .to_string(),
                )
            }),
        )
        .route(
            "/api/block/:hash/header",
            get(
                |State(state): State<ExplorerState>,
                 axum::extract::Path(hash): axum::extract::Path<String>| async move {
                    available(&state)?;
                    let block = genesis(*state.network.lock().unwrap());
                    if !state.serves_header.load(Ordering::SeqCst)
                        || hash != block.block_hash().to_string()
                    {
                        return Err(StatusCode::NOT_FOUND);
                    }
                    Ok(bitcoin::consensus::encode::serialize_hex(&block.header))
                },
            ),
        )
        .route(
            "/api/blocks/tip/height",
            get(|State(state): State<ExplorerState>| async move {
                state.tip_requests.fetch_add(1, Ordering::SeqCst);
                available(&state)?;
                Ok::<_, StatusCode>("101")
            }),
        )
        .route(
            "/api/fee-estimates",
            get(|State(state): State<ExplorerState>| async move {
                available(&state)?;
                Ok::<_, StatusCode>(r#"{"6":2.0}"#)
            }),
        )
        .with_state(state)
        // No keep-alive, so stopping the fixture really drops the connection.
        .layer(axum::middleware::map_response(
            |mut response: axum::response::Response| async move {
                response.headers_mut().insert(
                    axum::http::header::CONNECTION,
                    axum::http::HeaderValue::from_static("close"),
                );
                response
            },
        ))
}

impl Explorer {
    async fn new(network: Network) -> Self {
        let state = ExplorerState {
            network: Arc::new(Mutex::new(network)),
            up: Arc::new(AtomicBool::new(true)),
            serves_header: Arc::new(AtomicBool::new(true)),
            tip_requests: Arc::new(AtomicUsize::new(0)),
        };
        let (port, task) = serve(explorer_app(state.clone())).await;
        Self {
            url: format!("http://127.0.0.1:{port}"),
            port,
            up: Arc::clone(&state.up),
            tip_requests: Arc::clone(&state.tip_requests),
            state,
            task: Mutex::new(Some(task)),
        }
    }

    /// Close the listener and every open connection.
    async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }

    /// Listen again on the same port, serving `network`.
    async fn restart_on(&self, network: Network) {
        *self.state.network.lock().unwrap() = network;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", self.port))
            .await
            .unwrap();
        let app = explorer_app(self.state.clone());
        *self.task.lock().unwrap() = Some(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap()
        }));
    }
}

impl Drop for Explorer {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
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

// ── Unverified is never a pass, and checks end on reconnect ────────────

#[tokio::test]
async fn bitcoind_reply_without_a_chain_is_never_a_pass() {
    let core = Core::new(Some("")).await;
    let provider = core.provider(core.port, Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Unavailable);
    assert!(provider.get_block_height().await.is_err());
    assert!(!provider.is_synced().await);
    assert!(!core
        .methods
        .lock()
        .unwrap()
        .contains(&"getblockcount".to_string()));
}

#[tokio::test]
async fn bitcoind_is_checked_on_every_chain_reply_and_after_a_failure() {
    // Core changes chain without any failure: the next chain reply catches it.
    let core = Core::new(Some("signet")).await;
    let provider = core.provider(core.port, Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Verified);
    *core.chain.lock().unwrap() = Some("main");
    assert!(!provider.is_synced().await);
    assert!(provider.get_block_height().await.is_err());

    // Core fails a request, then answers on another chain: asked again first.
    let core = Core::new(Some("signet")).await;
    let provider = core.provider(core.port, Network::Signet);
    assert_eq!(provider.get_block_height().await.unwrap(), 101);
    *core.chain.lock().unwrap() = None;
    assert!(provider.get_block_height().await.is_err());
    *core.chain.lock().unwrap() = Some("main");
    let error = provider.get_block_height().await.unwrap_err().to_string();
    assert!(error.contains("network mismatch"), "{error}");
    // Only the height read before the failure reached Core; afterwards Core
    // was asked for its chain and refused before any data call.
    assert_eq!(
        core.methods.lock().unwrap().as_slice(),
        ["getblockchaininfo", "getblockcount", "getblockchaininfo"]
    );
}

#[tokio::test]
async fn electrum_server_swapped_between_connections_is_refused() {
    let network = Arc::new(Mutex::new(Network::Signet));
    let server = electrum_on(Arc::clone(&network)).await;
    let provider = electrum_provider(&server.url, Network::Signet);
    assert_eq!(provider.get_block_height().await.unwrap(), 101);
    *network.lock().unwrap() = Network::Bitcoin;
    let error = provider.get_block_height().await.unwrap_err().to_string();
    assert!(error.contains("network mismatch"), "{error}");
    assert!(matches!(
        provider.verify_network().await,
        NetworkCheck::Mismatch(_)
    ));
}

#[tokio::test]
async fn esplora_hash_string_alone_is_never_a_pass() {
    let explorer = Explorer::new(Network::Signet).await;
    explorer.state.serves_header.store(false, Ordering::SeqCst);
    let provider = esplora_provider(&explorer.url, &[], Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Unavailable);
    assert!(provider.get_block_height().await.is_err());
    assert!(!provider.is_synced().await);
    assert_eq!(explorer.tip_requests.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn esplora_is_checked_again_after_a_lost_connection() {
    let explorer = Explorer::new(Network::Signet).await;
    let provider = esplora_provider(&explorer.url, &[], Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Verified);
    assert_eq!(provider.estimate_fee(6).await.unwrap().sat_per_vbyte, 2.0);
    explorer.stop().await;
    assert!(provider.estimate_fee(6).await.is_err());
    explorer.restart_on(Network::Bitcoin).await;
    let error = provider.estimate_fee(6).await.unwrap_err().to_string();
    assert!(error.contains("network mismatch"), "{error}");
}

// ── Cached height and failed bodies ─────────────────────────────────────

#[tokio::test]
async fn esplora_cached_height_is_refused_after_a_mismatch() {
    let explorer = Explorer::new(Network::Signet).await;
    let provider = esplora_provider(&explorer.url, &[], Network::Signet);
    assert_eq!(provider.get_block_height().await.unwrap(), 101);
    assert!(provider.is_synced_with_height(101).await);
    *explorer.state.network.lock().unwrap() = Network::Bitcoin;
    assert!(matches!(
        provider.verify_network().await,
        NetworkCheck::Mismatch(_)
    ));
    let error = provider.get_block_height().await.unwrap_err().to_string();
    assert!(error.contains("network mismatch"), "{error}");
    assert!(!provider.is_synced().await);
    assert!(!provider.is_synced_with_height(101).await);
}

#[tokio::test]
async fn esplora_cached_height_needs_a_current_check() {
    let explorer = Explorer::new(Network::Signet).await;
    let provider = esplora_provider(&explorer.url, &[], Network::Signet);
    assert_eq!(provider.get_block_height().await.unwrap(), 101);
    // The connection drops (the check ends) and the endpoint returns on mainnet.
    explorer.stop().await;
    assert!(provider.estimate_fee(6).await.is_err());
    explorer.restart_on(Network::Bitcoin).await;
    let error = provider.get_block_height().await.unwrap_err().to_string();
    assert!(error.contains("network mismatch"), "{error}");
    assert!(!provider.is_synced().await);
}

/// A loopback Esplora speaking raw HTTP/1.1, so a response can stop after
/// its headers. Serves `network`; with `truncate`, fee and broadcast replies
/// promise a body and close the connection early.
struct RawExplorer {
    url: String,
    network: Arc<Mutex<Network>>,
    truncate: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl RawExplorer {
    async fn new(network: Network) -> Self {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let network = Arc::new(Mutex::new(network));
        let truncate = Arc::new(AtomicBool::new(false));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (served, cut) = (Arc::clone(&network), Arc::clone(&truncate));
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (served, cut) = (Arc::clone(&served), Arc::clone(&cut));
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match socket.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    let text = String::from_utf8_lossy(&request).to_string();
                    let path = text.split_whitespace().nth(1).unwrap_or("").to_owned();
                    let block = genesis(*served.lock().unwrap());
                    let hash = block.block_hash().to_string();
                    let body = if path == "/api/block-height/0" {
                        Some(hash.clone())
                    } else if path == format!("/api/block/{hash}/header") {
                        Some(bitcoin::consensus::encode::serialize_hex(&block.header))
                    } else if path == "/api/fee-estimates" || path == "/api/tx" {
                        if cut.load(Ordering::SeqCst) {
                            let _ = socket
                                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 64\r\nConnection: close\r\n\r\n{\"6\"")
                                .await;
                            return;
                        }
                        Some(r#"{"6":2.0}"#.to_owned())
                    } else {
                        None
                    };
                    let reply = match body {
                        Some(body) => format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        ),
                        None => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into(),
                    };
                    let _ = socket.write_all(reply.as_bytes()).await;
                });
            }
        });
        Self {
            url,
            network,
            truncate,
            task,
        }
    }
}

impl Drop for RawExplorer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn esplora_truncated_body_is_a_lost_connection() {
    let explorer = RawExplorer::new(Network::Signet).await;
    let provider = esplora_provider(&explorer.url, &[], Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Verified);
    assert_eq!(provider.estimate_fee(6).await.unwrap().sat_per_vbyte, 2.0);
    explorer.truncate.store(true, Ordering::SeqCst);
    assert!(provider.estimate_fee(6).await.is_err());
    explorer.truncate.store(false, Ordering::SeqCst);
    *explorer.network.lock().unwrap() = Network::Bitcoin;
    let error = provider.estimate_fee(6).await.unwrap_err().to_string();
    assert!(error.contains("network mismatch"), "{error}");
}

#[tokio::test]
async fn esplora_failed_recovery_broadcast_is_a_lost_connection() {
    use konsensus_chain::recovery::RecoveryChain;
    let explorer = RawExplorer::new(Network::Signet).await;
    let provider = esplora_provider(&explorer.url, &[], Network::Signet);
    assert_eq!(provider.verify_network().await, NetworkCheck::Verified);
    explorer.truncate.store(true, Ordering::SeqCst);
    let tx = genesis(Network::Signet).txdata[0].clone();
    assert!(provider.broadcast(&tx).await.is_err());
    explorer.truncate.store(false, Ordering::SeqCst);
    *explorer.network.lock().unwrap() = Network::Bitcoin;
    let error = provider.estimate_fee(6).await.unwrap_err().to_string();
    assert!(error.contains("network mismatch"), "{error}");
}

/// A tip kept by `FreshTip` is not served once its source has refused itself
/// for being on another network: the refusal is latched, the kept header too
/// old a witness.
#[tokio::test]
async fn a_kept_tip_is_dropped_when_its_source_refuses_its_network() {
    let network = Arc::new(Mutex::new(Network::Signet));
    let served = network.clone();
    let fixture = electrum_fixture::Fixture::new(move |request| {
        let network = *served.lock().unwrap();
        let genesis = bitcoin::blockdata::constants::genesis_block(network).header;
        let mut tip = genesis;
        tip.time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        let header = if request["params"][0] == 0 { genesis } else { tip };
        let result = match request["method"].as_str().unwrap() {
            "blockchain.block.header" => json!(bitcoin::consensus::encode::serialize_hex(&header)),
            "blockchain.headers.subscribe" => {
                json!({"height": 101, "hex": bitcoin::consensus::encode::serialize_hex(&tip)})
            }
            "blockchain.estimatefee" => json!(0.00002),
            method => panic!("unexpected method {method}"),
        };
        json!({ "result": result })
    })
    .await;
    let source = Arc::new(
        ElectrumProvider::new(ElectrumConfig {
            server_url: fixture.url.clone(),
            operator: Default::default(),
        })
        .unwrap()
        .with_network(Network::Signet),
    );
    let tip = konsensus_chain::FreshTip::new(
        source.clone(),
        Some(konsensus_chain::tip::TEST_NETWORK_MAX_TIP_AGE),
    );
    assert_eq!(tip.get_block_height().await.unwrap(), 101);
    // The server moves to another network; the next read through the wrapper
    // (a fee estimate, which bypasses the kept tip) latches the refusal.
    *network.lock().unwrap() = Network::Bitcoin;
    assert!(tip.estimate_fee(6).await.unwrap_err().to_string().contains("network mismatch"));
    assert!(source.get_block_height().await.is_err());
    assert!(tip.refusal().is_err());
    assert!(tip.get_block_height().await.is_err(), "the kept tip is not served");
    assert!(!tip.tip_is_fresh().await);
}

// ── Follow-ups: per-endpoint bounds, cache provenance, Electrum latch ───

#[tokio::test]
async fn esplora_cached_height_is_tied_to_the_endpoint_that_served_it() {
    let primary = Explorer::new(Network::Signet).await;
    let fallback = Explorer::new(Network::Signet).await;
    let provider = esplora_provider(&primary.url, &[&fallback.url], Network::Signet);
    // The height comes from the primary.
    assert_eq!(provider.get_block_height().await.unwrap(), 101);
    assert_eq!(primary.tip_requests.load(Ordering::SeqCst), 1);
    // The primary's connection drops (its check ends) and the verified
    // fallback serves the next request, so it is now the endpoint in use.
    primary.stop().await;
    assert_eq!(provider.estimate_fee(6).await.unwrap().sat_per_vbyte, 2.0);
    // The primary returns on mainnet. Its cached height is not served on the
    // strength of the fallback's check: the primary is asked again first.
    primary.restart_on(Network::Bitcoin).await;
    let error = provider.get_block_height().await.unwrap_err().to_string();
    assert!(error.contains("network mismatch"), "{error}");
    assert!(!provider.is_synced_with_height(101).await);
}

#[tokio::test]
async fn electrum_height_check_honours_a_refusal() {
    let network = Arc::new(Mutex::new(Network::Signet));
    let server = electrum_on(Arc::clone(&network)).await;
    let provider = electrum_provider(&server.url, Network::Signet);
    assert_eq!(provider.get_block_height().await.unwrap(), 101);
    assert!(provider.is_synced_with_height(101).await);
    *network.lock().unwrap() = Network::Bitcoin;
    assert!(provider.get_block_height().await.is_err());
    // A height read before the refusal never makes the source synced again.
    assert!(!provider.is_synced_with_height(101).await);
    *network.lock().unwrap() = Network::Signet;
    assert!(!provider.is_synced_with_height(101).await);
}

/// An authenticated transport that never answers.
#[derive(Debug)]
struct SilentTransport;

impl esplora_client::r#async::HttpTransport for SilentTransport {
    fn execute(
        &self,
        _request: reqwest::RequestBuilder,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>>
                + Send
                + '_,
        >,
    > {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn esplora_silent_endpoint_leaves_the_other_answer_in_place() {
    use konsensus_chain::network::{verify_esplora_api_urls, ESPLORA_ENDPOINT_CHECK_TIMEOUT};
    let fallback = Explorer::new(Network::Signet).await;
    let fallback_api = format!("{}/api", fallback.url);
    let urls = ["https://silent-primary.invalid/api", fallback_api.as_str()];
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(
        ESPLORA_ENDPOINT_CHECK_TIMEOUT + std::time::Duration::from_secs(5),
        verify_esplora_api_urls(Network::Signet, &urls, Some(&SilentTransport)),
    )
    .await
    .expect("a silent endpoint is bounded on its own");
    assert_eq!(result.verified, [false, true]);
    assert_eq!(result.check, NetworkCheck::Unavailable);
    // Endpoints are checked side by side: one bound, not one per endpoint.
    assert!(
        started.elapsed() < ESPLORA_ENDPOINT_CHECK_TIMEOUT + std::time::Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
}
