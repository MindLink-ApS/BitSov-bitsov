//! Many-node sandbox simulation: N in-process nodes running the same code,
//! driven by a seeded schedule, checked against network-wide invariants.
//!
//! Every node is the real thing minus its sockets to the outside world: the
//! real session handler (X3DH, self-heal, invoices, acks), the real message
//! handler (payment gate with settlement checks), the real pending flusher,
//! the real outbox reconciler and the real API router, over `price_open` Noise
//! transports on loopback. Money is F1's shared mock Lightning ledger (one
//! SQLite file, regtest invoices, no funds); the chain is a settable mock tip.
//! Nothing here touches mainnet or any network beyond 127.0.0.1.
//!
//! The seed fixes the identities and the schedule (who sends to whom, who
//! flaps, who restarts, which heights each node sees, what the adversaries
//! send). It cannot fix tokio's interleavings, so a failure reproduces as
//! "this schedule", usually but not always the same run.
//!
//! All scenarios are `#[ignore]`: CI time is unchanged. Run them with
//!
//! ```text
//! cargo test -p konsensus-node --bin konsensus sim_many -- --ignored --nocapture --test-threads=1
//! SIM_SEED=7 SIM_NODES=30 SIM_STEPS=8 cargo test -p konsensus-node --bin konsensus sim_many_mesh -- --ignored --nocapture
//! ```
//!
//! Each scenario prints its seed, size and a report; it fails with the list of
//! invariant violations (and the seed to rerun) when any invariant breaks.
//!
//! Findings (see the PR for details; each has a focused, ignored regression):
//! - BUG-SIM-1: one-time prekey offered to every peer until consumed; a node
//!   accepting two first contacts at once builds a mismatched session for the
//!   second, so acked paid messages are unreadable until self-heal
//!   (`sim_many_first_contact_fan_out`, konsensus-crypto
//!   `two_initiators_from_concurrent_offers_both_get_working_sessions`).
//! - The adversarial scenario can fail its "honest traffic still flows"
//!   invariant; that finding is handled through SECURITY.md, not here.
//! - PROCESS_SINGLETON: compose's admission ledger / locks / quote cache are
//!   process-wide and keyed by recipient only, so in-process each recipient
//!   gets one sender (`sim_many_singleton_two_senders_one_recipient`); the
//!   many-to-one shapes run in `scripts/regress/sim_many_nodes.py`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use tokio::sync::{broadcast, mpsc, watch};
use tower::ServiceExt;

use konsensus_core::traits::chain::{BlockHeader, ChainError, ChainProvider, FeeEstimate, TrustLevel};
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::{NodeId, NodeIdentity};
use konsensus_crypto::SessionManager;
use konsensus_lightning::shared_mock::SharedMockProvider;
use konsensus_message::{ControlEvent, Frame, NoiseTransport, PeerRegistry, ReachabilityMode, TransportConfig};

use super::{run as run_session_handler, SessionHandlerDeps};
use crate::msg_handler::{run as run_msg_handler, MsgHandlerDeps};

const JWT_SECRET: &str = "sim-many-nodes-jwt-secret";
const CHAT_MSAT: u64 = 2_000;
/// Routing-fee allowance every compose states per payment
/// (`max_routing_fee_msat`; the shared mock ledger charges no fee).
const ROUTING_FEE_MSAT: u64 = 1_000;
/// Aggregate all-in cap every compose states (`max_total_msat`): the message
/// plus a first-contact admission or a re-admission after a reconnect, each
/// one chat price under static pricing, each with its routing-fee allowance.
/// Compose refuses a payment to a peer without an open session when no cap
/// is given.
const MAX_TOTAL_MSAT: u64 = 3 * (CHAT_MSAT + ROUTING_FEE_MSAT);
const START_BALANCE_MSAT: u64 = 50_000_000;
const BASE_HEIGHT: u64 = 900_000;
/// Longer than compose's own session wait (25 s) plus its ack wait.
const COMPOSE_DEADLINE: Duration = Duration::from_secs(75);

// ── Seeded schedule ──────────────────────────────────────────────────────

/// SplitMix64: tiny, dependency-free, and the same on every platform.
#[derive(Clone)]
struct SimRng(u64);

impl SimRng {
    fn new(seed: u64) -> Self {
        Self(seed ^ 0x5157_4D4E_4F44_4553)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    fn chance(&mut self, p: f64) -> bool {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64 <= p
    }
    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
    fn bytes32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        self.fill(&mut b);
        b
    }
    fn uuid(&mut self) -> String {
        let mut b = [0u8; 16];
        self.fill(&mut b);
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let h = hex::encode(b);
        format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
    }
}

#[derive(Clone, Copy, Debug)]
struct SimConfig {
    seed: u64,
    nodes: usize,
    steps: usize,
    /// Concurrent composes per step.
    per_step: usize,
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn config(nodes: usize, steps: usize, per_step: usize) -> SimConfig {
    let nodes = env_or("SIM_NODES", nodes as u64) as usize;
    SimConfig {
        seed: env_or("SIM_SEED", 1),
        nodes,
        steps: env_or("SIM_STEPS", steps as u64) as usize,
        per_step: env_or("SIM_PER_STEP", per_step.min(nodes / 2).max(1) as u64) as usize,
    }
}

// ── Panics anywhere in the process (node tasks included) ─────────────────

fn panics() -> &'static Mutex<Vec<String>> {
    static PANICS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    static HOOK: OnceLock<()> = OnceLock::new();
    HOOK.get_or_init(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let thread = std::thread::current().name().unwrap_or("?").to_owned();
            panics().lock().unwrap_or_else(|p| p.into_inner()).push(format!("[{thread}] {info}"));
            previous(info);
        }));
    });
    PANICS.get_or_init(|| Mutex::new(Vec::new()))
}

fn panic_mark() -> usize {
    panics().lock().unwrap_or_else(|p| p.into_inner()).len()
}

fn panics_since(mark: usize) -> Vec<String> {
    panics().lock().unwrap_or_else(|p| p.into_inner())[mark..].to_vec()
}

fn quiet_logs() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let level = std::env::var("SIM_LOG").unwrap_or_else(|_| "error".into());
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_env_filter(tracing_subscriber::EnvFilter::new(level))
            .with_test_writer()
            .try_init();
    });
}

// ── A settable chain tip ─────────────────────────────────────────────────

struct SimChain {
    height: AtomicU64,
    inner: konsensus_chain::mock::MockChainProvider,
}

impl SimChain {
    fn new(height: u64) -> Self {
        Self { height: AtomicU64::new(height), inner: konsensus_chain::mock::MockChainProvider::new() }
    }
    fn set(&self, height: u64) {
        self.height.store(height, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl ChainProvider for SimChain {
    fn chain_view(&self) -> konsensus_core::traits::chain::ChainView {
        konsensus_core::traits::chain::ChainView { backend: "mock", trust_level: "simulated", host: None, explorer_default: false }
    }
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::ServerTrust
    }
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        Ok(self.height.load(Ordering::SeqCst))
    }
    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        self.inner.get_block_header(height).await
    }
    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        self.inner.estimate_fee(target_blocks).await
    }
    async fn is_tx_confirmed(&self, txid: &str, min: u32) -> Result<bool, ChainError> {
        self.inner.is_tx_confirmed(txid, min).await
    }
    async fn is_synced(&self) -> bool {
        true
    }
}

// ── What every node delivered to its owner ───────────────────────────────

#[derive(Clone, Debug)]
struct Delivery {
    at: usize,
    sender: NodeId,
    envelope_id: String,
    kind: u16,
    plaintext: Option<String>,
}

type Deliveries = Arc<Mutex<Vec<Delivery>>>;

// ── Nodes ────────────────────────────────────────────────────────────────

struct SimNode {
    idx: usize,
    id: NodeId,
    transport: Arc<NoiseTransport>,
    storage: Arc<dyn konsensus_storage::Storage>,
    sessions: Arc<SessionManager>,
    chain: Arc<SimChain>,
    peer_prices: Arc<konsensus_pricing::PeerPriceCache>,
    router: axum::Router,
    auth: String,
    shutdown: watch::Sender<bool>,
}

fn sim_identity(seed: u64, idx: usize) -> Arc<NodeIdentity> {
    let mut rng = SimRng::new(seed.wrapping_mul(1_000_003).wrapping_add(idx as u64 + 1));
    let mut material = [0u8; 64];
    rng.fill(&mut material);
    Arc::new(NodeIdentity::from_seed(&material).expect("64-byte seed"))
}

fn owner_name(idx: usize) -> String {
    format!("n{idx}")
}

struct Spec<'a> {
    idx: usize,
    identity: Arc<NodeIdentity>,
    ledger: &'a Path,
    data_dir: PathBuf,
    /// File-backed storage + persisted E2EE sessions (for restarts).
    persistent: bool,
    height: u64,
    deliveries: Deliveries,
}

async fn start_node(spec: Spec<'_>) -> SimNode {
    let Spec { idx, identity, ledger, data_dir, persistent, height, deliveries } = spec;
    std::fs::create_dir_all(&data_dir).unwrap();
    let id = *identity.node_id();
    let transport = Arc::new(NoiseTransport::new(
        Arc::clone(&identity),
        TransportConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            admission_mode: ReachabilityMode::PriceOpen,
            capabilities: crate::node::default_advertised_capabilities(false),
            ..Default::default()
        },
    ));
    transport.start_listener().await.unwrap();

    let wallet = Arc::new(SharedMockProvider::new(ledger, &owner_name(idx), START_BALANCE_MSAT).unwrap());
    let lightning: Arc<dyn LightningProvider> = Arc::clone(&wallet) as Arc<dyn LightningProvider>;
    let storage: Arc<dyn konsensus_storage::Storage> = if persistent {
        let path = data_dir.join("node.db");
        Arc::new(konsensus_storage::sqlite::SqliteStorage::open(path.to_str().unwrap()).await.unwrap())
    } else {
        Arc::new(konsensus_storage::sqlite::SqliteStorage::in_memory().await.unwrap())
    };
    let sessions = if persistent {
        let store: Arc<dyn konsensus_crypto::SessionStore> =
            Arc::new(crate::StorageSessionAdapter { storage: Arc::clone(&storage) });
        let sessions = Arc::new(SessionManager::with_store(Arc::clone(&identity), store));
        sessions.restore_sessions().await;
        sessions
    } else {
        Arc::new(SessionManager::new(Arc::clone(&identity)))
    };
    let registry = Arc::new(tokio::sync::RwLock::new(PeerRegistry::new()));
    let audit = Arc::new(konsensus_api::audit::AuditLog::open(data_dir.join("audit.log")).unwrap());
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig {
            chat_msat: CHAT_MSAT,
            ..Default::default()
        }));
    let sim_chain = Arc::new(SimChain::new(height));
    let chain: Arc<dyn ChainProvider> = Arc::clone(&sim_chain) as Arc<dyn ChainProvider>;
    let peer_prices = Arc::new(konsensus_pricing::PeerPriceCache::new());
    let routing = Arc::new(konsensus_routing::RoutingTable::with_defaults());
    let (ws_broadcast, mut ws_rx) = broadcast::channel(1024);
    let (ws_delivery_tx, _) = broadcast::channel(1024);
    let invoice_requests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let send_timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let peer_ln_pubkeys = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let (shutdown, shutdown_rx) = watch::channel(false);
    let front_door = konsensus_api::handlers::front_door::FrontDoorStore::default();
    let content_server = Arc::new(
        crate::content_server::ContentServer::new(crate::content_server::ContentServerConfig {
            content_dir: data_dir.join("pages"),
            ..Default::default()
        })
        .unwrap(),
    );
    let gate = Arc::new(konsensus_core::PaymentGate::with_config(konsensus_core::gate::GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    }));

    let state = Arc::new(konsensus_api::AppState {
        call_hangup_invoice: false,
        starter: Default::default(),
        identity: Arc::clone(&identity),
        storage: Arc::clone(&storage),
        lightning: Arc::clone(&lightning),
        chain: Arc::clone(&chain),
        pricing: Arc::clone(&pricing),
        gate: Arc::clone(&gate),
        peer_registry: Arc::clone(&registry),
        transport: Arc::clone(&transport) as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&sessions),
        jwt_secret: JWT_SECRET.into(),
        auth_challenges: konsensus_api::AuthChallenges::new(),
        pairing: None,
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        has_identity_passphrase: false,
        ws_broadcast: ws_broadcast.clone(),
        ws_delivery_broadcast: ws_delivery_tx.clone(),
        rate_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::new(10_000)),
        mnemonic_reveal_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::mnemonic_reveal_default()),
        audit_log: Arc::clone(&audit),
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::clone(&peer_prices),
        routing: Arc::clone(&routing),
        plaintext_cipher: None,
        send_timestamps: Arc::clone(&send_timestamps),
        invoice_requests: Arc::clone(&invoice_requests),
        data_dir: Some(data_dir.clone()),
        backup_dir: None,
        peer_ln_pubkeys: Arc::clone(&peer_ln_pubkeys),
        lightning_backend: "shared_mock".into(),
        chain_backend: "mock".into(),
        introduction: Default::default(),
        front_door: front_door.clone(),
        sponsor: Default::default(),
        stun_port: None,
        max_call_minutes: 60,
        call_reply_free: false,
        configured_stun_server: None,
        custody_mode: konsensus_api::custody::CustodyMode::LocalSeed,
        call_media: None,
        recovery_dir: None,
        gossip_validator: None,
        file_staging: Default::default(),
        call_devices: Default::default(),
    });

    let span = tracing::info_span!("node", n = idx);
    tokio::spawn(tracing::Instrument::instrument(run_msg_handler(MsgHandlerDeps {
        transport: Arc::clone(&transport),
        call_devices: state.call_devices.clone(),
        call_reply_free: false,
        transport_ack: Arc::clone(&transport),
        storage: Arc::clone(&storage),
        gate,
        pricing: Arc::clone(&pricing),
        lightning: Arc::clone(&lightning),
        chain: Arc::clone(&chain),
        peer_registry: Arc::clone(&registry),
        session_manager: Arc::clone(&sessions),
        nonce_adapter: Arc::new(konsensus_storage::StorageNonceAdapter::new(Arc::clone(&storage))),
        content_server: Some(content_server.clone()),
        front_door: front_door.clone(),
        routing: Arc::clone(&routing),
        identity: Arc::clone(&identity),
        plaintext_cipher: Arc::new(konsensus_crypto::PlaintextCacheCipher::new(identity.aes_key())),
        ws_tx: ws_broadcast.clone(),
        audit_log: Arc::clone(&audit),
        admission_mode: ReachabilityMode::PriceOpen,
        relay_engine: None,
        shutdown_rx: shutdown_rx.clone(),
    }), span.clone()));
    // The real pending flusher (store-and-forward on reconnect).
    let (pending_tx, pending_rx) = mpsc::channel(64);
    tokio::spawn(tracing::Instrument::instrument(crate::pending_handler::run(crate::pending_handler::PendingHandlerDeps {
        identity: Arc::clone(&identity),
        storage: Arc::clone(&storage),
        transport: Arc::clone(&transport) as Arc<dyn MessageTransport>,
        audit_log: Arc::clone(&audit),
        send_timestamps: Arc::clone(&send_timestamps),
        pending_rx,
        shutdown_rx: shutdown_rx.clone(),
    }), span.clone()));
    let (auto_channel_tx, auto_rx) = mpsc::channel(64);
    std::mem::forget(auto_rx);
    tokio::spawn(tracing::Instrument::instrument(run_session_handler(SessionHandlerDeps {
        call_hangup_invoice: false,
        content_server: Some(content_server.clone()),
        front_door: front_door.clone(),
        min_admission_cost_msat: 0,
        privacy: Default::default(),
        peer_exchange_floor: 0,
        transport: Arc::clone(&transport),
        session_manager: Arc::clone(&sessions),
        storage: Arc::clone(&storage),
        our_node_id: id,
        identity: Arc::clone(&identity),
        audit_log: Arc::clone(&audit),
        pricing: Arc::clone(&pricing),
        chain: Arc::clone(&chain),
        peer_prices: Arc::clone(&peer_prices),
        peer_registry: Arc::clone(&registry),
        routing: Arc::clone(&routing),
        gossip_validator: Arc::new(konsensus_gossip::GossipValidator::new(Default::default())),
        send_timestamps,
        lightning: Arc::clone(&lightning),
        lightning_addr: None,
        mock_lightning: true,
        invoice_requests,
        peer_ln_pubkeys: Arc::clone(&peer_ln_pubkeys),
        ws_broadcast,
        ws_delivery_tx,
        pending_tx,
        starter_hub_tx: None,
        starter_newcomer_tx: None,
        auto_channel_tx,
        shutdown_rx: shutdown_rx.clone(),
    }), span.clone()));
    // The outbox reconciler, as `serve` runs it (5 s here instead of 15 s).
    {
        let state = Arc::clone(&state);
        let mut stop = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tokio::select! {
                    _ = tick.tick() => { let _ = konsensus_api::handlers::messages::reconcile_operations(&state).await; }
                    _ = stop.changed() => break,
                }
            }
        });
    }
    // Everything the node hands its owner.
    {
        let mut stop = shutdown_rx;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = ws_rx.recv() => match msg {
                        Ok(msg) => deliveries.lock().unwrap().push(Delivery {
                            at: idx,
                            sender: msg.envelope.sender,
                            envelope_id: msg.envelope.id.to_string(),
                            kind: msg.envelope.kind,
                            plaintext: msg.plaintext.clone(),
                        }),
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            panic!("sim: node {idx} delivery recorder lagged by {n}");
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    _ = stop.changed() => break,
                }
            }
        });
    }

    let token = konsensus_api::auth::create_token(&id.to_hex(), JWT_SECRET, konsensus_api::auth::Scope::all()).unwrap();
    let router = konsensus_api::build_router(state).layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    SimNode {
        idx,
        id,
        transport,
        storage,
        sessions,
        chain: sim_chain,
        peer_prices,
        router,
        auth: format!("Bearer {token}"),
        shutdown,
    }
}

impl SimNode {
    fn addr(&self) -> String {
        self.transport.listen_addr().unwrap().to_string()
    }

    async fn request(&self, method: &str, uri: &str, body: Option<serde_json::Value>) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", &self.auth)
            .header("content-type", "application/json")
            .body(body.map(|b| Body::from(b.to_string())).unwrap_or_else(Body::empty))
            .unwrap();
        let span = tracing::info_span!("node", n = self.idx);
        let response = tracing::Instrument::instrument(self.router.clone().oneshot(request), span).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 22).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
    }

    async fn compose(&self, to: &NodeId, text: &str, operation_id: &str) -> Option<(StatusCode, serde_json::Value)> {
        let body = serde_json::json!({
            "operation_id": operation_id,
            "recipient": to.to_hex(),
            "kind": konsensus_core::kind::KIND_CHAT,
            "plaintext": text,
            "max_routing_fee_msat": ROUTING_FEE_MSAT,
            "max_total_msat": MAX_TOTAL_MSAT,
        });
        tokio::time::timeout(COMPOSE_DEADLINE, self.request("POST", "/api/v1/messages/compose", Some(body))).await.ok()
    }

    fn stop(&self) {
        let _ = self.shutdown.send(true);
        self.transport.shutdown();
    }
}

async fn wait_for<F, Fut>(within: Duration, mut check: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + within;
    loop {
        if check().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── The network ──────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Sent {
    step: usize,
    from: usize,
    to: usize,
    text: String,
    operation_id: String,
    /// None: compose did not return within COMPOSE_DEADLINE.
    status: Option<u16>,
    body: serde_json::Value,
}

impl Sent {
    /// Acked by the recipient (`accepted`). Compose's `delivered` only means
    /// "handed to a connected peer": a later MessageReject turns the operation
    /// into `rejected_retryable` with `delivered: true` still in the body.
    fn ok(&self) -> bool {
        self.status == Some(200) && self.body["accepted"] == true
    }
    /// The node claims the envelope is on its way: acked, or sent and awaiting
    /// its ack past compose's wait. Either must reach the owner exactly once.
    fn claims_delivery(&self) -> bool {
        self.ok() || (self.status == Some(200) && self.body["delivered"] == true && self.body["state"] == "sent")
    }
    /// Money this send's response says it spent (message + any readmission,
    /// or the amount a failure disclosed as settled).
    fn reported_msat(&self) -> u64 {
        let amount = self.body["amount_msat"].as_u64().unwrap_or(0);
        let readmission = self.body["readmission_msat"].as_u64().unwrap_or(0);
        amount + readmission
    }
}

struct Job {
    step: usize,
    from: usize,
    to: usize,
    text: String,
    operation_id: String,
}

struct Net {
    cfg: SimConfig,
    rng: SimRng,
    nodes: Vec<Option<SimNode>>,
    identities: Vec<Arc<NodeIdentity>>,
    data_dirs: Vec<PathBuf>,
    persistent: bool,
    deliveries: Deliveries,
    sent: Vec<Sent>,
    /// Current intended topology (edges that should be up).
    edges: HashSet<(usize, usize)>,
    /// The one node that may pay `r`'s admission in this process (see
    /// `PROCESS_SINGLETON` below): `sender_of[r]`.
    sender_of: Vec<usize>,
    violations: Vec<String>,
    notes: Vec<String>,
    /// Honest composes of the current `run_jobs` call not yet returned. Set
    /// before any compose or chaos future is polled, so chaos can tell
    /// whether it ran while honest traffic was in flight.
    inflight: AtomicUsize,
    _root: tempfile::TempDir,
    started: Instant,
    panic_mark: usize,
}

fn edge(a: usize, b: usize) -> (usize, usize) {
    (a.min(b), a.max(b))
}

/// I1 and the sim-plaintext half of I3 over what every node delivered to its
/// owner. Each sim plaintext is unique, so each observed delivery maps to the
/// one send that carries it; the delivery must be at that send's recipient,
/// from its sender, and counts toward that send's exactly-once budget across
/// ALL nodes (the sender's own copy of what it sent is not a delivery).
/// Returns the violations and how many failed sends were
/// delivered (once, at their recipient).
fn delivery_violations(sent: &[Sent], deliveries: &[Delivery], ids: &[NodeId]) -> (Vec<String>, usize) {
    let sends: HashMap<&str, &Sent> = sent.iter().map(|s| (s.text.as_str(), s)).collect();
    let mut observed: HashMap<&str, usize> = HashMap::new();
    let mut v = Vec::new();

    // I3: nothing the owner sees came from nowhere: every sim plaintext was
    // sent. I1: every observed delivery of a send is at its recipient and
    // from its sender.
    for d in deliveries {
        let Some(p) = d.plaintext.as_deref().filter(|p| p.starts_with("sim:")) else { continue };
        let Some(s) = sends.get(p) else {
            v.push(format!("I3 unsent plaintext delivered at n{}: {p:?}", d.at));
            continue;
        };
        // The sender's node also shows its owner the message it sent.
        if d.at == s.from && d.sender == ids[s.from] {
            continue;
        }
        *observed.entry(p).or_default() += 1;
        if d.at != s.to {
            v.push(format!("I1 recipient: step {} n{}->n{} {p:?} delivered at n{}", s.step, s.from, s.to, d.at));
        }
        if d.sender != ids[s.from] {
            v.push(format!("I1 sender: {p:?} delivered at n{} as from {}, sent by n{}", d.at, d.sender, s.from));
        }
    }

    // I1: a send reported delivered is delivered exactly once network-wide; a
    // failed send at most once.
    let mut failed_but_delivered = 0;
    for s in sent {
        let got = observed.get(s.text.as_str()).copied().unwrap_or(0);
        if s.claims_delivery() && got != 1 {
            let from = ids[s.from];
            let other: Vec<String> = deliveries
                .iter()
                .filter(|d| d.at == s.to && d.sender == from && d.plaintext.as_deref().is_none_or(|p| !p.starts_with("sim:")))
                .map(|d| format!("kind={} plaintext={:?} id={}", d.kind, d.plaintext.as_deref().map(|p| p.chars().take(40).collect::<String>()), d.envelope_id))
                .collect();
            v.push(format!(
                "I1 exactly-once: step {} n{}->n{} {:?} delivered {got} times across all nodes (op {}, message_id {}); other deliveries from sender there: {other:?}",
                s.step, s.from, s.to, s.text, s.operation_id, s.body["message_id"]
            ));
        }
        if !s.claims_delivery() && got > 1 {
            v.push(format!("I1 exactly-once: failed send step {} n{}->n{} {:?} delivered {got} times across all nodes", s.step, s.from, s.to, s.text));
        }
        if !s.claims_delivery() && got == 1 {
            failed_but_delivered += 1;
        }
    }
    (v, failed_but_delivered)
}

/// One settled ledger payment between two sim nodes.
#[derive(Clone, Debug)]
struct Payment {
    payer: usize,
    payee: usize,
    amount: u64,
    hash: String,
}

/// I4 per (payer, payee): every settled payment is explained exactly by what
/// a compose reported. Compose reports `amount_msat` (its message payment
/// plus any first-contact admission) and `readmission_msat`; its message
/// payment is the ledger row with the `payment_hash` it reported. What it
/// reported beyond that payment is an admission or re-admission, and consumes
/// settled payments of exactly that amount; reported money that never settled
/// is a violation, and so is every payment left over. No connection-epoch or
/// other blanket allowance: this in-process sim has no compose cut by a
/// restart (restarts run between steps), so every outcome is known, and a
/// hung compose (already I5) explains nothing either. Returns the violations,
/// the unexplained msat, and how many message payments were found by hash.
fn money_violations(sent: &[Sent], payments: &[Payment]) -> (Vec<String>, u64, usize) {
    type PairLedger<'a> = (Vec<&'a Sent>, Vec<&'a Payment>);
    let mut v = Vec::new();
    let mut unexplained = 0u64;
    let mut by_hash = 0usize;
    let mut pairs: BTreeMap<(usize, usize), PairLedger<'_>> = BTreeMap::new();
    for s in sent {
        pairs.entry((s.from, s.to)).or_default().0.push(s);
    }
    for p in payments {
        pairs.entry((p.payer, p.payee)).or_default().1.push(p);
    }
    for (&(p, r), (sends, rows)) in &pairs {
        let total: u64 = rows.iter().map(|x| x.amount).sum();
        if sends.is_empty() {
            unexplained += total;
            v.push(format!("I4 n{p} paid n{r} {}x/{total} msat but never sent to it", rows.len()));
            continue;
        }
        let cap = sends.len() as u64 * MAX_TOTAL_MSAT;
        if total > cap {
            v.push(format!("I4 over cap n{p}->n{r}: ledger {} payments/{total} msat > {} compose(s) x max_total_msat = {cap}", rows.len(), sends.len()));
        }
        let mut left: Vec<&Payment> = rows.clone();
        let mut admissions: Vec<(&Sent, u64)> = Vec::new();
        for s in sends {
            let reported = s.reported_msat();
            if reported > MAX_TOTAL_MSAT {
                v.push(format!("I4 cap: step {} n{p}->n{r} reported {reported} msat over its max_total_msat {MAX_TOTAL_MSAT}", s.step));
            }
            // A reported message payment must have settled: its money is never
            // reclassified as admission, so unrelated payments cannot stand in.
            let hash = s.body["payment_hash"].as_str().filter(|h| !h.is_empty());
            let message = match hash.map(|h| (h, left.iter().position(|x| x.hash == h))) {
                Some((_, Some(i))) => {
                    by_hash += 1;
                    left.swap_remove(i).amount
                }
                Some((h, None)) => {
                    v.push(format!(
                        "I4 message unsettled: step {} n{p}->n{r} op {} reported message payment {h}, which never settled",
                        s.step, s.operation_id
                    ));
                    continue;
                }
                None => 0,
            };
            match reported.checked_sub(message) {
                Some(0) => {}
                Some(admission) => admissions.push((s, admission)),
                None => v.push(format!(
                    "I4 under-reported: step {} n{p}->n{r} op {} reported {reported} msat, its message payment settled {message}",
                    s.step, s.operation_id
                )),
            }
        }
        left.sort_by_key(|x| std::cmp::Reverse(x.amount));
        for (s, want) in admissions {
            let mut need = want;
            let mut i = 0;
            while need > 0 && i < left.len() {
                if left[i].amount <= need {
                    need -= left.remove(i).amount;
                } else {
                    i += 1;
                }
            }
            if need > 0 {
                v.push(format!(
                    "I4 unsettled: step {} n{p}->n{r} op {} reported {want} msat of admission/re-admission, {need} msat of it has no settled payment",
                    s.step, s.operation_id
                ));
            }
        }
        if !left.is_empty() {
            let extra: u64 = left.iter().map(|x| x.amount).sum();
            unexplained += extra;
            v.push(format!(
                "I4 unexplained n{p}->n{r}: {} payment(s)/{extra} msat match no reported message, admission or re-admission (hashes {:?}; {} sends, {} ok)",
                left.len(),
                left.iter().map(|x| x.hash.chars().take(16).collect::<String>()).collect::<Vec<_>>(),
                sends.len(),
                sends.iter().filter(|s| s.ok()).count()
            ));
        }
    }
    (v, unexplained, by_hash)
}

impl Net {
    async fn start(cfg: SimConfig, persistent: bool) -> Self {
        quiet_logs();
        let panic_mark = panic_mark();
        let root = tempfile::tempdir().unwrap();
        let ledger = root.path().join("ledger.db");
        let deliveries: Deliveries = Default::default();
        let identities: Vec<_> = (0..cfg.nodes).map(|i| sim_identity(cfg.seed, i)).collect();
        let data_dirs: Vec<_> = (0..cfg.nodes).map(|i| root.path().join(format!("node-{i}"))).collect();
        let mut nodes = Vec::new();
        for i in 0..cfg.nodes {
            nodes.push(Some(
                start_node(Spec {
                    idx: i,
                    identity: Arc::clone(&identities[i]),
                    ledger: &ledger,
                    data_dir: data_dirs[i].clone(),
                    persistent,
                    height: BASE_HEIGHT,
                    deliveries: Arc::clone(&deliveries),
                })
                .await,
            ));
        }
        // No admission quote in a node's first second (F1 quarantine).
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        println!("sim: seed={} nodes={} steps={} per_step={} persistent={persistent}", cfg.seed, cfg.nodes, cfg.steps, cfg.per_step);
        let mut rng = SimRng::new(cfg.seed);
        let sender_of: Vec<usize> = (0..cfg.nodes)
            .map(|r| loop {
                let s = rng.below(cfg.nodes);
                if s != r {
                    break s;
                }
            })
            .collect();
        println!("sim: sender_of {:?}", sender_of);
        for (i, ident) in identities.iter().enumerate() {
            println!("sim: n{i} = {}", &ident.node_id().to_hex()[..12]);
        }
        Self {
            cfg,
            rng,
            sender_of,
            nodes,
            identities,
            data_dirs,
            persistent,
            deliveries,
            sent: Vec::new(),
            edges: HashSet::new(),
            violations: Vec::new(),
            notes: Vec::new(),
            inflight: AtomicUsize::new(0),
            _root: root,
            started: Instant::now(),
            panic_mark,
        }
    }

    fn ledger(&self) -> PathBuf {
        self._root.path().join("ledger.db")
    }

    fn node(&self, i: usize) -> &SimNode {
        self.nodes[i].as_ref().expect("node is up")
    }

    fn up(&self, i: usize) -> bool {
        self.nodes[i].is_some()
    }

    fn violation(&mut self, what: String) {
        println!("sim: VIOLATION {what}");
        self.violations.push(what);
    }

    async fn connected(&self, a: usize, b: usize) -> bool {
        self.up(a)
            && self.up(b)
            && self.node(a).transport.is_connected(&self.node(b).id).await
            && self.node(b).transport.is_connected(&self.node(a).id).await
    }

    /// `a` dials `b`; returns whether both sides see the connection.
    async fn dial(&mut self, a: usize, b: usize) -> bool {
        if !self.up(a) || !self.up(b) {
            return false;
        }
        if self.connected(a, b).await {
            self.edges.insert(edge(a, b));
            return true;
        }
        let addr = self.node(b).addr();
        let id_b = self.node(b).id;
        if let Err(e) = self.node(a).transport.connect(&id_b, &addr).await {
            self.notes.push(format!("dial n{a}->n{b} failed: {e}"));
            return false;
        }
        let ok = wait_for(Duration::from_secs(5), || self.connected(a, b)).await;
        if ok {
            self.edges.insert(edge(a, b));
        } else {
            self.notes.push(format!("dial n{a}->n{b}: both sides never saw the connection"));
        }
        ok
    }

    /// Every node's designated sender dials it, and every node dials
    /// `degree` random others.
    async fn mesh(&mut self, degree: usize) {
        let n = self.cfg.nodes;
        for r in 0..n {
            self.dial(self.sender_of[r], r).await;
        }
        for a in 0..n {
            for _ in 0..degree {
                let b = self.rng.below(n);
                if b != a {
                    self.dial(a, b).await;
                }
            }
        }
        println!("sim: mesh up: {} edges in {:.1}s", self.edges.len(), self.started.elapsed().as_secs_f64());
    }

    /// Pick up to `k` (sender_of[r], r) pairs with distinct senders.
    ///
    /// PROCESS_SINGLETON: compose keeps its first-contact admission ledger,
    /// admission locks and quote cache in process-wide statics keyed by the
    /// RECIPIENT only (konsensus-api compose.rs `admission_ledger`,
    /// `admission_locks`, `quote_cache`). One node per process never notices;
    /// two in-process senders to the same recipient share one entry and the
    /// second fails with "cannot re-sign another sender's envelope" (see
    /// `sim_many_singleton_two_senders_one_recipient`). So in-process, each
    /// recipient has exactly one sender. Many-to-one runs as separate
    /// processes: `scripts/regress/sim_many_nodes.py`.
    fn pick_pairs(&mut self, k: usize) -> Vec<(usize, usize)> {
        let n = self.cfg.nodes;
        let mut senders = HashSet::new();
        let mut out = Vec::new();
        let mut tries = 0;
        while out.len() < k && tries < k * 20 {
            tries += 1;
            let b = self.rng.below(n);
            let a = self.sender_of[b];
            if !self.up(a) || !self.up(b) || !senders.insert(a) {
                continue;
            }
            out.push((a, b));
        }
        out
    }

    /// Dial any missing pair and fix each send's text and operation id.
    async fn prepare(&mut self, step: usize, pairs: Vec<(usize, usize)>) -> Vec<Job> {
        for &(a, b) in &pairs {
            if !self.connected(a, b).await {
                self.dial(a, b).await;
            }
        }
        let base = self.sent.len();
        pairs
            .into_iter()
            .enumerate()
            .map(|(k, (a, b))| Job {
                step,
                from: a,
                to: b,
                text: format!("sim:{}:{step}:n{a}>n{b}:{}", self.cfg.seed, base + k),
                operation_id: self.rng.uuid(),
            })
            .collect()
    }

    /// Run every compose concurrently, alongside `chaos`.
    async fn run_jobs(&self, jobs: &[Job], chaos: impl std::future::Future<Output = ()>) -> Vec<Option<(StatusCode, serde_json::Value)>> {
        self.inflight.store(jobs.len(), Ordering::SeqCst);
        let composes = futures::future::join_all(jobs.iter().map(|j| async move {
            let to = self.node(j.to).id;
            let result = self.node(j.from).compose(&to, &j.text, &j.operation_id).await;
            self.inflight.fetch_sub(1, Ordering::SeqCst);
            result
        }));
        let (results, ()) = tokio::join!(composes, chaos);
        results
    }

    fn record(&mut self, jobs: Vec<Job>, results: Vec<Option<(StatusCode, serde_json::Value)>>) {
        for (j, result) in jobs.into_iter().zip(results) {
            let (status, body) = match result {
                Some((s, body)) => (Some(s.as_u16()), body),
                None => (None, serde_json::Value::Null),
            };
            self.sent.push(Sent { step: j.step, from: j.from, to: j.to, text: j.text, operation_id: j.operation_id, status, body });
        }
    }

    /// One step without chaos.
    async fn step_calm(&mut self, step: usize, pairs: Vec<(usize, usize)>) {
        let jobs = self.prepare(step, pairs).await;
        let results = self.run_jobs(&jobs, async {}).await;
        self.record(jobs, results);
    }

    async fn restart(&mut self, i: usize) {
        if let Some(node) = self.nodes[i].take() {
            node.stop();
            let height = node.chain.height.load(Ordering::SeqCst);
            drop(node);
            // Peers notice the drop.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let ledger = self.ledger();
            let fresh = start_node(Spec {
                idx: i,
                identity: Arc::clone(&self.identities[i]),
                ledger: &ledger,
                data_dir: self.data_dirs[i].clone(),
                persistent: self.persistent,
                height,
                deliveries: Arc::clone(&self.deliveries),
            })
            .await;
            self.nodes[i] = Some(fresh);
            tokio::time::sleep(Duration::from_millis(1_100)).await;
            let peers: Vec<_> = self.edges.iter().filter(|(x, y)| *x == i || *y == i).copied().collect();
            for (x, y) in peers {
                let other = if x == i { y } else { x };
                // Wait for the peer to drop the dead connection first.
                let other_sees_gone = {
                    let id = self.identities[i].node_id();
                    let node = self.node(other);
                    wait_for(Duration::from_secs(5), || async { !node.transport.is_connected(id).await }).await
                };
                if !other_sees_gone {
                    self.notes.push(format!("restart n{i}: n{other} still holds the dead connection after 5s"));
                }
                self.dial(i, other).await;
            }
        }
    }

    // ── Invariants ───────────────────────────────────────────────────────

    /// Wait until every sim message that was reported delivered is seen.
    async fn settle(&self, within: Duration) {
        let want: HashSet<(usize, String)> = self.sent.iter().filter(|s| s.claims_delivery()).map(|s| (s.to, s.text.clone())).collect();
        let deliveries = Arc::clone(&self.deliveries);
        wait_for(within, || {
            let got: HashSet<(usize, String)> = deliveries
                .lock()
                .unwrap()
                .iter()
                .filter_map(|d| d.plaintext.clone().map(|p| (d.at, p)))
                .collect();
            let done = want.is_subset(&got);
            async move { done }
        })
        .await;
    }

    /// Ledger rows: (payer, recipient, amount, memo) for every settled payment.
    fn ledger_rows(&self) -> Vec<(String, String, u64, String)> {
        let db = rusqlite::Connection::open(self.ledger()).unwrap();
        let mut stmt = db.prepare("SELECT payer, recipient, amount, memo FROM invoices WHERE payer IS NOT NULL").unwrap();
        stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? as u64, r.get::<_, String>(3)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    /// Settled payments between sim nodes, with their payment hashes.
    fn ledger_payments(&self) -> Vec<Payment> {
        let db = rusqlite::Connection::open(self.ledger()).unwrap();
        let mut stmt = db.prepare("SELECT payer, recipient, amount, hash FROM invoices WHERE payer IS NOT NULL").unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? as u64, r.get::<_, String>(3)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let idx = |name: &str| name.strip_prefix('n').and_then(|x| x.parse().ok());
        rows.into_iter()
            .filter_map(|(payer, payee, amount, hash)| Some(Payment { payer: idx(&payer)?, payee: idx(&payee)?, amount, hash }))
            .collect()
    }

    fn balances(&self) -> BTreeMap<String, i64> {
        let db = rusqlite::Connection::open(self.ledger()).unwrap();
        let mut stmt = db.prepare("SELECT owner, balance FROM accounts").unwrap();
        stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).unwrap().collect::<Result<_, _>>().unwrap()
    }

    /// The network-wide invariants every scenario shares.
    async fn check_common(&mut self, adversarial_ids: &HashSet<String>) {
        self.settle(Duration::from_secs(20)).await;
        // Let late duplicates (resends, reconcile ticks) arrive.
        tokio::time::sleep(Duration::from_secs(6)).await;

        let deliveries = self.deliveries.lock().unwrap().clone();
        let ids: Vec<NodeId> = self.identities.iter().map(|i| *i.node_id()).collect();
        let (mut v, failed_but_delivered) = delivery_violations(&self.sent, &deliveries, &ids);
        for d in &deliveries {
            if adversarial_ids.contains(&d.envelope_id) {
                v.push(format!("I3 adversarial envelope {} (kind {}) reached n{}'s owner", d.envelope_id, d.kind, d.at));
            }
        }

        // I4: money. Balances are conserved; every settled payment between two
        // sim nodes maps exactly to a message, admission or re-admission a
        // send between them reported (`money_violations`), and never more
        // than the sum of those composes' all-in caps.
        let balances = self.balances();
        let total: i64 = balances.values().sum();
        let expected = (self.cfg.nodes as i64) * START_BALANCE_MSAT as i64;
        if total != expected {
            v.push(format!("I4 conservation: ledger holds {total} msat, expected {expected}"));
        }
        for (owner, bal) in &balances {
            if *bal < 0 {
                v.push(format!("I4 negative balance {owner}={bal}"));
            }
        }
        let payments = self.ledger_payments();
        let mut paid: HashMap<(usize, usize), (u64, u64)> = HashMap::new();
        for x in &payments {
            let e = paid.entry((x.payer, x.payee)).or_default();
            e.0 += 1;
            e.1 += x.amount;
        }
        let (money, unexplained, by_hash) = money_violations(&self.sent, &payments);
        v.extend(money);

        // I5: no compose hangs; outbox operations of finished sends are terminal.
        let hung: Vec<_> = self.sent.iter().filter(|s| s.status.is_none()).collect();
        for s in &hung {
            v.push(format!("I5 compose hung >{}s: step {} n{}->n{} op {}", COMPOSE_DEADLINE.as_secs(), s.step, s.from, s.to, s.operation_id));
        }
        let mut stuck = 0;
        for i in 0..self.cfg.nodes {
            if !self.up(i) {
                continue;
            }
            let ops = self.node(i).storage.list_recoverable_operations().await.unwrap_or_default();
            for op in ops {
                if let Some(s) = self.sent.iter().find(|s| s.operation_id == op.operation_id) {
                    if s.ok() || (s.claims_delivery() && op.state != "sent") {
                        stuck += 1;
                        v.push(format!("I5 op {} (n{}->n{}, delivered) still recoverable in state {}", op.operation_id, s.from, s.to, op.state));
                    } else {
                        self.notes.push(format!("op {} (n{}->n{}, failed {:?}) left in state {} attempts={} err={:?}", op.operation_id, s.from, s.to, s.status, op.state, op.attempts, op.last_error));
                    }
                }
            }
        }

        // I0: the run exercised paid traffic: some send was acked, and every
        // acked (sender, recipient) pair settled at least one payment.
        let acked_pairs: HashSet<(usize, usize)> = self.sent.iter().filter(|s| s.ok()).map(|s| (s.from, s.to)).collect();
        if !self.sent.is_empty() && acked_pairs.is_empty() {
            v.push(format!("I0 no paid traffic: none of {} sends was acked", self.sent.len()));
        }
        for &(p, r) in &acked_pairs {
            if paid.get(&(p, r)).is_none_or(|x| x.0 == 0) {
                v.push(format!("I0 n{p}->n{r} acked without a settled payment"));
            }
        }

        // I6: no panics anywhere in the process.
        for p in panics_since(self.panic_mark) {
            v.push(format!("I6 panic: {p}"));
        }

        // Report.
        let ok = self.sent.iter().filter(|s| s.ok()).count();
        let mut statuses: BTreeMap<String, usize> = BTreeMap::new();
        for s in &self.sent {
            let key = match s.status {
                Some(200) if s.ok() => "200 acked".to_owned(),
                Some(200) => format!("200 {}", s.body["state"].as_str().unwrap_or("?")),
                Some(c) => format!("{c} {}", s.body["code"].as_str().or(s.body["error"].as_str()).unwrap_or("").chars().take(60).collect::<String>()),
                None => "hung".into(),
            };
            *statuses.entry(key).or_default() += 1;
        }
        let paid_total: u64 = paid.values().map(|x| x.1).sum();
        println!(
            "sim: report seed={} nodes={} sends={} ok={} failed_but_delivered={failed_but_delivered} payments={} msat_paid={paid_total} message_payments_by_hash={by_hash} unexplained_msat={unexplained} stuck_ops={stuck} runtime={:.1}s",
            self.cfg.seed, self.cfg.nodes, self.sent.len(), ok, paid.values().map(|x| x.0).sum::<u64>(), self.started.elapsed().as_secs_f64()
        );
        println!("sim: outcomes {statuses:?}");
        for note in self.notes.iter().take(40) {
            println!("sim: note {note}");
        }
        for x in v {
            self.violation(x);
        }
    }

    fn finish(self) {
        for node in self.nodes.iter().flatten() {
            node.stop();
        }
        if !self.violations.is_empty() {
            panic!(
                "sim: {} invariant violation(s) (seed={} nodes={} steps={}); rerun with SIM_SEED={} SIM_NODES={} SIM_STEPS={}:\n{}",
                self.violations.len(),
                self.cfg.seed,
                self.cfg.nodes,
                self.cfg.steps,
                self.cfg.seed,
                self.cfg.nodes,
                self.cfg.steps,
                self.violations.iter().take(50).cloned().collect::<Vec<_>>().join("\n")
            );
        }
    }
}

// ── Scenario 1: mesh + paid traffic ──────────────────────────────────────

async fn run_mesh(cfg: SimConfig) {
    let mut net = Net::start(cfg, false).await;
    net.mesh(3).await;
    for step in 0..cfg.steps {
        let pairs = net.pick_pairs(cfg.per_step);
        net.step_calm(step, pairs).await;
        let last = &net.sent[net.sent.len().saturating_sub(cfg.per_step)..];
        println!("sim: step {step}: {} sends, {} ok, t={:.1}s", last.len(), last.iter().filter(|s| s.ok()).count(), net.started.elapsed().as_secs_f64());
    }
    net.check_common(&HashSet::new()).await;
    // Scenario-specific: an honest network with no chaos delivers everything.
    let failed: Vec<_> = net.sent.iter().filter(|s| !s.ok()).map(|s| format!("step {} n{}->n{} {:?} {}", s.step, s.from, s.to, s.status, s.body)).collect();
    for f in failed {
        net.violation(format!("S1 honest send failed without chaos: {f}"));
    }
    net.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "many-node simulation; run explicitly"]
async fn sim_many_mesh_10() {
    run_mesh(config(10, 4, 5)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "many-node simulation; run explicitly"]
async fn sim_many_mesh_30() {
    run_mesh(config(30, 6, 15)).await;
}

// ── Scenario 2: churn (flaps and restarts mid-delivery) ──────────────────

async fn run_churn(cfg: SimConfig, restarts: bool) {
    let mut net = Net::start(cfg, true).await;
    net.mesh(3).await;
    for step in 0..cfg.steps {
        let pairs = net.pick_pairs(cfg.per_step);
        // Chaos: flap some of this step's pairs while their composes run.
        let flaps: Vec<(usize, usize, u64)> =
        {
            let mut out = Vec::new();
            for &(a, b) in &pairs {
                if net.rng.chance(0.3) {
                    out.push((a, b, 20 + net.rng.next() % 1_500));
                }
            }
            out
        };
        let jobs = net.prepare(step, pairs).await;
        let chaos = {
            let net = &net;
            let flaps = flaps.clone();
            async move {
                futures::future::join_all(flaps.into_iter().map(|(a, b, delay)| async move {
                    tokio::time::sleep(Duration::from_millis(delay)).await;
                    let id_b = net.node(b).id;
                    let _ = net.node(a).transport.disconnect(&id_b).await;
                }))
                .await;
            }
        };
        let results = net.run_jobs(&jobs, chaos).await;
        net.record(jobs, results);
        // Re-dial what flapped (a new connection epoch).
        for (a, b, _) in &flaps {
            let ok = wait_for(Duration::from_secs(5), || async { !net.connected(*a, *b).await }).await;
            if !ok {
                net.notes.push(format!("flap n{a}-n{b}: connection did not drop"));
            }
            net.dial(*a, *b).await;
        }
        if restarts && net.rng.chance(0.5) {
            let victim = net.rng.below(cfg.nodes);
            println!("sim: step {step}: restarting n{victim}");
            net.restart(victim).await;
        }
        let last = &net.sent[net.sent.len().saturating_sub(cfg.per_step)..];
        println!(
            "sim: step {step}: {} sends, {} ok, {} flaps, t={:.1}s",
            last.len(),
            last.iter().filter(|s| s.ok()).count(),
            flaps.len(),
            net.started.elapsed().as_secs_f64()
        );
    }
    // After the chaos, a calm round over the same pairs must deliver.
    let pairs = net.pick_pairs(cfg.per_step);
    net.step_calm(cfg.steps, pairs).await;
    let calm: Vec<_> = net.sent.iter().filter(|s| s.step == cfg.steps && !s.ok()).map(|s| format!("n{}->n{} {:?} {}", s.from, s.to, s.status, s.body)).collect();
    net.check_common(&HashSet::new()).await;
    for c in calm {
        net.violation(format!("S2 calm send after churn failed: {c}"));
    }
    net.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "many-node simulation; run explicitly"]
async fn sim_many_churn_flaps_10() {
    run_churn(config(10, 5, 5), false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "many-node simulation; run explicitly"]
async fn sim_many_churn_restarts_10() {
    run_churn(config(10, 6, 5), true).await;
}

// ── Scenario 3: adversarial peers ────────────────────────────────────────

/// A bare transport that only sends what it is told and counts replies.
struct Adversary {
    identity: Arc<NodeIdentity>,
    transport: Arc<NoiseTransport>,
    invoice_responses: Arc<AtomicUsize>,
    /// InvoiceError replies by reason, so the flood can prove which path refused it.
    invoice_refusals: Arc<Mutex<BTreeMap<String, usize>>>,
    other_replies: Arc<AtomicUsize>,
}

fn adversary(seed: u64, k: usize) -> Adversary {
    adversary_at(seed, k, SocketAddr::from(([127, 0, 0, 1], 0)))
}

/// An adversary whose listener, if started, binds `listen_addr`.
fn adversary_at(seed: u64, k: usize, listen_addr: SocketAddr) -> Adversary {
    let identity = sim_identity(seed ^ 0xADD5_0000, 10_000 + k);
    let transport = Arc::new(NoiseTransport::new(
        Arc::clone(&identity),
        TransportConfig {
            listen_addr,
            admission_mode: ReachabilityMode::PriceOpen,
            ..Default::default()
        },
    ));
    let invoice_responses = Arc::new(AtomicUsize::new(0));
    let invoice_refusals: Arc<Mutex<BTreeMap<String, usize>>> = Default::default();
    let other_replies = Arc::new(AtomicUsize::new(0));
    {
        let (t, inv, refused, other) =
            (Arc::clone(&transport), Arc::clone(&invoice_responses), Arc::clone(&invoice_refusals), Arc::clone(&other_replies));
        tokio::spawn(async move {
            while let Some(event) = t.recv_control().await {
                match event {
                    ControlEvent::InvoiceResponseReceived { .. } => {
                        inv.fetch_add(1, Ordering::SeqCst);
                    }
                    ControlEvent::InvoiceErrorReceived { reason, .. } => {
                        *refused.lock().unwrap().entry(reason).or_default() += 1;
                    }
                    _ => {
                        other.fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        });
        let t = Arc::clone(&transport);
        tokio::spawn(async move { while t.recv().await.is_ok() {} });
    }
    Adversary { identity, transport, invoice_responses, invoice_refusals, other_replies }
}

fn signed_envelope(identity: &NodeIdentity, to: NodeId, ciphertext: Vec<u8>, proof: konsensus_core::PaymentProof) -> konsensus_core::UkmEnvelope {
    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        *identity.node_id(),
        konsensus_core::types::Recipient::Node(to),
        ciphertext,
        proof,
    )
    .build();
    let sig = identity.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::Signature::from_ed25519(&sig);
    envelope
}

/// What each adversary does, chosen by the seed.
#[derive(Clone, Copy, Debug)]
enum Attack {
    /// Self-consistent but never-settled proof (unpaid).
    UnpaidProof,
    /// Random hash/preimage that do not match.
    RandomHash,
    /// The same unpaid envelope, many times.
    Replay,
    /// Garbage frame bytes.
    Malformed,
    /// A message with a ciphertext near/over the frame cap.
    Oversized,
    /// RequestInvoice flood of well-formed first-contact quote attempts.
    /// Runs alongside the honest steps from a second loopback source, and
    /// again in its own phase after them from the honest nodes' source (see
    /// `run_adversarial`).
    InvoiceFlood,
}

/// Attacks the step adversaries pick from. `InvoiceFlood` also runs
/// alongside honest traffic, from dedicated flooders (see `run_adversarial`).
const ATTACKS: [Attack; 5] = [Attack::UnpaidProof, Attack::RandomHash, Attack::Replay, Attack::Malformed, Attack::Oversized];

/// The recipient allows one first-contact quote per source address per 10 s
/// window (`admission_quotes.rs`). Waiting this long before the flood phase
/// means the flood's first attempt at each target is quotable.
const QUOTE_WINDOW_WAIT: Duration = Duration::from_secs(11);

/// Frames in one invoice flood (`Attack::InvoiceFlood`).
const FLOOD_FRAMES: usize = 300;

/// Where the concurrent flooders listen: a loopback source other than the
/// honest nodes' 127.0.0.1 (see `run_adversarial`).
const FLOOD_SOURCE: SocketAddr = SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0);

async fn attack(adv: &Adversary, target: &SimNode, kind: Attack, rng: &mut SimRng, ids: &Mutex<HashSet<String>>) -> usize {
    let to = target.id;
    let mut sent = 0;
    match kind {
        Attack::UnpaidProof => {
            for _ in 0..5 {
                let preimage = rng.bytes32();
                let hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(preimage).into();
                let env = signed_envelope(&adv.identity, to, b"unpaid".to_vec(), konsensus_core::PaymentProof::new(hash, preimage, CHAT_MSAT));
                ids.lock().unwrap().insert(env.id.to_string());
                if adv.transport.send_frame(&to, &Frame::Message(Box::new(env))).await.is_ok() { sent += 1; }
            }
        }
        Attack::RandomHash => {
            for _ in 0..5 {
                let env = signed_envelope(&adv.identity, to, b"random".to_vec(), konsensus_core::PaymentProof::new(rng.bytes32(), rng.bytes32(), CHAT_MSAT));
                ids.lock().unwrap().insert(env.id.to_string());
                if adv.transport.send_frame(&to, &Frame::Message(Box::new(env))).await.is_ok() { sent += 1; }
            }
        }
        Attack::Replay => {
            let preimage = rng.bytes32();
            let hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(preimage).into();
            let env = signed_envelope(&adv.identity, to, b"replay".to_vec(), konsensus_core::PaymentProof::new(hash, preimage, CHAT_MSAT));
            ids.lock().unwrap().insert(env.id.to_string());
            for _ in 0..20 {
                if adv.transport.send_frame(&to, &Frame::Message(Box::new(env.clone()))).await.is_ok() { sent += 1; }
            }
        }
        Attack::Malformed => {
            for i in 0..20 {
                let len = 1 + rng.below(4_000);
                let mut junk = vec![0u8; len];
                rng.fill(&mut junk);
                if i % 2 == 0 {
                    // Valid JSON shape, wrong content.
                    junk = format!("{{\"Message\":{{\"id\":\"{}\"}}}}", hex::encode(&junk[..len.min(32)])).into_bytes();
                }
                if adv.transport.send_raw_frame(&to, &junk).await.is_ok() { sent += 1; }
            }
        }
        Attack::Oversized => {
            for size in [60_000usize, 1 << 20, 4 << 20] {
                let mut ct = vec![0u8; size];
                rng.fill(&mut ct);
                let env = signed_envelope(&adv.identity, to, ct, konsensus_core::PaymentProof::new(rng.bytes32(), rng.bytes32(), CHAT_MSAT));
                ids.lock().unwrap().insert(env.id.to_string());
                if adv.transport.send_frame(&to, &Frame::Message(Box::new(env))).await.is_ok() { sent += 1; }
            }
        }
        Attack::InvoiceFlood => {
            // Fresh, well-formed first-contact attempts built the way a real
            // sender builds them, so the flood reaches quoting and its limit.
            use konsensus_core::admission_quote;
            let me = *adv.identity.node_id();
            for _ in 0..FLOOD_FRAMES {
                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                let frame = Frame::RequestInvoice {
                    request_id: admission_quote::request_id(&to, &me, now),
                    amount_msat: CHAT_MSAT,
                    purpose: admission_quote::PURPOSE.into(),
                };
                if adv.transport.send_frame(&to, &frame).await.is_ok() { sent += 1; } else { break; }
            }
        }
    }
    sent
}

async fn run_adversarial(cfg: SimConfig, adversaries: usize) {
    let mut net = Net::start(cfg, false).await;
    net.mesh(3).await;
    let mut advs: Vec<_> = (0..adversaries).map(|k| adversary(cfg.seed, k)).collect();
    let ids: Arc<Mutex<HashSet<String>>> = Default::default();
    // Each adversary connects to a few random honest nodes.
    let mut targets: Vec<Vec<usize>> = Vec::new();
    for adv in &advs {
        let mut t = Vec::new();
        for _ in 0..3 {
            let i = net.rng.below(cfg.nodes);
            let node = net.node(i);
            if adv.transport.connect(&node.id, &node.addr()).await.is_ok() {
                t.push(i);
            }
        }
        targets.push(t);
    }
    // Invoice floods each adversary ran; a flood earns at most one quote.
    let mut floods_by: Vec<usize> = vec![0; adversaries];

    // Concurrent flooders: a valid invoice flood runs during every honest
    // step, from a source address other than the honest nodes'.
    //
    // First-contact quoting is limited per source address, and every
    // in-process node dials from 127.0.0.1, so a flood from 127.0.0.1 would
    // also rate-limit honest first contact (the limit working as designed,
    // not a liveness failure). The flood needs its own source. macOS only
    // configures 127.0.0.1 on lo0 (127.0.0.2.. need an `ifconfig` alias and
    // root), so the second source is the IPv6 loopback ::1. The nodes listen
    // on 127.0.0.1 only, which ::1 cannot reach, so each target dials its
    // flooder instead: the recipient keys the limit on the connection's
    // remote address whichever side dialed, and treats the flooder as an
    // unprivileged stranger either way. Limit: this concurrent flood reaches
    // the recipient over a connection the recipient opened; flooding the
    // listener inbound is covered by the phase after the steps, which shares
    // the honest source and so cannot overlap honest first contact.
    let mut concurrent: Vec<usize> = Vec::new();
    for k in 0..adversaries {
        let c = advs.len();
        let flooder = adversary_at(cfg.seed, adversaries + k, FLOOD_SOURCE);
        let mut t = Vec::new();
        let mut failed = Vec::new();
        match flooder.transport.start_listener().await.map(|()| flooder.transport.listen_addr()) {
            Ok(Some(addr)) if addr.ip() != std::net::IpAddr::from([127, 0, 0, 1]) => {
                let fid = *flooder.identity.node_id();
                let mut seen = HashSet::new();
                for &i in &targets[k] {
                    if !seen.insert(i) {
                        continue;
                    }
                    let node = net.node(i);
                    let ok = node.transport.connect(&fid, &addr.to_string()).await.is_ok()
                        && wait_for(Duration::from_secs(5), || async { flooder.transport.is_connected(&node.id).await }).await;
                    if ok {
                        t.push(i);
                    } else {
                        failed.push(format!("S3 concurrent flood: n{i} could not connect to flooder a{c} at {addr}"));
                    }
                }
            }
            other => failed.push(format!("S3 concurrent flooder a{c} has no listener on a second loopback source ({FLOOD_SOURCE}): {other:?}")),
        }
        for f in failed {
            net.violation(f);
        }
        advs.push(flooder);
        targets.push(t);
        floods_by.push(0);
        concurrent.push(c);
    }

    let mut attack_log: BTreeMap<String, usize> = BTreeMap::new();
    let (mut concurrent_pairs, mut concurrent_frames) = (0usize, 0usize);
    for step in 0..cfg.steps {
        let pairs = net.pick_pairs(cfg.per_step);
        let plan: Vec<(usize, usize, Attack, u64)> = (0..adversaries)
            .flat_map(|k| {
                let t = targets[k].clone();
                let picks: Vec<_> = t.iter().map(|&i| (i, ATTACKS[net.rng.below(ATTACKS.len())], net.rng.next())).collect();
                picks.into_iter().map(move |(i, a, s)| (k, i, a, s))
            })
            .collect();
        let floods: Vec<(usize, usize)> = concurrent.iter().flat_map(|&k| targets[k].iter().map(move |&i| (k, i))).collect();
        let floods: Vec<(usize, usize, u64)> = floods.into_iter().map(|(k, i)| (k, i, net.rng.next())).collect();
        for (_, _, a, _) in &plan {
            *attack_log.entry(format!("{a:?}")).or_default() += 1;
        }
        *attack_log.entry(format!("{:?}", Attack::InvoiceFlood)).or_default() += floods.len();
        let jobs = net.prepare(step, pairs).await;
        // (flooder, target, frames sent, honest composes still in flight when it ended)
        let flood_results: Mutex<Vec<(usize, usize, usize, bool)>> = Mutex::new(Vec::new());
        let chaos = {
            let (net, advs, ids, flood_results) = (&net, &advs, &ids, &flood_results);
            async move {
                let attacks = futures::future::join_all(plan.into_iter().map(|(k, i, a, s)| async move {
                    if !net.up(i) {
                        return;
                    }
                    let mut rng = SimRng::new(s);
                    attack(&advs[k], net.node(i), a, &mut rng, ids).await;
                }));
                let floods = futures::future::join_all(floods.into_iter().map(|(k, i, s)| async move {
                    let mut rng = SimRng::new(s);
                    let sent = attack(&advs[k], net.node(i), Attack::InvoiceFlood, &mut rng, ids).await;
                    // `inflight` only falls during `run_jobs`, so a nonzero
                    // count here means the whole flood ran during honest composes.
                    let overlapped = net.inflight.load(Ordering::SeqCst) > 0;
                    flood_results.lock().unwrap().push((k, i, sent, overlapped));
                }));
                futures::future::join(attacks, floods).await;
            }
        };
        let results = net.run_jobs(&jobs, chaos).await;
        net.record(jobs, results);
        for (k, i, sent, overlapped) in flood_results.into_inner().unwrap() {
            floods_by[k] += 1;
            concurrent_pairs += 1;
            concurrent_frames += sent;
            if sent < FLOOD_FRAMES {
                net.violation(format!("S3 step {step}: concurrent flood a{k}->n{i} sent only {sent} of {FLOOD_FRAMES} frames"));
            }
            if !overlapped {
                net.violation(format!("S3 step {step}: concurrent flood a{k}->n{i} did not overlap the step's honest composes"));
            }
        }
        let last = &net.sent[net.sent.len().saturating_sub(cfg.per_step)..];
        println!("sim: step {step}: {} sends, {} ok, t={:.1}s", last.len(), last.iter().filter(|s| s.ok()).count(), net.started.elapsed().as_secs_f64());
    }
    if concurrent_pairs == 0 {
        net.violation("S3 no invoice flood ran alongside honest traffic (0 concurrent flood pairs)".into());
    }

    // Invoice flood phase from the honest nodes' own source, 127.0.0.1. A
    // flood there overlapping the honest steps would also limit honest first
    // contact from that same address, so it runs here, after the quote window
    // has passed. The step attackers are banned by now for invalid frames, so
    // each one floods its targets under a fresh identity from the same
    // address (identity rotation), all at once.
    tokio::time::sleep(QUOTE_WINDOW_WAIT).await;
    let mut phase: Vec<usize> = Vec::new();
    let mut flooded: HashSet<usize> = HashSet::new();
    let mut flood_plan = Vec::new();
    let mut failed = Vec::new();
    for k in 0..adversaries {
        let p = advs.len();
        let flooder = adversary(cfg.seed, 2 * adversaries + k);
        let mut t = Vec::new();
        for &i in &targets[k] {
            let node = net.node(i);
            match flooder.transport.connect(&node.id, &node.addr()).await {
                Ok(()) => {
                    t.push(i);
                    flooded.insert(i);
                    flood_plan.push((p, i, net.rng.next()));
                }
                Err(e) => failed.push(format!("S3 invoice flood phase: flooder a{p} could not connect to n{i}: {e}")),
            }
        }
        advs.push(flooder);
        floods_by.push(t.len());
        targets.push(t);
        phase.push(p);
    }
    for f in failed {
        net.violation(f);
    }
    let flood_pairs = flood_plan.len();
    *attack_log.entry(format!("{:?}", Attack::InvoiceFlood)).or_default() += flood_pairs;
    let flood_sent: usize = {
        let (net, advs, ids) = (&net, &advs, &ids);
        futures::future::join_all(flood_plan.into_iter().map(|(k, i, s)| async move {
            let mut rng = SimRng::new(s);
            attack(&advs[k], net.node(i), Attack::InvoiceFlood, &mut rng, ids).await
        }))
        .await
        .into_iter()
        .sum()
    };
    // An empty plan must not pass for a flood: the quote and rate-limit
    // checks below need at least one executed pair with its full workload.
    if flood_pairs == 0 {
        net.violation("S3 invoice flood phase executed no flood pair".into());
    }
    if flood_sent < FLOOD_FRAMES * flood_pairs {
        net.violation(format!("S3 invoice flood sent only {flood_sent} of {} frames", FLOOD_FRAMES * flood_pairs));
    }
    // Replies arrive on the adversaries' control channels; wait until they stop.
    let replies = |advs: &[Adversary]| -> usize {
        advs.iter()
            .map(|a| a.invoice_responses.load(Ordering::SeqCst) + a.invoice_refusals.lock().unwrap().values().sum::<usize>())
            .sum()
    };
    let mut seen = replies(&advs);
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let now = replies(&advs);
        if now == seen {
            break;
        }
        seen = now;
    }
    let adv_ids = ids.lock().unwrap().clone();
    net.check_common(&adv_ids).await;
    // S3: honest traffic still flows, including the composes that ran
    // alongside the concurrent flood.
    let failed: Vec<_> = net.sent.iter().filter(|s| !s.ok()).map(|s| format!("step {} n{}->n{} {:?} {}", s.step, s.from, s.to, s.status, s.body)).collect();
    for f in failed {
        net.violation(format!("S3 honest send failed under attack: {f}"));
    }
    // S3: unpaid adversaries got no session, no privilege, no cached prices,
    // and the invoice flood was bounded.
    let (mut quotes, mut rate_limited) = (vec![0usize; advs.len()], vec![0usize; advs.len()]);
    for (k, adv) in advs.iter().enumerate() {
        let aid = *adv.identity.node_id();
        for &i in &targets[k] {
            let node = net.node(i);
            let session = node.sessions.has_session(&aid).await;
            let privileged = node.transport.connected_privileged_peers().await.contains(&aid);
            let prices = node.peer_prices.get_peer_entry(&aid).await.is_some();
            if session {
                net.violation(format!("S3 n{i} formed a session with unpaid adversary a{k}"));
            }
            if privileged {
                net.violation(format!("S3 n{i} privileged unpaid adversary a{k}"));
            }
            if prices {
                net.violation(format!("S3 n{i} cached prices from unpaid adversary a{k}"));
            }
        }
        let inv = adv.invoice_responses.load(Ordering::SeqCst);
        let refused = adv.invoice_refusals.lock().unwrap().clone();
        println!(
            "sim: a{k} targets={:?} floods={} invoice_responses={inv} invoice_refusals={refused:?} other_replies={}",
            targets[k],
            floods_by[k],
            adv.other_replies.load(Ordering::SeqCst)
        );
        quotes[k] = inv;
        rate_limited[k] = refused.get(konsensus_api::invoice_refusal::ADMISSION_RATE_LIMITED).copied().unwrap_or(0);
        // Only floods request invoices. Each flood is FLOOD_FRAMES fresh
        // first-contact attempts from one source in well under the quote
        // window, so a recipient quotes at most once per flood.
        if inv > floods_by[k] {
            net.violation(format!("S3 a{k} got {inv} admission quotes from {} floods", floods_by[k]));
        }
        adv.transport.shutdown();
    }
    // Each flood must reach the real first-contact quote path (a stranger
    // gets one quote) and then the recipient's quote rate limit. A purpose or
    // request id the node does not accept would be refused before either.
    // Both are required unconditionally: a flood that never ran fails above
    // and here, rather than skipping these checks.
    let sum = |group: &[usize], of: &[usize]| -> usize { group.iter().map(|&k| of[k]).sum() };
    let (concurrent_quotes, concurrent_limited) = (sum(&concurrent, &quotes), sum(&concurrent, &rate_limited));
    let (phase_quotes, phase_limited) = (sum(&phase, &quotes), sum(&phase, &rate_limited));
    if concurrent_quotes == 0 {
        net.violation("S3 concurrent invoice flood never reached admission quoting (0 quotes)".into());
    }
    if concurrent_limited == 0 {
        net.violation("S3 concurrent invoice flood never hit the admission quote rate limit (0 rate-limited refusals)".into());
    }
    // The phase flooders share one source address, so each flooded
    // recipient quotes at most once in the whole phase.
    if phase_quotes > flooded.len() {
        net.violation(format!("S3 invoice flood got {phase_quotes} admission quotes from {} recipients", flooded.len()));
    }
    if phase_quotes == 0 {
        net.violation("S3 invoice flood never reached admission quoting (0 quotes)".into());
    }
    if phase_limited == 0 {
        net.violation("S3 invoice flood never hit the admission quote rate limit (0 rate-limited refusals)".into());
    }
    println!(
        "sim: attacks {attack_log:?} concurrent_pairs={concurrent_pairs} concurrent_frames={concurrent_frames} concurrent_quotes={concurrent_quotes} concurrent_rate_limited={concurrent_limited} flood_frames={flood_sent} flooded={} quotes={phase_quotes} rate_limited={phase_limited}",
        flooded.len()
    );
    net.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "many-node simulation; run explicitly"]
async fn sim_many_adversarial_10() {
    run_adversarial(config(10, 4, 5), 3).await;
}

// ── Scenario 4: height skew ──────────────────────────────────────────────

async fn run_skew(cfg: SimConfig) {
    let mut net = Net::start(cfg, false).await;
    // A third of the nodes start at height 0 (unknown tip), the rest skewed.
    let mut zero = HashSet::new();
    for i in 0..cfg.nodes {
        let h = match net.rng.below(3) {
            0 => {
                zero.insert(i);
                0
            }
            1 => BASE_HEIGHT - net.rng.below(50) as u64,
            _ => BASE_HEIGHT + net.rng.below(5_000) as u64,
        };
        net.node(i).chain.set(h);
    }
    net.mesh(3).await;
    for step in 0..cfg.steps {
        // Heights move: some jump far ahead, some fall back, some recover from 0.
        for i in 0..cfg.nodes {
            if net.rng.chance(0.3) {
                let cur = net.node(i).chain.height.load(Ordering::SeqCst);
                let h = match net.rng.below(4) {
                    0 => 0,
                    1 => cur.max(BASE_HEIGHT) + 2_016 + net.rng.below(10_000) as u64,
                    2 => cur.saturating_sub(net.rng.below(200) as u64).max(1),
                    _ => BASE_HEIGHT,
                };
                net.node(i).chain.set(h);
            }
        }
        let pairs = net.pick_pairs(cfg.per_step);
        net.step_calm(step, pairs).await;
        let last = &net.sent[net.sent.len().saturating_sub(cfg.per_step)..];
        println!("sim: step {step}: {} sends, {} ok, t={:.1}s", last.len(), last.iter().filter(|s| s.ok()).count(), net.started.elapsed().as_secs_f64());
    }
    // Calm: once every tip is sane, every pair delivers. This round runs
    // before the common and price checks so they cover its traffic too.
    for i in 0..cfg.nodes {
        net.node(i).chain.set(BASE_HEIGHT + 10_000);
    }
    let pairs = net.pick_pairs(cfg.per_step);
    net.step_calm(cfg.steps, pairs).await;
    let calm: Vec<_> = net.sent.iter().filter(|s| s.step == cfg.steps && !s.ok()).map(|s| format!("n{}->n{} {:?} {}", s.from, s.to, s.status, s.body)).collect();
    net.check_common(&HashSet::new()).await;
    // S4: no node caches a height-0 price table; every ok send paid the
    // recipient's real price (not a stale or skewed one).
    for i in 0..cfg.nodes {
        for (peer, entry) in net.node(i).peer_prices.all_entries().await {
            if entry.block_height == 0 {
                net.violation(format!("S4 n{i} cached a height-0 price table from {peer}"));
            }
        }
    }
    for (payer, recipient, amount, memo) in net.ledger_rows() {
        if amount != CHAT_MSAT {
            net.violation(format!("S4 {payer}->{recipient} paid {amount} msat (price {CHAT_MSAT}) memo={memo:?}"));
        }
    }
    for c in calm {
        net.violation(format!("S4 send after tips recovered failed: {c}"));
    }
    net.finish();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "many-node simulation; run explicitly"]
async fn sim_many_height_skew_10() {
    run_skew(config(10, 4, 5)).await;
}

/// BUG-SIM-1, node level: one hub pays first contact to K peers at once and
/// keeps sending. Every peer with a lower NodeId initiates X3DH from the
/// hub's PrekeyOffer, and every offer carries the SAME one-time prekey
/// (`SessionManager::prekey_bundle` offers `otpks.first()`), so all but the
/// first SessionInit the hub accepts build a mismatched session (the hub's
/// `accept_session` silently runs X3DH without the already-consumed one-time
/// prekey). The hub then fails the peer's ratchet init and drops the session
/// while the peer keeps it. Observable: some composes 502 after the admission
/// settled (no session in 25 s), and messages acked in the 10-25 s before
/// self-heal re-keys reach the owner as `plaintext: None`, never readable.
/// The crypto-level repro is
/// `konsensus-crypto session::tests::two_initiators_from_concurrent_offers_both_get_working_sessions`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "BUG-SIM-1: paid first-contact messages acked as delivered but undecryptable (one-time prekey reuse); still failing"]
async fn sim_many_first_contact_fan_out() {
    let k = env_or("SIM_PAIRS", 6) as usize;
    let cfg = SimConfig { seed: env_or("SIM_SEED", 1), nodes: k + 1, steps: env_or("SIM_STEPS", 3) as usize, per_step: k };
    let mut net = Net::start(cfg, false).await;
    // The hub has the highest NodeId: every spoke initiates X3DH toward it.
    let hub = (0..cfg.nodes).max_by_key(|&i| *net.identities[i].node_id().as_bytes()).unwrap();
    let spokes: Vec<_> = (0..cfg.nodes).filter(|&i| i != hub).collect();
    for &r in &spokes {
        net.sender_of[r] = hub;
        net.dial(hub, r).await;
    }
    for step in 0..cfg.steps {
        let pairs: Vec<_> = spokes.iter().map(|&r| (hub, r)).collect();
        net.step_calm(step, pairs).await;
    }
    net.check_common(&HashSet::new()).await;
    let failed: Vec<_> = net.sent.iter().filter(|s| !s.ok()).map(|s| format!("step {} n{}->n{} {:?} {}", s.step, s.from, s.to, s.status, s.body)).collect();
    for f in failed {
        net.violation(format!("S1 first-contact fan-out send failed: {f}"));
    }
    net.finish();
}

/// PROCESS_SINGLETON, minimal: two senders in ONE process each pay first
/// contact to the same recipient. The second compose finds the first one's
/// settled admission in the process-wide ledger (keyed by recipient only) and
/// fails trying to re-send it. Not reachable with one node per process (the
/// shipped deployment), so ignored: it documents why the in-process sim gives
/// each recipient one sender, and fails the day the ledger is keyed per node.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "documents a process-wide singleton (compose.rs admission_ledger keyed by recipient only); expected to fail"]
async fn sim_many_singleton_two_senders_one_recipient() {
    let cfg = SimConfig { seed: env_or("SIM_SEED", 1), nodes: 3, steps: 1, per_step: 1 };
    let mut net = Net::start(cfg, false).await;
    for a in [0, 1] {
        net.dial(a, 2).await;
    }
    for a in [0, 1] {
        let jobs = net.prepare(0, vec![(a, 2)]).await;
        let results = net.run_jobs(&jobs, async {}).await;
        net.record(jobs, results);
    }
    for s in net.sent.clone() {
        if !s.ok() {
            net.violation(format!("n{}->n{}: {:?} {}", s.from, s.to, s.status, s.body));
        }
    }
    net.finish();
}

/// The delivery oracle itself: a correct run passes, and a missing delivery,
/// a duplicate, a delivery at a node that was not the recipient, a wrong
/// sender and an unsent plaintext each produce a violation.
#[test]
fn sim_delivery_oracle_checks_every_observed_delivery() {
    let ids: Vec<NodeId> = (0..3).map(|i| *sim_identity(7, i).node_id()).collect();
    let send = |from: usize, to: usize, text: &str| Sent {
        step: 0,
        from,
        to,
        text: text.into(),
        operation_id: format!("op-{text}"),
        status: Some(200),
        body: serde_json::json!({"accepted": true, "delivered": true, "state": "acked"}),
    };
    let delivery = |at: usize, sender: usize, text: &str| Delivery {
        at,
        sender: ids[sender],
        envelope_id: format!("env-{text}-{at}"),
        kind: konsensus_core::kind::KIND_CHAT,
        plaintext: Some(text.into()),
    };
    let sent = vec![send(0, 2, "sim:7:0:a"), send(1, 0, "sim:7:0:b")];
    // Each sender's node also shows its owner the sent message.
    let good = vec![delivery(0, 0, "sim:7:0:a"), delivery(2, 0, "sim:7:0:a"), delivery(1, 1, "sim:7:0:b"), delivery(0, 1, "sim:7:0:b")];
    assert_eq!(delivery_violations(&sent, &good, &ids).0, Vec::<String>::new());

    let cases: Vec<(&str, Vec<Delivery>)> = vec![
        ("missing", vec![delivery(2, 0, "sim:7:0:a")]),
        ("duplicate at recipient", [good.clone(), vec![delivery(0, 1, "sim:7:0:b")]].concat()),
        ("also delivered at another node", [good.clone(), vec![delivery(1, 0, "sim:7:0:a")]].concat()),
        ("delivered only at another node", vec![delivery(1, 0, "sim:7:0:a"), delivery(0, 1, "sim:7:0:b")]),
        ("wrong sender", vec![delivery(2, 1, "sim:7:0:a"), delivery(0, 1, "sim:7:0:b")]),
        ("own copy at a node that did not send it", [good.clone(), vec![delivery(1, 1, "sim:7:0:a")]].concat()),
        ("unsent plaintext", [good.clone(), vec![delivery(1, 2, "sim:7:0:z")]].concat()),
    ];
    for (name, observed) in cases {
        let (v, _) = delivery_violations(&sent, &observed, &ids);
        assert!(!v.is_empty(), "{name}: the oracle accepted {observed:?}");
    }
}

/// The money oracle itself: every admission payment maps to an admission or
/// re-admission a compose reported, exactly; an extra one is a violation.
#[test]
fn sim_money_oracle_accounts_for_every_admission_payment() {
    let send = |from: usize, to: usize, amount: u64, readmission: Option<u64>, hash: &str| Sent {
        step: 0,
        from,
        to,
        text: format!("sim:7:0:{hash}"),
        operation_id: format!("op-{hash}"),
        status: Some(200),
        body: serde_json::json!({"accepted": true, "delivered": true, "state": "acked",
            "amount_msat": amount, "readmission_msat": readmission, "payment_hash": hash}),
    };
    let pay = |payer: usize, payee: usize, amount: u64, hash: &str| Payment { payer, payee, amount, hash: hash.into() };
    // First contact (admission + message), then a plain send, then a send
    // after a reconnect (re-admission reported separately).
    let sent = vec![
        send(0, 1, 2 * CHAT_MSAT, None, "m1"),
        send(0, 1, CHAT_MSAT, None, "m2"),
        send(0, 1, CHAT_MSAT, Some(CHAT_MSAT), "m3"),
    ];
    let good = vec![
        pay(0, 1, CHAT_MSAT, "adm1"),
        pay(0, 1, CHAT_MSAT, "m1"),
        pay(0, 1, CHAT_MSAT, "m2"),
        pay(0, 1, CHAT_MSAT, "readm1"),
        pay(0, 1, CHAT_MSAT, "m3"),
    ];
    let (v, unexplained, by_hash) = money_violations(&sent, &good);
    assert_eq!((v, unexplained, by_hash), (Vec::<String>::new(), 0, 3));

    let cases: Vec<(&str, Vec<Sent>, Vec<Payment>)> = vec![
        ("extra admission-sized payment", sent.clone(), [good.clone(), vec![pay(0, 1, CHAT_MSAT, "extra")]].concat()),
        ("message paid twice", sent.clone(), [good.clone(), vec![pay(0, 1, CHAT_MSAT, "m2-again")]].concat()),
        ("reported admission never settled", sent.clone(), good.iter().filter(|p| p.hash != "adm1").cloned().collect()),
        ("payment with no send", sent.clone(), [good.clone(), vec![pay(1, 0, CHAT_MSAT, "back")]].concat()),
        (
            "a reported message hash that never settled, offset by unrelated payments",
            vec![send(0, 1, 2 * CHAT_MSAT, None, "ghost")],
            vec![pay(0, 1, CHAT_MSAT, "u1"), pay(0, 1, CHAT_MSAT, "u2")],
        ),
        (
            "a failed compose that paid but reported nothing",
            [sent.clone(), vec![Sent { status: Some(502), body: serde_json::json!({"accepted": false, "code": 502}), ..send(0, 1, 0, None, "m4") }]].concat(),
            [good.clone(), vec![pay(0, 1, CHAT_MSAT, "adm-of-failed")]].concat(),
        ),
        (
            "a hung compose explains nothing",
            [sent.clone(), vec![Sent { status: None, body: serde_json::Value::Null, ..send(0, 1, 0, None, "m5") }]].concat(),
            [good.clone(), vec![pay(0, 1, CHAT_MSAT, "m5")]].concat(),
        ),
    ];
    for (name, sent, payments) in cases {
        let (v, _, _) = money_violations(&sent, &payments);
        assert!(!v.is_empty(), "{name}: the money oracle accepted {payments:?}");
    }
}

#[test]
fn sim_rng_is_deterministic() {
    let mut a = SimRng::new(42);
    let mut b = SimRng::new(42);
    let xs: Vec<u64> = (0..8).map(|_| a.next()).collect();
    let ys: Vec<u64> = (0..8).map(|_| b.next()).collect();
    assert_eq!(xs, ys);
    assert_eq!(sim_identity(42, 3).node_id(), sim_identity(42, 3).node_id());
    assert_ne!(sim_identity(42, 3).node_id(), sim_identity(42, 4).node_id());
}
