//! Node-level regression for BUG-PSI: a paid first contact settled, but no
//! session formed, because the payer's own P2 gate dropped the handshake
//! frames of the node it had just paid.
//!
//! Unlike `budgeted_reconnect_two_node`, nothing is pre-seeded: every node runs
//! the real session handler (X3DH, self-heal, invoices, acks) and the real
//! message handler (payment gate with settlement checks, promote-on-paid,
//! decrypt), over `price_open` Noise transports on loopback and F1's shared
//! mock Lightning ledger. The payer is driven through its real
//! `POST /api/v1/messages/compose` route.
//!
//! The fix (Atlas CoS, after the Fable 5.1 review): a connection on which WE
//! settled the peer's admission (`Connection::admission_paid`, set before our
//! proof goes out, dying with the connection) accepts the frames that complete
//! the act we paid for: PrekeyOffer, SessionInit, SessionAck, RatchetInit,
//! MessageAck, MessageReject, PriceTable, PriceResponse. Everything else, and
//! everything from an unpaid stranger, is still dropped.
//!
//! The cases follow the review's matrix (numbers in the test names).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use tokio::sync::{broadcast, mpsc, watch};
use tower::ServiceExt;

use konsensus_core::traits::lightning::{LightningProvider, PaymentDirection};
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::{NodeId, NodeIdentity};
use konsensus_crypto::SessionManager;
use konsensus_api::membrane::PrePaymentReason;
use konsensus_lightning::shared_mock::SharedMockProvider;
use konsensus_message::{ControlEvent, Frame, NoiseTransport, PeerRegistry, ReachabilityMode, TransportConfig};

use super::{run as run_session_handler, SessionHandlerDeps};
use crate::msg_handler::{run as run_msg_handler, MsgHandlerDeps};

const JWT_SECRET: &str = "paid-first-contact-regression-jwt-secret";
const CHAT_MSAT: u64 = 2_000;

/// Longest a session may take to form: one self-heal tick (15 s) plus round
/// trips, inside compose's own 25 s session wait.
const SESSION_DEADLINE: Duration = Duration::from_secs(40);

// ── Log capture: what each node's P2 gate dropped ────────────────────────

/// Every log line of this test binary, from the first capture on. Lines name
/// the peer (`peer=<hex>`) and every test uses fresh identities, so each test
/// reads only its own lines.
fn captured() -> &'static Mutex<Vec<String>> {
    static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .with_writer(|| Capture)
            .try_init();
    });
    LINES.get_or_init(|| Mutex::new(Vec::new()))
}

struct Capture;

impl std::io::Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(bytes);
        let mut lines = captured().lock().unwrap_or_else(|p| p.into_inner());
        lines.extend(text.lines().map(str::to_owned));
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A position in the capture, to read only what was logged after it.
fn log_mark() -> usize {
    captured().lock().unwrap_or_else(|p| p.into_inner()).len()
}

/// Lines logged after `from` that contain every needle.
fn logged_since(from: usize, needles: &[&str]) -> Vec<String> {
    let lines = captured().lock().unwrap_or_else(|p| p.into_inner());
    lines[from.min(lines.len())..]
        .iter()
        .filter(|l| needles.iter().all(|n| l.contains(n)))
        .cloned()
        .collect()
}

/// Our P2 gate's refusals so far, by reason. Since #96 a pre-payment refusal
/// is only counted, anonymously (no peer, no frame log line): tests compare
/// these counters before and after, on a node whose unpaid traffic they control.
type Refused = std::collections::BTreeMap<PrePaymentReason, u64>;

fn refused_delta(before: &Refused, after: &Refused, reason: PrePaymentReason) -> u64 {
    after.get(&reason).copied().unwrap_or(0) - before.get(&reason).copied().unwrap_or(0)
}

// ── Nodes ────────────────────────────────────────────────────────────────

/// Which side has the lower NodeId. The lower one initiates X3DH, so the
/// first-contact shapes run with the payer as initiator and as acceptor.
#[derive(Clone, Copy, Debug)]
enum Order {
    PayerLower,
    PayerHigher,
}

fn identities(order: Order) -> (Arc<NodeIdentity>, Arc<NodeIdentity>) {
    let (a, b) = (
        Arc::new(NodeIdentity::generate().unwrap().1),
        Arc::new(NodeIdentity::generate().unwrap().1),
    );
    let a_lower = a.node_id().as_bytes() < b.node_id().as_bytes();
    match (order, a_lower) {
        (Order::PayerLower, true) | (Order::PayerHigher, false) => (a, b),
        _ => (b, a),
    }
}

/// A node's wallet over the shared mock ledger.
#[derive(Clone, Copy)]
enum Wallet {
    Plain,
    /// Drops the connection to the payee right after its first payment
    /// settles, before the admission proof goes out (a flap).
    FlapAfterFirstPayment,
    /// Fails the invoice for the first message (not the admission's) once.
    FailFirstMessageInvoice,
}

struct Faulty {
    wallet: Arc<SharedMockProvider>,
    kind: Wallet,
    transport: Arc<NoiseTransport>,
    peer: Option<NodeId>,
    calls: std::sync::atomic::AtomicUsize,
}

impl Faulty {
    /// `FlapAfterFirstPayment`: drop the payee right after the first payment settles.
    async fn after_payment(&self) {
        if matches!(self.kind, Wallet::FlapAfterFirstPayment)
            && self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
        {
            let _ = self.transport.disconnect(&self.peer.expect("the peer to flap")).await;
        }
    }
}

#[async_trait::async_trait]
impl LightningProvider for Faulty {
    async fn create_invoice(&self, amount: u64, description: &str, expiry: u32)
        -> Result<konsensus_core::traits::lightning::Invoice, konsensus_core::traits::lightning::LightningError>
    {
        // Admissions are stateless quotes; this is the first message's invoice.
        if matches!(self.kind, Wallet::FailFirstMessageInvoice)
            && self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0
        {
            return Err(konsensus_core::traits::lightning::LightningError::Connection("test: invoice failed".into()));
        }
        self.wallet.create_invoice(amount, description, expiry).await
    }
    async fn pay_invoice(&self, bolt11: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>
    {
        let paid = self.wallet.pay_invoice(bolt11).await?;
        self.after_payment().await;
        Ok(paid)
    }
    /// Every payment is fee-limited since #99; the shared mock enforces it.
    async fn pay_invoice_with_fee_limit(&self, bolt11: &str, max_fee_msat: u64)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>
    {
        let paid = self.wallet.pay_invoice_with_fee_limit(bolt11, max_fee_msat).await?;
        self.after_payment().await;
        Ok(paid)
    }
    async fn keysend_with_fee_limit(&self, dest: &str, amount: u64, memo: Option<&str>, max_fee_msat: u64)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>
    {
        let paid = self.wallet.keysend_with_fee_limit(dest, amount, memo, max_fee_msat).await?;
        self.after_payment().await;
        Ok(paid)
    }
    fn routing_fee_policy(&self) -> konsensus_core::traits::lightning::RoutingFeePolicy {
        self.wallet.routing_fee_policy()
    }
    async fn get_payment_status(&self, hash: &str)
        -> Result<konsensus_core::traits::lightning::PaymentDetails, konsensus_core::traits::lightning::LightningError>
    {
        self.wallet.get_payment_status(hash).await
    }
    async fn create_stateless_invoice(&self, amount: u64, description: &str, expiry: u32)
        -> Result<konsensus_core::traits::lightning::Invoice, konsensus_core::traits::lightning::LightningError>
    {
        self.wallet.create_stateless_invoice(amount, description, expiry).await
    }
    async fn get_balance_msat(&self) -> Result<u64, konsensus_core::traits::lightning::LightningError> {
        self.wallet.get_balance_msat().await
    }
    async fn list_payments(&self, limit: u32)
        -> Result<Vec<konsensus_core::traits::lightning::PaymentDetails>, konsensus_core::traits::lightning::LightningError>
    {
        self.wallet.list_payments(limit).await
    }
    async fn get_node_pubkey(&self) -> Option<String> {
        self.wallet.get_node_pubkey().await
    }
    async fn is_available(&self) -> bool {
        true
    }
}

/// The reviewers' scheduling hooks, without touching production code: the
/// payer's API sees its transport through [`Hooked`], which, when armed,
/// suspends the compose task until the test releases it, either right after
/// `mark_admission_paid` (before the proof is built and sent) or right after
/// `admission_paid_on_connection` (after the coverage of a settled proof was
/// read, before it is acted on). It changes no wallet, journal, transport or
/// privilege state.
#[derive(Default)]
struct PauseAfterMark {
    armed: std::sync::atomic::AtomicBool,
    armed_query: std::sync::atomic::AtomicBool,
    armed_eager: std::sync::atomic::AtomicBool,
    armed_page_send: std::sync::atomic::AtomicBool,
    proof_sent: std::sync::atomic::AtomicBool,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl PauseAfterMark {
    fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    /// Pause after the next paid-flag read: the connection used to classify
    /// the proof has been read, nothing has been marked or sent.
    fn arm_after_classification(&self) {
        self.armed_query.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    /// Pause right before the first raw frame written after the admission
    /// proof went out: the payer's eager PrekeyOffer (PSI-SPEED), after its
    /// eligibility was decided and before it is written.
    fn arm_before_eager_offer(&self) {
        self.proof_sent.store(false, std::sync::atomic::Ordering::SeqCst);
        self.armed_eager.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn arm_before_page_send(&self) {
        self.armed_page_send.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    async fn hold_eager(&self) {
        if self.proof_sent.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.hold(&self.armed_eager).await;
        }
    }
    async fn hold(&self, armed: &std::sync::atomic::AtomicBool) {
        if armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.reached.notify_one();
            self.release.notified().await;
        }
    }
    async fn reached(&self) {
        tokio::time::timeout(Duration::from_secs(10), self.reached.notified())
            .await
            .expect("compose reached mark_admission_paid");
    }
    fn release(&self) {
        self.release.notify_one();
    }
}

/// The node's transport as its API sees it: pure delegation, plus the hook.
struct Hooked {
    inner: Arc<NoiseTransport>,
    pause: Arc<PauseAfterMark>,
}

#[async_trait::async_trait]
impl MessageTransport for Hooked {
    async fn send(&self, peer: &NodeId, envelope: &konsensus_core::UkmEnvelope) -> Result<(), konsensus_core::traits::transport::TransportError> {
        if envelope.kind == konsensus_core::kind::KIND_PAGE_REQUEST {
            self.pause.hold(&self.pause.armed_page_send).await;
        }
        self.inner.send(peer, envelope).await
    }
    async fn recv(&self) -> Result<konsensus_core::UkmEnvelope, konsensus_core::traits::transport::TransportError> {
        self.inner.recv().await
    }
    async fn connect(&self, peer: &NodeId, addr: &str) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.connect(peer, addr).await
    }
    async fn disconnect(&self, peer: &NodeId) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.disconnect(peer).await
    }
    async fn is_connected(&self, peer: &NodeId) -> bool {
        self.inner.is_connected(peer).await
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        self.inner.connected_peers().await
    }
    async fn request_peer_exchange(&self, peer: &NodeId) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.request_peer_exchange(peer).await
    }
    async fn send_raw_frame(&self, peer: &NodeId, frame_bytes: &[u8]) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.pause.hold_eager().await;
        self.inner.send_raw_frame(peer, frame_bytes).await
    }
    async fn send_raw_frame_on_paid_connection(
        &self,
        peer: &NodeId,
        since: std::time::Instant,
        frame_bytes: &[u8],
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.pause.hold_eager().await;
        self.inner.send_raw_frame_on_paid_connection(peer, since, frame_bytes).await
    }
    async fn peer_info(&self, peer: &NodeId) -> Option<konsensus_core::traits::transport::ConnectedPeerInfo> {
        self.inner.peer_info(peer).await
    }
    async fn connected_since(&self, peer: &NodeId) -> Option<std::time::Instant> {
        self.inner.connected_since(peer).await
    }
    async fn admission_paid_on_connection(&self, peer: &NodeId) -> bool {
        let paid = self.inner.admission_paid_on_connection(peer).await;
        self.pause.hold(&self.pause.armed_query).await;
        paid
    }
    async fn mark_admission_paid(&self, peer: &NodeId, since: std::time::Instant) {
        self.inner.mark_admission_paid(peer, since).await;
        self.pause.hold(&self.pause.armed).await;
    }
    async fn send_on_connection(
        &self,
        peer: &NodeId,
        since: Option<std::time::Instant>,
        envelope: &konsensus_core::UkmEnvelope,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        let sent = self.inner.send_on_connection(peer, since, envelope).await;
        if sent.is_ok() && self.pause.armed_eager.load(std::sync::atomic::Ordering::SeqCst) {
            self.pause.proof_sent.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        sent
    }
    async fn add_to_whitelist(&self, peer: &NodeId) {
        self.inner.add_to_whitelist(peer).await
    }
    async fn remove_from_whitelist(&self, peer: &NodeId) {
        self.inner.remove_from_whitelist(peer).await
    }
    async fn supervise_peer(&self, peer: &NodeId, addr: &str) {
        self.inner.supervise_peer(peer, addr).await
    }
}

/// One node: real session handler, real message handler, real API router.
struct Node {
    id: NodeId,
    pause: Arc<PauseAfterMark>,
    identity: Arc<NodeIdentity>,
    transport: Arc<NoiseTransport>,
    sessions: Arc<SessionManager>,
    storage: Arc<dyn konsensus_storage::Storage>,
    audit: Arc<konsensus_api::audit::AuditLog>,
    wallet: Arc<SharedMockProvider>,
    routing: Arc<konsensus_routing::RoutingTable>,
    peer_prices: Arc<konsensus_pricing::PeerPriceCache>,
    peer_ln_pubkeys: Arc<tokio::sync::Mutex<HashMap<NodeId, String>>>,
    router: axum::Router,
    auth: String,
    front_door: konsensus_api::handlers::front_door::FrontDoorStore,
    delivered: mpsc::UnboundedReceiver<String>,
    shutdown: watch::Sender<bool>,
    data_dir: PathBuf,
    _dir: Option<tempfile::TempDir>,
}

struct NodeSpec<'a> {
    identity: Arc<NodeIdentity>,
    whitelist: Vec<NodeId>,
    ledger: &'a Path,
    name: &'a str,
    balance_msat: u64,
    wallet: Wallet,
    peer: Option<NodeId>,
    /// Reuse a data dir (a restart keeps the admission journal).
    data_dir: Option<PathBuf>,
}

async fn start_node(spec: NodeSpec<'_>) -> Node {
    let (dir, data_dir) = match spec.data_dir {
        Some(path) => (None, path),
        None => {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().to_path_buf();
            (Some(dir), path)
        }
    };
    let identity = spec.identity;
    let id = *identity.node_id();
    let transport = Arc::new(NoiseTransport::new(
        Arc::clone(&identity),
        TransportConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            admission_mode: ReachabilityMode::PriceOpen,
            whitelist: spec.whitelist,
            capabilities: crate::node::default_advertised_capabilities(false),
            ..Default::default()
        },
    ));
    transport.start_listener().await.unwrap();

    let wallet = Arc::new(SharedMockProvider::new(spec.ledger, spec.name, spec.balance_msat).unwrap());
    let lightning: Arc<dyn LightningProvider> = match spec.wallet {
        Wallet::Plain => Arc::clone(&wallet) as Arc<dyn LightningProvider>,
        kind => Arc::new(Faulty {
            wallet: Arc::clone(&wallet),
            kind,
            transport: Arc::clone(&transport),
            peer: spec.peer,
            calls: Default::default(),
        }),
    };
    let storage: Arc<dyn konsensus_storage::Storage> =
        Arc::new(konsensus_storage::sqlite::SqliteStorage::in_memory().await.unwrap());
    let sessions = Arc::new(SessionManager::new(Arc::clone(&identity)));
    let registry = Arc::new(tokio::sync::RwLock::new(PeerRegistry::new()));
    let audit = Arc::new(konsensus_api::audit::AuditLog::open(data_dir.join(format!("audit-{id}.log"))).unwrap());
    let pricing: Arc<dyn konsensus_core::traits::pricing::PricingEngine> =
        Arc::new(konsensus_pricing::StaticPricingEngine::new(konsensus_pricing::StaticPricingConfig {
            chat_msat: CHAT_MSAT,
            ..Default::default()
        }));
    let chain: Arc<dyn konsensus_core::traits::chain::ChainProvider> =
        Arc::new(konsensus_chain::mock::MockChainProvider::new());
    let peer_prices = Arc::new(konsensus_pricing::PeerPriceCache::new());
    let routing = Arc::new(konsensus_routing::RoutingTable::with_defaults());
    let (ws_broadcast, mut ws_rx) = broadcast::channel(64);
    let (ws_delivery_tx, _) = broadcast::channel(64);
    let invoice_requests = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let send_timestamps = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let peer_ln_pubkeys = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let (shutdown, shutdown_rx) = watch::channel(false);
    let pause = Arc::new(PauseAfterMark::default());
    // Porch: the published card and `data_dir/pages` (browse_two_node).
    let front_door = konsensus_api::handlers::front_door::FrontDoorStore::default();
    let content_server = Arc::new(
        crate::content_server::ContentServer::new(crate::content_server::ContentServerConfig {
            content_dir: data_dir.join("pages"),
            ..Default::default()
        })
        .unwrap(),
    );
    // As a node on a real backend: the gate checks settlement with the wallet,
    // so an unpaid envelope (e.g. the peer's mock-priced profile) promotes nothing.
    let gate = Arc::new(konsensus_core::PaymentGate::with_config(konsensus_core::gate::GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    }));

    let state = Arc::new(konsensus_api::AppState {
        identity: Arc::clone(&identity),
        storage: Arc::clone(&storage),
        lightning: Arc::clone(&lightning),
        chain: Arc::clone(&chain),
        pricing: Arc::clone(&pricing),
        gate: Arc::clone(&gate),
        peer_registry: Arc::clone(&registry),
        transport: Arc::new(Hooked { inner: Arc::clone(&transport), pause: Arc::clone(&pause) }) as Arc<dyn MessageTransport>,
        session_manager: Arc::clone(&sessions),
        jwt_secret: JWT_SECRET.into(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        pairing: None,
        cors_enabled: false,
        operator_probes_enabled: true,
        sensitive_identity_routes_enabled: true,
        has_identity_passphrase: false,
        ws_broadcast: ws_broadcast.clone(),
        ws_delivery_broadcast: ws_delivery_tx.clone(),
        rate_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::new(100)),
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
        // The admission journal lives here, so a restart can recover it.
        data_dir: Some(data_dir.clone()),
        backup_dir: None,
        peer_ln_pubkeys: Arc::clone(&peer_ln_pubkeys),
        lightning_backend: "shared_mock".into(),
        chain_backend: "mock".into(),
        introduction: Default::default(),
        front_door: front_door.clone(),
        sponsor: Default::default(),
        stun_port: None,
        custody_mode: konsensus_api::custody::CustodyMode::LocalSeed,
        gossip_validator: None,
        file_staging: Default::default(),
    });

    tokio::spawn(run_msg_handler(MsgHandlerDeps {
        transport: Arc::clone(&transport),
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
    }));
    // Nothing drains these here: the pending flusher and auto-channel opener
    // are not under test. Leaked so their senders stay open.
    let (pending_tx, pending_rx) = mpsc::channel(64);
    let (auto_channel_tx, auto_rx) = mpsc::channel(64);
    std::mem::forget((pending_rx, auto_rx));
    tokio::spawn(run_session_handler(SessionHandlerDeps {
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
        auto_channel_tx,
        shutdown_rx,
    }));

    // Each decrypted, delivered plaintext, in order.
    let (delivered_tx, delivered) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            match ws_rx.recv().await {
                Ok(msg) => {
                    if let Some(text) = msg.plaintext.clone() {
                        let _ = delivered_tx.send(text);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let token = konsensus_api::auth::create_token(&id.to_hex(), JWT_SECRET, konsensus_api::auth::Scope::all()).unwrap();
    let router = konsensus_api::build_router(state)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    Node {
        id,
        pause,
        identity,
        transport,
        sessions,
        storage,
        audit,
        wallet,
        routing,
        peer_prices,
        peer_ln_pubkeys,
        router,
        auth: format!("Bearer {token}"),
        front_door,
        delivered,
        shutdown,
        data_dir,
        _dir: dir,
    }
}

impl Node {
    fn addr(&self) -> String {
        self.transport.listen_addr().unwrap().to_string()
    }

    async fn post(&self, uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("authorization", &self.auth)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
    }

    /// The owner's uncapped chat to `to`, through the real compose route.
    async fn compose(&self, to: &NodeId, text: &str) -> (StatusCode, serde_json::Value) {
        self.post(
            "/api/v1/messages/compose",
            serde_json::json!({
                "recipient": to.to_hex(),
                "kind": konsensus_core::kind::KIND_CHAT,
                "plaintext": text,
            }),
        )
        .await
    }

    /// Each payment this node made, msat, oldest first.
    async fn paid_out(&self) -> Vec<u64> {
        let mut paid: Vec<_> = self
            .wallet
            .list_payments(100)
            .await
            .unwrap()
            .into_iter()
            .filter(|p| p.direction == PaymentDirection::Outgoing)
            .map(|p| (p.timestamp, p.amount_msat))
            .collect();
        paid.sort();
        paid.into_iter().map(|(_, msat)| msat).collect()
    }

    /// This node's P2 refusals so far, summed over the hourly buckets.
    fn refused(&self) -> Refused {
        let mut total = Refused::new();
        for bucket in self.audit.membrane().pre_payment_refusals().buckets {
            for (reason, n) in bucket.counts {
                *total.entry(reason).or_default() += n;
            }
        }
        total
    }

    /// Fully privileged (whitelisted or promoted by the peer's payment). An
    /// admission WE paid does not count: see `paid_on_connection`.
    async fn privileged(&self, peer: &NodeId) -> bool {
        self.transport.connected_privileged_peers().await.contains(peer)
    }

    async fn paid_on_connection(&self, peer: &NodeId) -> bool {
        self.transport.admission_paid_on_connection(peer).await
    }

    async fn weight(&self, peer: &NodeId) -> f64 {
        self.routing.get_peer_weight(peer).await.unwrap_or(0.0)
    }

    /// The next plaintext this node delivers, and nothing else behind it.
    async fn delivered_once(&mut self, text: &str) {
        let got = tokio::time::timeout(Duration::from_secs(5), self.delivered.recv()).await;
        assert_eq!(got.ok().flatten().as_deref(), Some(text));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(self.delivered.try_recv().is_err(), "{text:?} delivered more than once");
    }

    fn stop(&self) {
        let _ = self.shutdown.send(true);
        self.transport.shutdown();
    }
}

async fn wait_until<F, Fut>(what: &str, within: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting until {what}");
}

/// Who holds whom in their whitelist, and who dials.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// The card path: nobody lists anybody; the payer dials.
    CardOnly,
    /// The launcher `reply` case: the payee listed the payer and dialled it;
    /// the payer did not list the payee.
    ReplyToDialler,
    /// The tester guide's order: the payer listed the payee and dialled it.
    WhitelistedDialler,
}

struct Pair {
    payer: Node,
    payee: Node,
    ledger: tempfile::TempDir,
}

async fn pair(shape: Shape, order: Order, payer_wallet: Wallet, payee_wallet: Wallet) -> Pair {
    let (payer_id, payee_id) = identities(order);
    let (payer_node, payee_node) = (*payer_id.node_id(), *payee_id.node_id());
    let (payer_list, payee_list) = match shape {
        Shape::CardOnly => (vec![], vec![]),
        Shape::ReplyToDialler => (vec![], vec![payer_node]),
        Shape::WhitelistedDialler => (vec![payee_node], vec![]),
    };
    let ledger = tempfile::tempdir().unwrap();
    let ledger_path = ledger.path().join("ledger.db");
    let payer = start_node(NodeSpec {
        identity: payer_id, whitelist: payer_list, ledger: &ledger_path, name: "payer",
        balance_msat: 1_000_000, wallet: payer_wallet, peer: Some(payee_node), data_dir: None,
    })
    .await;
    let payee = start_node(NodeSpec {
        identity: payee_id, whitelist: payee_list, ledger: &ledger_path, name: "payee",
        balance_msat: 0, wallet: payee_wallet, peer: None, data_dir: None,
    })
    .await;
    // The payee issues no admission quote in its first second (F1 quarantine).
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let pair = Pair { payer, payee, ledger };
    pair.dial(shape).await;
    pair
}

impl Pair {
    fn ledger(&self) -> PathBuf {
        self.ledger.path().join("ledger.db")
    }

    async fn dial(&self, shape: Shape) {
        match shape {
            Shape::ReplyToDialler => self.payee.transport.connect(&self.payer.id, &self.payer.addr()).await.unwrap(),
            Shape::CardOnly | Shape::WhitelistedDialler => {
                self.payer.transport.connect(&self.payee.id, &self.payee.addr()).await.unwrap()
            }
        }
        wait_until("both sides see the connection", Duration::from_secs(5), || async {
            self.payer.transport.is_connected(&self.payee.id).await
                && self.payee.transport.is_connected(&self.payer.id).await
        })
        .await;
    }

    /// The payee drops the connection; the payer dials again (card shape).
    async fn flap(&self) {
        self.payee.transport.disconnect(&self.payer.id).await.unwrap();
        wait_until("the payer sees the drop", Duration::from_secs(5), || async {
            !self.payer.transport.is_connected(&self.payee.id).await
        })
        .await;
        self.dial(Shape::CardOnly).await;
    }

    fn stop(&self) {
        self.payer.stop();
        self.payee.stop();
    }
}

/// A bare transport: a stranger that only sends what the test tells it to,
/// and records everything the node sends back.
fn stranger() -> (Arc<NodeIdentity>, Arc<NoiseTransport>) {
    let identity = Arc::new(NodeIdentity::generate().unwrap().1);
    let transport = Arc::new(NoiseTransport::new(
        Arc::clone(&identity),
        TransportConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            admission_mode: ReachabilityMode::PriceOpen,
            ..Default::default()
        },
    ));
    (identity, transport)
}

/// Control events a bare transport received within `window`.
async fn received(transport: &NoiseTransport, window: Duration) -> Vec<ControlEvent> {
    let mut events = Vec::new();
    let deadline = tokio::time::Instant::now() + window;
    while let Ok(Some(event)) = tokio::time::timeout_at(deadline, transport.recv_control()).await {
        events.push(event);
    }
    events
}

// ── 1–3: first contact delivers exactly once, for one admission ──────────

async fn first_contact_delivers_once(shape: Shape, order: Order) {
    let mark = log_mark();
    let mut net = pair(shape, order, Wallet::Plain, Wallet::Plain).await;
    let payee = net.payee.id;

    // Snapshot the payer's refusals the moment our admission is marked paid
    // (the after-mark hook, released at once): the reply-to-dialler payee may
    // offer its prekey before we paid, and that drop is expected.
    net.payer.pause.arm();
    let ((status, body), before) = tokio::join!(net.payer.compose(&payee, "hello"), async {
        net.payer.pause.reached().await;
        let before = net.payer.refused();
        net.payer.pause.release();
        before
    });
    assert_eq!(status, StatusCode::OK, "{shape:?}/{order:?}: {body}");
    assert_eq!(body["delivered"], true, "{body}");
    net.payee.delivered_once("hello").await;
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT, CHAT_MSAT], "one admission + the message");

    // After our admission settled, our gate dropped nothing the payee sent to
    // complete it (the payee is the only peer here).
    let settled = logged_since(mark, &["first-contact admission: settled", &format!("peer={payee}")]);
    assert_eq!(settled.len(), 1, "{shape:?}/{order:?}: one admission settled");
    let after = net.payer.refused();
    for reason in [PrePaymentReason::SessionBeforePayment, PrePaymentReason::DeliveryBeforePayment, PrePaymentReason::PriceBeforePayment] {
        assert_eq!(refused_delta(&before, &after, reason), 0, "{shape:?}/{order:?}: dropped the paid payee's frame ({reason:?})");
    }

    // The session holds: the next message pays the message only.
    let (status, body) = net.payer.compose(&payee, "again").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("again").await;
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT; 3], "no second admission");
    net.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m1_card_only_first_contact_delivers_once_payer_initiates() {
    first_contact_delivers_once(Shape::CardOnly, Order::PayerLower).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m1_card_only_first_contact_delivers_once_payee_initiates() {
    first_contact_delivers_once(Shape::CardOnly, Order::PayerHigher).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m2_reply_to_dialler_first_contact_delivers_once_payer_initiates() {
    first_contact_delivers_once(Shape::ReplyToDialler, Order::PayerLower).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m2_reply_to_dialler_first_contact_delivers_once_payee_initiates() {
    first_contact_delivers_once(Shape::ReplyToDialler, Order::PayerHigher).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m3_whitelisted_dialler_first_contact_delivers_once_payer_initiates() {
    first_contact_delivers_once(Shape::WhitelistedDialler, Order::PayerLower).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m3_whitelisted_dialler_first_contact_delivers_once_payee_initiates() {
    first_contact_delivers_once(Shape::WhitelistedDialler, Order::PayerHigher).await;
}

// ── 4–6, 11: retries ─────────────────────────────────────────────────────

/// 4: the payee's message invoice fails once after the admission settled. A
/// retry on the same connection inside the window pays no second admission.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m4_retry_on_the_same_connection_does_not_repay() {
    let mut net = pair(Shape::CardOnly, Order::PayerHigher, Wallet::Plain, Wallet::FailFirstMessageInvoice).await;
    let payee = net.payee.id;

    let (status, body) = net.payer.compose(&payee, "invoice fails").await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT], "the admission settled once");
    assert!(net.payer.paid_on_connection(&payee).await);

    let (status, body) = net.payer.compose(&payee, "retry").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("retry").await;
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT, CHAT_MSAT], "admission once, then the message");
    net.stop();
}

/// 5: the connection flaps after the admission settled, before its proof went
/// out. The proof never reached the payee, so it is unspent: the retry
/// delivers it on the new connection and pays the message only (Codex review
/// of b424ac5, P1: never pay again on settlement time vs connection time
/// alone). A proof that DID go out on an older connection is covered by m9
/// and the restart tests in `reconnect_recovery_tests.rs`.
async fn retry_after_flap_readmits_once(order: Order) {
    let mark = log_mark();
    let mut net = pair(Shape::CardOnly, order, Wallet::FlapAfterFirstPayment, Wallet::Plain).await;
    let payee = net.payee.id;

    let (status, body) = net.payer.compose(&payee, "lost in the flap").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["amount_msat"], CHAT_MSAT, "the settled admission is disclosed: {body}");
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT]);

    wait_until("the payee sees the drop", Duration::from_secs(5), || async {
        !net.payee.transport.is_connected(&net.payer.id).await
    })
    .await;
    net.dial(Shape::CardOnly).await;
    assert!(!net.payer.paid_on_connection(&payee).await, "a new connection starts unpaid");

    let (status, body) = net.payer.compose(&payee, "retry").await;
    assert_eq!(status, StatusCode::OK, "{order:?}: {body}");
    net.payee.delivered_once("retry").await;
    assert_eq!(
        net.payer.paid_out().await,
        vec![CHAT_MSAT, CHAT_MSAT],
        "the unsent admission proof admits the new connection; then the message"
    );
    assert_eq!(logged_since(mark, &["re-sent already-paid admission envelope", &format!("peer={payee}")]).len(), 1);
    net.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m5_retry_after_flap_readmits_once_payer_initiates() {
    retry_after_flap_readmits_once(Order::PayerLower).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m5_retry_after_flap_readmits_once_payee_initiates() {
    retry_after_flap_readmits_once(Order::PayerHigher).await;
}

// 6 (retry after 15 min on a new connection) takes the same path as 5 — a
// settlement older than the connection — with the TTL lapse covered by the
// sender ledger's unit tests in `compose.rs` (`prior_admission` at the TTL,
// `settled_on_connection`); a 15-minute wall-clock wait is not run here.

/// 11: the payer restarts inside the window after a settled admission whose
/// proof never went out. The journal is recovered with the proof marked
/// unsent, so the new connection is admitted by that proof: nothing is paid
/// twice, and the new connection's first contact delivers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m11_payer_restart_inside_the_window_pays_once_per_connection() {
    let mut net = pair(Shape::CardOnly, Order::PayerHigher, Wallet::FlapAfterFirstPayment, Wallet::Plain).await;
    let payee = net.payee.id;
    let (status, body) = net.payer.compose(&payee, "before the restart").await;
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT]);
    let journal = net.payer.data_dir.join("admission-attempts").join(payee.to_hex());
    assert!(journal.exists(), "the settled admission is journalled");

    // Restart the payer: same identity, same data dir, same wallet.
    net.payer.stop();
    let restarted = start_node(NodeSpec {
        identity: Arc::clone(&net.payer.identity), whitelist: vec![], ledger: &net.ledger(),
        name: "payer", balance_msat: 1_000_000, wallet: Wallet::Plain, peer: None,
        data_dir: Some(net.payer.data_dir.clone()),
    })
    .await;
    let old = std::mem::replace(&mut net.payer, restarted);
    net.payer._dir = old._dir;
    wait_until("the payee sees the old connection go", Duration::from_secs(5), || async {
        !net.payee.transport.is_connected(&net.payer.id).await
    })
    .await;
    net.dial(Shape::CardOnly).await;

    let (status, body) = net.payer.compose(&payee, "after the restart").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("after the restart").await;
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT, CHAT_MSAT], "the one admission, then the message");
    net.stop();
}

// ── 7, 8, 12: nothing for anyone who did not complete a paid act ─────────

/// 7: an unpaid stranger Z on the payer while it pays B. Z's prekey, prices
/// and peer-exchange request are dropped (each counted by the payer's gate,
/// and B's frames are not), Z gets nothing back, and no state is kept for Z.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m7_unpaid_stranger_gets_nothing_while_the_payer_pays_someone_else() {
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    let before = net.payer.refused();
    let (z_identity, z) = stranger();
    let z_id = *z_identity.node_id();
    z.connect(&payer, &net.payer.addr()).await.unwrap();

    let sessions = SessionManager::new(Arc::clone(&z_identity));
    let bundle = serde_json::to_value(sessions.prekey_bundle().await).unwrap();
    let compose = net.payer.compose(&payee, "to B");
    let pester = async {
        for _ in 0..2 {
            z.send_frame(&payer, &Frame::PrekeyOffer { bundle: bundle.clone() }).await.unwrap();
            z.send_frame(&payer, &Frame::PriceTable {
                prices: HashMap::from([("chat".into(), 1)]), block_height: 1, valid_blocks: 10, trust_discount: 0.0,
            }).await.unwrap();
            z.send_frame(&payer, &Frame::PeerExchangeRequest).await.unwrap();
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };
    let ((status, body), ()) = tokio::join!(compose, pester);
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("to B").await;

    // Past one self-heal tick: Z still has nothing.
    let back = received(&z, Duration::from_secs(16)).await;
    assert!(
        !back.iter().any(|e| matches!(
            e,
            ControlEvent::PrekeyOffer { .. } | ControlEvent::SessionInit { .. }
                | ControlEvent::PriceTableReceived { .. } | ControlEvent::PeerExchangeReceived { .. }
        )),
        "the payer answered an unpaid stranger: {back:?}"
    );
    assert!(!net.payer.sessions.has_session(&z_id).await);
    assert!(!net.payer.privileged(&z_id).await && !net.payer.paid_on_connection(&z_id).await);
    assert!(net.payer.peer_prices.get_peer_price(&z_id, 0).await.is_none(), "Z's prices were cached");
    // Exactly Z's frames: two of each, nothing of B's paid exchange.
    let after = net.payer.refused();
    assert_eq!(refused_delta(&before, &after, PrePaymentReason::SessionBeforePayment), 2, "{after:?}");
    assert_eq!(refused_delta(&before, &after, PrePaymentReason::PriceBeforePayment), 2, "{after:?}");
    assert_eq!(refused_delta(&before, &after, PrePaymentReason::PeerExchangeBeforePayment), 2, "{after:?}");
    assert_eq!(refused_delta(&before, &after, PrePaymentReason::DeliveryBeforePayment), 0, "{after:?}");
    z.shutdown();
    net.stop();
}

/// 8: the payee we paid still gets no peer exchange, no Lightning onboarding
/// and no gossip relay out of our payment: those frames stay privileged-only.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m8_paid_payee_gets_no_peer_exchange_lightning_or_gossip() {
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    let (status, body) = net.payer.compose(&payee, "hello").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("hello").await;
    assert!(net.payer.paid_on_connection(&payee).await);

    let before = net.payer.refused();
    let gossip = {
        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            konsensus_core::kind::KIND_CHAT,
            payee,
            konsensus_core::types::Recipient::Node(payer),
            b"gossip".to_vec(),
            konsensus_core::PaymentProof::new([1u8; 32], [2u8; 32], 1),
        )
        .build();
        let sig = net.payee.identity.sign(&envelope.signable_bytes());
        envelope.signature = konsensus_core::Signature::from_ed25519(&sig);
        envelope
    };
    net.payee.transport.send_frame(&payer, &Frame::PeerExchangeRequest).await.unwrap();
    net.payee.transport.send_frame(&payer, &Frame::LightningInfo { ln_pubkey: "02".repeat(33), ln_addr: None }).await.unwrap();
    net.payee.transport.send_frame(&payer, &Frame::Gossip(Box::new(gossip))).await.unwrap();
    wait_until("the payer dropped all three", Duration::from_secs(5), || async {
        let after = net.payer.refused();
        refused_delta(&before, &after, PrePaymentReason::PeerExchangeBeforePayment) == 1
            && refused_delta(&before, &after, PrePaymentReason::LightningInfoBeforePayment) == 1
            && refused_delta(&before, &after, PrePaymentReason::GossipBeforePayment) == 1
    })
    .await;
    assert!(!net.payer.peer_ln_pubkeys.lock().await.contains_key(&payee), "onboarding write from a payee");
    net.stop();
}

/// 12: while the payer composes to X, a stranger Y answers with a forged
/// invoice response and a price table. Y is not promoted, not marked paid,
/// its prices are not cached, and X's first contact is unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m12_a_quote_from_someone_else_is_refused_and_promotes_nothing() {
    let mut net = pair(Shape::CardOnly, Order::PayerHigher, Wallet::Plain, Wallet::Plain).await;
    let (payer, x) = (net.payer.id, net.payee.id);
    let (y_identity, y) = stranger();
    let y_id = *y_identity.node_id();
    y.connect(&payer, &net.payer.addr()).await.unwrap();

    let compose = net.payer.compose(&x, "to X");
    let forge = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let invoice = net.payee.wallet.create_invoice(CHAT_MSAT, "forged", 600).await.unwrap();
        for _ in 0..3 {
            y.send_frame(&payer, &Frame::InvoiceResponse {
                request_id: format!("v1:{x}:{payer}:0:forged"),
                bolt11: invoice.bolt11.clone(),
                payment_hash: invoice.payment_hash.clone(),
            }).await.unwrap();
            y.send_frame(&payer, &Frame::PriceTable {
                prices: HashMap::from([("chat".into(), 1)]), block_height: 1, valid_blocks: 10, trust_discount: 0.0,
            }).await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    };
    let ((status, body), ()) = tokio::join!(compose, forge);
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("to X").await;
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT, CHAT_MSAT], "X's admission + message only");
    assert!(!net.payer.privileged(&y_id).await, "Y promoted");
    assert!(!net.payer.paid_on_connection(&y_id).await, "Y marked paid");
    assert!(net.payer.peer_prices.get_peer_price(&y_id, 0).await.is_none(), "Y's prices were cached");
    y.shutdown();
    net.stop();
}

// ── 9, 10: reconnect and re-admission ────────────────────────────────────

/// 9: after a reconnect the payee's frames are dropped again (no durable
/// admission object) until our re-admission settles on the new connection.
/// 10: then (as after the first admission) the payee's MessageAck reaches us
/// and strengthens its routing weight (`record_success`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn m9_m10_reconnect_needs_readmission_then_acks_count() {
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let (payer, payee) = (net.payer.id, net.payee.id);

    let (status, body) = net.payer.compose(&payee, "first").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("first").await;
    wait_until("the payee's ack strengthens its weight", Duration::from_secs(5), || async {
        net.payer.weight(&payee).await > 0.0
    })
    .await;
    let weight = net.payer.weight(&payee).await;

    // 9. Reconnect: the new connection is unpaid on our side too.
    net.flap().await;
    assert!(!net.payer.paid_on_connection(&payee).await);
    assert!(!net.payer.privileged(&payee).await);
    let before = net.payer.refused();
    let bundle = serde_json::to_value(net.payee.sessions.prekey_bundle().await).unwrap();
    net.payee.transport.send_frame(&payer, &Frame::PrekeyOffer { bundle }).await.unwrap();
    net.payee
        .transport
        .send_frame(&payer, &Frame::MessageAck { id: konsensus_core::types::MessageId::from_bytes([3u8; 32]), duplicate: false })
        .await
        .unwrap();
    wait_until("the payer dropped both", Duration::from_secs(5), || async {
        let after = net.payer.refused();
        refused_delta(&before, &after, PrePaymentReason::SessionBeforePayment) == 1
            && refused_delta(&before, &after, PrePaymentReason::DeliveryBeforePayment) == 1
    })
    .await;
    assert!(net.payer.sessions.can_send(&payee).await, "a dropped frame left the session alone");

    // 10. Re-admission (#86) settles on the new connection; the message is
    //     delivered and its ack counts again.
    let (status, body) = net.payer.compose(&payee, "after the reconnect").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("after the reconnect").await;
    assert!(net.payer.paid_on_connection(&payee).await);
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT; 4], "admission + message, per connection");
    wait_until("the ack after re-admission strengthens its weight", Duration::from_secs(5), || async {
        net.payer.weight(&payee).await > weight
    })
    .await;
    net.stop();
}

// ── POST /peers on a live connection ─────────────────────────────────────

/// The launcher `reply` case, healed by the owner instead of a payment: the
/// payee (listing the payer) dialled, and the payer's owner now adds the payee
/// with `POST /peers`. The live connection is privileged at once, as after a
/// reconnect; the session forms with no payment; the reply pays the message.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn post_peers_whitelist_takes_effect_on_the_live_connection() {
    let mut net = pair(Shape::ReplyToDialler, Order::PayerHigher, Wallet::Plain, Wallet::Plain).await;
    let payee = net.payee.id;
    assert!(!net.payer.privileged(&payee).await, "the payer did not list the payee at connect");

    let (status, body) = net
        .payer
        .post(
            "/api/v1/peers",
            serde_json::json!({ "node_id": payee.to_hex(), "addr": net.payee.addr(), "auto_connect": false }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(net.payer.privileged(&payee).await, "the owner's whitelist add applies to the live connection");

    wait_until("the session forms with no payment", SESSION_DEADLINE, || async {
        net.payer.sessions.can_send(&payee).await
    })
    .await;
    assert!(net.payer.paid_out().await.is_empty());

    let (status, body) = net.payer.compose(&payee, "reply").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("reply").await;
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT], "the message only, no admission");
    net.stop();
}

// ── Codex review of b424ac5 ──────────────────────────────────────────────

/// P1: the connection is replaced between `mark_admission_paid` and the proof
/// send (the reviewer's pause-after-mark hook). The proof is bound to the
/// marked generation, so it is NOT sent on the replacement; the first compose
/// fails with the settled amount disclosed, the unspent proof is kept, and the
/// retry delivers it on the replacement. Outgoing: one admission, one message.
async fn replacement_between_mark_and_send_pays_admission_once(order: Order) {
    let mut net = pair(Shape::CardOnly, order, Wallet::Plain, Wallet::Plain).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    let original = net.payer.transport.connected_since(&payee).await.unwrap();
    net.payer.pause.arm();
    let ((status, body), replacement) = tokio::join!(net.payer.compose(&payee, "first"), async {
        net.payer.pause.reached().await;
        assert!(net.payer.paid_on_connection(&payee).await, "marked before the pause");
        net.flap().await;
        let replacement = net.payer.transport.connected_since(&payee).await.unwrap();
        assert_ne!(original, replacement, "a new generation");
        assert!(!net.payer.paid_on_connection(&payee).await, "the mark died with its connection");
        net.payer.pause.release();
        replacement
    });
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{order:?}: {body}");
    assert_eq!(body["amount_msat"], CHAT_MSAT, "the settled admission is disclosed: {body}");
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT]);
    // Nothing went out on the replacement: the payee has not been admitted on it.
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!net.payee.privileged(&payer).await, "{order:?}: the proof went out on the replacement");

    let (status, body) = net.payer.compose(&payee, "retry").await;
    assert_eq!(status, StatusCode::OK, "{order:?}: {body}");
    assert_eq!(net.payer.transport.connected_since(&payee).await, Some(replacement), "no further reconnect");
    net.payee.delivered_once("retry").await;
    assert!(net.payer.paid_on_connection(&payee).await);
    assert_eq!(
        net.payer.paid_out().await,
        vec![CHAT_MSAT, CHAT_MSAT],
        "{order:?}: exactly one admission plus one message"
    );
    net.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p1_replacement_between_mark_and_send_pays_admission_once_payer_initiates() {
    replacement_between_mark_and_send_pays_admission_once(Order::PayerLower).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p1_replacement_between_mark_and_send_pays_admission_once_payee_initiates() {
    replacement_between_mark_and_send_pays_admission_once(Order::PayerHigher).await;
}

/// A self-signed envelope from `from` to `to` with a zero-amount proof over a
/// preimage it made up: it never paid anything.
fn unpaid_envelope(from: &Node, to: &NodeId, seed: u8) -> konsensus_core::UkmEnvelope {
    use sha2::{Digest, Sha256};
    let preimage = [seed; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        konsensus_core::kind::KIND_CHAT,
        from.id,
        konsensus_core::types::Recipient::Node(*to),
        b"underpaid".to_vec(),
        konsensus_core::PaymentProof::new(hash, preimage, 0),
    )
    .build();
    envelope.signature = konsensus_core::Signature::from_ed25519(&from.identity.sign(&envelope.signable_bytes()));
    envelope
}

/// P2: a payee we paid (bought frames only, never privileged) sends us an
/// unpaid envelope. It gets what any unpaid stranger gets: no rejection
/// record, no MessageReject and no corrective price table. Control: once the
/// owner privileges the payee, the same kind of envelope does get both, which
/// also proves the first one was processed (the handler is in order).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2_paid_payee_gets_no_rejection_or_prices_for_an_unpaid_envelope() {
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    let (status, body) = net.payer.compose(&payee, "hello").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("hello").await;
    assert!(net.payer.paid_on_connection(&payee).await);
    assert!(!net.payer.privileged(&payee).await, "paying does not privilege the payee");
    assert!(net.payee.paid_out().await.is_empty(), "the payee never paid the payer");

    let mark = log_mark();
    let unpaid = unpaid_envelope(&net.payee, &payer, 57);
    net.payee.transport.send(&payer, &unpaid).await.unwrap();
    // The gate logs every rejection, privileged or not: wait until the payer
    // has refused it before privileging the payee for the control.
    let gate_refusals = || logged_since(mark, &["rejected: insufficient payment", &format!("sender={payee}")]).len();
    wait_until("the payer's gate refused the unpaid envelope", Duration::from_secs(5), || async { gate_refusals() == 1 }).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Control: the owner privileges the payee; its next unpaid envelope is answered.
    let (status, body) = net
        .payer
        .post(
            "/api/v1/peers",
            serde_json::json!({ "node_id": payee.to_hex(), "addr": net.payee.addr(), "auto_connect": false }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let control = unpaid_envelope(&net.payee, &payer, 58);
    net.payee.transport.send(&payer, &control).await.unwrap();
    wait_until("the privileged control is answered", Duration::from_secs(5), || async {
        !logged_since(mark, &["sent corrective price table after payment mismatch", &format!("peer={payee}")]).is_empty()
    })
    .await;

    let rejected = logged_since(mark, &["payment gate REJECTED incoming message", &format!("sender={payee}")]);
    assert_eq!(rejected.len(), 1, "only the privileged control is recorded: {rejected:?}");
    let tables = logged_since(mark, &["sent corrective price table after payment mismatch", &format!("peer={payee}")]);
    assert_eq!(tables.len(), 1, "only the privileged control gets prices: {tables:?}");
    let rejects = |id: &konsensus_core::types::MessageId| {
        logged_since(mark, &["message rejected by peer", &format!("peer={payer}"), &format!("msg_id={id}")]).len()
    };
    wait_until("the payee sees the control's MessageReject", Duration::from_secs(5), || async {
        rejects(&control.id) > 0
    })
    .await;
    assert_eq!(rejects(&unpaid.id), 0, "the unpaid envelope from the paid-for payee got a MessageReject");
    net.stop();
}


/// Simulate durable state at reconnect after sixteen minutes, including the
/// generic outbox row written by the old #103. Run the real flusher alongside
/// compose, Noise, settlement gate and recipient storage: only the new
/// generation's admission may arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sixteen_minute_flap_with_legacy_outbox_accepts_only_one_new_admission() {
    use konsensus_core::{PaymentProof, Recipient, Signature, UkmEnvelopeBuilder};
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let payee = net.payee.id;
    let invoice = net.payee.wallet.create_invoice(CHAT_MSAT, "konsensus:admission", 3600).await.unwrap();
    let paid = net.payer.wallet.pay_invoice(&invoice.bolt11).await.unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
    let mut old = UkmEnvelopeBuilder::new(konsensus_core::kind::KIND_CHAT, net.payer.id,
        Recipient::Node(payee), b"konsensus:admission:v1".to_vec(),
        PaymentProof::new(hex::decode(&paid.payment_hash).unwrap().try_into().unwrap(),
            hex::decode(paid.preimage.unwrap()).unwrap().try_into().unwrap(), CHAT_MSAT))
        .timestamp(now.as_millis() as u64 - 960_000).build();
    old.signature = Signature::from_ed25519(&net.payer.identity.sign(&old.signable_bytes()));
    let journal = net.payer.data_dir.join("admission-attempts");
    std::fs::create_dir_all(&journal).unwrap();
    std::fs::write(journal.join(payee.to_hex()), serde_json::to_vec(&serde_json::json!({
        "payment_hash": paid.payment_hash, "amount_msat": CHAT_MSAT, "quote": [0, CHAT_MSAT],
        "envelope": old, "settled_at_unix": now.as_secs() - 960, "proof_delivered": true,
        "original_reservation": null, "message_may_have_dispatched": false
    })).unwrap()).unwrap();
    // Model the write failing or recipient crashing before its commit.
    net.payer.storage.store_message(&old).await.unwrap();
    net.payer.storage.prepare_delivery(&old.id, &payee).await.unwrap();
    net.flap().await;
    let (pending_tx, pending_rx) = mpsc::channel(4);
    let (stop, shutdown_rx) = watch::channel(false);
    let flusher = tokio::spawn(crate::pending_handler::run(crate::pending_handler::PendingHandlerDeps {
        identity: net.payer.identity.clone(), storage: net.payer.storage.clone(),
        transport: net.payer.transport.clone(),
        audit_log: Arc::new(konsensus_api::audit::AuditLog::open(net.payer.data_dir.join("flusher.log")).unwrap()),
        send_timestamps: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        pending_rx, shutdown_rx,
    }));
    pending_tx.send(payee).await.unwrap();
    let (status, body) = net.payer.compose(&payee, "after sixteen minute flap").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("after sixteen minute flap").await;
    wait_until("legacy admission is removed", Duration::from_secs(5), || async {
        net.payer.storage.get_message(&old.id).await.unwrap().is_none()
    }).await;
    assert!(net.payee.storage.get_message(&old.id).await.unwrap().is_none(), "old proof never reached recipient acceptance");
    let received = net.payee.storage.get_messages_for_recipient(&Recipient::Node(payee), 100, None).await.unwrap();
    assert_eq!(received.iter().filter(|e| e.ciphertext == b"konsensus:admission:v1").count(), 1,
        "exactly one admission accepted on the replacement generation");
    let outgoing = net.payer.storage.get_messages_for_recipient(&Recipient::Node(payee), 100, None).await.unwrap();
    assert!(outgoing.iter().all(|e| e.ciphertext != b"konsensus:admission:v1"), "no outgoing marker chats");
    assert!(net.payer.paid_on_connection(&payee).await);
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT; 3], "old settlement, new admission, message");
    stop.send(true).unwrap(); flusher.await.unwrap(); net.stop();
}

// ── PSI-SPEED: first contact without waiting for a self-heal tick ────────

/// First contact used to wait up to one 15 s self-heal tick (about 12 s
/// observed). Now the payee offers its prekey on promotion, the payer offers
/// right after its proof, and answers the payee's offer when the payee is the
/// X3DH initiator.
const FIRST_CONTACT_BUDGET: Duration = Duration::from_secs(2);

/// The paid first contact completes (compose returns delivered) well inside
/// [`FIRST_CONTACT_BUDGET`], paying one admission plus the message. A
/// stranger connected to the payee throughout gets nothing out of it.
async fn first_contact_is_fast(order: Order) {
    let mut net = pair(Shape::CardOnly, order, Wallet::Plain, Wallet::Plain).await;
    let payee = net.payee.id;
    let (z_identity, z) = stranger();
    let z_id = *z_identity.node_id();
    z.connect(&payee, &net.payee.addr()).await.unwrap();
    wait_until("the payee sees the stranger", Duration::from_secs(5), || async {
        net.payee.transport.is_connected(&z_id).await
    })
    .await;

    let started = std::time::Instant::now();
    let (status, body) = net.payer.compose(&payee, "fast").await;
    let elapsed = started.elapsed();
    assert_eq!(status, StatusCode::OK, "{order:?}: {body}");
    assert_eq!(body["delivered"], true, "{body}");
    println!("PSI-SPEED first contact {order:?}: {elapsed:?}");
    assert!(elapsed < FIRST_CONTACT_BUDGET, "{order:?}: first contact took {elapsed:?}");
    net.payee.delivered_once("fast").await;
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT, CHAT_MSAT], "one admission + the message");

    // The stranger, unpaid, got no prekey, handshake or prices.
    let back = received(&z, Duration::from_secs(2)).await;
    assert!(
        !back.iter().any(|e| matches!(
            e,
            ControlEvent::PrekeyOffer { .. } | ControlEvent::SessionInit { .. }
                | ControlEvent::PriceTableReceived { .. } | ControlEvent::PeerExchangeReceived { .. }
        )),
        "the payee answered an unpaid stranger: {back:?}"
    );
    assert!(!net.payee.sessions.has_session(&z_id).await);
    z.shutdown();
    net.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn speed_first_contact_is_fast_payer_initiates() {
    first_contact_is_fast(Order::PayerLower).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn speed_first_contact_is_fast_payee_initiates() {
    first_contact_is_fast(Order::PayerHigher).await;
}

/// A loopback TCP proxy to `upstream` that adds `delay` of latency to every
/// byte coming back from it (order kept) and none to the other direction.
/// Returns its address. Test-only: it sees only Noise ciphertext.
async fn slow_return_proxy(upstream: String, delay: Duration) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let Ok(server) = tokio::net::TcpStream::connect(&upstream).await else { continue };
            let (mut client_rd, mut client_wr) = client.into_split();
            let (mut server_rd, mut server_wr) = server.into_split();
            tokio::spawn(async move { let _ = tokio::io::copy(&mut client_rd, &mut server_wr).await; });
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n) = server_rd.read(&mut buf).await {
                    if n == 0 || tx.send((tokio::time::Instant::now() + delay, buf[..n].to_vec())).is_err() { break; }
                }
            });
            tokio::spawn(async move {
                while let Some((due, bytes)) = rx.recv().await {
                    tokio::time::sleep_until(due).await;
                    if client_wr.write_all(&bytes).await.is_err() { break; }
                }
            });
        }
    });
    addr
}

/// Fable review of #102: in the payer-higher order the payer is the X3DH
/// acceptor. It holds a session (SessionInit received) before its sending
/// chain exists, which needs the payee's RatchetInit a round trip later.
/// Compose must wait until it can SEND, not only until a session exists, or
/// the first compose fails ("session not initialized") after a consumed
/// admission. The payee's bytes to the payer are delayed by 250 ms (a proxy)
/// so that window is always wider than the 50 ms poll: deterministic.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn speed_payer_higher_first_compose_delivers_while_ratchet_init_is_in_flight() {
    let mut net = pair(Shape::CardOnly, Order::PayerHigher, Wallet::Plain, Wallet::Plain).await;
    let payee = net.payee.id;
    // Reconnect through the proxy before anything was paid.
    net.payee.transport.disconnect(&net.payer.id).await.unwrap();
    wait_until("the payer sees the drop", Duration::from_secs(5), || async {
        !net.payer.transport.is_connected(&payee).await
    })
    .await;
    let proxy = slow_return_proxy(net.payee.addr(), Duration::from_millis(250)).await;
    net.payer.transport.connect(&payee, &proxy).await.unwrap();
    wait_until("both sides see the proxied connection", Duration::from_secs(5), || async {
        net.payer.transport.is_connected(&payee).await && net.payee.transport.is_connected(&net.payer.id).await
    })
    .await;

    let (status, body) = net.payer.compose(&payee, "first").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["delivered"], true, "{body}");
    net.payee.delivered_once("first").await;
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT, CHAT_MSAT], "one admission + the message");
    net.stop();
}

/// Codex review of 7af1bc8 (#102 P1): the connection is replaced after the
/// payer's eager PrekeyOffer was found eligible (its proof went out on the
/// paid connection) and before it is written. The offer is bound to the paid
/// generation: it never reaches the unpaid replacement (whose P2 gate at the
/// payee would drop it), and the payee sends nothing there either. The paid
/// connection is gone, so this first contact fails with the settled amount
/// disclosed; the retry pays the replacement's own admission once and delivers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn speed_eager_offer_never_reaches_an_unpaid_replacement() {
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let payee = net.payee.id;
    let original = net.payer.transport.connected_since(&payee).await.unwrap();
    net.payer.pause.arm_before_eager_offer();
    let mark = log_mark();
    let ((status, body), (payee_before, payer_before)) = tokio::join!(net.payer.compose(&payee, "first"), async {
        net.payer.pause.reached().await;
        // Each side's session refusals from here on: an eager offer on the
        // unpaid replacement is refused (and counted) by the other side's gate.
        let before = (net.payee.refused(), net.payer.refused());
        net.flap().await;
        let replacement = net.payer.transport.connected_since(&payee).await.unwrap();
        assert_ne!(original, replacement, "a new generation");
        assert!(!net.payer.paid_on_connection(&payee).await, "the replacement is unpaid");
        net.payer.pause.release();
        before
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let session = PrePaymentReason::SessionBeforePayment;
    assert_eq!(refused_delta(&payee_before, &net.payee.refused(), session), 0, "the payer's eager offer reached the unpaid replacement");
    assert_eq!(refused_delta(&payer_before, &net.payer.refused(), session), 0, "the payee offered on the unpaid replacement");
    assert!(
        logged_since(mark, &["sent PrekeyOffer right after the admission proof", &format!("peer={payee}")]).is_empty(),
        "an eager offer was written after the paid connection was replaced"
    );
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["amount_msat"], CHAT_MSAT, "the settled admission is disclosed: {body}");
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT]);

    let (status, body) = net.payer.compose(&payee, "retry").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("retry").await;
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT; 3], "one admission per admitted connection, plus the message");
    net.stop();
}

/// Codex review of e56d018 (P2): the connection is replaced after a settled,
/// already-delivered proof was classified against it and before the proof is
/// re-sent. The re-send must not mark the replacement paid for a proof that
/// was consumed on the old connection (that would block the admission the
/// replacement needs). It classifies again on the live connection: the proof
/// was consumed, so exactly one more admission is paid and the message goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn p2_replacement_after_classification_readmits_once_and_delivers() {
    let mut net = pair(Shape::CardOnly, Order::PayerHigher, Wallet::Plain, Wallet::FailFirstMessageInvoice).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    let (status, body) = net.payer.compose(&payee, "invoice fails").await;
    assert_ne!(status, StatusCode::OK, "{body}");
    assert_eq!(net.payer.paid_out().await, vec![CHAT_MSAT], "the admission settled once");
    assert!(net.payee.privileged(&payer).await, "the proof was delivered and consumed on the first connection");
    let original = net.payer.transport.connected_since(&payee).await.unwrap();
    // No E2EE session: the retry takes the first-contact path and re-sends the proof.
    net.payer.sessions.remove_session(&payee).await;
    net.payee.sessions.remove_session(&payer).await;

    net.payer.pause.arm_after_classification();
    let ((status, body), replacement) = tokio::join!(net.payer.compose(&payee, "racing retry"), async {
        net.payer.pause.reached().await;
        net.flap().await;
        let replacement = net.payer.transport.connected_since(&payee).await.unwrap();
        assert_ne!(original, replacement, "a new generation");
        assert!(!net.payer.paid_on_connection(&payee).await, "a new connection starts unpaid");
        net.payer.pause.release();
        replacement
    });
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(net.payer.transport.connected_since(&payee).await, Some(replacement), "no further reconnect");
    net.payee.delivered_once("racing retry").await;
    assert!(net.payer.paid_on_connection(&payee).await, "the replacement was paid for on its own");
    assert!(net.payee.privileged(&payer).await, "the replacement was admitted");
    assert_eq!(
        net.payer.paid_out().await,
        vec![CHAT_MSAT; 3],
        "one admission per admitted connection, plus the message"
    );
    net.stop();
}

#[path = "browse_two_node.rs"]
mod browse_two_node;

/// #162: a settled chat promotes this connection, but buys no discovery act.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_exchange_payment_promoted_sender_still_requires_own_quote_and_payment() {
    let mut net = pair(Shape::CardOnly, Order::PayerLower, Wallet::Plain, Wallet::Plain).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    let (status, body) = net.payer.compose(&payee, "promote only for chat").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("promote only for chat").await;
    assert!(net.payee.privileged(&payer).await);
    let before = net.payee.refused();
    let paid = net.payer.paid_out().await;
    net.payer.transport.send_frame(&payee, &Frame::PeerExchangeRequest).await.unwrap();
    wait_until("promoted sender's unpaid discovery refused", Duration::from_secs(5), || async {
        refused_delta(&before, &net.payee.refused(), PrePaymentReason::PeerExchangeBeforePayment) == 1
    }).await;
    assert_eq!(net.payer.paid_out().await, paid);
    net.stop();
}
