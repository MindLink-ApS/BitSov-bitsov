//! Two-node test of a session race after a link drop. The order of events is
//! forced by a relay in the test, not by timing.
//!
//! After a drop both nodes dial. When the higher id's dial finishes first, the
//! lower id answers its offer on that connection: it runs X3DH and writes
//! `SessionInit`. Then the lower id's own dial finishes. Both sides keep the lower
//! id's outbound connection, so the higher id closes the first one without reading
//! the frame. The write succeeded and nothing resends it. The higher id's offer on
//! the surviving connection arrives inside the lower id's negotiation cooldown.
//! Both sides still have a sending chain, so self-heal stays quiet on both.
//!
//! Real pieces: session handler, message handler, supervisor dials, X3DH, Noise
//! and the compose route, all as in production, with the production cooldown and
//! self-heal tick, so these tests take real time. The stand-ins: the shared mock
//! Lightning ledger, and the relay every node-to-node socket goes through.
//!
//! The relay only forwards, holds or closes bytes. It reads the four-byte frame
//! length and never a frame's contents.
//!
//! The assertion is the one a user sees: after the race, within [`RECOVERY_BOUND`],
//! a message from each side is decrypted and delivered by the other.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, watch, Notify};
use tower::ServiceExt;
use tracing::instrument::WithSubscriber;

use konsensus_core::traits::lightning::{LightningProvider, PaymentDirection};
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::{NodeId, NodeIdentity};
use konsensus_crypto::SessionManager;
use konsensus_lightning::shared_mock::SharedMockProvider;
use konsensus_message::{NoiseTransport, PeerRegistry, ReachabilityMode, TransportConfig};

use super::{run as run_session_handler, SessionHandlerDeps};
use crate::msg_handler::{run as run_msg_handler, MsgHandlerDeps};

const JWT_SECRET: &str = "session-race-regression-jwt-secret";
const CHAT_MSAT: u64 = 2_000;

/// The negotiation cooldown, three self-heal ticks and round trips. A node that
/// notices anything at all has room to repair it several times over.
const RECOVERY_BOUND: Duration = Duration::from_secs(60);

/// Long enough past the first X3DH that the cooldown does not throttle the offer
/// on the closing connection. Only a floor: nothing below races against it.
const PAST_COOLDOWN: Duration = Duration::from_secs(11);

/// How long the setup steps may take. These are failure deadlines; the steps
/// themselves wait on events and move on as soon as those happen.
const STEP: Duration = Duration::from_secs(8);

/// Frames a responder writes before it can write anything else: Noise message 2
/// and HelloAck.
const RESPONDER_HANDSHAKE_FRAMES: usize = 2;

// ── The relay ─────────────────────────────────────────────────────────────

/// How a released connection forwards what the responder (dialled side) writes.
#[derive(Clone, Copy, Debug)]
enum Leg {
    Pass,
    /// Forward this many frames, then keep accepting and hold what follows.
    HoldResponderAfter(usize),
}

/// What a connection holds back from the dialler. The responder's writes keep
/// succeeding, as they do when the bytes are on the wire to a socket that is
/// about to close.
#[derive(Default)]
struct Held {
    bytes: Mutex<Vec<u8>>,
    /// Frames forwarded so far, responder to dialler.
    forwarded: Mutex<usize>,
    /// Forward up to this many frames more, then hold again.
    more: Mutex<usize>,
    wake: Notify,
    flush: Notify,
    dialler_write_result: Mutex<Option<bool>>,
}

impl Held {
    fn frame_sizes(&self) -> Vec<usize> {
        let bytes = self.bytes.lock().unwrap();
        let mut sizes = Vec::new();
        let mut at = 0;
        while at + 4 <= bytes.len() {
            let len = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            if at + 4 + len > bytes.len() {
                break;
            }
            sizes.push(len);
            at += 4 + len;
        }
        sizes
    }

    /// Forward the next `frames` held frames, in order, and hold what follows.
    fn forward_more(&self, frames: usize) {
        *self.more.lock().unwrap() += frames;
        self.wake.notify_one();
    }
}

struct Relay {
    addr: SocketAddr,
    target: SocketAddr,
    gated: Arc<AtomicBool>,
    pending: Arc<Mutex<VecDeque<TcpStream>>>,
    legs: Arc<Mutex<Vec<tokio::task::AbortHandle>>>,
    arrived: Arc<Notify>,
}

impl Relay {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let relay = Self {
            addr,
            target,
            gated: Arc::new(AtomicBool::new(false)),
            pending: Arc::new(Mutex::new(VecDeque::new())),
            legs: Arc::new(Mutex::new(Vec::new())),
            arrived: Arc::new(Notify::new()),
        };
        let (gated, pending, legs, arrived) = (
            Arc::clone(&relay.gated),
            Arc::clone(&relay.pending),
            Arc::clone(&relay.legs),
            Arc::clone(&relay.arrived),
        );
        tokio::spawn(async move {
            while let Ok((dialler, _)) = listener.accept().await {
                if gated.load(Ordering::SeqCst) {
                    pending.lock().unwrap().push_back(dialler);
                    arrived.notify_waiters();
                } else {
                    connect_leg(dialler, target, Leg::Pass, &legs).await;
                }
            }
        });
        relay
    }

    fn gate(&self, on: bool) {
        self.gated.store(on, Ordering::SeqCst);
    }

    /// The link drops: every live connection through this relay closes.
    fn cut(&self) {
        for leg in self.legs.lock().unwrap().drain(..) {
            leg.abort();
        }
    }

    async fn wait_for_dial(&self, who: &str) {
        wait_until(&format!("{who}'s dial reaches the relay"), STEP, || async {
            !self.pending.lock().unwrap().is_empty()
        })
        .await;
    }

    /// Let the oldest held dial through.
    async fn release(&self, leg: Leg) -> Arc<Held> {
        let dialler = self.pending.lock().unwrap().pop_front().expect("a held dial");
        connect_leg(dialler, self.target, leg, &self.legs).await
    }
}

async fn connect_leg(
    dialler: TcpStream,
    target: SocketAddr,
    leg: Leg,
    legs: &Mutex<Vec<tokio::task::AbortHandle>>,
) -> Arc<Held> {
    let held = Arc::new(Held::default());
    let responder = TcpStream::connect(target).await.unwrap();
    let (mut from_dialler, mut to_dialler) = dialler.into_split();
    let (mut from_responder, mut to_responder) = responder.into_split();

    let forward = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut from_dialler, &mut to_responder).await;
        let _ = to_responder.shutdown().await;
    });
    let back = {
        let held = Arc::clone(&held);
        tokio::spawn(async move {
            match leg {
                Leg::Pass => {
                    let _ = tokio::io::copy(&mut from_responder, &mut to_dialler).await;
                    let _ = to_dialler.shutdown().await;
                }
                Leg::HoldResponderAfter(frames) => {
                    *held.more.lock().unwrap() = frames;
                    pump_with_hold(&mut from_responder, &mut to_dialler, &held).await;
                }
            }
        })
    };
    let mut legs = legs.lock().unwrap();
    legs.push(forward.abort_handle());
    legs.push(back.abort_handle());
    held
}

/// Forward whole frames while `more` allows, buffer the rest, and on `flush` write
/// the buffer to the dialler. No end of stream reaches the dialler before that.
async fn pump_with_hold(
    from_responder: &mut tokio::net::tcp::OwnedReadHalf,
    to_dialler: &mut tokio::net::tcp::OwnedWriteHalf,
    held: &Held,
) {
    let mut chunk = [0u8; 16 * 1024];
    let mut responder_open = true;
    loop {
        let wanted = {
            let bytes = held.bytes.lock().unwrap();
            *held.more.lock().unwrap() > 0 && whole_frame_len(&bytes).is_some()
        };
        if wanted {
            let frame = {
                let mut bytes = held.bytes.lock().unwrap();
                let len = whole_frame_len(&bytes).expect("checked above");
                bytes.drain(..len).collect::<Vec<u8>>()
            };
            let _ = to_dialler.write_all(&frame).await;
            *held.more.lock().unwrap() -= 1;
            *held.forwarded.lock().unwrap() += 1;
            continue;
        }
        tokio::select! {
            read = from_responder.read(&mut chunk), if responder_open => match read {
                Ok(0) | Err(_) => responder_open = false,
                Ok(n) => held.bytes.lock().unwrap().extend_from_slice(&chunk[..n]),
            },
            _ = held.wake.notified() => {}
            _ = held.flush.notified() => {
                let bytes = std::mem::take(&mut *held.bytes.lock().unwrap());
                let written = to_dialler.write_all(&bytes).await.is_ok();
                *held.dialler_write_result.lock().unwrap() = Some(written);
                let _ = to_dialler.shutdown().await;
                return;
            }
        }
    }
}

fn whole_frame_len(bytes: &[u8]) -> Option<usize> {
    let len = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    (bytes.len() >= 4 + len).then_some(4 + len)
}

// ── Nodes ─────────────────────────────────────────────────────────────────

/// Each node's session and message handler logs, for the report only.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<String>>>);

struct LogWriter(Logs);

impl std::io::Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let text = String::from_utf8_lossy(bytes);
        self.0 .0.lock().unwrap().extend(text.lines().map(str::to_owned));
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Logs {
    fn dispatch(&self) -> tracing::Dispatch {
        let logs = self.clone();
        tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(move || LogWriter(logs.clone()))
                .finish(),
        )
    }

    fn mark(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    fn count_since(&self, from: usize, needle: &str) -> usize {
        let lines = self.0.lock().unwrap();
        lines[from.min(lines.len())..].iter().filter(|line| line.contains(needle)).count()
    }
}

struct Node {
    id: NodeId,
    transport: Arc<NoiseTransport>,
    sessions: Arc<SessionManager>,
    wallet: Arc<SharedMockProvider>,
    peer_prices: Arc<konsensus_pricing::PeerPriceCache>,
    router: axum::Router,
    auth: String,
    delivered: Arc<Mutex<Vec<String>>>,
    logs: Logs,
    shutdown: watch::Sender<bool>,
    _dir: tempfile::TempDir,
}

async fn start_node(identity: Arc<NodeIdentity>, peer: NodeId, ledger: &Path, name: &str) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let data_dir: PathBuf = dir.path().to_path_buf();
    let id = *identity.node_id();
    let transport = Arc::new(NoiseTransport::new(
        Arc::clone(&identity),
        TransportConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            admission_mode: ReachabilityMode::PriceOpen,
            whitelist: vec![peer],
            capabilities: crate::node::default_advertised_capabilities(false),
            ..Default::default()
        },
    ));
    transport.start_listener().await.unwrap();

    let wallet = Arc::new(SharedMockProvider::new(ledger, name, 10_000_000).unwrap());
    let lightning: Arc<dyn LightningProvider> = Arc::clone(&wallet) as Arc<dyn LightningProvider>;
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
        configured_stun_server: None,
        custody_mode: konsensus_api::custody::CustodyMode::LocalSeed,
        call_media: None,
        recovery_dir: None,
        gossip_validator: None,
        file_staging: Default::default(),
    });

    let logs = Logs::default();
    tokio::spawn(
        run_msg_handler(MsgHandlerDeps {
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
        })
        .with_subscriber(logs.dispatch()),
    );
    // Nothing drains these here. Leaked so their senders stay open.
    let (pending_tx, pending_rx) = mpsc::channel(64);
    let (auto_channel_tx, auto_rx) = mpsc::channel(64);
    std::mem::forget((pending_rx, auto_rx));
    tokio::spawn(
        run_session_handler(SessionHandlerDeps {
            content_server: Some(content_server),
            front_door,
            min_admission_cost_msat: 0,
            privacy: Default::default(),
            peer_exchange_floor: 0,
            transport: Arc::clone(&transport),
            session_manager: Arc::clone(&sessions),
            storage: Arc::clone(&storage),
            our_node_id: id,
            identity: Arc::clone(&identity),
            audit_log: audit,
            pricing,
            chain,
            peer_prices: Arc::clone(&peer_prices),
            peer_registry: registry,
            routing,
            gossip_validator: Arc::new(konsensus_gossip::GossipValidator::new(Default::default())),
            send_timestamps,
            lightning,
            lightning_addr: None,
            mock_lightning: true,
            invoice_requests,
            peer_ln_pubkeys,
            ws_broadcast,
            ws_delivery_tx,
            pending_tx,
            starter_hub_tx: None,
            starter_newcomer_tx: None,
            auto_channel_tx,
            shutdown_rx,
        })
        .with_subscriber(logs.dispatch()),
    );

    let delivered = Arc::new(Mutex::new(Vec::new()));
    {
        let delivered = Arc::clone(&delivered);
        tokio::spawn(async move {
            loop {
                match ws_rx.recv().await {
                    Ok(message) => {
                        if let Some(text) = message.plaintext.clone() {
                            delivered.lock().unwrap().push(text);
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    let token = konsensus_api::auth::create_token(&id.to_hex(), JWT_SECRET, konsensus_api::auth::Scope::all()).unwrap();
    let router = konsensus_api::build_router(state)
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 50_000))));
    Node {
        id,
        transport,
        sessions,
        wallet,
        peer_prices,
        router,
        auth: format!("Bearer {token}"),
        delivered,
        logs,
        shutdown,
        _dir: dir,
    }
}

impl Node {
    /// The owner's chat to `to`, through the real compose route.
    async fn compose(&self, to: &NodeId, text: &str) -> (StatusCode, serde_json::Value) {
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/messages/compose")
            .header("authorization", &self.auth)
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "recipient": to.to_hex(),
                    "kind": konsensus_core::kind::KIND_CHAT,
                    "plaintext": text,
                })
                .to_string(),
            ))
            .unwrap();
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
    }

    fn has_delivered(&self, text: &str) -> bool {
        self.delivered.lock().unwrap().iter().any(|seen| seen == text)
    }

    async fn paid_out(&self) -> usize {
        self.wallet
            .list_payments(1_000)
            .await
            .unwrap()
            .into_iter()
            .filter(|payment| payment.direction == PaymentDirection::Outgoing)
            .count()
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
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting until {what}");
}

// ── The pair and the forced order ─────────────────────────────────────────

struct Pair {
    higher: Node,
    lower: Node,
    /// Connections the higher id dials go through this one.
    to_lower: Relay,
    /// Connections the lower id dials go through this one.
    to_higher: Relay,
    /// The lower id's session is marked, so it runs X3DH on the offer.
    marked: bool,
    _ledger: tempfile::TempDir,
}

/// Two nodes that list each other, with a working session and a message delivered
/// each way, past the negotiation cooldown. Both supervisors dial through the relay.
async fn ready_pair() -> Pair {
    let (a, b) = (
        Arc::new(NodeIdentity::generate().unwrap().1),
        Arc::new(NodeIdentity::generate().unwrap().1),
    );
    let (lower_id, higher_id) = if a.node_id().as_bytes() < b.node_id().as_bytes() { (a, b) } else { (b, a) };
    let (lower_node, higher_node) = (*lower_id.node_id(), *higher_id.node_id());
    let ledger = tempfile::tempdir().unwrap();
    let ledger_path = ledger.path().join("ledger.db");
    let higher = start_node(higher_id, lower_node, &ledger_path, "higher").await;
    let lower = start_node(lower_id, higher_node, &ledger_path, "lower").await;
    let to_lower = Relay::start(lower.transport.listen_addr().unwrap()).await;
    let to_higher = Relay::start(higher.transport.listen_addr().unwrap()).await;

    higher.transport.connect(&lower.id, &to_lower.addr.to_string()).await.unwrap();
    wait_until("both sides see the connection", STEP, || async {
        higher.transport.is_connected(&lower.id).await && lower.transport.is_connected(&higher.id).await
    })
    .await;
    // Already connected: this only records where the lower id's supervisor dials.
    lower.transport.connect(&higher.id, &to_higher.addr.to_string()).await.unwrap();
    wait_until("both sides can send", STEP, || async {
        higher.sessions.can_send(&lower.id).await && lower.sessions.can_send(&higher.id).await
    })
    .await;

    let pair = Pair { higher, lower, to_lower, to_higher, marked: false, _ledger: ledger };
    for (from, to, text) in [
        (&pair.higher, &pair.lower, "before the drop, from the higher id"),
        (&pair.lower, &pair.higher, "before the drop, from the lower id"),
    ] {
        let (status, body) = from.compose(&to.id, text).await;
        assert_eq!(status, StatusCode::OK, "{text}: {body}");
        wait_until("the first message is delivered", STEP, || async { to.has_delivered(text) }).await;
    }
    tokio::time::sleep(PAST_COOLDOWN).await;
    pair
}

/// The order forced on the two dials, and on the frames of the first connection.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Order {
    /// The race: the higher id's dial finishes first, and the lower id's
    /// `SessionInit` is held until the higher id has closed that connection.
    HigherFirstInitLost,
    /// The same dials, one frame later: the higher id reads `SessionInit`, the lower
    /// id reads its acknowledgement and writes `RatchetInit`, and that frame is lost.
    HigherFirstRatchetInitLost,
    /// Control: same dials, but the first connection forwards everything, so the
    /// frame is read before the connection is replaced.
    HigherFirstInitRead,
    /// Control: the lower id's dial finishes first, so the higher id's is refused
    /// and there is one connection.
    LowerFirst,
}

/// What the forced order produced, from each node's logs and the relay.
#[derive(Debug)]
#[allow(dead_code)] // Read through Debug.
struct RaceFacts {
    order: Order,
    first_connection_replaced: bool,
    lower_ran_x3dh: usize,
    lower_throttled_an_offer: usize,
    higher_accepted_a_session: usize,
    lower_not_acted_on_offer: usize,
    frames_held_from_lower: Vec<usize>,
    held_write_to_closed_ok: Option<bool>,
    /// From the cut to the survivor being up. Must stay inside the cooldown.
    setup_took: Duration,
}

impl Pair {
    /// Cut the link, then drive both supervisors' dials in the given order.
    async fn force_order(&self, order: Order) -> RaceFacts {
        let (higher, lower) = (&self.higher, &self.lower);
        let started = tokio::time::Instant::now();
        let lower_mark = lower.logs.mark();
        let higher_mark = higher.logs.mark();
        let before = (
            higher.transport.connected_since(&lower.id).await,
            lower.transport.connected_since(&higher.id).await,
        );

        // A price table that arrives from here on tells us the lower id's handler
        // is past the offer that came ahead of it on the same connection.
        lower.peer_prices.remove(&higher.id).await;

        self.to_lower.gate(true);
        self.to_higher.gate(true);
        self.to_lower.cut();
        self.to_higher.cut();
        // Each dial starts while the other is still unfinished, as after a real drop.
        self.to_lower.wait_for_dial("the higher id").await;
        self.to_higher.wait_for_dial("the lower id").await;

        let mut held = None;
        let mut frames_held_from_lower = Vec::new();
        let mut first_connection_replaced = false;
        match order {
            Order::HigherFirstInitLost | Order::HigherFirstRatchetInitLost | Order::HigherFirstInitRead => {
                let leg = match order {
                    Order::HigherFirstInitRead => Leg::Pass,
                    _ => Leg::HoldResponderAfter(RESPONDER_HANDSHAKE_FRAMES),
                };
                let first = self.to_lower.release(leg).await;
                wait_until("the higher id registers the first connection", STEP, || async {
                    higher.transport.connected_since(&lower.id).await.is_some()
                        && higher.transport.connected_since(&lower.id).await != before.0
                })
                .await;
                let first_generation = higher.transport.connected_since(&lower.id).await;
                // The lower id's handler has dealt with the offer. If it ran X3DH,
                // SessionInit has been written to the first connection.
                wait_until("the lower id has handled the higher id's offer", STEP, || async {
                    lower.peer_prices.get_peer_entry(&higher.id).await.is_some()
                })
                .await;
                if order == Order::HigherFirstInitRead {
                    // Everything the lower id wrote has been forwarded; let the higher
                    // id finish with it, which ends in a sending chain on both sides.
                    wait_until("the higher id reads the frame", STEP, || async {
                        lower.logs.count_since(lower_mark, "X3DH initiated") == 0
                            || higher.logs.count_since(higher_mark, "ratchet init received") > 0
                    })
                    .await;
                }

                if order == Order::HigherFirstRatchetInitLost && lower.logs.count_since(lower_mark, "X3DH initiated") > 0 {
                    // One frame at a time, so nothing behind `SessionInit` gets through:
                    // the acknowledgement that triggers `RatchetInit` comes after the
                    // log line this checks first.
                    wait_until("the higher id reads the init", STEP, || async {
                        if higher.logs.count_since(higher_mark, "E2EE session accepted") > 0 {
                            return true;
                        }
                        if !first.frame_sizes().is_empty() && *first.more.lock().unwrap() == 0 {
                            first.forward_more(1);
                        }
                        false
                    })
                    .await;
                    wait_until("the lower id writes its ratchet init", STEP, || async {
                        lower.logs.count_since(lower_mark, "sending ratchet init") > 0 && !first.frame_sizes().is_empty()
                    })
                    .await;
                }

                self.to_higher.release(Leg::Pass).await;
                wait_until("the higher id replaces the first connection", STEP, || async {
                    let now = higher.transport.connected_since(&lower.id).await;
                    now.is_some() && now != first_generation
                })
                .await;
                first_connection_replaced = true;
                wait_until("the lower id has its own connection", STEP, || async {
                    let now = lower.transport.connected_since(&higher.id).await;
                    now.is_some() && now != before.1
                })
                .await;
                if order != Order::HigherFirstInitRead {
                    // Whatever was held now goes to a socket the higher id has closed.
                    frames_held_from_lower = first.frame_sizes();
                    first.flush.notify_one();
                    held = Some(first);
                }
            }
            Order::LowerFirst => {
                self.to_higher.release(Leg::Pass).await;
                wait_until("the lower id's connection is up on both sides", STEP, || async {
                    higher.transport.connected_since(&lower.id).await != before.0
                        && lower.transport.connected_since(&higher.id).await != before.1
                })
                .await;
                let surviving = higher.transport.connected_since(&lower.id).await;
                self.to_lower.release(Leg::Pass).await;
                // The higher id's dial completes and is refused: nothing changes.
                wait_until("the higher id keeps the surviving connection", STEP, || async {
                    higher.transport.connected_since(&lower.id).await == surviving
                })
                .await;
            }
        }
        self.to_lower.gate(false);
        self.to_higher.gate(false);

        wait_until("the surviving connection is up on both sides", STEP, || async {
            higher.transport.is_connected(&lower.id).await && lower.transport.is_connected(&higher.id).await
        })
        .await;
        if let Some(first) = &held {
            wait_until("the held bytes were written", STEP, || async {
                first.dialler_write_result.lock().unwrap().is_some()
            })
            .await;
        }
        let setup_took = started.elapsed();
        // Report only: give the offer on the survivor a moment to show in the log.
        let throttled_or_quiet = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < throttled_or_quiet
            && lower.logs.count_since(lower_mark, "session re-negotiation throttled") == 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Marked, and it must have run X3DH, or the run proves nothing about that order.
        assert!(
            !self.marked || lower.logs.count_since(lower_mark, "X3DH initiated") > 0,
            "the lower id's session was marked, so it runs X3DH"
        );
        RaceFacts {
            order,
            first_connection_replaced,
            lower_ran_x3dh: lower.logs.count_since(lower_mark, "X3DH initiated"),
            lower_throttled_an_offer: lower.logs.count_since(lower_mark, "session re-negotiation throttled"),
            higher_accepted_a_session: higher.logs.count_since(higher_mark, "E2EE session accepted"),
            lower_not_acted_on_offer: lower.logs.count_since(lower_mark, "prekey offer not acted on"),
            frames_held_from_lower,
            held_write_to_closed_ok: held.as_ref().and_then(|first| *first.dialler_write_result.lock().unwrap()),
            setup_took,
        }
    }

    fn stop(&self) {
        self.higher.stop();
        self.lower.stop();
    }
}

// ── After the race: what a user sees ──────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq)]
enum Side {
    Higher,
    Lower,
}

#[derive(Debug, Default)]
#[allow(dead_code)] // Read through Debug.
struct Delivery {
    attempts: usize,
    delivered_after: Option<Duration>,
    last_refusal: Option<String>,
}

/// Send from each side, `first` before the other, until a message from each has
/// been delivered or `RECOVERY_BOUND` is up. An undelivered side tries again every
/// few seconds, as a user would.
async fn messages_each_way(pair: &Pair, first: Side) -> (Delivery, Delivery, usize) {
    let started = tokio::time::Instant::now();
    let deadline = started + RECOVERY_BOUND;
    let paid_before = pair.higher.paid_out().await + pair.lower.paid_out().await;
    let (mut from_higher, mut from_lower) = (Delivery::default(), Delivery::default());
    let order = match first {
        Side::Higher => [Side::Higher, Side::Lower],
        Side::Lower => [Side::Lower, Side::Higher],
    };
    let mut round = 0;
    while tokio::time::Instant::now() < deadline
        && (from_higher.delivered_after.is_none() || from_lower.delivered_after.is_none())
    {
        round += 1;
        for side in order {
            let (node, peer, delivery, name) = match side {
                Side::Higher => (&pair.higher, &pair.lower, &mut from_higher, "higher"),
                Side::Lower => (&pair.lower, &pair.higher, &mut from_lower, "lower"),
            };
            if delivery.delivered_after.is_some() {
                continue;
            }
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() {
                break;
            }
            let text = format!("after the race, round {round}, from the {name} id");
            delivery.attempts += 1;
            match tokio::time::timeout(left, node.compose(&peer.id, &text)).await {
                Ok((status, body)) => {
                    let answer = format!("{status}: {}", refusal_of(&body));
                    eprintln!(
                        "SESSION-RACE attempt t={:?} from={name} status={status} delivered={} accepted={} amount_msat={} code={} reason={}",
                        started.elapsed(), body["delivered"], body["accepted"], body["amount_msat"], body["code"], body["reason"],
                    );
                    let within = Duration::from_secs(3).min(deadline.saturating_duration_since(tokio::time::Instant::now()));
                    let until = tokio::time::Instant::now() + within;
                    while tokio::time::Instant::now() < until && !peer.has_delivered(&text) {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    if peer.has_delivered(&text) {
                        delivery.delivered_after = Some(started.elapsed());
                    } else {
                        delivery.last_refusal = Some(answer);
                    }
                }
                Err(_) => delivery.last_refusal = Some("still waiting when the bound ran out".into()),
            }
        }
        let pause = Duration::from_secs(5).min(deadline.saturating_duration_since(tokio::time::Instant::now()));
        if from_higher.delivered_after.is_none() || from_lower.delivered_after.is_none() {
            tokio::time::sleep(pause).await;
        }
    }
    let paid = pair.higher.paid_out().await + pair.lower.paid_out().await - paid_before;
    (from_higher, from_lower, paid)
}

/// The part of a compose answer that says why a message did not land.
fn refusal_of(body: &serde_json::Value) -> String {
    for key in ["reason", "error", "reject_reason", "rejected_reason", "detail", "delivery_status"] {
        if let Some(text) = body.get(key).and_then(|value| value.as_str()) {
            return text.chars().take(120).collect();
        }
    }
    format!("delivered={} accepted={}", body["delivered"], body["accepted"])
}

fn report(test: &str, facts: &RaceFacts, from_higher: &Delivery, from_lower: &Delivery, paid: usize) {
    eprintln!("SESSION-RACE {test}: {facts:?}");
    eprintln!(
        "SESSION-RACE {test}: from_higher={from_higher:?} from_lower={from_lower:?} payments_during_recovery={paid}"
    );
}

/// The forced order must really have happened, or a pass means nothing.
fn assert_race_happened(facts: &RaceFacts) {
    assert!(facts.first_connection_replaced, "{facts:?}");
    assert_eq!(facts.higher_accepted_a_session, 0, "the frame must not be read: {facts:?}");
    assert!(facts.held_write_to_closed_ok.is_some(), "{facts:?}");
    assert!(facts.setup_took < Duration::from_secs(8), "stalled past the cooldown, so this run proves nothing: {facts:?}");
}

async fn race_then_messages(test: &str, order: Order, first: Side) {
    let pair = ready_pair().await;
    run_and_assert(test, &pair, order, first).await;
}

async fn run_and_assert(test: &str, pair: &Pair, order: Order, first: Side) {
    let (from_higher, from_lower, paid, facts) = run_race(test, pair, order, first).await;
    assert!(
        from_higher.attempts == 1 && from_lower.attempts == 1 && paid == 2,
        "the first message each way is read, and nothing else is paid for. paid {paid}; \
         from the higher id: {from_higher:?}; from the lower id: {from_lower:?}; {facts:?}"
    );
}

/// Force the order, then send until a message from each side is read.
async fn run_race(test: &str, pair: &Pair, order: Order, first: Side) -> (Delivery, Delivery, usize, RaceFacts) {
    let facts = pair.force_order(order).await;
    if order == Order::HigherFirstInitLost {
        assert_race_happened(&facts);
    }
    let (from_higher, from_lower, paid) = messages_each_way(pair, first).await;
    report(test, &facts, &from_higher, &from_lower, paid);
    pair.stop();
    assert!(
        from_higher.delivered_after.is_some() && from_lower.delivered_after.is_some(),
        "within {RECOVERY_BOUND:?} of the race a message from each side must be read. \
         from the higher id: {from_higher:?}; from the lower id: {from_lower:?}; {facts:?}"
    );
    (from_higher, from_lower, paid, facts)
}

/// Force the order, let nobody send for [`RECOVERY_BOUND`], then ask whether each
/// side can read the other. Encrypting and previewing changes no receiving state.
async fn idle_then_probe(test: &str, pair: &Pair, order: Order) {
    let facts = pair.force_order(order).await;
    if order == Order::HigherFirstInitLost {
        assert_race_happened(&facts);
    }
    let (higher, lower) = (&pair.higher, &pair.lower);
    tokio::time::sleep(RECOVERY_BOUND).await;
    let can_send = (higher.sessions.can_send(&lower.id).await, lower.sessions.can_send(&higher.id).await);
    let to_lower = higher.sessions.encrypt(&lower.id, b"probe").await.expect("the higher id reports it can send");
    let to_higher = lower.sessions.encrypt(&higher.id, b"probe").await.expect("the lower id reports it can send");
    let readable = (
        lower.sessions.preview_decrypt(&higher.id, &to_lower).await.is_ok(),
        higher.sessions.preview_decrypt(&lower.id, &to_higher).await.is_ok(),
    );
    eprintln!("SESSION-RACE {test}: {facts:?}");
    eprintln!("SESSION-RACE {test}: can_send(higher,lower)={can_send:?} readable(by lower,by higher)={readable:?}");
    pair.stop();
    assert_eq!(readable, (true, true), "both report able to send, on sessions that must match: {facts:?}");
}

/// Force the order, then only the higher id sends, every few seconds, until one
/// message is delivered or the bound is up. The lower id says nothing.
async fn only_the_higher_id_speaks(test: &str, pair: &Pair, order: Order) {
    let facts = pair.force_order(order).await;
    let (higher, lower) = (&pair.higher, &pair.lower);
    let started = tokio::time::Instant::now();
    let paid_before = higher.paid_out().await;
    let (mut attempts, mut delivered_after) = (0, None);
    while started.elapsed() < RECOVERY_BOUND && delivered_after.is_none() {
        attempts += 1;
        let text = format!("after the race, attempt {attempts}, from the higher id");
        let left = RECOVERY_BOUND.saturating_sub(started.elapsed());
        if let Ok((status, body)) = tokio::time::timeout(left, higher.compose(&lower.id, &text)).await {
            eprintln!(
                "SESSION-RACE attempt t={:?} from=higher status={status} accepted={} amount_msat={}",
                started.elapsed(), body["accepted"], body["amount_msat"],
            );
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
        if lower.has_delivered(&text) {
            delivered_after = Some(started.elapsed());
        } else {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
    let paid = higher.paid_out().await - paid_before;
    eprintln!("SESSION-RACE {test}: {facts:?}");
    eprintln!("SESSION-RACE {test}: attempts={attempts} delivered_after={delivered_after:?} paid_by_higher={paid}");
    pair.stop();
    assert!(delivered_after.is_some(), "the higher id never got through: {facts:?}");
    assert!(attempts == 1 && paid == 1, "its first message is read: {attempts} attempts, {paid} paid: {facts:?}");
}

// ── The race ──────────────────────────────────────────────────────────────

/// The higher id speaks first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_race_messages_flow_when_the_higher_id_speaks_first() {
    race_then_messages("higher-first", Order::HigherFirstInitLost, Side::Higher).await;
}

/// Same race, the lower id speaks first. The higher id cannot read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_race_messages_flow_when_the_lower_id_speaks_first() {
    race_then_messages("lower-first", Order::HigherFirstInitLost, Side::Lower).await;
}

/// Same race, nobody sends. Without a message, does anything notice?
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_race_the_sessions_agree_without_any_traffic() {
    let pair = ready_pair().await;
    idle_then_probe("idle", &pair, Order::HigherFirstInitLost).await;
}

/// Same race with the lower id holding no session when the link drops, so it runs
/// X3DH on the closing connection whatever rule it applies to a healthy session.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_race_with_no_session_on_the_lower_id_messages_flow() {
    let pair = ready_pair().await;
    assert!(pair.lower.sessions.remove_session(&pair.higher.id).await);
    // The lower id's new session is gone with the init, and it has no earlier one that
    // can read the higher id, so what is sent before they agree again is refused.
    run_race("no-session-on-lower", &pair, Order::HigherFirstInitLost, Side::Higher).await;
}

/// The same dials, but the frame lost is `RatchetInit`, not `SessionInit`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_losing_the_ratchet_init_messages_flow() {
    race_then_messages("ratchet-init-lost", Order::HigherFirstRatchetInitLost, Side::Higher).await;
}

/// `RatchetInit` lost and nobody sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_losing_the_ratchet_init_the_sessions_agree_without_any_traffic() {
    let pair = ready_pair().await;
    idle_then_probe("ratchet-init-lost-idle", &pair, Order::HigherFirstRatchetInitLost).await;
}

/// `RatchetInit` lost and only the higher id sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_losing_the_ratchet_init_the_higher_id_gets_through_alone() {
    let pair = ready_pair().await;
    only_the_higher_id_speaks("ratchet-init-lost-higher-alone", &pair, Order::HigherFirstRatchetInitLost).await;
}

/// The race, and only the higher id sends.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_race_the_higher_id_gets_through_alone() {
    let pair = ready_pair().await;
    only_the_higher_id_speaks("higher-alone", &pair, Order::HigherFirstInitLost).await;
}

// ── Controls: the same setup with the other orders ──────────────────────

/// The frame is read before the connection is replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_when_the_init_is_read_first_messages_flow() {
    race_then_messages("control-init-read", Order::HigherFirstInitRead, Side::Higher).await;
}

/// The lower id's dial finishes first: one connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn control_when_the_lower_id_dials_first_messages_flow() {
    race_then_messages("control-lower-dial", Order::LowerFirst, Side::Higher).await;
}

// ── Only where a healthy session ignores a reconnect's offer ──────────────
//
// A healthy lower id no longer runs X3DH on connect, so the orders above never put
// a `SessionInit` on the closing connection here. A session marked for renegotiation
// still does, so these force it.

async fn marked_pair() -> Pair {
    let mut pair = ready_pair().await;
    pair.lower.sessions.mark_needs_renegotiation(&pair.higher.id).await;
    pair.marked = true;
    pair
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn marked_session_init_lost_higher_speaks_first() {
    run_and_assert("marked-init-lost-higher-first", &marked_pair().await, Order::HigherFirstInitLost, Side::Higher).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn marked_session_init_lost_lower_speaks_first() {
    run_and_assert("marked-init-lost-lower-first", &marked_pair().await, Order::HigherFirstInitLost, Side::Lower).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn marked_session_init_lost_idle() {
    idle_then_probe("marked-init-lost-idle", &marked_pair().await, Order::HigherFirstInitLost).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn marked_session_ratchet_init_lost_higher_speaks_first() {
    run_and_assert("marked-ratchet-lost-higher-first", &marked_pair().await, Order::HigherFirstRatchetInitLost, Side::Higher).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn marked_session_ratchet_init_lost_lower_speaks_first() {
    run_and_assert("marked-ratchet-lost-lower-first", &marked_pair().await, Order::HigherFirstRatchetInitLost, Side::Lower).await;
}

/// After `RatchetInit` is lost the lower id is on the new session and the higher id
/// on the old one. With no traffic, does anything notice?
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn marked_session_ratchet_init_lost_idle() {
    let pair = marked_pair().await;
    let before = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    idle_then_probe("marked-ratchet-lost-idle", &pair, Order::HigherFirstRatchetInitLost).await;
    // Reading is not enough: the session before and the one held aside both read. Each
    // side must be on the new session, with no message having asked for it.
    assert!(pair.lower.sessions.session_newer_than(&pair.higher.id, before).await, "the lower id moved");
    assert!(pair.higher.sessions.session_newer_than(&pair.lower.id, before).await, "the higher id moved");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn marked_session_ratchet_init_lost_higher_alone() {
    only_the_higher_id_speaks("marked-ratchet-lost-higher-alone", &marked_pair().await, Order::HigherFirstRatchetInitLost).await;
}
