//! Two nodes in one process (M6 N2): a packet written into node A's owner
//! media socket comes out of node B's owner media socket, and back.
//!
//! Real Noise transports on loopback, real call media routers, real SQLite
//! call state (a paid live call on both sides), the real API router served on a
//! loopback port with a paired device holding `spend`, and a plain WebSocket
//! client. Nothing is stubbed on the media path.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use konsensus_api::auth::Scope;
use konsensus_api::pairing::{self, PairingService};
use konsensus_core::payloads::call::{CallEntry, Phase, Side};
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::{NodeId, NodeIdentity};
use konsensus_message::{NoiseTransport, PeerRegistry, TransportConfig};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

use super::{CallMediaRouter, PaidCallAdmission, MediaLink};

const JWT_SECRET: &str = "call-media-two-node-jwt-secret";
const CALL: &str = "00112233445566778899aabbccddeeff";

/// The owner terminal, so the test can type the grant confirmation.
#[derive(Clone, Default)]
struct Console(Arc<Mutex<Vec<u8>>>);

impl Console {
    fn confirmation(&self, label: &str) -> String {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .rfind(|line| line.starts_with(&format!("{label} CODE ")))
            .unwrap_or_else(|| panic!("owner console has no confirmation for {label}"))
            .to_owned()
    }
}

impl std::io::Write for Console {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct Node {
    id: NodeId,
    transport: Arc<NoiseTransport>,
    storage: Arc<dyn konsensus_storage::Storage>,
    api_addr: SocketAddr,
    /// A paired device's token carrying `spend`.
    token: String,
    shutdown: watch::Sender<bool>,
    _dir: tempfile::TempDir,
}

async fn start_node(identity: Arc<NodeIdentity>, whitelist: Vec<NodeId>) -> Node {
    let dir = tempfile::tempdir().unwrap();
    let id = *identity.node_id();
    let transport = Arc::new(NoiseTransport::new(
        Arc::clone(&identity),
        TransportConfig {
            listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            whitelist,
            capabilities: crate::node::default_advertised_capabilities(false),
            ..Default::default()
        },
    ));
    transport.start_listener().await.unwrap();
    let storage: Arc<dyn konsensus_storage::Storage> =
        Arc::new(konsensus_storage::sqlite::SqliteStorage::in_memory().await.unwrap());
    let (shutdown, shutdown_rx) = watch::channel(false);

    let router = CallMediaRouter::new(
        Arc::clone(&transport) as Arc<dyn MediaLink>,
        Arc::new(PaidCallAdmission::new(Arc::clone(&storage))),
    );
    router.spawn(shutdown_rx);

    // A paired app with an owner spend grant: the only caller the media
    // socket admits.
    let console = Console::default();
    let service = Arc::new(
        PairingService::open(dir.path(), pairing::identity_fingerprint(&id.to_hex()), true)
            .unwrap()
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code(),
    );
    let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    service.open_pairing_window(Duration::from_secs(60));
    let client = service
        .create_verified_remote_pairing("app", &hex::encode(key.verifying_key().to_bytes()), &[9; 32])
        .unwrap();
    let op = service.create_elevation_request(&client.client_id, vec![Scope::Spend]).unwrap();
    service
        .grant_elevation(
            &op.op_id,
            &console.confirmation(&pairing::grant_confirmation_phrase(&op)),
            konsensus_api::spend_budget::GrantTerms::new(100_000),
        )
        .unwrap();
    let epoch = service.list_clients().into_iter().find(|c| c.client_id == client.client_id).unwrap().epoch;
    let token = konsensus_api::auth::create_paired_token(
        &id.to_hex(),
        JWT_SECRET,
        vec![Scope::Read, Scope::Receive, Scope::Spend],
        &client.client_id,
        epoch,
        &service.bound_fingerprint(),
    )
    .unwrap();

    let audit = Arc::new(konsensus_api::audit::AuditLog::open(dir.path().join("audit.log")).unwrap());
    let state = Arc::new(konsensus_api::AppState {
        starter: Default::default(),
        identity: Arc::clone(&identity),
        storage: Arc::clone(&storage),
        lightning: Arc::new(konsensus_lightning::MockLightningProvider::new()),
        chain: Arc::new(konsensus_chain::mock::MockChainProvider::new()),
        pricing: Arc::new(konsensus_pricing::StaticPricingEngine::new(Default::default())),
        gate: Arc::new(konsensus_core::PaymentGate::new()),
        peer_registry: Arc::new(tokio::sync::RwLock::new(PeerRegistry::new())),
        transport: Arc::clone(&transport) as Arc<dyn MessageTransport>,
        session_manager: Arc::new(konsensus_crypto::SessionManager::new(Arc::clone(&identity))),
        jwt_secret: JWT_SECRET.into(),
        file_staging: Default::default(),
        auth_challenges: Arc::new(tokio::sync::Mutex::new(Default::default())),
        pairing: Some(service),
        cors_enabled: false,
        operator_probes_enabled: false,
        sensitive_identity_routes_enabled: false,
        has_identity_passphrase: false,
        ws_broadcast: tokio::sync::broadcast::channel(16).0,
        ws_delivery_broadcast: tokio::sync::broadcast::channel(16).0,
        rate_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::new(100)),
        mnemonic_reveal_limiter: Arc::new(konsensus_api::rate_limit::RateLimiter::mnemonic_reveal_default()),
        audit_log: audit,
        started_at: std::time::Instant::now(),
        content_dir: None,
        web_page_price_msat: None,
        peer_prices: Arc::new(konsensus_pricing::PeerPriceCache::new()),
        routing: Arc::new(konsensus_routing::RoutingTable::with_defaults()),
        plaintext_cipher: None,
        send_timestamps: Arc::new(tokio::sync::Mutex::new(Default::default())),
        invoice_requests: Arc::new(tokio::sync::Mutex::new(Default::default())),
        data_dir: Some(dir.path().to_path_buf()),
        backup_dir: None,
        peer_ln_pubkeys: Arc::new(tokio::sync::Mutex::new(Default::default())),
        lightning_backend: "mock".into(),
        chain_backend: "mock".into(),
        introduction: Default::default(),
        front_door: Default::default(),
        sponsor: Default::default(),
        stun_port: None,
        configured_stun_server: None,
        custody_mode: konsensus_api::custody::CustodyMode::LocalSeed,
        call_media: Some(router as Arc<dyn konsensus_api::call_media::CallMediaPort>),
        recovery_dir: None,
        gossip_validator: None,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    let app = konsensus_api::build_router_for_addr(state, api_addr);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await.unwrap();
    });

    Node { id, transport, storage, api_addr, token, shutdown, _dir: dir }
}

impl Node {
    fn addr(&self) -> String {
        self.transport.listen_addr().unwrap().to_string()
    }

    /// An answered call with its first 60-second block settled.
    async fn live_call(&self, peer: &NodeId, side: Side) {
        let now = chrono::Utc::now().timestamp_millis() as u64;
        self.storage
            .call_put(peer, CALL, &CallEntry { side, phase: Phase::Live, deadline_ms: now + 70_000, pending: None, paid_until_ms: Some(now + 60_000), next_block_seq: 1, end_reason: None, unpaid_notice_used: false })
            .await
            .unwrap();
    }

    /// Open the owner media socket for `CALL` with `peer`; the status when refused.
    async fn media_socket(
        &self,
        peer: &NodeId,
        token: &str,
    ) -> Result<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, u16> {
        let mut request = format!("ws://{}/api/v1/calls/{CALL}/media?peer={}", self.api_addr, peer.to_hex())
            .into_client_request()
            .unwrap();
        request.headers_mut().insert(
            "sec-websocket-protocol",
            format!("bitsov.v1, bitsov.jwt.{token}").parse().unwrap(),
        );
        match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => Ok(socket),
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => Err(response.status().as_u16()),
            Err(e) => panic!("websocket connect failed: {e}"),
        }
    }
}

fn packet(seq: u32, payload: &[u8]) -> Message {
    Message::Binary([seq.to_be_bytes().as_slice(), payload].concat())
}

async fn next_binary<S>(socket: &mut S) -> Vec<u8>
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await.expect("socket open").expect("socket ok") {
                Message::Binary(bytes) => return bytes,
                Message::Ping(_) | Message::Pong(_) | Message::Text(_) => continue,
                other => panic!("unexpected message {other:?}"),
            }
        }
    })
    .await
    .expect("a packet within five seconds")
}

async fn wait_until<F, Fut>(what: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting until {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_packet_into_node_a_s_socket_comes_out_of_node_b_s_socket() {
    let (id_a, id_b) = (
        Arc::new(NodeIdentity::generate().unwrap().1),
        Arc::new(NodeIdentity::generate().unwrap().1),
    );
    let a = start_node(Arc::clone(&id_a), vec![*id_b.node_id()]).await;
    let b = start_node(Arc::clone(&id_b), vec![*id_a.node_id()]).await;
    a.transport.connect(&b.id, &b.addr()).await.unwrap();
    wait_until("both see the connection", || async {
        a.transport.is_connected(&b.id).await && b.transport.is_connected(&a.id).await
    })
    .await;

    // Nothing is admitted before a live call has paid block coverage.
    assert_eq!(a.media_socket(&b.id, &a.token).await.err(), Some(403));

    a.live_call(&b.id, Side::Caller).await;
    b.live_call(&a.id, Side::Callee).await;
    // The owner's key-proof token is not a paired device: refused.
    let owner = konsensus_api::auth::create_token(&a.id.to_hex(), JWT_SECRET, Scope::all()).unwrap();
    assert_eq!(a.media_socket(&b.id, &owner).await.err(), Some(403));

    let mut app_a = a.media_socket(&b.id, &a.token).await.unwrap();
    let mut app_b = b.media_socket(&a.id, &b.token).await.unwrap();
    assert_eq!(a.media_socket(&b.id, &a.token).await.err(), Some(409), "one socket per call");

    // A → B: twenty "20 ms Opus" packets, in order, byte for byte.
    for seq in 1..=20u32 {
        app_a.send(packet(seq, &[seq as u8; 160])).await.unwrap();
    }
    for seq in 1..=20u32 {
        let bytes = next_binary(&mut app_b).await;
        assert_eq!(&bytes[..4], &seq.to_be_bytes());
        assert_eq!(&bytes[4..], &[seq as u8; 160][..]);
    }

    // B → A: the other direction on the same sockets.
    app_b.send(packet(7, b"hello from b")).await.unwrap();
    assert_eq!(next_binary(&mut app_a).await, [&7u32.to_be_bytes()[..], b"hello from b"].concat());

    // A malformed app packet (no header) is dropped; the socket stays up.
    app_a.send(Message::Binary(vec![1, 2])).await.unwrap();
    app_a.send(packet(21, b"still here")).await.unwrap();
    assert_eq!(next_binary(&mut app_b).await, [&21u32.to_be_bytes()[..], b"still here"].concat());

    // The call ends on B: B's socket closes and nothing more arrives on it.
    b.storage.call_delete(&a.id, CALL).await.unwrap();
    tokio::time::sleep(super::ADMISSION_RECHECK + Duration::from_millis(200)).await;
    app_a.send(packet(22, b"after hangup")).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match app_b.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => return true,
                Some(Ok(Message::Binary(_))) => return false,
                Some(Ok(_)) => continue,
            }
        }
    })
    .await
    .expect("B's socket closes after the call ended");
    assert!(closed, "no media after the call ended");

    let _ = a.shutdown.send(true);
    let _ = b.shutdown.send(true);
}
