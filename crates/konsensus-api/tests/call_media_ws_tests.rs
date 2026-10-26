//! The owner media socket's gate (M6 N2): every refusal before the upgrade.
//! Only a paired device holding `spend`, as the node's owner, on a call the
//! router admits, gets `101`; everything else is a plain HTTP refusal.
//!
//! Upgrade cases use disposable loopback listeners: the WebSocket extractor
//! needs a real connection, so `oneshot` cannot reach the handler's gate.

mod common;

#[path = "common/owner_console.rs"]
mod owner_console;
use owner_console::OwnerConsole;

use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use tower::ServiceExt;

use konsensus_api::auth::Scope;
use konsensus_api::call_media::{AttachRefusal, CallMediaPort, MediaAttachment, MediaQueue};
use konsensus_api::pairing::{self, PairingService};
use konsensus_api::state::AppState;
use konsensus_core::NodeId;

use common::{auth_header, test_state_with_data_dir};

const CALL: &str = "00112233445566778899aabbccddeeff";

/// A router that answers every attach the same way.
struct StubPort(Option<AttachRefusal>);

#[async_trait]
impl CallMediaPort for StubPort {
    async fn attach(&self, peer: &NodeId, _call_id: &str) -> Result<MediaAttachment, AttachRefusal> {
        match self.0 {
            Some(refusal) => Err(refusal),
            None => Ok(MediaAttachment::new(*peer, MediaQueue::new(4), MediaQueue::new(4), || {})),
        }
    }
}

struct Fixture {
    state: Arc<AppState>,
    service: Arc<PairingService>,
    console: OwnerConsole,
    /// The live loopback listener serving the real router.
    addr: std::net::SocketAddr,
}

async fn fixture(dir: &std::path::Path, port: Option<Arc<dyn CallMediaPort>>) -> Fixture {
    let console = OwnerConsole::default();
    let base = test_state_with_data_dir(dir.to_path_buf());
    let fingerprint = pairing::identity_fingerprint(&base.identity.node_id().to_hex());
    let service = Arc::new(
        PairingService::open(dir, fingerprint, true)
            .unwrap()
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code(),
    );
    let state = Arc::new(AppState { pairing: Some(Arc::clone(&service)), call_media: port, ..(*base).clone() });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = konsensus_api::build_router_for_addr(Arc::clone(&state), addr);
    tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .unwrap();
    });
    Fixture { state, service, console, addr }
}

impl Fixture {

    /// A paired device; with `spend` when the owner granted it.
    fn paired_token(&self, seed: u8, scopes: Vec<Scope>) -> String {
        let key = SigningKey::from_bytes(&[seed; 32]);
        self.service.open_pairing_window(std::time::Duration::from_secs(60));
        let client = self
            .service
            .create_verified_remote_pairing(&format!("app-{seed}"), &hex::encode(key.verifying_key().to_bytes()), &[seed; 32])
            .unwrap();
        if scopes.contains(&Scope::Spend) {
            let op = self.service.create_elevation_request(&client.client_id, vec![Scope::Spend]).unwrap();
            self.service
                .grant_elevation(
                    &op.op_id,
                    &self.console.confirmation(&pairing::grant_confirmation_phrase(&op)),
                    konsensus_api::spend_budget::GrantTerms::new(100_000),
                )
                .unwrap();
        }
        let epoch = self.service.list_clients().into_iter().find(|c| c.client_id == client.client_id).unwrap().epoch;
        konsensus_api::auth::create_paired_token(
            &self.state.identity.node_id().to_hex(),
            &self.state.jwt_secret,
            scopes,
            &client.client_id,
            epoch,
            &self.service.bound_fingerprint(),
        )
        .unwrap()
    }

    /// The upgrade request as a browser sends it; the status it gets.
    async fn upgrade(&self, path: &str, token: Option<&str>) -> StatusCode {
        self.open(path, token).await.0
    }

    async fn open(&self, path: &str, token: Option<&str>) -> (StatusCode, tokio::net::TcpStream) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tcp = tokio::net::TcpSocket::new_v4().unwrap();
        tcp.set_recv_buffer_size(1024).unwrap();
        let mut stream = tcp.connect(self.addr).await.unwrap();
        let protocol = match token {
            Some(token) => format!("Sec-WebSocket-Protocol: bitsov.v1, bitsov.jwt.{token}\r\n"),
            None => String::new(),
        };
        stream
            .write_all(
                format!(
                    "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
                     Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{protocol}\r\n",
                    self.addr
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !response.ends_with(b"\r\n\r\n") {
                response.push(stream.read_u8().await.unwrap());
                assert!(response.len() < 8192);
            }
        })
        .await
        .unwrap();
        let status: u16 = std::str::from_utf8(&response).unwrap().split_whitespace().nth(1).unwrap().parse().unwrap();
        (StatusCode::from_u16(status).unwrap(), stream)
    }
}

fn media_path(peer: &NodeId) -> String {
    format!("/api/v1/calls/{CALL}/media?peer={}", peer.to_hex())
}

#[tokio::test]
async fn media_socket_refuses_everything_but_a_paired_spending_owner_on_an_admitted_call() {
    let peer = NodeId::from_bytes([5; 32]);
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Some(Arc::new(StubPort(None)))).await;
    let path = media_path(&peer);

    // No token, a bad token: 401, like `/ws`.
    assert_eq!(f.upgrade(&path, None).await, StatusCode::UNAUTHORIZED);
    assert_eq!(f.upgrade(&path, Some("not-a-jwt")).await, StatusCode::UNAUTHORIZED);

    // The owner's own key-proof token is not a paired device: 403.
    let owner = auth_header(&f.state).trim_start_matches("Bearer ").to_owned();
    assert_eq!(f.upgrade(&path, Some(&owner)).await, StatusCode::FORBIDDEN);

    // A paired device without `spend` (the default pairing): 403.
    let read_only = f.paired_token(21, vec![Scope::Read, Scope::Receive]);
    assert_eq!(f.upgrade(&path, Some(&read_only)).await, StatusCode::FORBIDDEN);

    // A paired device the owner granted `spend`: through to the router.
    let spender = f.paired_token(22, vec![Scope::Read, Scope::Receive, Scope::Spend]);
    assert_eq!(f.upgrade(&path, Some(&spender)).await, StatusCode::SWITCHING_PROTOCOLS);

    // Malformed call or peer ids never reach the router.
    assert_eq!(f.upgrade(&format!("/api/v1/calls/not-a-call/media?peer={}", peer.to_hex()), Some(&spender)).await, StatusCode::BAD_REQUEST);
    assert_eq!(f.upgrade(&format!("/api/v1/calls/{CALL}/media"), Some(&spender)).await, StatusCode::BAD_REQUEST);
    assert_eq!(f.upgrade(&format!("/api/v1/calls/{CALL}/media?peer=zz"), Some(&spender)).await, StatusCode::BAD_REQUEST);

    // Revoked meanwhile: the same token is refused.
    for client in f.service.list_clients() {
        f.service.revoke(&client.client_id).unwrap();
    }
    assert_eq!(f.upgrade(&path, Some(&spender)).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn media_socket_reports_the_router_s_refusal() {
    let peer = NodeId::from_bytes([6; 32]);
    let cases = [
        (Some(AttachRefusal::NotAdmitted), StatusCode::FORBIDDEN),
        (Some(AttachRefusal::AlreadyAttached), StatusCode::CONFLICT),
        (Some(AttachRefusal::Unavailable), StatusCode::SERVICE_UNAVAILABLE),
    ];
    for (refusal, status) in cases {
        let dir = tempfile::tempdir().unwrap();
        let f = fixture(dir.path(), Some(Arc::new(StubPort(refusal)))).await;
        let spender = f.paired_token(23, vec![Scope::Read, Scope::Receive, Scope::Spend]);
        assert_eq!(f.upgrade(&media_path(&peer), Some(&spender)).await, status, "{refusal:?}");
    }

    // A node without a router: 503, never a silent socket.
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), None).await;
    let spender = f.paired_token(24, vec![Scope::Read, Scope::Receive, Scope::Spend]);
    assert_eq!(f.upgrade(&media_path(&peer), Some(&spender)).await, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn media_socket_is_not_a_plain_http_route() {
    let dir = tempfile::tempdir().unwrap();
    let f = fixture(dir.path(), Some(Arc::new(StubPort(None)))).await;
    let spender = f.paired_token(25, vec![Scope::Read, Scope::Receive, Scope::Spend]);
    // No upgrade headers: refused before the handler, even with a valid token.
    let app = konsensus_api::build_router_for_addr(Arc::clone(&f.state), f.addr)
        .layer(axum::extract::connect_info::MockConnectInfo(f.addr))
        .layer(axum::Extension(axum::extract::ConnectInfo(f.addr)));
    let request = Request::builder()
        .uri(format!("/api/v1/calls/{CALL}/media?peer={}&token={spender}", NodeId::from_bytes([7; 32]).to_hex()))
        .header("host", f.addr.to_string())
        .body(Body::empty())
        .unwrap();
    let status = app.oneshot(request).await.unwrap().status();
    assert!(status.is_client_error(), "{status}");
    assert_ne!(status, StatusCode::OK);
}

/// Observe the real socket's attachment lifetime, and supply outbound media.
struct ObservedPort {
    to_node: Arc<MediaQueue>,
    from_node: Arc<MediaQueue>,
    released: Arc<tokio::sync::Notify>,
}
impl ObservedPort {
    fn new() -> Arc<Self> {
        Arc::new(Self { to_node: MediaQueue::new(32), from_node: MediaQueue::new(32),
            released: Arc::new(tokio::sync::Notify::new()) })
    }
}
#[async_trait]
impl CallMediaPort for ObservedPort {
    async fn attach(&self, peer: &NodeId, _: &str) -> Result<MediaAttachment, AttachRefusal> {
        let released = self.released.clone();
        Ok(MediaAttachment::new(*peer, self.to_node.clone(), self.from_node.clone(), move || released.notify_one()))
    }
}

fn masked_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![opcode];
    if payload.len() < 126 {
        frame.push(0x80 | payload.len() as u8);
    } else {
        frame.push(0x80 | 126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    }
    frame.extend_from_slice(&[0; 4]);
    frame.extend_from_slice(payload);
    frame
}

#[tokio::test]
async fn oversize_frame_header_is_rejected_before_the_body_arrives() {
    use tokio::io::AsyncWriteExt;
    let dir = tempfile::tempdir().unwrap();
    let port = ObservedPort::new();
    let f = fixture(dir.path(), Some(port.clone())).await;
    let token = f.paired_token(30, vec![Scope::Spend]);
    let (status, mut socket) = f.open(&media_path(&NodeId::from_bytes([8; 32])), Some(&token)).await;
    assert_eq!(status, StatusCode::SWITCHING_PROTOCOLS);
    // Declares 4101 bytes, but sends only the header and mask. Waiting for
    // a body here means the WebSocket framing limit was not installed.
    socket.write_all(&[0x82, 0xfe, 0x10, 0x05, 0, 0, 0, 0]).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), port.released.notified())
        .await.expect("oversize frame was buffered instead of rejected");
    assert!(port.to_node.is_empty());
}

#[tokio::test]
async fn fragmented_message_cannot_exceed_the_media_limit() {
    use tokio::io::AsyncWriteExt;
    let dir = tempfile::tempdir().unwrap();
    let port = ObservedPort::new();
    let f = fixture(dir.path(), Some(port.clone())).await;
    let token = f.paired_token(31, vec![Scope::Spend]);
    let (_, mut socket) = f.open(&media_path(&NodeId::from_bytes([8; 32])), Some(&token)).await;
    socket.write_all(&masked_frame(0x02, &vec![0; 3000])).await.unwrap();
    socket.write_all(&masked_frame(0x80, &vec![0; 1101])).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), port.released.notified())
        .await.expect("fragment reassembly exceeded the media limit");
    assert!(port.to_node.is_empty());
}

#[tokio::test]
async fn text_malformed_and_control_floods_share_the_ingress_budget() {
    use tokio::io::AsyncWriteExt;
    for opcode in [0x81, 0x82, 0x89, 0x8a] {
        let dir = tempfile::tempdir().unwrap();
        let port = ObservedPort::new();
        let f = fixture(dir.path(), Some(port.clone())).await;
        let token = f.paired_token(32, vec![Scope::Spend]);
        let (_, mut socket) = f.open(&media_path(&NodeId::from_bytes([8; 32])), Some(&token)).await;
        // Text is deliberately not JSON. Binary is deliberately too short.
        let frame = masked_frame(opcode, b"x");
        socket.write_all(&frame.repeat(101)).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), port.released.notified())
            .await.unwrap_or_else(|_| panic!("opcode {opcode:x} bypassed the ingress budget"));
        assert!(port.to_node.is_empty());
    }
}

#[tokio::test]
async fn non_reading_socket_releases_attachment_on_write_timeout() {
    stalled_socket_releases("timeout").await;
}

#[tokio::test]
async fn call_termination_releases_attachment_while_socket_is_stalled() {
    stalled_socket_releases("ended").await;
}

#[tokio::test]
async fn pairing_revocation_releases_attachment_while_socket_is_stalled() {
    stalled_socket_releases("revoked").await;
}

async fn stalled_socket_releases(reason: &str) {
    use konsensus_api::call_media::MediaFrame;
    use std::time::Duration;
    let dir = tempfile::tempdir().unwrap();
    let port = ObservedPort::new();
    let f = fixture(dir.path(), Some(port.clone())).await;
    let token = f.paired_token(33, vec![Scope::Spend]);
    let (_, socket) = f.open(&media_path(&NodeId::from_bytes([8; 32])), Some(&token)).await;
    // Keep the client alive but never read. A small TCP receive window plus
    // sustained bounded-queue production forces the server's send to stall.
    let output = port.from_node.clone();
    let producer = tokio::spawn(async move {
        loop {
            for seq in 0..32 {
                if output.push(MediaFrame { seq, payload: vec![0; 4096] }).is_err() { return; }
            }
            tokio::task::yield_now().await;
        }
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    match reason {
        "ended" => port.from_node.close(),
        "revoked" => for client in f.service.list_clients() { f.service.revoke(&client.client_id).unwrap(); },
        _ => {}
    }
    // Both termination checks must win before the two-second write deadline.
    let bound = match reason {
        "ended" => Duration::from_millis(300),
        "revoked" => Duration::from_millis(1350),
        _ => Duration::from_secs(3),
    };
    let result = tokio::time::timeout(bound, port.released.notified()).await;
    producer.abort();
    result.unwrap_or_else(|_| panic!("{reason}: stalled send prevented attachment release"));
    assert!(port.to_node.is_closed() && port.from_node.is_closed());
    drop(socket);
}

#[tokio::test]
async fn text_ping_is_ignored_without_a_json_reply() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let dir = tempfile::tempdir().unwrap();
    let port = ObservedPort::new();
    let f = fixture(dir.path(), Some(port.clone())).await;
    let token = f.paired_token(34, vec![Scope::Spend]);
    let (_, mut socket) = f.open(&media_path(&NodeId::from_bytes([8; 32])), Some(&token)).await;
    socket.write_all(&masked_frame(0x81, br#"{"type":"ping"}"#)).await.unwrap();
    let mut byte = [0; 1];
    assert!(tokio::time::timeout(std::time::Duration::from_millis(100), socket.read(&mut byte)).await.is_err(),
        "binary media socket must not parse and answer text JSON");
    assert!(port.to_node.is_empty());
}

#[tokio::test]
async fn socket_ingress_byte_budget_counts_before_routing() {
    use tokio::io::AsyncWriteExt;
    let dir = tempfile::tempdir().unwrap();
    let port = ObservedPort::new();
    let f = fixture(dir.path(), Some(port.clone())).await;
    let token = f.paired_token(35, vec![Scope::Spend]);
    let (_, mut socket) = f.open(&media_path(&NodeId::from_bytes([8; 32])), Some(&token)).await;
    // Every packet is valid and exactly at the per-message limit; the 16th
    // crosses 64 KiB including headers, well below the 100-message limit.
    socket.write_all(&masked_frame(0x82, &vec![0; 4100]).repeat(16)).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), port.released.notified()).await.unwrap();
    assert_eq!(port.to_node.len(), 15);
    assert_eq!(port.to_node.try_pop().unwrap().payload.len(), 4096);
}
