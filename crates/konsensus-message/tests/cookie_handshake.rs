//! Pre-Noise anti-DoS cookie (doorway hardening #2) — end-to-end handshake tests.
//!
//! Covers the adaptive and required pre-Noise cookie gate at the transport level:
//!
//! 1. **Round-trip.** A cookie-requiring responder and a normal initiator complete
//!    a connection: the initiator transparently answers the self-describing
//!    challenge and the federation handshake succeeds.
//! 2. **Idle path is unchanged.** With `CookieMode::Adaptive` (the default) the
//!    handshake is byte-identical to pre-cookie — the control case.
//! 3. **Flood rejection.** A raw client that connects to a cookie-requiring node
//!    but cannot echo a valid cookie is dropped *before* the node spends a Noise
//!    DH, and is never registered as a peer. The challenge it receives is the
//!    self-describing `BSc1` frame (recognizable without prior negotiation).

use std::sync::Arc;

use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::NodeId;
use konsensus_message::wire::{Capability, SovereigntyTier};
use konsensus_message::{CookieMode, NoiseTransport, ReachabilityMode, TransportConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

fn make_identity(passphrase: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(MNEMONIC, passphrase).unwrap())
}

fn make_config(whitelist: Vec<NodeId>, cookie_mode: CookieMode) -> TransportConfig {
    TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        tier: SovereigntyTier::T1,
        capabilities: vec![Capability::X3dh],
        whitelist,
        version: 2,
        admission_mode: ReachabilityMode::Whitelist,
        cookie_mode,
        dos_edge: Default::default(),
    }
}

/// Write a length-prefixed (4-byte big-endian) frame, matching the transport's
/// internal framing.
async fn write_framed(stream: &mut tokio::net::TcpStream, data: &[u8]) {
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await.unwrap();
    stream.write_all(data).await.unwrap();
    stream.flush().await.unwrap();
}

/// Read one length-prefixed frame.
async fn read_framed(stream: &mut tokio::net::TcpStream) -> std::io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

// =============================================================================
// TEST 1 — cookie-requiring responder accepts a normal initiator (round-trip)
// =============================================================================

#[tokio::test]
async fn cookie_required_responder_accepts_initiator() {
    let alice = make_identity("alice");
    let bob = make_identity("bob");
    let alice_id = *alice.node_id();
    let bob_id = *bob.node_id();

    // Bob requires the pre-Noise cookie; both whitelist each other.
    let config_bob = make_config(vec![alice_id], CookieMode::Required);
    let config_alice = make_config(vec![bob_id], CookieMode::Disabled);

    let transport_bob = Arc::new(NoiseTransport::new(Arc::clone(&bob), config_bob));
    transport_bob.start_listener().await.expect("Bob listener");
    let bob_addr = transport_bob.listen_addr().expect("Bob addr");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let transport_alice = NoiseTransport::new(Arc::clone(&alice), config_alice);

    // Alice does not know Bob requires a cookie; she sends an optimistic Noise
    // message-1, receives the self-describing challenge, answers it, and the
    // handshake completes.
    transport_alice
        .connect(&bob_id, &bob_addr.to_string())
        .await
        .expect("cookie round-trip connection must succeed");

    assert!(
        transport_alice.is_connected(&bob_id).await,
        "Alice must be connected after answering the cookie challenge"
    );
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert!(
        transport_bob.is_connected(&alice_id).await,
        "Bob must register Alice after a valid cookie + handshake"
    );

    transport_bob.shutdown();
}

// =============================================================================
// TEST 2 — default (Adaptive) idle handshake is unchanged (control)
// =============================================================================

#[tokio::test]
async fn default_adaptive_handshake_is_unchanged_when_idle() {
    let alice = make_identity("alice");
    let bob = make_identity("bob");
    let alice_id = *alice.node_id();
    let bob_id = *bob.node_id();

    // Default cookie mode everywhere: no challenge is ever sent.
    let config_bob = make_config(vec![alice_id], CookieMode::default());
    let config_alice = make_config(vec![bob_id], CookieMode::default());
    assert_eq!(CookieMode::default(), CookieMode::Adaptive);

    let transport_bob = Arc::new(NoiseTransport::new(Arc::clone(&bob), config_bob));
    transport_bob.start_listener().await.expect("Bob listener");
    let bob_addr = transport_bob.listen_addr().expect("Bob addr");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let transport_alice = NoiseTransport::new(Arc::clone(&alice), config_alice);
    transport_alice
        .connect(&bob_id, &bob_addr.to_string())
        .await
        .expect("idle connection must succeed unchanged");

    assert!(transport_alice.is_connected(&bob_id).await);
    transport_bob.shutdown();
}

// =============================================================================
// TEST 3 — a client that cannot answer the cookie is rejected before any DH
// =============================================================================

#[tokio::test]
async fn cookie_required_rejects_client_that_cannot_answer() {
    let bob = make_identity("bob");
    let attacker = make_identity("attacker");
    let attacker_id = *attacker.node_id();

    let config_bob = make_config(vec![attacker_id], CookieMode::Required);
    let transport_bob = Arc::new(NoiseTransport::new(Arc::clone(&bob), config_bob));
    transport_bob.start_listener().await.expect("Bob listener");
    let bob_addr = transport_bob.listen_addr().expect("Bob addr");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // Raw client: connect and send a bogus first blob (as an optimistic Noise
    // message-1 would be), then observe the self-describing challenge.
    let mut sock = tokio::net::TcpStream::connect(bob_addr).await.unwrap();
    write_framed(&mut sock, &[0x42u8; 32]).await;

    let challenge = read_framed(&mut sock)
        .await
        .expect("must receive a challenge");
    assert_eq!(
        &challenge[0..4],
        b"BSc1",
        "the pre-Noise challenge must be self-describing (BSc1 magic)"
    );
    assert_eq!(challenge.len(), 38, "fixed cookie frame size");
    assert_eq!(challenge[4], 1, "kind byte = challenge");
    assert_eq!(challenge[5], 0, "difficulty must be 0 (no active PoW)");

    // Answer with a tampered cookie (flip the MAC region) → must be rejected.
    let mut bad = challenge.clone();
    bad[4] = 2; // mark as a response
    bad[14] ^= 0xFF; // corrupt the MAC
    write_framed(&mut sock, &bad).await;

    // The responder rejects before any Noise DH: the next read yields EOF/error.
    let after = read_framed(&mut sock).await;
    assert!(
        after.is_err(),
        "an invalid cookie must drop the connection before the Noise handshake"
    );

    // And the unproven client is never registered as a peer.
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert!(
        !transport_bob.is_connected(&attacker_id).await,
        "a client that cannot answer the cookie must not be admitted"
    );

    transport_bob.shutdown();
}

// =============================================================================
// TEST 4 — oversized pre-Noise frame is refused without allocating (#302 #1)
// =============================================================================

#[tokio::test]
async fn oversized_pre_noise_frame_is_refused() {
    let bob = make_identity("bob");
    let attacker_id = *make_identity("attacker").node_id();

    let config_bob = make_config(vec![attacker_id], CookieMode::Required);
    let transport_bob = Arc::new(NoiseTransport::new(Arc::clone(&bob), config_bob));
    transport_bob.start_listener().await.expect("Bob listener");
    let bob_addr = transport_bob.listen_addr().expect("Bob addr");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut sock = tokio::net::TcpStream::connect(bob_addr).await.unwrap();
    // Claim a 16 MiB pre-Noise frame but send no payload. A cookie-mode node must
    // refuse on the length prefix ALONE (bounded pre-Noise reader) — it must not
    // allocate the buffer or block waiting for 16 MiB from an unproven source.
    let huge: u32 = 16 * 1024 * 1024;
    sock.write_all(&huge.to_be_bytes()).await.unwrap();
    sock.flush().await.unwrap();

    // The responder rejects and drops promptly; our next read yields EOF/error.
    let after = read_framed(&mut sock).await;
    assert!(
        after.is_err(),
        "an oversized pre-Noise frame must be refused on the length prefix alone"
    );

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert!(
        !transport_bob.is_connected(&attacker_id).await,
        "a source sending an oversized pre-Noise frame must not be admitted"
    );

    transport_bob.shutdown();
}

// =============================================================================
// TEST 5 — a response with a reserved (PoW) field set is rejected (#302 #3)
// =============================================================================

#[tokio::test]
async fn cookie_response_with_reserved_field_set_is_rejected() {
    let bob = make_identity("bob");
    let attacker_id = *make_identity("attacker").node_id();

    let config_bob = make_config(vec![attacker_id], CookieMode::Required);
    let transport_bob = Arc::new(NoiseTransport::new(Arc::clone(&bob), config_bob));
    transport_bob.start_listener().await.expect("Bob listener");
    let bob_addr = transport_bob.listen_addr().expect("Bob addr");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let mut sock = tokio::net::TcpStream::connect(bob_addr).await.unwrap();
    write_framed(&mut sock, &[0x42u8; 32]).await; // optimistic first blob
    let challenge = read_framed(&mut sock)
        .await
        .expect("must receive a challenge");
    assert_eq!(&challenge[0..4], b"BSc1");

    // Echo the (valid) cookie MAC verbatim but set the reserved difficulty byte.
    // v1 carries no PoW, so even a MAC-valid response must be rejected.
    let mut resp = challenge.clone();
    resp[4] = 2; // kind = response
    resp[5] = 1; // difficulty (reserved) != 0
    write_framed(&mut sock, &resp).await;

    let after = read_framed(&mut sock).await;
    assert!(
        after.is_err(),
        "a MAC-valid response with a non-zero reserved field must still be rejected"
    );

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert!(
        !transport_bob.is_connected(&attacker_id).await,
        "a reserved-field-setting client must not be admitted"
    );

    transport_bob.shutdown();
}

/// Saturating the optimistic lane must trigger a cookie, not consume the
/// capacity reserved for a responsive peer. A normal peer completes both
/// cookie and Noise exchanges while the slow clients remain connected.
#[tokio::test]
async fn adaptive_cookie_preserves_capacity_for_honest_peer() {
    let alice = make_identity("adaptive-alice");
    let bob = make_identity("adaptive-bob");
    let mut config = make_config(vec![*alice.node_id()], CookieMode::Adaptive);
    config.dos_edge.cookie_threshold = 2;
    config.dos_edge.max_handshakes = 4;
    config.dos_edge.max_per_subnet = 4;
    config.dos_edge.max_per_ip = 4;
    let bob_transport = NoiseTransport::new(bob.clone(), config);
    bob_transport.start_listener().await.unwrap();
    let addr = bob_transport.listen_addr().unwrap();
    let mut slow = Vec::new();
    for _ in 0..2 {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        // A real message 1 guarantees the listener admitted this socket.
        let mut noise =
            konsensus_crypto::noise::NoiseSession::initiator(alice.x25519_secret_bytes()).unwrap();
        write_framed(&mut socket, &noise.write_handshake(&[]).unwrap()).await;
        let reply = read_framed(&mut socket).await.unwrap();
        assert_ne!(&reply[..4], b"BSc1");
        slow.push(socket); // never finish message 3
    }
    let mut probe = tokio::net::TcpStream::connect(addr).await.unwrap();
    write_framed(&mut probe, &[42; 32]).await;
    let challenge = read_framed(&mut probe).await.unwrap();
    assert_eq!(&challenge[..4], b"BSc1");
    drop(probe);
    let alice_transport = NoiseTransport::new(
        alice.clone(),
        make_config(vec![*bob.node_id()], CookieMode::Adaptive),
    );
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        alice_transport.connect(bob.node_id(), &addr.to_string()),
    )
    .await
    .unwrap()
    .expect("honest peer must complete cookie and Noise under load");
    assert!(alice_transport.is_connected(bob.node_id()).await);
    bob_transport.shutdown();
}

#[tokio::test]
async fn single_source_connection_flood_is_refused_before_noise() {
    let bob = make_identity("rate-bob");
    let mut config = make_config(vec![], CookieMode::Required);
    config.dos_edge.connection_burst = 2;
    config.dos_edge.connections_per_second = 0.01;
    let transport = NoiseTransport::new(bob, config);
    transport.start_listener().await.unwrap();
    let addr = transport.listen_addr().unwrap();
    for _ in 0..2 {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_framed(&mut socket, &[42; 32]).await;
        assert_eq!(&read_framed(&mut socket).await.unwrap()[..4], b"BSc1");
    }
    for _ in 0..8 {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut byte = [0];
        let read = tokio::time::timeout(std::time::Duration::from_secs(1), socket.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(read, Ok(0) | Err(_)),
            "rate refusal must happen before reading message 1"
        );
    }
    transport.shutdown();
}

async fn answer_cookie(socket: &mut tokio::net::TcpStream) {
    write_framed(socket, &[42; 32]).await;
    let mut challenge = read_framed(socket).await.unwrap();
    assert_eq!(&challenge[..4], b"BSc1");
    challenge[4] = 2;
    write_framed(socket, &challenge).await;
}

#[tokio::test]
async fn global_noise_cap_applies_even_to_valid_cookies() {
    let bob = make_identity("global-cap");
    let mut config = make_config(vec![], CookieMode::Required);
    config.dos_edge.max_handshakes = 2;
    config.dos_edge.cookie_threshold = 1;
    let transport = NoiseTransport::new(bob.clone(), config);
    transport.start_listener().await.unwrap();
    let addr = transport.listen_addr().unwrap();
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        answer_cookie(&mut socket).await;
        let mut noise =
            konsensus_crypto::noise::NoiseSession::initiator(bob.x25519_secret_bytes()).unwrap();
        write_framed(&mut socket, &noise.write_handshake(&[]).unwrap()).await;
        assert_ne!(&read_framed(&mut socket).await.unwrap()[..4], b"BSc1");
        held.push(socket);
    }
    let mut excess = tokio::net::TcpStream::connect(addr).await.unwrap();
    answer_cookie(&mut excess).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), read_framed(&mut excess))
            .await
            .unwrap()
            .is_err()
    );
    transport.shutdown();
}

#[tokio::test]
async fn pending_cookie_sockets_are_bounded_and_shutdown_releases_them() {
    let mut config = make_config(vec![], CookieMode::Required);
    config.dos_edge.max_pending = 2;
    config.dos_edge.max_handshakes = 2;
    config.dos_edge.cookie_threshold = 1;
    let transport = NoiseTransport::new(make_identity("pending-cap"), config);
    transport.start_listener().await.unwrap();
    let addr = transport.listen_addr().unwrap();
    let mut held = Vec::new();
    for _ in 0..2 {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_framed(&mut socket, &[42; 32]).await;
        assert_eq!(&read_framed(&mut socket).await.unwrap()[..4], b"BSc1");
        held.push(socket);
    }
    for _ in 0..20 {
        let mut excess = tokio::net::TcpStream::connect(addr).await.unwrap();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), read_framed(&mut excess)).await;
        assert!(
            result.unwrap().is_err(),
            "excess socket must close without waiting for a cookie or Noise"
        );
    }
    transport.shutdown();
    for mut socket in held {
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), read_framed(&mut socket))
                .await
                .unwrap()
                .is_err()
        );
    }
}

#[tokio::test]
async fn unanswered_cookie_expires_and_frees_capacity() {
    let mut config = make_config(vec![], CookieMode::Required);
    config.dos_edge.cookie_timeout_secs = 1;
    config.dos_edge.max_per_ip = 1;
    let transport = NoiseTransport::new(make_identity("cookie-deadline"), config);
    transport.start_listener().await.unwrap();
    let addr = transport.listen_addr().unwrap();
    let mut slow = tokio::net::TcpStream::connect(addr).await.unwrap();
    write_framed(&mut slow, &[42; 32]).await;
    assert_eq!(&read_framed(&mut slow).await.unwrap()[..4], b"BSc1");
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), read_framed(&mut slow))
            .await
            .unwrap()
            .is_err()
    );
    let mut next = tokio::net::TcpStream::connect(addr).await.unwrap();
    write_framed(&mut next, &[42; 32]).await;
    assert_eq!(&read_framed(&mut next).await.unwrap()[..4], b"BSc1");
    transport.shutdown();
}

#[tokio::test]
async fn valid_cookie_does_not_bypass_source_handshake_rate() {
    let identity = make_identity("handshake-rate");
    let mut config = make_config(vec![], CookieMode::Required);
    config.dos_edge.handshake_burst = 1;
    config.dos_edge.handshakes_per_second = 0.001;
    let transport = NoiseTransport::new(identity.clone(), config);
    transport.start_listener().await.unwrap();
    let addr = transport.listen_addr().unwrap();
    let mut first = tokio::net::TcpStream::connect(addr).await.unwrap();
    answer_cookie(&mut first).await;
    let mut noise =
        konsensus_crypto::noise::NoiseSession::initiator(identity.x25519_secret_bytes()).unwrap();
    write_framed(&mut first, &noise.write_handshake(&[]).unwrap()).await;
    assert_ne!(&read_framed(&mut first).await.unwrap()[..4], b"BSc1");
    drop(first);
    let mut next = tokio::net::TcpStream::connect(addr).await.unwrap();
    answer_cookie(&mut next).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), read_framed(&mut next))
            .await
            .unwrap()
            .is_err(),
        "valid cookie must still be refused before a second Noise handshake"
    );
    transport.shutdown();
}

#[tokio::test]
async fn total_deadline_does_not_restart_after_cookie() {
    let identity = make_identity("total-deadline");
    let mut config = make_config(vec![], CookieMode::Required);
    config.dos_edge.cookie_timeout_secs = 2;
    config.dos_edge.handshake_timeout_secs = 2;
    let transport = NoiseTransport::new(identity.clone(), config);
    transport.start_listener().await.unwrap();
    let mut socket = tokio::net::TcpStream::connect(transport.listen_addr().unwrap())
        .await
        .unwrap();
    write_framed(&mut socket, &[42; 32]).await;
    let mut challenge = read_framed(&mut socket).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    challenge[4] = 2;
    write_framed(&mut socket, &challenge).await;
    let mut noise =
        konsensus_crypto::noise::NoiseSession::initiator(identity.x25519_secret_bytes()).unwrap();
    write_framed(&mut socket, &noise.write_handshake(&[]).unwrap()).await;
    assert_ne!(&read_framed(&mut socket).await.unwrap()[..4], b"BSc1");
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(1200),
            read_framed(&mut socket)
        )
        .await
        .unwrap()
        .is_err(),
        "cookie time must count toward the total handshake deadline"
    );
    transport.shutdown();
}

#[tokio::test]
async fn paid_connection_keeps_delivering_during_source_flood() {
    use konsensus_message::{wire::Frame, ControlEvent};
    let alice = make_identity("paid-alice");
    let bob = make_identity("paid-bob");
    let mut config = make_config(vec![], CookieMode::Required);
    config.admission_mode = ReachabilityMode::PriceOpen;
    let responder = NoiseTransport::new(bob.clone(), config);
    responder.start_listener().await.unwrap();
    let addr = responder.listen_addr().unwrap();
    let initiator = NoiseTransport::new(
        alice.clone(),
        make_config(vec![*bob.node_id()], CookieMode::Adaptive),
    );
    initiator
        .connect(bob.node_id(), &addr.to_string())
        .await
        .unwrap();
    assert!(matches!(
        responder.recv_control().await,
        Some(ControlEvent::PeerConnected {
            privileged: false,
            ..
        })
    ));
    // Exercise the transport transition called after the application verifies
    // settled payment; payment-proof validation is covered by the node suite.
    assert!(responder.promote_to_privileged(alice.node_id()).await);
    let mut flood = Vec::new();
    for _ in 0..4 {
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        write_framed(&mut socket, &[42; 32]).await;
        assert_eq!(&read_framed(&mut socket).await.unwrap()[..4], b"BSc1");
        flood.push(socket);
    }
    let mut excess = tokio::net::TcpStream::connect(addr).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), read_framed(&mut excess))
            .await
            .unwrap()
            .is_err()
    );
    let frame = Frame::SessionInit {
        init_data: serde_json::json!({"test": "paid delivery"}),
    };
    initiator
        .send_raw_frame(bob.node_id(), &frame.to_bytes().unwrap())
        .await
        .unwrap();
    let event = tokio::time::timeout(std::time::Duration::from_secs(1), responder.recv_control())
        .await
        .unwrap();
    assert!(
        matches!(event, Some(ControlEvent::SessionInit { peer_id, privileged: true, .. }) if peer_id == *alice.node_id())
    );
    assert!(responder.is_connected(alice.node_id()).await);
    responder.shutdown();
    initiator.shutdown();
}
