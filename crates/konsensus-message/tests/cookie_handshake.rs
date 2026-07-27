//! Pre-Noise anti-DoS cookie (doorway hardening #2) — end-to-end handshake tests.
//!
//! Covers the operator-opt-in pre-Noise cookie gate at the transport level:
//!
//! 1. **Round-trip.** A cookie-requiring responder and a normal initiator complete
//!    a connection: the initiator transparently answers the self-describing
//!    challenge and the federation handshake succeeds.
//! 2. **Default off is unchanged.** With `CookieMode::Disabled` (the default) the
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
// TEST 2 — default (Disabled) handshake is unchanged (control)
// =============================================================================

#[tokio::test]
async fn default_disabled_handshake_is_unchanged() {
    let alice = make_identity("alice");
    let bob = make_identity("bob");
    let alice_id = *alice.node_id();
    let bob_id = *bob.node_id();

    // Default cookie mode everywhere: no challenge is ever sent.
    let config_bob = make_config(vec![alice_id], CookieMode::default());
    let config_alice = make_config(vec![bob_id], CookieMode::default());
    assert_eq!(CookieMode::default(), CookieMode::Disabled);

    let transport_bob = Arc::new(NoiseTransport::new(Arc::clone(&bob), config_bob));
    transport_bob.start_listener().await.expect("Bob listener");
    let bob_addr = transport_bob.listen_addr().expect("Bob addr");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let transport_alice = NoiseTransport::new(Arc::clone(&alice), config_alice);
    transport_alice
        .connect(&bob_id, &bob_addr.to_string())
        .await
        .expect("default-off connection must succeed unchanged");

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

    let challenge = read_framed(&mut sock).await.expect("must receive a challenge");
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
    let challenge = read_framed(&mut sock).await.expect("must receive a challenge");
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
