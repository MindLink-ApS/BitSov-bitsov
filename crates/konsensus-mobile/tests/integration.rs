//! Integration test: pair mobile client to a local Noise echo server over WS.
//!
//! Spins up an in-process echo server (Noise responder) and connects to it
//! with `NoiseWssTransport` (Noise initiator). Verifies the full handshake,
//! round-trip message delivery, and payload-too-large rejection.

use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;

use konsensus_mobile::{
    derive_public_key, generate_x25519_keypair, MobileClient, MobileNodeConfig, MobileSession,
    error::MobileError,
    transport::NoiseWssTransport,
};

async fn bind_random() -> (TcpListener, SocketAddr) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    (l, a)
}

/// Minimal echo server: accepts one WS connection, completes Noise handshake,
/// echoes every received message back until the client closes.
async fn echo_server(listener: TcpListener, server_key: [u8; 32]) {
    let (stream, _) = listener.accept().await.expect("accept");
    let mut t: NoiseWssTransport = NoiseWssTransport::accept(stream, &server_key)
        .await
        .expect("echo server handshake failed");
    loop {
        match t.recv().await {
            Ok(msg) => t.send(&msg).await.expect("echo send"),
            Err(MobileError::ConnectionClosed) => break,
            Err(e) => panic!("echo server error: {e}"),
        }
    }
}

#[tokio::test]
async fn test_handshake_and_echo() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("konsensus_mobile=debug")
        .with_test_writer()
        .try_init();

    let server_kp = generate_x25519_keypair();
    let client_kp = generate_x25519_keypair();
    let server_private: [u8; 32] = server_kp.private_key.clone().try_into().unwrap();
    let server_public: Vec<u8> = server_kp.public_key.clone();

    let (listener, addr) = bind_random().await;
    tokio::spawn(echo_server(listener, server_private));
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let session: Arc<MobileSession> = MobileClient::new(MobileNodeConfig {
        endpoint: format!("ws://{addr}"),
        static_private_key: client_kp.private_key,
    })
    .connect()
    .await
    .expect("connect failed");

    assert_eq!(session.remote_static_key(), server_public, "remote key mismatch");

    // Small payload round-trip.
    let msg = b"hello from mobile".to_vec();
    session.send(msg.clone()).await.expect("send");
    assert_eq!(session.recv().await.expect("recv"), msg);

    // 1 KiB round-trip.
    let big: Vec<u8> = (0u8..=255).cycle().take(1024).collect();
    session.send(big.clone()).await.expect("send big");
    assert_eq!(session.recv().await.expect("recv big"), big);
}

#[tokio::test]
async fn test_keypair_roundtrip() {
    let kp = generate_x25519_keypair();
    assert_eq!(kp.private_key.len(), 32);
    assert_eq!(kp.public_key.len(), 32);
    let derived = derive_public_key(kp.private_key.clone()).unwrap();
    assert_eq!(derived, kp.public_key);
}

#[tokio::test]
async fn test_payload_too_large() {
    let server_kp = generate_x25519_keypair();
    let client_kp = generate_x25519_keypair();
    let server_private: [u8; 32] = server_kp.private_key.try_into().unwrap();

    let (listener, addr) = bind_random().await;
    tokio::spawn(echo_server(listener, server_private));
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;

    let session: Arc<MobileSession> = MobileClient::new(MobileNodeConfig {
        endpoint: format!("ws://{addr}"),
        static_private_key: client_kp.private_key,
    })
    .connect()
    .await
    .unwrap();

    // 65520 bytes exceeds MAX_NOISE_PAYLOAD (65519).
    let oversized = vec![0u8; 65_520];
    assert!(matches!(
        session.send(oversized).await,
        Err(MobileError::PayloadTooLarge { .. })
    ));
}
