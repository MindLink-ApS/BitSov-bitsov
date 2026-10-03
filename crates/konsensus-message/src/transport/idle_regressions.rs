//! Regression coverage for raw introduction dials (no supervisor keepalive).
use super::tests::{make_identity, TEST_MNEMONIC_A, TEST_MNEMONIC_B};
use super::*;

async fn pair() -> (NoiseTransport, NoiseTransport, NodeId, NodeId) {
    let a = make_identity(TEST_MNEMONIC_A);
    let b = make_identity(TEST_MNEMONIC_B);
    let aid = *a.node_id();
    let bid = *b.node_id();
    let config = TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admission_mode: ReachabilityMode::PriceOpen,
        ..Default::default()
    };
    let a = NoiseTransport::new(a, config.clone());
    let b = NoiseTransport::new(b, config);
    b.start_listener().await.unwrap();
    a.connect(&bid, &b.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    (a, b, aid, bid)
}

#[tokio::test]
async fn raw_acceptor_and_dialer_survive_sixty_seconds_idle() {
    let (a, b, aid, bid) = pair().await;
    let ab = a.connected_since(&bid).await.unwrap();
    let ba = b.connected_since(&aid).await.unwrap();
    tokio::time::sleep(Duration::from_secs(65)).await;
    assert_eq!(a.connected_since(&bid).await, Some(ab));
    assert_eq!(b.connected_since(&aid).await, Some(ba));
    assert!(
        !a.peers
            .read()
            .await
            .get(&bid)
            .unwrap()
            .lock()
            .await
            .privileged
    );
    assert!(
        !b.peers
            .read()
            .await
            .get(&aid)
            .unwrap()
            .lock()
            .await
            .privileged
    );
    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn introduction_only_stranger_is_not_redialed() {
    let (a, b, _aid, bid) = pair().await;
    a.disconnect(&bid).await.unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert!(!a.is_connected(&bid).await);
    a.shutdown();
    b.shutdown();
}

async fn wait_reconnected(a: &NoiseTransport, peer: NodeId, old: Instant) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if a.connected_since(&peer).await.is_some_and(|now| now != old) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("eligible peer must reconnect after forced drop");
}

#[tokio::test]
async fn operation_reconnects_then_releases_stranger() {
    let (a, b, _aid, bid) = pair().await;
    let operation = a.retain_peer(&bid).await.unwrap();
    let old = a.connected_since(&bid).await.unwrap();
    a.disconnect(&bid).await.unwrap();
    wait_reconnected(&a, bid, old).await;
    assert!(
        a.connected_privileged_peers().await.is_empty(),
        "retry must not grant admission"
    );
    drop(operation);
    a.disconnect(&bid).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!a.is_connected(&bid).await);
    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn live_session_reconnects_without_contact_or_auto_connect() {
    let (a, b, _aid, bid) = pair().await;
    let sessions = Arc::new(konsensus_crypto::SessionManager::new(a.identity.clone()));
    let recipient = konsensus_crypto::SessionManager::new(b.identity.clone());
    sessions
        .initiate_session(&bid, &recipient.prekey_bundle().await)
        .await
        .unwrap();
    a.set_reconnect_sessions(&sessions);
    let old = a.connected_since(&bid).await.unwrap();
    a.disconnect(&bid).await.unwrap();
    wait_reconnected(&a, bid, old).await;
    assert!(a.connected_privileged_peers().await.is_empty());
    sessions.remove_session(&bid).await;
    a.disconnect(&bid).await.unwrap();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!a.is_connected(&bid).await);
    a.shutdown();
    b.shutdown();
}

/// A manual initiator never sends a Ping. The production acceptor must initiate
/// keepalives itself, rather than accidentally relying on the dialer's task.
#[tokio::test]
async fn acceptor_pings_a_passive_initiator_for_over_sixty_seconds() {
    let identity = make_identity(TEST_MNEMONIC_A);
    let config = TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admission_mode: ReachabilityMode::PriceOpen,
        ..Default::default()
    };
    let b = NoiseTransport::new(make_identity(TEST_MNEMONIC_B), config.clone());
    b.start_listener().await.unwrap();
    let stream = TcpStream::connect(b.listen_addr().unwrap()).await.unwrap();
    let (reader, writer) = stream.into_split();
    let (reader, writer, noise) =
        handshake::noise_handshake_initiator(reader, writer, *identity.x25519_secret_bytes())
            .await
            .unwrap();
    let (_, _, _, mut reader, mut writer, mut noise) =
        handshake::perform_federation_handshake_initiator(
            reader, writer, noise, &identity, &config,
        )
        .await
        .unwrap();
    let started = Instant::now();
    let mut pings = 0;
    while started.elapsed() < Duration::from_secs(65) {
        let encrypted = read_noise_message(&mut reader)
            .await
            .expect("acceptor must ping without dialer supervision");
        let frame = Frame::from_bytes(&noise.decrypt(&encrypted).unwrap()).unwrap();
        if let Frame::Ping { nonce } = frame {
            pings += 1;
            let pong = noise
                .encrypt(&Frame::Pong { nonce }.to_bytes().unwrap())
                .unwrap();
            write_noise_message(&mut writer, &pong).await.unwrap();
        }
    }
    assert!(pings >= 6);
    assert!(b.is_connected(identity.node_id()).await);
    b.shutdown();
}

#[tokio::test(start_paused = true)]
async fn silent_or_partial_peer_still_times_out_at_thirty_seconds() {
    for partial in [false, true] {
        let (mut peer, mut reader) = tokio::io::duplex(64);
        if partial {
            peer.write_all(&[0, 0]).await.unwrap();
        }
        let start = tokio::time::Instant::now();
        let result = read_noise_message(&mut reader).await;
        assert!(
            matches!(result, Err(WireError::Io(ref e)) if e.kind() == std::io::ErrorKind::TimedOut)
        );
        assert_eq!(start.elapsed(), Duration::from_secs(30));
    }
}

#[tokio::test]
async fn busy_local_writer_is_not_a_one_second_keepalive_failure() {
    let (a, b, _aid, bid) = pair().await;
    let conn = a.peers.read().await.get(&bid).unwrap().clone();
    let since = a.connected_since(&bid).await;
    // Hold the writer across the first ping tick. Neither direction has
    // approached its 30-second read deadline.
    let writer = conn.lock().await;
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert_eq!(a.connected_since(&bid).await, since);
    drop(writer);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(a.connected_since(&bid).await, since);
    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn simultaneous_contact_dials_converge_on_one_live_generation() {
    let ia = make_identity(TEST_MNEMONIC_A);
    let ib = make_identity(TEST_MNEMONIC_B);
    let aid = *ia.node_id();
    let bid = *ib.node_id();
    let config = TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admission_mode: ReachabilityMode::PriceOpen,
        ..Default::default()
    };
    let a = NoiseTransport::new(ia, config.clone());
    let b = NoiseTransport::new(ib, config);
    a.start_listener().await.unwrap();
    b.start_listener().await.unwrap();
    let aa = a.listen_addr().unwrap().to_string();
    let ba = b.listen_addr().unwrap().to_string();
    let (ab, ba_result) = tokio::join!(a.connect(&bid, &ba), b.connect(&aid, &aa));
    ab.unwrap();
    ba_result.unwrap();
    a.supervise_peer(&bid, &ba).await;
    b.supervise_peer(&aid, &aa).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let ab = a.connected_since(&bid).await.unwrap();
    let ba = b.connected_since(&aid).await.unwrap();
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert_eq!(a.connected_since(&bid).await, Some(ab));
    assert_eq!(b.connected_since(&aid).await, Some(ba));
    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn cancelled_disconnect_closes_untracked_generation() {
    let (a, b, _aid, bid) = pair().await;
    let a = Arc::new(a);
    let conn = a.peers.read().await.get(&bid).unwrap().clone();
    let writer = conn.lock().await;
    let dialer = a.clone();
    let disconnect = tokio::spawn(async move { dialer.disconnect(&bid).await });
    tokio::time::timeout(Duration::from_millis(500), async {
        while a.is_connected(&bid).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    disconnect.abort();
    assert!(disconnect.await.unwrap_err().is_cancelled());
    assert!(
        conn.is_closed(),
        "cancelled disconnect must stop the old reader and keepalive"
    );
    drop(writer);
    a.shutdown();
    b.shutdown();
}
