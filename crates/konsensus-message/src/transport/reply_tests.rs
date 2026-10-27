use super::*;

async fn pair() -> (Arc<NoiseTransport>, Arc<NoiseTransport>, NodeId, NodeId) {
    let (_, a) = NodeIdentity::generate().unwrap();
    let (_, b) = NodeIdentity::generate().unwrap();
    let (a, b) = (Arc::new(a), Arc::new(b));
    let (aid, bid) = (*a.node_id(), *b.node_id());
    let config = || TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        admission_mode: ReachabilityMode::PriceOpen,
        ..Default::default()
    };
    let a = Arc::new(NoiseTransport::new(a, config()));
    let b = Arc::new(NoiseTransport::new(b, config()));
    b.start_listener().await.unwrap();
    a.connect(&bid, &b.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !b.is_connected(&aid).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    (a, b, aid, bid)
}

fn refusal() -> Frame {
    Frame::InvoiceError {
        request_id: "request".into(),
        reason: "konsensus:admission_required".into(),
    }
}

#[tokio::test]
async fn budgeted_reconnect_redials_closed_generation_before_reader_cleanup() {
    let (a, b, aid, bid) = pair().await;
    let addr = b.listen_addr().unwrap().to_string();
    let old_generation = a.connected_since(&bid).await.unwrap();
    // Consume the original registrations before waiting for the replacement.
    assert!(matches!(a.recv_control().await, Some(ControlEvent::PeerConnected { .. })));
    assert!(matches!(b.recv_control().await, Some(ControlEvent::PeerConnected { .. })));

    // remove() closes the socket before acquiring the map's write lock. Hold
    // that lock out so the dial observes exactly this real teardown window.
    // This current-thread test polls the dial before any cleanup task can run.
    let peers = a.peers.read().await;
    let old = peers.get(&bid).unwrap().clone();
    old.close();
    assert!(!a.is_connected(&bid).await);
    let reconnect = a.connect(&bid, &addr);
    tokio::pin!(reconnect);
    assert!(
        futures::poll!(&mut reconnect).is_pending(),
        "connect must dial, not return success for a closed map entry"
    );
    drop(peers);

    tokio::time::timeout(Duration::from_secs(5), async {
        reconnect.await.unwrap();
        assert!(matches!(
            b.recv_control().await,
            Some(ControlEvent::PeerConnected { peer_id, .. }) if peer_id == aid
        ));
    }).await.expect("replacement handshake must complete");
    assert!(a.is_connected(&bid).await);
    assert!(b.is_connected(&aid).await);
    assert_ne!(a.connected_since(&bid).await, Some(old_generation));
    // A delayed old reader must not remove the replacement it raced with.
    old.remove(&bid, &a.peers).await;
    assert!(a.is_connected(&bid).await);
    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn control_reply_backpressure_closes_without_waiting_for_connection_lock() {
    let (a, b, aid, bid) = pair().await;
    let conn = b.peers.read().await.get(&aid).unwrap().clone();
    let held = conn.lock().await;
    let mut refused = false;
    for _ in 0..64 {
        let result = tokio::time::timeout(
            Duration::from_millis(100),
            b.enqueue_control_frame(&aid, &refusal()),
        )
        .await
        .expect("enqueue waited for connection I/O");
        if result.is_err() {
            refused = true;
            break;
        }
    }
    assert!(refused, "reply queue must be bounded");
    assert!(
        !b.is_connected(&aid).await,
        "backpressure must remove the connection immediately"
    );
    drop(held);
    tokio::time::timeout(Duration::from_secs(2), async {
        while a.is_connected(&bid).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("backpressure did not close socket");
    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn control_reply_deadline_includes_waiting_for_connection_lock() {
    let (a, b, aid, bid) = pair().await;
    let conn = b.peers.read().await.get(&aid).unwrap().clone();
    let held = conn.lock().await;
    b.enqueue_control_frame(&aid, &refusal()).await.unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        while b.is_connected(&aid).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reply worker did not enforce deadline");
    drop(held);
    tokio::time::timeout(Duration::from_secs(2), async {
        while a.is_connected(&bid).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("deadline did not close socket");
    a.shutdown();
    b.shutdown();
}

#[tokio::test]
async fn admission_payment_guard_lives_until_connection_replacement() {
    let (a, b, aid, bid) = pair().await;
    let generation = a.connected_since(&bid).await.unwrap();
    assert!(!a.admission_paid_on_connection(&bid).await);
    a.mark_admission_paid(&bid, generation).await;
    assert!(a.admission_paid_on_connection(&bid).await);
    b.disconnect(&aid).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while a.is_connected(&bid).await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    a.connect(&bid, &b.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    assert!(!a.admission_paid_on_connection(&bid).await);
    a.mark_admission_paid(&bid, generation).await;
    assert!(
        !a.admission_paid_on_connection(&bid).await,
        "old generation cannot mark replacement paid"
    );
    a.shutdown();
    b.shutdown();
}
