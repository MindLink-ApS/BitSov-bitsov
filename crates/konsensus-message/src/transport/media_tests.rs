//! Media admission and backpressure over real Noise/TCP connections.
use super::*;
use tokio::io::AsyncReadExt;

const CALL: &str = "00112233445566778899aabbccddeeff";

fn open_transport() -> NoiseTransport {
    NoiseTransport::new(
        Arc::new(NodeIdentity::generate().unwrap().1),
        TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            admission_mode: ReachabilityMode::PriceOpen,
            ..Default::default()
        },
    )
}

// A control frame on the same ordered stream proves all earlier media was
// processed, without draining the media queue or relying on a sleep.
async fn barrier(sender: &NoiseTransport, receiver: &NoiseTransport) {
    sender
        .send_frame(receiver.identity.node_id(), &Frame::PriceQuery { kind: 0 })
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(ControlEvent::PriceQueryReceived { peer_id, .. }) =
                receiver.recv_control().await
            {
                assert_eq!(&peer_id, sender.identity.node_id());
                break;
            }
        }
    })
    .await
    .expect("reader processed the stream");
}

#[tokio::test]
async fn unpaid_media_flood_does_not_block_paid_call_media() {
    flood_does_not_block_paid_call(false).await;
}

#[tokio::test]
async fn privileged_media_flood_cannot_fill_the_shared_queue() {
    flood_does_not_block_paid_call(true).await;
}

#[tokio::test]
async fn reconnect_with_queued_media_preserves_identity_quota_and_other_paid_media() {
    const OTHER_CALL: &str = "ffeeddccbbaa99887766554433221100";
    let receiver = open_transport();
    let flooder = open_transport();
    let paid = open_transport();
    receiver.start_listener().await.unwrap();
    flooder.start_listener().await.unwrap();
    let addr = receiver.listen_addr().unwrap().to_string();
    let receiver_id = receiver.identity.node_id();
    let flooder_id = flooder.identity.node_id();
    paid.connect(receiver_id, &addr).await.unwrap();
    barrier(&paid, &receiver).await;
    let paid_id = paid.identity.node_id();
    let since = receiver.connected_since(paid_id).await.unwrap();
    receiver.mark_admission_paid(paid_id, since).await;

    for generation in 0..3 {
        // Exercise both accepting and dialing the replacement connection.
        if generation == 1 {
            receiver
                .connect(flooder_id, &flooder.listen_addr().unwrap().to_string())
                .await
                .unwrap();
        } else {
            flooder.connect(receiver_id, &addr).await.unwrap();
        }
        barrier(&flooder, &receiver).await;
        assert!(receiver.promote_to_privileged(flooder_id).await);
        for seq in 0..1024 {
            flooder
                .send_frame(
                    receiver_id,
                    &Frame::call_media(CALL, generation * 1024 + seq, vec![1]).unwrap(),
                )
                .await
                .unwrap();
        }
        barrier(&flooder, &receiver).await;
        assert_eq!(
            receiver.call_media_rx.lock().await.len(),
            64,
            "reconnect must not add quota while old frames remain queued"
        );
        if generation < 2 {
            flooder.disconnect(receiver_id).await.unwrap();
            receiver.disconnect(flooder_id).await.unwrap();
        }
    }

    paid.send_frame(
        receiver_id,
        &Frame::call_media(OTHER_CALL, 42, vec![4, 2]).unwrap(),
    )
    .await
    .unwrap();
    barrier(&paid, &receiver).await;
    assert_eq!(receiver.call_media_rx.lock().await.len(), 65);
    for _ in 0..64 {
        let event = receiver.recv_call_media().await.unwrap();
        assert_eq!(event.peer_id, *flooder_id);
        assert!(event.seq < 1024, "replacement bypassed the old backlog");
    }
    let event = receiver.recv_call_media().await.unwrap();
    assert_eq!(event.peer_id, *paid_id);
    assert_eq!(event.call_id, OTHER_CALL);
    assert_eq!(event.data, [4, 2]);
    assert!(event.privileged);

    // Draining old generations releases quota for the current connection.
    tokio::time::sleep(Duration::from_millis(20)).await;
    flooder
        .send_frame(receiver_id, &Frame::call_media(CALL, 4096, vec![8]).unwrap())
        .await
        .unwrap();
    barrier(&flooder, &receiver).await;
    let event = tokio::time::timeout(Duration::from_secs(5), receiver.recv_call_media())
        .await
        .expect("old queue permits must be reusable after dequeue")
        .unwrap();
    assert_eq!(event.peer_id, *flooder_id);
    assert_eq!(event.seq, 4096);
    receiver.shutdown();
    flooder.shutdown();
    paid.shutdown();
}

async fn flood_does_not_block_paid_call(promote_flooder: bool) {
    let receiver = open_transport();
    let flooder = open_transport();
    let paid = open_transport();
    receiver.start_listener().await.unwrap();
    let addr = receiver.listen_addr().unwrap().to_string();
    let receiver_id = receiver.identity.node_id();
    flooder.connect(receiver_id, &addr).await.unwrap();
    paid.connect(receiver_id, &addr).await.unwrap();
    barrier(&flooder, &receiver).await;
    barrier(&paid, &receiver).await;
    if promote_flooder {
        assert!(
            receiver
                .promote_to_privileged(flooder.identity.node_id())
                .await
        );
    }
    // Exercise admission_paid independently of privilege.
    let paid_id = paid.identity.node_id();
    let since = receiver.connected_since(paid_id).await.unwrap();
    receiver.mark_admission_paid(paid_id, since).await;
    for seq in 0..1024 {
        flooder
            .send_frame(receiver_id, &Frame::call_media(CALL, seq, vec![1]).unwrap())
            .await
            .unwrap();
    }
    barrier(&flooder, &receiver).await;
    if !promote_flooder {
        assert_eq!(
            receiver.call_media_rx.lock().await.len(),
            0,
            "unpaid frames entered the shared queue"
        );
    }
    paid.send_frame(
        receiver_id,
        &Frame::call_media(CALL, 42, vec![4, 2]).unwrap(),
    )
    .await
    .unwrap();
    barrier(&paid, &receiver).await;
    let queued = receiver.call_media_rx.lock().await.len();
    assert!(
        queued < CALL_MEDIA_CHANNEL_CAPACITY,
        "one peer occupied the entire shared queue"
    );
    if promote_flooder {
        assert_eq!(queued, 65, "64 flooder slots plus the paid peer's frame");
    }
    let mut delivered = false;
    for _ in 0..queued {
        let event = receiver.recv_call_media().await.unwrap();
        if event.peer_id == *paid_id {
            assert_eq!(
                (event.call_id.as_str(), event.seq, event.data.as_slice()),
                (CALL, 42, &[4, 2][..])
            );
            assert!(event.privileged);
            delivered = true;
        }
    }
    assert!(delivered, "flood displaced paid media");

    // The paid connection continues to deliver after the flood drains.
    paid.send_frame(receiver_id, &Frame::call_media(CALL, 43, vec![3]).unwrap())
        .await
        .unwrap();
    barrier(&paid, &receiver).await;
    assert_eq!(receiver.recv_call_media().await.unwrap().seq, 43);
    if promote_flooder {
        // The flooder exhausted all its queue slots. Once dequeued, those
        // permits must be reusable; allow the independent rate bucket to
        // replenish its 10 ms burst before checking quota recovery.
        tokio::time::sleep(Duration::from_millis(20)).await;
        flooder
            .send_frame(
                receiver_id,
                &Frame::call_media(CALL, 2048, vec![8]).unwrap(),
            )
            .await
            .unwrap();
        barrier(&flooder, &receiver).await;
        let event = tokio::time::timeout(Duration::from_secs(5), receiver.recv_call_media())
            .await
            .expect("dequeue must release the flooder's quota")
            .unwrap();
        assert_eq!(event.peer_id, *flooder.identity.node_id());
        assert_eq!(event.seq, 2048);
    }
    receiver.shutdown();
    flooder.shutdown();
    paid.shutdown();
}

#[tokio::test]
async fn unwritable_media_drops_before_encryption_and_preserves_signalling() {
    let mut sender = NoiseSession::initiator(&[11; 32]).unwrap();
    let mut receiver = NoiseSession::responder(&[22; 32]).unwrap();
    receiver
        .read_handshake(&sender.write_handshake(&[]).unwrap())
        .unwrap();
    sender
        .read_handshake(&receiver.write_handshake(&[]).unwrap())
        .unwrap();
    receiver
        .read_handshake(&sender.write_handshake(&[]).unwrap())
        .unwrap();
    assert!(sender.try_finish_handshake().unwrap());
    assert!(receiver.try_finish_handshake().unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    socket2::SockRef::from(&listener)
        .set_recv_buffer_size(1024)
        .unwrap();
    let client = tokio::net::TcpSocket::new_v4().unwrap();
    client.set_send_buffer_size(4096).unwrap();
    let (client, accepted) = tokio::join!(
        client.connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let (_reader, writer) = client.unwrap().into_split();
    let (mut server, addr) = accepted.unwrap();
    let transport = open_transport();
    let peer = NodeId::from_bytes([44; 32]);
    let now = Instant::now();
    let conn = Connection::new(
        PeerConnection {
            advertised_trust_discount: None,
            source_ip: addr.ip(),
            privileged: true,
            noise: sender,
            writer,
            tier: SovereigntyTier::T1,
            capabilities: vec![],
            connected_at: now,
            last_recv: now,
            pending_ping: None,
            invalid_frame_level: 0.0,
            invalid_frame_last_leak: now,
            bytes_received: 0,
            memory_budget_window_start: now,
        },
        peer,
        transport.peers.clone(),
        true,
    )
    .unwrap();
    transport.peers.write().await.insert(peer, conn.clone());
    // Fill the TCP buffers with a known prefix, before any Noise nonce is
    // used. Drain exactly this prefix later, then decrypt actual frames.
    let mut filled = 0;
    {
        let state = conn.lock().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match state.writer.try_write(&[0; 65536]) {
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if tokio::time::timeout(Duration::from_millis(50), state.writer.writable())
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => panic!("fill socket: {e}"),
                }
            }
        })
        .await
        .expect("send buffer fills");
    }
    let media = Frame::call_media(CALL, 1, vec![7])
        .unwrap()
        .to_bytes()
        .unwrap();
    // Cancellation while waiting for readiness must also preserve the link.
    assert!(tokio::time::timeout(
        Duration::from_millis(10),
        transport.send_call_media(&peer, &media)
    )
    .await
    .is_err());
    assert!(!conn.is_closed(), "readiness cancellation consumed a nonce");
    assert!(matches!(
        transport.send_call_media(&peer, &media).await,
        Err(TransportError::Timeout(_))
    ));
    assert!(
        transport.is_connected(&peer).await,
        "a full socket closed the peer link"
    );
    tokio::time::timeout(
        Duration::from_secs(5),
        server.read_exact(&mut vec![0; filled]),
    )
    .await
    .unwrap()
    .unwrap();
    transport
        .send_frame(&peer, &Frame::SessionAck)
        .await
        .unwrap();
    let mut reader = server.into_split().0;
    let encrypted = read_noise_message(&mut reader).await.unwrap();
    let clear = receiver
        .decrypt(&encrypted)
        .expect("dropping media must not consume a nonce");
    assert!(matches!(
        Frame::from_bytes(&clear).unwrap(),
        Frame::SessionAck
    ));
    transport.send_call_media(&peer, &media).await.unwrap();
    let encrypted = read_noise_message(&mut reader).await.unwrap();
    assert_eq!(receiver.decrypt(&encrypted).unwrap(), media);
    transport.shutdown();
}
