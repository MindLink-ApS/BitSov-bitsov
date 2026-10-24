use super::*;
use konsensus_message::{ReachabilityMode, TransportConfig};
use std::collections::HashMap;
use std::time::Duration;

async fn next_control(transport: &NoiseTransport) -> ControlEvent {
    tokio::time::timeout(Duration::from_secs(2), transport.recv_control())
        .await
        .expect("expected session control frame")
        .expect("transport open")
}

#[tokio::test]
async fn consumed_rekey_prekey_recovers_two_send_ready_peers() {
    let (_, a) = NodeIdentity::generate().unwrap();
    let (_, b) = NodeIdentity::generate().unwrap();
    let (alice, bob) = if a.node_id().as_bytes() < b.node_id().as_bytes() {
        (Arc::new(a), Arc::new(b))
    } else {
        (Arc::new(b), Arc::new(a))
    };
    let alice_mgr = SessionManager::new(alice.clone());
    let bob_mgr = SessionManager::new(bob.clone());
    let build = |identity: Arc<NodeIdentity>, peer| {
        Arc::new(NoiseTransport::new(
            identity,
            TransportConfig {
                listen_addr: "127.0.0.1:0".parse().unwrap(),
                admission_mode: ReachabilityMode::PriceOpen,
                whitelist: vec![peer],
                ..Default::default()
            },
        ))
    };
    let source = build(alice.clone(), *bob.node_id());
    let target = build(bob.clone(), *alice.node_id());
    target.start_listener().await.unwrap();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    assert!(matches!(
        next_control(&source).await,
        ControlEvent::PeerConnected { .. }
    ));
    assert!(matches!(
        next_control(&target).await,
        ControlEvent::PeerConnected { .. }
    ));

    let old_init = alice_mgr
        .initiate_session(bob.node_id(), &bob_mgr.prekey_bundle().await)
        .await
        .unwrap();
    bob_mgr
        .accept_session(alice.node_id(), &old_init)
        .await
        .unwrap();
    let first = alice_mgr
        .encrypt(bob.node_id(), b"old session")
        .await
        .unwrap();
    bob_mgr.decrypt(alice.node_id(), &first).await.unwrap();
    assert!(alice_mgr.can_send(bob.node_id()).await);
    assert!(bob_mgr.can_send(alice.node_id()).await);

    // Another session consumes the offered OPK while our rekey is in flight.
    let stale_offer = bob_mgr.prekey_bundle().await;
    let (_, other) = NodeIdentity::generate().unwrap();
    let other = Arc::new(other);
    let other_mgr = SessionManager::new(other.clone());
    let other_init = other_mgr
        .initiate_session(bob.node_id(), &stale_offer)
        .await
        .unwrap();
    bob_mgr
        .accept_session(other.node_id(), &other_init)
        .await
        .unwrap();
    alice_mgr.remove_session(bob.node_id()).await;
    let refused_init = alice_mgr
        .initiate_session(bob.node_id(), &stale_offer)
        .await
        .unwrap();
    let mut initiator_negotiations = HashMap::from([(*bob.node_id(), tokio::time::Instant::now())]);

    let storage: Arc<dyn konsensus_storage::Storage> =
        Arc::new(konsensus_storage::SqliteStorage::in_memory().await.unwrap());
    let dir = tempfile::tempdir().unwrap();
    let audit = Arc::new(AuditLog::open(dir.path().join("audit.jsonl")).unwrap());
    let mut negotiations = HashMap::new();
    let mut control_replays = HashMap::new();
    let mut pending_rekeys = HashMap::new();
    handle_session_init(
        alice.node_id(),
        serde_json::to_value(&refused_init).unwrap(),
        &bob_mgr,
        &storage,
        &target,
        &audit,
        &mut negotiations,
        &mut control_replays,
    )
    .await
    .update_rekey_retry(alice.node_id(), &mut pending_rekeys);
    assert!(
        bob_mgr
            .is_repeat_session_init(alice.node_id(), &old_init)
            .await,
        "refusal must preserve the old session"
    );
    assert!(alice_mgr.can_send(bob.node_id()).await);
    assert!(bob_mgr.can_send(alice.node_id()).await);
    assert!(
        negotiations.is_empty(),
        "refusal must not refresh negotiation cooldown"
    );

    heal_connected_e2ee_sessions(&bob_mgr, &target, &mut pending_rekeys).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), source.recv_control())
            .await
            .is_err(),
        "retry must wait out the initiator's negotiation cooldown"
    );
    tokio::time::pause();
    tokio::time::advance(SESSION_NEGOTIATION_COOLDOWN + Duration::from_secs(1)).await;
    tokio::time::resume();
    heal_connected_e2ee_sessions(&bob_mgr, &target, &mut pending_rekeys).await;
    let ControlEvent::PrekeyOffer {
        bundle,
        privileged: true,
        ..
    } = next_control(&source).await
    else {
        panic!("expected a fresh prekey offer");
    };
    let fresh: konsensus_crypto::SerializablePrekeyBundle =
        serde_json::from_value(bundle.clone()).unwrap();
    assert_ne!(fresh.one_time_prekey_id, stale_offer.one_time_prekey_id);
    tokio::time::pause();
    tokio::time::advance(SESSION_SELF_HEAL_INTERVAL).await;
    tokio::time::resume();
    heal_connected_e2ee_sessions(&bob_mgr, &target, &mut pending_rekeys).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), source.recv_control())
            .await
            .is_err(),
        "a refused rekey schedules only one delayed offer"
    );
    handle_prekey_offer(
        bob.node_id(),
        bundle,
        *alice.node_id(),
        &alice_mgr,
        &storage,
        &source,
        &audit,
        &mut initiator_negotiations,
    )
    .await;
    let ControlEvent::SessionInit {
        init_data,
        privileged: true,
        ..
    } = next_control(&target).await
    else {
        panic!("expected fresh SessionInit");
    };
    handle_session_init(
        alice.node_id(),
        init_data,
        &bob_mgr,
        &storage,
        &target,
        &audit,
        &mut negotiations,
        &mut control_replays,
    )
    .await
    .update_rekey_retry(alice.node_id(), &mut pending_rekeys);
    assert!(matches!(
        next_control(&source).await,
        ControlEvent::SessionAck {
            privileged: true,
            ..
        }
    ));
    handle_session_ack(
        bob.node_id(),
        &alice_mgr,
        &source,
        &audit,
        &mut HashMap::new(),
    )
    .await;
    let ControlEvent::RatchetInit {
        payload,
        privileged: true,
        ..
    } = next_control(&target).await
    else {
        panic!("expected fresh RatchetInit");
    };
    handle_ratchet_init(alice.node_id(), &payload, &bob_mgr, &storage, &target).await;
    for (sender, recipient, to, from) in [
        (&alice_mgr, &bob_mgr, bob.node_id(), alice.node_id()),
        (&bob_mgr, &alice_mgr, alice.node_id(), bob.node_id()),
    ] {
        let message = sender.encrypt(to, b"recovered").await.unwrap();
        assert_eq!(
            recipient.decrypt(from, &message).await.unwrap(),
            b"recovered"
        );
    }
    heal_connected_e2ee_sessions(&bob_mgr, &target, &mut pending_rekeys).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(20), source.recv_control())
            .await
            .is_err(),
        "successful rekey must stop retries"
    );
    source.shutdown();
    target.shutdown();
}

#[tokio::test(start_paused = true)]
async fn rekey_retries_are_capped_and_replays_do_not_postpone_them() {
    let peer = NodeId::from_bytes([0; 32]);
    let mut pending = HashMap::new();
    SessionInitOutcome::Retry.update_rekey_retry(&peer, &mut pending);
    let deadline = pending[&peer];
    tokio::time::advance(Duration::from_secs(1)).await;
    SessionInitOutcome::Retry.update_rekey_retry(&peer, &mut pending);
    SessionInitOutcome::Unchanged.update_rekey_retry(&peer, &mut pending);
    assert_eq!(pending[&peer], deadline);
    for i in 1..=MAX_PENDING_REKEY_RETRIES {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&(i as u64).to_le_bytes());
        SessionInitOutcome::Retry.update_rekey_retry(&NodeId::from_bytes(id), &mut pending);
    }
    assert_eq!(pending.len(), MAX_PENDING_REKEY_RETRIES);
    SessionInitOutcome::Accepted.update_rekey_retry(&peer, &mut pending);
    assert!(
        !pending.contains_key(&peer),
        "acceptance cancels a pending retry"
    );
}

#[tokio::test]
async fn delayed_rekey_retry_does_not_offer_prekeys_to_an_unpaid_connection() {
    let (_, a) = NodeIdentity::generate().unwrap();
    let (_, b) = NodeIdentity::generate().unwrap();
    let alice = Arc::new(a);
    let bob = Arc::new(b);
    let source = Arc::new(NoiseTransport::new(
        alice.clone(),
        TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            admission_mode: ReachabilityMode::PriceOpen,
            whitelist: vec![*bob.node_id()],
            ..Default::default()
        },
    ));
    let target = Arc::new(NoiseTransport::new(
        bob.clone(),
        TransportConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            admission_mode: ReachabilityMode::PriceOpen,
            ..Default::default()
        },
    ));
    let manager = SessionManager::new(bob.clone());
    target.start_listener().await.unwrap();
    source
        .connect(bob.node_id(), &target.listen_addr().unwrap().to_string())
        .await
        .unwrap();
    assert!(matches!(
        next_control(&source).await,
        ControlEvent::PeerConnected { .. }
    ));
    assert!(matches!(
        next_control(&target).await,
        ControlEvent::PeerConnected { .. }
    ));
    assert!(target.connected_session_peers().await.is_empty());
    let mut pending = HashMap::from([(*alice.node_id(), tokio::time::Instant::now())]);
    heal_connected_e2ee_sessions(&manager, &target, &mut pending).await;
    assert!(
        pending.is_empty(),
        "drop retries whose connection is no longer eligible"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), source.recv_control())
            .await
            .is_err(),
        "a pending retry must not bypass admission"
    );
    source.shutdown();
    target.shutdown();
}
