//! A lost E2EE session recovers on the live connection, whichever side lost it.
//!
//! Only the lower NodeId runs X3DH and it needs the higher id's bundle, so a
//! lower id without a session depends on the higher id offering. Real session
//! and message handlers, real X3DH, Noise transports on loopback and the shared
//! mock ledger (see the parent module). The self-heal tick and the cooldowns
//! are the production values, so these tests run in real time.

use super::*;

/// The negotiation cooldown, one self-heal tick and round trips.
const RECOVERY_BOUND: Duration = Duration::from_secs(30);

/// `Order::PayerHigher`: the payee holds the lower id and initiates X3DH.
async fn ready_pair(order: Order) -> Pair {
    let mut net = pair(Shape::CardOnly, order, Wallet::Plain, Wallet::Plain).await;
    let payee = net.payee.id;
    let (status, body) = net.payer.compose(&payee, "hello").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    net.payee.delivered_once("hello").await;
    both_can_send(&net, Duration::from_secs(5)).await;
    net
}

async fn both_can_send(net: &Pair, within: Duration) {
    let (payer, payee) = (net.payer.id, net.payee.id);
    wait_until("both sides can send", within, || async {
        net.payer.sessions.can_send(&payee).await && net.payee.sessions.can_send(&payer).await
    })
    .await;
}

/// The lower id loses its session while the higher id keeps a working one. No
/// new connection, and a message goes each way afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lower_id_that_lost_its_session_recovers_on_the_same_connection() {
    let mut net = ready_pair(Order::PayerHigher).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    assert!(payee.as_bytes() < payer.as_bytes(), "the payee is the initiator");
    let generations = (
        net.payer.transport.connected_since(&payee).await.unwrap(),
        net.payee.transport.connected_since(&payer).await.unwrap(),
    );

    assert!(net.payee.sessions.remove_session(&payer).await);
    assert!(net.payer.sessions.can_send(&payee).await, "the higher id does not know");
    wait_until("the lower id has a session again", RECOVERY_BOUND, || async {
        net.payee.sessions.can_send(&payer).await
    })
    .await;
    both_can_send(&net, Duration::from_secs(5)).await;
    assert_eq!(
        (
            net.payer.transport.connected_since(&payee).await.unwrap(),
            net.payee.transport.connected_since(&payer).await.unwrap(),
        ),
        generations,
        "recovered without a new connection"
    );

    let (status, body) = net.payer.compose(&payee, "from the higher id").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["delivered"], true, "{body}");
    net.payee.delivered_once("from the higher id").await;
    let (status, body) = net.payee.compose(&payer, "from the lower id").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["delivered"], true, "{body}");
    // The payer's feed also carries what it composed itself.
    let mut seen = Vec::new();
    while let Ok(Some(text)) = tokio::time::timeout(Duration::from_secs(2), net.payer.delivered.recv()).await {
        seen.push(text);
    }
    assert_eq!(seen.iter().filter(|text| *text == "from the lower id").count(), 1, "{seen:?}");
    net.stop();
}

/// Lost again right after a negotiation, both sides are inside their cooldowns
/// (the shape a reconnect leaves behind): no answer yet, but a later tick
/// recovers it within the same bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_lost_right_after_a_negotiation_recovers_too() {
    let net = ready_pair(Order::PayerHigher).await;
    let payer = net.payer.id;
    for lost in ["after a quiet period", "inside the cooldown"] {
        assert!(net.payee.sessions.remove_session(&payer).await, "{lost}");
        wait_until(lost, RECOVERY_BOUND, || async { net.payee.sessions.can_send(&payer).await }).await;
        both_can_send(&net, Duration::from_secs(5)).await;
    }
    net.stop();
}

/// A healthy pair's connect offers get no answer, so a reconnect negotiates once
/// and leaves the session it made alone. Both sides are listed, so the new
/// connection is privileged from the start and both offer on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_connection_negotiates_once() {
    let net = ready_pair(Order::PayerHigher).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    net.payer.transport.add_to_whitelist(&payee).await;
    net.payee.transport.add_to_whitelist(&payer).await;
    // Past the negotiation cooldown, so the connect offer is acted on.
    tokio::time::sleep(Duration::from_secs(11)).await;
    let mark = log_mark();
    net.flap().await;
    both_can_send(&net, Duration::from_secs(5)).await;
    // Past the connection's own cooldown and one self-heal tick.
    tokio::time::sleep(Duration::from_secs(16)).await;
    let peer = format!("peer={payer}");
    assert_eq!(logged_since(mark, &["X3DH initiated", &peer]).len(), 1, "one negotiation");
    assert!(
        logged_since(mark, &["answered the peer's PrekeyOffer", &format!("peer={payee}")]).is_empty(),
        "a connect offer was answered"
    );
    net.stop();
}

/// How many offers a bare peer that floods PrekeyOffers gets back from a node.
async fn offers_back_while_flooding(
    node: &Node,
    transport: &NoiseTransport,
    sessions: &SessionManager,
    window: Duration,
) -> usize {
    let bundle = serde_json::to_value(sessions.prekey_bundle().await).unwrap();
    let flood = Frame::PrekeyOffer { bundle };
    let deadline = tokio::time::Instant::now() + window;
    let mut offers = 0;
    while tokio::time::Instant::now() < deadline {
        transport.send_frame(&node.id, &flood).await.unwrap();
        for event in received(transport, Duration::from_millis(100)).await {
            if matches!(event, ControlEvent::PrekeyOffer { .. }) {
                offers += 1;
            }
        }
    }
    offers
}

/// A privileged peer flooding offers gets at most one answer per cooldown and
/// none on a young connection; an unprivileged one gets none at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offer_flood_gets_a_rate_limited_answer_and_a_stranger_gets_none() {
    let ledger = tempfile::tempdir().unwrap();
    let ledger_path = ledger.path().join("ledger.db");

    // Two bare peers, the node above both in NodeId order so it is the side
    // that answers: one privileged (listed), one not.
    let (peer_identity, peer_transport) = stranger();
    let (other_identity, other_transport) = stranger();
    let floor = peer_identity.node_id().as_bytes().max(other_identity.node_id().as_bytes()).to_owned();
    let node_identity = loop {
        let candidate = Arc::new(NodeIdentity::generate().unwrap().1);
        if candidate.node_id().as_bytes() > &floor {
            break candidate;
        }
    };
    let node = start_node(NodeSpec {
        identity: node_identity, whitelist: vec![*peer_identity.node_id()], ledger: &ledger_path, name: "node",
        balance_msat: 0, wallet: Wallet::Plain, peer: None, data_dir: None,
    })
    .await;
    for transport in [&peer_transport, &other_transport] {
        transport.start_listener().await.unwrap();
        transport.add_to_whitelist(&node.id).await;
        transport.connect(&node.id, &node.addr()).await.unwrap();
    }
    let peer_sessions = SessionManager::new(Arc::clone(&peer_identity));
    let other_sessions = SessionManager::new(Arc::clone(&other_identity));
    // The node holds a working session with the listed peer, so its self-heal
    // tick stays quiet and every offer it sends is an answer.
    let init = peer_sessions.initiate_session(&node.id, &node.sessions.prekey_bundle().await).await.unwrap();
    node.sessions.accept_session(peer_identity.node_id(), &init).await.unwrap();
    let first = peer_sessions.encrypt(&node.id, b"ratchet-init").await.unwrap();
    node.sessions.decrypt(peer_identity.node_id(), &first).await.unwrap();

    // A young connection: only the node's own connect offer comes back.
    let young = offers_back_while_flooding(&node, &peer_transport, &peer_sessions, Duration::from_secs(8)).await;
    assert_eq!(young, 1, "only the connect offer on a young connection");

    // Past the cooldown: 25 s of flooding at about ten offers a second buys at
    // most three answers (one per ten seconds, however the window falls).
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (answers, stranger_offers) = tokio::join!(
        offers_back_while_flooding(&node, &peer_transport, &peer_sessions, Duration::from_secs(25)),
        offers_back_while_flooding(&node, &other_transport, &other_sessions, Duration::from_secs(25)),
    );
    assert!((2..=3).contains(&answers), "one answer per cooldown, got {answers}");
    assert_eq!(stranger_offers, 0, "no prekey for an unprivileged peer");
    node.stop();
    drop(ledger);
}
