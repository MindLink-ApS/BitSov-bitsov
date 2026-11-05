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

/// When the higher id needs the session and the lower id still looks healthy: the
/// first tick that counts, up to two more for the spacing, and round trips.
const HIGHER_ID_RECOVERY_BOUND: Duration = Duration::from_secs(60);

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

/// Both sides can send, the initiator's session is confirmed, and neither holds a
/// newer session aside: the acceptor has moved over, so what it sends is under the
/// session the initiator uses.
async fn both_can_send(net: &Pair, within: Duration) {
    let (payer, payee) = (net.payer.id, net.payee.id);
    wait_until("both sides can send", within, || async {
        net.payer.sessions.can_send(&payee).await
            && net.payee.sessions.can_send(&payer).await
            && !net.payer.sessions.awaiting_confirmation(&payee).await
            && !net.payee.sessions.awaiting_confirmation(&payer).await
            && !net.payer.sessions.replacement_pending(&payee).await
            && !net.payee.sessions.replacement_pending(&payer).await
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
    assert_eq!(body["accepted"], true, "{body}");
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

/// Both sides can send on sessions that do not match. One paid message is refused;
/// the recipient keeps its session, asks for a replacement, and within the bound
/// messages go each way on the same connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sessions_that_disagree_renegotiate_on_the_same_connection() {
    let net = ready_pair(Order::PayerHigher).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    let generation = net.payer.transport.connected_since(&payee).await.unwrap();
    disagree_with_no_earlier_session(&net).await;
    tokio::time::sleep(Duration::from_secs(11)).await;

    let (status, body) = net.payer.compose(&payee, "unreadable").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_ne!(body["accepted"], true, "{body}");
    assert!(net.payee.sessions.has_session(&payer).await, "one envelope does not cost the session");
    wait_until("the sides agree again", RECOVERY_BOUND, || async {
        !net.payee.sessions.needs_renegotiation(&payer).await
    })
    .await;
    both_can_send(&net, Duration::from_secs(5)).await;
    assert_eq!(net.payer.transport.connected_since(&payee).await.unwrap(), generation, "no new connection");

    assert_messages_go_each_way(&net).await;
    net.stop();
}

/// A message each way, both accepted by the other side's node.
async fn assert_messages_go_each_way(net: &Pair) {
    let (payer, payee) = (net.payer.id, net.payee.id);
    for (from, to, text) in [(&net.payer, &payee, "from the higher id"), (&net.payee, &payer, "from the lower id")] {
        let (status, body) = from.compose(to, text).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["accepted"], true, "{text}: {body}");
    }
}

/// Sessions that already disagree, with nothing marked and nobody sending: a
/// reconnect finds them and they agree again, with nothing paid.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnect_finds_sessions_that_disagree_with_nobody_sending() {
    let net = ready_pair(Order::PayerHigher).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    net.payer.transport.add_to_whitelist(&payee).await;
    net.payee.transport.add_to_whitelist(&payer).await;
    disagree_with_no_earlier_session(&net).await;
    tokio::time::sleep(Duration::from_secs(11)).await;
    let unreadable = net.payer.sessions.encrypt(&payee, b"unreadable").await.unwrap();
    assert!(net.payee.sessions.preview_decrypt(&payer, &unreadable).await.is_err());
    assert!(!net.payer.sessions.needs_renegotiation(&payee).await, "nothing has found them yet");
    let paid = (net.payer.paid_out().await.len(), net.payee.paid_out().await.len());
    let before = now_ms();

    net.flap().await;
    wait_until("the sides agree again", HIGHER_ID_RECOVERY_BOUND, || async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        net.payer.sessions.session_newer_than(&payee, before).await && sessions_read_each_other(&net).await
    })
    .await;
    assert_eq!((net.payer.paid_out().await.len(), net.payee.paid_out().await.len()), paid, "nothing was paid");
    assert_messages_go_each_way(&net).await;
    net.stop();
}

/// The higher id is still on the session the lower id replaced, and sends. The lower
/// id reads it, so the paid message is not lost, and the two agree again unasked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_message_under_a_replaced_session_is_read_and_the_sides_agree_again() {
    let mut net = ready_pair(Order::PayerHigher).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    net.payee.sessions.reinitiate_session(&payer, &net.payer.sessions.prekey_bundle().await).await.unwrap();
    assert!(net.payee.sessions.confirm_session(&payer).await);
    let paid = net.payer.paid_out().await.len();
    let before = now_ms();

    let (status, body) = net.payer.compose(&payee, "under the replaced session").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["accepted"], true, "{body}");
    assert_eq!(net.payer.paid_out().await.len(), paid + 1);
    net.payee.delivered_once("under the replaced session").await;

    wait_until("the sides agree again", HIGHER_ID_RECOVERY_BOUND, || async {
        tokio::time::sleep(Duration::from_millis(500)).await;
        net.payer.sessions.session_newer_than(&payee, before).await && sessions_read_each_other(&net).await
    })
    .await;
    assert_messages_go_each_way(&net).await;
    net.stop();
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64
}

/// The lower id moves to a session the higher id never saw, with no earlier one kept.
async fn disagree_with_no_earlier_session(net: &Pair) {
    let payer = net.payer.id;
    assert!(net.payee.sessions.remove_session(&payer).await);
    net.payee.sessions.reinitiate_session(&payer, &net.payer.sessions.prekey_bundle().await).await.unwrap();
    assert!(net.payee.sessions.confirm_session(&payer).await);
}

/// Each side reads what the other would send now, and neither is waiting to replace
/// its session. This takes send chain positions but puts nothing on the wire.
async fn sessions_read_each_other(net: &Pair) -> bool {
    let (payer, payee) = (net.payer.id, net.payee.id);
    if net.payer.sessions.needs_renegotiation(&payee).await
        || net.payee.sessions.needs_renegotiation(&payer).await
        || net.payee.sessions.awaiting_confirmation(&payer).await
        || net.payer.sessions.replacement_pending(&payee).await
        || net.payee.sessions.replacement_pending(&payer).await
    {
        return false;
    }
    let (Ok(to_payee), Ok(to_payer)) = (
        net.payer.sessions.encrypt(&payee, b"check").await,
        net.payee.sessions.encrypt(&payer, b"check").await,
    ) else {
        return false;
    };
    net.payee.sessions.preview_decrypt(&payer, &to_payee).await.is_ok()
        && net.payer.sessions.preview_decrypt(&payee, &to_payer).await.is_ok()
}

/// The higher id loses its session while the lower id looks healthy. It offers on
/// every tick, and the lower id acts on the second of those. No new connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn higher_id_that_lost_its_session_recovers_on_the_same_connection() {
    let net = ready_pair(Order::PayerHigher).await;
    let payee = net.payee.id;
    let generation = net.payer.transport.connected_since(&payee).await.unwrap();
    assert!(net.payer.sessions.remove_session(&payee).await);
    wait_until("the higher id has a session again", HIGHER_ID_RECOVERY_BOUND, || async {
        net.payer.sessions.can_send(&payee).await
    })
    .await;
    both_can_send(&net, Duration::from_secs(5)).await;
    assert_eq!(net.payer.transport.connected_since(&payee).await.unwrap(), generation, "no new connection");
    assert_messages_go_each_way(&net).await;
    net.stop();
}

/// The lower id, with no session, acts on a stale offer and installs a session at
/// once. The higher id refuses the init, so no confirmation comes. Both sides report
/// send-ready on sessions that do not match. Self-heal picks it up with no paid
/// traffic at all, and messages then go each way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_initial_handshake_recovers_without_paid_traffic() {
    let net = ready_pair(Order::PayerHigher).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    let stale = net.payer.sessions.prekey_bundle().await;
    // A real negotiation spends that bundle's one-time pre-key.
    let init = net.payee.sessions.reinitiate_session(&payer, &stale).await.unwrap();
    net.payer.sessions.reaccept_session(&payee, &init).await.unwrap();
    assert!(net.payee.sessions.confirm_session(&payer).await);
    let moves_it = net.payee.sessions.encrypt(&payer, b"ratchet-init").await.unwrap();
    net.payer.sessions.decrypt(&payee, &moves_it).await.unwrap();
    both_can_send(&net, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_secs(11)).await;

    let paid = (net.payer.paid_out().await.len(), net.payee.paid_out().await.len());
    assert!(net.payee.sessions.remove_session(&payer).await);
    let mark = log_mark();
    let offer = Frame::PrekeyOffer { bundle: serde_json::to_value(&stale).unwrap() };
    net.payer.transport.send_frame(&payee, &offer).await.unwrap();
    wait_until("the peer refuses the init", Duration::from_secs(5), || async {
        !logged_since(mark, &["session accept failed", &format!("peer={payee}")]).is_empty()
    })
    .await;
    assert!(net.payee.sessions.can_send(&payer).await && net.payer.sessions.can_send(&payee).await, "both report send-ready");
    assert!(net.payee.sessions.awaiting_confirmation(&payer).await);

    wait_until("the lower id's session is confirmed", RECOVERY_BOUND, || async {
        !net.payee.sessions.awaiting_confirmation(&payer).await
    })
    .await;
    both_can_send(&net, Duration::from_secs(5)).await;
    assert_eq!(
        (net.payer.paid_out().await.len(), net.payee.paid_out().await.len()),
        paid,
        "recovery needed no paid traffic"
    );
    assert_messages_go_each_way(&net).await;
    net.stop();
}

/// A valid but stale offer is replayed at a healthy lower id. One offer is not acted
/// on: no X3DH, and messages go each way on the session it has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_offer_does_not_replace_a_working_session() {
    let net = ready_pair(Order::PayerHigher).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    let stale = net.payer.sessions.prekey_bundle().await;
    net.payee.sessions.mark_needs_renegotiation(&payer).await;
    wait_until("a negotiation spends that pre-key", RECOVERY_BOUND, || async {
        !net.payee.sessions.needs_renegotiation(&payer).await
    })
    .await;
    both_can_send(&net, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_secs(11)).await;

    let mark = log_mark();
    let offer = Frame::PrekeyOffer { bundle: serde_json::to_value(&stale).unwrap() };
    net.payer.transport.send_frame(&payee, &offer).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(logged_since(mark, &["X3DH initiated", &format!("peer={payer}")]).is_empty(), "one offer starts nothing");
    assert_messages_go_each_way(&net).await;
    net.stop();
}

/// A reconnect keeps a healthy session: both sides offer, nothing is negotiated, and
/// a ciphertext from before the reconnect still reads after it. Both sides are
/// listed, so the new connection is privileged from the start and both offer on it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnect_keeps_a_healthy_session() {
    let net = ready_pair(Order::PayerHigher).await;
    let (payer, payee) = (net.payer.id, net.payee.id);
    net.payer.transport.add_to_whitelist(&payee).await;
    net.payee.transport.add_to_whitelist(&payer).await;
    // Past the negotiation cooldown, so a connect offer would be acted on.
    tokio::time::sleep(Duration::from_secs(11)).await;
    let before = net.payer.sessions.encrypt(&payee, b"from before the reconnect").await.unwrap();
    let mark = log_mark();
    net.flap().await;
    // Past the connection's own cooldown and one self-heal tick.
    tokio::time::sleep(Duration::from_secs(16)).await;
    assert!(logged_since(mark, &["X3DH initiated", &format!("peer={payer}")]).is_empty(), "no negotiation");
    assert!(
        logged_since(mark, &["answered the peer's PrekeyOffer", &format!("peer={payee}")]).is_empty(),
        "a connect offer was answered"
    );
    assert_eq!(net.payee.sessions.decrypt(&payer, &before).await.unwrap(), b"from before the reconnect");
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
        balance_msat: 0, wallet: Wallet::Plain, peer: None, data_dir: None, session_store: None,
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
