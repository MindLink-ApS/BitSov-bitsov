//! M6 P1: two production nodes, real LDK settlement and owner media sockets.
//! Reuses the three-node paid lane's chain, app, pairing and owner helpers.
//! No fabricated call rows, payment proofs, peer prices or accelerated clocks.
use super::*;
use axum::http::StatusCode;
use futures::{SinkExt, StreamExt};
use konsensus_core::payloads::call::{CallEntry, HangupReason, Phase};
use konsensus_core::traits::lightning::LightningError;
use konsensus_core::NodeId;
use konsensus_crypto::SessionManager;
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
const PRICE: u64 = 23_001;
const SIGNAL_PRICE: u64 = 1_000;
// Direct-channel signaling pays the one-sat invoice floor with no routing fee.
const CLOSING_ALLOWANCE: u64 = SIGNAL_PRICE;
const CALL: &str = "00112233445566778899aabbccddeeff";
pub(super) const SDP: &str = "v=0\r\ns=M6 node-routed audio\r\nt=0 0\r\n";

pub(super) fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().try_into().unwrap()
}

async fn entry(app: &app::App, peer: &NodeId) -> CallEntry {
    app.state
        .storage
        .call_get(peer, CALL)
        .await
        .unwrap()
        .unwrap()
}

async fn socket(app: &app::App, peer: &NodeId) -> Result<Socket, u16> {
    socket_for(app, peer, CALL).await
}

async fn socket_for(app: &app::App, peer: &NodeId, call_id: &str) -> Result<Socket, u16> {
    let mut request = format!(
        "ws://{}/api/v1/calls/{call_id}/media?peer={}",
        app.media_addr.unwrap(),
        peer.to_hex()
    )
    .into_client_request()
    .unwrap();
    request.headers_mut().insert(
        "sec-websocket-protocol",
        format!("bitsov.v1, bitsov.jwt.{}", app.token)
            .parse()
            .unwrap(),
    );
    match tokio_tungstenite::connect_async(request).await {
        Ok((socket, _)) => Ok(socket),
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            Err(response.status().as_u16())
        }
        Err(error) => panic!("owner media connect: {error}"),
    }
}

async fn next_binary(socket: &mut Socket) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket
                .next()
                .await
                .expect("paid socket open")
                .expect("media read")
            {
                Message::Binary(bytes) => return bytes,
                Message::Ping(_) | Message::Pong(_) | Message::Text(_) => {}
                other => panic!("unexpected paid media: {other:?}"),
            }
        }
    })
    .await
    .expect("media delivery deadline")
}

fn packet(seq: u32, direction: u8) -> Vec<u8> {
    // 160-byte audio-sized payload with direction and sequence discrimination.
    [seq.to_be_bytes().as_slice(), &[direction; 160]].concat()
}

async fn audio_until(a: &mut Socket, b: &mut Socket, until: u64, seq: &mut u32) {
    let mut tick = tokio::time::interval(Duration::from_millis(20));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    while now_ms() < until {
        tick.tick().await;
        let ab = packet(*seq, 0xa0);
        let ba = packet(*seq, 0xb0);
        a.send(Message::Binary(ab.clone())).await.unwrap();
        b.send(Message::Binary(ba.clone())).await.unwrap();
        let (at_b, at_a) = tokio::join!(next_binary(b), next_binary(a));
        assert_eq!(at_b, ab, "A -> B ordered frame {seq}");
        assert_eq!(at_a, ba, "B -> A ordered frame {seq}");
        *seq += 1;
    }
}

async fn closed_without_media(socket: &mut Socket) {
    // Try to send even if the close frame has not yet reached this app.
    let _ = socket.send(Message::Binary(packet(u32::MAX, 0xee))).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await {
                None | Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                Some(Ok(Message::Binary(_))) => panic!("media delivered after cutoff"),
                Some(Ok(_)) => {}
            }
        }
    })
    .await
    .expect("ended socket closes");
}

async fn compose(
    app: &app::App,
    peer: &NodeId,
    kind: u16,
    signal: Value,
    cap: u64,
) -> (StatusCode, Value) {
    let mut request = json!({
        "operation_id": uuid::Uuid::new_v4().to_string(),
        "recipient": peer.to_hex(), "kind": kind, "plaintext": signal.to_string(),
        "max_routing_fee_msat": 0, "max_total_msat": cap,
    });
    if kind == 400 {
        // Explicit owner consent at both inclusive ceilings, separate from
        // the offer payment cap and with no direct-channel routing fee.
        request["max_block_msat"] = json!(PRICE);
        request["max_hold_msat"] = json!(u64::from(app.state.max_call_minutes) * PRICE);
    }
    app.post("/api/v1/messages/compose", request, false).await
}

/// A sending chain can still belong to the session being replaced. Wait for
/// confirmation and handover before sending traffic under the recovered session.
async fn session_recovered(sessions: &SessionManager, peer: &NodeId) -> bool {
    sessions.can_send(peer).await
        && !sessions.awaiting_confirmation(peer).await
        && !sessions.replacement_pending(peer).await
}

/// Shared production pair: callers choose tariffs, limits and approval roots.
pub(super) struct Pair {
    pub caller: app::App,
    pub callee: app::App,
    pub a: Arc<LdkProvider>,
    pub b: Arc<LdkProvider>,
    _dirs: [tempfile::TempDir; 2],
    _chain: infra::Chain,
}

impl Pair {
    pub async fn start(
        caller_calls: app::CallOptions,
        callee_calls: app::CallOptions,
        approval_keys: [Option<ed25519_dalek::VerifyingKey>; 2],
        fee_policy: konsensus_core::traits::lightning::RoutingFeePolicy,
    ) -> Self {
        Self::start_ordered(caller_calls, callee_calls, approval_keys, fee_policy, false).await
    }

    async fn start_ordered(
        caller_calls: app::CallOptions,
        callee_calls: app::CallOptions,
        approval_keys: [Option<ed25519_dalek::VerifyingKey>; 2],
        fee_policy: konsensus_core::traits::lightning::RoutingFeePolicy,
        caller_higher: bool,
    ) -> Self {
        let chain = infra::Chain::start().await;
        let dirs = [(); 2].map(|_| tempfile::tempdir().unwrap());
        let configs = dirs
            .each_ref()
            .map(|dir| infra::lightning_config(dir.path(), &chain.url));
        let identity = |index: usize| {
            *NodeIdentity::from_mnemonic(&configs[index].mnemonic, "")
                .unwrap()
                .node_id()
        };
        // Who holds the lower NodeId decides who runs X3DH.
        let (first, second) = if caller_higher && identity(0).as_bytes() < identity(1).as_bytes() {
            (1, 0)
        } else {
            (0, 1)
        };
        let a = Arc::new(
            LdkProvider::new(configs[first].clone())
                .await
                .unwrap()
                .with_routing_fee_policy(fee_policy),
        );
        let b = Arc::new(
            LdkProvider::new(configs[second].clone())
                .await
                .unwrap()
                .with_routing_fee_policy(fee_policy),
        );
        chain.fund(a.node()).await;
        chain.fund(b.node()).await;
        let start = |index: usize, wallet, calls| {
            app::App::start_with_options(
                dirs[index].path(),
                &chain,
                wallet,
                Some(app::Options {
                    identity: Arc::new(
                        NodeIdentity::from_mnemonic(&configs[index].mnemonic, "").unwrap(),
                    ),
                    chain_url: chain.api_url.clone(),
                    calls: Some(calls),
                    readiness_gated: false,
                    owner_approval_key: approval_keys[if index == first { 0 } else { 1 }],
                }),
            )
        };
        // Different prices catch an accidental fallback to the caller's tariff.
        let caller = start(first, a.clone(), caller_calls).await;
        let callee = start(second, b.clone(), callee_calls).await;
        let aid = *caller.state.identity.node_id();
        let bid = *callee.state.identity.node_id();

        let (status, body) = caller
            .post(
                "/api/v1/payments/open-channel",
                json!({
                    "peer_pubkey": b.node().node_id().to_string(),
                    "peer_addr": configs[second].listening_address,
                    "amount_sats": 1_000_000, "announce": false,
                }),
                true,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "owner channel open: {body}");
        chain.confirm_channel(a.node(), b.node(), &[]).await;
        // B must pay its answer and terminal signal. Move real channel liquidity,
        // including the acceptor's reserve, rather than minting a mock balance.
        let liquidity = b
            .create_invoice(50_000_000, "regtest callee signaling liquidity", 600)
            .await
            .unwrap();
        a.pay_invoice_with_fee_limit(&liquidity.bolt11, 0)
            .await
            .unwrap();
        settle(&a, &liquidity.payment_hash).await;
        settle(&b, &liquidity.payment_hash).await;
        wait("callee outbound liquidity", || async {
            capacity(b.node()) > 10_000_000
        })
        .await;
        wait("both wallets ready", || async {
            a.money_ready().await && b.money_ready().await
        })
        .await;
        three_node::list_contact(&caller, &callee, "M6 owners list their call peer").await;
        three_node::list_contact(&callee, &caller, "M6 owners list their call peer").await;
        three_node::connect(&caller, &callee, "M6 Noise connection").await;
        // Listing contacts can race the first supervised handshake. A transport
        // connection alone does not prove the prekey exchange has completed.
        wait("both signaling sessions established", || async {
            session_recovered(&caller.state.session_manager, &bid).await
                && session_recovered(&callee.state.session_manager, &aid).await
        })
        .await;

        Self {
            caller,
            callee,
            a,
            b,
            _dirs: dirs,
            _chain: chain,
        }
    }
}

/// Two funded nodes with a direct channel, paired clients, owner consent and an
/// E2EE session both ways.
struct Lane {
    steps: Steps,
    _chain: infra::Chain,
    _dirs: [tempfile::TempDir; 2],
    a: Arc<LdkProvider>,
    b: Arc<LdkProvider>,
    caller: app::App,
    callee: app::App,
    aid: NodeId,
    bid: NodeId,
}

async fn lane(max_minutes: u16, caller_higher: bool) -> Lane {
    let mut steps = Steps::new();
    let Pair {
        mut caller,
        mut callee,
        a,
        b,
        _dirs,
        _chain,
    } = Pair::start_ordered(
        app::CallOptions {
            block_msat: 7_001,
            max_minutes,
            offer_msat: SIGNAL_PRICE,
            chat_msat: 2_001,
        },
        app::CallOptions {
            block_msat: PRICE,
            max_minutes: 60,
            offer_msat: SIGNAL_PRICE,
            chat_msat: 2_001,
        },
        [None; 2],
        three_node::direct_channel_fee_policy(),
        caller_higher,
    )
    .await;
    let aid = *caller.state.identity.node_id();
    let bid = *callee.state.identity.node_id();

    let offer = json!({"v":1, "call_id":CALL, "media":"audio", "sdp":SDP});
    let before = a.list_payments(100).await.unwrap().len();
    let (status, _) = compose(&caller, &bid, 400, offer.clone(), SIGNAL_PRICE).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "read-only pairing cannot consent to spending"
    );
    assert_eq!(a.list_payments(100).await.unwrap().len(), before);
    three_node::elevate(&mut caller, &[bid.to_hex()]).await;
    three_node::elevate(&mut callee, &[aid.to_hex()]).await;
    // Exercise the established encrypted session through the paid product path.
    caller.compose(&mut callee, "M6 call preflight").await;
    let quoted = konsensus_api::calls::peer_call_kind_price(&caller.state, &bid, 404)
        .await
        .unwrap();
    assert_eq!(quoted, PRICE, "callee's live kind-404 answer");
    steps.pass("two funded nodes, direct channel, paired clients and owner consent");
    Lane {
        steps,
        _chain,
        _dirs,
        a,
        b,
        caller,
        callee,
        aid,
        bid,
    }
}

async fn scenario(max_minutes: u16, paid_blocks: u32, reason: HangupReason) {
    one_call(lane(max_minutes, false).await, max_minutes, paid_blocks, reason).await;
}

/// One whole call on `lane`, from the offer to the released reservation.
async fn one_call(lane: Lane, max_minutes: u16, paid_blocks: u32, reason: HangupReason) {
    let Lane { mut steps, _chain, _dirs, a, b, mut caller, mut callee, aid, bid } = lane;
    let used_before = caller.used();
    let counts_before = caller
        .service
        .grant_view_for(&caller.client)
        .unwrap()
        .breakers
        .payments_last_hour;
    let served_before = b
        .list_payments(100)
        .await
        .unwrap()
        .into_iter()
        .filter(|p| {
            p.direction == PaymentDirection::Incoming
                && p.status == PaymentStatus::Settled
                && p.amount_msat == PRICE
        })
        .count();
    let offer = json!({"v":1, "call_id":CALL, "media":"audio", "sdp":SDP});
    let (status, body) = compose(&caller, &bid, 400, offer, SIGNAL_PRICE).await;
    assert_eq!(status, StatusCode::OK, "offer: {body}");
    recv_kind(&mut callee, &aid, 400).await;
    let held = caller
        .service
        .call_spend_status(&bid.to_hex(), CALL)
        .unwrap();
    let reserved = u64::from(max_minutes) * PRICE + CLOSING_ALLOWANCE;
    assert_eq!(held.reserved_msat, reserved);
    assert_eq!(held.remaining_msat, held.reserved_msat);
    assert_eq!(held.spent_msat, 0);
    assert_eq!(held.per_block_msat, PRICE);
    assert_eq!(held.per_block_fee_msat, 0);
    assert_eq!(held.max_call_minutes, max_minutes);
    assert!(!held.closed);
    let (status, body) = compose(
        &callee,
        &aid,
        401,
        json!({"v":1, "call_id":CALL, "sdp":SDP}),
        SIGNAL_PRICE,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "answer: {body}");
    recv_kind(&mut caller, &bid, 401).await;
    assert_eq!(entry(&caller, &bid).await.paid_until_ms, None);
    assert_eq!(entry(&callee, &aid).await.paid_until_ms, None);
    assert_eq!(socket(&caller, &bid).await.err(), Some(403));
    assert_eq!(socket(&callee, &aid).await.err(), Some(403));
    steps.pass("answer grants no media; full reservation held before block zero");

    let anchors = [
        entry(&caller, &bid).await.deadline_ms - 30_000,
        entry(&callee, &aid).await.deadline_ms - 30_000,
    ];
    let mut sockets = None;
    let mut frame_seq = 0;
    let mut hashes = std::collections::BTreeSet::new();
    for seq in 0..paid_blocks {
        if let Some((ref mut sa, ref mut sb)) = sockets {
            let due = entry(&caller, &bid).await.next_block_due_ms().unwrap();
            audio_until(sa, sb, due + 20, &mut frame_seq).await;
        }
        let (status, body) = compose(
            &caller,
            &bid,
            404,
            json!({"call_id":CALL, "seq":seq}),
            PRICE,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "block {seq}: {body}");
        assert_eq!(body["amount_msat"], PRICE);
        let received = recv_kind(&mut callee, &aid, 404).await;
        assert_eq!(received.envelope.payment_proof.amount_msat, PRICE);
        let hash = body["payment_hash"].as_str().unwrap();
        assert_eq!(
            hex::encode(received.envelope.payment_proof.payment_hash),
            hash
        );
        assert!(
            hashes.insert(hash.to_owned()),
            "each block has a distinct settled payment"
        );
        settle(&a, hash).await;
        settle(&b, hash).await;
        for (wallet, direction) in [
            (&a, PaymentDirection::Outgoing),
            (&b, PaymentDirection::Incoming),
        ] {
            let payment = wallet.get_payment_status(hash).await.unwrap();
            assert_eq!(payment.amount_msat, PRICE);
            assert_eq!(payment.direction, direction);
            if direction == PaymentDirection::Outgoing {
                assert_eq!(payment.fee_msat, Some(0));
            }
        }
        for ((app, peer), anchor) in [(&caller, &bid), (&callee, &aid)].into_iter().zip(anchors) {
            let state = entry(app, peer).await;
            assert_eq!(state.next_block_seq, seq + 1);
            assert_eq!(
                state.paid_until_ms,
                Some(anchor + u64::from(seq + 1) * 60_000),
                "each settled block buys exactly one real minute from answer"
            );
        }
        let spent = u64::from(seq + 1) * PRICE;
        let status = caller
            .service
            .call_spend_status(&bid.to_hex(), CALL)
            .unwrap();
        assert_eq!(status.spent_msat, spent);
        assert_eq!(status.remaining_msat, held.reserved_msat - spent);
        assert_eq!(status.released_msat, 0);
        assert_eq!(caller.used(), used_before + SIGNAL_PRICE + reserved);
        // One reservation plus the offer; renewal never consumes another count.
        assert_eq!(
            caller
                .service
                .grant_view_for(&caller.client)
                .unwrap()
                .breakers
                .payments_last_hour,
            counts_before + 2
        );
        if sockets.is_none() {
            sockets = Some((
                socket(&caller, &bid).await.unwrap(),
                socket(&callee, &aid).await.unwrap(),
            ));
        }
        let (sa, sb) = sockets.as_mut().unwrap();
        audio_until(sa, sb, now_ms() + 400, &mut frame_seq).await;
        println!(
            "M6 BLOCK PASS seq={seq} amount_msat={PRICE} spent_msat={spent} remaining_msat={}",
            status.remaining_msat
        );
    }
    let (mut sa, mut sb) = sockets.unwrap();
    let caller_until = entry(&caller, &bid).await.paid_until_ms.unwrap();
    let callee_until = entry(&callee, &aid).await.paid_until_ms.unwrap();
    if reason == HangupReason::DurationCap {
        let (status, calls) = caller
            .get(&format!("/api/v1/calls?peer={}", bid.to_hex()), false)
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(calls[0]["next_block_due_ms"].is_null());
        let before = a.list_payments(100).await.unwrap().len();
        let (status, body) = compose(
            &caller,
            &bid,
            404,
            json!({"call_id":CALL, "seq":paid_blocks}),
            PRICE,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "over cap: {body}");
        assert_eq!(body["reason"], "call_duration_cap");
        assert_eq!(a.list_payments(100).await.unwrap().len(), before);
        audio_until(
            &mut sa,
            &mut sb,
            caller_until.saturating_sub(1_000),
            &mut frame_seq,
        )
        .await;
    } else {
        // Deliberately stop requesting 404, but keep audio and both transports
        // alive across the paid boundary and into the real ten-second grace.
        audio_until(
            &mut sa,
            &mut sb,
            caller_until.max(callee_until) + 2_000,
            &mut frame_seq,
        )
        .await;
        assert_eq!(
            entry(&callee, &aid).await.phase,
            Phase::Live,
            "not ended before grace"
        );
    }
    let (ending, other, ending_peer, cutoff, not_before) = if reason == HangupReason::Unpaid {
        (
            &callee,
            &mut caller,
            &aid,
            callee_until + 10_000,
            callee_until + 10_000,
        )
    } else {
        (
            &caller,
            &mut callee,
            &bid,
            caller_until + 10_000,
            caller_until,
        )
    };
    // Observe the responsible node directly. Waiting for both ends first can
    // hide a premature B cutoff behind A's later, correct local timeout.
    wait("responsible node ends the call", || async {
        let state = entry(ending, ending_peer).await;
        if state.phase != Phase::Ended {
            return false;
        }
        assert!(
            now_ms() >= not_before,
            "call ended before its boundary/grace"
        );
        true
    })
    .await;
    if reason == HangupReason::DurationCap {
        assert!(now_ms() < cutoff, "duration cap has no grace");
    }
    let notice = recv_kind(other, ending.state.identity.node_id(), 403).await;
    let signal: Value = serde_json::from_str(notice.plaintext.as_deref().unwrap()).unwrap();
    assert_eq!(
        signal["reason"],
        reason.as_str(),
        "real paid terminal notification"
    );
    let terminal_hash = hex::encode(notice.envelope.payment_proof.payment_hash);
    for wallet in [&a, &b] {
        settle(wallet, &terminal_hash).await;
        assert_eq!(
            wallet
                .get_payment_status(&terminal_hash)
                .await
                .unwrap()
                .amount_msat,
            SIGNAL_PRICE
        );
    }
    wait("both nodes ended", || async {
        entry(&caller, &bid).await.phase == Phase::Ended
            && entry(&callee, &aid).await.phase == Phase::Ended
    })
    .await;
    for (app, peer) in [(&caller, &bid), (&callee, &aid)] {
        assert_eq!(entry(app, peer).await.end_reason, Some(reason));
        assert_eq!(
            socket(app, peer).await.err(),
            Some(403),
            "ended media cannot reopen"
        );
    }
    // N2 deliberately caches positive admission for up to one second; its
    // independent route monitor tears down idle sockets on that cadence.
    // Do not mistake this documented bound for permission for another block.
    tokio::time::sleep(crate::call_media::ADMISSION_RECHECK + Duration::from_millis(200)).await;
    tokio::join!(closed_without_media(&mut sa), closed_without_media(&mut sb));
    wait("reservation release", || async {
        caller
            .service
            .call_spend_status(&bid.to_hex(), CALL)
            .unwrap()
            .closed
    })
    .await;
    let receipt = caller
        .service
        .call_spend_status(&bid.to_hex(), CALL)
        .unwrap();
    // The caller's duration-cap notice draws from its grant hold. For unpaid,
    // the callee sends the notice, leaving the caller's allowance to release.
    let closing_spent = if reason == HangupReason::DurationCap {
        SIGNAL_PRICE
    } else {
        0
    };
    let spent = u64::from(paid_blocks) * PRICE + closing_spent;
    assert_eq!(receipt.spent_msat, spent);
    assert_eq!(receipt.remaining_msat, 0);
    assert_eq!(receipt.released_msat, reserved - spent);
    let final_used = caller.used();
    // The offer and all settled draws, including a caller closing signal,
    // remain charged to the paired grant after the unused remainder releases.
    assert_eq!(final_used, used_before + SIGNAL_PRICE + spent);
    for _ in 0..3 {
        konsensus_api::calls::maintain_calls(&caller.state, now_ms())
            .await
            .unwrap();
        konsensus_api::calls::maintain_calls(&callee.state, now_ms())
            .await
            .unwrap();
        assert_eq!(
            caller
                .service
                .call_spend_status(&bid.to_hex(), CALL)
                .unwrap(),
            receipt,
            "repeated end cleanup cannot release twice"
        );
        assert_eq!(caller.used(), final_used);
    }
    let paid: Vec<_> = b
        .list_payments(100)
        .await
        .unwrap()
        .into_iter()
        .filter(|p| {
            p.direction == PaymentDirection::Incoming
                && p.status == PaymentStatus::Settled
                && p.amount_msat == PRICE
        })
        .collect();
    assert_eq!(
        paid.len(),
        served_before + paid_blocks as usize,
        "no hidden extra block payments"
    );
    assert!(frame_seq >= 20, "bidirectional audio exercised");
    println!("M6 CALL PASS reason={} paid_blocks={paid_blocks} price_msat={PRICE} closing_allowance_msat={CLOSING_ALLOWANCE} closing_spent_msat={closing_spent} reserved_msat={} spent_msat={} released_msat={} frames_each_direction={frame_seq}",
        reason.as_str(), held.reserved_msat, receipt.spent_msat, receipt.released_msat);
    steps.pass("cutoff, ordered media and exactly-once remainder release");
    caller.stop().await;
    callee.stop().await;
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}

/// The callee holds the lower NodeId, so it alone can run X3DH, and it loses its
/// session during a paid call while the caller keeps a working one. The next
/// block is refused before anything is paid. The session comes back on the same
/// connection within the bound, a message goes each way, and the next call is
/// paid and carries audio.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_paid_call_e2e.sh"]
async fn lost_session_recovers_on_the_connection_and_the_next_call_works() {
    /// The negotiation cooldown, one self-heal tick and round trips.
    const RECOVERY_BOUND: Duration = Duration::from_secs(30);
    const LOST: &str = "ffeeddccbbaa99887766554433221100";
    const MINUTES: u16 = 2;

    let mut lane = lane(MINUTES, true).await;
    let (aid, bid) = (lane.aid, lane.bid);
    assert!(bid.as_bytes() < aid.as_bytes(), "the callee initiates X3DH");
    let (caller, callee) = (&mut lane.caller, &mut lane.callee);
    let (a, b) = (&lane.a, &lane.b);

    let offer = json!({"v":1, "call_id":LOST, "media":"audio", "sdp":SDP});
    let (status, body) = compose(caller, &bid, 400, offer, SIGNAL_PRICE).await;
    assert_eq!(status, StatusCode::OK, "offer: {body}");
    recv_kind(callee, &aid, 400).await;
    let answer = json!({"v":1, "call_id":LOST, "sdp":SDP});
    let (status, body) = compose(callee, &aid, 401, answer, SIGNAL_PRICE).await;
    assert_eq!(status, StatusCode::OK, "answer: {body}");
    recv_kind(caller, &bid, 401).await;
    let block = |seq: u32| json!({"call_id":LOST, "seq":seq});
    let (status, body) = compose(caller, &bid, 404, block(0), PRICE).await;
    assert_eq!(status, StatusCode::OK, "block 0: {body}");
    recv_kind(callee, &aid, 404).await;
    settle(a, body["payment_hash"].as_str().unwrap()).await;
    settle(b, body["payment_hash"].as_str().unwrap()).await;
    let live = caller.state.storage.call_get(&bid, LOST).await.unwrap().unwrap();
    let due = live.next_block_due_ms().unwrap();
    tokio::time::sleep(Duration::from_millis(due.saturating_sub(now_ms()) + 20)).await;
    lane.steps.pass("a paid call is live and its next block is due");

    let connection = |app: &app::App, peer: NodeId| {
        let transport = app.state.transport.clone();
        async move { transport.connected_since(&peer).await.unwrap() }
    };
    let generations = (connection(caller, bid).await, connection(callee, aid).await);
    let payments = a.list_payments(100).await.unwrap().len();
    let spent = caller.service.call_spend_status(&bid.to_hex(), LOST).unwrap().spent_msat;
    // Self-heal keeps running, so bar recovery until the block has its answer. While
    // the higher id does not answer offers, the lower id cannot get its bundle.
    use std::sync::atomic::Ordering;
    crate::session_handler::HOLD_PREKEY_ANSWERS.store(true, Ordering::SeqCst);
    assert!(callee.state.session_manager.remove_session(&aid).await);
    let (status, body) = compose(caller, &bid, 404, block(1), PRICE).await;
    let lost_throughout = !callee.state.session_manager.has_session(&aid).await;
    crate::session_handler::HOLD_RECOVERY_RATCHET_INIT.store(true, Ordering::SeqCst);
    crate::session_handler::HOLD_PREKEY_ANSWERS.store(false, Ordering::SeqCst);
    let lost_at = std::time::Instant::now();
    assert!(lost_throughout, "the barrier held");
    assert_eq!(status, StatusCode::BAD_REQUEST, "no session, no invoice: {body}");
    assert_eq!(body["reason"], "call_block_unpayable", "{body}");
    assert_eq!(a.list_payments(100).await.unwrap().len(), payments, "nothing paid");
    let hold = caller.service.call_spend_status(&bid.to_hex(), LOST).unwrap();
    assert_eq!((hold.spent_msat, hold.closed), (spent, false), "the hold is untouched");
    lane.steps.pass("the block for a lost session is refused before payment");

    // Start B's first message while handover is still pending. The test barrier
    // holds A's RatchetInit, so scheduler speed cannot skip this state.
    wait("the recovered initiator has a sending chain", || async {
        assert!(lost_at.elapsed() < RECOVERY_BOUND, "not recovered within the bound");
        callee.state.session_manager.can_send(&aid).await
            && caller.state.session_manager.replacement_pending(&bid).await
    }).await;
    let first = json!({"operation_id": uuid::Uuid::new_v4().to_string(),
        "recipient": bid.to_hex(), "kind": 0, "plaintext": "first message during recovery"});
    let (status, body) = caller.post("/api/v1/messages/compose", first.clone(), false).await;
    crate::session_handler::HOLD_RECOVERY_RATCHET_INIT.store(false, Ordering::SeqCst);
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], "session_handover", "{body}");
    assert_eq!(body["retry_allowed"], true, "{body}");
    assert_eq!(a.list_payments(100).await.unwrap().len(), payments, "handover defers payment");
    println!("RECOVERY HANDOVER FIRST SEND deferred");
    // Retry the same operation immediately; production owns session readiness.
    // No test handover predicate is used to authorize this first message.
    loop {
        assert!(lost_at.elapsed() < RECOVERY_BOUND, "first recovery message: {body}");
        let (status, body) = caller.post("/api/v1/messages/compose", first.clone(), false).await;
        if status == StatusCode::OK {
            assert_eq!(body["accepted"], true, "{body}");
            recv_kind(callee, &aid, 0).await;
            break;
        }
        assert_eq!(body["reason"], "session_handover", "{body}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!("SESSION RECOVERED after {:?}", lost_at.elapsed());
    assert_eq!(
        (connection(caller, bid).await, connection(callee, aid).await),
        generations,
        "no new connection"
    );
    caller.compose(callee, "after recovery, from the caller").await;
    callee.compose(caller, "after recovery, from the callee").await;
    lane.steps.pass("the session recovers on the same connection and carries messages");

    // Nothing more was paid, so the callee ends this call as unpaid.
    wait("the lost call ends", || async {
        let ended = |app: &app::App, peer: NodeId| {
            let storage = app.state.storage.clone();
            async move {
                storage.call_get(&peer, LOST).await.unwrap().unwrap().phase == Phase::Ended
            }
        };
        ended(caller, bid).await && ended(callee, aid).await
    })
    .await;
    let notice = recv_kind(caller, &bid, 403).await;
    settle(a, &hex::encode(notice.envelope.payment_proof.payment_hash)).await;
    wait("its reservation closes", || async {
        caller.service.call_spend_status(&bid.to_hex(), LOST).unwrap().closed
    })
    .await;
    one_call(lane, MINUTES, 1, HangupReason::Unpaid).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_paid_call_e2e.sh"]
async fn unpaid_after_three_paid_blocks() {
    scenario(5, 3, HangupReason::Unpaid).await;
}

#[tokio::test]
async fn recovery_waits_until_both_sessions_have_switched() {
    let (_, initiator) = NodeIdentity::generate().unwrap();
    let (_, responder) = NodeIdentity::generate().unwrap();
    let (aid, bid) = (*initiator.node_id(), *responder.node_id());
    let a = SessionManager::new(Arc::new(initiator));
    let b = SessionManager::new(Arc::new(responder));
    assert!(!session_recovered(&a, &bid).await);

    let init = a.initiate_session(&bid, &b.prekey_bundle().await).await.unwrap();
    b.accept_session(&aid, &init).await.unwrap();
    assert!(!session_recovered(&b, &aid).await, "no sending chain yet");
    assert!(a.confirm_session(&bid).await);
    let first = a.encrypt(&bid, b"initial session").await.unwrap();
    assert_eq!(b.decrypt(&aid, &first).await.unwrap(), b"initial session");
    assert!(session_recovered(&a, &bid).await);
    assert!(session_recovered(&b, &aid).await);

    assert!(a.remove_session(&bid).await);
    let init = a.reinitiate_session(&bid, &b.prekey_bundle().await).await.unwrap();
    b.reaccept_session(&aid, &init).await.unwrap();
    assert!(a.can_send(&bid).await && b.can_send(&aid).await);
    assert!(!session_recovered(&a, &bid).await, "SessionAck is still outstanding");
    assert!(a.confirm_session(&bid).await);
    assert!(session_recovered(&a, &bid).await);
    assert!(!session_recovered(&b, &aid).await, "the responder still sends on the previous session");

    let init = a.encrypt(&bid, b"ratchet-init").await.unwrap();
    assert_eq!(b.decrypt(&aid, &init).await.unwrap(), b"ratchet-init");
    assert!(session_recovered(&a, &bid).await && session_recovered(&b, &aid).await);
    let reply = b.encrypt(&aid, b"after recovery").await.unwrap();
    assert_eq!(a.decrypt(&bid, &reply).await.unwrap(), b"after recovery");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_paid_call_e2e.sh"]
async fn one_minute_duration_cap() {
    scenario(1, 1, HangupReason::DurationCap).await;
}

/// Real LDK settlement, then a callee whose chain sync has lapsed: acts it has
/// been paid for count for a bounded time, and it takes on no new money work.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_paid_call_e2e.sh"]
async fn paid_signals_count_briefly_while_callee_is_not_ready() {
    let mut steps = Steps::new();
    let chain = infra::Chain::start().await;
    let fault = three_node::fault_proxy::FaultProxy::start(&chain.url).await;
    let dirs = [(); 2].map(|_| tempfile::tempdir().unwrap());
    let caller_config = infra::lightning_config(dirs[0].path(), &chain.url);
    let mut callee_config = infra::lightning_config(dirs[1].path(), &fault.url);
    // Only the callee's wallet sync goes through the fault; its chain API does not.
    callee_config.esplora_sync_intervals.lightning_wallet_sync_interval_secs = Some(10);
    let a = Arc::new(
        LdkProvider::new(caller_config.clone())
            .await
            .unwrap()
            .with_routing_fee_policy(three_node::direct_channel_fee_policy()),
    );
    let b = Arc::new(
        LdkProvider::new(callee_config.clone())
            .await
            .unwrap()
            .with_routing_fee_policy(three_node::direct_channel_fee_policy()),
    );
    chain.fund(a.node()).await;
    chain.fund(b.node()).await;
    let options = |config: &konsensus_lightning::LdkConfig, block_msat, readiness_gated| {
        Some(app::Options {
            identity: Arc::new(NodeIdentity::from_mnemonic(&config.mnemonic, "").unwrap()),
            chain_url: chain.api_url.clone(),
            calls: Some(app::CallOptions {
                block_msat,
                max_minutes: 5,
                offer_msat: SIGNAL_PRICE,
                chat_msat: 2_001,
            }),
            readiness_gated,
            owner_approval_key: None,
        })
    };
    let mut caller = app::App::start_with_options(
        dirs[0].path(),
        &chain,
        a.clone(),
        options(&caller_config, 7_001, false),
    )
    .await;
    let mut callee = app::App::start_with_options(
        dirs[1].path(),
        &chain,
        b.clone(),
        options(&callee_config, PRICE, true),
    )
    .await;
    let aid = *caller.state.identity.node_id();
    let bid = *callee.state.identity.node_id();
    let (status, body) = caller
        .post(
            "/api/v1/payments/open-channel",
            json!({
                "peer_pubkey": b.node().node_id().to_string(),
                "peer_addr": callee_config.listening_address,
                "amount_sats": 1_000_000, "announce": false,
            }),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "owner channel open: {body}");
    chain.confirm_channel(a.node(), b.node(), &[]).await;
    let money = callee.state.lightning.clone();
    wait("both wallets ready", || async {
        a.money_ready().await && money.money_ready().await
    })
    .await;
    three_node::list_contact(&caller, &callee, "owners list their call peer").await;
    three_node::list_contact(&callee, &caller, "owners list their call peer").await;
    three_node::connect(&caller, &callee, "Noise connection").await;
    wait("both signaling sessions established", || async {
        caller.state.session_manager.can_send(&bid).await
            && callee.state.session_manager.can_send(&aid).await
    })
    .await;
    three_node::elevate(&mut caller, &[bid.to_hex()]).await;
    three_node::elevate(&mut callee, &[aid.to_hex()]).await;
    caller.compose(&mut callee, "while ready").await;
    // The callee's real key, as its Lightning info frame would deliver it, so
    // these acts go by keysend: that path has no readiness check before paying.
    caller
        .state
        .peer_ln_pubkeys
        .lock()
        .await
        .insert(bid, b.node().node_id().to_string());
    steps.pass("two funded nodes, direct channel, callee behind the readiness wrappers");

    fault.set_limited(true);
    wait("callee chain sync lapses", || async {
        fault.rejected() > 0 && !money.money_ready().await
    })
    .await;
    let received_before = b
        .list_payments(100)
        .await
        .unwrap()
        .into_iter()
        .filter(|p| p.direction == PaymentDirection::Incoming)
        .count();

    // No pre-check protects a keysend: this is settled before the gate sees it.
    caller.compose(&mut callee, "paid while the callee cannot sync").await;
    let received: Vec<_> = b
        .list_payments(100)
        .await
        .unwrap()
        .into_iter()
        .filter(|p| p.direction == PaymentDirection::Incoming)
        .collect();
    assert_eq!(received.len(), received_before + 1, "exactly one new settlement");
    assert!(!money.money_ready().await, "still not ready when admitted");
    steps.pass("settled message admitted and delivered while not ready");

    // Nothing else opened: new invoices and other status readers still refuse.
    let settled = received
        .iter()
        .find(|p| p.status == PaymentStatus::Settled)
        .unwrap();
    assert!(matches!(
        money.get_payment_status(&settled.payment_hash).await,
        Err(LightningError::NotReady)
    ));
    assert!(matches!(
        money.create_invoice(1_000, "regtest", 60).await,
        Err(LightningError::NotReady)
    ));

    // A paid offer rings now, not as a late resend after the caller has gone.
    let offer = json!({"v":1, "call_id":CALL, "media":"audio", "sdp":SDP});
    let (status, body) = compose(&caller, &bid, 400, offer, SIGNAL_PRICE).await;
    assert_eq!(status, StatusCode::OK, "offer: {body}");
    assert_eq!(body["delivered"], true, "offer: {body}");
    recv_kind(&mut callee, &aid, 400).await;
    assert_eq!(entry(&callee, &aid).await.phase, Phase::Ringing);
    // The callee cannot pay for its answer yet. That refusal costs nothing and
    // leaves the call ringing.
    let (status, body) = compose(
        &callee,
        &aid,
        401,
        json!({"v":1, "call_id":CALL, "sdp":SDP}),
        SIGNAL_PRICE,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "answer: {body}");
    assert_eq!(body["code"], "not_ready", "answer: {body}");
    assert_eq!(entry(&callee, &aid).await.phase, Phase::Ringing);
    assert!(!money.money_ready().await, "still not ready after the offer");
    // A paid hangup reaches it too, so the ring ends with the caller.
    let (status, body) = compose(
        &caller,
        &bid,
        403,
        json!({"v":1, "call_id":CALL, "reason":"hangup"}),
        SIGNAL_PRICE,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "hangup: {body}");
    recv_kind(&mut callee, &aid, 403).await;
    assert_eq!(entry(&callee, &aid).await.phase, Phase::Ended);
    assert!(!money.money_ready().await, "still not ready after the hangup");
    steps.pass("offer rings, unpayable answer refused, hangup ends the ring, all while not ready");

    // Past the bound a fresh settlement is not confirmed: refused as it would
    // have been, nothing burned, and the sender's normal resend delivers it.
    let cutoff = b.gate_settlement_cutoff().expect("a good sync is on record");
    tokio::time::timeout(Duration::from_secs(300), async {
        while now_ms() / 1000 <= cutoff {
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("the settlement cutoff passes");
    assert!(!money.money_ready().await, "still not ready past the cutoff");
    assert_eq!(b.gate_settlement_cutoff(), Some(cutoff), "no sync moved the cutoff");
    const LATE: &str = "settled past the cutoff";
    let operation = uuid::Uuid::new_v4().to_string();
    let (status, body) = caller
        .post(
            "/api/v1/messages/compose",
            json!({"operation_id": operation, "recipient": bid.to_hex(), "kind": 0, "plaintext": LATE}),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "late message: {body}");
    let late_state = || async {
        let (status, body) = caller
            .get(&format!("/api/v1/messages/operations/{operation}"), false)
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body["state"].as_str().unwrap().to_owned()
    };
    wait("the late message is refused, retryably", || async {
        late_state().await == "rejected_retryable"
    })
    .await;
    assert!(!money.money_ready().await, "still not ready when refused");
    steps.pass("settlement past the bound refused while not ready");

    fault.set_limited(false);
    // Failed syncs have backed off by now, so this can take a few minutes.
    tokio::time::timeout(Duration::from_secs(360), async {
        while !money.money_ready().await {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("callee recovers");
    assert_ne!(late_state().await, "failed_paid", "a refusal past the bound stays retryable");
    caller.compose(&mut callee, "after recovery").await;
    steps.pass("recovery needs no restart; delivery continues");
    println!("GATE WHILE NOT READY PASS");
    caller.stop().await;
    callee.stop().await;
    a.shutdown().await.unwrap();
    money.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_paid_call_e2e.sh"]
async fn client_detach_stops_renewals_and_unanswered_calls_still_expire() {
    let mut lane = lane(5, false).await;
    let (aid, bid) = (lane.aid, lane.bid);
    for (call_id, cut_callee) in [
        ("10000000000000000000000000000001", true),
        ("10000000000000000000000000000002", false),
    ] {
        let (caller, callee) = (&mut lane.caller, &mut lane.callee);
        let (status, body) = compose(caller, &bid, 400,
            json!({"v":1, "call_id":call_id, "media":"audio", "sdp":SDP}), SIGNAL_PRICE).await;
        assert_eq!(status, StatusCode::OK, "offer: {body}");
        recv_kind(callee, &aid, 400).await;
        let (status, body) = compose(callee, &aid, 401,
            json!({"v":1, "call_id":call_id, "sdp":SDP}), SIGNAL_PRICE).await;
        assert_eq!(status, StatusCode::OK, "answer: {body}");
        recv_kind(caller, &bid, 401).await;
        let (status, body) = compose(caller, &bid, 404,
            json!({"call_id":call_id, "seq":0}), PRICE).await;
        assert_eq!(status, StatusCode::OK, "block zero: {body}");
        recv_kind(callee, &aid, 404).await;
        settle(&lane.a, body["payment_hash"].as_str().unwrap()).await;
        settle(&lane.b, body["payment_hash"].as_str().unwrap()).await;
        let initial = caller.state.storage.call_get(&bid, call_id).await.unwrap().unwrap();
        let mut a_socket = socket_for(caller, &bid, call_id).await.unwrap();
        let mut b_socket = socket_for(callee, &aid, call_id).await.unwrap();
        let mut seq = 0;
        audio_until(&mut a_socket, &mut b_socket, now_ms() + 5_000, &mut seq).await;
        let before = lane.a.list_payments(100).await.unwrap().into_iter()
            .filter(|p| p.direction == PaymentDirection::Outgoing && p.amount_msat == PRICE).count();
        let cut = std::time::Instant::now();
        let mut survivor = if cut_callee { drop(b_socket); a_socket } else { drop(a_socket); b_socket };
        let generations = (
            caller.state.transport.connected_since(&bid).await.unwrap(),
            callee.state.transport.connected_since(&aid).await.unwrap(),
        );
        let mut renewal_attempted = false;
        tokio::time::timeout(Duration::from_secs(90), async {
            let mut tick = tokio::time::interval(Duration::from_millis(20));
            loop {
                tick.tick().await;
                // The surviving client keeps sending even with no received audio.
                let _ = survivor.send(Message::Binary(packet(seq, 0xa0))).await;
                seq += 1;
                let a_entry = caller.state.storage.call_get(&bid, call_id).await.unwrap().unwrap();
                let b_entry = callee.state.storage.call_get(&aid, call_id).await.unwrap().unwrap();
                if cut_callee && !renewal_attempted && now_ms() >= initial.next_block_due_ms().unwrap() {
                    renewal_attempted = true;
                    let (status, body) = compose(caller, &bid, 404,
                        json!({"call_id":call_id, "seq":1}), PRICE).await;
                    assert_eq!(status, StatusCode::BAD_REQUEST, "detached callee must refuse renewal: {body}");
                    assert_eq!(body["reason"], "call_block_unpayable", "{body}");
                }
                if a_entry.phase == Phase::Ended && b_entry.phase == Phase::Ended { break; }
            }
        }).await.expect("both calls must end within 90 seconds of client cut");
        assert_eq!(renewal_attempted, cut_callee);
        for (app, peer) in [(&*caller, bid), (&*callee, aid)] {
            let ended = app.state.storage.call_get(&peer, call_id).await.unwrap().unwrap();
            assert_eq!(ended.next_block_seq, 1, "no post-cut block admitted");
            if cut_callee && peer == aid {
                assert_eq!(ended.end_reason, Some(HangupReason::Hangup));
            } else {
                assert_eq!(ended.end_reason, Some(HangupReason::Unpaid));
            }
        }
        assert_eq!(lane.a.list_payments(100).await.unwrap().into_iter()
            .filter(|p| p.direction == PaymentDirection::Outgoing && p.amount_msat == PRICE).count(), before,
            "no new media payment after the cut");
        assert_eq!((caller.state.transport.connected_since(&bid).await.unwrap(),
            callee.state.transport.connected_since(&aid).await.unwrap()), generations, "both nodes stay connected");
        // Pre-cut frames may already be buffered in the survivor's receive queue.
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(Ok(message)) = survivor.next().await {
                if matches!(message, Message::Close(_)) { break; }
            }
        }).await.expect("surviving media socket closes");
        wait("cut call reservation released", || async {
            caller.service.call_spend_status(&bid.to_hex(), call_id).unwrap().closed
        }).await;
        println!("client detach callee={cut_callee} closed_ms={} paid_blocks=1", cut.elapsed().as_millis());
    }
    let call_id = "10000000000000000000000000000003";
    let (status, body) = compose(&lane.caller, &bid, 400,
        json!({"v":1, "call_id":call_id, "media":"audio", "sdp":SDP}), SIGNAL_PRICE).await;
    assert_eq!(status, StatusCode::OK, "unanswered offer: {body}");
    recv_kind(&mut lane.callee, &aid, 400).await;
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let mut open = false;
            for (app, peer) in [(&lane.caller, bid), (&lane.callee, aid)] {
                let (status, calls) = app.get(&format!("/api/v1/calls?peer={}", peer.to_hex()), false).await;
                assert_eq!(status, StatusCode::OK, "{calls}");
                open |= calls.as_array().unwrap().iter().any(|c| c["id"] == call_id);
            }
            if !open { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }).await.expect("unanswered call expires");
    for (app, peer) in [(&lane.caller, bid), (&lane.callee, aid)] {
        let ended = app.state.storage.call_get(&peer, call_id).await.unwrap().unwrap().at(now_ms()).unwrap();
        assert_eq!(ended.phase, Phase::Ended);
        assert_eq!(ended.end_reason, Some(HangupReason::Timeout));
        assert_eq!(ended.next_block_seq, 0);
        assert_eq!(ended.paid_until_ms, None);
    }
    lane.caller.stop().await;
    lane.callee.stop().await;
    lane.a.shutdown().await.unwrap();
    lane.b.shutdown().await.unwrap();
}
