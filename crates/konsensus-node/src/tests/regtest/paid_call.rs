//! M6 P1: two production nodes, real LDK settlement and owner media sockets.
//! Reuses the three-node paid lane's chain, app, pairing and owner helpers.
//! No fabricated call rows, payment proofs, peer prices or accelerated clocks.
use super::*;
use axum::http::StatusCode;
use futures::{SinkExt, StreamExt};
use konsensus_core::payloads::call::{CallEntry, HangupReason, Phase};
use konsensus_core::NodeId;
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
const PRICE: u64 = 23_001;
const CALL: &str = "00112233445566778899aabbccddeeff";
const SDP: &str = "v=0\r\ns=M6 node-routed audio\r\nt=0 0\r\n";

fn now_ms() -> u64 {
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
    let mut request = format!(
        "ws://{}/api/v1/calls/{CALL}/media?peer={}",
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
    app.post(
        "/api/v1/messages/compose",
        json!({
            "operation_id": uuid::Uuid::new_v4().to_string(),
            "recipient": peer.to_hex(), "kind": kind, "plaintext": signal.to_string(),
            "max_routing_fee_msat": 0, "max_total_msat": cap,
        }),
        false,
    )
    .await
}

async fn scenario(max_minutes: u16, paid_blocks: u32, reason: HangupReason) {
    let mut steps = Steps::new();
    let chain = infra::Chain::start().await;
    let dirs = [(); 2].map(|_| tempfile::tempdir().unwrap());
    let configs = dirs
        .each_ref()
        .map(|dir| infra::lightning_config(dir.path(), &chain.url));
    let a = Arc::new(
        LdkProvider::new(configs[0].clone())
            .await
            .unwrap()
            .with_routing_fee_policy(three_node::direct_channel_fee_policy()),
    );
    let b = Arc::new(
        LdkProvider::new(configs[1].clone())
            .await
            .unwrap()
            .with_routing_fee_policy(three_node::direct_channel_fee_policy()),
    );
    chain.fund(a.node()).await;
    chain.fund(b.node()).await;
    let start = |index: usize, wallet, block_msat, max_minutes| {
        app::App::start_with_options(
            dirs[index].path(),
            &chain,
            wallet,
            Some(app::Options {
                identity: Arc::new(
                    NodeIdentity::from_mnemonic(&configs[index].mnemonic, "").unwrap(),
                ),
                chain_url: chain.api_url.clone(),
                calls: Some(app::CallOptions {
                    block_msat,
                    max_minutes,
                }),
            }),
        )
    };
    // Different prices catch an accidental fallback to the caller's tariff.
    let mut caller = start(0, a.clone(), 7_001, max_minutes).await;
    let mut callee = start(1, b.clone(), PRICE, 60).await;
    let aid = *caller.state.identity.node_id();
    let bid = *callee.state.identity.node_id();

    let (status, body) = caller
        .post(
            "/api/v1/payments/open-channel",
            json!({
                "peer_pubkey": b.node().node_id().to_string(),
                "peer_addr": configs[1].listening_address,
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
        caller.state.session_manager.can_send(&bid).await
            && callee.state.session_manager.can_send(&aid).await
    })
    .await;

    let offer = json!({"v":1, "call_id":CALL, "media":"audio", "sdp":SDP});
    let before = a.list_payments(100).await.unwrap().len();
    let (status, _) = compose(&caller, &bid, 400, offer.clone(), 1_000).await;
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
    let used_before = caller.used();
    let counts_before = caller
        .service
        .grant_view_for(&caller.client)
        .unwrap()
        .breakers
        .payments_last_hour;
    let quoted = konsensus_api::calls::peer_call_kind_price(&caller.state, &bid, 404)
        .await
        .unwrap();
    assert_eq!(quoted, PRICE, "callee's live kind-404 answer");
    steps.pass("two funded nodes, direct channel, paired clients and owner consent");

    let (status, body) = compose(&caller, &bid, 400, offer, 1_000).await;
    assert_eq!(status, StatusCode::OK, "offer: {body}");
    recv_kind(&mut callee, &aid, 400).await;
    let held = caller
        .service
        .call_spend_status(&bid.to_hex(), CALL)
        .unwrap();
    assert_eq!(held.reserved_msat, u64::from(max_minutes) * PRICE);
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
        1_000,
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
        assert_eq!(caller.used(), used_before + 1_000 + held.reserved_msat);
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
            1_000
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
    assert_eq!(receipt.spent_msat, u64::from(paid_blocks) * PRICE);
    assert_eq!(receipt.remaining_msat, 0);
    assert_eq!(
        receipt.released_msat,
        held.reserved_msat - receipt.spent_msat
    );
    let final_used = caller.used();
    // Timer notifications use bounded node authority, not the paired grant.
    assert_eq!(final_used, used_before + 1_000 + receipt.spent_msat);
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
        paid_blocks as usize,
        "no hidden extra block payments"
    );
    assert!(frame_seq >= 20, "bidirectional audio exercised");
    println!("M6 CALL PASS reason={} paid_blocks={paid_blocks} price_msat={PRICE} reserved_msat={} spent_msat={} released_msat={} frames_each_direction={frame_seq}",
        reason.as_str(), held.reserved_msat, receipt.spent_msat, receipt.released_msat);
    steps.pass("cutoff, ordered media and exactly-once remainder release");
    caller.stop().await;
    callee.stop().await;
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_paid_call_e2e.sh"]
async fn unpaid_after_three_paid_blocks() {
    scenario(5, 3, HangupReason::Unpaid).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "real Bitcoin Core + electrs; scripts/regress/two_node_paid_call_e2e.sh"]
async fn one_minute_duration_cap() {
    scenario(1, 1, HangupReason::DurationCap).await;
}
