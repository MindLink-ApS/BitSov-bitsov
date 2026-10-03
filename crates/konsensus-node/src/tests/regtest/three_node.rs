//! Atlas TEST5 runs 1–4, local regtest only. Doctrine: 1–6 hold: all
//! delivered content settles, refusals spend nothing, keys identify nodes and
//! devices, contacts stay local, seeds are disposable and self-custodied.
use super::*;
use axum::http::StatusCode;
use konsensus_api::control::{self, ControlRequest, ControlResponse};
use konsensus_core::traits::transport::MessageTransport;
use konsensus_message::Frame;
use std::path::Path;

#[path = "fault_proxy.rs"]
mod fault_proxy;

const APPROVAL: &str = "Atlas run 2 #15 / run 3 #2: remote elevation + headless owner approval";
const QUOTE: &str = "Atlas runs 1–2: read-scope quote and paid receipt blocked";
const SYNC: &str = "Atlas run 2 #13 / run 4 steps 1,3: 429 stalls and silent recipient timeout";
const REPLY: &str = "Atlas run 2 #17: A has zero inbound liquidity; B cannot reply yet";
const RESTART: &str = "Atlas run 4 steps 2–3: recipient restart during an active client flow";
const SKEW: &str = "Atlas run 4 step 3: mixed-version height-0 price table";
const ROOM: &str = "Atlas run 2 #14–18: paid room flow never reached";

async fn eventually<F, Fut>(incident: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(180), async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{incident}: condition did not recover in 180s"));
}

async fn owner(app: &app::App, request: ControlRequest, incident: &str) {
    let socket = app
        .state
        .data_dir
        .as_ref()
        .unwrap()
        .join(control::SOCKET_FILE);
    let reply = tokio::time::timeout(Duration::from_secs(5), control::send(&socket, &request))
        .await
        .expect("owner socket deadline")
        .expect("owner socket response");
    assert!(
        matches!(reply, ControlResponse::Ok { .. }),
        "{incident}: {reply:?}"
    );
}

async fn elevate(app: &mut app::App) {
    use std::os::unix::fs::PermissionsExt;
    let scopes = app.refresh_token().await;
    assert_eq!(
        scopes,
        json!(["read", "receive"]),
        "{APPROVAL}: starts without spend"
    );
    let (status, pending) = app
        .post(
            "/api/v1/pair/elevation-request",
            json!({"scopes": ["spend"], "budget": {"budget_msat": 1_000_000}}),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{APPROVAL}: {pending}");
    assert!(
        app.service.grant_view_for(&app.client).is_none(),
        "{APPROVAL}: ask must not grant"
    );
    let op = pending["op_id"].as_str().expect(APPROVAL);
    let (status, body) = app
        .get(&format!("/api/v1/pair/elevation/{op}"), false)
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{APPROVAL}: pending must be remotely readable: {body}"
    );
    let file = app.service.dir().join(format!("owner-approval-{op}"));
    assert_eq!(
        std::fs::metadata(&file)
            .expect(APPROVAL)
            .permissions()
            .mode()
            & 0o777,
        0o600,
        "{APPROVAL}: protected headless code file"
    );
    let text = std::fs::read_to_string(&file).expect(APPROVAL);
    let confirmation = text
        .lines()
        .find(|line| line.starts_with("GRANT ") && line.contains(" CODE "))
        .expect(APPROVAL)
        .to_owned();
    let nonce = confirmation.split_once(" CODE ").expect(APPROVAL).1;
    let short_code = text
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("and type this code when it asks: ")
        })
        .expect(APPROVAL);
    for response in [&pending, &body] {
        for secret in [nonce, short_code] {
            assert!(
                !response.to_string().contains(secret),
                "{APPROVAL}: secret not in HTTP"
            );
        }
    }
    owner(
        app,
        ControlRequest::Grant {
            op_id: op.to_owned(),
            confirmation,
            terms: konsensus_api::spend_budget::GrantTerms::new(1_000_000)
                .per_call(200_000)
                .for_secs(3600),
        },
        APPROVAL,
    )
    .await;
    assert!(!file.exists(), "{APPROVAL}: consumed owner file removed");
    let scopes = app.refresh_token().await;
    assert!(
        scopes.as_array().expect(APPROVAL).contains(&json!("spend")),
        "{APPROVAL}: refreshed token"
    );
    let (status, grant) = app.get("/api/v1/pair/grant", false).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{APPROVAL}: remote grant read: {grant}"
    );
    assert_eq!(app.used(), 0, "{APPROVAL}: granting never spends");
}

async fn connect(from: &app::App, to: &app::App, incident: &str) {
    from.transport
        .connect(
            to.state.identity.node_id(),
            &to.transport.listen_addr().unwrap().to_string(),
        )
        .await
        .unwrap_or_else(|e| panic!("{incident}: Noise: {e}"));
    eventually(incident, || {
        to.transport.is_connected(from.state.identity.node_id())
    })
    .await;
    // The production stateless quote gate quarantines a new connection for 1s.
    tokio::time::sleep(Duration::from_millis(1100)).await;
}

async fn quote(from: &app::App, to: &app::App, incident: &str) -> Value {
    let (status, body) = tokio::time::timeout(
        Duration::from_secs(8),
        from.post(
            "/api/v1/messages/first-contact/quote",
            json!({"recipient": to.state.identity.node_id().to_hex()}),
            false,
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{incident}: quote timed out instead of answering"));
    assert_eq!(status, StatusCode::OK, "{incident}: {body}");
    assert_eq!(body["admission_msat"], 2_001, "{incident}: {body}");
    assert_eq!(body["message_msat"], 2_001, "{incident}: {body}");
    body
}

async fn approve_contact(from: &app::App, to: &app::App, quote: &Value) {
    owner(
        from,
        ControlRequest::ApproveFirstContact {
            client_id: from.client.clone(),
            grant_op_id: from
                .service
                .grant_view_for(&from.client)
                .expect(APPROVAL)
                .op_id,
            recipient: to.state.identity.node_id().to_hex(),
            max_total_msat: quote["total_msat"].as_u64().expect(QUOTE),
            contact_budget_msat: Some(200_000),
        },
        APPROVAL,
    )
    .await;
}

async fn list_contact(from: &app::App, to: &app::App, incident: &str) {
    let (status, body) = from
        .post(
            "/api/v1/peers",
            json!({
                "node_id": to.state.identity.node_id().to_hex(),
                "addr": to.transport.listen_addr().unwrap().to_string(), "auto_connect": false,
            }),
            true,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{incident}: private owner contact: {body}"
    );
}

async fn paid(from: &app::App, to: &mut app::App, text: &str, incident: &str) -> Value {
    to.received = to.state.ws_broadcast.subscribe();
    let used = from.used();
    let (status, body) = from
        .post(
            "/api/v1/messages/compose",
            json!({
                "recipient": to.state.identity.node_id().to_hex(), "kind": 0, "plaintext": text,
            }),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{incident}: {body}");
    assert_eq!(body["delivered"], true, "{incident}: {body}");
    assert_eq!(
        body["fee_paid_msat"], 0,
        "{incident}: direct channel has a known zero routing fee, not null"
    );
    assert!(from.used() > used, "{incident}: each act must be paid");
    let got = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let got = to.received.recv().await.expect("recipient feed");
            if got.envelope.sender == *from.state.identity.node_id() && got.plaintext.is_some() {
                break got;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{incident}: no decrypted message"));
    assert_eq!(
        got.plaintext.as_deref(),
        Some(text),
        "{incident}: decrypted content"
    );
    assert_ne!(
        got.envelope.ciphertext,
        text.as_bytes(),
        "{incident}: E2EE on the wire"
    );
    assert_eq!(
        got.envelope.payment_proof.amount_msat, 2_001,
        "{incident}: recipient-bound payment"
    );
    assert_eq!(
        got.envelope.recipient,
        konsensus_core::Recipient::Node(*to.state.identity.node_id()),
        "{incident}"
    );
    for app in [from, &*to] {
        let peer = if app.state.identity.node_id() == from.state.identity.node_id() {
            to.state.identity.node_id()
        } else {
            from.state.identity.node_id()
        };
        assert!(
            app.state.session_manager.has_session(peer).await,
            "{incident}: E2EE session missing"
        );
    }
    body
}

async fn start_app(
    dir: &Path,
    chain: &infra::Chain,
    wallet: Arc<LdkProvider>,
    config: &konsensus_lightning::LdkConfig,
    chain_url: &str,
) -> app::App {
    app::App::start_with_options(
        dir,
        chain,
        wallet,
        Some(app::Options {
            identity: Arc::new(NodeIdentity::from_mnemonic(&config.mnemonic, "").unwrap()),
            chain_url: chain_url.to_owned(),
        }),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "local Bitcoin Core + Esplora electrs; scripts/regress/three_node_paid_e2e.sh"]
async fn three_node_paid_e2e() {
    for variable in ["BITCOIND_EXE", "ELECTRS_EXE"] {
        if !std::env::var_os(variable).is_some_and(|p| Path::new(&p).is_file()) {
            eprintln!("SKIP three-node paid E2E: {variable} unavailable offline; compiled, no daemons started");
            return;
        }
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let mut steps = Steps::new();
    let chain = infra::Chain::start().await;
    let fault = fault_proxy::FaultProxy::start(&chain.url).await;
    let dirs = [(); 3].map(|_| tempfile::tempdir().unwrap());
    let configs = [
        infra::lightning_config(dirs[0].path(), &chain.url),
        infra::lightning_config(dirs[1].path(), &fault.url),
        infra::lightning_config(dirs[2].path(), &chain.url),
    ];
    let a = Arc::new(LdkProvider::new(configs[0].clone()).await.unwrap());
    let mut b = Arc::new(LdkProvider::new(configs[1].clone()).await.unwrap());
    let c = Arc::new(LdkProvider::new(configs[2].clone()).await.unwrap());
    chain.fund(a.node()).await;
    let mut alice = start_app(
        dirs[0].path(),
        &chain,
        a.clone(),
        &configs[0],
        &chain.api_url,
    )
    .await;
    let mut bob = start_app(dirs[1].path(), &chain, b.clone(), &configs[1], &fault.url).await;
    let mut carol = start_app(
        dirs[2].path(),
        &chain,
        c.clone(),
        &configs[2],
        &chain.api_url,
    )
    .await;
    for wallet in [&a, &b, &c] {
        eventually(QUOTE, || wallet.money_ready()).await;
    }
    assert_eq!(
        alice.refresh_token().await,
        json!(["read", "receive"]),
        "{APPROVAL}"
    );

    // Owner-only channel opening: paired read+receive cannot open a channel.
    for (wallet, config, other) in [(&b, &configs[1], c.node()), (&c, &configs[2], b.node())] {
        let request = json!({"peer_pubkey": wallet.node().node_id().to_string(),
            "peer_addr": config.listening_address, "amount_sats": 1_000_000, "announce": false});
        let channels_before = a.node().list_channels().len();
        let (status, body) = alice
            .post("/api/v1/payments/open-channel", request.clone(), false)
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "Atlas run 2 #7: paired channel open: {body}"
        );
        assert_eq!(
            a.node().list_channels().len(),
            channels_before,
            "Atlas run 2 #7: refusal must not open"
        );
        let (status, body) = alice
            .post("/api/v1/payments/open-channel", request, true)
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "Atlas run 2 #10–12: owner channel open: {body}"
        );
        chain
            .confirm_channel(a.node(), wallet.node(), &[other])
            .await;
    }
    assert_eq!(
        a.node().list_channels().len(),
        2,
        "Atlas run 2 #12: A has channels to B and C"
    );
    assert_eq!(
        capacity(b.node()),
        0,
        "{REPLY}: B starts without outbound balance"
    );
    connect(&alice, &bob, QUOTE).await;
    connect(&alice, &carol, QUOTE).await;
    steps.pass("Atlas run 2 channels: A->B and A->C usable, three application nodes");

    // No cache seeding: 429 travels through B's real chain provider and LDK.
    fault.set_limited(true);
    eventually(SYNC, || async {
        fault.rejected() > 0 && b.chain_sync_status().is_some() && !b.money_ready().await
    })
    .await;
    let before = (
        capacity(a.node()),
        capacity(b.node()),
        b.list_payments(500).await.unwrap().len(),
    );
    let (status, refusal) = tokio::time::timeout(
        Duration::from_secs(8),
        alice.post(
            "/api/v1/messages/first-contact/quote",
            json!({"recipient": bob.state.identity.node_id().to_hex()}),
            false,
        ),
    )
    .await
    .unwrap_or_else(|_| panic!("{SYNC}: recipient silently timed out"));
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{SYNC}: {refusal}");
    assert_eq!(refusal["code"], "peer_not_ready", "{SYNC}: {refusal}");
    assert_eq!(refusal["retry_allowed"], true, "{SYNC}: {refusal}");
    assert_eq!(
        (
            capacity(a.node()),
            capacity(b.node()),
            b.list_payments(500).await.unwrap().len()
        ),
        before,
        "{SYNC}: refusal changes neither balances nor invoice records"
    );
    assert!(
        alice.service.grant_view_for(&alice.client).is_none(),
        "{SYNC}: no hidden spend grant"
    );
    chain.mine(&[a.node(), c.node()], 1).await;
    let tip: u64 = chain.bitcoin.client.call("getblockcount", &[]).unwrap();
    fault.set_limited(false);
    eventually(SYNC, || async {
        b.chain_sync_status().is_none()
            && b.money_ready().await
            && u64::from(b.node().status().current_best_block.height) == tip
    })
    .await;
    steps.pass("Atlas run 4 429: typed refusal in <8s, background sync recovers without restart/manual sync");

    let payments_before = b.list_payments(500).await.unwrap().len();
    let first = quote(&alice, &bob, QUOTE).await;
    assert_eq!(
        b.list_payments(500).await.unwrap().len(),
        payments_before,
        "{QUOTE}: quote does not create a payable record"
    );
    let before = (
        capacity(a.node()),
        capacity(b.node()),
        settled_outgoing(&a).await.len(),
        b.list_payments(500).await.unwrap().len(),
    );
    bob.received = bob.state.ws_broadcast.subscribe();
    let (status, refusal) = alice
        .post(
            "/api/v1/messages/compose",
            json!({
                "recipient": bob.state.identity.node_id().to_hex(), "kind": 0,
                "plaintext": "read+receive cannot spend",
            }),
            false,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "{APPROVAL}: pre-elevation compose: {refusal}"
    );
    assert_eq!(
        refusal, "token lacks required scope: spend",
        "{APPROVAL}: explicit authority refusal"
    );
    assert_eq!(
        (
            capacity(a.node()),
            capacity(b.node()),
            settled_outgoing(&a).await.len(),
            b.list_payments(500).await.unwrap().len()
        ),
        before,
        "{APPROVAL}: no payment or invoice on refusal"
    );
    assert!(
        matches!(
            bob.received.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ),
        "{APPROVAL}: refused compose must not reach recipient"
    );
    elevate(&mut alice).await;
    approve_contact(&alice, &bob, &first).await;
    paid(&alice, &mut bob, "Atlas paid first contact A to B", QUOTE).await;
    assert_eq!(
        alice.used(),
        4_002,
        "{QUOTE}: admission + message, zero routing fee"
    );
    steps.pass("Atlas runs 1–3: read quote, remote spend request, headless control grant, paid E2EE receipt");

    list_contact(&alice, &bob, REPLY).await;
    elevate(&mut bob).await;
    let before = (
        capacity(a.node()),
        capacity(b.node()),
        bob.used(),
        settled_outgoing(&b).await.len(),
    );
    let (status, refusal) = bob.post("/api/v1/messages/compose", json!({
        "recipient": alice.state.identity.node_id().to_hex(), "kind": 0, "plaintext": "no reply liquidity yet",
    }), false).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{REPLY}: {refusal}");
    assert_eq!(refusal["code"], "not_dispatched", "{REPLY}: {refusal}");
    assert_eq!(
        (
            capacity(a.node()),
            capacity(b.node()),
            bob.used(),
            settled_outgoing(&b).await.len()
        ),
        before,
        "{REPLY}: refusal released reservation and paid nothing"
    );
    let invoice = b
        .create_invoice(50_000_000, "regtest inbound liquidity on A", 600)
        .await
        .unwrap();
    a.pay_invoice_with_fee_limit(&invoice.bolt11, 0)
        .await
        .unwrap();
    settle(&a, &invoice.payment_hash).await;
    settle(&b, &invoice.payment_hash).await;
    eventually(REPLY, || async { capacity(b.node()) > 10_000_000 }).await;
    paid(
        &bob,
        &mut alice,
        "B replies after A obtains inbound liquidity",
        REPLY,
    )
    .await;
    assert_eq!(bob.used(), 2_001, "{REPLY}: one paid reply only");
    list_contact(&bob, &alice, RESTART).await;
    steps.pass(
        "Atlas run 2 liquidity: unfunded reply refused without payment, rebalanced reply delivered",
    );

    let first_c = quote(&alice, &carol, ROOM).await;
    approve_contact(&alice, &carol, &first_c).await;
    paid(&alice, &mut carol, "A to C first contact", ROOM).await;
    list_contact(&alice, &carol, ROOM).await;

    // An older recipient advertised height 0 while current senders enforce
    // table expiry. Inject the old wire representation, not a cache mutation.
    bob.transport
        .send_frame(
            alice.state.identity.node_id(),
            &Frame::PriceTable {
                prices: std::collections::HashMap::from([("communication".to_owned(), 999_999)]),
                block_height: 0,
                valid_blocks: 1,
                trust_discount: 0.0,
            },
        )
        .await
        .expect(SKEW);
    eventually(SKEW, || async {
        alice
            .state
            .peer_prices
            .get_peer_entry(bob.state.identity.node_id())
            .await
            .is_some_and(|entry| {
                entry.block_height == 0 && entry.prices.get("communication") == Some(&999_999)
            })
    })
    .await;
    assert!(
        alice
            .state
            .peer_prices
            .get_fresh_peer_price(
                bob.state.identity.node_id(),
                0,
                tip,
                Duration::from_secs(300)
            )
            .await
            .is_none(),
        "{SKEW}: reject expired height-0 table"
    );
    let used = alice.used();
    paid(
        &alice,
        &mut bob,
        "paid through mixed-version price table",
        SKEW,
    )
    .await;
    assert_eq!(
        alice.used() - used,
        2_001,
        "{SKEW}: equal-price fallback; no stale overpayment"
    );
    steps
        .pass("Atlas run 4 version mix: stale height-0 wire table cannot change the settled price");

    // Restart the whole recipient stack between paid acts while A stays live.
    let bob_id = *bob.state.identity.node_id();
    let ln_id = b.node().node_id();
    let channels: Vec<_> = b
        .node()
        .list_channels()
        .iter()
        .map(|ch| ch.channel_id)
        .collect();
    let used_a = alice.used();
    bob.stop().await;
    b.shutdown().await.expect(RESTART);
    drop(b);
    eventually(RESTART, || async {
        !alice.transport.is_connected(&bob_id).await
    })
    .await;
    b = Arc::new(LdkProvider::new(configs[1].clone()).await.expect(RESTART));
    bob = start_app(dirs[1].path(), &chain, b.clone(), &configs[1], &fault.url).await;
    assert_eq!(
        *bob.state.identity.node_id(),
        bob_id,
        "{RESTART}: node key survives"
    );
    assert_eq!(
        b.node().node_id(),
        ln_id,
        "{RESTART}: wallet identity survives"
    );
    assert_eq!(
        b.node()
            .list_channels()
            .iter()
            .map(|ch| ch.channel_id)
            .collect::<Vec<_>>(),
        channels,
        "{RESTART}: channel state survives"
    );
    assert!(
        bob.state
            .session_manager
            .has_session(alice.state.identity.node_id())
            .await,
        "{RESTART}: encrypted session restored from disk before reconnect"
    );
    eventually(RESTART, || b.money_ready()).await;
    connect(&alice, &bob, RESTART).await;
    eventually(RESTART, || async {
        b.node().list_channels().iter().all(|ch| ch.is_usable)
    })
    .await;
    assert_eq!(
        alice.used(),
        used_a,
        "{RESTART}: reconnect itself is not a payment"
    );
    paid(
        &alice,
        &mut bob,
        "A keeps its paired client across B restart",
        RESTART,
    )
    .await;
    steps.pass(
        "Atlas run 4 restart: same keys/channels/session storage, A's existing client sends again",
    );

    use konsensus_core::payloads::room::RoomBinding;
    let room = RoomBinding::create(&[
        *alice.state.identity.node_id(),
        bob_id,
        *carol.state.identity.node_id(),
    ])
    .unwrap();
    let text = json!({"v": 1, "room": room, "msg": format!("{:032x}", rand::random::<u128>()), "text": "Atlas room B+C"}).to_string();
    bob.received = bob.state.ws_broadcast.subscribe();
    carol.received = carol.state.ws_broadcast.subscribe();
    let used = alice.used();
    let (status, receipt) = alice
        .post(
            "/api/v1/messages/compose",
            json!({
                "recipient": room.id, "is_room": true, "kind": 0, "plaintext": text,
            }),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{ROOM}: {receipt}");
    assert_eq!(
        receipt["amount_msat"], 4_002,
        "{ROOM}: two separately paid acts"
    );
    assert_eq!(
        receipt["fee_paid_msat"], 0,
        "{ROOM}: known direct-channel fees"
    );
    assert_eq!(
        alice.used() - used,
        4_002,
        "{ROOM}: exact two-recipient debit"
    );
    let outcomes = receipt["member_outcomes"].as_array().expect(ROOM);
    assert_eq!(outcomes.len(), 2, "{ROOM}: two receipts");
    for outcome in outcomes {
        assert_eq!(outcome["status"], "settled", "{ROOM}: {outcome}");
        assert_eq!(outcome["amount_msat"], 2_001, "{ROOM}: {outcome}");
    }
    for recipient in [&mut bob, &mut carol] {
        let got = recv_from(recipient, alice.state.identity.node_id(), 0).await;
        assert_eq!(
            got.plaintext.as_deref(),
            Some(text.as_str()),
            "{ROOM}: decrypted room binding"
        );
        assert_eq!(
            got.envelope.recipient,
            konsensus_core::Recipient::Node(*recipient.state.identity.node_id()),
            "{ROOM}"
        );
        assert_eq!(got.envelope.payment_proof.amount_msat, 2_001, "{ROOM}");
    }
    steps.pass("Atlas room: B+C each receive a recipient-bound paid E2EE message");
    alice.stop().await;
    bob.stop().await;
    carol.stop().await;
    for wallet in [&a, &b, &c] {
        wallet
            .shutdown()
            .await
            .expect("Atlas run 2 #25: clean wallet shutdown");
    }
    println!(
        "THREE-NODE PAID E2E PASS; Doctrine: 1–6 hold; elapsed {:?}",
        steps.started.elapsed()
    );
}
