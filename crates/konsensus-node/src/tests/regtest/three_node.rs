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
const SKEW: &str = "Atlas run 4 step 6: stale peer prices at quote time";
const SENDER_SYNC: &str = "sender-side 429: local not_ready before dispatch";
const SLOW_OWNER: &str = "quote TTL expires while owner approves";
const READMISSION: &str = "reconnect needs a per-recipient allowance";
const ROOM: &str = "Atlas run 2 #14–18: paid room flow never reached";

async fn eventually<F, Fut>(incident: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(360), async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{incident}: condition did not recover in 360s"));
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

async fn elevate(app: &mut app::App, recipients: &[String]) {
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
    let mut terms = konsensus_api::spend_budget::GrantTerms::new(1_000_000)
        .per_call(200_000)
        .for_secs(3600);
    for recipient in recipients {
        terms = terms.recipient(recipient, 200_000);
    }
    owner(
        app,
        ControlRequest::Grant {
            op_id: op.to_owned(),
            confirmation,
            terms,
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

async fn log_reconnect(from: &app::App, to: &app::App, phase: &str) {
    for (label, local, remote) in [("sender", from, to), ("recipient", to, from)] {
        let peer = remote.state.identity.node_id();
        println!(
            "{READMISSION}: {phase}: {label}: e2ee_session={}, {}",
            local.state.session_manager.has_session(peer).await,
            local.transport.reconnect_diagnostics(peer).await,
        );
    }
}

async fn reconnect(from: &app::App, to: &app::App, incident: &str) {
    let peer = to.state.identity.node_id();
    let sender = from.state.identity.node_id();
    let old_from = from.transport.connected_since(peer).await.expect(incident);
    let old_to = to.transport.connected_since(sender).await.expect(incident);
    let used = from.used();
    println!(
        "{incident}: forcing reconnect from generations sender={old_from:?}, recipient={old_to:?}"
    );
    log_reconnect(from, to, "before forced disconnect").await;
    from.transport.disconnect(peer).await.expect(incident);
    log_reconnect(from, to, "after forced disconnect").await;
    // A live E2EE session (created by slow-owner delivery) keeps the product
    // supervisor interested. It may replace the socket between polls. Waiting
    // for !is_connected on the recipient can then wait forever on a healthy
    // replacement. Accept either the supervisor's dial or this explicit dial,
    // but require a NEW generation at BOTH ends before testing re-admission.
    let dial = tokio::time::timeout(
        Duration::from_secs(30),
        from.transport
            .connect(peer, &to.transport.listen_addr().unwrap().to_string()),
    )
    .await;
    log_reconnect(from, to, "explicit dial finished").await;
    dial.expect("re-admission: explicit dial deadline")
        .expect(incident);
    let wait = tokio::time::timeout(Duration::from_secs(360), async {
        let mut next_log = std::time::Instant::now();
        loop {
            let new_from = from.transport.connected_since(peer).await;
            let new_to = to.transport.connected_since(sender).await;
            if new_from.is_some_and(|generation| generation != old_from)
                && new_to.is_some_and(|generation| generation != old_to)
            {
                break;
            }
            if std::time::Instant::now() >= next_log {
                log_reconnect(from, to, "waiting for both replacement generations").await;
                next_log = std::time::Instant::now() + Duration::from_secs(5);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await;
    log_reconnect(from, to, "replacement generation wait finished").await;
    wait.unwrap_or_else(|_| panic!("{incident}: replacement generations did not recover in 360s"));
    assert_eq!(
        from.used(),
        used,
        "{incident}: reconnect itself spends nothing"
    );
    for (local, remote) in [(from, to), (to, from)] {
        assert!(
            !local
                .transport
                .admission_paid_on_connection(remote.state.identity.node_id())
                .await,
            "{incident}: new generation must not inherit paid admission"
        );
        assert!(
            local
                .state
                .session_manager
                .has_session(remote.state.identity.node_id())
                .await,
            "{incident}: reconnect must preserve the E2EE session"
        );
    }
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

async fn approve_contact(
    from: &app::App,
    to: &app::App,
    quote: &Value,
    contact_budget_msat: Option<u64>,
) {
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
            contact_budget_msat,
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
                "addr": to.transport.listen_addr().unwrap().to_string(),
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
        assert!(
            std::env::var_os(variable).is_some_and(|p| Path::new(&p).is_file()),
            "missing {variable}: ignored regtest requires fixtures; use runner for SKIP (exit 77)"
        );
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let mut steps = Steps::new();
    let chain = infra::Chain::start().await;
    let fault = fault_proxy::FaultProxy::start(&chain.url).await;
    let sender_fault = fault_proxy::FaultProxy::start(&chain.url).await;
    let dirs = [(); 3].map(|_| tempfile::tempdir().unwrap());
    let configs = [
        infra::lightning_config(dirs[0].path(), &sender_fault.url),
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
        &sender_fault.url,
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

    // Noise and Esplora are separate hops. Capture connection generations so
    // automatic reconnects cannot hide chain-triggered transport loss.
    let ab = alice.transport.connected_since(bob.state.identity.node_id()).await.unwrap();
    let ba = bob.transport.connected_since(alice.state.identity.node_id()).await.unwrap();
    assert_ne!(fault.url, format!("http://{}", bob.transport.listen_addr().unwrap()));
    // No cache seeding: 429 travels through B's real chain provider and LDK.
    fault.set_limited(true);
    eventually(SYNC, || async {
        assert_eq!(alice.transport.connected_since(bob.state.identity.node_id()).await,
            Some(ab), "{SYNC}: sender->recipient Noise hop lost while waiting for chain failure; rejected={}, sync={:?}", fault.rejected(), b.chain_sync_status());
        assert_eq!(bob.transport.connected_since(alice.state.identity.node_id()).await,
            Some(ba), "{SYNC}: recipient->sender Noise hop lost while waiting for chain failure");
        fault.rejected() > 0 && b.chain_sync_status().is_some() && !b.money_ready().await
    })
    .await;
    println!("{SYNC}: Esplora rejected={}, sync={:?}, money_ready=false, both original Noise connections alive",
        fault.rejected(), b.chain_sync_status());
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
    assert_eq!(alice.transport.connected_since(bob.state.identity.node_id()).await,
        Some(ab), "{SYNC}: sender Noise connection changed during quote: {refusal}");
    assert_eq!(bob.transport.connected_since(alice.state.identity.node_id()).await,
        Some(ba), "{SYNC}: recipient Noise connection changed during quote: {refusal}");
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE,
        "{SYNC}: Noise intact, quote/refusal hop failed: {refusal}; sync={:?}", b.chain_sync_status());
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

    // The refused quote consumed the recipient's 10s source cooldown.
    tokio::time::sleep(Duration::from_secs(10)).await;
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
    elevate(&mut alice, &[]).await;
    approve_contact(&alice, &bob, &first, None).await;
    paid(&alice, &mut bob, "Atlas paid first contact A to B", QUOTE).await;
    assert_eq!(
        alice.used(),
        4_002,
        "{QUOTE}: admission + message, zero routing fee"
    );
    steps.pass("Atlas runs 1–3: read quote, remote spend request, headless control grant, paid E2EE receipt");

    sender_fault.set_limited(true);
    eventually(SENDER_SYNC, || async {
        sender_fault.rejected() > 0 && a.chain_sync_status().is_some() && !a.money_ready().await
    })
    .await;
    let before = (
        alice.used(),
        capacity(a.node()),
        capacity(b.node()),
        settled_outgoing(&a).await.len(),
        b.list_payments(500).await.unwrap().len(),
    );
    let (status, refusal) = tokio::time::timeout(
        Duration::from_secs(8),
        alice.post(
            "/api/v1/messages/compose",
            json!({"recipient": bob.state.identity.node_id().to_hex(),
            "kind": 0, "plaintext": "sender chain is limited"}),
            false,
        ),
    )
    .await
    .expect(SENDER_SYNC);
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{SENDER_SYNC}: {refusal}"
    );
    assert_eq!(refusal["code"], "not_ready", "{SENDER_SYNC}: {refusal}");
    assert_eq!(
        (
            alice.used(),
            capacity(a.node()),
            capacity(b.node()),
            settled_outgoing(&a).await.len(),
            b.list_payments(500).await.unwrap().len()
        ),
        before,
        "{SENDER_SYNC}: local refusal before payment/invoice"
    );
    sender_fault.set_limited(false);
    eventually(SENDER_SYNC, || async {
        a.chain_sync_status().is_none() && a.money_ready().await
    })
    .await;
    let used = alice.used();
    paid(
        &alice,
        &mut bob,
        "sender recovers without restart",
        SENDER_SYNC,
    )
    .await;
    assert_eq!(alice.used() - used, 2_001, "{SENDER_SYNC}");
    steps.pass("Sender 429: local not_ready pays nothing; background recovery permits paid send");

    list_contact(&alice, &bob, REPLY).await;
    elevate(&mut bob, &[]).await;
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
    let reply = paid(
        &bob,
        &mut alice,
        "B replies after A obtains inbound liquidity",
        REPLY,
    )
    .await;
    assert_eq!(bob.used(), 2_001, "{REPLY}: one paid reply only");
    assert!(
        reply["readmission_msat"].is_null(),
        "{REPLY}: admitted reply requires no first-contact payment"
    );
    steps.pass(
        "Atlas run 2 liquidity: unfunded reply refused without payment, rebalanced reply delivered",
    );

    let first_c = quote(&alice, &carol, ROOM).await;
    let expires = first_c["expires_at"].as_u64().expect(SLOW_OWNER);
    let idle_started = std::time::Instant::now();
    let ac = alice.transport.connected_since(carol.state.identity.node_id()).await.unwrap();
    let ca = carol.transport.connected_since(alice.state.identity.node_id()).await.unwrap();
    let payments = settled_outgoing(&a).await.len();
    let used = alice.used();
    // Real wall clock: neither the signed quote nor the owner's clock is mocked.
    while std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= expires
    {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(idle_started.elapsed() > Duration::from_secs(30), "{SLOW_OWNER}: exercise the old read timeout");
    assert_eq!(alice.transport.connected_since(carol.state.identity.node_id()).await,
        Some(ac), "{SLOW_OWNER}: product keepalive must preserve the dialer's quote link");
    assert_eq!(carol.transport.connected_since(alice.state.identity.node_id()).await,
        Some(ca), "{SLOW_OWNER}: product keepalive must preserve the acceptor's quote link");
    approve_contact(&alice, &carol, &first_c, None).await;
    paid(
        &alice,
        &mut carol,
        "A to C first contact after slow owner approval",
        SLOW_OWNER,
    )
    .await;
    assert_eq!(
        alice.used() - used,
        4_002,
        "{SLOW_OWNER}: no double admission debit"
    );
    assert_eq!(
        settled_outgoing(&a).await.len() - payments,
        2,
        "{SLOW_OWNER}: admission and message only"
    );
    steps.pass("Slow owner: expired quote replaced; exactly one admission and one message paid");

    // C was approved once, without a standing per-recipient budget. Its
    // consumed one-time approval must not authorize another admission.
    assert!(
        alice
            .service
            .grant_view_for(&alice.client)
            .unwrap()
            .per_recipient_msat
            .is_empty(),
        "{READMISSION}"
    );
    reconnect(&alice, &carol, "re-admission without recipient allowance").await;
    assert!(
        !alice
            .state
            .peer_ln_pubkeys
            .lock()
            .await
            .contains_key(carol.state.identity.node_id()),
        "{READMISSION}: fixture must exercise invoice/admission, not a cached keysend route"
    );
    let before = (
        alice.used(),
        capacity(a.node()),
        capacity(c.node()),
        settled_outgoing(&a).await.len(),
        c.list_payments(500).await.unwrap().len(),
    );
    let (status, refusal) = alice
        .post(
            "/api/v1/messages/compose",
            json!({
                "recipient": carol.state.identity.node_id().to_hex(), "kind": 0,
                "plaintext": "no standing C allowance after reconnect",
            }),
            false,
        )
        .await;
    log_reconnect(&alice, &carol, "compose without recipient allowance returned").await;
    println!("{READMISSION}: refusal status={status}, body={refusal}");
    assert_eq!(status, StatusCode::CONFLICT, "{READMISSION}: {refusal}");
    assert_eq!(
        refusal["code"], "budget_exceeded",
        "{READMISSION}: {refusal}"
    );
    assert_eq!(
        refusal["reason"], "first_contact",
        "{READMISSION}: {refusal}"
    );
    assert_eq!(
        (
            alice.used(),
            capacity(a.node()),
            capacity(c.node()),
            settled_outgoing(&a).await.len(),
            c.list_payments(500).await.unwrap().len()
        ),
        before,
        "{READMISSION}: refusal pays nothing and creates no invoice"
    );
    // Replace the empty grant through the owner socket with explicit
    // --recipient-style entries. No new one-time contact approval is issued.
    owner(
        &alice,
        ControlRequest::RevokeGrant {
            client_id: Some(alice.client.clone()),
        },
        READMISSION,
    )
    .await;
    elevate(
        &mut alice,
        &[
            bob.state.identity.node_id().to_hex(),
            carol.state.identity.node_id().to_hex(),
        ],
    )
    .await;
    let used = alice.used();
    paid(
        &alice,
        &mut carol,
        "owner authorizes C re-admission",
        READMISSION,
    )
    .await;
    log_reconnect(&alice, &carol, "paid with recipient allowance").await;
    assert_eq!(alice.used() - used, 4_002, "{READMISSION}");
    reconnect(&alice, &carol, "re-admission with standing recipient allowance").await;
    let used = alice.used();
    paid(
        &alice,
        &mut carol,
        "C allowance alone authorizes re-admission",
        READMISSION,
    )
    .await;
    assert_eq!(
        alice.used() - used,
        4_002,
        "{READMISSION}: admission 2001 + message 2001"
    );
    steps.pass(
        "Re-admission: absent recipient cap refuses without spend; standing cap pays exactly 4002",
    );
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
    let (status, tables) = alice.get("/api/v1/pricing/peers", false).await;
    assert_eq!(status, StatusCode::OK, "{SKEW}: {tables}");
    let entry = tables
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["peer_id"] == bob.state.identity.node_id().to_hex())
        .expect(SKEW);
    assert_eq!(
        entry["stale"], true,
        "{SKEW}: UI must flag the expired table"
    );
    assert_eq!(entry["block_height"], 0, "{SKEW}");
    let before = (
        alice.used(),
        settled_outgoing(&a).await.len(),
        b.list_payments(500).await.unwrap().len(),
    );
    let fresh = quote(&alice, &bob, SKEW).await;
    assert_eq!(
        fresh["message_msat"], 2_001,
        "{SKEW}: quote must reject the cached 999999 price"
    );
    assert_eq!(
        (
            alice.used(),
            settled_outgoing(&a).await.len(),
            b.list_payments(500).await.unwrap().len()
        ),
        before,
        "{SKEW}: quote and pricing reads spend nothing"
    );
    // The pricing endpoint reports cache freshness; it does not silently refresh
    // it. Exercise the real wire update and read the same app endpoint again.
    bob.transport
        .send_frame(
            alice.state.identity.node_id(),
            &Frame::PriceTable {
                prices: std::collections::HashMap::from([("communication".to_owned(), 2_001)]),
                block_height: tip,
                valid_blocks: 6,
                trust_discount: 0.0,
            },
        )
        .await
        .expect(SKEW);
    eventually(SKEW, || async {
        let (status, tables) = alice.get("/api/v1/pricing/peers", false).await;
        status == StatusCode::OK
            && tables.as_array().unwrap().iter().any(|entry| {
                entry["peer_id"] == bob.state.identity.node_id().to_hex()
                    && entry["stale"] == false
                    && entry["prices"]["communication"] == 2_001
            })
    })
    .await;
    steps.pass("Atlas run 4 stale pricing: /pricing/peers marks stale, quote uses fresh target price, wire refresh clears stale");

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
    assert!(
        !alice
            .state
            .peer_ln_pubkeys
            .lock()
            .await
            .contains_key(&bob_id),
        "{RESTART}: fixture must exercise re-admission rather than cached keysend"
    );
    paid(
        &alice,
        &mut bob,
        "A keeps its paired client across B restart",
        RESTART,
    )
    .await;
    assert_eq!(
        alice.used() - used_a,
        4_002,
        "{RESTART}: exactly one re-admission plus one message"
    );
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

/// PR #200's transaction-existence and absent-parent rebroadcast contract.
/// Healthy 404 evidence suppresses; unavailable evidence preserves recovery.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Core/electrs; set REGTEST_GHOST_AFTER_PR200=1"]
async fn ghost_unfunded_channel_requires_pr200() {
    assert_eq!(
        std::env::var("REGTEST_GHOST_AFTER_PR200").as_deref(),
        Ok("1"),
        "SKIP ghost/unfunded channel: requires PR #200; enable explicitly after merge"
    );
    let chain = infra::Chain::start().await;
    let fault = fault_proxy::FaultProxy::start(&chain.url).await;
    let dirs = [(); 2].map(|_| tempfile::tempdir().unwrap());
    let a_config = infra::lightning_config(dirs[0].path(), &fault.url);
    let b_config = infra::lightning_config(dirs[1].path(), &chain.url);
    let a = LdkProvider::new(a_config).await.unwrap();
    let b = LdkProvider::new(b_config.clone()).await.unwrap();
    chain.fund(a.node()).await;
    eventually("ghost: wallets ready", || async {
        a.money_ready().await && b.money_ready().await
    })
    .await;
    // Lose the funding broadcast at the backend boundary, preserving the real
    // signed funding transaction, channel negotiation, and durable LDK monitor.
    fault.drop_broadcasts();
    let opened = a
        .open_channel_with_status(
            &b.node().node_id().to_string(),
            b_config.listening_address.as_ref().unwrap(),
            1_000_000,
            false,
            None,
        )
        .await
        .unwrap();
    eventually("ghost: funding outpoint", || async {
        a.node()
            .list_channels()
            .iter()
            .any(|ch| ch.funding_txo.is_some())
    })
    .await;
    let channel = a
        .node()
        .list_channels()
        .into_iter()
        .find(|ch| ch.funding_txo.is_some())
        .unwrap();
    let funding = channel.funding_txo.unwrap();
    eventually("ghost: funding actually dropped", || async {
        fault
            .broadcasts()
            .iter()
            .any(|tx| tx.compute_txid() == funding.txid)
    })
    .await;
    let mempool: Vec<String> = chain.bitcoin.client.call("getrawmempool", &[]).unwrap();
    assert!(mempool.is_empty(), "ghost funding must never reach Core");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let absent = client
        .get(format!("{}/tx/{}", chain.url, funding.txid))
        .send()
        .await
        .unwrap();
    assert_eq!(
        absent.status(),
        StatusCode::NOT_FOUND,
        "only /tx/{{txid}} 404 proves absence"
    );
    // Do not use /status: this electrs may answer 200 + confirmed:false for an
    // unknown tx, which says nothing about funding existence.
    a.close_channel(&opened.channel_id, true).await.unwrap();
    eventually("ghost: removed channel with retained closing claim", || async {
        a.node().list_channels().is_empty() && a.node().list_balances().lightning_balances.iter().any(|balance|
            matches!(balance, ldk_node::LightningBalance::ClaimableOnChannelClose { amount_satoshis, .. } if *amount_satoshis > 0))
    }).await;
    let reads_before = fault.reads().len();
    let balance = a
        .get_balance_breakdown()
        .await
        .expect("#200: proven absent funding must be excluded");
    assert!(
        fault.reads()[reads_before..]
            .iter()
            .any(|path| path == &format!("/tx/{}", funding.txid)),
        "#200: production funding_present must use transaction existence, not /status"
    );
    assert_eq!(
        balance.closing_sats,
        Some(0),
        "ghost claim excluded from closing"
    );
    let raw = a.node().list_balances();
    assert!(
        raw.total_lightning_balance_sats > 0,
        "fixture must retain the ghost monitor claim"
    );
    assert_eq!(
        a.get_balance_msat().await.unwrap(),
        raw.spendable_onchain_balance_sats * 1_000,
        "ghost claim excluded from node aggregate too"
    );
    let commitments = || {
        fault.broadcast_attempts().into_iter()
            .filter(|(_, tx)| tx.input.iter().any(|input| input.previous_output == funding))
            .map(|(at, _)| at).collect::<Vec<_>>()
    };
    // First test suppression with fresh absence evidence available. The first
    // close can race channel removal; allow it to finish, then cover the next
    // eligible rebroadcast (the queue backs off at 30, 60, 120... seconds).
    tokio::time::sleep(Duration::from_secs(35)).await;
    let before = commitments().len();
    let reads_before = fault.read_responses().len();
    tokio::time::sleep(Duration::from_secs(95)).await;
    let funding_path = format!("/tx/{}", funding.txid);
    let evidence: Vec<_> = fault.read_responses()[reads_before..].iter()
        .filter(|(path, _)| path == &funding_path).cloned().collect();
    println!("ghost: funding={}, listed_channels={}, raw_claim_sats={}, fresh_evidence={evidence:?}, commitment_posts_before={before}, after={}",
        funding, a.node().list_channels().len(), raw.total_lightning_balance_sats, commitments().len());
    assert!(a.node().list_channels().is_empty(), "ghost: suppression requires a closed monitor");
    assert!(evidence.iter().any(|(_, status)| *status == StatusCode::NOT_FOUND),
        "ghost: no fresh funding absence lookup during rebroadcast window: {evidence:?}");
    assert_eq!(commitments().len(), before,
        "#200: fresh 404 + closed monitor must suppress commitment POSTs");

    // A 429 is UNKNOWN, not absence. #200 intentionally does not cache a 404:
    // funding may arrive later. Such packages remain eligible and POST retries
    // share a cooldown with a 10s floor (exponential by backend episode).
    // One POST in 95s was not that contract.
    let before = commitments().len();
    fault.set_limited(true);
    eventually("ghost: UNKNOWN funding must still permit a commitment POST under 429", || async {
        commitments().len() > before
    }).await;
    // Start observation at an actual commitment attempt, not an arbitrary LDK
    // tick. Queue cooldown and other HTTP work may delay its first attempt.
    let first = commitments()[before];
    tokio::time::sleep(Duration::from_secs(95).saturating_sub(first.elapsed())).await;
    let attempts = commitments();
    let attempts: Vec<_> = attempts[before..].iter().copied()
        .filter(|at| at.duration_since(first) <= Duration::from_secs(95)).collect();
    let gaps: Vec<_> = attempts.windows(2).map(|pair| pair[1].duration_since(pair[0])).collect();
    println!("ghost: unknown funding under 429; rejected={}, commitment_posts={}, gaps={gaps:?}, sync={:?}",
        fault.rejected(), attempts.len(), a.chain_sync_status());
    assert!(fault.rejected() > 0, "ghost: backend fault must actually be exercised");
    // Every retry waits at least 10s after its own 429. Concurrent packages can
    // extend a shared episode, so its exponent is NOT this transaction's retry
    // index. At most ten attempts fit in 95s even at the 10s floor.
    assert!(!attempts.is_empty(), "ghost: UNKNOWN funding branch never exercised");
    assert!(attempts.len() <= 10,
        "#200: 95s 429 retry bound exceeded: posts={}, gaps={gaps:?}", attempts.len());
    for (index, gap) in gaps.iter().enumerate() {
        // Proxy timestamps precede response processing; tolerate 1s scheduling skew.
        let minimum = Duration::from_secs(9);
        assert!(*gap >= minimum,
            "#200: commitment retry {} failed backoff: gap={gap:?}, minimum={minimum:?}", index + 1);
    }
    // Even if shared cooldown reached 300s before this POST, it must retain
    // the commitment and retry. Do not let one observed attempt mask its loss.
    eventually("ghost: commitment retained for retry during 429 (300s cooldown cap)", || async {
        commitments().len() >= before + 2
    }).await;
    let retried = commitments();
    let retry_gap = retried[before + 1].duration_since(retried[before]);
    assert!((Duration::from_secs(9)..=Duration::from_secs(360)).contains(&retry_gap),
        "ghost: retained commitment retry outside 10s floor / 300s cap plus allowance: {retry_gap:?}");
    // This fixture closes one channel without mining/fee changes during the
    // observation: there must be only one commitment transaction stream.
    let commitment_ids: std::collections::HashSet<_> = fault.broadcast_attempts().into_iter()
        .filter(|(_, tx)| tx.input.iter().any(|input| input.previous_output == funding))
        .map(|(_, tx)| tx.compute_txid()).collect();
    assert_eq!(commitment_ids.len(), 1, "ghost: unexpected competing commitment transactions: {commitment_ids:?}");
    fault.set_limited(false);
    for wallet in [&a, &b] {
        wallet.shutdown().await.unwrap();
    }
    println!(
        "GHOST UNFUNDED CHANNEL PASS: proven absence, excluded closing claim, bounded rebroadcast"
    );
}
