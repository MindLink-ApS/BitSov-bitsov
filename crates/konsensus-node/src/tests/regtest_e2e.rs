//! Real LDK/Bitcoin Core regression. Run via scripts/regress/regtest_e2e.sh.
//! Catches fee-rate loss, free stranger admission, missing X3DH, lost replies,
//! and inaccurate payment/budget reconciliation (including sub-satoshi amounts).
use konsensus_core::traits::lightning::{LightningProvider, PaymentDirection, PaymentStatus};
use konsensus_core::NodeIdentity;
use konsensus_lightning::LdkProvider;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
#[path = "regtest/app.rs"]
mod app;
#[path = "regtest/infra.rs"]
mod infra;

async fn wait<F, Fut>(label: &str, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    tokio::time::timeout(Duration::from_secs(60), async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout: {label}"));
}

async fn settle(a: &LdkProvider, hash: &str) {
    wait("payment settlement", || async {
        let payment = a.get_payment_status(hash).await.unwrap();
        assert_ne!(payment.status, PaymentStatus::Failed, "{payment:?}");
        payment.status == PaymentStatus::Settled
    })
    .await;
}

fn capacity(node: &ldk_node::Node) -> u64 {
    node.list_channels()
        .iter()
        .map(|c| c.outbound_capacity_msat)
        .sum()
}

/// Per-step wall-clock timings for the report.
struct Steps {
    started: std::time::Instant,
    last: std::time::Instant,
}

impl Steps {
    fn new() -> Self {
        let now = std::time::Instant::now();
        Self {
            started: now,
            last: now,
        }
    }
    fn pass(&mut self, name: &str) {
        let now = std::time::Instant::now();
        println!(
            "STEP PASS {name}: {:.1}s (elapsed {:.1}s)",
            (now - self.last).as_secs_f64(),
            (now - self.started).as_secs_f64()
        );
        self.last = now;
    }
}

/// Talk-track beat timings for `scripts/demo-rehearsal.sh` (one line per beat).
struct Beats {
    last: std::time::Instant,
}

impl Beats {
    fn new() -> Self {
        Self {
            last: std::time::Instant::now(),
        }
    }
    fn pass(&mut self, name: &str) {
        let now = std::time::Instant::now();
        println!("BEAT PASS {name}: {:.3}s", (now - self.last).as_secs_f64());
        self.last = now;
    }
}

/// The forwarding policy `node`'s peer C announced on their channel, as `node`
/// sees it: this is what C charges on its hop towards `node`, and what `node`'s
/// invoices carry in their route hints.
fn hop_policy(node: &ldk_node::Node, c: &ldk_node::Node) -> Option<(u64, u64)> {
    let c_id = c.node_id();
    let seen = node
        .list_channels()
        .into_iter()
        .find(|ch| ch.counterparty_node_id == c_id)?;
    let own = c
        .list_channels()
        .into_iter()
        .find(|ch| ch.channel_id == seen.channel_id)?;
    let policy = (
        u64::from(seen.counterparty_forwarding_info_fee_base_msat?),
        u64::from(seen.counterparty_forwarding_info_fee_proportional_millionths?),
    );
    assert_eq!(
        policy,
        (
            u64::from(own.config.forwarding_fee_base_msat),
            u64::from(own.config.forwarding_fee_proportional_millionths)
        ),
        "C's announced policy must match its own channel config"
    );
    Some(policy)
}

fn hop_fee((base, ppm): (u64, u64), amount_msat: u64) -> u64 {
    base + amount_msat * ppm / 1_000_000
}

/// Topology A -- C -- B: C is a routing-only LDK node with no app, so every
/// A<->B payment pays C's positive forwarding fee. There is no A-B channel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn real_ldk_regtest_e2e() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let mut steps = Steps::new();
    let chain = infra::Chain::start().await;
    let dirs = [(); 3].map(|_| tempfile::tempdir().unwrap());
    let (a, _) = infra::lightning(dirs[0].path(), &chain).await;
    let (b, addr_b) = infra::lightning(dirs[1].path(), &chain).await;
    let (c, addr_c) = infra::router(dirs[2].path(), &chain).await;
    let c_pubkey = c.node_id().to_string();
    steps.pass("chain + 3 real LDK nodes started");
    chain.fund(a.node()).await;
    chain.fund(&c).await;
    steps.pass("A and C funded 3,000,000 sat each from regtest coinbase");

    chain.refuse_explicit_rate(&a, &c_pubkey, &addr_c).await;
    steps.pass("explicit per-channel funding fee rate refused (#101), no channel, no broadcast");

    // A opens through the product's supported path (no explicit rate).
    a.open_channel(&c_pubkey, &addr_c, 1_000_000, false, None)
        .await
        .unwrap();
    let fee_ac = chain.confirm_channel(a.node(), &c, &[b.node()]).await;
    c.open_channel(
        b.node().node_id(),
        addr_b.parse().unwrap(),
        1_000_000,
        None,
        None,
    )
    .unwrap();
    let fee_cb = chain.confirm_channel(&c, b.node(), &[a.node()]).await;
    assert_eq!(
        a.node().list_balances().total_onchain_balance_sats,
        2_000_000 - fee_ac
    );
    assert_eq!(
        c.list_balances().total_onchain_balance_sats,
        2_000_000 - fee_cb
    );
    let b_id = b.node().node_id();
    assert!(
        a.node()
            .list_channels()
            .iter()
            .all(|ch| ch.counterparty_node_id != b_id),
        "A and B must not share a channel"
    );
    steps.pass("channels A->C and C->B opened via estimator and usable");

    wait("C's channel_update reaches A and B", || async {
        hop_policy(a.node(), &c).is_some() && hop_policy(b.node(), &c).is_some()
    })
    .await;
    let (to_b, to_a) = (
        hop_policy(b.node(), &c).unwrap(),
        hop_policy(a.node(), &c).unwrap(),
    );
    let (fee_b, fee_a) = (hop_fee(to_b, 2_001), hop_fee(to_a, 2_001));
    assert!(
        fee_b > 0 && fee_a > 0,
        "C must charge a positive forwarding fee"
    );
    println!("C forwarding policy: towards B {to_b:?}, towards A {to_a:?}; 2001 msat pays {fee_b} / {fee_a} msat");

    // Give B outbound liquidity to clear its reserve and reply. A real routed
    // transfer through C; it does not admit either Noise identity.
    let liquidity = 50_000_000;
    let inv = b
        .create_invoice(liquidity, "regtest reply liquidity", 600)
        .await
        .unwrap();
    let pending = a
        .pay_invoice_with_fee_limit(&inv.bolt11, hop_fee(to_b, liquidity))
        .await
        .unwrap();
    println!(
        "initial payment status: {:?}, fee: {:?}",
        pending.status, pending.fee_msat
    );
    settle(&a, &inv.payment_hash).await;
    settle(&b, &inv.payment_hash).await;
    assert_eq!(
        a.get_payment_status(&inv.payment_hash)
            .await
            .unwrap()
            .fee_msat,
        Some(hop_fee(to_b, liquidity))
    );
    wait("liquidity committed", || async {
        capacity(b.node()) > 10_000_000
    })
    .await;
    let (before_a, before_b, before_c) = (capacity(a.node()), capacity(b.node()), capacity(&c));
    steps.pass("routed liquidity A->C->B settled at exactly C's fee");

    let mut alice = app::App::start(dirs[0].path(), &chain, a.clone()).await;
    let mut bob = app::App::start(dirs[1].path(), &chain, b.clone()).await;
    let peer = bob.state.identity.node_id().to_hex();
    use konsensus_core::traits::transport::MessageTransport;
    alice
        .transport
        .connect(
            bob.state.identity.node_id(),
            &bob.transport.listen_addr().unwrap().to_string(),
        )
        .await
        .unwrap();
    wait("Noise connected", || {
        bob.transport.is_connected(alice.state.identity.node_id())
    })
    .await;
    assert!(
        !alice
            .state
            .session_manager
            .has_session(bob.state.identity.node_id())
            .await
    );
    assert!(bob.transport.connected_privileged_peers().await.is_empty());
    steps.pass("apps started, Noise connected, no session, B has no privileged peer");
    // The stateless quote gate deliberately quarantines the first second.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let payments_before = b.list_payments(100).await.unwrap().len();
    let (status, quote) = alice
        .post(
            "/api/v1/messages/first-contact/quote",
            json!({"recipient":peer}),
            false,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{quote}");
    println!("stateless quote: {quote}");
    assert_eq!(quote["admission_msat"], 2_001);
    assert_eq!(quote["message_msat"], 2_001);
    assert_eq!(quote["total_msat"], 14_002);
    assert_eq!(
        b.list_payments(100).await.unwrap().len(),
        payments_before,
        "stateless quote must not persist a Lightning invoice record"
    );
    assert_eq!(alice.used(), 0);
    let grant = alice.service.grant_view_for(&alice.client).unwrap();
    let (status, body) = alice
        .post(
            "/api/v1/pair/first-contact-grant",
            json!({
                "client_id":alice.client, "grant_op_id":grant.op_id, "recipient":peer,
                "max_total_msat":quote["total_msat"], "contact_budget_msat":100_000
            }),
            true,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    steps.pass("stateless first-contact quote 14002 msat + owner grant");

    alice.compose(&mut bob, "hello stranger").await;
    assert!(
        alice
            .state
            .session_manager
            .has_session(bob.state.identity.node_id())
            .await
    );
    assert!(
        bob.state
            .session_manager
            .has_session(alice.state.identity.node_id())
            .await
    );
    println!("budget after first contact: A used {} msat", alice.used());
    steps.pass("first contact: admission + E2EE message delivered via C");
    alice.compose(&mut bob, "paid follow-up").await;
    println!("budget after follow-up: A used {} msat", alice.used());
    steps.pass("paid follow-up delivered");
    // #100: on the payer side a paid connection buys the session frames only;
    // RequestInvoice stays privileged-only. Unlisted, B's reply would be a
    // first contact of its own, refused for want of a grant, nothing paid.
    let alice_hex = alice.state.identity.node_id().to_hex();
    let payments_b = b.list_payments(100).await.unwrap().len();
    let (status, body) = bob
        .post(
            "/api/v1/messages/compose",
            json!({"recipient": alice_hex, "kind": 0, "plaintext": "unlisted reply"}),
            false,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::CONFLICT, "{body}");
    assert_eq!(body["reason"], "first_contact", "{body}");
    assert_eq!(bob.used(), 0);
    assert_eq!(b.list_payments(100).await.unwrap().len(), payments_b);
    println!("unlisted reply refused, nothing paid: {body}");
    steps.pass("unlisted reply refused before any invoice request or payment");
    // The launcher reply case: A's owner lists B, which privileges the live
    // connection; B then pays the message price only.
    let (status, body) = alice
        .post(
            "/api/v1/peers",
            json!({
                "node_id": peer, "addr": bob.transport.listen_addr().unwrap().to_string(),
                "auto_connect": false
            }),
            true,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    bob.compose(&mut alice, "B replies").await;
    println!("budget after reply: B used {} msat", bob.used());
    steps.pass("B's paid reply delivered to A");

    // A route exists (A->C->B) but costs more than the caller's fee ceiling:
    // refused before dispatch, reservation released, nothing moves.
    let (used_a, cap_a) = (alice.used(), capacity(a.node()));
    let over = b
        .create_invoice(2_001, "over fee ceiling", 600)
        .await
        .unwrap();
    let (status, body) = alice
        .post(
            "/api/v1/payments/pay",
            json!({"bolt11": over.bolt11, "max_routing_fee_msat": fee_b - 1}),
            false,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched", "{body}");
    assert_eq!(body["max_routing_fee_msat"], fee_b - 1);
    assert_eq!(alice.used(), used_a, "reservation must be released");
    assert_eq!(
        a.get_payment_status(&over.payment_hash)
            .await
            .unwrap()
            .status,
        PaymentStatus::Failed
    );
    assert_eq!(
        b.get_payment_status(&over.payment_hash)
            .await
            .unwrap()
            .status,
        PaymentStatus::Pending
    );
    assert_eq!(capacity(a.node()), cap_a);
    println!(
        "over-ceiling: route fee {fee_b} msat > cap {} msat refused: {body}",
        fee_b - 1
    );
    steps.pass("route above fee ceiling refused pre-dispatch, reservation released");

    // The same route with the ceiling at exactly C's fee dispatches and settles.
    let capped = b.create_invoice(2_001, "fee capped", 600).await.unwrap();
    let (status, body) = alice
        .post(
            "/api/v1/payments/pay",
            json!({"bolt11": capped.bolt11, "max_routing_fee_msat": fee_b}),
            false,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    println!(
        "fee-capped pay response: {body}; A used {} msat",
        alice.used()
    );
    settle(&a, &capped.payment_hash).await;
    settle(&b, &capped.payment_hash).await;
    steps.pass("fee-capped payment (cap == C's fee) settled");

    // Reconciliation, msat-exact, from real LDK payment records and channels.
    let sent_a = 4 * 2_001;
    let expected_a = before_a - sent_a - 4 * fee_b + 2_001;
    let expected_b = before_b + sent_a - 2_001 - fee_a;
    let expected_c = before_c + 4 * fee_b + fee_a;
    wait(
        "exact channel deltas after all HTLC commitments",
        || async {
            capacity(a.node()) == expected_a
                && capacity(b.node()) == expected_b
                && capacity(&c) == expected_c
        },
    )
    .await;
    for (node, amounts, fee) in [
        (&a, vec![liquidity, 2_001, 2_001, 2_001, 2_001], fee_b),
        (&b, vec![2_001], fee_a),
    ] {
        let payments = node.list_payments(100).await.unwrap();
        let mut settled: Vec<_> = payments
            .iter()
            .filter(|p| {
                p.direction == PaymentDirection::Outgoing
                    && p.status == PaymentStatus::Settled
                    && !p.payment_hash.is_empty()
            })
            .collect();
        settled.sort_by_key(|p| std::cmp::Reverse(p.amount_msat));
        assert_eq!(
            settled.iter().map(|p| p.amount_msat).collect::<Vec<_>>(),
            amounts,
            "{settled:?}"
        );
        for payment in &settled {
            let expected_fee = if payment.amount_msat == liquidity {
                hop_fee(to_b, liquidity)
            } else {
                fee
            };
            assert_eq!(payment.fee_msat, Some(expected_fee), "{payment:?}");
            use sha2::{Digest, Sha256};
            let preimage = hex::decode(payment.preimage.as_ref().unwrap()).unwrap();
            assert_eq!(hex::encode(Sha256::digest(preimage)), payment.payment_hash);
        }
    }
    // Real LDK also lists the on-chain channel funding as an outgoing,
    // hashless "payment": reconcile it against the mempool-measured fee.
    let funding: Vec<_> = a
        .list_payments(100)
        .await
        .unwrap()
        .into_iter()
        .filter(|p| p.payment_hash.is_empty() && p.direction == PaymentDirection::Outgoing)
        .collect();
    assert_eq!(funding.len(), 1, "{funding:?}");
    assert_eq!(funding[0].amount_msat, 1_000_000_000);
    assert_eq!(funding[0].fee_msat, Some(fee_ac * 1_000));
    let (used_a, used_b) = (alice.used(), bob.used());
    println!(
        "reconciled: A paid 4x2001 msat + 4x{fee_b} fee, received 2001; B paid 2001 + {fee_a} fee; C earned {} msat; budgets A {used_a} / B {used_b} msat; funding {fee_ac}+{fee_cb} sat",
        4 * fee_b + fee_a
    );
    assert_eq!(
        used_a,
        4 * (2_001 + fee_b),
        "A budget = principal + actual fees"
    );
    assert_eq!(used_b, 2_001 + fee_a, "B budget = principal + actual fee");
    steps.pass("msat reconciliation: channels, payment records, preimages, budgets");
    drop(alice);
    drop(bob);
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    c.stop().unwrap();
    println!("REGTEST-E2E complete in {:?}", steps.started.elapsed());
}

/// Real pre-dispatch reservation release. This is deliberately a NO-ROUTE
/// control, not a claim that a two-node direct channel charges forwarding fees.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn real_ldk_predispatch_refusal() {
    let chain = infra::Chain::start().await;
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, _) = infra::lightning(dir_a.path(), &chain).await;
    let (b, _) = infra::lightning(dir_b.path(), &chain).await;
    let alice = app::App::start(dir_a.path(), &chain, a.clone()).await;
    let invoice = b
        .create_invoice(2_001, "no-route refusal control", 600)
        .await
        .unwrap();
    // Startup sync is asynchronous. Reach the payment dispatch gate, rather
    // than racing its wallet-readiness guard and receiving 503/not_ready.
    wait("payer ready", || a.money_ready()).await;
    let (status, body) = alice
        .post(
            "/api/v1/payments/pay",
            json!({
                "bolt11": invoice.bolt11, "max_routing_fee_msat": 37
            }),
            false,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched", "{body}");
    assert_eq!(body["max_routing_fee_msat"], 37);
    assert_eq!(
        alice.used(),
        0,
        "principal + fee reservation must be released"
    );
    assert_eq!(
        a.get_payment_status(&invoice.payment_hash)
            .await
            .unwrap()
            .status,
        PaymentStatus::Failed
    );
    assert_eq!(
        b.get_payment_status(&invoice.payment_hash)
            .await
            .unwrap()
            .status,
        PaymentStatus::Pending
    );
    assert_eq!(a.get_balance_msat().await.unwrap(), 0);
    assert_eq!(b.get_balance_msat().await.unwrap(), 0);
    assert!(a.node().list_channels().is_empty());
    println!("real LDK no-route refusal: 2001 msat + 37 msat fee reservation released; no balance movement");
    drop(alice);
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
}

/// Mexico demo talk-track rehearsal on real LDK regtest: first contact with
/// owner approval, paid message, paid reply, over-cap refusal at 0 msat, and
/// exact msat reconciliation. Run via `scripts/demo-rehearsal.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/demo-rehearsal.sh"]
async fn mexico_demo_rehearsal() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let chain = infra::Chain::start().await;
    let dirs = [(); 3].map(|_| tempfile::tempdir().unwrap());
    let (a, _) = infra::lightning(dirs[0].path(), &chain).await;
    let (b, addr_b) = infra::lightning(dirs[1].path(), &chain).await;
    let (c, addr_c) = infra::router(dirs[2].path(), &chain).await;
    let c_pubkey = c.node_id().to_string();
    chain.fund(a.node()).await;
    chain.fund(&c).await;

    a.open_channel(&c_pubkey, &addr_c, 1_000_000, false, None)
        .await
        .unwrap();
    chain.confirm_channel(a.node(), &c, &[b.node()]).await;
    c.open_channel(
        b.node().node_id(),
        addr_b.parse().unwrap(),
        1_000_000,
        None,
        None,
    )
    .unwrap();
    chain.confirm_channel(&c, b.node(), &[a.node()]).await;
    assert!(
        a.node()
            .list_channels()
            .iter()
            .all(|ch| ch.counterparty_node_id != b.node().node_id()),
        "A and B must not share a channel"
    );

    wait("C's channel_update reaches A and B", || async {
        hop_policy(a.node(), &c).is_some() && hop_policy(b.node(), &c).is_some()
    })
    .await;
    let (to_b, to_a) = (
        hop_policy(b.node(), &c).unwrap(),
        hop_policy(a.node(), &c).unwrap(),
    );
    let (fee_b, fee_a) = (hop_fee(to_b, 2_001), hop_fee(to_a, 2_001));
    assert!(
        fee_b > 0 && fee_a > 0,
        "C must charge a positive forwarding fee"
    );

    let liquidity = 50_000_000;
    let inv = b
        .create_invoice(liquidity, "demo reply liquidity", 600)
        .await
        .unwrap();
    a.pay_invoice_with_fee_limit(&inv.bolt11, hop_fee(to_b, liquidity))
        .await
        .unwrap();
    settle(&a, &inv.payment_hash).await;
    settle(&b, &inv.payment_hash).await;
    wait("liquidity committed", || async {
        capacity(b.node()) > 10_000_000
    })
    .await;
    let (before_a, before_b, before_c) = (capacity(a.node()), capacity(b.node()), capacity(&c));

    let mut alice = app::App::start(dirs[0].path(), &chain, a.clone()).await;
    let mut bob = app::App::start(dirs[1].path(), &chain, b.clone()).await;
    let peer = bob.state.identity.node_id().to_hex();
    use konsensus_core::traits::transport::MessageTransport;
    alice
        .transport
        .connect(
            bob.state.identity.node_id(),
            &bob.transport.listen_addr().unwrap().to_string(),
        )
        .await
        .unwrap();
    wait("Noise connected", || {
        bob.transport.is_connected(alice.state.identity.node_id())
    })
    .await;
    println!("SETUP three nodes paired on 127.0.0.1 (A--C--B)");
    let mut beats = Beats::new();

    // Beat 1: first contact with owner approval.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (status, quote) = alice
        .post(
            "/api/v1/messages/first-contact/quote",
            json!({"recipient": peer}),
            false,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{quote}");
    let grant = alice.service.grant_view_for(&alice.client).unwrap();
    let (status, body) = alice
        .post(
            "/api/v1/pair/first-contact-grant",
            json!({
                "client_id": alice.client, "grant_op_id": grant.op_id, "recipient": peer,
                "max_total_msat": quote["total_msat"], "contact_budget_msat": 100_000
            }),
            true,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    alice.compose(&mut bob, "hello stranger").await;
    assert!(
        alice
            .state
            .session_manager
            .has_session(bob.state.identity.node_id())
            .await
    );
    beats.pass("first contact with owner approval");

    // Beat 2: paid follow-up message under budget.
    alice.compose(&mut bob, "paid follow-up").await;
    beats.pass("paid message");

    // Beat 3: paid reply after A's owner lists B.
    let (status, body) = alice
        .post(
            "/api/v1/peers",
            json!({
                "node_id": peer, "addr": bob.transport.listen_addr().unwrap().to_string(),
                "auto_connect": false
            }),
            true,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    bob.compose(&mut alice, "B replies").await;
    beats.pass("paid reply");

    // Beat 4: refuse a route above the fee cap; nothing moves (0 msat).
    let (used_a, cap_a, cap_b, cap_c) = (
        alice.used(),
        capacity(a.node()),
        capacity(b.node()),
        capacity(&c),
    );
    let over = b
        .create_invoice(2_001, "over fee ceiling", 600)
        .await
        .unwrap();
    let (status, body) = alice
        .post(
            "/api/v1/payments/pay",
            json!({"bolt11": over.bolt11, "max_routing_fee_msat": fee_b - 1}),
            false,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched", "{body}");
    assert_eq!(alice.used(), used_a, "reservation must be released");
    assert_eq!(capacity(a.node()), cap_a);
    assert_eq!(capacity(b.node()), cap_b);
    assert_eq!(capacity(&c), cap_c);
    assert_eq!(
        a.get_payment_status(&over.payment_hash)
            .await
            .unwrap()
            .status,
        PaymentStatus::Failed
    );
    assert_eq!(
        b.get_payment_status(&over.payment_hash)
            .await
            .unwrap()
            .status,
        PaymentStatus::Pending
    );
    beats.pass("refusal over cap at 0 msat");

    // Beat 5: exact msat reconciliation (talk-track money only; refusal excluded).
    let sent_a = 3 * 2_001;
    let expected_a = before_a - sent_a - 3 * fee_b + 2_001;
    let expected_b = before_b + sent_a - 2_001 - fee_a;
    let expected_c = before_c + 3 * fee_b + fee_a;
    wait(
        "exact channel deltas after talk-track settlements",
        || async {
            capacity(a.node()) == expected_a
                && capacity(b.node()) == expected_b
                && capacity(&c) == expected_c
        },
    )
    .await;
    for (node, amounts, fee) in [
        (&a, vec![liquidity, 2_001, 2_001, 2_001], fee_b),
        (&b, vec![2_001], fee_a),
    ] {
        let payments = node.list_payments(100).await.unwrap();
        let mut settled: Vec<_> = payments
            .iter()
            .filter(|p| {
                p.direction == PaymentDirection::Outgoing
                    && p.status == PaymentStatus::Settled
                    && !p.payment_hash.is_empty()
            })
            .collect();
        settled.sort_by_key(|p| std::cmp::Reverse(p.amount_msat));
        assert_eq!(
            settled.iter().map(|p| p.amount_msat).collect::<Vec<_>>(),
            amounts,
            "{settled:?}"
        );
        for payment in &settled {
            let expected_fee = if payment.amount_msat == liquidity {
                hop_fee(to_b, liquidity)
            } else {
                fee
            };
            assert_eq!(payment.fee_msat, Some(expected_fee), "{payment:?}");
            use sha2::{Digest, Sha256};
            let preimage = hex::decode(payment.preimage.as_ref().unwrap()).unwrap();
            assert_eq!(hex::encode(Sha256::digest(preimage)), payment.payment_hash);
        }
    }
    assert_eq!(alice.used(), 3 * (2_001 + fee_b));
    assert_eq!(bob.used(), 2_001 + fee_a);
    println!(
        "reconciled: A {before_a}->{expected_a} ({}), B {before_b}->{expected_b} ({}), C {before_c}->{expected_c} ({})",
        expected_a as i64 - before_a as i64,
        expected_b as i64 - before_b as i64,
        expected_c as i64 - before_c as i64
    );
    beats.pass("exact msat reconciliation");

    drop(alice);
    drop(bob);
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    c.stop().unwrap();
}
