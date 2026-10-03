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
#[cfg(unix)]
#[path = "regtest/three_node.rs"]
mod three_node;

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
    fn skip(&mut self, name: &str, reason: &str) {
        println!("BEAT SKIP {name}: {reason}");
        self.last = std::time::Instant::now();
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

/// One call signal through `from`'s real compose API.
async fn signal(from: &app::App, to: &str, kind: u16, plaintext: String) -> (axum::http::StatusCode, Value) {
    from.post("/api/v1/messages/compose", json!({"recipient": to, "kind": kind, "plaintext": plaintext}), false).await
}

/// Wait for `app` to receive a signal of `kind` from `from` (its feed also
/// echoes its own sends).
async fn recv_kind(app: &mut app::App, from: &konsensus_core::NodeId, kind: u16) -> Arc<konsensus_api::state::WsMessage> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let m = app.received.recv().await.unwrap();
            if m.envelope.sender == *from && m.envelope.kind == kind {
                return m;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for kind {kind}"))
}

/// 1:1 call signalling over real LDK on regtest (overnight ticket A, step 2).
/// Same A -- C -- B topology as `real_ldk_regtest_e2e`. The offer (400) pays
/// B's `call_msat` (10,000 msat default) once; answer/ICE/hangup pay the
/// realtime price (1,000 msat after the 1-sat floor). A reused call id and a
/// signal after hangup are refused by the sender's own node before paying.
/// Media (WebRTC) never touches the node and is not part of this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn real_ldk_regtest_calls() {
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
    let _ = (capacity(a.node()), capacity(b.node()), capacity(&c));
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

    // A holds B's price table, which advertises the call offer by kind.
    let bob_id = *bob.state.identity.node_id();
    let alice_id = *alice.state.identity.node_id();
    // A asks B for its call price (PriceQuery 400 -> PriceResponse); nothing is paid.
    let price = konsensus_api::calls::peer_call_price(&alice.state, &bob_id).await.unwrap();
    assert_eq!(price, 10_000);
    let entry = alice.state.peer_prices.get_peer_entry(&bob_id).await.unwrap();
    println!("A asked B's call price: kind:400={:?}; realtime_signaling={:?}", entry.prices.get("kind:400"), entry.prices.get("realtime_signaling"));
    steps.pass("A asks B's live call price (10000 msat), nothing paid");

    let (a_used0, b_used0) = (alice.used(), bob.used());
    let (a_cap0, b_cap0, c_cap0) = (capacity(a.node()), capacity(b.node()), capacity(&c));
    let a_pay0 = a.list_payments(200).await.unwrap().len();
    let call_id = format!("{:032x}", rand::random::<u128>());
    let sdp = r"v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";
    let bob_hex = bob_id.to_hex();
    let alice_hex = alice_id.to_hex();

    // Offer: paid once at B's call price; B's app is rung.
    let offer = format!(r#"{{"v":1,"call_id":"{call_id}","media":"audio","sdp":"{sdp}"}}"#);
    let started = std::time::Instant::now();
    let (status, body) = signal(&alice, &bob_hex, 400, offer.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 10_000, "{body}");
    let rung = recv_kind(&mut bob, &alice_id, 400).await;
    assert_eq!(rung.plaintext.as_deref(), Some(offer.as_str()));
    println!("offer paid 10000 msat and rang B in {:?}: {body}", started.elapsed());
    steps.pass("call offer paid at call_msat and forwarded to B's WS");

    // The same call id again: A's node refuses before any quote or payment.
    let (status, body) = signal(&alice, &bob_hex, 400, offer.clone()).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], "call_id_used", "{body}");
    // The caller cannot answer its own call.
    let answer = format!(r#"{{"v":1,"call_id":"{call_id}","sdp":"{sdp}"}}"#);
    let (status, body) = signal(&alice, &bob_hex, 401, answer.clone()).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], "call_not_live", "{body}");
    assert_eq!(a.list_payments(200).await.unwrap().len(), a_pay0 + 1, "refusals pay nothing");
    steps.pass("reused call id and caller-side answer refused before paying");

    // B answers; A receives it. ICE flows while live; B hangs up.
    let started = std::time::Instant::now();
    let (status, body) = signal(&bob, &alice_hex, 401, answer.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(recv_kind(&mut alice, &bob_id, 401).await.plaintext.as_deref(), Some(answer.as_str()));
    println!("answer paid {} msat, reached A in {:?}", body["amount_msat"], started.elapsed());
    let ice = format!(r#"{{"v":1,"call_id":"{call_id}","candidate":"candidate:1 1 udp 2122260223 127.0.0.1 54321 typ host","sdp_mid":"0","sdp_mline_index":0}}"#);
    let (status, body) = signal(&alice, &bob_hex, 402, ice.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    recv_kind(&mut bob, &alice_id, 402).await;
    let hangup = format!(r#"{{"v":1,"call_id":"{call_id}","reason":"hangup"}}"#);
    let (status, body) = signal(&bob, &alice_hex, 403, hangup).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    recv_kind(&mut alice, &bob_id, 403).await;
    steps.pass("answer, ICE and hangup paid and delivered both ways");

    // After the hangup, the call is over on both nodes.
    let (status, body) = signal(&alice, &bob_hex, 402, ice).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], "call_not_live", "{body}");
    steps.pass("ICE after hangup refused before paying");

    // msat-exact: A paid offer 10000 + ICE 1000; B paid answer 1000 + hangup 1000,
    // each plus C's forwarding fee on its hop.
    let (fee_b10k, fee_b1k, fee_a1k) = (hop_fee(to_b, 10_000), hop_fee(to_b, 1_000), hop_fee(to_a, 1_000));
    let a_paid = 10_000 + 1_000 + fee_b10k + fee_b1k;
    let b_paid = 2 * (1_000 + fee_a1k);
    wait("exact channel deltas after the call", || async {
        capacity(a.node()) == a_cap0 - a_paid + 2_000
            && capacity(b.node()) == b_cap0 + 11_000 - b_paid
            && capacity(&c) == c_cap0 + fee_b10k + fee_b1k + 2 * fee_a1k
    })
    .await;
    assert_eq!(alice.used() - a_used0, a_paid, "A budget = principals + actual fees");
    assert_eq!(bob.used() - b_used0, b_paid, "B budget = principals + actual fees");
    println!(
        "CALL RECONCILED: A paid {a_paid} msat (offer 10000 + ICE 1000 + fees {}), B paid {b_paid} msat (answer + hangup 2x1000 + fees {}), C earned {} msat",
        fee_b10k + fee_b1k, 2 * fee_a1k, fee_b10k + fee_b1k + 2 * fee_a1k
    );
    steps.pass("msat reconciliation: channels and budgets");

    // Codex P2 (#131): a call after a reconnect must not be stuck behind the
    // call price query. Observed on real LDK: the uncapped (owner) call asks
    // B's call price, re-admits the new connection through the existing flow
    // (reported separately as readmission_msat), then pays the call once.
    alice.transport.disconnect(bob.state.identity.node_id()).await.unwrap();
    wait("disconnected", || async { !bob.transport.is_connected(alice.state.identity.node_id()).await }).await;
    alice.transport.connect(bob.state.identity.node_id(), &bob.transport.listen_addr().unwrap().to_string()).await.unwrap();
    wait("reconnected", || bob.transport.is_connected(alice.state.identity.node_id())).await;
    let pays = a.list_payments(200).await.unwrap().len();
    let fresh = format!("{:032x}", rand::random::<u128>());
    let offer2 = format!(r#"{{"v":1,"call_id":"{fresh}","media":"audio","sdp":"{sdp}"}}"#);
    let (status, body) = signal(&alice, &bob_hex, 400, offer2.clone()).await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!((body["amount_msat"].as_u64(), body["readmission_msat"].as_u64()), (Some(10_000), Some(2_001)), "{body}");
    assert_eq!(recv_kind(&mut bob, &alice_id, 400).await.plaintext.as_deref(), Some(offer2.as_str()));
    assert!(a.list_payments(200).await.unwrap().len() > pays);
    let entry = alice.state.storage.call_get(&bob_id, &fresh).await.unwrap().unwrap();
    assert_eq!((entry.phase, entry.pending), (konsensus_core::payloads::call::Phase::Ringing, None), "committed only once paid");
    println!("call after reconnect: {body}");
    steps.pass("call after reconnect re-admitted once (2001 msat), then paid the call and rang B");
    drop(alice);
    drop(bob);
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    c.stop().unwrap();
    println!("REGTEST-CALLS complete in {:?}", steps.started.elapsed());
}

/// Mesh meeting of three over real LDK on regtest (small group meetings,
/// prototype). Topology: apps A (host), B, C each with one channel to the
/// routing node R. A meeting is nothing but 1:1 calls sharing a meeting id
/// and roster [A, B, C]; the earlier participant places (and pays) each leg:
/// A->B, A->C, B->C. Each leg offer pays the callee's `call_msat` once
/// (10,000 msat); answers and hangups pay the realtime price (1,000 msat), each
/// plus R's forwarding fee. A leg out of roster order is refused by the
/// caller's own node before anything is paid.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn real_ldk_regtest_meeting() {
    use axum::http::StatusCode;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let mut steps = Steps::new();
    let chain = infra::Chain::start().await;
    let dirs = [(); 4].map(|_| tempfile::tempdir().unwrap());
    let (a, _) = infra::lightning(dirs[0].path(), &chain).await;
    let (b, addr_b) = infra::lightning(dirs[1].path(), &chain).await;
    let (c, addr_c) = infra::lightning(dirs[2].path(), &chain).await;
    let (r, addr_r) = infra::router(dirs[3].path(), &chain).await;
    steps.pass("chain + 4 real LDK nodes started (apps A, B, C; router R)");
    chain.fund(a.node()).await;
    chain.fund(&r).await;
    a.open_channel(&r.node_id().to_string(), &addr_r, 1_000_000, false, None).await.unwrap();
    chain.confirm_channel(a.node(), &r, &[b.node(), c.node()]).await;
    r.open_channel(b.node().node_id(), addr_b.parse().unwrap(), 1_000_000, None, None).unwrap();
    chain.confirm_channel(&r, b.node(), &[a.node(), c.node()]).await;
    r.open_channel(c.node().node_id(), addr_c.parse().unwrap(), 1_000_000, None, None).unwrap();
    chain.confirm_channel(&r, c.node(), &[a.node(), b.node()]).await;
    steps.pass("channels A->R, R->B, R->C opened and usable");

    wait("R's channel_updates reach A, B and C", || async {
        hop_policy(a.node(), &r).is_some() && hop_policy(b.node(), &r).is_some() && hop_policy(c.node(), &r).is_some()
    })
    .await;
    // R's fee on its hop towards each app.
    let (to_a, to_b, to_c) = (hop_policy(a.node(), &r).unwrap(), hop_policy(b.node(), &r).unwrap(), hop_policy(c.node(), &r).unwrap());
    // B and C need outbound liquidity to answer, hang up and (B) place a leg.
    for (to, node, policy) in [(&b, "B", to_b), (&c, "C", to_c)] {
        let liquidity = 50_000_000;
        let inv = to.create_invoice(liquidity, "regtest meeting liquidity", 600).await.unwrap();
        a.pay_invoice_with_fee_limit(&inv.bolt11, hop_fee(policy, liquidity)).await.unwrap();
        settle(&a, &inv.payment_hash).await;
        settle(to, &inv.payment_hash).await;
        println!("liquidity to {node} settled");
    }
    wait("liquidity committed", || async { capacity(b.node()) > 10_000_000 && capacity(c.node()) > 10_000_000 }).await;
    steps.pass("routed liquidity A->R->B and A->R->C settled");

    let mut alice = app::App::start(dirs[0].path(), &chain, a.clone()).await;
    let mut bob = app::App::start(dirs[1].path(), &chain, b.clone()).await;
    let mut carol = app::App::start(dirs[2].path(), &chain, c.clone()).await;
    // The stateless quote gate deliberately quarantines the first second.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    // A cycle, so each node is first-contacted once: the admission ledger is
    // process-global and all three apps share this test process.
    contacts(&mut alice, &mut bob).await;
    contacts(&mut bob, &mut carol).await;
    contacts(&mut carol, &mut alice).await;
    steps.pass("A-B, A-C, B-C are paid contacts with E2EE sessions");

    let (a_id, b_id, c_id) = (*alice.state.identity.node_id(), *bob.state.identity.node_id(), *carol.state.identity.node_id());
    let (a_hex, b_hex, c_hex) = (a_id.to_hex(), b_id.to_hex(), c_id.to_hex());
    let meeting = format!("{:032x}", rand::random::<u128>());
    let sdp = r"v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";
    let leg = |call_id: &str| {
        format!(r#"{{"v":1,"call_id":"{call_id}","media":"audio","sdp":"{sdp}","meeting":{{"id":"{meeting}","roster":["{a_hex}","{b_hex}","{c_hex}"]}}}}"#)
    };
    let answer = |call_id: &str| format!(r#"{{"v":1,"call_id":"{call_id}","sdp":"{sdp}"}}"#);
    let hangup = |call_id: &str| format!(r#"{{"v":1,"call_id":"{call_id}","reason":"hangup"}}"#);
    let (ab, ac, bc) = [(); 3].map(|_| format!("{:032x}", rand::random::<u128>())).into();

    let (a_used0, b_used0, c_used0) = (alice.used(), bob.used(), carol.used());
    let (a_cap0, b_cap0, c_cap0, r_cap0) = (capacity(a.node()), capacity(b.node()), capacity(c.node()), capacity(&r));
    let pays = |n: &Arc<LdkProvider>| {
        let n = n.clone();
        async move { n.list_payments(500).await.unwrap().len() }
    };
    let c_pays0 = pays(&c).await;

    // A leg out of roster order: C (last) may not ring A. C's node refuses it
    // before any price query or payment.
    let wrong = format!("{:032x}", rand::random::<u128>());
    let (status, body) = signal(&carol, &a_hex, 400, leg(&wrong)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["reason"], "call_signal_invalid", "{body}");
    assert_eq!(pays(&c).await, c_pays0, "refused leg pays nothing");
    assert_eq!(carol.used(), c_used0);
    steps.pass("out-of-order leg (C->A) refused by C's own node, nothing paid");

    // Host invites: one leg to each invitee, each paid once at the callee's call price.
    for (to, to_hex, to_id, call) in [(&mut bob, &b_hex, b_id, &ab), (&mut carol, &c_hex, c_id, &ac)] {
        to.received = to.state.ws_broadcast.subscribe();
        let (status, body) = signal(&alice, to_hex, 400, leg(call)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["amount_msat"], 10_000, "{body}");
        let rung = recv_from(to, &a_id, 400).await;
        assert_eq!(rung.plaintext.as_deref(), Some(leg(call).as_str()));
        let _ = to_id;
    }
    steps.pass("host A placed legs A->B and A->C, 10000 msat each, both rang");

    // The same leg again: refused before paying (single-use per leg).
    let (status, body) = signal(&alice, &b_hex, 400, leg(&ab)).await;
    assert_eq!((status, body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("call_id_used")), "{body}");

    // B joins: answers the host's leg, then places its own leg to the later C.
    alice.received = alice.state.ws_broadcast.subscribe();
    let (status, body) = signal(&bob, &a_hex, 401, answer(&ab)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    recv_from(&mut alice, &b_id, 401).await;
    // The call-price query limit (one per peer per 2 s) is process-global, and
    // A just asked C: in this shared test process B must wait it out.
    tokio::time::sleep(Duration::from_millis(2_100)).await;
    carol.received = carol.state.ws_broadcast.subscribe();
    let (status, body) = signal(&bob, &c_hex, 400, leg(&bc)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 10_000, "{body}");
    recv_from(&mut carol, &b_id, 400).await;
    steps.pass("B joined: answered A, placed leg B->C (10000 msat)");

    // C joins: answers both ringing legs of the meeting.
    alice.received = alice.state.ws_broadcast.subscribe();
    bob.received = bob.state.ws_broadcast.subscribe();
    let (status, body) = signal(&carol, &a_hex, 401, answer(&ac)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body2) = signal(&carol, &b_hex, 401, answer(&bc)).await;
    assert_eq!(status, StatusCode::OK, "{body2}");
    recv_from(&mut alice, &c_id, 401).await;
    recv_from(&mut bob, &c_id, 401).await;
    for (x, y, call) in [(&alice, &b_id, &ab), (&alice, &c_id, &ac), (&bob, &c_id, &bc)] {
        let e = x.state.storage.call_get(y, call).await.unwrap().unwrap();
        assert_eq!(e.phase, konsensus_core::payloads::call::Phase::Live);
    }
    steps.pass("C joined: all three legs live (full mesh)");

    // C leaves: one paid hangup per live leg. A and B stay connected.
    alice.received = alice.state.ws_broadcast.subscribe();
    bob.received = bob.state.ws_broadcast.subscribe();
    for (to, call) in [(&a_hex, &ac), (&b_hex, &bc)] {
        let (status, body) = signal(&carol, to, 403, hangup(call)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    recv_from(&mut alice, &c_id, 403).await;
    recv_from(&mut bob, &c_id, 403).await;
    assert_eq!(alice.state.storage.call_get(&b_id, &ab).await.unwrap().unwrap().phase, konsensus_core::payloads::call::Phase::Live);
    // An ended leg takes no more signals, even from a participant.
    let (status, body) = signal(&bob, &c_hex, 403, hangup(&bc)).await;
    assert_eq!((status, body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("call_not_live")), "{body}");
    steps.pass("C left (2 paid hangups); A-B still live; ended leg refused");

    // A ends the meeting's last leg.
    bob.received = bob.state.ws_broadcast.subscribe();
    let (status, body) = signal(&alice, &b_hex, 403, hangup(&ab)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    recv_from(&mut bob, &a_id, 403).await;
    steps.pass("A hung up the last leg");

    // msat-exact. Paid (principal + R's fee on the hop to the payee):
    //   A: offers A->B, A->C (10000 each), hangup A->B (1000)
    //   B: offer B->C (10000), answer B->A (1000)
    //   C: answers C->A, C->B, hangups C->A, C->B (1000 each)
    let f = |p, amt| hop_fee(p, amt);
    let a_paid = 10_000 + f(to_b, 10_000) + 10_000 + f(to_c, 10_000) + 1_000 + f(to_b, 1_000);
    let b_paid = 10_000 + f(to_c, 10_000) + 1_000 + f(to_a, 1_000);
    let c_paid = 2 * (1_000 + f(to_a, 1_000)) + 2 * (1_000 + f(to_b, 1_000));
    let (a_got, b_got, c_got) = (3_000, 13_000, 20_000);
    let r_earned = (a_paid - 21_000) + (b_paid - 11_000) + (c_paid - 4_000);
    wait("exact channel deltas after the meeting", || async {
        capacity(a.node()) == a_cap0 - a_paid + a_got
            && capacity(b.node()) == b_cap0 - b_paid + b_got
            && capacity(c.node()) == c_cap0 - c_paid + c_got
            && capacity(&r) == r_cap0 + r_earned
    })
    .await;
    assert_eq!(alice.used() - a_used0, a_paid, "A budget = principals + actual fees");
    assert_eq!(bob.used() - b_used0, b_paid, "B budget = principals + actual fees");
    assert_eq!(carol.used() - c_used0, c_paid, "C budget = principals + actual fees");
    println!(
        "MEETING RECONCILED: A paid {a_paid} got {a_got}; B paid {b_paid} got {b_got}; C paid {c_paid} got {c_got}; R earned {r_earned} msat"
    );
    steps.pass("msat reconciliation: channels and budgets, per participant");
    drop((alice, bob, carol));
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    c.shutdown().await.unwrap();
    r.stop().unwrap();
    println!("REGTEST-MEETING complete in {:?}", steps.started.elapsed());
}

/// Rooms MVP over real LDK on regtest. Topology: apps A (sender), B, C, D,
/// each with one channel to the routing node R. A room is ordinary chat
/// (kind 0) carrying a room binding {id, roster, salt}, the id committing to
/// the roster; A pays each other member through the room fan-out: B, C and D
/// each get their own envelope and are paid their chat price (2,001 msat)
/// plus R's fee on the hop to them. B replies with one 1:1 room leg, and A's
/// room thread shows both directions, A's three copies as one entry.
/// Refusals, msat-exact: A's own node refuses a roster without A, a 1:1 room
/// chat to a non-member and the room id with a swapped roster before paying;
/// a member whose node does not advertise `room_binding_v1` is skipped and
/// paid nothing; and A refuses (withdraws, never shows) paid room chats from
/// B whose roster lacks B or whose roster does not match the room id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn real_ldk_regtest_room() {
    use axum::http::StatusCode;
    use konsensus_core::traits::transport::MessageTransport;
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let mut steps = Steps::new();
    let chain = infra::Chain::start().await;
    let dirs = [(); 5].map(|_| tempfile::tempdir().unwrap());
    let (a, _) = infra::lightning(dirs[0].path(), &chain).await;
    let (b, addr_b) = infra::lightning(dirs[1].path(), &chain).await;
    let (c, addr_c) = infra::lightning(dirs[2].path(), &chain).await;
    let (d, addr_d) = infra::lightning(dirs[3].path(), &chain).await;
    let (r, addr_r) = infra::router(dirs[4].path(), &chain).await;
    steps.pass("chain + 5 real LDK nodes started (apps A, B, C, D; router R)");
    chain.fund(a.node()).await;
    chain.fund(&r).await;
    a.open_channel(&r.node_id().to_string(), &addr_r, 1_000_000, false, None).await.unwrap();
    chain.confirm_channel(a.node(), &r, &[b.node(), c.node(), d.node()]).await;
    r.open_channel(b.node().node_id(), addr_b.parse().unwrap(), 800_000, None, None).unwrap();
    chain.confirm_channel(&r, b.node(), &[a.node(), c.node(), d.node()]).await;
    r.open_channel(c.node().node_id(), addr_c.parse().unwrap(), 800_000, None, None).unwrap();
    chain.confirm_channel(&r, c.node(), &[a.node(), b.node(), d.node()]).await;
    r.open_channel(d.node().node_id(), addr_d.parse().unwrap(), 800_000, None, None).unwrap();
    chain.confirm_channel(&r, d.node(), &[a.node(), b.node(), c.node()]).await;
    steps.pass("channels A->R, R->B, R->C, R->D opened and usable");

    wait("R's channel_updates reach A, B, C and D", || async {
        [a.node(), b.node(), c.node(), d.node()].iter().all(|n| hop_policy(n, &r).is_some())
    })
    .await;
    let [to_a, to_b, to_c, to_d] = [a.node(), b.node(), c.node(), d.node()].map(|n| hop_policy(n, &r).unwrap());
    // Members need outbound liquidity to reply as contacts (and B to pay A).
    for (to, node, policy) in [(&b, "B", to_b), (&c, "C", to_c), (&d, "D", to_d)] {
        let liquidity = 50_000_000;
        let inv = to.create_invoice(liquidity, "regtest room liquidity", 600).await.unwrap();
        a.pay_invoice_with_fee_limit(&inv.bolt11, hop_fee(policy, liquidity)).await.unwrap();
        settle(&a, &inv.payment_hash).await;
        settle(to, &inv.payment_hash).await;
        println!("liquidity to {node} settled");
    }
    wait("liquidity committed", || async {
        [b.node(), c.node(), d.node()].iter().all(|n| capacity(n) > 10_000_000)
    })
    .await;
    steps.pass("routed liquidity A->R->{B,C,D} settled");

    let mut alice = app::App::start(dirs[0].path(), &chain, a.clone()).await;
    let mut bob = app::App::start(dirs[1].path(), &chain, b.clone()).await;
    let mut carol = app::App::start(dirs[2].path(), &chain, c.clone()).await;
    let mut dave = app::App::start(dirs[3].path(), &chain, d.clone()).await;
    // The stateless quote gate deliberately quarantines the first second.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    // A first-contacts each member once (the admission ledger is process-global).
    let bob_reply = contacts(&mut alice, &mut bob).await;
    contacts(&mut alice, &mut carol).await;
    contacts(&mut alice, &mut dave).await;
    steps.pass("A-B, A-C, A-D are paid contacts with E2EE sessions");

    let (a_id, b_id, c_id, d_id) = (*alice.state.identity.node_id(), *bob.state.identity.node_id(), *carol.state.identity.node_id(), *dave.state.identity.node_id());
    for peer in [b_id, c_id, d_id] {
        let info = alice.transport.peer_info(&peer).await.expect("connected");
        assert!(info.capabilities.iter().any(|c| c == r#"Custom("room_binding_v1")"#), "{:?}", info.capabilities);
    }
    use konsensus_core::payloads::room::RoomBinding;
    let room_of = |ids: &[konsensus_core::NodeId]| RoomBinding::create(ids).unwrap();
    let room_chat = |room: &RoomBinding, text: &str| {
        json!({"v": 1, "room": room, "msg": format!("{:032x}", rand::random::<u128>()), "text": text}).to_string()
    };
    async fn send_room(alice: &app::App, room: &RoomBinding, plaintext: String) -> (StatusCode, Value) {
        alice.post("/api/v1/messages/compose", json!({"recipient": room.id, "is_room": true, "kind": 0, "plaintext": plaintext}), false).await
    }
    let pays = |n: &Arc<LdkProvider>| {
        let n = n.clone();
        async move { n.list_payments(500).await.unwrap().len() }
    };
    let chat_msat: u64 = 2_001;
    let (a_used0, b_used0) = (alice.used(), bob.used());
    let caps0 = [capacity(a.node()), capacity(b.node()), capacity(c.node()), capacity(d.node()), capacity(&r)];
    let a_pays0 = pays(&a).await;

    // Refused by A's own node before any quote or payment.
    let full = room_of(&[a_id, b_id, c_id, d_id]);
    let not_mine = room_of(&[b_id, c_id, d_id]);
    let (status, body) = send_room(&alice, &not_mine, room_chat(&not_mine, "not mine")).await;
    assert_eq!((status, body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("room_sender_not_member")), "{body}");
    let (status, body) = alice
        .post("/api/v1/messages/compose", json!({"recipient": d_id.to_hex(), "kind": 0, "plaintext": room_chat(&room_of(&[a_id, b_id, c_id]), "not yours")}), false)
        .await;
    assert_eq!((status, body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("room_recipient_not_member")), "{body}");
    // The room id of [A, B, C, D] with D swapped for an outsider.
    let outsider = NodeIdentity::generate().unwrap().1;
    let mut swapped = full.clone();
    swapped.roster = room_of(&[a_id, b_id, c_id, *outsider.node_id()]).roster;
    let (status, body) = send_room(&alice, &full, room_chat(&swapped, "swapped")).await;
    assert_eq!((status, body["reason"].as_str()), (StatusCode::BAD_REQUEST, Some("room_binding_invalid")), "{body}");
    assert_eq!((pays(&a).await, alice.used()), (a_pays0, a_used0), "nothing paid");
    steps.pass("roster without A, a 1:1 room chat to a non-member, a swapped roster: refused by A's node, nothing paid");

    // Fan-out to 3 members: each paid once, on its own envelope.
    let text = room_chat(&full, "hello room");
    for app in [&mut bob, &mut carol, &mut dave] {
        app.received = app.state.ws_broadcast.subscribe();
    }
    let (status, body) = send_room(&alice, &full, text.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], 3 * chat_msat, "{body}");
    let outcomes = body["member_outcomes"].as_array().unwrap();
    assert_eq!(outcomes.len(), 3, "{body}");
    for o in outcomes {
        assert_eq!((o["status"].as_str(), o["amount_msat"].as_u64()), (Some("settled"), Some(chat_msat)), "{o}");
    }
    for app in [&mut bob, &mut carol, &mut dave] {
        let got = recv_from(app, &a_id, 0).await;
        assert_eq!(got.plaintext.as_deref(), Some(text.as_str()));
        assert_eq!(got.envelope.recipient, konsensus_core::Recipient::Node(*app.state.identity.node_id()), "addressed to the member");
        assert_eq!(got.envelope.payment_proof.amount_msat, chat_msat);
    }
    steps.pass("A -> {B, C, D}: 3 paid envelopes, 2001 msat each, all delivered");

    // B answers the room on its 1:1 leg to A (how the app sends: one leg per
    // member). A's room thread holds both directions, A's copies as one entry.
    let b_used_reply = bob.used();
    let reply_text = room_chat(&full, "hello from b");
    let reply = bob.compose(&mut alice, &reply_text).await;
    assert_eq!(reply["amount_msat"], chat_msat, "{reply}");
    let reply_paid = bob.used() - b_used_reply;
    let (status, thread) = alice.get(&format!("/api/v1/messages?room={}", full.id), true).await;
    assert_eq!(status, StatusCode::OK, "{thread}");
    let thread = thread.as_array().unwrap();
    assert_eq!(thread.len(), 2, "{thread:?}");
    let ours = thread.iter().find(|m| m["sender"] == a_id.to_hex()).expect("A's own room message");
    assert_eq!((ours["recipient"].as_str(), ours["payment_amount_msat"].as_u64()), (Some(full.id.as_str()), Some(3 * chat_msat)), "{ours}");
    let copies: Vec<&str> = ours["copies"].as_array().unwrap().iter().map(|c| c["recipient"].as_str().unwrap()).collect();
    let mut members = vec![b_id.to_hex(), c_id.to_hex(), d_id.to_hex()];
    members.sort();
    assert_eq!(copies, members, "{ours}");
    let theirs = thread.iter().find(|m| m["sender"] == b_id.to_hex()).expect("B's room reply");
    assert_eq!(theirs["plaintext"].as_str(), Some(reply_text.as_str()));
    assert_eq!(theirs["room"]["id"].as_str(), Some(full.id.as_str()));
    steps.pass("B's 1:1 room leg (2001 msat) reaches A; A's thread: B's reply + A's 3 copies as one");

    // A member whose node does not advertise room_binding_v1 (here: a node
    // A is not connected to) is skipped before any quote, paid nothing.
    let absent = NodeIdentity::generate().unwrap().1;
    let partial_room = room_of(&[a_id, b_id, *absent.node_id()]);
    let partial = room_chat(&partial_room, "partial");
    bob.received = bob.state.ws_broadcast.subscribe();
    let (status, body) = send_room(&alice, &partial_room, partial.clone()).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["amount_msat"], chat_msat, "{body}");
    let skipped = body["member_outcomes"].as_array().unwrap().iter().find(|o| o["recipient"] == absent.node_id().to_hex()).unwrap().clone();
    assert_eq!((skipped["status"].as_str(), skipped["amount_msat"].as_u64(), skipped["code"].as_str()), (Some("refused"), Some(0), Some("room_binding_unsupported")));
    assert_eq!(recv_from(&mut bob, &a_id, 0).await.plaintext.as_deref(), Some(partial.as_str()));
    steps.pass("unsupported member skipped (0 msat); B paid 2001 msat");

    // Receive side: B pays A for room chats only a modified node would send
    // (B's own compose refuses them). A's gate admits each payment, then A
    // refuses the binding: withdrawn, never shown, terminal for B.
    let price = bob_reply["amount_msat"].as_u64().unwrap();
    assert_eq!(price, chat_msat);
    let hex32 = |s: &str| <[u8; 32]>::try_from(hex::decode(s).unwrap()).unwrap();
    let mut swapped_in = full.clone();
    swapped_in.roster = room_of(&[a_id, b_id, c_id, *outsider.node_id()]).roster;
    for (rogue, code) in [
        (room_chat(&room_of(&[a_id, c_id, d_id]), "let me in"), "room_sender_not_member:"),
        (room_chat(&swapped_in, "new roster, same room"), "room_binding_invalid:"),
    ] {
        let invoice = a.create_invoice(price, "rogue room chat", 600).await.unwrap();
        b.pay_invoice_with_fee_limit(&invoice.bolt11, hop_fee(to_a, price)).await.unwrap();
        settle(&b, &invoice.payment_hash).await;
        let preimage = b.get_payment_status(&invoice.payment_hash).await.unwrap().preimage.expect("preimage");
        let ratchet = bob.state.session_manager.encrypt(&a_id, rogue.as_bytes()).await.unwrap();
        let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
            0,
            b_id,
            konsensus_core::Recipient::Node(a_id),
            konsensus_crypto::ratchet_message_to_bytes(&ratchet),
            konsensus_core::PaymentProof::new(hex32(&invoice.payment_hash), hex32(&preimage), price),
        )
        .build();
        envelope.signature = konsensus_core::Signature::from_ed25519(&bob.state.identity.sign(&envelope.signable_bytes()));
        bob.state.storage.store_message(&envelope).await.unwrap();
        bob.state.storage.prepare_delivery(&envelope.id, &a_id).await.unwrap();
        let mut b_delivery = bob.state.ws_delivery_broadcast.subscribe();
        alice.received = alice.state.ws_broadcast.subscribe();
        bob.transport.send(&a_id, &envelope).await.unwrap();
        let status = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let s = b_delivery.recv().await.unwrap();
                if s.message_id == envelope.id.to_hex() {
                    return s;
                }
            }
        })
        .await
        .expect("A answered the rogue room chat");
        assert_eq!(status.status, "failed_paid", "terminal: {status:?}");
        assert!(status.reason.as_deref().unwrap_or_default().starts_with(code), "{status:?}");
        assert!(alice.state.storage.get_message(&envelope.id).await.unwrap().is_none(), "withdrawn on A");
        while let Ok(m) = alice.received.try_recv() {
            assert_ne!(m.envelope.id, envelope.id, "the refused room chat reached A's app");
        }
        let (_, listed) = alice.get("/api/v1/messages?limit=1000", true).await;
        assert!(listed.as_array().unwrap().iter().all(|m| m["id"] != envelope.id.to_hex()), "listed on A");
    }
    steps.pass("A refused B's paid room chats (roster without B; swapped roster under the room id), withdrawn");

    // msat-exact, between the snapshots:
    //   A paid 3 fan-out legs + 1 partial leg; B paid A its room reply and
    //   two refused rogue chats.
    let f = hop_fee;
    let a_paid = chat_msat + f(to_b, chat_msat) + chat_msat + f(to_c, chat_msat) + chat_msat + f(to_d, chat_msat) + chat_msat + f(to_b, chat_msat);
    let b_paid = 3 * (price + f(to_a, price));
    let (a_got, b_got, c_got, d_got) = (3 * price, 2 * chat_msat, chat_msat, chat_msat);
    let r_earned = (a_paid - 4 * chat_msat) + (b_paid - 3 * price);
    wait("exact channel deltas after the room", || async {
        capacity(a.node()) == caps0[0] - a_paid + a_got
            && capacity(b.node()) == caps0[1] - b_paid + b_got
            && capacity(c.node()) == caps0[2] + c_got
            && capacity(d.node()) == caps0[3] + d_got
            && capacity(&r) == caps0[4] + r_earned
    })
    .await;
    assert_eq!(alice.used() - a_used0, a_paid, "A budget = principals + actual fees");
    assert_eq!(reply_paid, price + f(to_a, price), "B's reply leg: price + actual fee");
    assert_eq!(bob.used() - b_used0, reply_paid, "B's rogue payments bypassed its app budget");
    println!(
        "ROOM RECONCILED: A paid {a_paid} got {a_got}; B paid {b_paid} got {b_got}; C got {c_got}; D got {d_got}; R earned {r_earned} msat"
    );
    steps.pass("msat reconciliation: channels and budgets, per member");
    drop((alice, bob, carol, dave));
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    c.shutdown().await.unwrap();
    d.shutdown().await.unwrap();
    r.stop().unwrap();
    println!("REGTEST-ROOM complete in {:?}", steps.started.elapsed());
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

/// `x` and `y` become contacts the ordinary way: x pays first contact, lists
/// y, and y replies (returns y's reply receipt). No meeting or room shortcut.
async fn contacts(x: &mut app::App, y: &mut app::App) -> Value {
    use axum::http::StatusCode;
    use konsensus_core::traits::transport::MessageTransport;
    let y_hex = y.state.identity.node_id().to_hex();
    x.transport.connect(y.state.identity.node_id(), &y.transport.listen_addr().unwrap().to_string()).await.unwrap();
    wait("Noise connected", || y.transport.is_connected(x.state.identity.node_id())).await;
    let (status, quote) = x.post("/api/v1/messages/first-contact/quote", json!({"recipient": y_hex}), false).await;
    assert_eq!(status, StatusCode::OK, "{quote}");
    let grant = x.service.grant_view_for(&x.client).unwrap();
    let (status, body) = x
        .post(
            "/api/v1/pair/first-contact-grant",
            json!({"client_id": x.client, "grant_op_id": grant.op_id, "recipient": y_hex,
                   "max_total_msat": quote["total_msat"], "contact_budget_msat": 200_000}),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    x.compose(y, "hello").await;
    let (status, body) = x
        .post("/api/v1/peers", json!({"node_id": y_hex, "addr": y.transport.listen_addr().unwrap().to_string(), "auto_connect": false}), true)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    y.compose(x, "hello back").await
}

/// Next message on `app`'s feed from `from` of `kind` (the feed also echoes
/// the app's own sends).
async fn recv_from(
    app: &mut app::App,
    from: &konsensus_core::NodeId,
    kind: u16,
) -> Arc<konsensus_api::state::WsMessage> {
    use tokio::sync::broadcast::error::RecvError;
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match app.received.recv().await {
                Ok(m) if m.envelope.sender == *from && m.envelope.kind == kind => return m,
                Ok(_) | Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => panic!("feed closed"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timeout waiting for kind {kind}"))
}

/// One call signal through `from`'s real compose API.
async fn call_signal(
    from: &app::App,
    to: &konsensus_core::NodeId,
    kind: u16,
    text: &str,
) -> (axum::http::StatusCode, Value) {
    let body = json!({"recipient": to.to_hex(), "kind": kind, "plaintext": text});
    from.post("/api/v1/messages/compose", body, false).await
}

/// Channel capacities and grant usage at one point of the talk track.
#[derive(Clone, Copy)]
struct Snapshot {
    a: u64,
    b: u64,
    c: u64,
    used_a: u64,
    used_b: u64,
}

/// Per-beat msat books for the A -- C -- B rehearsal: each money beat states
/// what every channel and budget must move by, and waits for exactly that.
struct Books<'n> {
    a: &'n ldk_node::Node,
    b: &'n ldk_node::Node,
    c: &'n ldk_node::Node,
    last: Snapshot,
}

impl<'n> Books<'n> {
    fn snapshot(&self, alice: &app::App, bob: &app::App) -> Snapshot {
        Snapshot {
            a: capacity(self.a),
            b: capacity(self.b),
            c: capacity(self.c),
            used_a: alice.used(),
            used_b: bob.used(),
        }
    }

    /// Channel deltas in msat (signed) and budget debits since the last beat.
    async fn reconcile(
        &mut self,
        beat: &str,
        (alice, bob): (&app::App, &app::App),
        (da, db, dc): (i64, i64, i64),
        (ua, ub): (u64, u64),
    ) {
        let last = self.last;
        let moved = |from: u64, by: i64| u64::try_from(from as i64 + by).unwrap();
        let (a, b, c) = (moved(last.a, da), moved(last.b, db), moved(last.c, dc));
        wait(&format!("exact channel deltas for {beat}"), || async {
            capacity(self.a) == a && capacity(self.b) == b && capacity(self.c) == c
        })
        .await;
        assert_eq!(alice.used() - last.used_a, ua, "{beat}: A budget");
        assert_eq!(bob.used() - last.used_b, ub, "{beat}: B budget");
        assert_eq!(da + db + dc, 0, "{beat}: msat conserved across A, B and C");
        println!("MSAT {beat}: A {da:+} B {db:+} C {dc:+} msat; budget A +{ua} B +{ub} msat");
        self.last = self.snapshot(alice, bob);
    }
}

/// Settled outgoing payments `node` made, largest first.
async fn settled_outgoing(node: &LdkProvider) -> Vec<konsensus_core::traits::lightning::PaymentDetails> {
    let mut settled: Vec<_> = node
        .list_payments(200)
        .await
        .unwrap()
        .into_iter()
        .filter(|p| {
            p.direction == PaymentDirection::Outgoing
                && p.status == PaymentStatus::Settled
                && !p.payment_hash.is_empty()
        })
        .collect();
    settled.sort_by_key(|p| std::cmp::Reverse(p.amount_msat));
    settled
}

/// Demo talk-track rehearsal on real LDK regtest, A -- C -- B with B behind a
/// front door: B publishes a front-door card and exports it as a link; A
/// verifies it and knocks (first contact with owner approval, admission paid
/// once); paid message; paid reply; a voice note sent as a paid file and
/// received intact; a 1:1 call offer paid once at call_msat with answer and
/// hangup (only when the checkout has paid calls, #131, else a SKIP line);
/// refusal over cap at 0 msat; exact msat reconciliation. Every money beat
/// also reconciles to the msat on its own. Run via `scripts/demo-rehearsal.sh`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/demo-rehearsal.sh"]
async fn mexico_demo_rehearsal() {
    use axum::http::StatusCode;
    use base64::Engine;
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

    let mut alice = app::App::start(dirs[0].path(), &chain, a.clone()).await;
    let mut bob = app::App::start(dirs[1].path(), &chain, b.clone()).await;
    let peer = bob.state.identity.node_id().to_hex();
    let (alice_id, bob_id) = (
        *alice.state.identity.node_id(),
        *bob.state.identity.node_id(),
    );
    use konsensus_core::traits::transport::MessageTransport;
    assert!(!alice.transport.is_connected(&bob_id).await);
    println!("SETUP three nodes on 127.0.0.1 (A--C--B); A has never dialled B");
    let mut books = Books {
        a: a.node(),
        b: b.node(),
        c: &c,
        last: Snapshot {
            a: 0,
            b: 0,
            c: 0,
            used_a: 0,
            used_b: 0,
        },
    };
    books.last = books.snapshot(&alice, &bob);
    let start = books.last;
    let mut beats = Beats::new();

    // Beat 1: B's owner publishes a front door; the link is also the QR payload.
    let (status, door) = bob
        .put(
            "/api/v1/front-door",
            json!({
                "display_name": "Bob", "tagline": "Paid messages welcome",
                "about": "Rehearsal front door on regtest"
            }),
            true,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{door}");
    let link = door["link"].as_str().unwrap().to_owned();
    assert!(link.starts_with("bitsov://front-door#"), "{link}");
    assert_eq!(door["qr_payload"], door["link"]);
    assert_eq!((&door["verified"], &door["fresh"]), (&json!(true), &json!(true)));
    let card = &door["card"];
    assert_eq!(card["node_id"], peer);
    assert_eq!(card["network"], "regtest");
    assert_eq!(card["reach"], "local", "{card}");
    assert_eq!(card["prices"]["admission_msat"], 2_001);
    assert_eq!(card["prices"]["message_msat"], 2_001);
    let (status, published) = bob.get("/api/v1/front-door", false).await;
    assert_eq!(status, StatusCode::OK, "{published}");
    assert_eq!(published["link"], door["link"]);
    println!("front door link ({} chars): {link}", link.len());
    beats.pass("front-door card created and exported as link");

    // Beat 2: A verifies the pasted link: signed by B, fresh, on regtest.
    let (status, seen) = alice
        .post("/api/v1/front-door/verify", json!({"card": link}), false)
        .await;
    assert_eq!(status, StatusCode::OK, "{seen}");
    assert_eq!((&seen["verified"], &seen["fresh"]), (&json!(true), &json!(true)));
    assert_eq!(&seen["card"], card);
    assert!(!alice.transport.is_connected(&bob_id).await, "verify never dials");
    beats.pass("front-door card verified");

    // Beat 3: A knocks. Open dials B unprivileged (A consents to the displayed
    // local endpoint); the ordinary first contact with owner approval then
    // pays B's advertised admission exactly once.
    let (status, opened) = alice
        .post(
            "/api/v1/front-door/open",
            json!({"card": link, "allow_local": true}),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    assert_eq!((&opened["node_id"], &opened["connected"]), (&json!(peer), &json!(true)));
    wait("Noise connected via front door", || {
        bob.transport.is_connected(&alice_id)
    })
    .await;
    assert!(!alice.state.session_manager.has_session(&bob_id).await);
    assert!(bob.transport.connected_privileged_peers().await.is_empty());
    // The stateless quote gate deliberately quarantines the first second.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let (status, quote) = alice
        .post(
            "/api/v1/messages/first-contact/quote",
            json!({"recipient": peer}),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{quote}");
    assert_eq!(quote["admission_msat"], card["prices"]["admission_msat"], "{quote}");
    assert_eq!(quote["message_msat"], card["prices"]["message_msat"], "{quote}");
    let paid_before = settled_outgoing(&a).await.len();
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
    assert_eq!(status, StatusCode::OK, "{body}");
    alice.compose(&mut bob, "hello from your front door").await;
    assert!(alice.state.session_manager.has_session(&bob_id).await);
    assert_eq!(
        settled_outgoing(&a).await.len(),
        paid_before + 2,
        "admission + first message"
    );
    let knock = 2 * (2_001 + fee_b);
    books
        .reconcile(
            "first contact",
            (&alice, &bob),
            (-(knock as i64), 2 * 2_001, 2 * fee_b as i64),
            (knock, 0),
        )
        .await;
    beats.pass("first contact with owner approval (front-door knock, paid once)");

    // Beat 4: paid follow-up under budget; admission is not paid again.
    alice.compose(&mut bob, "paid follow-up").await;
    assert_eq!(settled_outgoing(&a).await.len(), paid_before + 3);
    books
        .reconcile(
            "paid message",
            (&alice, &bob),
            (-((2_001 + fee_b) as i64), 2_001, fee_b as i64),
            (2_001 + fee_b, 0),
        )
        .await;
    beats.pass("paid message");

    // Beat 5: paid reply after A's owner lists B.
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
    assert_eq!(status, StatusCode::OK, "{body}");
    bob.compose(&mut alice, "B replies").await;
    books
        .reconcile(
            "paid reply",
            (&alice, &bob),
            (2_001, -((2_001 + fee_a) as i64), fee_a as i64),
            (0, 2_001 + fee_a),
        )
        .await;
    beats.pass("paid reply");

    // Beat 6: a voice note as the app sends it: an ordinary paid file
    // (kind 200, audio/webm, voice-note-<stamp>.webm), received intact.
    let clip: Vec<u8> = [0x1a, 0x45, 0xdf, 0xa3]
        .into_iter()
        .chain((0..24_000u32).map(|i| (i * 31 % 251) as u8))
        .collect();
    let name = "voice-note-20260930-101500.webm";
    let (status, staged) = alice
        .post(
            "/api/v1/files",
            json!({
                "filename": name, "mime_type": "audio/webm",
                "data_b64": base64::engine::general_purpose::STANDARD.encode(&clip)
            }),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{staged}");
    let (status, sent) = alice
        .post(
            &format!("/api/v1/files/{}/send", staged["file_id"].as_str().unwrap()),
            json!({"recipient": peer}),
            false,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{sent}");
    assert_eq!(sent["delivered"], true, "{sent}");
    // file_ref_msat is 100 msat; Lightning pays at least 1 sat.
    let file_msat = 1_000;
    assert_eq!(sent["amount_msat"], file_msat, "{sent}");
    let got = recv_from(&mut bob, &alice_id, konsensus_core::kind::KIND_FILE_REF).await;
    assert_eq!(got.plaintext.as_deref(), Some(format!("[file: {name}]").as_str()));
    let (status, files) = bob.get("/api/v1/files", false).await;
    assert_eq!(status, StatusCode::OK, "{files}");
    let record = files
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["message_id"] == sent["message_id"])
        .unwrap_or_else(|| panic!("B has no file for {sent}: {files}"));
    assert_eq!(record["filename"], name);
    assert_eq!(record["mime_type"], "audio/webm");
    assert_eq!(record["sender"], alice_id.to_hex());
    assert_eq!(record["blake3_hash"], staged["blake3_hash"]);
    let (status, download) = bob
        .get(&format!("/api/v1/files/{}", record["id"].as_str().unwrap()), false)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(download["data_b64"].as_str().unwrap())
            .unwrap(),
        clip
    );
    let fee_file = hop_fee(to_b, file_msat);
    books
        .reconcile(
            "voice note",
            (&alice, &bob),
            (-((file_msat + fee_file) as i64), file_msat as i64, fee_file as i64),
            (file_msat + fee_file, 0),
        )
        .await;
    println!("voice note: {} bytes, {sent}", clip.len());
    beats.pass("voice note sent as paid file and received");

    // Beat 7: a 1:1 call (#131). The offer pays B's call_msat once; the same
    // call id is refused before paying; answer and hangup pay the realtime
    // price. Media (WebRTC) never touches the node.
    const CALL: &str = "1:1 call offer paid once at call_msat, answered and hung up";
    let (mut call_a, mut call_b) = (vec![], vec![]);
    if std::env::var("DEMO_REHEARSAL_CALLS").as_deref() == Ok("run") {
        let (call_msat, signal_msat) = (10_000, 1_000);
        let call_id = format!("{:032x}", rand::random::<u128>());
        let sdp = r"v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n";
        let offer = format!(r#"{{"v":1,"call_id":"{call_id}","media":"audio","sdp":"{sdp}"}}"#);
        let (status, body) = call_signal(&alice, &bob_id, 400, &offer).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["amount_msat"], call_msat, "{body}");
        let rung = recv_from(&mut bob, &alice_id, 400).await;
        assert_eq!(rung.plaintext.as_deref(), Some(offer.as_str()));
        let paid = settled_outgoing(&a).await.len();
        let (status, body) = call_signal(&alice, &bob_id, 400, &offer).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["reason"], "call_id_used", "{body}");
        assert_eq!(settled_outgoing(&a).await.len(), paid, "refusal pays nothing");

        let answer = format!(r#"{{"v":1,"call_id":"{call_id}","sdp":"{sdp}"}}"#);
        let (status, body) = call_signal(&bob, &alice_id, 401, &answer).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["amount_msat"], signal_msat, "{body}");
        let answered = recv_from(&mut alice, &bob_id, 401).await;
        assert_eq!(answered.plaintext.as_deref(), Some(answer.as_str()));
        let hangup = format!(r#"{{"v":1,"call_id":"{call_id}","reason":"hangup"}}"#);
        let (status, body) = call_signal(&alice, &bob_id, 403, &hangup).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["amount_msat"], signal_msat, "{body}");
        recv_from(&mut bob, &alice_id, 403).await;

        let (fee_offer, fee_hangup, fee_answer) = (
            hop_fee(to_b, call_msat),
            hop_fee(to_b, signal_msat),
            hop_fee(to_a, signal_msat),
        );
        let (paid_a, paid_b) = (
            call_msat + fee_offer + signal_msat + fee_hangup,
            signal_msat + fee_answer,
        );
        books
            .reconcile(
                "call",
                (&alice, &bob),
                (
                    signal_msat as i64 - paid_a as i64,
                    (call_msat + signal_msat) as i64 - paid_b as i64,
                    (fee_offer + fee_hangup + fee_answer) as i64,
                ),
                (paid_a, paid_b),
            )
            .await;
        (call_a, call_b) = (vec![call_msat, signal_msat], vec![signal_msat]);
        beats.pass(CALL);
    } else {
        let reason = std::env::var("DEMO_REHEARSAL_CALLS_SKIP")
            .unwrap_or_else(|_| "paid 1:1 calls (#131) not enabled for this run".into());
        beats.skip(CALL, &reason);
    }

    // Beat 8: refuse a route above the fee cap; nothing moves (0 msat).
    let used_a = alice.used();
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
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["code"], "not_dispatched", "{body}");
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
    books
        .reconcile("refusal", (&alice, &bob), (0, 0, 0), (0, 0))
        .await;
    beats.pass("refusal over cap at 0 msat");

    // Beat 9: the whole talk track against the ledgers: every settled payment
    // at its exact principal and C's exact fee, and the channel totals.
    let end = books.snapshot(&alice, &bob);
    let mut sent_a: Vec<u64> = [vec![liquidity, 2_001, 2_001, 2_001, file_msat], call_a].concat();
    let mut sent_b: Vec<u64> = [vec![2_001], call_b].concat();
    let mut spent = [0u64; 2];
    for ((node, amounts, towards), spent) in [
        (&a, &mut sent_a, to_b),
        (&b, &mut sent_b, to_a),
    ]
    .into_iter()
    .zip(&mut spent)
    {
        amounts.sort_by_key(|&m| std::cmp::Reverse(m));
        let settled = settled_outgoing(node).await;
        assert_eq!(
            settled.iter().map(|p| p.amount_msat).collect::<Vec<_>>(),
            *amounts,
            "{settled:?}"
        );
        for payment in &settled {
            assert_eq!(
                payment.fee_msat,
                Some(hop_fee(towards, payment.amount_msat)),
                "{payment:?}"
            );
            use sha2::{Digest, Sha256};
            let preimage = hex::decode(payment.preimage.as_ref().unwrap()).unwrap();
            assert_eq!(hex::encode(Sha256::digest(preimage)), payment.payment_hash);
            if payment.amount_msat != liquidity {
                *spent += payment.amount_msat + hop_fee(towards, payment.amount_msat);
            }
        }
    }
    let received_b: u64 = sent_a.iter().filter(|&&m| m != liquidity).sum();
    let received_a: u64 = sent_b.iter().sum();
    let fees = spent[0] + spent[1] - received_a - received_b;
    assert_eq!(end.a, start.a - spent[0] + received_a);
    assert_eq!(end.b, start.b - spent[1] + received_b);
    assert_eq!(end.c, start.c + fees);
    assert_eq!(end.used_a - start.used_a, spent[0], "A budget = principals + fees");
    assert_eq!(end.used_b - start.used_b, spent[1], "B budget = principals + fees");
    println!(
        "reconciled: A {}->{} ({:+}), B {}->{} ({:+}), C {}->{} ({:+}) msat",
        start.a,
        end.a,
        end.a as i64 - start.a as i64,
        start.b,
        end.b,
        end.b as i64 - start.b as i64,
        start.c,
        end.c,
        end.c as i64 - start.c as i64
    );
    beats.pass("exact msat reconciliation");

    drop(alice);
    drop(bob);
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    c.stop().unwrap();
}

/// Step 1 chain source: use only the existing Core harness, no electrs or peers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires an offline BITCOIND_EXE; launches isolated regtest only"]
async fn bitcoind_chain_source_pruned_and_full() {
    use konsensus_chain::{BitcoindConfig, BitcoindProvider};
    use konsensus_core::traits::chain::ChainProvider;
    for pruned in [true, false] {
        let mut conf = corepc_node::Conf::default();
        conf.wallet = None;
        conf.network = "regtest";
        conf.p2p = corepc_node::P2P::No;
        conf.args = vec!["-regtest", "-fallbackfee=0.0001", "-networkactive=0", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1", "-dnsseed=0", "-discover=0"];
        conf.args.push(if pruned { "-prune=550" } else { "-txindex=1" });
        let bitcoin = corepc_node::Node::with_conf(std::env::var("BITCOIND_EXE").expect("offline BITCOIND_EXE"), &conf).unwrap();
        let _: Value = bitcoin.client.call("createwallet", &[json!("chain-source")]).unwrap();
        let address: Value = bitcoin.client.call("getnewaddress", &[]).unwrap();
        let blocks: Value = bitcoin.client.call("generatetoaddress", &[json!(101), address]).unwrap();
        let block: Value = bitcoin.client.call("getblock", &[blocks[100].clone()]).unwrap();
        let txid = block["tx"][0].as_str().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut rpc = BitcoindConfig {
            rpc_host: "127.0.0.1".into(), rpc_port: bitcoin.params.rpc_socket.port(),
            cookie_file: Some(bitcoin.params.cookie_file.clone()), rpc_user: None, rpc_password_file: None,
        };
        if !pruned {
            let cookie = std::fs::read_to_string(&bitcoin.params.cookie_file).unwrap();
            let (user, password) = cookie.trim().split_once(':').unwrap();
            let path = dir.path().join("rpc.pass");
            std::fs::write(&path, password).unwrap();
            rpc.cookie_file = None;
            rpc.rpc_user = Some(user.into());
            rpc.rpc_password_file = Some(path);
        }
        let provider = BitcoindProvider::new(rpc.clone()).unwrap();
        assert_eq!(provider.get_block_height().await.unwrap(), 101);
        assert_eq!(provider.get_block_header(1).await.unwrap().height, 1);
        assert!(provider.is_synced().await);
        assert!(provider.is_tx_confirmed(txid, 1).await.unwrap());
        assert!(!provider.is_tx_confirmed(txid, 2).await.unwrap());
        assert_eq!(provider.chain_view().trust_level, "own_node");
        let ldk = LdkProvider::new(konsensus_lightning::LdkConfig {
            logging: Default::default(),
            electrum: None,
            bitcoind: Some(rpc), liquidity: Default::default(), storage_dir: dir.path().join("ldk"),
            scb_backup_dir: None, scb_rotation_count: 3,
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            passphrase: None, network: "regtest".into(),
            // These must not even be validated/probed when Core is selected.
            esplora_url: "disabled".into(), esplora_url_fallback: Some("disabled".into()), credentials_file: None,
            rgs_url: None, lsp_node_id: None, lsp_address: None, lsp_token: None, listening_address: None,
        }).await.unwrap();
        assert!(ldk.is_available().await);
        wait("bitcoind LDK wallet synchronization", || ldk.money_ready()).await;
        assert_eq!(ldk.node().status().current_best_block.height, 101);
        let address: Value = bitcoin.client.call("getnewaddress", &[]).unwrap();
        let _: Value = bitcoin.client.call("generatetoaddress", &[json!(1), address]).unwrap();
        wait("bitcoind LDK follows new blocks", || async {
            ldk.node().status().current_best_block.height == 102
        }).await;
        assert!(provider.is_tx_confirmed(txid, 2).await.unwrap());
        ldk.shutdown().await.unwrap();
    }
}
