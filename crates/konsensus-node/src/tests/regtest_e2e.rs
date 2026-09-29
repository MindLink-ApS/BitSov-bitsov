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
async fn signal(
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
        let (status, body) = signal(&alice, &bob_id, 400, &offer).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["amount_msat"], call_msat, "{body}");
        let rung = recv_from(&mut bob, &alice_id, 400).await;
        assert_eq!(rung.plaintext.as_deref(), Some(offer.as_str()));
        let paid = settled_outgoing(&a).await.len();
        let (status, body) = signal(&alice, &bob_id, 400, &offer).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["reason"], "call_id_used", "{body}");
        assert_eq!(settled_outgoing(&a).await.len(), paid, "refusal pays nothing");

        let answer = format!(r#"{{"v":1,"call_id":"{call_id}","sdp":"{sdp}"}}"#);
        let (status, body) = signal(&bob, &alice_id, 401, &answer).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["amount_msat"], signal_msat, "{body}");
        let answered = recv_from(&mut alice, &bob_id, 401).await;
        assert_eq!(answered.plaintext.as_deref(), Some(answer.as_str()));
        let hangup = format!(r#"{{"v":1,"call_id":"{call_id}","reason":"hangup"}}"#);
        let (status, body) = signal(&alice, &bob_id, 403, &hangup).await;
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
