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

fn capacity(node: &LdkProvider) -> u64 {
    node.node()
        .list_channels()
        .iter()
        .map(|c| c.outbound_capacity_msat)
        .sum()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn real_ldk_regtest_e2e() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();
    let started = std::time::Instant::now();
    let chain = infra::Chain::start().await;
    let (dir_a, dir_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let (a, _) = infra::lightning(dir_a.path(), &chain).await;
    let (b, addr_b) = infra::lightning(dir_b.path(), &chain).await;
    println!("real LDK nodes started; funding A from matured regtest coinbase");
    chain.fund(&a).await;
    let funding_fee = chain.channel(&a, &b, &addr_b).await;
    assert_eq!(
        a.node().list_balances().total_onchain_balance_sats,
        2_000_000 - funding_fee
    );

    // Give B enough outbound liquidity to clear its channel reserve and reply.
    // This is a real Lightning transfer; it does not admit either Noise identity.
    let inv = b
        .create_invoice(50_000_000, "regtest reply liquidity", 600)
        .await
        .unwrap();
    let pending = a.pay_invoice_with_fee_limit(&inv.bolt11, 0).await.unwrap();
    println!(
        "initial payment status: {:?}, fee: {:?}",
        pending.status, pending.fee_msat
    );
    settle(&a, &inv.payment_hash).await;
    settle(&b, &inv.payment_hash).await;
    wait("liquidity committed", || async {
        capacity(&b) > 10_000_000
    })
    .await;
    let (before_a, before_b) = (capacity(&a), capacity(&b));

    let mut alice = app::App::start(dir_a.path(), &chain, a.clone()).await;
    let mut bob = app::App::start(dir_b.path(), &chain, b.clone()).await;
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
    assert!(
        !alice
            .state
            .session_manager
            .has_session(bob.state.identity.node_id())
            .await
    );
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
    alice.compose(&mut bob, "paid follow-up").await;
    bob.compose(&mut alice, "B replies").await;
    wait(
        "exact channel deltas after all HTLC commitments",
        || async { capacity(&a) == before_a - 4_002 && capacity(&b) == before_b + 4_002 },
    )
    .await;
    assert_eq!(alice.used(), 6_003);
    assert_eq!(bob.used(), 2_001);
    for (node, expected) in [(&a, 50_006_003), (&b, 2_001)] {
        let payments = node.list_payments(100).await.unwrap();
        let outgoing: Vec<_> = payments
            .iter()
            .filter(|p| p.direction == PaymentDirection::Outgoing)
            .collect();
        assert!(
            outgoing
                .iter()
                .all(|p| p.status == PaymentStatus::Settled && p.fee_msat == Some(0)),
            "{outgoing:?}"
        );
        assert_eq!(
            outgoing.iter().map(|p| p.amount_msat).sum::<u64>(),
            expected
        );
        for payment in outgoing {
            use sha2::{Digest, Sha256};
            let preimage = hex::decode(payment.preimage.as_ref().unwrap()).unwrap();
            assert_eq!(hex::encode(Sha256::digest(preimage)), payment.payment_hash);
        }
    }
    println!("reconciled: A sent 6003 msat, B replied 2001 msat, net A -4002 / B +4002 msat; route fees 0 msat; funding {funding_fee} sat");
    drop(alice);
    drop(bob);
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    println!(
        "Messaging/reconciliation assertions passed in {:?}; diagnostic estimated-fee mode: {}",
        started.elapsed(),
        std::env::var("REGTEST_DIAGNOSTIC_ESTIMATED_FEE").is_ok()
    );
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
    let (status, body) = alice
        .post(
            "/api/v1/payments/pay",
            json!({
                "bolt11": invoice.bolt11, "max_routing_fee_msat": 37
            }),
            false,
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::BAD_GATEWAY, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains("payment not dispatched"),
        "{body}"
    );
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
