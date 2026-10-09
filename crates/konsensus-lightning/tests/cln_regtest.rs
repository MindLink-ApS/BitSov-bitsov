//! Real CLN interoperability. No downloads; see docs/regtest-e2e.md.
//! Mutations caught: missing/widened maxfee, unusable rune restrictions, broken
//! CLN settlement mapping, or accepting a paid envelope without incoming funds.
#![cfg(unix)]
#[path = "common/cln_regtest.rs"]
mod fixture;

use fixture::*;
use konsensus_core::{
    gate::{GateConfig, GateRejection, PaymentGate},
    kind::KIND_CHAT,
    traits::lightning::{LightningProvider, PaymentDetails, PaymentDirection, PaymentStatus},
    types::{PaymentProof, Recipient, Signature},
    NodeIdentity, UkmEnvelopeBuilder,
};
use serde_json::json;
use std::time::Duration;

struct Price;
#[async_trait::async_trait]
impl konsensus_core::traits::pricing::PricingEngine for Price {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    async fn get_price_msat(
        &self,
        _: u16,
    ) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        Ok(2_001)
    }
    async fn get_category_price_msat(
        &self,
        _: konsensus_core::kind::KindCategory,
    ) -> Result<u64, konsensus_core::traits::pricing::PricingError> {
        Ok(2_001)
    }
}

async fn paid_message(
    sender: &NodeIdentity,
    recipient: &NodeIdentity,
    receiver: &dyn LightningProvider,
    payer: &dyn LightningProvider,
    payment: &PaymentDetails,
    content: &[u8],
) {
    let receipt = settle(receiver, &payment.payment_hash).await;
    assert_eq!(receipt.direction, PaymentDirection::Incoming);
    assert_eq!(receipt.amount_msat, 2_001);
    assert_eq!(receipt.preimage, payment.preimage);
    let envelope = |preimage: [u8; 32], amount| {
        let mut envelope = UkmEnvelopeBuilder::new(
            KIND_CHAT,
            *sender.node_id(),
            Recipient::Node(*recipient.node_id()),
            content.to_vec(),
            PaymentProof::new(
                hex::decode(&payment.payment_hash)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                preimage,
                amount,
            ),
        )
        .build();
        envelope.signature = Signature::from_ed25519(&sender.sign(&envelope.signable_bytes()));
        envelope
    };
    let preimage = hex::decode(receipt.preimage.unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let gate = PaymentGate::with_config(GateConfig {
        verify_lightning_settlement: true,
        ..Default::default()
    });
    assert!(gate
        .validate_paid_envelope(
            &envelope(preimage, 2_001),
            &Price,
            None,
            Some(receiver),
            0.0,
            Some(recipient.node_id())
        )
        .await
        .is_ok());
    // A valid signed proof and a real settled OUTGOING record must not buy
    // admission. Unlike a malformed preimage this reaches settlement checking.
    settle(payer, &payment.payment_hash).await;
    assert!(matches!(
        gate.validate_paid_envelope(
            &envelope(preimage, 2_001),
            &Price,
            None,
            Some(payer),
            0.0,
            Some(recipient.node_id())
        )
        .await,
        Err(GateRejection::PaymentSettlementMismatch(_))
    ));
    assert!(gate
        .validate_paid_envelope(
            &envelope([99; 32], 2_001),
            &Price,
            None,
            Some(receiver),
            0.0,
            Some(recipient.node_id())
        )
        .await
        .is_err());
    assert!(matches!(
        gate.validate_paid_envelope(
            &envelope(preimage, 2_000),
            &Price,
            None,
            Some(receiver),
            0.0,
            Some(recipient.node_id())
        )
        .await,
        Err(GateRejection::InsufficientPayment { .. })
    ));
}

/// T5/T7/T8/T9: CLN -- LDK hub -- LDK recipient. Only the hub can forward
/// to the recipient, whose private invoice hint advertises a 5,000 msat fee.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires BITCOIND_EXE and LIGHTNINGD_EXE; isolated real-node regtest"]
async fn real_cln_regtest() {
    let Some(binaries) = Binaries::from_env() else {
        return;
    };
    tokio::time::timeout(Duration::from_secs(600), scenario(binaries))
        .await
        .expect("CLN regtest exceeded 600 seconds");
    println!("CLN REGTEST PASS: T5 T7 T8 T9");
}

async fn scenario(binaries: Binaries) {
    let core = Core::start(&binaries.bitcoind).await;
    core.mine(101).await;
    let cln = Cln::start(&binaries, &core).await;
    let hub = Ldk::start(&core, true).await;
    let recipient = Ldk::start(&core, false).await;
    let nodes = [&hub, &recipient];
    for node in nodes {
        core.rpc(
            "sendtoaddress",
            json!([
                node.provider
                    .node()
                    .onchain_payment()
                    .new_address()
                    .unwrap()
                    .to_string(),
                0.03
            ]),
        )
        .await;
    }
    let address = cln.rpc("newaddr", json!({})).await["bech32"].clone();
    core.rpc("sendtoaddress", json!([address, 0.03])).await;
    core.mine(6).await;
    sync(&core, &cln, &nodes).await;
    let id = cln.rpc("getinfo", json!({})).await["id"]
        .as_str()
        .unwrap()
        .to_owned();
    cln.rpc(
        "connect",
        json!({"id": hub.id(), "host":"127.0.0.1", "port":hub.port}),
    )
    .await;
    cln.rpc(
        "fundchannel",
        json!({"id":hub.id(), "amount":1_000_000, "announce":false}),
    )
    .await;
    confirm(&core, &cln, &nodes, 1, 0).await;
    hub.provider
        .open_channel(
            &recipient.id(),
            &format!("127.0.0.1:{}", recipient.port),
            1_000_000,
            false,
            None,
        )
        .await
        .unwrap();
    confirm(&core, &cln, &nodes, 2, 1).await;
    assert_eq!(cln.channels().await.len(), 1);
    assert_eq!(recipient.provider.node().list_channels().len(), 1);
    let channel = hub
        .provider
        .node()
        .list_channels()
        .into_iter()
        .find(|ch| ch.counterparty_node_id.to_string() == recipient.id())
        .unwrap();
    let mut policy = channel.config;
    policy.forwarding_fee_base_msat = 5_000;
    policy.forwarding_fee_proportional_millionths = 0;
    hub.provider
        .node()
        .update_channel_config(
            &channel.user_channel_id,
            channel.counterparty_node_id,
            policy,
        )
        .unwrap();
    wait("recipient learns the hub's fee", || async {
        recipient.provider.node().list_channels().iter().any(|ch| {
            ch.counterparty_forwarding_info_fee_base_msat == Some(5_000)
                && ch.counterparty_forwarding_info_fee_proportional_millionths == Some(0)
        })
    })
    .await;
    let provider = cln.provider().await;
    wait("CLN money ready", || provider.money_ready()).await;
    println!(
        "T5 PASS: real CLN {} with restricted clnrest rune; CLN--LDK--LDK channels usable",
        cln.version
    );

    // Give the hub sufficient outbound liquidity on the CLN channel to reply.
    let liquidity = hub
        .provider
        .create_invoice(50_000_000, "reply liquidity", 600)
        .await
        .unwrap();
    let paid = provider
        .pay_invoice_with_fee_limit(&liquidity.bolt11, 0)
        .await
        .unwrap();
    assert_eq!(paid.fee_msat, Some(0));
    settle(&hub.provider, &liquidity.payment_hash).await;
    cln.idle().await;
    let alice = NodeIdentity::generate().unwrap().1;
    let bob = NodeIdentity::generate().unwrap().1;
    let paid = provider
        .keysend_with_fee_limit(&hub.id(), 2_001, Some("CLN paid message"), 0)
        .await
        .unwrap();
    assert_eq!(paid.status, PaymentStatus::Settled);
    assert_eq!(paid.fee_msat, Some(0));
    paid_message(
        &alice,
        &bob,
        &hub.provider,
        &provider,
        &paid,
        b"CLN paid message",
    )
    .await;
    let reply = hub
        .provider
        .keysend_with_fee_limit(&id, 2_001, Some("LDK paid reply"), 0)
        .await
        .unwrap();
    let reply = settle(&hub.provider, &reply.payment_hash).await;
    paid_message(
        &bob,
        &alice,
        &provider,
        &hub.provider,
        &reply,
        b"LDK paid reply",
    )
    .await;
    assert_eq!(reply.fee_msat, Some(0));
    println!(
        "T7 PASS: {} paid message admitted by LDK gate; paid LDK reply admitted by CLN gate",
        cln.keysend_method
    );

    // Positive control establishes a route, liquidity, rune authorization and
    // the exact fee BEFORE the negative test. No-route cannot pass T8.
    let control = recipient
        .provider
        .create_invoice(2_001, "high fee positive control", 600)
        .await
        .unwrap();
    let invoice: lightning_invoice::Bolt11Invoice = control.bolt11.parse().unwrap();
    assert!(invoice
        .route_hints()
        .iter()
        .any(|hint| hint
            .0
            .iter()
            .any(|hop| hop.src_node_id.to_string() == hub.id()
                && hop.fees.base_msat == 5_000
                && hop.fees.proportional_millionths == 0)));
    let paid = provider
        .pay_invoice_with_fee_limit(&control.bolt11, 5_000)
        .await
        .unwrap();
    assert_eq!(paid.fee_msat, Some(5_000));
    settle(&recipient.provider, &control.payment_hash).await;
    cln.idle().await;
    stable_capacities(&nodes).await;
    let balances = cln.balances().await;
    let capacities = capacities(&nodes);
    let denied = recipient
        .provider
        .create_invoice(2_001, "above fee ceiling", 600)
        .await
        .unwrap();
    // The provider treats any error after POST conservatively. A timeout alone
    // is NOT proof: await CLN's terminal result/HTLC drainage below as well.
    assert!(provider
        .pay_invoice_with_fee_limit(&denied.bolt11, 4_999)
        .await
        .is_err());
    cln.wait_failed_payment(&denied.payment_hash).await;
    cln.idle().await;
    assert_eq!(
        recipient
            .provider
            .get_payment_status(&denied.payment_hash)
            .await
            .unwrap()
            .status,
        PaymentStatus::Pending
    );
    assert_eq!(
        cln.balances().await,
        balances,
        "CLN principal/fees must not move"
    );
    assert_eq!(
        fixture::capacities(&nodes),
        capacities,
        "neither LDK node may be debited"
    );
    let attempts = cln
        .rpc("listsendpays", json!({"payment_hash":denied.payment_hash}))
        .await;
    assert!(attempts["payments"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p["status"] == "failed"));
    // The route must still work after the refusal: a dead peer or route cannot
    // masquerade as enforcement of the lower ceiling.
    let after = recipient
        .provider
        .create_invoice(2_001, "route still available", 600)
        .await
        .unwrap();
    assert_eq!(
        provider
            .pay_invoice_with_fee_limit(&after.bolt11, 5_000)
            .await
            .unwrap()
            .fee_msat,
        Some(5_000)
    );
    settle(&recipient.provider, &after.payment_hash).await;
    cln.idle().await;
    println!(
        "T8 PASS: proven 5000-msat route refuses 4999-msat ceiling; no settlement, HTLC or debit"
    );

    let before = cln.balances().await;
    let sends_before = cln.rpc("listsendpays", json!({})).await;
    for maxfee in [None, Some(10_001)] {
        let invoice = hub
            .provider
            .create_invoice(2_001, "rune refusal", 600)
            .await
            .unwrap();
        let mut params = json!({"invstring":invoice.bolt11});
        if let Some(fee) = maxfee {
            params["maxfee"] = json!(fee);
        }
        cln.assert_rune_denied("xpay", params).await;
        assert_eq!(
            hub.provider
                .get_payment_status(&invoice.payment_hash)
                .await
                .unwrap()
                .status,
            PaymentStatus::Pending
        );
        let mut params = json!({"destination":hub.id(), "amount_msat":2_001});
        if let Some(fee) = maxfee {
            params["maxfee"] = json!(fee);
        }
        cln.assert_rune_denied(cln.keysend_method, params).await;
    }
    let destination = core.rpc("getnewaddress", json!([])).await;
    cln.assert_rune_denied(
        "withdraw",
        json!({"destination":destination, "satoshi":10_000}),
    )
    .await;
    cln.idle().await;
    assert_eq!(cln.rpc("listsendpays", json!({})).await, sends_before);
    assert_eq!(cln.balances().await, before);
    // Same restricted credential must still be usable after the negative probes.
    let allowed = hub
        .provider
        .create_invoice(2_001, "rune positive control", 600)
        .await
        .unwrap();
    assert_eq!(
        provider
            .pay_invoice_with_fee_limit(&allowed.bolt11, 0)
            .await
            .unwrap()
            .fee_msat,
        Some(0)
    );
    settle(&hub.provider, &allowed.payment_hash).await;
    println!(
        "T9 PASS: missing/over-cap maxfee and withdraw rejected by rune; capped payment succeeds"
    );
    hub.provider.shutdown().await.unwrap();
    recipient.provider.shutdown().await.unwrap();
}

async fn stable_capacities(nodes: &[&Ldk]) {
    // Commitment updates may follow settlement events; require a quiet window.
    let mut previous = capacities(nodes);
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let current = capacities(nodes);
        if current == previous {
            return;
        }
        previous = current;
    }
    panic!("LDK capacities did not stabilize");
}
