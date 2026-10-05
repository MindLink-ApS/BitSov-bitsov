//! Production hub/client interoperability: JIT funding is never admission.
use super::super::*;
use konsensus_lightning::liquidity::{LiquidityConfig, LspConfig};
use konsensus_lightning::lsps2_service::Lsps2ServiceConfig;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/three_node_paid_e2e.sh"]
async fn hub_jit_then_stateless_admission() {
    let chain = infra::Chain::start().await;
    let dirs = [(); 3].map(|_| tempfile::tempdir().unwrap());
    let mut hub_config = infra::lightning_config(dirs[0].path(), &chain.url);
    hub_config.lsps2_service = Lsps2ServiceConfig {
        enabled: true,
        require_token: Some("regtest-private-pilot".into()),
        forwarding_fee_ppm: 500,
        forwarding_fee_base_msat: 1000,
        ..Default::default()
    };
    let hub_addr = hub_config.listening_address.clone().unwrap();
    let hub = LdkProvider::new(hub_config.clone()).await.unwrap();
    let hub_id = hub.node().node_id();
    hub.shutdown().await.unwrap();
    drop(hub);

    let mut client_config = infra::lightning_config(dirs[1].path(), &chain.url);
    client_config.liquidity = LiquidityConfig {
        enabled: true,
        selected_provider: Some(hub_id.to_string()),
        providers: vec![LspConfig {
            node_id: hub_id.to_string(),
            address: hub_addr.clone(),
            token: Some("regtest-private-pilot".into()),
        }],
    };
    let client = LdkProvider::new(client_config).await.unwrap();
    // A disconnected service is a bounded failure, never a free invoice or
    // permission to switch providers. Reuse this exact client after recovery.
    assert!(tokio::time::timeout(
        Duration::from_secs(60),
        client.quote_liquidity("owner", 100_000_000, 1_000_000)
    )
    .await
    .unwrap()
    .is_err());
    assert!(client.node().list_channels().is_empty());
    let hub = LdkProvider::new(hub_config.clone()).await.unwrap();
    let (sponsor, _) = infra::lightning(dirs[2].path(), &chain).await;
    for node in [client.node(), hub.node(), sponsor.node()] {
        // The client's on-chain funds preserve the anchor reserve; they do not
        // create a channel or substitute for the sponsor's Lightning top-up.
        chain.fund(node).await;
        assert!(node.config().node_alias.is_none());
    }
    sponsor
        .open_channel(&hub_id.to_string(), &hub_addr, 1_000_000, false, None)
        .await
        .unwrap();
    chain
        .confirm_channel(sponsor.node(), hub.node(), &[client.node()])
        .await;
    assert!(client.node().list_channels().is_empty());

    let funding = tokio::time::timeout(Duration::from_secs(60), async {
        let terms = client
            .quote_liquidity("owner", 100_000_000, 1_000_000)
            .await
            .unwrap();
        assert_eq!(terms.max_fee_msat, 1_000_000);
        let invoice = client
            .accept_liquidity("owner", &terms.quote_id)
            .await
            .unwrap();
        sponsor
            .pay_invoice_with_fee_limit(&invoice.bolt11, 5000)
            .await
            .unwrap();
        // Existing client trust flow observes the funding transaction before
        // claiming. Drive the real chain source while the zero-conf JIT opens.
        wait("JIT settlement", || async {
            client.node().sync_wallets().unwrap();
            client
                .get_payment_status(&invoice.payment_hash)
                .await
                .unwrap()
                .status
                == PaymentStatus::Settled
        })
        .await;
        settle(&sponsor, &invoice.payment_hash).await;
        invoice
    })
    .await
    .expect("JIT quote/open/settlement must complete within 60 seconds");
    let receipt = client
        .liquidity_receipt(&funding.payment_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(receipt.gross_msat, 100_000_000);
    assert_eq!(receipt.lsp_fee_msat, 1_000_000);
    assert_eq!(receipt.net_received_msat, 99_000_000);
    assert!(
        client
            .is_funding_payment(&funding.payment_hash)
            .await
            .unwrap(),
        "gate must exclude funding from admission"
    );
    assert_eq!(client.node().list_channels().len(), 1);
    assert_eq!(hub.node().list_channels().len(), 2);
    let channel = client.node().list_channels().pop().unwrap();
    assert!(channel.is_usable && !channel.is_announced && !channel.is_outbound);
    assert!(channel.outbound_capacity_msat > 90_000_000);
    assert!(
        channel.inbound_capacity_msat > 90_000_000,
        "overprovisioning supplies receipt capacity"
    );
    chain
        .confirm_channel(hub.node(), client.node(), &[sponsor.node()])
        .await;

    wait("client receives hub tariff", || async {
        client.node().list_channels().iter().any(|c| {
            c.counterparty_forwarding_info_fee_base_msat == Some(1000)
                && c.counterparty_forwarding_info_fee_proportional_millionths == Some(500)
        })
    })
    .await;
    assert_eq!(hop_policy(client.node(), hub.node()), Some((1000, 500)));

    // Simulate a crash window leaving a persisted JIT channel at LDK's 0/0.
    // Startup reconciliation must repair it even without a new ChannelReady.
    let jit = hub
        .node()
        .list_channels()
        .into_iter()
        .find(|c| c.counterparty_node_id == client.node().node_id())
        .unwrap();
    let mut zero = jit.config;
    zero.forwarding_fee_base_msat = 0;
    zero.forwarding_fee_proportional_millionths = 0;
    hub.node()
        .update_channel_config(&jit.user_channel_id, jit.counterparty_node_id, zero)
        .unwrap();
    hub.shutdown().await.unwrap();
    drop(hub);
    let hub = LdkProvider::new(hub_config).await.unwrap();
    client
        .node()
        .connect(hub_id, hub_addr.parse().unwrap(), true)
        .unwrap();
    sponsor
        .node()
        .connect(hub_id, hub_addr.parse().unwrap(), true)
        .unwrap();
    wait("JIT tariff restored after restart", || async {
        hub.node().list_channels().iter().any(|c| {
            c.user_channel_id == jit.user_channel_id
                && c.is_usable
                && c.config.forwarding_fee_base_msat == 1000
                && c.config.forwarding_fee_proportional_millionths == 500
        }) && client.node().list_channels().iter().all(|c| c.is_usable)
            && sponsor.node().list_channels().iter().all(|c| c.is_usable)
    })
    .await;

    // Both directions use fresh, ordinary stateless admission quotes. The app
    // pays from its JIT balance; receiving on the overprovisioned side earns
    // the hub its configured positive tariff without skimming the principal.
    for (payer, recipient) in [(&client, sponsor.as_ref()), (sponsor.as_ref(), &client)] {
        let amount = 2_001;
        wait("admission route policy", || async {
            recipient
                .node()
                .list_channels()
                .iter()
                .any(|c| c.counterparty_forwarding_info_fee_base_msat == Some(1000))
        })
        .await;
        let fee = hop_fee(hop_policy(recipient.node(), hub.node()).unwrap(), amount);
        let allowance = payer.routing_fee_policy().ceiling(amount, None);
        assert!(fee > 0 && fee <= allowance);
        let invoice = recipient
            .create_stateless_invoice(amount, "admission", 60)
            .await
            .unwrap();
        let id = ldk_node::lightning::ln::channelmanager::PaymentId(
            hex::decode(&invoice.payment_hash)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert!(
            recipient.node().payment(&id).is_none(),
            "quote must remain stateless"
        );
        payer
            .pay_invoice_with_fee_limit(&invoice.bolt11, allowance)
            .await
            .unwrap();
        settle(payer, &invoice.payment_hash).await;
        settle(recipient, &invoice.payment_hash).await;
        let sent = payer
            .get_payment_status(&invoice.payment_hash)
            .await
            .unwrap();
        let received = recipient
            .verify_payment(&invoice.payment_hash)
            .await
            .unwrap();
        assert_eq!(sent.fee_msat, Some(fee));
        assert_eq!(received.amount_msat, amount, "no fee skim on admission");
        assert!(!recipient
            .is_funding_payment(&invoice.payment_hash)
            .await
            .unwrap());
        assert_eq!(received.direction, PaymentDirection::Incoming);
        assert!(recipient
            .liquidity_receipt(&invoice.payment_hash)
            .await
            .unwrap()
            .is_none());
        assert_eq!(sent.preimage, received.preimage);
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(
                hex::decode(received.preimage.unwrap()).unwrap()
            )),
            invoice.payment_hash
        );
    }
    client.shutdown().await.unwrap();
    sponsor.shutdown().await.unwrap();
    hub.shutdown().await.unwrap();
    println!("PASS hub LSPS2 JIT: bounded funding, disconnect/restart, stateless admission, positive capped tariff");
}
