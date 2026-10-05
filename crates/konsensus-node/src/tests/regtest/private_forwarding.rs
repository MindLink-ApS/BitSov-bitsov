//! #225: exercise the production hub constructor, without the LSPS2 override.
use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn production_hub_private_forwarding_is_opt_in() {
    let chain = infra::Chain::start().await;
    // Fresh nodes per case: failed routes must not poison the positive control's scorer.
    for enabled in [false, true] {
        let dirs = [(); 3].map(|_| tempfile::tempdir().unwrap());
        let (a, _) = infra::lightning(dirs[0].path(), &chain).await;
        let (b, b_addr) = infra::lightning(dirs[1].path(), &chain).await;
        let mut config = infra::lightning_config(dirs[2].path(), &chain.url);
        config.forward_to_private_channels = enabled;
        let hub_addr = config.listening_address.clone().unwrap();
        let hub = LdkProvider::new(config).await.unwrap();
        let hub_id = hub.node().node_id().to_string();
        for node in [a.node(), b.node(), hub.node()] {
            assert!(node.config().node_alias.is_none());
        }
        chain.fund(a.node()).await;
        chain.fund(hub.node()).await;
        a.open_channel(&hub_id, &hub_addr, 1_000_000, false, None)
            .await
            .unwrap();
        chain
            .confirm_channel(a.node(), hub.node(), &[b.node()])
            .await;
        hub.open_channel(
            &b.node().node_id().to_string(),
            &b_addr,
            1_000_000,
            false,
            None,
        )
        .await
        .unwrap();
        chain
            .confirm_channel(hub.node(), b.node(), &[a.node()])
            .await;
        for node in [a.node(), b.node(), hub.node()] {
            assert!(node
                .list_channels()
                .iter()
                .all(|c| c.is_usable && !c.is_announced));
        }
        assert_eq!(a.node().list_channels().len(), 1);
        assert_eq!(b.node().list_channels().len(), 1);
        assert_eq!(hub.node().list_channels().len(), 2);
        wait("hub forwarding policy received", || async {
            hop_policy(b.node(), hub.node()).is_some()
        })
        .await;
        let amount = 100_000;
        let fee = hop_fee(hop_policy(b.node(), hub.node()).unwrap(), amount);
        assert!(fee > 0);
        let invoice = b
            .create_invoice(amount, "private hub forwarding", 600)
            .await
            .unwrap();
        let parsed: lightning_invoice::Bolt11Invoice = invoice.bolt11.parse().unwrap();
        assert!(
            parsed.route_hints().iter().any(|hint| hint
                .0
                .iter()
                .any(|hop| { hop.src_node_id == hub.node().node_id() })),
            "the invoice must supply the private hub route"
        );
        // Dispatch must succeed in BOTH cases: a pre-dispatch routing failure
        // does not reproduce PrivateChannelForward at the hub.
        a.pay_invoice_with_fee_limit(&invoice.bolt11, fee)
            .await
            .unwrap();
        if enabled {
            settle(&a, &invoice.payment_hash).await;
            settle(&b, &invoice.payment_hash).await;
            let sent = a.get_payment_status(&invoice.payment_hash).await.unwrap();
            let received = b.get_payment_status(&invoice.payment_hash).await.unwrap();
            assert_eq!(sent.fee_msat, Some(fee));
            assert_eq!(received.amount_msat, amount);
            assert!(sent.preimage.is_some());
        } else {
            wait("private forward rejected", || async {
                a.get_payment_status(&invoice.payment_hash)
                    .await
                    .unwrap()
                    .status
                    == PaymentStatus::Failed
            })
            .await;
            let log = std::fs::read_to_string(dirs[2].path().join("ldk/ldk_node.log")).unwrap();
            assert!(
                log.contains("PrivateChannelForward"),
                "hub must reject the private forward"
            );
            assert_ne!(
                b.get_payment_status(&invoice.payment_hash)
                    .await
                    .unwrap()
                    .status,
                PaymentStatus::Settled
            );
        }
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
        hub.shutdown().await.unwrap();
    }
}
