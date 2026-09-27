//! Exercise the production pre-claim handler, without starting a node, network
//! listeners, chain RPC or a funded wallet. MPP parts use LDK's in-memory harness.
use super::*;
use lightning::events::bump_transaction::Wallet as LdkWallet;
use lightning_types::payment::PaymentSecret;

#[derive(Default)]
struct ClaimLog(Mutex<Vec<String>>);
impl crate::logger::LogWriter for ClaimLog {
    fn log<'a>(&self, record: crate::logger::LogRecord<'a>) {
        self.0.lock().unwrap().push(record.args.to_string());
    }
}

fn setup() -> (tempfile::TempDir, crate::Builder, Arc<ClaimLog>) {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(ClaimLog::default());
    let mut builder = crate::Builder::new();
    builder.set_custom_logger(log.clone());
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_entropy_seed_bytes([87; 64]);
    builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
    (dir, builder, log)
}

fn handler(node: &crate::Node) -> EventHandler<Arc<Logger>> {
    EventHandler::new(
        node.event_queue.clone(), node.wallet.clone(),
        Arc::new(BumpTransactionEventHandler::new(node.tx_broadcaster.clone(),
            Arc::new(LdkWallet::new(node.wallet.clone(), node.logger.clone())),
            node.keys_manager.clone(), node.logger.clone())),
        node.channel_manager.clone(), node.connection_manager.clone(), node.output_sweeper.clone(),
        node.network_graph.clone(), None, node.payment_store.clone(), node.peer_store.clone(),
        None, node.onion_messenger.clone(), None, node.runtime.clone(), node.logger.clone(), node.config.clone(),
    )
}

fn register(node: &crate::Node, gross: Option<u64>, cap: u64) -> (PaymentHash, PaymentPurpose) {
    // Same amount-free inbound registration used by lsps2_create_jit_invoice.
    let (hash, secret) = node.channel_manager.create_inbound_payment(None, 120, None).unwrap();
    let preimage = node.channel_manager.get_payment_preimage(hash, secret).unwrap();
    insert(node, hash, secret, preimage, gross, cap);
    (hash, PaymentPurpose::Bolt11InvoicePayment { payment_preimage: Some(preimage), payment_secret: secret })
}

fn insert(node: &crate::Node, hash: PaymentHash, secret: PaymentSecret, preimage: PaymentPreimage,
    gross: Option<u64>, cap: u64) {
    node.payment_store.insert(PaymentDetails::new(
        PaymentId(hash.0), PaymentKind::Bolt11Jit {
            hash, preimage: Some(preimage), secret: Some(secret), counterparty_skimmed_fee_msat: None,
            lsp_fee_limits: crate::payment::LSPFeeLimits {
                max_total_opening_fee_msat: Some(cap), max_proportional_opening_fee_ppm_msat: None,
            },
        }, gross, None, PaymentDirection::Inbound, PaymentStatus::Pending,
    )).unwrap();
}

fn claimable(hash: PaymentHash, purpose: PaymentPurpose, net: u64, skim: u64) -> LdkEvent {
    LdkEvent::PaymentClaimable {
        payment_hash: hash, purpose, amount_msat: net, counterparty_skimmed_fee_msat: skim,
        receiver_node_id: None, receiving_channel_ids: vec![], claim_deadline: None,
        onion_fields: None, payment_id: Some(PaymentId(hash.0)),
    }
}

fn reached_claim(log: &ClaimLog) -> bool {
    log.0.lock().unwrap().iter().any(|s| s.starts_with("Received payment from payment hash"))
}

#[tokio::test]
async fn fixed_jit_rejects_underfunding_before_claim_and_preserves_terms() {
    let (_dir, builder, log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    let handler = handler(&node);
    for (net, skim, should_claim) in [
        (10_000, 0, false), (97_999, 2_000, false), (98_000, 2_000, true),
        (100_000, 0, true), (98_000, 2_001, false),
    ] {
        let (hash, purpose) = register(&node, Some(100_000), 2_000);
        log.0.lock().unwrap().clear();
        handler.handle_event(claimable(hash, purpose, net, skim)).await.unwrap();
        assert_eq!(reached_claim(&log), should_claim, "net={net}, skim={skim}");
        let stored = node.payment(&PaymentId(hash.0)).unwrap();
        assert_eq!(stored.amount_msat, Some(100_000), "claim decision must not replace gross with net");
        assert_eq!(stored.status, if should_claim { PaymentStatus::Pending } else { PaymentStatus::Failed });
        assert!(node.next_event().is_none(), "claimable is not a settled receipt");
    }
}

#[tokio::test]
async fn fixed_jit_minimum_survives_restart_and_failed_attempts() {
    let (_dir, builder, log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    let (hash, purpose) = register(&node, Some(100_000), 2_000);
    drop(node);
    let node = builder.build_with_fs_store().unwrap();
    let handler = handler(&node);
    for (net, should_claim) in [(10_000, false), (97_999, false), (98_000, true)] {
        log.0.lock().unwrap().clear();
        handler.handle_event(claimable(hash, purpose.clone(), net, 2_000)).await.unwrap();
        assert_eq!(reached_claim(&log), should_claim, "net={net}");
        assert_eq!(node.payment(&PaymentId(hash.0)).unwrap().amount_msat, Some(100_000));
    }
}

#[tokio::test]
async fn malformed_fixed_jit_terms_fail_closed_without_underflow() {
    let (_dir, builder, log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    let handler = handler(&node);
    for (gross, cap) in [(Some(0), 0), (Some(1_000), 1_001), (Some(1_000), 1_000), (None, 2_000)] {
        let (hash, purpose) = register(&node, gross, cap);
        log.0.lock().unwrap().clear();
        handler.handle_event(claimable(hash, purpose, 10_000, 0)).await.unwrap();
        assert!(!reached_claim(&log), "invalid fixed terms reached claim");
        assert_eq!(node.payment(&PaymentId(hash.0)).unwrap().status, PaymentStatus::Failed);
    }
}

#[tokio::test]
async fn settled_jit_replay_after_restart_keeps_net_fee_and_success() {
    let (_dir, builder, log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    // Fee larger than net catches any attempt to treat settled net as gross.
    let (hash, purpose) = register(&node, Some(100_000), 80_000);
    let receive = handler(&node);
    receive.handle_event(claimable(hash, purpose.clone(), 20_000, 80_000)).await.unwrap();
    receive.handle_event(LdkEvent::PaymentClaimed {
        payment_hash: hash, purpose: purpose.clone(), amount_msat: 20_000,
        receiver_node_id: None, htlcs: vec![], sender_intended_total_msat: Some(100_000),
        onion_fields: None, payment_id: Some(PaymentId(hash.0)),
    }).await.unwrap();
    drop(receive);
    drop(node);
    let node = builder.build_with_fs_store().unwrap();
    let receive = handler(&node);
    for _ in 0..2 {
        log.0.lock().unwrap().clear();
        receive.handle_event(claimable(hash, purpose.clone(), 20_000, 80_000)).await.unwrap();
        assert!(!reached_claim(&log), "settled funding must not claim again");
        let receipt = node.payment(&PaymentId(hash.0)).unwrap();
        assert_eq!(receipt.status, PaymentStatus::Succeeded);
        assert_eq!(receipt.amount_msat, Some(20_000));
        assert!(matches!(receipt.kind, PaymentKind::Bolt11Jit {
            counterparty_skimmed_fee_msat: Some(80_000), ..
        }));
    }
}

#[tokio::test]
async fn mpp_parts_wait_for_aggregate_and_partial_total_fails_the_jit_minimum() {
    use lightning::ln::functional_test_utils::*;
    use lightning::ln::channelmanager::RecipientOnionFields;
    use lightning::ln::msgs::BaseMessageHandler;
    use lightning::routing::router::{PaymentParameters, RouteParameters};

    // Four purely in-memory channel managers; no sockets or node.start(). Each
    // payment has two independent routes to the same receiver.
    let chanmon_cfgs = create_chanmon_cfgs(4);
    let cfgs = create_node_cfgs(4, &chanmon_cfgs);
    let managers = create_node_chanmgrs(4, &cfgs, &[None, None, None, None]);
    let nodes = create_network(4, &cfgs, &managers);
    let a = create_announced_chan_between_nodes(&nodes, 0, 1).0;
    let b = create_announced_chan_between_nodes(&nodes, 0, 2).0;
    let c = create_announced_chan_between_nodes(&nodes, 1, 3).0;
    let d = create_announced_chan_between_nodes(&nodes, 2, 3).0;
    let (_dir, builder, log) = setup();
    let node = builder.build_with_fs_store().unwrap();
    let handler = handler(&node);

    for (part, expected_claim) in [(49_000, Some(true)), (48_999, Some(false)), (99_000, None)] {
        let params = PaymentParameters::from_node_id(nodes[3].node.get_our_node_id(), TEST_FINAL_CLTV)
            .with_bolt11_features(nodes[3].node.bolt11_invoice_features()).unwrap();
        let mut route = get_route(&nodes[0], &RouteParameters::from_payment_params_and_value(params, part)).unwrap();
        route.paths.push(route.paths[0].clone());
        route.paths[0].hops[0].pubkey = nodes[1].node.get_our_node_id();
        route.paths[0].hops[0].short_channel_id = a.contents.short_channel_id;
        route.paths[0].hops[1].short_channel_id = c.contents.short_channel_id;
        route.paths[1].hops[0].pubkey = nodes[2].node.get_our_node_id();
        route.paths[1].hops[0].short_channel_id = b.contents.short_channel_id;
        route.paths[1].hops[1].short_channel_id = d.contents.short_channel_id;
        let (hash, secret) = nodes[3].node.create_inbound_payment(None, 7200, None).unwrap();
        let preimage = nodes[3].node.get_payment_preimage(hash, secret).unwrap();
        insert(&node, hash, secret, preimage, Some(100_000), 2_000);
        nodes[0].node.send_payment_with_route(route, hash,
            RecipientOnionFields::secret_only(secret), PaymentId(hash.0)).unwrap();
        check_added_monitors(&nodes[0], 2);
        let mut messages = nodes[0].node.get_and_clear_pending_msg_events();
        let first = remove_first_msg_event_to_node(&nodes[1].node.get_our_node_id(), &mut messages);
        let event = pass_along_path(&nodes[0], &[&nodes[1], &nodes[3]], part * 2,
            hash, Some(secret), first, false, Some(preimage));
        assert!(event.is_none(), "one MPP part must not reach the claim policy");
        assert_eq!(node.payment(&PaymentId(hash.0)).unwrap().status, PaymentStatus::Pending);

        let Some(expected_claim) = expected_claim else {
            // Even a shard above the approved 98,000 minimum cannot be claimed
            // while the declared MPP total is incomplete. Withhold part two,
            // advance the pinned LDK MPP timeout, and observe a fail (no fulfill).
            for _ in 0..3 { nodes[3].node.timer_tick_occurred(); }
            expect_and_process_pending_htlcs_and_htlc_handling_failed(&nodes[3], &[
                lightning::events::HTLCHandlingFailureType::Receive { payment_hash: hash }
            ]);
            let failures = nodes[3].node.get_and_clear_pending_msg_events();
            assert_eq!(failures.len(), 1);
            assert!(matches!(&failures[0], lightning::ln::msgs::MessageSendEvent::UpdateHTLCs { updates, .. }
                if updates.update_fail_htlcs.len() == 1 && updates.update_fulfill_htlcs.is_empty()));
            check_added_monitors(&nodes[3], 1);
            assert_eq!(node.payment(&PaymentId(hash.0)).unwrap().status, PaymentStatus::Pending);
            continue;
        };

        let second = remove_first_msg_event_to_node(&nodes[2].node.get_our_node_id(), &mut messages);
        let aggregate = pass_along_path(&nodes[0], &[&nodes[2], &nodes[3]], part * 2,
            hash, Some(secret), second, true, Some(preimage)).unwrap();
        assert!(matches!(&aggregate, LdkEvent::PaymentClaimable { amount_msat, receiving_channel_ids, .. }
            if *amount_msat == part * 2 && receiving_channel_ids.len() == 2));
        log.0.lock().unwrap().clear();
        handler.handle_event(aggregate).await.unwrap();
        assert_eq!(reached_claim(&log), expected_claim);
        assert_eq!(node.payment(&PaymentId(hash.0)).unwrap().status,
            if expected_claim { PaymentStatus::Pending } else { PaymentStatus::Failed });
    }
}
