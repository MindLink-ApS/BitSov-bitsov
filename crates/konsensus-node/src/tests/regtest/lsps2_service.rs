//! Production hub/client interoperability: JIT funding is never admission.
use super::super::*;
use konsensus_lightning::liquidity::{LiquidityConfig, LspConfig};
use konsensus_lightning::lsps2_service::Lsps2ServiceConfig;

// Fresh regtest chains have no fee-estimation history. Supply an explicit
// deterministic estimator response; every wallet/chain/broadcast request still
// goes to the real electrs/Core fixture. Production must reject missing estimates.
struct FeeSource(tokio::task::JoinHandle<()>);
impl Drop for FeeSource {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn fee_source(upstream: String) -> (String, FeeSource) {
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let router = axum::Router::new()
        .route(
            "/fee-estimates",
            axum::routing::get(|| async {
                axum::Json(serde_json::json!({"6": 3.0, "12": 2.0, "144": 1.0}))
            }),
        )
        .route(
            "/*path",
            axum::routing::any(
                move |axum::extract::Path(path): axum::extract::Path<String>,
                      method: axum::http::Method,
                      body: axum::body::Bytes| {
                    let client = client.clone();
                    let url = format!("{upstream}/{path}");
                    async move {
                        let response = client.request(method, url).body(body).send().await.unwrap();
                        (response.status(), response.bytes().await.unwrap())
                    }
                },
            ),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (url, FeeSource(task))
}

// Option A Phase 0 uses the production provider selection and push plumbing.
// Only the hub is funded. In particular, do not use confirm_channel here:
// mining after open would hide a regression in zero-conf acceptance.
struct StarterChannel {
    hub: LdkProvider,
    client: LdkProvider,
    chain: infra::Chain,
    _fees: FeeSource,
    dirs: [tempfile::TempDir; 2],
    height_before_open: u64,
}

impl StarterChannel {
    async fn new(trust_no_reserve: bool, hub_selected: bool) -> Self {
        let chain = infra::Chain::start().await;
        let dirs = [(); 2].map(|_| tempfile::tempdir().unwrap());
        let (fee_url, fees) = fee_source(chain.url.clone()).await;
        let hub_config = infra::lightning_config(dirs[0].path(), &fee_url);
        let hub_addr = hub_config.listening_address.clone().unwrap();
        let hub = LdkProvider::new(hub_config).await.unwrap();
        chain.fund(hub.node()).await;

        let hub_id = hub.node().node_id().to_string();
        let mut client_config = infra::lightning_config(dirs[1].path(), &fee_url);
        // The client cannot accept an inbound TCP connection at any address.
        client_config.listening_address = None;
        let other_id = ldk_node::bitcoin::secp256k1::PublicKey::from_secret_key(
            &ldk_node::bitcoin::secp256k1::Secp256k1::new(),
            &ldk_node::bitcoin::secp256k1::SecretKey::from_slice(&[42; 32]).unwrap(),
        )
        .to_string();
        client_config.liquidity = LiquidityConfig {
            enabled: true,
            selected_provider: Some(if hub_selected {
                hub_id.clone()
            } else {
                other_id.clone()
            }),
            providers: vec![
                LspConfig {
                    node_id: hub_id,
                    address: hub_addr.clone(),
                    token: None,
                    trust_no_reserve,
                },
                // A configured opt-in on a NON-selected provider must not waive
                // its reserve. No connection to this dummy provider is needed.
                LspConfig {
                    node_id: other_id,
                    address: "127.0.0.1:0".into(),
                    token: None,
                    trust_no_reserve: true,
                },
            ],
        };
        let client = LdkProvider::new(client_config).await.unwrap();
        client.node().sync_wallets().unwrap();
        assert_eq!(client.node().list_balances().total_onchain_balance_sats, 0);
        assert!(client.node().list_channels().is_empty());
        assert!(client.node().config().listening_addresses.is_none());

        // Establish that the supplied address cannot connect before the
        // client initiates. lib.rs::open_channel_inner calls
        // connection.rs::connect_peer_if_necessary, whose connected-peer check
        // must return BEFORE attempting this same bogus address again.
        assert_eq!(
            hub.node().connect(
                client.node().node_id(),
                "127.0.0.1:0".parse().unwrap(),
                false,
            ),
            Err(ldk_node::NodeError::ConnectionFailed),
        );
        client
            .node()
            .connect(hub.node().node_id(), hub_addr.parse().unwrap(), false)
            .unwrap();
        wait("client-initiated LN connection on both ends", || async {
            [(hub.node(), client.node()), (client.node(), hub.node())]
                .iter()
                .all(|(node, peer)| {
                    node.list_peers()
                        .iter()
                        .any(|p| p.node_id == peer.node_id() && p.is_connected)
                })
        })
        .await;
        let height_before_open = chain.bitcoin.client.call("getblockcount", &[]).unwrap();
        Self {
            hub,
            client,
            chain,
            _fees: fees,
            dirs,
            height_before_open,
        }
    }

    async fn open(
        &self,
        amount_sats: u64,
    ) -> Result<
        konsensus_core::traits::lightning::ChannelOpenResult,
        konsensus_core::traits::lightning::LightningError,
    > {
        use konsensus_core::traits::lightning::{FundingOptions, FundingPriority};
        tokio::time::timeout(
            Duration::from_secs(60),
            self.hub.open_channel_with_funding(
                &self.client.node().node_id().to_string(),
                "127.0.0.1:0",
                amount_sats,
                false,
                FundingOptions {
                    priority: FundingPriority::Economy,
                    max_funding_fee_sats: Some(2_000),
                },
                Some(10_000_000),
            ),
        )
        .await
        .expect("starter open must finish without dialing the client")
    }

    fn assert_no_blocks_or_client_funds(&self) {
        let height: u64 = self
            .chain
            .bitcoin
            .client
            .call("getblockcount", &[])
            .unwrap();
        assert_eq!(
            height, self.height_before_open,
            "no blocks mined after open"
        );
        assert_eq!(
            self.client
                .node()
                .list_balances()
                .total_onchain_balance_sats,
            0
        );
    }

    async fn rejected(self, amount_sats: u64, marker: &str) {
        let outcome = self.open(amount_sats).await;
        let log_path = self.dirs[1].path().join("ldk/ldk_node.log");
        let expected = format!(
            "Rejecting inbound Anchor channel from peer {} due to insufficient available on-chain reserves. Available: 0/25000sats",
            self.hub.node().node_id()
        );
        wait("explicit client anchor-reserve rejection", || async {
            std::fs::read_to_string(&log_path)
                .unwrap()
                .contains(&expected)
        })
        .await;
        println!("PHASE0 OBSERVED {marker}: anchor offer rejected for reserve 0/25000");
        // A refused anchor offer alone is insufficient: LDK may retry with a
        // non-anchor type. Such an accepted/funded fallback must fail this test.
        let error = outcome.expect_err("reserve refusal must not become a funded fallback channel");
        wait("rejected channel removed on both ends", || async {
            self.hub.node().list_channels().is_empty()
                && self.client.node().list_channels().is_empty()
        })
        .await;
        let mempool: Vec<String> = self
            .chain
            .bitcoin
            .client
            .call("getrawmempool", &[])
            .unwrap();
        assert!(mempool.is_empty(), "rejection must not broadcast funding");
        self.assert_no_blocks_or_client_funds();
        println!("PHASE0 PASS {marker}: {amount_sats} sat, anchor reserve 0/25000; {error}");
        self.client.shutdown().await.unwrap();
        self.hub.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn phase0_push_zero_conf_connection_reuse_and_payment() {
    let fixture = StarterChannel::new(true, true).await;
    let opened = fixture.open(100_000).await.unwrap();
    let txid = opened.funding_txid.expect("real funding transaction");
    wait(
        "starter channel usable at both endpoints without mining",
        || async {
            fixture.client.node().sync_wallets().unwrap();
            [fixture.hub.node(), fixture.client.node()]
                .iter()
                .all(|node| {
                    let channels = node.list_channels();
                    channels.len() == 1 && channels[0].is_usable
                })
        },
    )
    .await;
    for node in [fixture.hub.node(), fixture.client.node()] {
        let channels = node.list_channels();
        let channel = &channels[0];
        assert_eq!(channel.channel_value_sats, 100_000);
        assert!(!channel.is_announced);
        assert!(channel.is_channel_ready && channel.is_usable);
        assert_eq!(channel.confirmations_required, Some(0));
        assert_eq!(channel.confirmations.unwrap_or(0), 0);
        assert_eq!(channel.funding_txo.unwrap().txid.to_string(), txid);
    }
    let before = capacity(fixture.client.node());
    // The push is exactly 10k sats. Spendable outbound excludes the negotiated
    // punishment reserve (normally 1% = 1k sats); it is not an on-chain top-up.
    let client_channel = fixture.client.node().list_channels().remove(0);
    assert!(!client_channel.is_outbound);
    assert!(
        (9_000_000..=10_000_000).contains(&before),
        "outbound: {before} msat"
    );
    assert_eq!(
        before + client_channel.unspendable_punishment_reserve.unwrap() * 1_000,
        10_000_000,
    );
    let mempool: Vec<String> = fixture
        .chain
        .bitcoin
        .client
        .call("getrawmempool", &[])
        .unwrap();
    assert_eq!(mempool, vec![txid.clone()]);
    fixture.assert_no_blocks_or_client_funds();
    println!("PHASE0 PASS push-zero-conf: 100000 sat / 10000 sat push, outbound {before} msat, empty wallet, funding in mempool");
    println!("PHASE0 PASS connect-reuse: client has no listener; hub opens over client's connection with 127.0.0.1:0");

    let invoice = fixture
        .hub
        .create_invoice(1_000_000, "Phase 0 pushed balance", 600)
        .await
        .unwrap();
    fixture
        .client
        .pay_invoice_with_fee_limit(&invoice.bolt11, 0)
        .await
        .unwrap();
    settle(&fixture.client, &invoice.payment_hash).await;
    settle(&fixture.hub, &invoice.payment_hash).await;
    let payment = fixture
        .client
        .get_payment_status(&invoice.payment_hash)
        .await
        .unwrap();
    assert_eq!(payment.amount_msat, 1_000_000);
    assert_eq!(payment.fee_msat, Some(0));
    wait("starter payment deducted from pushed balance", || async {
        capacity(fixture.client.node()) == before - 1_000_000
    })
    .await;
    fixture.assert_no_blocks_or_client_funds();
    let mempool: Vec<String> = fixture
        .chain
        .bitcoin
        .client
        .call("getrawmempool", &[])
        .unwrap();
    assert_eq!(mempool, vec![txid]);
    println!("PHASE0 PASS spend-push: client paid hub 1000000 msat, zero fee, both settled before confirmation");
    fixture.client.shutdown().await.unwrap();
    fixture.hub.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn phase0_reject_without_reserve_opt_in() {
    StarterChannel::new(false, true)
        .await
        .rejected(100_000, "reject-opt-out")
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn phase0_reject_non_selected_provider() {
    StarterChannel::new(true, false)
        .await
        .rejected(100_000, "reject-non-selected")
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/regtest_e2e.sh"]
async fn phase0_reject_above_reserve_waiver_cap() {
    StarterChannel::new(true, true)
        .await
        .rejected(200_001, "reject-above-cap")
        .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local Bitcoin Core and electrs; scripts/regress/three_node_paid_e2e.sh"]
async fn hub_jit_then_stateless_admission() {
    let chain = infra::Chain::start().await;
    let dirs = [(); 3].map(|_| tempfile::tempdir().unwrap());
    let (fee_url, _fee_source) = fee_source(chain.url.clone()).await;
    let mut hub_config = infra::lightning_config(dirs[0].path(), &fee_url);
    hub_config.lsps2_service = Lsps2ServiceConfig {
        enabled: true,
        require_token: Some("regtest-private-pilot".into()),
        funding_priority: konsensus_core::traits::lightning::FundingPriority::Economy,
        max_funding_fee_sats: 2000,
        max_concurrent_jit_opens: 1,
        max_jit_capital_sats: 250000,
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
            trust_no_reserve: false,
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
    for node in [client.node(), sponsor.node()] {
        // The client's on-chain funds preserve the anchor reserve; they do not
        // create a channel or substitute for the sponsor's Lightning top-up.
        chain.fund(node).await;
        assert!(node.config().node_alias.is_none());
    }
    // Fund only the hub's inbound anchor reserve at first. JIT must fail
    // without dropping its held payment, then recover once wallet funds arrive.
    let hub_funding_addr = hub.node().onchain_payment().new_address().unwrap();
    let _: serde_json::Value = chain
        .bitcoin
        .client
        .call(
            "sendtoaddress",
            &[
                serde_json::json!(hub_funding_addr.to_string()),
                serde_json::json!(0.0005),
            ],
        )
        .unwrap();
    chain.mine(&[hub.node()], 6).await;
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
        wait("durable insufficient-funds open failure", || async {
            hub.node().lsps2_service_metrics().failed_opens > 0
        })
        .await;
        let pending = hub.node().lsps2_service_metrics();
        assert_eq!(pending.pending_opens, 1);
        assert_eq!(pending.opens, 0);
        assert_eq!(pending.opening_fees_earned_msat, 0);
        assert!(pending.capital_locked_sats <= 250000);
        let _: serde_json::Value = chain
            .bitcoin
            .client
            .call(
                "sendtoaddress",
                &[
                    serde_json::json!(hub_funding_addr.to_string()),
                    serde_json::json!(0.03),
                ],
            )
            .unwrap();
        chain.mine(&[hub.node()], 1).await;
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
    .unwrap_or_else(|error| {
        eprintln!(
            "hub JIT metrics at timeout: {:?}",
            hub.node().lsps2_service_metrics()
        );
        fn dump_logs(path: &std::path::Path) {
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        dump_logs(&entry.path());
                    } else if entry.file_name().to_string_lossy().contains("log") {
                        if let Ok(log) = std::fs::read_to_string(entry.path()) {
                            eprintln!("{}: {}", entry.path().display(), log);
                        }
                    }
                }
            }
        }
        dump_logs(dirs[0].path());
        panic!("JIT quote/open/settlement must complete within 60 seconds: {error}");
    });
    wait("hub earned skim metrics", || async {
        hub.node().lsps2_service_metrics().opening_fees_earned_msat == 1000000
    })
    .await;
    let hub_metrics = hub.node().lsps2_service_metrics();
    assert_eq!(hub_metrics.opens, 1);
    assert_eq!(hub_metrics.pending_opens, 0);
    assert!(hub_metrics.failed_opens >= 1 && hub_metrics.open_retries >= 1);
    assert_eq!(hub_metrics.capital_locked_sats, 225000); // 198k channel + 25k reserve + 2k fee cap
    let funding_outpoint = hub
        .node()
        .list_channels()
        .into_iter()
        .find(|c| c.counterparty_node_id == client.node().node_id())
        .unwrap()
        .funding_txo
        .unwrap();
    let entry: serde_json::Value = chain
        .bitcoin
        .client
        .call(
            "getmempoolentry",
            &[serde_json::json!(funding_outpoint.txid.to_string())],
        )
        .unwrap();
    let fee_sats = (entry["fees"]["base"].as_f64().unwrap() * 100_000_000.0).round() as u64;
    assert!(
        fee_sats > 0 && fee_sats <= 2000,
        "JIT funding exceeds owner's absolute cap: {fee_sats}"
    );
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
    let channel_id = client.node().list_channels().pop().unwrap().channel_id;
    // PaymentClaimed can persist the receipt before the peer's revoke_and_ack
    // credits the client's spendable balance. Sponsor settlement and hub skim
    // metrics also follow the preimage, not this channel's commitment update.
    let channel = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            if let Some(channel) = client.node().list_channels().into_iter().find(|c| {
                c.channel_id == channel_id
                    && c.outbound_capacity_msat > 90_000_000
                    && c.inbound_capacity_msat > 90_000_000
            }) {
                return channel;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        // ChannelDetails includes outbound/inbound capacity and the punishment
        // reserve; BalanceDetails includes claimable balances and anchor reserve.
        panic!(
            "JIT channel {channel_id:?} capacities must both exceed 90_000_000 msat within 60s \
             after payment {} settled; client channels={:#?}; client balances={:#?}; \
             hub channels={:#?}",
            funding.payment_hash,
            client.node().list_channels(),
            client.node().list_balances(),
            hub.node().list_channels(),
        );
    });
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

    let restored = hub.node().lsps2_service_metrics();
    assert_eq!(restored.opens, hub_metrics.opens);
    assert_eq!(
        restored.opening_fees_earned_msat,
        hub_metrics.opening_fees_earned_msat
    );
    assert_eq!(
        restored.capital_locked_sats,
        hub_metrics.capital_locked_sats
    );
    assert_eq!(restored.failed_opens, hub_metrics.failed_opens);
    assert_eq!(restored.open_retries, hub_metrics.open_retries);

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
    assert_eq!(
        hub.node().lsps2_service_metrics().opening_fees_earned_msat,
        1000000,
        "ordinary admission must not add any opening skim revenue"
    );
    client.shutdown().await.unwrap();
    sponsor.shutdown().await.unwrap();
    hub.shutdown().await.unwrap();
    println!("PASS hub LSPS2 JIT: bounded funding, disconnect/restart, stateless admission, positive capped tariff");
}
