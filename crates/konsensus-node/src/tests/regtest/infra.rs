//! Reuses corepc-node from the existing LDK harness; no download features.
use super::*;
use std::process::{Child, Command, Stdio};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct Chain {
    _electrs: Process,
    pub bitcoin: corepc_node::Node,
    pub url: String,
    pub api_url: String,
    api_task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
}

impl Drop for Chain {
    fn drop(&mut self) {
        self.api_task.abort();
        let _ = self._electrs.0.kill();
        let _ = self._electrs.0.wait();
        let _ = self.bitcoin.stop();
    }
}

pub fn loopback() -> String {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .to_string()
}

impl Chain {
    pub async fn start() -> Self {
        let mut conf = corepc_node::Conf::default();
        // Raw JSON avoids the harness versioned wallet response schema.
        conf.wallet = None;
        conf.network = "regtest";
        conf.p2p = corepc_node::P2P::No;
        conf.args = vec![
            "-regtest",
            "-fallbackfee=0.0001",
            "-networkactive=0",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-dnsseed=0",
            "-discover=0",
            "-txindex=1",
        ];
        let bitcoin = corepc_node::Node::with_conf(
            std::env::var("BITCOIND_EXE").expect("BITCOIND_EXE"),
            &conf,
        )
        .unwrap();
        let _: Value = bitcoin
            .client
            .call("createwallet", &[json!("regtest")])
            .expect("create regtest wallet");
        let dir = tempfile::tempdir().unwrap();
        let address: Value = bitcoin.client.call("getnewaddress", &[]).unwrap();
        let _: Value = bitcoin
            .client
            .call("generatetoaddress", &[json!(101), address])
            .unwrap();
        let http = loopback();
        let cookie = std::fs::read_to_string(&bitcoin.params.cookie_file).unwrap();
        let log = std::fs::File::create(dir.path().join("electrs.log")).unwrap();
        let child = Command::new(std::env::var("ELECTRS_EXE").expect("ELECTRS_EXE"))
            .args([
                "--network",
                "regtest",
                "--jsonrpc-import",
                "--daemon-rpc-addr",
                &bitcoin.params.rpc_socket.to_string(),
                "--cookie",
                cookie.trim(),
                "--db-dir",
                dir.path().to_str().unwrap(),
                "--electrum-rpc-addr",
                &loopback(),
                "--monitoring-addr",
                &loopback(),
                "--http-addr",
                &http,
            ])
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        let child = Process(child);
        // Application EsploraProvider uses /api, while LDK and this electrs
        // expose root paths. Forward actual responses without fabricating data.
        let url = format!("http://{http}");
        let upstream = url.clone();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let router = axum::Router::new().route(
            "/api/*path",
            axum::routing::get(
                move |axum::extract::Path(path): axum::extract::Path<String>| {
                    let upstream = upstream.clone();
                    let client = client.clone();
                    async move {
                        let response = client
                            .get(format!("{upstream}/{path}"))
                            .send()
                            .await
                            .unwrap();
                        (response.status(), response.bytes().await.unwrap())
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let api_url = format!("http://{}", listener.local_addr().unwrap());
        let api_task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let chain = Self {
            _electrs: child,
            bitcoin,
            url,
            api_url,
            api_task,
            _dir: dir,
        };
        chain.indexed().await;
        chain
    }

    async fn indexed(&self) {
        let target: u64 = self.bitcoin.client.call("getblockcount", &[]).unwrap();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        wait("electrs index", || async {
            match client
                .get(format!("{}/blocks/tip/height", self.url))
                .send()
                .await
            {
                Ok(r) => r.text().await.ok().and_then(|s| s.parse::<u64>().ok()) == Some(target),
                Err(_) => false,
            }
        })
        .await;
    }

    pub async fn mine(&self, nodes: &[&ldk_node::Node], blocks: u64) {
        let addr: Value = self.bitcoin.client.call("getnewaddress", &[]).unwrap();
        let _: Value = self
            .bitcoin
            .client
            .call("generatetoaddress", &[json!(blocks), addr])
            .unwrap();
        self.indexed().await;
        for node in nodes {
            node.sync_wallets().unwrap();
        }
    }

    pub async fn fund(&self, node: &ldk_node::Node) {
        let addr = node.onchain_payment().new_address().unwrap();
        let _: Value = self
            .bitcoin
            .client
            .call("sendtoaddress", &[json!(addr.to_string()), json!(0.03)])
            .unwrap();
        self.mine(&[node], 6).await;
        assert_eq!(node.list_balances().total_onchain_balance_sats, 3_000_000);
    }

    /// #101: real LDK cannot bound a per-channel funding fee rate, so an
    /// explicit rate is refused before any peer connection or broadcast.
    pub async fn refuse_explicit_rate(&self, a: &LdkProvider, peer: &str, addr_b: &str) {
        let error = a
            .open_channel(peer, addr_b, 1_000_000, false, Some(3.0))
            .await
            .expect_err("explicit funding fee rate must be refused");
        assert!(
            matches!(
                &error,
                konsensus_core::traits::lightning::LightningError::PaymentNotDispatched(m)
                    if m.contains("per-channel funding fee rate")
            ),
            "{error}"
        );
        assert!(
            a.node().list_channels().is_empty(),
            "refusal opened a channel"
        );
        let mempool: Vec<String> = self.bitcoin.client.call("getrawmempool", &[]).unwrap();
        assert!(mempool.is_empty(), "refusal broadcast funding");
        println!("explicit 3 sat/vB refused before dispatch: {error}");
    }

    /// Waits for the just-opened a->b channel's funding transaction, reports
    /// its actual fee, confirms it and waits until both ends can use it.
    /// `synced` are the other nodes whose wallets follow the new blocks.
    pub async fn confirm_channel(
        &self,
        a: &ldk_node::Node,
        b: &ldk_node::Node,
        synced: &[&ldk_node::Node],
    ) -> u64 {
        wait("funding transaction in mempool", || async {
            let txs: Vec<String> = self.bitcoin.client.call("getrawmempool", &[]).unwrap();
            !txs.is_empty()
        })
        .await;
        let txs: Vec<String> = self.bitcoin.client.call("getrawmempool", &[]).unwrap();
        assert_eq!(txs.len(), 1);
        let entry: Value = self
            .bitcoin
            .client
            .call("getmempoolentry", &[json!(txs[0])])
            .unwrap();
        let fee = bitcoin::Amount::from_btc(entry["fees"]["base"].as_f64().unwrap())
            .unwrap()
            .to_sat();
        let vsize = entry["vsize"].as_u64().unwrap();
        println!("funding fee: {fee} sat, {vsize} vB (estimator)");
        let nodes: Vec<&ldk_node::Node> =
            [a, b].into_iter().chain(synced.iter().copied()).collect();
        self.mine(&nodes, 6).await;
        let (a_id, b_id) = (a.node_id(), b.node_id());
        wait("both channel endpoints usable", || async {
            a.list_channels()
                .iter()
                .any(|c| c.counterparty_node_id == b_id && c.is_usable)
                && b.list_channels()
                    .iter()
                    .any(|c| c.counterparty_node_id == a_id && c.is_usable)
        })
        .await;
        fee
    }
}

pub async fn lightning(dir: &std::path::Path, chain: &Chain) -> (Arc<LdkProvider>, String) {
    let config = lightning_config(dir, &chain.url);
    let addr = config.listening_address.clone().unwrap();
    let provider = LdkProvider::new(config).await.unwrap();
    (Arc::new(provider), addr)
}

pub fn lightning_config(dir: &std::path::Path, url: &str) -> konsensus_lightning::LdkConfig {
    let (mnemonic, _) = NodeIdentity::generate().unwrap();
    konsensus_lightning::LdkConfig {
        forward_to_private_channels: false,
        esplora_sync_intervals: Default::default(),
        logging: Default::default(),
        electrum: None,
        bitcoind: None,
        storage_dir: dir.join("ldk"),
        mnemonic,
        passphrase: None,
        network: "regtest".into(),
        esplora_url: url.to_owned(),
        esplora_url_fallback: None, credentials_file: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: Some(loopback()),
        liquidity: Default::default(),
        scb_backup_dir: None,
        scb_rotation_count: 2,
    }
}

/// Routing-only LDK node C, built directly on ldk-node: no app, no BitSov
/// wallet policy. Stock LDK refuses to forward into an unannounced channel
/// (`PrivateChannelForward`) unless it acts as an LSPS2 service, which is
/// exactly the role an LSP plays for a private BitSov node. No client ever
/// requests a JIT channel here; the service role only enables forwarding.
pub async fn router(dir: &std::path::Path, chain: &Chain) -> (Arc<ldk_node::Node>, String) {
    let addr = loopback();
    let mut seed = [0u8; 64];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut seed);
    let mut builder = ldk_node::Builder::new();
    builder
        .set_network(ldk_node::bitcoin::Network::Regtest)
        .set_storage_dir_path(dir.join("ldk").to_string_lossy().into_owned())
        .set_chain_source_esplora(chain.url.clone(), None)
        .set_entropy_seed_bytes(seed)
        .set_liquidity_provider_lsps2(ldk_node::liquidity::LSPS2ServiceConfig {
            require_token: Some("regtest-routing-only".into()),
            advertise_service: false,
            channel_opening_fee_ppm: 0,
            channel_over_provisioning_ppm: 0,
            min_channel_opening_fee_msat: 0,
            min_channel_lifetime: 144,
            max_client_to_self_delay: 1024,
            min_payment_size_msat: 0,
            max_payment_size_msat: 0,
            client_trusts_lsp: false,
        });
    builder
        .set_listening_addresses(vec![addr.parse().unwrap()])
        .unwrap();
    let node = Arc::new(builder.build().unwrap());
    node.start().unwrap();
    // ldk-node queues events until handled; drain them like any operator would.
    let events = Arc::clone(&node);
    tokio::spawn(async move {
        loop {
            let _ = events.next_event_async().await;
            if events.event_handled().is_err() {
                return;
            }
        }
    });
    (node, addr)
}
