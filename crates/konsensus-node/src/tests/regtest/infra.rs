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

    pub async fn mine(&self, nodes: &[&LdkProvider], blocks: u64) {
        let addr: Value = self.bitcoin.client.call("getnewaddress", &[]).unwrap();
        let _: Value = self
            .bitcoin
            .client
            .call("generatetoaddress", &[json!(blocks), addr])
            .unwrap();
        self.indexed().await;
        for node in nodes {
            node.node().sync_wallets().unwrap();
        }
    }

    pub async fn fund(&self, node: &LdkProvider) {
        let addr = node.node().onchain_payment().new_address().unwrap();
        let _: Value = self
            .bitcoin
            .client
            .call("sendtoaddress", &[json!(addr.to_string()), json!(0.03)])
            .unwrap();
        self.mine(&[node], 6).await;
        assert_eq!(
            node.node().list_balances().total_onchain_balance_sats,
            3_000_000
        );
    }

    pub async fn channel(&self, a: &LdkProvider, b: &LdkProvider, addr_b: &str) -> u64 {
        let result = a
            .open_channel(
                &b.get_node_pubkey().await.unwrap(),
                addr_b,
                1_000_000,
                false,
                Some(3.0),
            )
            .await;
        let explicit = result.is_ok();
        if let Err(error) = result {
            assert!(
                matches!(
                    error,
                    konsensus_core::traits::lightning::LightningError::PaymentNotDispatched(_)
                ),
                "{error}"
            );
            assert!(
                a.node().list_channels().is_empty(),
                "refusal opened a channel"
            );
            let mempool: Vec<String> = self.bitcoin.client.call("getrawmempool", &[]).unwrap();
            assert!(mempool.is_empty(), "refusal broadcast funding");
            assert_eq!(std::env::var("REGTEST_DIAGNOSTIC_ESTIMATED_FEE").as_deref(), Ok("1"),
                "REGTEST-E2E BLOCKED: explicit 3 sat/vB refused before dispatch: {error}. Set REGTEST_DIAGNOSTIC_ESTIMATED_FEE=1 ONLY to diagnose the remaining flow using the estimator.");
            println!(
                "DIAGNOSTIC ONLY: explicit 3 sat/vB refused: {error}; continuing with estimator"
            );
            a.open_channel(
                &b.get_node_pubkey().await.unwrap(),
                addr_b,
                1_000_000,
                false,
                None,
            )
            .await
            .unwrap();
        }
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
        if explicit {
            assert!(
                fee >= 3 * vsize && fee <= 3 * vsize + 3,
                "explicit 3 sat/vB: fee={fee}, vsize={vsize}"
            );
        }
        println!("funding fee: {fee} sat, {vsize} vB; explicit rate honored: {explicit}");
        self.mine(&[a, b], 6).await;
        wait("both channel endpoints usable", || async {
            [a, b]
                .iter()
                .all(|n| n.node().list_channels().iter().any(|c| c.is_usable))
        })
        .await;
        fee
    }
}

pub async fn lightning(dir: &std::path::Path, chain: &Chain) -> (Arc<LdkProvider>, String) {
    let addr = loopback();
    let (mnemonic, _) = NodeIdentity::generate().unwrap();
    let provider = LdkProvider::new(konsensus_lightning::LdkConfig {
        storage_dir: dir.join("ldk"),
        mnemonic,
        passphrase: None,
        network: "regtest".into(),
        esplora_url: chain.url.clone(),
        esplora_url_fallback: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: Some(addr.clone()),
        liquidity: Default::default(),
        scb_backup_dir: None,
        scb_rotation_count: 2,
    })
    .await
    .unwrap();
    (Arc::new(provider), addr)
}
