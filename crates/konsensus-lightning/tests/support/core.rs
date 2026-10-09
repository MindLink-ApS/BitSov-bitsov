use bitcoin::Network;
use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

pub struct Core {
    process: Child,
    fee_proxy: Option<tokio::task::JoinHandle<()>>,
    pub url: String,
    pub port: u16,
    _dir: tempfile::TempDir,
}
impl Drop for Core {
    fn drop(&mut self) {
        if let Some(proxy) = &self.fee_proxy {
            proxy.abort();
        }
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
pub fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
impl Core {
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let port = port();
        let process =
            Command::new(std::env::var("BITCOIND_EXE").unwrap_or_else(|_| "bitcoind".into()))
                .args([
                    "-regtest",
                    "-server",
                    "-listen=0",
                    "-txindex=1",
                    "-fallbackfee=0.00002",
                    "-rpcuser=migration-test",
                    "-rpcpassword=migration-test",
                ])
                .arg(format!("-datadir={}", dir.path().display()))
                .arg(format!("-rpcport={port}"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("requires bitcoind");
        let mut core = Self {
            process,
            fee_proxy: None,
            url: format!("http://127.0.0.1:{port}"),
            port,
            _dir: dir,
        };
        for _ in 0..100 {
            if core.try_rpc("getblockchaininfo", json!([])).await.is_some() {
                core.rpc("createwallet", json!(["migration"])).await;
                // An empty regtest chain has no statistical fee estimator.
                // Supply only that missing fixture datum (2 sat/vB); every
                // block, transaction, funding operation and broadcast uses Core.
                // The production LSPS2 freshness/capital gates remain enabled.
                let upstream = core.url.clone();
                let client = reqwest::Client::new();
                let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
                    let upstream = upstream.clone();
                    let client = client.clone();
                    async move {
                        if body["method"] == "estimatesmartfee" {
                            return axum::Json(json!({"result":{"feerate":0.00002,"blocks":body["params"][0]},"error":null,"id":body["id"]}));
                        }
                        axum::Json(client.post(upstream).basic_auth("migration-test", Some("migration-test")).json(&body).send().await.unwrap().json::<Value>().await.unwrap())
                    }
                }));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                core.port = listener.local_addr().unwrap().port();
                core.fee_proxy = Some(tokio::spawn(async move {
                    axum::serve(listener, app).await.unwrap();
                }));
                return core;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("bitcoind startup timeout");
    }
    pub async fn try_rpc(&self, method: &str, params: Value) -> Option<Value> {
        let result: Value = reqwest::Client::new()
            .post(&self.url)
            .basic_auth("migration-test", Some("migration-test"))
            .json(&json!({"jsonrpc":"1.0", "id":1, "method":method, "params":params}))
            .send()
            .await
            .ok()?
            .json()
            .await
            .ok()?;
        result["error"].is_null().then(|| result["result"].clone())
    }
    pub async fn rpc(&self, method: &str, params: Value) -> Value {
        self.try_rpc(method, params)
            .await
            .unwrap_or_else(|| panic!("RPC {method} failed"))
    }
    pub async fn mine(&self, n: u32, nodes: &[&ldk_node::Node]) {
        let address = self.rpc("getnewaddress", json!([])).await;
        self.rpc("generatetoaddress", json!([n, address])).await;
        for node in nodes {
            tokio::task::block_in_place(|| node.sync_wallets()).unwrap();
            drain_events(node);
        }
    }
}
pub fn drain_events(node: &ldk_node::Node) {
    while node.next_event().is_some() {
        node.event_handled().unwrap();
    }
}
pub fn node(core: &Core, path: &Path, seed: [u8; 64], listen: u16) -> ldk_node::Node {
    let mut builder = ldk_node::Builder::from_config(ldk_node::config::Config {
        cooperative_close_only: true,
        accept_forwards_to_priv_channels: true,
        ..Default::default()
    });
    if seed == [1; 64] {
        let service = konsensus_lightning::lsps2_service::Lsps2ServiceConfig {
            enabled: true,
            require_token: Some("recover-test".into()),
            ..Default::default()
        }
        .to_ldk(false)
        .unwrap()
        .unwrap();
        builder.set_liquidity_provider_lsps2(service);
    }
    builder.set_network(Network::Regtest);
    builder.set_entropy_seed_bytes(seed);
    builder.set_storage_dir_path(path.to_str().unwrap().to_owned());
    builder.set_chain_source_bitcoind_rpc(
        "127.0.0.1".into(),
        core.port,
        "migration-test".into(),
        "migration-test".into(),
    );
    builder.set_gossip_source_p2p();
    builder
        .set_listening_addresses(vec![format!("127.0.0.1:{listen}").parse().unwrap()])
        .unwrap();
    let node = builder.build().unwrap();
    node.start().unwrap();
    node
}
