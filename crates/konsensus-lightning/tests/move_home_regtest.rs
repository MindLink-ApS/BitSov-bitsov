//! Run with BITCOIND_EXE=/path/to/bitcoind cargo test -p konsensus-lightning
//! --test move_home_regtest -- --ignored --nocapture
//! No auto-downloads. This test is compiled in the ordinary test suite.
use bitcoin::Network;
use konsensus_lightning::move_home::{Backend, Job, LdkBackend, Plan, Progress, JOURNAL_FILE};
use serde_json::{json, Value};
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Core {
    process: Child,
    url: String,
    port: u16,
    _dir: tempfile::TempDir,
}
impl Drop for Core {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
impl Core {
    async fn start() -> Self {
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
        let core = Self {
            process,
            url: format!("http://127.0.0.1:{port}"),
            port,
            _dir: dir,
        };
        for _ in 0..100 {
            if core.try_rpc("getblockchaininfo", json!([])).await.is_some() {
                core.rpc("createwallet", json!(["migration"])).await;
                return core;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("bitcoind startup timeout");
    }
    async fn try_rpc(&self, method: &str, params: Value) -> Option<Value> {
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
    async fn rpc(&self, method: &str, params: Value) -> Value {
        self.try_rpc(method, params)
            .await
            .unwrap_or_else(|| panic!("RPC {method} failed"))
    }
    async fn mine(&self, n: u32, nodes: &[&ldk_node::Node]) {
        let address = self.rpc("getnewaddress", json!([])).await;
        self.rpc("generatetoaddress", json!([n, address])).await;
        for node in nodes {
            tokio::task::block_in_place(|| node.sync_wallets()).unwrap();
            drain_events(node);
        }
    }
}
fn drain_events(node: &ldk_node::Node) {
    while node.next_event().is_some() {
        node.event_handled().unwrap();
    }
}
fn node(core: &Core, path: &Path, seed: [u8; 64], listen: u16) -> ldk_node::Node {
    let mut builder = ldk_node::Builder::from_config(ldk_node::config::Config {
        cooperative_close_only: true,
        ..Default::default()
    });
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires a local bitcoind binary; closes real regtest channels"]
async fn close_current_channel_restart_and_send_only_home() {
    let core = Core::start().await;
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a_port = port();
    let b_port = port();
    let mut a = node(&core, a_dir.path(), [1; 64], a_port);
    let mut b = node(&core, b_dir.path(), [2; 64], b_port);
    assert_eq!(
        a.node_id().to_string(),
        konsensus_lightning::move_home::node_id_from_seed(&[1; 64]).unwrap()
    );
    core.mine(101, &[&a, &b]).await;
    let funding = a.onchain_payment().new_address().unwrap();
    core.rpc("sendtoaddress", json!([funding.to_string(), 0.02]))
        .await;
    core.mine(6, &[&a, &b]).await;
    a.open_channel(
        b.node_id(),
        format!("127.0.0.1:{b_port}").parse().unwrap(),
        500_000,
        None,
        None,
    )
    .unwrap();
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.mine(1, &[&a, &b]).await;
        if a.list_channels().iter().any(|c| c.is_channel_ready) {
            break;
        }
    }
    assert!(a.list_channels().iter().any(|c| c.is_channel_ready));
    // A snapshot exists, then state advances. The lock must refuse before
    // booting a historical LDK node or producing a revoked commitment.
    let scb = a_dir.path().join("snapshot");
    konsensus_lightning::scb_export::write_monitor_store_scb(a_dir.path(), &scb).unwrap();
    let description = ldk_node::lightning_invoice::Bolt11InvoiceDescription::Direct(
        ldk_node::lightning_invoice::Description::new("advance state".into()).unwrap(),
    );
    let invoice = b
        .bolt11_payment()
        .receive(10_000, &description, 3600)
        .unwrap();
    a.bolt11_payment().send(&invoice, None).unwrap();
    for _ in 0..60 {
        drain_events(&a);
        drain_events(&b);
        if a.list_payments()
            .iter()
            .any(|p| p.status == ldk_node::payment::PaymentStatus::Succeeded)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(a
        .list_payments()
        .iter()
        .any(|p| p.status == ldk_node::payment::PaymentStatus::Succeeded));
    let restore_dir = a_dir.path().join("forbidden-restore");
    let before = core.rpc("getrawmempool", json!([])).await;
    let blocked = konsensus_lightning::decrypt_and_load_scb_backup(
        &std::fs::read(scb).unwrap(),
        &[0; 32],
        [1; 64],
        &restore_dir,
        "regtest",
        "http://127.0.0.1:1",
    );
    assert!(blocked.err().unwrap().to_string().contains("disabled"));
    assert!(!restore_dir.exists());
    assert_eq!(before, core.rpc("getrawmempool", json!([])).await);

    let destination = core
        .rpc("getnewaddress", json!([]))
        .await
        .as_str()
        .unwrap()
        .to_owned();
    let plan = Plan::new(a.node_id().to_string(), "regtest", &destination, 2).unwrap();
    let journal = a_dir.path().join(JOURNAL_FILE);
    let mut job = Job::begin(&journal, plan.clone()).unwrap();
    b.stop().unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    job.advance(&mut LdkBackend { node: &a }).unwrap();
    assert!(a
        .list_peers()
        .iter()
        .any(|p| p.node_id == b.node_id() && p.is_persisted));
    drop(job);
    a.stop().unwrap();
    drop(a);
    drop(b);
    a = node(&core, a_dir.path(), [1; 64], a_port);
    b = node(&core, b_dir.path(), [2; 64], b_port);
    job = Job::load(&journal, &plan).unwrap().unwrap();

    let mut restarted = false;
    let mut swept = false;
    let mut completed = false;
    for _ in 0..100 {
        let mut backend = LdkBackend { node: &a };
        match job.advance(&mut backend).unwrap() {
            Progress::SweepPreview(sweep) => {
                assert!(backend.snapshot().unwrap().channels.is_empty());
                let tx = sweep.tx().unwrap();
                assert_eq!(tx.output.len(), 1);
                assert_eq!(
                    tx.output[0].script_pubkey,
                    plan.address().unwrap().script_pubkey()
                );
                job.approve_sweep(&sweep, &backend).unwrap();
                // Crash point: consent durable, broadcast hasn't happened.
                drop(job);
                a.stop().unwrap();
                drop(a);
                a = node(&core, a_dir.path(), [1; 64], a_port);
                job = Job::load(&journal, &plan).unwrap().unwrap();
                restarted = true;
                swept = true;
            }
            Progress::Confirming { .. } | Progress::Waiting { .. } => {}
            Progress::Complete => {
                completed = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        core.mine(1, &[&a, &b]).await;
    }
    assert!(restarted && swept && completed);
    let received = core
        .rpc("getreceivedbyaddress", json!([destination, 6]))
        .await;
    assert!(received.as_f64().unwrap() > 0.0);
    assert!(a.list_channels().is_empty());
    a.stop().unwrap();
    b.stop().unwrap();
}
