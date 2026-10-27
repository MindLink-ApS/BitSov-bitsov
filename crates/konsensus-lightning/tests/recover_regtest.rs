//! BITCOIND_EXE=/path/to/bitcoind cargo test -p konsensus-lightning --test recover_regtest -- --ignored --nocapture
//! No downloads. A stale store is never passed to a running LDK builder.
#[path = "support/core.rs"]
mod core;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{bip32::Xpriv, Network, OutPoint, Transaction};
use core::*;
use konsensus_chain::{recovery::RecoveryChain, BitcoindConfig, BitcoindProvider};
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_lightning::{
    move_home::Plan,
    recover::{self, Job, Progress},
    LdkConfig, LdkProvider,
};
use konsensus_recovery::{BackupIndex, RecoveryKeys};
use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let path = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &path);
        } else {
            std::fs::copy(entry.path(), path).unwrap();
        }
    }
}

/// Offline inspection in the TEST only. No broadcaster/ChainMonitor is constructed.
fn latest_holder(path: &Path, seed: [u8; 64]) -> Transaction {
    use ldk_node::lightning::{
        chain::{
            chaininterface::{BroadcasterInterface, ConfirmationTarget, FeeEstimator},
            channelmonitor::{ChannelMonitor, ChannelMonitorUpdate},
        },
        sign::{InMemorySigner, KeysManager},
        util::{
            logger::{Logger, Record},
            ser::{Readable, ReadableArgs},
        },
    };
    struct Quiet;
    impl Logger for Quiet {
        fn log(&self, _: Record) {}
    }
    let db = rusqlite::Connection::open_with_flags(
        path.join("ldk_node_data.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT value FROM ldk_node_data WHERE primary_namespace='monitors'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let master = Xpriv::new_master(Network::Regtest, &seed).unwrap();
    let keys = KeysManager::new(&master.private_key.secret_bytes(), 0, 0, true);
    let bytes = bytes.strip_prefix(&[0xff, 0xff]).unwrap_or(&bytes);
    let (_, monitor) = <(bitcoin::BlockHash, ChannelMonitor<InMemorySigner>)>::read(
        &mut std::io::Cursor::new(bytes),
        (&keys, &keys),
    )
    .unwrap();
    struct Offline;
    impl BroadcasterInterface for Offline {
        fn broadcast_transactions(&self, _: &[&Transaction]) {
            panic!("inspection must not broadcast");
        }
    }
    impl FeeEstimator for Offline {
        fn get_est_sat_per_1000_weight(&self, _: ConfirmationTarget) -> u32 {
            253
        }
    }
    let mut stmt = db
        .prepare("SELECT value FROM ldk_node_data WHERE primary_namespace='monitor_updates'")
        .unwrap();
    let mut updates: Vec<ChannelMonitorUpdate> = stmt
        .query_map([], |r| r.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|row| ChannelMonitorUpdate::read(&mut std::io::Cursor::new(row.unwrap())).unwrap())
        .collect();
    updates.sort_by_key(|u| u.update_id);
    for update in updates {
        if update.update_id > monitor.get_latest_update_id() {
            monitor
                .update_monitor(
                    &update,
                    &Arc::new(Offline),
                    &Arc::new(Offline),
                    &Arc::new(Quiet),
                )
                .unwrap();
        }
    }
    monitor
        .unsafe_get_latest_holder_commitment_txn(&Arc::new(Quiet))
        .remove(0)
}
async fn pay(hub: &ldk_node::Node, b: &ldk_node::Node, sats: u64) {
    let description = ldk_node::lightning_invoice::Bolt11InvoiceDescription::Direct(
        ldk_node::lightning_invoice::Description::new("advance B balance".into()).unwrap(),
    );
    let invoice = b
        .bolt11_payment()
        .receive(sats * 1000, &description, 3600)
        .unwrap();
    let id = hub.bolt11_payment().send(&invoice, None).unwrap();
    for _ in 0..100 {
        drain_events(hub);
        drain_events(b);
        if hub
            .payment(&id)
            .is_some_and(|p| p.status == ldk_node::payment::PaymentStatus::Succeeded)
        {
            tokio::time::sleep(Duration::from_millis(500)).await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("payment did not settle");
}

async fn run(with_backup: bool) {
    println!("recover scenario backup={with_backup}");
    let core = Core::start().await;
    let root = tempfile::tempdir().unwrap();
    let h_dir = root.path().join("H");
    let b_dir = root.path().join("B");
    let snapshot = root.path().join("snapshot");
    let restored = root.path().join("restored");
    let mnemonic = bip39::Mnemonic::from_entropy(&[2; 32]).unwrap().to_string();
    let seed = konsensus_lightning::scb_restore::derive_ldk_entropy_seed(&mnemonic, None).unwrap();
    let executable = std::env::var_os("KONSENSUS_EXE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .join("konsensus")
        });
    let init = std::process::Command::new(&executable)
        .args(["init", "--non-interactive", "--tier", "full", "--dir"])
        .arg(&b_dir)
        .output()
        .expect("build konsensus-node first, or set KONSENSUS_EXE");
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    std::fs::write(b_dir.join("mnemonic.txt"), &mnemonic).unwrap();
    let b_store = b_dir.join("ldk");
    let h_port = port();
    let b_port = port();
    let mut h = node(&core, &h_dir, [1; 64], h_port);
    let mut b = node(&core, &b_store, seed, b_port);
    core.mine(101, &[&h, &b]).await;
    core.rpc(
        "sendtoaddress",
        json!([h.onchain_payment().new_address().unwrap().to_string(), 0.02]),
    )
    .await;
    // Preserve the acceptor's 25,000-sat anchor reserve on-chain.
    core.rpc(
        "sendtoaddress",
        json!([
            b.onchain_payment().new_address().unwrap().to_string(),
            0.0005
        ]),
    )
    .await;
    core.mine(6, &[&h, &b]).await;
    h.open_channel(
        b.node_id(),
        format!("127.0.0.1:{b_port}").parse().unwrap(),
        500_000,
        None,
        None,
    )
    .unwrap();
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.mine(1, &[&h, &b]).await;
        if h.list_channels().iter().any(|c| c.is_channel_ready)
            && b.list_channels().iter().any(|c| c.is_channel_ready)
        {
            break;
        }
    }
    assert!(h.list_channels().iter().any(|c| c.is_channel_ready));
    let funding = h.list_channels()[0].funding_txo.unwrap();
    let funding = OutPoint {
        txid: funding.txid,
        vout: funding.vout,
    };
    println!("channel ready; advancing to snapshot");
    pay(&h, &b, 50_000).await;
    h.stop().unwrap();
    b.stop().unwrap();
    drop(h);
    drop(b);
    let old_h = latest_holder(&h_dir, [1; 64]);
    copy_dir(&b_dir, &snapshot);
    let scb = snapshot.join("index.scb");
    konsensus_lightning::scb_export::write_monitor_store_scb(&snapshot.join("ldk"), &scb).unwrap();
    let backup_key = konsensus_lightning::scb_restore::derive_scb_master_key_from_ldk_seed(&seed);
    let rotated = konsensus_lightning::scb_rotate::rotate_scb_backup(
        &konsensus_lightning::scb_rotate::ScbRotationConfig {
            scb_path: scb,
            backup_dir: snapshot.join("backup"),
            rotation_count: 2,
        },
        &backup_key,
    )
    .unwrap();
    h = node(&core, &h_dir, [1; 64], h_port);
    b = node(&core, &b_store, seed, b_port);
    h.connect(
        b.node_id(),
        format!("127.0.0.1:{b_port}").parse().unwrap(),
        true,
    )
    .unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    pay(&h, &b, 30_000).await;
    let latest_balance = 80_000;
    assert_eq!(
        b.list_channels()[0].outbound_capacity_msat / 1000
            + b.list_channels()[0].unspendable_punishment_reserve.unwrap(),
        latest_balance
    );
    h.stop().unwrap();
    b.stop().unwrap();
    drop(h);
    drop(b);
    let latest_h = latest_holder(&h_dir, [1; 64]);
    assert_ne!(
        old_h.compute_txid(),
        latest_h.compute_txid(),
        "snapshot must actually be stale"
    );
    // Model restoring the snapshot on a different host/volume, the PR1 fence's
    // documented coverage. Same-host image rollback remains outside that fence.
    let instance = snapshot.join("ldk/INSTANCE");
    let mut record: Value = serde_json::from_slice(&std::fs::read(&instance).unwrap()).unwrap();
    record["binding"] = json!("ff".repeat(32));
    std::fs::write(&instance, serde_json::to_vec(&record).unwrap()).unwrap();
    let copied_config = snapshot.join("konsensus.toml");
    let config_text = std::fs::read_to_string(&copied_config)
        .unwrap()
        .replace(b_dir.to_str().unwrap(), snapshot.to_str().unwrap());
    std::fs::write(&copied_config, config_text).unwrap();
    let before = core.rpc("getrawmempool", json!([])).await;
    let refused = std::process::Command::new(&executable)
        .args(["start", "--config"])
        .arg(&copied_config)
        .output()
        .unwrap();
    assert!(!refused.status.success());
    let output = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        String::from_utf8_lossy(&refused.stderr)
    );
    assert!(
        output.contains("host_binding_mismatch"),
        "normal startup did not reach the PR1 fence: {output}"
    );
    assert_eq!(before, core.rpc("getrawmempool", json!([])).await);
    std::fs::remove_dir_all(&b_dir).unwrap();
    h = node(&core, &h_dir, [1; 64], h_port);

    // Record *every* broadcast from recovering B, including its LDK RPC client.
    let broadcasts = Arc::new(Mutex::new(Vec::<Transaction>::new()));
    let recorded = broadcasts.clone();
    let url = core.url.clone();
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let recorded = recorded.clone();
            let url = url.clone();
            async move {
                if body["method"] == "sendrawtransaction" {
                    let raw = hex::decode(body["params"][0].as_str().unwrap()).unwrap();
                    recorded
                        .lock()
                        .unwrap()
                        .push(bitcoin::consensus::deserialize(&raw).unwrap());
                }
                assert_ne!(
                    body["method"], "submitpackage",
                    "record package broadcasts too if LDK changes its transport"
                );
                let response: Value = reqwest::Client::new()
                    .post(url)
                    .basic_auth("migration-test", Some("migration-test"))
                    .json(&body)
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                axum::Json(response)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let proxy = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let password_file = root.path().join("rpc-password");
    std::fs::write(&password_file, "migration-test").unwrap();
    let rpc = BitcoindConfig {
        rpc_host: "127.0.0.1".into(),
        rpc_port: proxy_port,
        cookie_file: None,
        rpc_user: Some("migration-test".into()),
        rpc_password_file: Some(password_file),
    };
    let chain = BitcoindProvider::new(rpc.clone()).unwrap();
    std::fs::create_dir(&restored).unwrap();
    recover::initialize(&restored).unwrap();
    assert!(recover::ensure_normal_start(&restored).is_err());
    assert!(recover::ensure_fresh_root(&snapshot.join("ldk")).is_err());
    let master = Xpriv::new_master(Network::Regtest, &seed).unwrap();
    let keys = RecoveryKeys::from_ldk_seed(&master.private_key.secret_bytes()).unwrap();
    let index = with_backup.then(|| {
        BackupIndex::decrypt(
            &std::fs::read(rotated.latest_path).unwrap(),
            &backup_key,
            &keys,
        )
        .unwrap()
    });
    if let Some(index) = &index {
        assert_eq!(index.channels()[0].funding_outpoint, funding);
    }
    let scripts = recover::scripts(&keys, index.as_ref());
    assert_eq!(scripts.len(), if with_backup { 1 } else { 2000 });
    let destination = recover::wallet_address(&seed, Network::Regtest).unwrap();
    let plan = Plan::new(
        konsensus_lightning::move_home::node_id_from_seed(&seed).unwrap(),
        "regtest",
        &destination.to_string(),
        2,
    )
    .unwrap();
    let funding_hints = if with_backup { vec![funding] } else { vec![] };
    let mut job = Job::load_or_begin(&restored, plan.clone(), funding_hints.clone()).unwrap();
    let provider = LdkProvider::new_for_recovery(config(
        &restored.join("recover-session-test"),
        &mnemonic,
        rpc.clone(),
    ))
    .await
    .unwrap();
    assert_eq!(
        provider.node().onchain_payment().new_address().unwrap(),
        destination
    );
    assert!(provider.node().list_channels().is_empty());
    provider
        .node()
        .connect(
            h.node_id(),
            format!("127.0.0.1:{h_port}").parse().unwrap(),
            true,
        )
        .unwrap();
    let mut swept = None;
    let mut ready = false;
    for _ in 0..90 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.mine(1, &[&h, provider.node()]).await;
        match job.advance(&chain, &keys, &scripts).await.unwrap() {
            Progress::SweepPreview { sweep, inputs } => {
                assert_eq!(inputs.len(), 1);
                assert_eq!(
                    inputs[0].outpoint.txid,
                    latest_h.compute_txid(),
                    "H must publish its latest commitment"
                );
                assert_eq!(inputs[0].txout.value.to_sat(), latest_balance);
                let tx = sweep.tx().unwrap();
                assert!(tx.input.iter().all(|i| i.previous_output != funding));
                assert_eq!(
                    sweep.validate(&plan).unwrap(),
                    latest_balance - sweep.fee_sats
                );
                swept = Some(tx.compute_txid());
                job.approve(&chain, sweep, inputs).await.unwrap();
                // Crash boundary: exact consent survives before first broadcast.
                drop(job);
                job = Job::load_or_begin(&restored, plan.clone(), funding_hints.clone()).unwrap();
                assert!(recover::ensure_normal_start(&restored).is_err());
            }
            Progress::SelfTest => {
                let checks = recover::self_test(&provider, &job, true).await.unwrap();
                assert!(checks.contains("money_ready=true"));
                ready = true;
                break;
            }
            Progress::WaitingForHub | Progress::Confirming { .. } => {}
            Progress::Complete => panic!("unexpected early completion"),
        }
    }
    assert!(ready, "on-chain recovery did not complete");
    assert!(!job.done());
    assert!(recover::ensure_normal_start(&restored).is_err());
    {
        let sent = broadcasts.lock().unwrap();
        assert!(!sent.is_empty());
        assert!(
            sent.iter()
                .all(|tx| tx.input.iter().all(|i| i.previous_output != funding)),
            "B must never spend funding"
        );
        assert!(sent.iter().any(|tx| Some(tx.compute_txid()) == swept));
    }
    let close = chain
        .transaction(latest_h.compute_txid())
        .await
        .unwrap()
        .unwrap();
    assert!(close
        .transaction
        .input
        .iter()
        .any(|i| i.previous_output == funding));
    provider.shutdown().await.unwrap();
    println!("sweep confirmed; verifying fresh Lightning channel");
    verify_lightning(
        &core,
        &h,
        h_port,
        &restored,
        &mnemonic,
        rpc.clone(),
        &mut job,
        &chain,
    )
    .await;
    assert!(job.done());
    recover::ensure_normal_start(&restored).unwrap();
    // A normal provider now loads the exact new live channel store, not a temporary session.
    let normal = LdkProvider::new(config(&restored, &mnemonic, rpc))
        .await
        .unwrap();
    assert_eq!(normal.node().list_channels().len(), 1);
    normal.shutdown().await.unwrap();
    h.stop().unwrap();
    proxy.abort();
}

/// Force-close with an in-flight HTLC: seed-only recovery sweeps only the static
/// `to_remote` output, completes the hub self-test, and never re-signs the input.
/// The preimage is withheld, so the HTLC cannot settle before the commitment that
/// contains it is force-closed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local bitcoind; seed-only recovery after force-close and data loss"]
async fn recover_force_closed_channel_from_seed_after_data_loss() {
    println!("recover scenario force-close seed-only");
    let core = Core::start().await;
    let root = tempfile::tempdir().unwrap();
    let h_dir = root.path().join("H");
    let b_dir = root.path().join("B");
    let restored = root.path().join("restored");
    let mnemonic = bip39::Mnemonic::from_entropy(&[4; 32]).unwrap().to_string();
    let seed = konsensus_lightning::scb_restore::derive_ldk_entropy_seed(&mnemonic, None).unwrap();
    let b_store = b_dir.join("ldk");
    let h_port = port();
    let b_port = port();
    let h = node(&core, &h_dir, [1; 64], h_port);
    let b = node(&core, &b_store, seed, b_port);
    core.mine(101, &[&h, &b]).await;
    core.rpc(
        "sendtoaddress",
        json!([h.onchain_payment().new_address().unwrap().to_string(), 0.02]),
    )
    .await;
    core.rpc(
        "sendtoaddress",
        json!([
            b.onchain_payment().new_address().unwrap().to_string(),
            0.0005
        ]),
    )
    .await;
    core.mine(6, &[&h, &b]).await;
    h.open_channel(
        b.node_id(),
        format!("127.0.0.1:{b_port}").parse().unwrap(),
        500_000,
        None,
        None,
    )
    .unwrap();
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.mine(1, &[&h, &b]).await;
        if h.list_channels().iter().any(|c| c.is_channel_ready)
            && b.list_channels().iter().any(|c| c.is_channel_ready)
        {
            break;
        }
    }
    assert!(b.list_channels().iter().any(|c| c.is_channel_ready));
    let channel = b.list_channels()[0].clone();
    let funding = channel.funding_txo.unwrap();
    let funding = OutPoint {
        txid: funding.txid,
        vout: funding.vout,
    };
    pay(&h, &b, 50_000).await;
    let inflight_sats = 25_000;
    let hub_seed = [1u8; 64];
    let pre_commit = latest_holder(&h_dir, hub_seed);
    let description = ldk_node::lightning_invoice::Bolt11InvoiceDescription::Direct(
        ldk_node::lightning_invoice::Description::new("in-flight HTLC".into()).unwrap(),
    );
    // receive() would claim on arrival. Hold the preimage so no event handler,
    // poll, or block sync can settle the HTLC before force-close.
    let preimage = PaymentPreimage([9u8; 32]);
    let payment_hash = PaymentHash(sha256::Hash::hash(&preimage.0).to_byte_array());
    let invoice = b
        .bolt11_payment()
        .receive_for_hash(inflight_sats * 1000, &description, 3600, payment_hash)
        .unwrap();
    let inflight = h.bolt11_payment().send(&invoice, None).unwrap();
    assert_eq!(
        h.payment(&inflight).unwrap().status,
        ldk_node::payment::PaymentStatus::Pending,
        "HTLC must still be in flight when the channel is force-closed"
    );
    let prior_outputs: Vec<_> = pre_commit
        .output
        .iter()
        .map(|output| (output.script_pubkey.clone(), output.value))
        .collect();
    let mut htlc_output = None;
    for _ in 0..200 {
        drain_events(&h);
        drain_events(&b);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            h.payment(&inflight).unwrap().status,
            ldk_node::payment::PaymentStatus::Pending,
            "withheld preimage must keep the HTLC pending until it is committed"
        );
        let commit = latest_holder(&h_dir, hub_seed);
        if let Some(output) = commit.output.iter().find(|output| {
            output.value.to_sat() == inflight_sats
                && !prior_outputs.iter().any(|(script, value)| {
                    script == &output.script_pubkey && *value == output.value
                })
        }) {
            htlc_output = Some(output.clone());
            break;
        }
    }
    let htlc_output = htlc_output.expect("HTLC must be on the hub commitment before force-close");
    let settled_balance = b.list_channels()[0].outbound_capacity_msat / 1000
        + b.list_channels()[0].unspendable_punishment_reserve.unwrap();
    let committed = latest_holder(&h_dir, hub_seed);
    assert!(
        committed.output.iter().any(|output| {
            output.script_pubkey == htlc_output.script_pubkey && output.value == htlc_output.value
        }),
        "HTLC must still be on the hub commitment at force-close"
    );
    assert_eq!(
        h.payment(&inflight).unwrap().status,
        ldk_node::payment::PaymentStatus::Pending,
        "HTLC must still be in flight when the channel is force-closed"
    );
    let h_channel = h.list_channels()[0].clone();
    h.force_close_channel(
        &h_channel.user_channel_id,
        b.node_id(),
        Some("regtest hub force-close".into()),
    )
    .unwrap();
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.mine(1, &[&h, &b]).await;
        if b.list_channels().is_empty() {
            break;
        }
    }
    assert!(
        b.list_channels().is_empty(),
        "force-close did not remove the channel"
    );
    b.stop().unwrap();
    drop(b);
    let master = Xpriv::new_master(Network::Regtest, &seed).unwrap();
    let keys = RecoveryKeys::from_ldk_seed(&master.private_key.secret_bytes()).unwrap();
    let scripts = recover::scripts(&keys, None);
    let password_file = root.path().join("rpc-password");
    std::fs::write(&password_file, "migration-test").unwrap();
    let rpc = BitcoindConfig {
        rpc_host: "127.0.0.1".into(),
        rpc_port: core.port,
        cookie_file: None,
        rpc_user: Some("migration-test".into()),
        rpc_password_file: Some(password_file),
    };
    let chain = BitcoindProvider::new(rpc.clone()).unwrap();
    let mut close_tx = None;
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.mine(1, &[&h]).await;
        if let Some(close) = chain.funding_spend(funding).await.unwrap() {
            if close.confirmations > 0 {
                close_tx = Some(close.transaction);
                break;
            }
        }
    }
    let close = close_tx.expect("force-close transaction never confirmed");
    let recoverable: Vec<_> = close
        .output
        .iter()
        .filter(|o| scripts.iter().any(|s| s.script_pubkey == o.script_pubkey))
        .collect();
    assert_eq!(
        recoverable.len(),
        1,
        "only the static to_remote output is recoverable from the seed"
    );
    assert_eq!(
        recoverable[0].value.to_sat(),
        settled_balance,
        "hub commitment must pay B's settled balance to the static to_remote key"
    );
    let htlc_outpoint = OutPoint {
        txid: close.compute_txid(),
        vout: close
            .output
            .iter()
            .position(|output| {
                output.script_pubkey == htlc_output.script_pubkey
                    && output.value == htlc_output.value
            })
            .expect("force-close must include the in-flight HTLC output") as u32,
    };
    assert!(
        !scripts
            .iter()
            .any(|s| s.script_pubkey == htlc_output.script_pubkey),
        "HTLC output must not match seed-only recovery scripts"
    );
    println!(
        "force-close has {} recoverable output(s); HTLC value {} sats left on chain",
        recoverable.len(),
        inflight_sats
    );
    std::fs::remove_dir_all(&b_dir).unwrap();
    let broadcasts = Arc::new(Mutex::new(Vec::<Transaction>::new()));
    let recorded = broadcasts.clone();
    let url = core.url.clone();
    let app = axum::Router::new().route(
        "/",
        axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
            let recorded = recorded.clone();
            let url = url.clone();
            async move {
                if body["method"] == "sendrawtransaction" {
                    let raw = hex::decode(body["params"][0].as_str().unwrap()).unwrap();
                    recorded
                        .lock()
                        .unwrap()
                        .push(bitcoin::consensus::deserialize(&raw).unwrap());
                }
                assert_ne!(
                    body["method"], "submitpackage",
                    "record package broadcasts too if LDK changes its transport"
                );
                let response: Value = reqwest::Client::new()
                    .post(url)
                    .basic_auth("migration-test", Some("migration-test"))
                    .json(&body)
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                axum::Json(response)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    let proxy = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let proxy_rpc = BitcoindConfig {
        rpc_host: "127.0.0.1".into(),
        rpc_port: proxy_port,
        cookie_file: None,
        rpc_user: Some("migration-test".into()),
        rpc_password_file: Some(root.path().join("rpc-password")),
    };
    let chain = BitcoindProvider::new(proxy_rpc.clone()).unwrap();
    std::fs::create_dir(&restored).unwrap();
    recover::initialize(&restored).unwrap();
    let destination = recover::wallet_address(&seed, Network::Regtest).unwrap();
    let plan = Plan::new(
        konsensus_lightning::move_home::node_id_from_seed(&seed).unwrap(),
        "regtest",
        &destination.to_string(),
        2,
    )
    .unwrap();
    let mut job = Job::load_or_begin(&restored, plan.clone(), vec![]).unwrap();
    let provider = LdkProvider::new_for_recovery(config(
        &restored.join("recover-session-test"),
        &mnemonic,
        proxy_rpc.clone(),
    ))
    .await
    .unwrap();
    provider
        .node()
        .connect(
            h.node_id(),
            format!("127.0.0.1:{h_port}").parse().unwrap(),
            true,
        )
        .unwrap();
    let mut approved_sweep: Option<Transaction> = None;
    let mut permitted_inputs: Vec<OutPoint> = Vec::new();
    let mut ready = false;
    let mut max_confirmations = 0u32;
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.mine(1, &[&h, provider.node()]).await;
        match job.advance(&chain, &keys, &scripts).await.unwrap() {
            Progress::SweepPreview { sweep, inputs } => {
                assert_eq!(inputs.len(), 1);
                assert_eq!(inputs[0].outpoint.txid, close.compute_txid());
                assert_eq!(inputs[0].txout.value.to_sat(), settled_balance);
                assert_eq!(inputs[0].txout.script_pubkey, recoverable[0].script_pubkey);
                assert!(
                    inputs
                        .iter()
                        .all(|i| i.txout.script_pubkey != htlc_output.script_pubkey),
                    "sweep must not spend the in-flight HTLC output"
                );
                let tx = sweep.tx().unwrap();
                let preview_inputs: Vec<_> = inputs.iter().map(|input| input.outpoint).collect();
                assert_eq!(
                    tx.input
                        .iter()
                        .map(|input| input.previous_output)
                        .collect::<Vec<_>>(),
                    preview_inputs,
                    "approved sweep inputs must be exactly the preview outputs"
                );
                assert!(tx.input.iter().all(|input| {
                    input.previous_output != funding && input.previous_output != htlc_outpoint
                }));
                assert_eq!(
                    sweep.validate(&plan).unwrap(),
                    settled_balance - sweep.fee_sats
                );
                permitted_inputs = preview_inputs;
                approved_sweep = Some(tx);
                job.approve(&chain, sweep, inputs).await.unwrap();
            }
            Progress::SelfTest => {
                let sweep_txid = approved_sweep
                    .as_ref()
                    .expect("self-test without an approved sweep")
                    .compute_txid();
                let confirmed = chain
                    .transaction(sweep_txid)
                    .await
                    .unwrap()
                    .expect("sweep transaction must be on chain");
                max_confirmations = max_confirmations.max(confirmed.confirmations);
                let checks = recover::self_test(&provider, &job, true).await.unwrap();
                assert!(checks.contains("money_ready=true"));
                ready = true;
                break;
            }
            Progress::WaitingForHub => {}
            Progress::Confirming { confirmations, .. } => {
                max_confirmations = max_confirmations.max(confirmations);
            }
            Progress::Complete => panic!("unexpected early completion"),
        }
    }
    assert!(ready, "seed-only recovery did not reach the hub self-test");
    assert!(
        max_confirmations >= konsensus_lightning::move_home::FINAL_CONFIRMATIONS,
        "sweep must reach six confirmations before the hub self-test (saw {max_confirmations})"
    );
    let approved = approved_sweep
        .as_ref()
        .expect("recovery broadcast without an approved sweep");
    let sent_count = {
        let recorded = broadcasts.lock().unwrap();
        assert!(
            !recorded.is_empty(),
            "recovery must broadcast the approved sweep"
        );
        for tx in recorded.iter() {
            let spent: Vec<_> = tx.input.iter().map(|input| input.previous_output).collect();
            assert!(
                spent
                    .iter()
                    .all(|outpoint| permitted_inputs.contains(outpoint)),
                "broadcast {} spends an input outside the approved sweep",
                tx.compute_txid()
            );
            assert!(
                spent
                    .iter()
                    .all(|outpoint| *outpoint != funding && *outpoint != htlc_outpoint),
                "broadcast {} spends funding or the in-flight HTLC",
                tx.compute_txid()
            );
            assert_eq!(
                tx,
                approved,
                "broadcast {} is not the approved sweep",
                tx.compute_txid()
            );
        }
        recorded.len()
    };
    let (progress, _) = (job.advance(&chain, &keys, &scripts).await.unwrap(), ());
    assert!(matches!(progress, Progress::SelfTest), "{progress:?}");
    assert_eq!(
        broadcasts.lock().unwrap().len(),
        sent_count,
        "rerunning recovery must not sign a second transaction for the same input"
    );
    provider.shutdown().await.unwrap();
    // The HTLC is still on the force-close. The hub must time it out and sweep
    // the second-stage CSV output before LSPS2 will archive the monitor.
    resolve_outgoing_htlc_timeout(&core, &h).await;
    verify_lightning(
        &core, &h, h_port, &restored, &mnemonic, proxy_rpc, &mut job, &chain,
    )
    .await;
    assert!(job.done());
    recover::ensure_normal_start(&restored).unwrap();
    h.stop().unwrap();
    proxy.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local bitcoind; latest-state hub recovery with and without a stale backup"]
async fn recover_latest_hub_state_with_and_without_stale_backup() {
    run(false).await;
    run(true).await;
}

fn config(dir: &Path, mnemonic: &str, rpc: BitcoindConfig) -> LdkConfig {
    LdkConfig {
        tower: Default::default(),
        forward_to_private_channels: false,
        our_to_self_delay_blocks: None,
        lsps2_service: Default::default(),
        channel_peers: None,
        channel_capacity_limits: Default::default(),
        esplora_sync_intervals: Default::default(),
        logging: Default::default(),
        electrum: None,
        bitcoind: Some(rpc),
        liquidity: Default::default(),
        storage_dir: dir.into(),
        scb_backup_dir: None,
        scb_rotation_count: 3,
        mnemonic: mnemonic.into(),
        passphrase: None,
        network: "regtest".into(),
        esplora_url: "http://127.0.0.1:1".into(),
        esplora_url_fallback: None,
        credentials_file: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: None,
    }
}

/// Confirm the hub's HTLC-timeout and the CSV spend of that output.
///
/// Seed recovery must not claim this output. LSPS2 keeps the manual-close
/// monitor's full capital reserved until the monitor archives, which requires
/// both on-chain claims to confirm before the archival delay.
async fn resolve_outgoing_htlc_timeout(core: &Core, hub: &ldk_node::Node) {
    core.mine(150, &[hub]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    core.mine(6, &[hub]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    core.mine(
        u32::from(ldk_node::lightning::ln::channelmanager::BREAKDOWN_TIMEOUT),
        &[hub],
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    core.mine(6, &[hub]).await;
}

#[allow(clippy::too_many_arguments)]
async fn verify_lightning(
    core: &Core,
    h: &ldk_node::Node,
    h_port: u16,
    storage: &Path,
    mnemonic: &str,
    rpc: BitcoindConfig,
    job: &mut Job,
    chain: &BitcoindProvider,
) {
    // The hub conservatively retains capital for old manual closing monitors.
    // Resolve its CSV claim, confirm the sweep, then advance the real LDK
    // archival delay; never disable the hub's capital gate for this drill.
    core.mine(150, &[h]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    core.mine(12, &[h]).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    core.mine(6, &[h]).await;
    core.mine(
        ldk_node::lightning::chain::channelmonitor::ARCHIVAL_DELAY_BLOCKS + 1,
        &[h],
    )
    .await;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        core.mine(1, &[h]).await;
        if h.lsps2_service_metrics().capital_locked_sats == 0 {
            break;
        }
    }
    assert_eq!(
        h.lsps2_service_metrics().capital_locked_sats,
        0,
        "hub's previous close must release its capital reservation"
    );
    let payer_dir = tempfile::tempdir().unwrap();
    let payer = node(core, payer_dir.path(), [3; 64], port());
    core.rpc(
        "sendtoaddress",
        json!([
            payer.onchain_payment().new_address().unwrap().to_string(),
            0.02
        ]),
    )
    .await;
    core.mine(6, &[h, &payer]).await;
    payer
        .open_channel(
            h.node_id(),
            format!("127.0.0.1:{h_port}").parse().unwrap(),
            500_000,
            None,
            None,
        )
        .unwrap();
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.mine(1, &[h, &payer]).await;
        if payer.list_channels().iter().any(|c| c.is_usable) {
            break;
        }
    }
    assert!(payer.list_channels().iter().any(|c| c.is_usable));
    job.begin_verification(h.node_id().to_string()).unwrap();
    let mut cfg = config(storage, mnemonic, rpc);
    cfg.liquidity = konsensus_lightning::liquidity::LiquidityConfig {
        enabled: true,
        selected_provider: Some(h.node_id().to_string()),
        providers: vec![konsensus_lightning::liquidity::LspConfig {
            trust_no_reserve: false,
            node_id: h.node_id().to_string(),
            address: format!("127.0.0.1:{h_port}"),
            token: Some("recover-test".into()),
        }],
    };
    let id = job.verification().unwrap().store_id.clone();
    let recovered = LdkProvider::new_for_recovery_verification(cfg.clone(), &id)
        .await
        .unwrap();
    // A fresh Bitcoind-backed wallet starts at the current tip, so old seed
    // funds are not a synchronized reserve for this verification store.
    println!(
        "verification reserve before funding: {} sats",
        recovered
            .node()
            .list_balances()
            .spendable_onchain_balance_sats
    );
    core.rpc(
        "sendtoaddress",
        json!([
            recovered
                .node()
                .onchain_payment()
                .new_address()
                .unwrap()
                .to_string(),
            0.0005
        ]),
    )
    .await;
    core.mine(6, &[h, &payer, recovered.node()]).await;
    assert!(
        recovered
            .node()
            .list_balances()
            .spendable_onchain_balance_sats
            >= 25_000
    );
    println!("verification provider started; requesting LSPS2 quote");
    let quote = recovered
        .quote_liquidity("test-console", 20_000_000, 2_000_000)
        .await
        .unwrap();
    let invoice = recovered
        .accept_liquidity("test-console", &quote.quote_id)
        .await
        .unwrap();
    let mut verification = job.verification().unwrap().clone();
    verification.invoice = Some(invoice.bolt11.clone());
    job.save_verification(verification).unwrap();
    println!("LSPS2 quote accepted; paying from external wallet");
    let payment = payer
        .bolt11_payment()
        .send(&invoice.bolt11.parse().unwrap(), None)
        .unwrap();
    for _ in 0..120 {
        tokio::time::sleep(Duration::from_millis(500)).await;
        core.mine(1, &[h, &payer, recovered.node()]).await;
        if payer
            .payment(&payment)
            .is_some_and(|p| p.status == ldk_node::payment::PaymentStatus::Succeeded)
        {
            break;
        }
    }
    assert_eq!(
        payer.payment(&payment).unwrap().status,
        ldk_node::payment::PaymentStatus::Succeeded
    );
    assert!(recovered.node().list_channels().iter().any(|c| c.is_usable));
    println!("fresh LSPS2 channel funded; sending 1-sat test");
    // The new channel can be usable before a zero-fee keysend route exists.
    let mut sent = false;
    for _ in 0..10 {
        if recovered
            .send_recovery_self_test(&h.node_id().to_string(), [42; 32])
            .is_ok()
        {
            sent = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        core.mine(1, &[h, recovered.node()]).await;
    }
    assert!(sent, "1-sat self-test send failed");
    for _ in 0..60 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        drain_events(h);
        if recovered.node().list_payments().iter().any(|p| {
            p.direction == ldk_node::payment::PaymentDirection::Outbound
                && p.amount_msat == Some(1000)
                && p.status == ldk_node::payment::PaymentStatus::Succeeded
        }) {
            break;
        }
    }
    assert!(recovered.node().list_payments().iter().any(|p| p.direction
        == ldk_node::payment::PaymentDirection::Outbound
        && p.amount_msat == Some(1000)
        && p.status == ldk_node::payment::PaymentStatus::Succeeded));
    assert!(recovered.money_ready().await);
    // Restart the canonical verification store before journal completion.
    recovered.shutdown().await.unwrap();
    let resumed = LdkProvider::new_for_recovery_verification(cfg, &id)
        .await
        .unwrap();
    assert_eq!(resumed.node().list_channels().len(), 1);
    let report = job
        .finish(chain, "LSPS2 funded; 1-sat hub payment settled".into())
        .await
        .unwrap();
    assert_eq!(report.sweep_txids.len(), 1);
    resumed.shutdown().await.unwrap();
    payer.stop().unwrap();
}
