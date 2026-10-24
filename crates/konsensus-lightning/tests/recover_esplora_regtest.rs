//! BITCOIND_EXE=/path/to/bitcoind cargo test -p konsensus-lightning --test recover_esplora_regtest -- --ignored --nocapture
//! Seed-only recovery against a real regtest chain through a request-counting
//! Esplora shim: every derived script is read until the hub close is found,
//! then each 30-second pass reads only the discovered output. No downloads.
#[allow(dead_code)]
#[path = "support/core.rs"]
mod core;
use bitcoin::{
    hashes::{sha256, Hash},
    Address, Amount, Network, OutPoint, Transaction, Txid,
};
use core::Core;
use konsensus_chain::{EsploraConfig, EsploraProvider};
use konsensus_core::traits::chain::TrustLevel;
use konsensus_lightning::{
    move_home::Plan,
    recover::{self, Job, Progress},
};
use konsensus_recovery::{RecoveryKeys, RecoveryScript};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};

const FULL_PASS_MINIMUM: usize = 2000;
const NARROWED_PASS_MAXIMUM: usize = 32;

#[derive(Default)]
struct Index {
    height: u32,
    hashes: HashMap<u32, String>,
    /// txid -> (raw hex, confirmed block height)
    transactions: HashMap<Txid, (String, Option<u32>)>,
    /// outputs keyed by Esplora scripthash (sha256 of the script)
    outputs: BTreeMap<String, Vec<(OutPoint, u64)>>,
    spends: HashMap<OutPoint, Txid>,
}
impl Index {
    fn record(&mut self, tx: &Value, height: Option<u32>) {
        let txid: Txid = tx["txid"].as_str().unwrap().parse().unwrap();
        if let Some(known) = self.transactions.get_mut(&txid) {
            // A mempool transaction that confirmed keeps its outputs and spends.
            known.1 = height;
            return;
        }
        let hex = tx["hex"].as_str().unwrap().to_owned();
        self.transactions.insert(txid, (hex, height));
        for input in tx["vin"].as_array().unwrap() {
            if let Some(prev) = input["txid"].as_str() {
                let outpoint = OutPoint {
                    txid: prev.parse().unwrap(),
                    vout: input["vout"].as_u64().unwrap() as u32,
                };
                self.spends.insert(outpoint, txid);
            }
        }
        for (vout, output) in tx["vout"].as_array().unwrap().iter().enumerate() {
            let script = hex::decode(output["scriptPubKey"]["hex"].as_str().unwrap()).unwrap();
            let value = Amount::from_btc(output["value"].as_f64().unwrap())
                .unwrap()
                .to_sat();
            self.outputs
                .entry(sha256::Hash::hash(&script).to_string())
                .or_default()
                .push((
                    OutPoint {
                        txid,
                        vout: vout as u32,
                    },
                    value,
                ));
        }
    }
}

fn status(index: &Index, txid: Txid) -> Value {
    match index.transactions.get(&txid).and_then(|(_, h)| *h) {
        Some(height) => {
            json!({"confirmed":true,"block_height":height,"block_hash":index.hashes[&height]})
        }
        None => json!({"confirmed":false}),
    }
}

struct Shim {
    core: Arc<Core>,
    index: Mutex<Index>,
    requests: AtomicUsize,
}
impl Shim {
    /// Pull new blocks and mempool entries from bitcoind before answering.
    async fn sync(&self) {
        let count = self
            .core
            .rpc("getblockcount", json!([]))
            .await
            .as_u64()
            .unwrap() as u32;
        let from = self.index.lock().unwrap().height + 1;
        for height in from..=count {
            let hash = self.core.rpc("getblockhash", json!([height])).await;
            let block = self.core.rpc("getblock", json!([hash, 2])).await;
            let mut index = self.index.lock().unwrap();
            index
                .hashes
                .insert(height, hash.as_str().unwrap().to_owned());
            for tx in block["tx"].as_array().unwrap() {
                index.record(tx, Some(height));
            }
            index.height = height;
        }
        let mempool = self.core.rpc("getrawmempool", json!([])).await;
        for txid in mempool.as_array().unwrap() {
            let id: Txid = txid.as_str().unwrap().parse().unwrap();
            if self.index.lock().unwrap().transactions.contains_key(&id) {
                continue;
            }
            let tx = self
                .core
                .rpc("getrawtransaction", json!([txid, true]))
                .await;
            self.index.lock().unwrap().record(&tx, None);
        }
    }
    fn status(&self, txid: Txid) -> Value {
        let index = self.index.lock().unwrap();
        status(&index, txid)
    }
    async fn get(&self, path: &str) -> String {
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.sync().await;
        let parts: Vec<&str> = path.split('/').collect();
        match parts.as_slice() {
            ["blocks", "tip", "hash"] => self
                .core
                .rpc("getbestblockhash", json!([]))
                .await
                .as_str()
                .unwrap()
                .to_owned(),
            ["block", hash] => {
                let block = self.core.rpc("getblock", json!([hash, 1])).await;
                json!({"height":block["height"]}).to_string()
            }
            ["block-height", height] => {
                self.index.lock().unwrap().hashes[&height.parse::<u32>().unwrap()].clone()
            }
            ["scripthash", hash, "utxo"] => {
                let index = self.index.lock().unwrap();
                let utxos: Vec<Value> = index
                    .outputs
                    .get(*hash)
                    .into_iter()
                    .flatten()
                    .filter(|(outpoint, _)| !index.spends.contains_key(outpoint))
                    .map(|(outpoint, value)| {
                        json!({"txid":outpoint.txid,"vout":outpoint.vout,"value":value,"status":status(&index, outpoint.txid)})
                    })
                    .collect();
                Value::Array(utxos).to_string()
            }
            ["tx", txid, "hex"] => {
                let txid: Txid = txid.parse().unwrap();
                self.index.lock().unwrap().transactions[&txid].0.clone()
            }
            ["tx", txid, "status"] => self.status(txid.parse().unwrap()).to_string(),
            ["tx", txid, "outspend", vout] => {
                let outpoint = OutPoint {
                    txid: txid.parse().unwrap(),
                    vout: vout.parse().unwrap(),
                };
                match self.index.lock().unwrap().spends.get(&outpoint) {
                    Some(spender) => json!({"spent":true,"txid":spender}).to_string(),
                    None => json!({"spent":false}).to_string(),
                }
            }
            _ => panic!("unexpected Esplora request {path}"),
        }
    }
    async fn post_tx(&self, raw: String) -> String {
        self.requests.fetch_add(1, Ordering::SeqCst);
        self.core
            .rpc("sendrawtransaction", json!([raw.trim()]))
            .await
            .as_str()
            .unwrap()
            .to_owned()
    }
}

/// One 30-second recovery pass, returning its progress and HTTP request count.
async fn pass(
    job: &mut Job,
    chain: &EsploraProvider,
    keys: &RecoveryKeys,
    scripts: &[RecoveryScript],
    shim: &Shim,
) -> (Progress, usize) {
    shim.requests.store(0, Ordering::SeqCst);
    let progress = job.advance(chain, keys, scripts).await.unwrap();
    (progress, shim.requests.load(Ordering::SeqCst))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires local bitcoind; seed-only Esplora recovery read bound"]
async fn seed_only_esplora_recovery_bounds_reads_after_the_first_pass() {
    let core = Arc::new(Core::start().await);
    let shim = Arc::new(Shim {
        core: core.clone(),
        index: Mutex::new(Index::default()),
        requests: AtomicUsize::new(0),
    });
    let get_shim = shim.clone();
    let post_shim = shim.clone();
    let app = axum::Router::new()
        .route(
            "/api/*path",
            axum::routing::get(
                move |axum::extract::Path(path): axum::extract::Path<String>| {
                    let shim = get_shim.clone();
                    async move { shim.get(&path).await }
                },
            ),
        )
        .route(
            "/api/tx",
            axum::routing::post(move |body: String| {
                let shim = post_shim.clone();
                async move { shim.post_tx(body).await }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    core.mine(101, &[]).await;

    let mnemonic = bip39::Mnemonic::from_entropy(&[2; 32]).unwrap().to_string();
    let seed = konsensus_lightning::scb_restore::derive_ldk_entropy_seed(&mnemonic, None).unwrap();
    let master = bitcoin::bip32::Xpriv::new_master(Network::Regtest, &seed).unwrap();
    let keys = RecoveryKeys::from_ldk_seed(&master.private_key.secret_bytes()).unwrap();
    let scripts = recover::scripts(&keys, None);
    assert_eq!(scripts.len(), FULL_PASS_MINIMUM);
    // Stand in for the hub's close: a payment to B's static to_remote script,
    // unconfirmed at first, exactly as a fresh force-close appears on Esplora.
    let to_remote = Address::from_script(&scripts[0].script_pubkey, Network::Regtest).unwrap();
    let close: Txid = core
        .rpc("sendtoaddress", json!([to_remote.to_string(), 0.0009]))
        .await
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let destination = recover::wallet_address(&seed, Network::Regtest).unwrap();
    let plan = Plan::new(
        konsensus_lightning::move_home::node_id_from_seed(&seed).unwrap(),
        "regtest",
        &destination.to_string(),
        2,
    )
    .unwrap();
    let restored = tempfile::tempdir().unwrap();
    recover::initialize(restored.path()).unwrap();
    let mut job = Job::load_or_begin(restored.path(), plan.clone(), vec![]).unwrap();
    let chain = EsploraProvider::new(EsploraConfig::custom(url, TrustLevel::ServerTrust)).unwrap();

    let (progress, first) = pass(&mut job, &chain, &keys, &scripts, &shim).await;
    assert!(matches!(progress, Progress::WaitingForHub), "{progress:?}");
    assert!(
        first >= FULL_PASS_MINIMUM,
        "first pass read {first} requests"
    );
    println!("first seed-only pass: {first} HTTP requests");

    let (progress, polled) = pass(&mut job, &chain, &keys, &scripts, &shim).await;
    assert!(matches!(progress, Progress::WaitingForHub), "{progress:?}");
    assert!(
        polled <= NARROWED_PASS_MAXIMUM,
        "unconfirmed poll read {polled}"
    );
    println!("unconfirmed-close poll: {polled} HTTP requests");

    core.mine(1, &[]).await;
    let (progress, polled) = pass(&mut job, &chain, &keys, &scripts, &shim).await;
    let Progress::SweepPreview { sweep, inputs } = progress else {
        panic!("{progress:?}");
    };
    assert!(
        polled <= NARROWED_PASS_MAXIMUM,
        "confirmed poll read {polled}"
    );
    println!("confirmed-close poll: {polled} HTTP requests");
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].outpoint.txid, close);
    assert_eq!(inputs[0].txout.value.to_sat(), 90_000);
    let tx: Transaction = sweep.tx().unwrap();
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].script_pubkey, destination.script_pubkey());
    let sweep_txid = tx.compute_txid();
    job.approve(&chain, sweep, inputs).await.unwrap();

    let (progress, polled) = pass(&mut job, &chain, &keys, &scripts, &shim).await;
    assert!(
        matches!(
            progress,
            Progress::Confirming {
                confirmations: 0,
                ..
            }
        ),
        "{progress:?}"
    );
    assert!(
        polled <= NARROWED_PASS_MAXIMUM,
        "broadcast pass read {polled}"
    );
    let mempool = core.rpc("getrawmempool", json!([])).await;
    assert!(
        mempool
            .as_array()
            .unwrap()
            .iter()
            .any(|id| id == &json!(sweep_txid.to_string())),
        "sweep must reach the regtest mempool: {mempool}"
    );

    core.mine(6, &[]).await;
    let (progress, last) = pass(&mut job, &chain, &keys, &scripts, &shim).await;
    assert!(matches!(progress, Progress::SelfTest), "{progress:?}");
    assert!(last >= FULL_PASS_MINIMUM, "post-sweep rescan read {last}");
    println!("post-sweep late-close rescan: {last} HTTP requests");
    // Rerunning never signs a second spend of the same input.
    let (progress, _) = pass(&mut job, &chain, &keys, &scripts, &shim).await;
    assert!(matches!(progress, Progress::SelfTest), "{progress:?}");
    server.abort();
}
