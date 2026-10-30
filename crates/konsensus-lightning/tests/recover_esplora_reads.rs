//! Seed-only recovery over a request-counting Esplora stand-in: the first pass
//! reads every derived script, unconfirmed polls read only discovered outputs,
//! and the preview pass rescans all scripts to combine confirmed closes.
//! No bitcoind: the chain is a synthetic regtest view served over HTTP.
use bitcoin::{
    absolute,
    hashes::{sha256, Hash},
    transaction, Amount, OutPoint, Transaction, TxIn, TxOut, Txid,
};
use konsensus_chain::{EsploraConfig, EsploraProvider};
use konsensus_core::traits::chain::TrustLevel;
use konsensus_lightning::{
    move_home::Plan,
    recover::{self, Job, Progress},
};
use konsensus_recovery::RecoveryKeys;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

/// Every derived script costs one request. Narrowed passes read the discovered
/// unconfirmed output, its transaction, its spend status and the tip: a handful.
const FULL_PASS_MINIMUM: usize = 2000;
const NARROWED_PASS_MAXIMUM: usize = 32;

#[derive(Clone)]
struct View {
    tip: u32,
    close: Transaction,
    close_height: Option<u32>,
    sweep: Option<Transaction>,
    sweep_height: Option<u32>,
}
impl View {
    fn status(&self, txid: Txid) -> Option<Value> {
        let height = if txid == self.close.compute_txid() {
            self.close_height
        } else if self.sweep.as_ref().map(|t| t.compute_txid()) == Some(txid) {
            self.sweep_height
        } else {
            return None;
        };
        Some(match height {
            Some(height) => {
                json!({"confirmed":true,"block_height":height,"block_hash":block_hash(height)})
            }
            None => json!({"confirmed":false}),
        })
    }
    fn transaction(&self, txid: Txid) -> Option<&Transaction> {
        if txid == self.close.compute_txid() {
            Some(&self.close)
        } else {
            self.sweep.as_ref().filter(|t| t.compute_txid() == txid)
        }
    }
}
fn block_hash(height: u32) -> String {
    format!("{height:064x}")
}

async fn serve(
    view: Arc<Mutex<View>>,
    requests: Arc<AtomicUsize>,
) -> (String, tokio::task::JoinHandle<()>) {
    let get_view = view.clone();
    let get_requests = requests.clone();
    let post_view = view;
    let app = axum::Router::new()
        .route(
            "/api/*path",
            axum::routing::get(
                move |axum::extract::Path(path): axum::extract::Path<String>| {
                    let view = get_view.clone();
                    let requests = get_requests.clone();
                    async move {
                        requests.fetch_add(1, Ordering::SeqCst);
                        let view = view.lock().unwrap().clone();
                        let parts: Vec<&str> = path.split('/').collect();
                        match parts.as_slice() {
                            ["blocks", "tip", "hash"] => block_hash(view.tip),
                            ["block", hash] => {
                                let height = u32::from_str_radix(hash.trim_start_matches('0'), 16)
                                    .unwrap_or(0);
                                json!({"height":height}).to_string()
                            }
                            ["block-height", height] => block_hash(height.parse().unwrap()),
                            ["scripthash", hash, "utxo"] => {
                                let close_hash =
                                    sha256::Hash::hash(view.close.output[0].script_pubkey.as_bytes())
                                        .to_string();
                                if *hash == close_hash && view.sweep.is_none() {
                                    let txid = view.close.compute_txid();
                                    json!([{"txid":txid,"vout":0,"value":view.close.output[0].value.to_sat(),"status":view.status(txid).unwrap()}]).to_string()
                                } else {
                                    "[]".into()
                                }
                            }
                            ["tx", txid, "hex"] => bitcoin::consensus::encode::serialize_hex(
                                view.transaction(txid.parse().unwrap()).expect("known tx"),
                            ),
                            ["tx", txid, "status"] => view.status(txid.parse().unwrap()).unwrap().to_string(),
                            ["tx", txid, "outspend", "0"] => {
                                let txid: Txid = txid.parse().unwrap();
                                match &view.sweep {
                                    Some(sweep) if txid == view.close.compute_txid() => {
                                        json!({"spent":true,"txid":sweep.compute_txid()}).to_string()
                                    }
                                    _ => json!({"spent":false}).to_string(),
                                }
                            }
                            _ => panic!("unexpected Esplora request {path}"),
                        }
                    }
                },
            ),
        )
        .route(
            "/api/tx",
            axum::routing::post(move |body: String| {
                let view = post_view.clone();
                async move {
                    let raw = hex::decode(body.trim()).unwrap();
                    let tx: Transaction = bitcoin::consensus::deserialize(&raw).unwrap();
                    let txid = tx.compute_txid().to_string();
                    let mut view = view.lock().unwrap();
                    assert!(view.sweep.is_none(), "one sweep only");
                    view.sweep = Some(tx);
                    txid
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (url, server)
}

/// One 30-second recovery pass, returning its progress and HTTP request count.
async fn pass(
    job: &mut Job,
    chain: &EsploraProvider,
    keys: &RecoveryKeys,
    requests: &AtomicUsize,
) -> (Progress, usize) {
    requests.store(0, Ordering::SeqCst);
    let progress = job.advance(chain, keys, keys.scripts()).await.unwrap();
    (progress, requests.load(Ordering::SeqCst))
}

#[tokio::test]
async fn seed_only_recovery_bounds_unconfirmed_polls_and_rescans_before_preview() {
    let keys = RecoveryKeys::from_ldk_seed(&[9; 32]).unwrap();
    assert_eq!(keys.scripts().len(), FULL_PASS_MINIMUM);
    // The hub's close pays B's static to_remote key; in the mempool at first.
    let close = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: keys.scripts()[0].script_pubkey.clone(),
        }],
    };
    let view = Arc::new(Mutex::new(View {
        tip: 100,
        close,
        close_height: None,
        sweep: None,
        sweep_height: None,
    }));
    let requests = Arc::new(AtomicUsize::new(0));
    let (url, server) = serve(view.clone(), requests.clone()).await;
    let chain = EsploraProvider::new(EsploraConfig::custom(url, TrustLevel::ServerTrust)).unwrap();
    let dir = tempfile::tempdir().unwrap();
    recover::initialize(dir.path()).unwrap();
    let plan = Plan::new(
        "node".into(),
        "regtest",
        "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        2,
    )
    .unwrap();
    let mut job = Job::load_or_begin(dir.path(), plan.clone(), vec![]).unwrap();

    let (progress, first) = pass(&mut job, &chain, &keys, &requests).await;
    assert!(matches!(progress, Progress::WaitingForHub), "{progress:?}");
    assert!(
        first >= FULL_PASS_MINIMUM,
        "first pass read {first} requests"
    );

    let (progress, polled) = pass(&mut job, &chain, &keys, &requests).await;
    assert!(matches!(progress, Progress::WaitingForHub), "{progress:?}");
    assert!(
        polled <= NARROWED_PASS_MAXIMUM,
        "unconfirmed-close poll read {polled} requests"
    );

    {
        let mut view = view.lock().unwrap();
        view.tip = 101;
        view.close_height = Some(101);
    }
    let (progress, polled) = pass(&mut job, &chain, &keys, &requests).await;
    let Progress::SweepPreview { sweep, inputs } = progress else {
        panic!("{progress:?}");
    };
    assert!(
        polled >= FULL_PASS_MINIMUM,
        "pre-preview rescan read {polled} requests"
    );
    assert_eq!(inputs.len(), 1);
    assert_eq!(sweep.validate(&plan).unwrap(), 90_000 - sweep.fee_sats);
    let sweep_txid = sweep.tx().unwrap().compute_txid();
    requests.store(0, Ordering::SeqCst);
    job.approve(&chain, sweep, inputs).await.unwrap();
    let consent = requests.load(Ordering::SeqCst);
    assert!(
        consent <= NARROWED_PASS_MAXIMUM,
        "consent recheck read {consent} requests"
    );

    let (progress, polled) = pass(&mut job, &chain, &keys, &requests).await;
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
    assert_eq!(
        view.lock()
            .unwrap()
            .sweep
            .as_ref()
            .map(|t| t.compute_txid()),
        Some(sweep_txid)
    );

    {
        let mut view = view.lock().unwrap();
        view.sweep_height = Some(102);
        view.tip = 107;
    }
    // Six confirmations: the sweep is final and every script is scanned once
    // more for late closes before the self-test.
    let (progress, last) = pass(&mut job, &chain, &keys, &requests).await;
    assert!(matches!(progress, Progress::SelfTest), "{progress:?}");
    assert!(last >= FULL_PASS_MINIMUM, "post-sweep rescan read {last}");
    server.abort();
}
