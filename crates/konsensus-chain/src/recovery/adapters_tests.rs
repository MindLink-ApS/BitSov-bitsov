use super::*;
use crate::{
    BitcoindConfig, BitcoindProvider, ElectrumConfig, ElectrumOperator, ElectrumProvider,
    EsploraConfig, EsploraProvider,
};
use bitcoin::{absolute, transaction, Amount, OutPoint, Transaction, TxIn, TxOut};
use konsensus_core::traits::chain::TrustLevel;
use konsensus_recovery::RecoveryKeys;
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

fn fixture() -> (RecoveryKeys, Transaction) {
    let keys = RecoveryKeys::from_ldk_seed(&[5; 32]).unwrap();
    let tx = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(55_000),
            script_pubkey: keys.scripts()[0].script_pubkey.clone(),
        }],
    };
    (keys, tx)
}

#[tokio::test]
async fn esplora_long_scan_allows_new_blocks_during_script_discovery() {
    let advanced = Arc::new(AtomicBool::new(false));
    let server_advanced = advanced.clone();
    let app = axum::Router::new().route(
        "/api/*path",
        axum::routing::get(
            move |axum::extract::Path(path): axum::extract::Path<String>| {
                let advanced = server_advanced.clone();
                async move {
                    match path.as_str() {
                        "blocks/tip/hash" => if advanced.load(Ordering::SeqCst) {
                            "bb"
                        } else {
                            "aa"
                        }
                        .repeat(32),
                        p if p.starts_with("block/") => {
                            json!({"height":if advanced.load(Ordering::SeqCst) { 21 } else { 20 }})
                                .to_string()
                        }
                        p if p.ends_with("/utxo") => {
                            advanced.store(true, Ordering::SeqCst);
                            "[]".into()
                        }
                        _ => panic!("unexpected request {path}"),
                    }
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let chain = EsploraProvider::new(EsploraConfig::custom(url, TrustLevel::ServerTrust)).unwrap();
    let keys = RecoveryKeys::from_ldk_seed(&[5; 32]).unwrap();
    assert!(chain.scan(&keys.scripts()[..2]).await.unwrap().is_empty());
    server.abort();
}
#[tokio::test]
async fn esplora_authenticates_prevouts_and_rechecks_mempool_spends() {
    let (keys, tx) = fixture();
    let txid = tx.compute_txid();
    let raw = bitcoin::consensus::encode::serialize_hex(&tx);
    let bad = Arc::new(AtomicBool::new(false));
    let spent = Arc::new(AtomicBool::new(false));
    let bad_server = bad.clone();
    let spent_server = spent.clone();
    let app = axum::Router::new().route("/api/*path", axum::routing::get(move |axum::extract::Path(path): axum::extract::Path<String>| {
        let bad = bad_server.clone(); let spent = spent_server.clone(); let raw = raw.clone();
        async move {
            match path.as_str() {
                "blocks/tip/hash" | "block-height/19" => "ab".repeat(32),
                p if p.starts_with("block/") => json!({"height":20}).to_string(),
                p if p.ends_with("/utxo") => json!([{"txid":txid,"vout":0,"value":if bad.load(Ordering::SeqCst) { 55_001 } else { 55_000 },"status":{"confirmed":true,"block_height":19,"block_hash":"ab".repeat(32)}}]).to_string(),
                p if p.ends_with("/hex") => raw,
                p if p.contains("/outspend/") => json!({"spent":spent.load(Ordering::SeqCst)}).to_string(),
                p if p.ends_with("/status") => json!({"confirmed":true,"block_height":19,"block_hash":"ab".repeat(32)}).to_string(),
                _ => panic!("unexpected Esplora request {path}"),
            }
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let chain = EsploraProvider::new(EsploraConfig::custom(url, TrustLevel::ServerTrust)).unwrap();
    let outputs = chain.scan(&keys.scripts()[..1]).await.unwrap();
    assert_eq!(outputs[0].txout, tx.output[0]);
    assert_eq!(outputs[0].confirmations, 2);
    assert!(chain.recheck(&outputs).await.unwrap());
    assert_eq!(
        chain.transaction(txid).await.unwrap().unwrap().transaction,
        tx
    );
    spent.store(true, Ordering::SeqCst);
    assert!(!chain.recheck(&outputs).await.unwrap());
    bad.store(true, Ordering::SeqCst);
    assert!(chain.scan(&keys.scripts()[..1]).await.is_err());
    server.abort();
}
#[tokio::test]
async fn core_scan_excludes_mempool_spends_and_rejects_changed_prevouts() {
    let (keys, tx) = fixture();
    let txid = tx.compute_txid();
    let script = tx.output[0].script_pubkey.to_hex_string();
    let bad = Arc::new(AtomicBool::new(false));
    let spent = Arc::new(AtomicBool::new(false));
    let bad_server = bad.clone();
    let spent_server = spent.clone();
    let app = axum::Router::new().route("/", axum::routing::post(move |axum::Json(body): axum::Json<Value>| {
        let bad = bad_server.clone(); let spent = spent_server.clone(); let script = script.clone();
        async move {
            let result = match body["method"].as_str().unwrap() {
                "getblockchaininfo" => json!({"initialblockdownload":false,"blocks":20,"headers":20,"bestblockhash":"ab".repeat(32)}),
                "scantxoutset" => json!({"success":true,"bestblock":"ab".repeat(32),"height":20,"unspents":[{"txid":txid,"vout":0,"height":19,"amount":0.00055,"scriptPubKey":script}]}),
                "gettxout" if spent.load(Ordering::SeqCst) => Value::Null,
                "gettxout" => json!({"bestblock":"ab".repeat(32),"confirmations":2,"value":if bad.load(Ordering::SeqCst) { 0.00056 } else { 0.00055 },"scriptPubKey":{"hex":script}}),
                method => panic!("unexpected Core request {method}"),
            }; axum::Json(json!({"result":result,"error":null,"id":1}))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let password = dir.path().join("password");
    std::fs::write(&password, "fixture").unwrap();
    let chain = BitcoindProvider::new(BitcoindConfig {
        rpc_host: "127.0.0.1".into(),
        rpc_port: port,
        cookie_file: None,
        rpc_user: Some("fixture".into()),
        rpc_password_file: Some(password),
    })
    .unwrap();
    let outputs = chain.scan(&keys.scripts()[..1]).await.unwrap();
    assert_eq!(outputs[0].txout, tx.output[0]);
    spent.store(true, Ordering::SeqCst);
    assert!(chain.scan(&keys.scripts()[..1]).await.unwrap().is_empty());
    spent.store(false, Ordering::SeqCst);
    bad.store(true, Ordering::SeqCst);
    assert!(chain.scan(&keys.scripts()[..1]).await.is_err());
    server.abort();
}
#[tokio::test]
async fn electrum_batch_authenticates_raw_amounts_and_scripts() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    let (keys, tx) = fixture();
    let txid = tx.compute_txid();
    let raw = bitcoin::consensus::encode::serialize_hex(&tx);
    let header = bitcoin::consensus::encode::serialize_hex(
        &bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
    );
    let bad = Arc::new(AtomicBool::new(false));
    let bad_server = bad.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let raw = raw.clone();
            let header = header.clone();
            let bad = bad_server.clone();
            tokio::spawn(async move {
                let (read, mut write) = socket.into_split();
                let mut lines = tokio::io::BufReader::new(read).lines();
                while let Some(line) = lines.next_line().await.unwrap() {
                    let request: Value = serde_json::from_str(&line).unwrap();
                    let result = match request["method"].as_str().unwrap() {
                        "blockchain.headers.subscribe" => json!({"height":20,"hex":header}),
                        "blockchain.scripthash.listunspent" => {
                            json!([{"tx_hash":txid,"tx_pos":0,"height":19,"value":if bad.load(Ordering::SeqCst) { 55_001 } else { 55_000 }}])
                        }
                        "blockchain.transaction.get" => json!(raw),
                        method => panic!("unexpected Electrum request {method}"),
                    };
                    let reply = format!(
                        "{}\n",
                        json!({"jsonrpc":"2.0","id":request["id"],"result":result})
                    );
                    write.write_all(reply.as_bytes()).await.unwrap();
                }
            });
        }
    });
    let chain = ElectrumProvider::new(ElectrumConfig {
        server_url: format!("tcp://{address}"),
        operator: ElectrumOperator::Own,
    })
    .unwrap();
    let outputs = chain.scan(&keys.scripts()[..1]).await.unwrap();
    assert_eq!(outputs[0].txout, tx.output[0]);
    assert_eq!(outputs[0].confirmations, 2);
    bad.store(true, Ordering::SeqCst);
    assert!(chain.scan(&keys.scripts()[..1]).await.is_err());
    server.abort();
}
