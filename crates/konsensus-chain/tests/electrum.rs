use konsensus_chain::{ElectrumConfig, ElectrumProvider};
use konsensus_core::traits::chain::{ChainProvider, TrustLevel};
use serde_json::json;

#[path = "support/electrum_fixture.rs"]
mod electrum_fixture;

fn config(url: &str) -> ElectrumConfig {
    serde_json::from_value(json!({"server_url":url})).unwrap()
}

#[test]
fn labels_are_declarations_and_never_upgrade_validation() {
    for (operator, label) in [
        (None, "third_party"),
        (Some("third_party"), "third_party"),
        (Some("own"), "own_node"),
    ] {
        let mut value = json!({"server_url":"tcp://127.0.0.1:50001"});
        if let Some(operator) = operator {
            value["operator"] = json!(operator);
        }
        let provider = ElectrumProvider::new(serde_json::from_value(value).unwrap()).unwrap();
        let view = serde_json::to_value(provider.chain_view()).unwrap();
        assert_eq!(
            view,
            json!({"backend":"electrum","trust_level":label,"host":"127.0.0.1"})
        );
        assert_eq!(provider.trust_level(), TrustLevel::ServerTrust);
    }
}

#[test]
fn plaintext_is_restricted_without_resolving_hostnames() {
    for host in [
        "localhost",
        "127.0.0.2",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "[::1]",
        "[fd12::1]",
        "[::ffff:192.168.1.1]",
        "server.onion",
    ] {
        config(&format!("tcp://{host}:50001"));
    }
    for url in [
        "tcp://8.8.8.8:50001",
        "tcp://[2606:4700::1111]:50001",
        "tcp://[::ffff:8.8.8.8]:50001",
        "tcp://172.32.0.1:50001",
        "tcp://0.0.0.0:50001",
        "tcp://[::]:50001",
        "tcp://umbrel.local:50001",
        "tcp://localhost.evil:50001",
        "tcp://127.1:50001",
        "tcp://2130706433:50001",
        "tcp://0177.0.0.1:50001",
        "ssl://example.org:50002/",
        "ssl://example.org:50002?secret",
        "ssl://example.org:50002#secret",
        "ssl://user:pass@example.org:50002",
        "ssl://example.org:65536",
        "ssl://example.org:+1",
        "ssl://[127.0.0.1]:50002",
        "ssl://[::1]:50002",
        "ssl://[2001:db8::1]:50002",
        "SSL://example.org:50002",
        " ssl://example.org:50002",
    ] {
        assert!(
            serde_json::from_value::<ElectrumConfig>(json!({"server_url":url})).is_err(),
            "accepted {url}"
        );
    }
}

#[tokio::test]
async fn provider_reads_only_the_selected_electrum_and_preserves_unavailable() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let header = bitcoin::consensus::encode::serialize_hex(&genesis.header);
    let tx = genesis.txdata[0].clone();
    let txid = tx.compute_txid().to_string();
    let raw_tx = bitcoin::consensus::encode::serialize_hex(&tx);
    let expected_id = txid.clone();
    let fixture = electrum_fixture::Fixture::new(move |req| {
        let result = match req["method"].as_str().unwrap() {
            "blockchain.headers.subscribe" => json!({"height":101,"hex":header}),
            "blockchain.block.header" => json!(header),
            "blockchain.estimatefee" => {
                if req["params"][0] == 1 {
                    json!(-1)
                } else {
                    json!(0.00002)
                }
            }
            "blockchain.transaction.get" if req["params"][0] == expected_id => json!(raw_tx),
            "blockchain.scripthash.get_history" => json!([{"tx_hash":expected_id,"height":100}]),
            _ => return json!({"error":{"code":-1,"message":"REMOTE_SECRET"}}),
        };
        json!({"result":result})
    })
    .await;
    let provider = ElectrumProvider::new(config(&fixture.url)).unwrap();
    assert_eq!(provider.get_block_height().await.unwrap(), 101);
    let block = provider.get_block_header(0).await.unwrap();
    assert_eq!(block.hash, genesis.block_hash().to_string());
    assert_eq!(block.timestamp, 1296688602);
    assert_eq!(block.bits, 0x207fffff);
    assert_eq!(provider.estimate_fee(6).await.unwrap().sat_per_vbyte, 2.0);
    assert!(provider.estimate_fee(1).await.is_err());
    assert!(provider.tx_visible(&txid).await.unwrap());
    assert!(provider.is_tx_confirmed(&txid, 2).await.unwrap());
    assert!(!provider.is_tx_confirmed(&txid, 3).await.unwrap());
    assert!(provider.is_synced().await);
    let error = provider.tx_visible(&"00".repeat(32)).await.unwrap_err();
    assert!(!error.to_string().contains("REMOTE_SECRET"));
    assert!(fixture
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["method"] == "blockchain.scripthash.get_history"));
}

#[tokio::test]
async fn confirmation_distinguishes_mempool_from_unavailable_or_inconsistent_history() {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let tx = &genesis.txdata[0];
    let txid = tx.compute_txid().to_string();
    for (height, expected) in [(0, Some(false)), (-1, Some(false)), (102, None), (-2, None)] {
        let header = bitcoin::consensus::encode::serialize_hex(&genesis.header);
        let raw = bitcoin::consensus::encode::serialize_hex(tx);
        let expected_id = txid.clone();
        let fixture = electrum_fixture::Fixture::new(move |req| {
            let result = match req["method"].as_str().unwrap() {
                "blockchain.transaction.get" => json!(raw),
                "blockchain.scripthash.get_history" if height == -2 => json!([]),
                "blockchain.scripthash.get_history" => {
                    json!([{"tx_hash":expected_id,"height":height}])
                }
                "blockchain.headers.subscribe" => json!({"height":101,"hex":header}),
                _ => panic!("unexpected Electrum request"),
            };
            json!({"result":result})
        })
        .await;
        let provider = ElectrumProvider::new(config(&fixture.url)).unwrap();
        assert_eq!(provider.is_tx_confirmed(&txid, 1).await.ok(), expected);
        // A server returning another transaction must never prove visibility
        // or confirmation, even if its script history looks confirmed.
        assert!(provider.is_tx_confirmed(&"00".repeat(32), 1).await.is_err());
        assert!(provider.tx_visible(&"00".repeat(32)).await.is_err());
    }
    let fixture = electrum_fixture::Fixture::new(
        |_| json!({"error":{"code":-5,"message":"No such transaction"}}),
    )
    .await;
    let provider = ElectrumProvider::new(config(&fixture.url)).unwrap();
    assert!(provider.is_tx_confirmed(&txid, 1).await.is_err());
    assert!(!provider.is_synced().await);
}

#[tokio::test]
async fn broadcast_visibility_allows_delayed_propagation_but_preserves_other_errors() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    let tx =
        bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).txdata[0].clone();
    let txid = tx.compute_txid().to_string();
    let raw = bitcoin::consensus::encode::serialize_hex(&tx);
    let attempts = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&attempts);
    let fixture =
        electrum_fixture::Fixture::new(move |_| match seen.fetch_add(1, Ordering::SeqCst) {
            0 => json!({"error":{"code":-5,"message":"No such mempool or blockchain transaction"}}),
            1 => json!({"result":raw}),
            _ => json!({"error":{"code":-1,"message":"REMOTE_SECRET"}}),
        })
        .await;
    let provider = ElectrumProvider::new(config(&fixture.url)).unwrap();
    assert!(!provider.tx_visible(&txid).await.unwrap());
    assert!(provider.tx_visible(&txid).await.unwrap());
    assert!(provider.tx_visible(&txid).await.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
    assert_eq!(fixture.requests.lock().unwrap().len(), 3);
}
