use super::*;
use crate::config::{
    ApiConfig, BackupConfig, ChainConfig, IdentityConfig, LightningConfig, NetworkConfig,
    NodeConfig, NodeTier, PaymentGateConfig, PricingConfig, RelayConfig, StorageConfig, WebConfig,
};
use std::collections::HashMap;
use std::path::PathBuf;

/// Helper: create a minimal valid config with a temp mnemonic file.
fn test_config(dir: &std::path::Path) -> NodeConfig {
    let mnemonic_path = dir.join("mnemonic.txt");
    // Valid 24-word BIP-39 mnemonic
    std::fs::write(
        &mnemonic_path,
        "abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art",
    )
    .unwrap();
    NodeConfig {
        services: Default::default(),
        tower: Default::default(),
        node: Default::default(),
        logging: Default::default(),
        privacy: Default::default(),
        disk_free_floor_bytes: 0,
        routing_fees: Default::default(),
        tier: NodeTier::Light,
        identity: IdentityConfig {
            mnemonic_file: mnemonic_path,
            passphrase: String::new(),
            hosted: false,
        },
        network: NetworkConfig::default(),
        lightning: LightningConfig::Mock {
            initial_balance_msat: 100_000_000_000,
        },
        chain: ChainConfig::Mock,
        pricing: PricingConfig::default(),
        payment_gate: PaymentGateConfig::default(),
        storage: StorageConfig::Sqlite {
            path: dir.join("konsensus.db").to_string_lossy().into_owned(),
            encrypted: false,
            retention_days: 0,
        },
        backup: BackupConfig::default(),
        api: ApiConfig::default(),
        remote_access: Default::default(),
        web: WebConfig::default(),
        peers: Vec::new(),
        admission_mode: konsensus_message::ReachabilityMode::Whitelist,
        cookie_mode: konsensus_message::CookieMode::Disabled,
        dos_edge: Default::default(),
        onboarding_subsidy: crate::config::SubsidyConfig::default(),
        sponsor: crate::config::SponsorConfig::default(),
        relay: RelayConfig::default(),
        calls: Default::default(),
    }
}

/// Helper: create a config struct for snapshot tests (no temp dir needed).
fn snapshot_config(storage: StorageConfig) -> NodeConfig {
    NodeConfig {
        services: Default::default(),
        tower: Default::default(),
        node: Default::default(),
        logging: Default::default(),
        privacy: Default::default(),
        disk_free_floor_bytes: 0,
        routing_fees: Default::default(),
        tier: NodeTier::Light,
        identity: IdentityConfig {
            mnemonic_file: PathBuf::from("/tmp/m.txt"),
            passphrase: String::new(),
            hosted: false,
        },
        network: NetworkConfig::default(),
        lightning: LightningConfig::Mock {
            initial_balance_msat: 100_000,
        },
        chain: ChainConfig::Mock,
        pricing: PricingConfig::default(),
        payment_gate: PaymentGateConfig::default(),
        storage,
        backup: BackupConfig::default(),
        api: ApiConfig::default(),
        remote_access: Default::default(),
        web: WebConfig::default(),
        peers: Vec::new(),
        admission_mode: konsensus_message::ReachabilityMode::Whitelist,
        cookie_mode: konsensus_message::CookieMode::Disabled,
        dos_edge: Default::default(),
        onboarding_subsidy: crate::config::SubsidyConfig::default(),
        sponsor: crate::config::SponsorConfig::default(),
        relay: RelayConfig::default(),
        calls: Default::default(),
    }
}

// ── from_config tests ──────────────────────────────────────────────

#[tokio::test]
async fn from_config_mock_backends() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    let node = KonsensusNode::from_config(config, None).await.unwrap();
    assert_eq!(node.node_id().to_hex().len(), 64);
    let reg = node.peer_registry().read().await;
    assert_eq!(reg.len(), 0);
}

#[tokio::test]
async fn from_config_with_encrypted_storage() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.storage = StorageConfig::Sqlite {
        path: dir.path().join("enc.db").to_string_lossy().into_owned(),
        encrypted: true,
        retention_days: 0,
    };
    let node = KonsensusNode::from_config(config, None).await.unwrap();
    assert_eq!(node.node_id().to_hex().len(), 64);
}

#[tokio::test]
async fn from_config_missing_mnemonic_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.identity.mnemonic_file = dir.path().join("missing_mnemonic.txt");
    let err = KonsensusNode::from_config(config, None)
        .await
        .err()
        .expect("should fail");
    assert!(
        err.to_string().contains("failed to read mnemonic"),
        "got: {err}"
    );
}

#[tokio::test]
async fn from_config_invalid_mnemonic_fails() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    std::fs::write(
        &config.identity.mnemonic_file,
        "not a valid mnemonic at all",
    )
    .unwrap();
    let err = KonsensusNode::from_config(config, None)
        .await
        .err()
        .expect("should fail");
    assert!(
        err.to_string().contains("mnemonic") || err.to_string().contains("identity"),
        "got: {err}"
    );
}

#[tokio::test]
async fn from_config_empty_mnemonic_fails() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    std::fs::write(&config.identity.mnemonic_file, "").unwrap();
    let err = KonsensusNode::from_config(config, None)
        .await
        .err()
        .expect("should fail");
    assert!(err.to_string().contains("mnemonic") || err.to_string().contains("identity"));
}

#[tokio::test]
async fn from_config_chain_aware_pricing() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.pricing.mode = crate::config::PricingMode::ChainAware;
    let node = KonsensusNode::from_config(config, None).await.unwrap();
    assert_eq!(node.node_id().to_hex().len(), 64);
}

#[tokio::test]
async fn from_config_with_peers() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.peers.push(crate::config::PeerConfigEntry {
        node_id: "ab".repeat(32),
        addr: "10.0.0.1:9735".parse().unwrap(),
        label: Some("test-peer".to_string()),
        auto_connect: false,
    });
    let node = KonsensusNode::from_config(config, None).await.unwrap();
    let reg = node.peer_registry().read().await;
    assert_eq!(reg.len(), 1);
}

#[tokio::test]
async fn from_config_with_multiple_peers() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    for i in 0..3u8 {
        let hex = format!("{:02x}", i).repeat(32);
        config.peers.push(crate::config::PeerConfigEntry {
            node_id: hex,
            addr: format!("10.0.0.{}:9735", i + 1).parse().unwrap(),
            label: Some(format!("peer-{i}")),
            auto_connect: i == 0,
        });
    }
    let node = KonsensusNode::from_config(config, None).await.unwrap();
    let reg = node.peer_registry().read().await;
    assert_eq!(reg.len(), 3);
}

#[tokio::test]
async fn from_config_invalid_peer_node_id_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.peers.push(crate::config::PeerConfigEntry {
        node_id: "not-valid-hex".to_string(),
        addr: "10.0.0.1:9735".parse().unwrap(),
        label: None,
        auto_connect: true,
    });
    let err = KonsensusNode::from_config(config, None)
        .await
        .err()
        .expect("should fail");
    assert!(err.to_string().contains("invalid node_id"), "got: {err}");
}

#[tokio::test]
async fn from_config_deterministic_identity() {
    let dir = tempfile::tempdir().unwrap();
    let config1 = test_config(dir.path());
    let config2 = test_config(dir.path());
    let node1 = KonsensusNode::from_config(config1, None).await.unwrap();
    let first_id = node1.node_id().to_hex();
    drop(node1); // A retained directory may have only one live state owner.
    let node2 = KonsensusNode::from_config(config2, None).await.unwrap();
    assert_eq!(
        first_id,
        node2.node_id().to_hex(),
        "same mnemonic should produce same identity"
    );
}

#[tokio::test]
async fn from_config_different_passphrase_different_identity() {
    let dir = tempfile::tempdir().unwrap();
    let mut config1 = test_config(dir.path());
    let mut config2 = test_config(dir.path());
    config1.identity.passphrase = "alpha".to_string();
    config2.identity.passphrase = "beta".to_string();
    let node1 = KonsensusNode::from_config(config1, None).await.unwrap();
    let first_id = node1.node_id().to_hex();
    drop(node1); // A retained directory may have only one live state owner.
    let node2 = KonsensusNode::from_config(config2, None).await.unwrap();
    assert_ne!(
        first_id,
        node2.node_id().to_hex(),
        "different passphrases should produce different identities"
    );
}

#[tokio::test]
async fn shutdown_signal_propagates() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    let node = KonsensusNode::from_config(config, None).await.unwrap();
    let mut rx = node.shutdown_rx();
    assert!(!*rx.borrow(), "shutdown should start as false");
    node.shutdown();
    rx.changed().await.unwrap();
    assert!(*rx.borrow(), "shutdown should be true after signal");
}

// ── Fee rate snapshot tests ────────────────────────────────────────

#[test]
fn fee_rate_snapshot_path_sqlite() {
    let config = snapshot_config(StorageConfig::Sqlite {
        path: "/data/konsensus/node.db".to_string(),
        encrypted: false,
        retention_days: 0,
    });
    let path = KonsensusNode::fee_rate_snapshot_path(&config);
    assert_eq!(
        path,
        std::path::PathBuf::from("/data/konsensus/fee_rate_snapshot.json")
    );
}

#[test]
fn fee_rate_snapshot_path_postgres_uses_cwd() {
    let config = snapshot_config(StorageConfig::Postgres {
        url: "postgres://localhost/konsensus".to_string(),
        encrypted: false,
        retention_days: 0,
    });
    let path = KonsensusNode::fee_rate_snapshot_path(&config);
    assert_eq!(path, std::path::PathBuf::from("./fee_rate_snapshot.json"));
}

#[test]
fn load_fee_rate_snapshot_missing_file_returns_none() {
    let path = std::path::Path::new("/nonexistent/snapshot.json");
    assert!(KonsensusNode::load_fee_rate_snapshot(path).is_none());
}

#[test]
fn load_fee_rate_snapshot_invalid_json_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad_snapshot.json");
    std::fs::write(&path, "not valid json {{{").unwrap();
    assert!(KonsensusNode::load_fee_rate_snapshot(&path).is_none());
}

#[test]
fn load_fee_rate_snapshot_empty_file_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.json");
    std::fs::write(&path, "").unwrap();
    assert!(KonsensusNode::load_fee_rate_snapshot(&path).is_none());
}

#[test]
fn load_fee_rate_snapshot_valid_json() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("snapshot.json");
    let mut targets = HashMap::new();
    targets.insert(6, 5.0);
    let snapshot = konsensus_pricing::FeeRateSnapshot {
        targets,
        block_height: 840_000,
        timestamp_secs: 1700000000,
    };
    std::fs::write(&path, serde_json::to_string(&snapshot).unwrap()).unwrap();
    let loaded = KonsensusNode::load_fee_rate_snapshot(&path).unwrap();
    assert!((loaded.targets[&6] - 5.0).abs() < f64::EPSILON);
    assert_eq!(loaded.block_height, 840_000);
    assert_eq!(loaded.timestamp_secs, 1700000000);
}

#[test]
fn save_and_load_fee_rate_snapshot_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let config = snapshot_config(StorageConfig::Sqlite {
        path: dir.path().join("node.db").to_string_lossy().into_owned(),
        encrypted: false,
        retention_days: 0,
    });
    let mut targets = HashMap::new();
    targets.insert(6, 12.5);
    targets.insert(3, 25.0);
    let snapshot = konsensus_pricing::FeeRateSnapshot {
        targets,
        block_height: 841_000,
        timestamp_secs: 1700001000,
    };
    KonsensusNode::save_fee_rate_snapshot(&config, &snapshot);

    let path = KonsensusNode::fee_rate_snapshot_path(&config);
    let loaded = KonsensusNode::load_fee_rate_snapshot(&path).unwrap();
    assert!((loaded.targets[&6] - 12.5).abs() < f64::EPSILON);
    assert!((loaded.targets[&3] - 25.0).abs() < f64::EPSILON);
    assert_eq!(loaded.block_height, 841_000);
}

#[test]
fn save_fee_rate_snapshot_to_nonexistent_dir_does_not_panic() {
    let config = snapshot_config(StorageConfig::Sqlite {
        path: "/nonexistent/deep/path/node.db".to_string(),
        encrypted: false,
        retention_days: 0,
    });
    let snapshot = konsensus_pricing::FeeRateSnapshot {
        targets: HashMap::new(),
        block_height: 800_000,
        timestamp_secs: 1600000000,
    };
    // Should not panic — just logs a warning
    KonsensusNode::save_fee_rate_snapshot(&config, &snapshot);
}

#[test]
fn save_fee_rate_snapshot_overwrites_existing() {
    let dir = tempfile::tempdir().unwrap();
    let config = snapshot_config(StorageConfig::Sqlite {
        path: dir.path().join("node.db").to_string_lossy().into_owned(),
        encrypted: false,
        retention_days: 0,
    });
    let mut targets1 = HashMap::new();
    targets1.insert(6, 10.0);
    let snapshot1 = konsensus_pricing::FeeRateSnapshot {
        targets: targets1,
        block_height: 100,
        timestamp_secs: 1000,
    };
    KonsensusNode::save_fee_rate_snapshot(&config, &snapshot1);

    let mut targets2 = HashMap::new();
    targets2.insert(6, 20.0);
    let snapshot2 = konsensus_pricing::FeeRateSnapshot {
        targets: targets2,
        block_height: 200,
        timestamp_secs: 2000,
    };
    KonsensusNode::save_fee_rate_snapshot(&config, &snapshot2);

    let path = KonsensusNode::fee_rate_snapshot_path(&config);
    let loaded = KonsensusNode::load_fee_rate_snapshot(&path).unwrap();
    assert_eq!(
        loaded.block_height, 200,
        "second save should overwrite first"
    );
}

// ── Accessor tests ─────────────────────────────────────────────────

#[tokio::test]
async fn node_accessors_return_expected_types() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    let node = KonsensusNode::from_config(config, None).await.unwrap();

    assert_eq!(node.identity().node_id(), node.node_id());
    assert!(node.lightning().is_available().await);
    assert!(node.config().pricing.chat_msat > 0);
}

#[tokio::test]
async fn from_config_chain_aware_with_ema_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.pricing.mode = crate::config::PricingMode::ChainAware;

    // Write a snapshot file before building the node
    let mut targets = HashMap::new();
    targets.insert(6, 8.0);
    let snapshot = konsensus_pricing::FeeRateSnapshot {
        targets,
        block_height: 840_500,
        timestamp_secs: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };
    let snapshot_path = dir.path().join("fee_rate_snapshot.json");
    std::fs::write(&snapshot_path, serde_json::to_string(&snapshot).unwrap()).unwrap();

    let node = KonsensusNode::from_config(config, None).await.unwrap();
    assert_eq!(node.node_id().to_hex().len(), 64);
}

#[tokio::test]
async fn from_config_mnemonic_with_extra_whitespace() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    // Add leading/trailing whitespace — from_config should trim it
    let mnemonic = "  abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon abandon abandon art  \n";
    std::fs::write(&config.identity.mnemonic_file, mnemonic).unwrap();
    let node = KonsensusNode::from_config(config, None).await.unwrap();
    assert_eq!(node.node_id().to_hex().len(), 64);
}

#[tokio::test]
async fn from_config_lnbits_lightning_provider() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.lightning = LightningConfig::Lnbits {
        api_url: "http://localhost:5000".to_string(),
        admin_key: "test-key".to_string(),
    };
    let error = match KonsensusNode::from_config(config, None).await {
        Ok(_) => panic!("LNbits must fail at startup, before any payment"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("not_supported") && error.contains("LNbits"));
}

// BOOT-2: exhaustion of the real fee barrier must preserve local services.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn offline_fee_barrier_preserves_local_identity_and_storage() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    let expected = *KonsensusNode::from_config(config.clone(), None).await.unwrap().node_id();
    config.lightning = LightningConfig::Ldk {
        forward_to_private_channels: false,
        our_to_self_delay_blocks: None,
        lsps2_service: Default::default(),
        onchain_wallet_sync_interval_secs: None,
        lightning_wallet_sync_interval_secs: None,
        fee_rate_cache_update_interval_secs: None,
        liquidity: Default::default(), network: "bitcoin".into(),
        esplora_url: "http://127.0.0.1:1".into(), esplora_url_fallback: None, credentials_file: None,
        rgs_url: None, lsp_node_id: None, lsp_address: None, lsp_token: None,
        listening_address: None, advertised_address: None,
    };
    let node = KonsensusNode::from_config(config, None).await
        .expect("fee outage must leave local services available");
    assert_eq!(*node.node_id(), expected);
    assert!(!node.lightning().is_available().await);
    assert_eq!(node.storage().count_pending_deliveries().await.unwrap(), 0);
    let error = node.lightning().create_invoice(1000, "offline", 60).await.unwrap_err();
    assert!(error.to_string().contains("not_ready"), "{error}");
    node.lightning().shutdown().await.unwrap();
}

#[tokio::test]
async fn disk_guard_refuses_new_work_but_preserves_reads_closes_and_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = test_config(dir.path());
    config.disk_free_floor_bytes = u64::MAX;
    let node = KonsensusNode::from_config(config, None).await.unwrap();
    let ln = node.lightning();
    assert!(ln.disk_status().unwrap().disk_low);
    assert!(ln.disk_status().unwrap().disk_free_bytes.is_some());
    assert!(ln
        .create_invoice(1000, "new work", 60)
        .await
        .unwrap_err()
        .to_string()
        .contains("disk_low"));
    assert!(ln
        .pay_invoice("invalid invoice")
        .await
        .unwrap_err()
        .to_string()
        .contains("disk_low"));
    assert!(ln
        .open_channel("peer", "address", 10000, false, None)
        .await
        .unwrap_err()
        .to_string()
        .contains("disk_low"));
    let refused = [
        ln.create_stateless_invoice(1000, "quote", 60)
            .await
            .unwrap_err(),
        ln.create_hodl_invoice("hash", 1000, "hold", 60)
            .await
            .unwrap_err(),
        ln.pay_invoice_with_fee_limit("invoice", 1000)
            .await
            .unwrap_err(),
        ln.keysend("peer", 1000, None).await.unwrap_err(),
        ln.keysend_with_fee_limit("peer", 1000, None, 1000)
            .await
            .unwrap_err(),
        ln.keysend_with_binding("peer", 1000, &[1])
            .await
            .unwrap_err(),
        ln.quote_liquidity("owner", 1000, 1000).await.unwrap_err(),
        ln.accept_liquidity("owner", "quote").await.unwrap_err(),
    ];
    for error in refused {
        assert!(error.to_string().contains("disk_low"));
    }
    assert_eq!(ln.get_balance_msat().await.unwrap(), 100_000_000_000);
    assert!(ln.list_channels().await.is_ok());
    // Mock does not support closes; its own error proves the disk guard allows dispatch.
    let close = ln
        .close_channel("channel", false)
        .await
        .unwrap_err()
        .to_string();
    assert!(!close.contains("disk_low"));
    assert!(ln.shutdown().await.is_ok());
    node.shutdown();
}

#[tokio::test]
async fn newer_generation_refused_before_database_creation() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(dir.path());
    crate::safety::ensure_generation(dir.path(), u64::MAX).unwrap();
    let err = KonsensusNode::from_config(config, None)
        .await
        .err()
        .expect("must refuse");
    assert!(err.to_string().contains("state_generation_newer"));
    assert!(!dir.path().join("konsensus.db").exists());
}

#[tokio::test]
async fn state_lease_outlives_cloned_lightning_handle() {
    let dir = tempfile::tempdir().unwrap();
    let node = KonsensusNode::from_config(test_config(dir.path()), None)
        .await
        .unwrap();
    let lightning = node.lightning().clone();
    drop(node);
    assert!(crate::safety::ensure_generation(dir.path(), 2)
        .unwrap_err()
        .to_string()
        .contains("state_generation_busy"));
    lightning.shutdown().await.unwrap();
    drop(lightning);
    crate::safety::ensure_generation(dir.path(), 2).unwrap();
}
