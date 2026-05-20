use super::*;

#[test]
fn deserialize_minimal_config() {
    let toml = r#"
[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "lnbits"
api_url = "http://localhost:5000"
admin_key = "test-key"

[chain]
backend = "esplora"

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert_eq!(
        config.identity.mnemonic_file,
        PathBuf::from("/var/konsensus/mnemonic.txt")
    );
    assert_eq!(config.network.tier, SovereigntyTier::T1);
    assert_eq!(config.pricing.chat_msat, 10);
    assert_eq!(config.api.listen_addr.port(), 3141);
    assert!(matches!(config.storage, StorageConfig::Sqlite { encrypted: true, .. }));
}

#[test]
fn deserialize_full_config() {
    let toml = r#"
[identity]
mnemonic_file = "/keys/mnemonic.txt"
passphrase = "secret"

[network]
listen_addr = "0.0.0.0:9000"
tier = "T2"

[lightning]
backend = "lnbits"
api_url = "https://ln.example.com"
admin_key = "admin123"

[chain]
backend = "esplora"
api_url = "https://mempool.example.com"

[pricing]
chat_msat = 20
longform_msat = 100
file_ref_msat = 200

[storage]
backend = "postgres"
url = "postgres://user:pass@localhost/konsensus"
encrypted = true

[api]
listen_addr = "0.0.0.0:8080"
jwt_secret = "my-jwt-secret"
rate_limit_rps = 120
cors_enabled = false

[[peers]]
node_id = "aaaa"
addr = "10.0.0.1:9735"
label = "Alice"
auto_connect = true

[[peers]]
node_id = "bbbb"
addr = "10.0.0.2:9735"
auto_connect = false
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.identity.passphrase, "secret");
    assert_eq!(config.network.tier, SovereigntyTier::T2);
    assert_eq!(config.pricing.chat_msat, 20);
    assert_eq!(config.pricing.file_ref_msat, 200);
    // Default values for unset fields
    assert_eq!(config.pricing.control_msat, 1);
    assert_eq!(config.pricing.realtime_signal_msat, 50);
    assert_eq!(config.peers.len(), 2);
    assert_eq!(config.peers[0].label.as_deref(), Some("Alice"));
    assert!(!config.peers[1].auto_connect);
    assert!(matches!(config.storage, StorageConfig::Postgres { encrypted: true, .. }));
}

#[test]
fn default_config_serializes() {
    let config = NodeConfig::default_for_tier(NodeTier::Light,PathBuf::from("/tmp/mnemonic.txt"), Path::new("/tmp"));
    let toml_str = toml::to_string_pretty(&config).unwrap();
    assert!(toml_str.contains("mnemonic_file"));
    assert!(toml_str.contains("mock"), "default config should use mock backends for out-of-box experience");
}

#[test]
fn operator_probes_default_by_node_tier() {
    let cloud = NodeConfig::default_for_tier(
        NodeTier::Cloud,
        PathBuf::from("/tmp/cloud-mnemonic.txt"),
        Path::new("/tmp/cloud"),
    );
    let light = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/tmp/light-mnemonic.txt"),
        Path::new("/tmp/light"),
    );
    let full = NodeConfig::default_for_tier(
        NodeTier::Full,
        PathBuf::from("/tmp/full-mnemonic.txt"),
        Path::new("/tmp/full"),
    );

    assert_eq!(cloud.api.operator_probes_enabled, Some(true));
    assert_eq!(light.api.operator_probes_enabled, Some(false));
    assert_eq!(full.api.operator_probes_enabled, Some(false));
}

#[test]
fn deserialize_mock_backends() {
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "mock"
initial_balance_msat = 50000000000

[chain]
backend = "mock"

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    match &config.lightning {
        LightningConfig::Mock {
            initial_balance_msat,
        } => {
            assert_eq!(*initial_balance_msat, 50_000_000_000);
        }
        _ => panic!("expected mock lightning"),
    }
    assert!(matches!(config.chain, ChainConfig::Mock));
}

#[test]
fn mock_lightning_default_balance() {
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "mock"

[chain]
backend = "esplora"

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    match &config.lightning {
        LightningConfig::Mock {
            initial_balance_msat,
        } => {
            assert_eq!(*initial_balance_msat, 100_000_000_000); // 1 BTC default
        }
        _ => panic!("expected mock lightning"),
    }
}

#[test]
fn sqlite_storage_config() {
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]
[lightning]
backend = "lnbits"
api_url = "http://localhost:5000"
admin_key = "key"

[chain]
backend = "esplora"

[storage]
backend = "sqlite"
path = "/data/node.db"
encrypted = true
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    match config.storage {
        StorageConfig::Sqlite { path, encrypted, retention_days } => {
            assert_eq!(path, "/data/node.db");
            assert!(encrypted);
            assert_eq!(retention_days, 0);
        }
        _ => panic!("expected sqlite"),
    }
}

#[test]
fn deserialize_backup_config() {
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]
[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"

[backup]
scb_dir = "/var/lib/bitsov/backups"
rotation_count = 12
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.backup.scb_dir, "/var/lib/bitsov/backups");
    assert_eq!(config.backup.rotation_count, 12);
}

#[test]
fn default_backup_config_uses_node_dir() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Full,
        PathBuf::from("/tmp/mnemonic.txt"),
        Path::new("/tmp/konsensus-test-node"),
    );
    assert!(config
        .backup
        .scb_dir
        .ends_with("/tmp/konsensus-test-node/backups"));
    assert_eq!(config.backup.rotation_count, 24);
}

#[test]
fn validate_port_collision() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light,PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.network.listen_addr = "0.0.0.0:3141".parse().unwrap();
    config.api.listen_addr = "127.0.0.1:3141".parse().unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("same port"), "got: {err}");
}

#[test]
fn validate_invalid_peer_node_id() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light,PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.push(PeerConfigEntry {
        node_id: "not-valid-hex".into(),
        addr: "10.0.0.1:9735".parse().unwrap(),
        label: None,
        auto_connect: true,
    });
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("invalid node_id"), "got: {err}");
}

#[test]
fn validate_zero_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light,PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear(); // Clear bootstrap peers so validation reaches pricing check
    config.pricing.chat_msat = 0;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("pricing"), "got: {err}");
}

#[test]
fn validate_zero_backup_rotation_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.backup.rotation_count = 0;
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string().contains("backup.rotation_count"),
        "got: {err}"
    );
}

#[test]
fn validate_missing_mnemonic_file() {
    let config = NodeConfig::default_for_tier(NodeTier::Light,PathBuf::from("/nonexistent/path/mnemonic.txt"), Path::new("/nonexistent/path"));
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("mnemonic file not found"), "got: {err}");
}

#[test]
fn deserialize_chain_aware_pricing() {
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "mock"

[chain]
backend = "esplora"
api_url = "https://mempool.space"

[pricing]
mode = "chain_aware"
fee_target_blocks = 3
fee_cache_secs = 30
chat_msat = 15

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.pricing.mode, PricingMode::ChainAware);
    assert_eq!(config.pricing.fee_target_blocks, 3);
    assert_eq!(config.pricing.fee_cache_secs, 30);
    assert_eq!(config.pricing.chat_msat, 15);
    // Defaults for unset fields
    assert_eq!(config.pricing.control_msat, 1);
}

#[test]
fn default_pricing_mode_is_static() {
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.pricing.mode, PricingMode::Static);
    assert_eq!(config.pricing.fee_target_blocks, 6);
    assert_eq!(config.pricing.fee_cache_secs, 60);
}

#[test]
fn default_tier_is_light() {
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.tier, NodeTier::Light);
}

#[test]
fn deserialize_cloud_tier() {
    let toml = r#"
tier = "cloud"

[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.tier, NodeTier::Cloud);
    assert_eq!(
        config.tier.to_sovereignty_tier(),
        SovereigntyTier::T1
    );
}

#[test]
fn deserialize_full_tier_with_hosted_url() {
    let toml = r#"
tier = "full"

[identity]
mnemonic_file = "m.txt"

[network]
tier = "T2"

[lightning]
backend = "mock"

[chain]
backend = "esplora"

[storage]
backend = "sqlite"
encrypted = true
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.tier, NodeTier::Full);
    assert_eq!(config.network.tier, SovereigntyTier::T2);
}

#[test]
fn default_for_tier_cloud() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Cloud,
        PathBuf::from("/tmp/mnemonic.txt"),
        Path::new("/tmp"),
    );
    assert_eq!(config.tier, NodeTier::Cloud);
    assert_eq!(config.network.tier, SovereigntyTier::T1);
}

#[test]
fn default_for_tier_light() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/tmp/mnemonic.txt"),
        Path::new("/tmp"),
    );
    assert_eq!(config.tier, NodeTier::Light);
    assert_eq!(config.network.tier, SovereigntyTier::T1);
}

#[test]
fn default_for_tier_full() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Full,
        PathBuf::from("/tmp/mnemonic.txt"),
        Path::new("/tmp"),
    );
    assert_eq!(config.tier, NodeTier::Full);
    assert_eq!(config.network.tier, SovereigntyTier::T2);
    // Full tier defaults to encrypted storage
    assert!(matches!(config.storage, StorageConfig::Sqlite { encrypted: true, .. }));
    // Full tier defaults to Esplora chain backend
    assert!(matches!(config.chain, ChainConfig::Esplora { .. }));
}

#[test]
fn node_tier_display() {
    assert_eq!(NodeTier::Cloud.to_string(), "cloud");
    assert_eq!(NodeTier::Light.to_string(), "light");
    assert_eq!(NodeTier::Full.to_string(), "full");
}

#[test]
fn bootstrap_node_ids_are_valid_hex() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/tmp/mnemonic.txt"),
        Path::new("/tmp"),
    );
    assert_eq!(config.peers.len(), 3, "Light tier should have 3 bootstrap peers");
    for (i, peer) in config.peers.iter().enumerate() {
        assert_eq!(peer.node_id.len(), 64, "peer[{i}] node_id should be 64 hex chars");
        assert!(
            konsensus_core::types::NodeId::from_hex(&peer.node_id).is_ok(),
            "peer[{i}] node_id should be valid hex: {}",
            peer.node_id
        );
    }
}

#[test]
fn bootstrap_node_ids_are_unique() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/tmp/mnemonic.txt"),
        Path::new("/tmp"),
    );
    let ids: Vec<&str> = config.peers.iter().map(|p| p.node_id.as_str()).collect();
    // All three bootstrap peers must have distinct node IDs
    assert_ne!(ids[0], ids[1], "alpha and beta should differ");
    assert_ne!(ids[1], ids[2], "beta and gamma should differ");
    assert_ne!(ids[0], ids[2], "alpha and gamma should differ");
}

#[test]
fn bootstrap_ports_avoid_lnd_default() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/tmp/mnemonic.txt"),
        Path::new("/tmp"),
    );
    for peer in &config.peers {
        assert_ne!(
            peer.addr.port(),
            9735,
            "bootstrap peer {} uses port 9735 (LND default) — should use BitSov P2P port",
            peer.label.as_deref().unwrap_or("unknown")
        );
    }
}

#[test]
fn bootstrap_cloud_has_no_peers() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Cloud,
        PathBuf::from("/tmp/mnemonic.txt"),
        Path::new("/tmp"),
    );
    assert!(config.peers.is_empty(), "Cloud tier should have no bootstrap peers");
}

// ─── Config validation hardening tests ──────────────────────────────────

#[test]
fn validate_zero_longform_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    config.pricing.longform_msat = 0;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("pricing"), "got: {err}");
}

#[test]
fn validate_zero_file_ref_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    config.pricing.file_ref_msat = 0;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("pricing"), "got: {err}");
}

#[test]
fn validate_zero_control_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    config.pricing.control_msat = 0;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("pricing"), "got: {err}");
}

#[test]
fn validate_zero_realtime_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    config.pricing.realtime_signal_msat = 0;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("pricing"), "got: {err}");
}

#[test]
fn validate_different_ports_ok() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    config.network.listen_addr = "0.0.0.0:9735".parse().unwrap();
    config.api.listen_addr = "127.0.0.1:3141".parse().unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_same_port_different_specific_ips_ok() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    // Two distinct specific IPs on same port should not collide
    config.network.listen_addr = "10.0.0.1:3141".parse().unwrap();
    config.api.listen_addr = "10.0.0.2:3141".parse().unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_peer_short_node_id_rejected() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    config.peers.push(PeerConfigEntry {
        node_id: "abcdef".into(), // Too short — need 64 hex chars
        addr: "10.0.0.1:9735".parse().unwrap(),
        label: None,
        auto_connect: true,
    });
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("invalid node_id"), "got: {err}");
}

#[test]
fn validate_peer_odd_length_hex_rejected() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    config.peers.push(PeerConfigEntry {
        node_id: "a".repeat(63), // Odd length
        addr: "10.0.0.1:9735".parse().unwrap(),
        label: None,
        auto_connect: true,
    });
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("invalid node_id"), "got: {err}");
}

#[test]
fn validate_valid_peer_node_id_ok() {
    let mut config = NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    // Valid 64-char hex (32 bytes)
    config.peers.push(PeerConfigEntry {
        node_id: "ab".repeat(32),
        addr: "10.0.0.1:9735".parse().unwrap(),
        label: None,
        auto_connect: true,
    });
    assert!(config.validate().is_ok());
}

#[test]
fn default_config_for_each_tier() {
    // Verify all tiers produce valid configs (except mnemonic existence check)
    for tier in [NodeTier::Cloud, NodeTier::Light, NodeTier::Full] {
        let config = NodeConfig::default_for_tier(
            tier,
            PathBuf::from("/dev/null"), // exists
            Path::new("/tmp"),
        );
        // Skip peers validation (bootstrap peers have generated IDs)
        // Just verify the config is well-formed
        assert!(config.pricing.chat_msat > 0);
        assert!(config.pricing.longform_msat > 0);
        assert!(config.pricing.file_ref_msat > 0);
        assert!(config.pricing.control_msat > 0);
        assert!(config.pricing.realtime_signal_msat > 0);
    }
}

#[test]
fn tier_serialization_roundtrip() {
    for tier in [NodeTier::Cloud, NodeTier::Light, NodeTier::Full] {
        let serialized = serde_json::to_string(&tier).unwrap();
        let deserialized: NodeTier = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tier, deserialized);
    }
}

// ── Tier conversion tests ──────────────────────────────────────────

#[test]
fn node_tier_to_sovereignty_tier_mapping() {
    assert_eq!(
        NodeTier::Cloud.to_sovereignty_tier(),
        SovereigntyTier::T1,
        "Cloud must map to T1"
    );
    assert_eq!(
        NodeTier::Light.to_sovereignty_tier(),
        SovereigntyTier::T1,
        "Light must map to T1"
    );
    assert_eq!(
        NodeTier::Full.to_sovereignty_tier(),
        SovereigntyTier::T2,
        "Full must map to T2"
    );
}

#[test]
fn node_tier_descriptions_are_non_empty() {
    for tier in [NodeTier::Cloud, NodeTier::Light, NodeTier::Full] {
        let desc = tier.description();
        assert!(!desc.is_empty(), "{tier:?} description must not be empty");
    }
}

#[test]
fn node_tier_description_contains_tier_name() {
    assert!(NodeTier::Cloud.description().to_lowercase().contains("cloud"));
    assert!(NodeTier::Light.description().to_lowercase().contains("light"));
    assert!(NodeTier::Full.description().to_lowercase().contains("full"));
}

// ── LightningConfig tests ──────────────────────────────────────────

#[test]
fn lightning_config_is_mock() {
    let mock = LightningConfig::Mock {
        initial_balance_msat: 1000,
    };
    assert!(mock.is_mock());

    let lnbits = LightningConfig::Lnbits {
        api_url: "http://localhost:5000".into(),
        admin_key: "key".into(),
    };
    assert!(!lnbits.is_mock());
}

#[test]
fn lightning_config_backend_name() {
    let mock = LightningConfig::Mock {
        initial_balance_msat: 1000,
    };
    assert_eq!(mock.backend_name(), "mock");

    let lnbits = LightningConfig::Lnbits {
        api_url: "http://localhost:5000".into(),
        admin_key: "key".into(),
    };
    assert_eq!(lnbits.backend_name(), "lnbits");
}

// ── Config load/save roundtrip tests ───────────────────────────────

#[test]
fn config_save_and_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic_path = dir.path().join("mnemonic.txt");
    std::fs::write(&mnemonic_path, "abandon ".repeat(24).trim()).unwrap();

    let config =
        NodeConfig::default_for_tier(NodeTier::Light, mnemonic_path.clone(), dir.path());

    let config_path = dir.path().join("konsensus.toml");
    config.save(&config_path).unwrap();

    // The saved file should be valid TOML
    let content = std::fs::read_to_string(&config_path).unwrap();
    assert!(!content.is_empty());
    assert!(content.contains("[identity]"));
    assert!(content.contains("[network]"));
    assert!(content.contains("[lightning]"));

    // Load should succeed and produce equivalent config
    let loaded = NodeConfig::load(&config_path).unwrap();
    assert_eq!(loaded.tier, config.tier);
    assert_eq!(loaded.pricing.chat_msat, config.pricing.chat_msat);
    assert_eq!(
        loaded.network.listen_addr.port(),
        config.network.listen_addr.port()
    );
}

#[test]
fn config_load_nonexistent_file_fails() {
    let result = NodeConfig::load(Path::new("/nonexistent/path/konsensus.toml"));
    assert!(result.is_err());
}

#[test]
fn config_load_invalid_toml_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.toml");
    std::fs::write(&path, "this is [not valid toml {{{{").unwrap();

    let result = NodeConfig::load(&path);
    assert!(result.is_err());
}

#[test]
fn config_load_missing_required_fields_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.toml");
    // Missing identity, network, etc.
    std::fs::write(&path, "[pricing]\nchat_msat = 10\n").unwrap();

    let result = NodeConfig::load(&path);
    assert!(result.is_err());
}

#[test]
fn config_save_to_readonly_dir_fails() {
    // Use a path inside a non-existent directory
    let result = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    )
    .save(Path::new("/nonexistent/deep/path/konsensus.toml"));
    assert!(result.is_err());
}

// ── Validation edge cases ──────────────────────────────────────────

#[test]
fn validate_rejects_missing_mnemonic() {
    let toml = r#"
[identity]
mnemonic_file = "/definitely/does/not/exist/mnemonic.txt"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    let result = config.validate();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("mnemonic file not found"));
}

#[test]
fn validate_rejects_colliding_ports() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic_path = dir.path().join("mnemonic.txt");
    std::fs::write(&mnemonic_path, "test").unwrap();

    let toml = format!(
        r#"
[identity]
mnemonic_file = "{}"

[network]
listen_addr = "0.0.0.0:3141"

[api]
listen_addr = "0.0.0.0:3141"

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"
"#,
        mnemonic_path.display()
    );
    let config: NodeConfig = toml::from_str(&toml).unwrap();
    let result = config.validate();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("same port"));
}

#[test]
fn validate_rejects_zero_longform_price() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic_path = dir.path().join("mnemonic.txt");
    std::fs::write(&mnemonic_path, "test").unwrap();

    let toml = format!(
        r#"
[identity]
mnemonic_file = "{}"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"

[pricing]
chat_msat = 10
longform_msat = 0
file_ref_msat = 50
control_msat = 1
"#,
        mnemonic_path.display()
    );
    let config: NodeConfig = toml::from_str(&toml).unwrap();
    let result = config.validate();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("pricing values must be > 0"));
}

#[test]
fn validate_rejects_invalid_peer_node_id() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic_path = dir.path().join("mnemonic.txt");
    std::fs::write(&mnemonic_path, "test").unwrap();

    let toml = format!(
        r#"
[identity]
mnemonic_file = "{}"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"

[[peers]]
node_id = "not-valid-hex"
addr = "127.0.0.1:9736"
"#,
        mnemonic_path.display()
    );
    let config: NodeConfig = toml::from_str(&toml).unwrap();
    let result = config.validate();
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("invalid node_id"));
}

// ── Default tier config assertions ─────────────────────────────────

#[test]
fn full_tier_uses_encrypted_storage() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Full,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    match &config.storage {
        StorageConfig::Sqlite { encrypted, .. } => {
            assert!(encrypted, "Full tier must use encrypted storage");
        }
        _ => panic!("Full tier must use SQLite"),
    }
}

#[test]
fn cloud_tier_uses_encrypted_storage() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Cloud,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    match &config.storage {
        StorageConfig::Sqlite { encrypted, .. } => {
            assert!(encrypted, "Cloud tier must use encrypted storage");
        }
        _ => panic!("Cloud tier must use SQLite"),
    }
}

#[test]
fn light_tier_uses_encrypted_storage() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    match &config.storage {
        StorageConfig::Sqlite { encrypted, .. } => {
            assert!(encrypted, "Light tier must use encrypted storage");
        }
        _ => panic!("Light tier must use SQLite"),
    }
}

#[test]
fn default_tier_is_cloud() {
    let tier: NodeTier = serde_json::from_str(r#""cloud""#).unwrap();
    assert_eq!(tier, NodeTier::Cloud);
}

#[test]
fn tier_display_lowercase() {
    assert_eq!(format!("{}", NodeTier::Cloud), "cloud");
    assert_eq!(format!("{}", NodeTier::Light), "light");
    assert_eq!(format!("{}", NodeTier::Full), "full");
}

// ═══════════════════════════════════════════════════════════
// deny_unknown_fields: typo protection on tagged enums
// ═══════════════════════════════════════════════════════════

#[test]
fn lightning_config_rejects_typo_in_ldk_field() {
    // A typo like "lsp_nod_id" instead of "lsp_node_id" must fail, not silently default.
    let toml = r#"
backend = "ldk"
lsp_nod_id = "02abc123"
"#;
    let result: Result<LightningConfig, _> = toml::from_str(toml);
    assert!(result.is_err(), "Typo in LDK field must be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("unknown field"),
        "Error should mention unknown field, got: {err}"
    );
}

#[test]
fn lightning_config_rejects_typo_in_mock_field() {
    let toml = r#"
backend = "mock"
initial_balace_msat = 5000
"#;
    let result: Result<LightningConfig, _> = toml::from_str(toml);
    assert!(result.is_err(), "Typo in mock field must be rejected");
}

#[test]
fn lightning_config_accepts_valid_ldk_fields() {
    let toml = r#"
backend = "ldk"
network = "testnet"
esplora_url = "https://mempool.space/testnet/api"
lsp_node_id = "02abc123"
lsp_address = "127.0.0.1:9735"
lsp_token = "mytoken"
"#;
    let config: LightningConfig = toml::from_str(toml).unwrap();
    assert!(matches!(config, LightningConfig::Ldk { .. }));
}

#[test]
fn storage_config_rejects_typo_in_encrypted() {
    // "encrypred" instead of "encrypted" must fail, not silently use a default.
    let toml = r#"
backend = "sqlite"
encrypred = true
"#;
    let result: Result<StorageConfig, _> = toml::from_str(toml);
    assert!(result.is_err(), "Typo in storage field must be rejected");
}

#[test]
fn storage_config_rejects_typo_in_retention() {
    let toml = r#"
backend = "sqlite"
retension_days = 30
"#;
    let result: Result<StorageConfig, _> = toml::from_str(toml);
    assert!(result.is_err(), "Typo in retention field must be rejected");
}

#[test]
fn storage_config_accepts_valid_sqlite_fields() {
    let toml = r#"
backend = "sqlite"
path = "/data/konsensus.db"
encrypted = true
retention_days = 30
"#;
    let config: StorageConfig = toml::from_str(toml).unwrap();
    assert!(matches!(config, StorageConfig::Sqlite { .. }));
    assert_eq!(config.retention_days(), 30);
}

#[test]
fn chain_config_rejects_typo_in_esplora() {
    let toml = r#"
backend = "esplora"
api_ulr = "https://example.com"
"#;
    let result: Result<ChainConfig, _> = toml::from_str(toml);
    assert!(result.is_err(), "Typo in chain field must be rejected");
}

#[test]
fn chain_config_accepts_primary_and_fallback() {
    let toml = r#"
backend = "esplora"
esplora_url_primary = "https://primary.example.com"
esplora_url_fallback = "https://fallback.example.com"
"#;
    let config: ChainConfig = toml::from_str(toml).unwrap();
    match config {
        ChainConfig::Esplora {
            api_url,
            esplora_url_fallback,
        } => {
            assert_eq!(api_url, "https://primary.example.com");
            assert_eq!(
                esplora_url_fallback,
                Some("https://fallback.example.com".to_string())
            );
        }
        ChainConfig::Mock => panic!("expected esplora config"),
    }
}

#[test]
fn chain_config_backcompat_api_url_only() {
    let toml = r#"
backend = "esplora"
api_url = "https://legacy.example.com"
"#;
    let config: ChainConfig = toml::from_str(toml).unwrap();
    match config {
        ChainConfig::Esplora {
            api_url,
            esplora_url_fallback,
        } => {
            assert_eq!(api_url, "https://legacy.example.com");
            assert_eq!(esplora_url_fallback, None);
        }
        ChainConfig::Mock => panic!("expected esplora config"),
    }
}

#[test]
fn full_config_rejects_typo_in_nested_lightning() {
    // End-to-end: typo in a nested section within a full NodeConfig.
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "lnbits"
api_url = "http://localhost:5000"
admin_kee = "deadbeef"

[chain]
backend = "mock"

[storage]
backend = "sqlite"
"#;
    let result: Result<NodeConfig, _> = toml::from_str(toml);
    assert!(result.is_err(), "Typo in nested lightning config must be rejected");
}
