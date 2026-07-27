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
    assert!(matches!(
        config.storage,
        StorageConfig::Sqlite {
            encrypted: true,
            ..
        }
    ));
    // M1a: omitting `admission_mode` parses (deny_unknown_fields + #[serde(default)])
    // and resolves to the closed-mesh default — existing live-mesh configs keep
    // parsing and stay closed (fail-closed, off-by-default).
    assert_eq!(
        config.admission_mode,
        konsensus_message::ReachabilityMode::Whitelist,
        "omitted admission_mode must default to Whitelist (closed mesh)"
    );
    // R1-a OFF-BY-DEFAULT: omitting [onboarding_subsidy] must parse and yield a
    // fully fail-closed, disabled subsidy so existing configs spend nothing.
    assert!(
        !config.onboarding_subsidy.enabled,
        "omitted onboarding_subsidy must be disabled (off-by-default)"
    );
    // T2R8 OFF-BY-DEFAULT: ordinary nodes must not advertise relay capability
    // unless the operator explicitly opts in with [relay] enabled=true.
    assert!(
        !config.relay.enabled,
        "omitted relay config must be disabled (off-by-default)"
    );
}

#[test]
fn onboarding_subsidy_defaults_to_disabled_when_omitted() {
    // Explicit regression for the R1-a OFF-BY-DEFAULT invariant: a config that
    // never mentions [onboarding_subsidy] yields a disabled subsidy with all
    // spend caps at their fail-closed defaults and an empty allowlist.
    let toml = r#"
[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "mock"

[chain]
backend = "esplora"

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert!(!config.onboarding_subsidy.enabled);
    assert_eq!(config.onboarding_subsidy.max_channel_sats, 0);
    assert_eq!(config.onboarding_subsidy.max_total_budget_sats, 0);
    assert_eq!(config.onboarding_subsidy.per_peer_max_opens, 1);
    assert!(config.onboarding_subsidy.allowlist.is_empty());
}

#[test]
fn relay_config_defaults_to_disabled_when_omitted() {
    // Existing live-mesh configs do not include [relay]. They must continue to
    // parse and stay non-relay by default.
    let toml = r#"
[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

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
    assert!(!config.relay.enabled);
}

#[test]
fn relay_config_enabled_parses() {
    // Operator opt-in: the relay advertisement bit is explicit and isolated to
    // the [relay] block.
    let toml = r#"
[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"

[relay]
enabled = true
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert!(config.relay.enabled);
}

#[test]
fn relay_durable_db_path_defaults_none_and_parses_when_set() {
    // P8.1: the durable-store backend selector. Omitted ⇒ None (non-durable
    // in-memory store, current behaviour). Set ⇒ the operator's durable DB path.
    let base = r#"
[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"

[relay]
enabled = true
"#;
    let omitted: NodeConfig = toml::from_str(base).unwrap();
    assert!(
        omitted.relay.durable_db_path.is_none(),
        "omitted durable_db_path must default to None (in-memory store)"
    );

    let toml_with_path = format!("{base}durable_db_path = \"/var/konsensus/relay.db\"\n");
    let with_path: NodeConfig = toml::from_str(&toml_with_path).unwrap();
    assert_eq!(
        with_path.relay.durable_db_path.as_deref(),
        Some(std::path::Path::new("/var/konsensus/relay.db"))
    );
}

#[test]
fn relay_config_unknown_field_errors_not_silent_enable_or_default() {
    // The relay advertisement gate is fail-closed: a typo in [relay] must reject
    // the config instead of silently defaulting to disabled or accepting an
    // operator's intended enablement under the wrong key.
    let toml = r#"
[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"

[relay]
enabld = true
"#;
    let parsed = toml::from_str::<NodeConfig>(toml);
    assert!(
        parsed.is_err(),
        "unknown [relay] field must error, never silently enable or default"
    );
    let err = parsed.unwrap_err().to_string();
    assert!(
        err.contains("unknown field"),
        "error should mention unknown field, got: {err}"
    );
}

#[test]
fn onboarding_subsidy_field_defaults_when_block_present() {
    // With the block present but only `enabled` set, the remaining fields fall
    // back to their fail-closed defaults: zero spend caps keep every open
    // suppressed, and per_peer_max_opens defaults to 1.
    let toml = r#"
[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "mock"

[chain]
backend = "esplora"

[storage]
backend = "sqlite"

[onboarding_subsidy]
enabled = true
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert!(config.onboarding_subsidy.enabled);
    assert_eq!(
        config.onboarding_subsidy.max_channel_sats, 0,
        "unset per-channel cap stays fail-closed"
    );
    assert_eq!(config.onboarding_subsidy.max_total_budget_sats, 0);
    assert_eq!(
        config.onboarding_subsidy.per_peer_max_opens, 1,
        "per_peer_max_opens default is 1"
    );
    assert!(config.onboarding_subsidy.allowlist.is_empty());
}

#[test]
fn admission_mode_defaults_to_whitelist_when_omitted() {
    // Explicit regression for the M1a OFF-BY-DEFAULT invariant: a config that does
    // not mention admission_mode at all yields Whitelist, never PriceOpen.
    let toml = r#"
[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

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
    assert_eq!(
        config.admission_mode,
        konsensus_message::ReachabilityMode::Whitelist
    );
}

#[test]
fn admission_mode_price_open_parses() {
    // The operator opts into price-admission with `admission_mode = "price_open"`
    // (token pinned by the per-variant `#[serde(rename = "price_open")]` on
    // `ReachabilityMode`).
    let toml = r#"
admission_mode = "price_open"

[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

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
    assert_eq!(
        config.admission_mode,
        konsensus_message::ReachabilityMode::PriceOpen
    );
}

#[test]
fn cookie_mode_defaults_to_disabled_when_omitted() {
    // Off-by-default invariant for doorway hardening #2: a config that omits
    // cookie_mode yields Disabled (handshake byte-identical to pre-cookie).
    let toml = r#"
[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

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
    assert_eq!(config.cookie_mode, konsensus_message::CookieMode::Disabled);
}

#[test]
fn cookie_mode_required_parses() {
    // The operator opts into the pre-Noise cookie with `cookie_mode = "required"`
    // (snake_case token from `#[serde(rename_all = "snake_case")]` on CookieMode).
    let toml = r#"
cookie_mode = "required"

[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

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
    assert_eq!(config.cookie_mode, konsensus_message::CookieMode::Required);
}

#[test]
fn admission_mode_unknown_token_errors_not_silent_whitelist() {
    // Doctrine (CODEX.md §Renames fail loud, never silent-default): `NodeConfig`
    // carries `deny_unknown_fields` and `admission_mode` carries `#[serde(default)]`.
    // `#[serde(default)]` only fills an ABSENT field — a PRESENT-but-unknown token
    // must FAIL the whole parse, never fall back to the Whitelist default, which
    // would re-install membership-as-admission invisibly. This is the config-wire
    // counterpart of the enum-level `unknown_token_errors_never_silent_default`.
    let toml = r#"
admission_mode = "admission"

[identity]
mnemonic_file = "/var/konsensus/mnemonic.txt"

[network]
listen_addr = "0.0.0.0:9735"

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"
"#;
    let parsed = toml::from_str::<NodeConfig>(toml);
    assert!(
        parsed.is_err(),
        "unknown admission_mode token must error, not silently default to Whitelist"
    );
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

[payment_gate]
verify_lightning_settlement = true

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
    assert_eq!(config.payment_gate.verify_lightning_settlement, Some(true));
    assert_eq!(config.peers.len(), 2);
    assert_eq!(config.peers[0].label.as_deref(), Some("Alice"));
    assert!(!config.peers[1].auto_connect);
    assert!(matches!(
        config.storage,
        StorageConfig::Postgres {
            encrypted: true,
            ..
        }
    ));
}

#[test]
fn default_config_serializes() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/tmp/mnemonic.txt"),
        Path::new("/tmp"),
    );
    let toml_str = toml::to_string_pretty(&config).unwrap();
    assert!(toml_str.contains("mnemonic_file"));
    assert!(
        toml_str.contains("mock"),
        "default config should use mock backends for out-of-box experience"
    );
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
fn payment_gate_settlement_verification_infers_from_lightning_backend() {
    let ldk_toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "ldk"

[chain]
backend = "mock"

[storage]
backend = "sqlite"
"#;
    let ldk_config: NodeConfig = toml::from_str(ldk_toml).unwrap();
    assert!(
        ldk_config
            .payment_gate_runtime_config()
            .verify_lightning_settlement,
        "real Lightning backends must default to strict settlement verification"
    );

    let mock_toml = r#"
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
    let mock_config: NodeConfig = toml::from_str(mock_toml).unwrap();
    assert!(
        !mock_config
            .payment_gate_runtime_config()
            .verify_lightning_settlement,
        "mock Lightning stays loose for local/dev tests unless explicitly overridden"
    );
}

#[test]
fn payment_gate_settlement_verification_override_wins() {
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "ldk"

[chain]
backend = "mock"

[payment_gate]
verify_lightning_settlement = false

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert!(
        !config
            .payment_gate_runtime_config()
            .verify_lightning_settlement,
        "explicit operator override must be honored for staging/debug rollbacks"
    );
}

#[test]
fn payment_gate_min_admission_cost_reaches_runtime_config() {
    // Doorway hardening #4: the operator cost-floor knob must parse from TOML and
    // reach the runtime GateConfig the gate actually enforces — money-path knob,
    // so guard the wiring with a focused regression test.
    let toml = r#"
[identity]
mnemonic_file = "m.txt"

[network]

[lightning]
backend = "mock"

[chain]
backend = "mock"

[payment_gate]
min_admission_cost_msat = 50

[storage]
backend = "sqlite"
"#;
    let config: NodeConfig = toml::from_str(toml).unwrap();
    assert_eq!(
        config.payment_gate.min_admission_cost_msat,
        Some(50),
        "TOML min_admission_cost_msat must deserialize into the config field"
    );
    assert_eq!(
        config.payment_gate_runtime_config().min_admission_cost_msat,
        50,
        "configured cost floor must reach the runtime GateConfig the gate enforces"
    );
}

#[test]
fn payment_gate_min_admission_cost_defaults_to_zero_when_omitted() {
    // Omitted knob => floor off (0): pricing byte-identical to pre-#4 behaviour.
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
    assert_eq!(config.payment_gate.min_admission_cost_msat, None);
    assert_eq!(
        config.payment_gate_runtime_config().min_admission_cost_msat,
        0,
        "omitted cost floor must resolve to 0 (off) — byte-identical to pre-#4 pricing"
    );
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
        StorageConfig::Sqlite {
            path,
            encrypted,
            retention_days,
        } => {
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

/// RV-RESTORE durability guard: a config that omits `[backup]` (so `scb_dir`
/// falls back to the relative `"backups"` default) must, after `load()`, hold an
/// ABSOLUTE path anchored to the config file's own directory — never a
/// CWD-relative one. A relative path resolved against the process working
/// directory would put a node's only recovery material (SCB + whitelist sidecar)
/// wherever the service was launched (e.g. `/tmp`), where it vanishes on reboot
/// and silently defeats disaster recovery while the node looks healthy.
#[test]
fn load_anchors_relative_scb_dir_to_config_dir() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic_path = dir.path().join("mnemonic.txt");
    std::fs::write(&mnemonic_path, "abandon ".repeat(24).trim()).unwrap();

    // Build a valid config, then strip scb_dir down to the relative default that
    // a hand-written / upgraded config (no [backup] section) would deserialize to.
    let mut config =
        NodeConfig::default_for_tier(NodeTier::Light, mnemonic_path.clone(), dir.path());
    config.backup.scb_dir = "backups".to_string();

    let config_path = dir.path().join("konsensus.toml");
    config.save(&config_path).unwrap();
    let loaded = NodeConfig::load(&config_path).unwrap();

    let scb = Path::new(&loaded.backup.scb_dir);
    assert!(
        scb.is_absolute(),
        "relative scb_dir must be anchored to an absolute path, got {:?}",
        loaded.backup.scb_dir
    );
    // Anchored to the config file's directory (canonicalized), not the CWD.
    let expected = std::fs::canonicalize(dir.path()).unwrap().join("backups");
    assert_eq!(scb, expected.as_path());
}

/// Counterpart to the durability guard: an ABSOLUTE `scb_dir` (what
/// `konsensus init` writes) is preserved verbatim — `load()` only rewrites the
/// relative fallback, never an operator's explicit absolute choice.
#[test]
fn load_preserves_absolute_scb_dir() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic_path = dir.path().join("mnemonic.txt");
    std::fs::write(&mnemonic_path, "abandon ".repeat(24).trim()).unwrap();

    let mut config =
        NodeConfig::default_for_tier(NodeTier::Light, mnemonic_path.clone(), dir.path());
    config.backup.scb_dir = "/var/lib/bitsov/backups".to_string();

    let config_path = dir.path().join("konsensus.toml");
    config.save(&config_path).unwrap();
    let loaded = NodeConfig::load(&config_path).unwrap();

    assert_eq!(loaded.backup.scb_dir, "/var/lib/bitsov/backups");
}

#[test]
fn validate_port_collision() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.network.listen_addr = "0.0.0.0:3141".parse().unwrap();
    config.api.listen_addr = "127.0.0.1:3141".parse().unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("same port"), "got: {err}");
}

/// A fresh full-tier node leaves BOTH the P2P network listener and the LDK
/// Lightning listener on 0.0.0.0:9735 (that is exactly what
/// `default_for_tier(Full)` produces). Validation must reject the collision —
/// at runtime it silently hangs the node (LDK shuts down + the transport
/// listener never returns + the API never binds). Reproduced on 2 hosts during
/// R4.5 staging.
#[test]
fn validate_p2p_lightning_port_collision() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Full,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    // Both default to 0.0.0.0:9735 — assert the precondition so this test still
    // exercises the collision if the defaults ever change.
    assert_eq!(config.network.listen_addr, "0.0.0.0:9735".parse().unwrap());
    assert!(matches!(
        &config.lightning,
        LightningConfig::Ldk { listening_address: Some(a), .. } if a == "0.0.0.0:9735"
    ));
    // Keep the API off 9735 so this test isolates the P2P-vs-Lightning guard.
    config.api.listen_addr = "127.0.0.1:3141".parse().unwrap();

    let err = config.validate().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("same port"), "got: {msg}");
    assert!(msg.contains("Lightning listening address"), "got: {msg}");
}

/// Control: separating the P2P and Lightning ports (the fix operators apply,
/// e.g. alpha runs P2P 9736 / Lightning 9735) validates cleanly.
#[test]
fn validate_p2p_lightning_distinct_ports_ok() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Full,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.network.listen_addr = "0.0.0.0:9736".parse().unwrap();
    config.api.listen_addr = "127.0.0.1:3141".parse().unwrap();
    if let LightningConfig::Ldk {
        listening_address, ..
    } = &mut config.lightning
    {
        *listening_address = Some("0.0.0.0:9735".to_string());
    } else {
        panic!("full tier should default to an LDK Lightning backend");
    }

    config
        .validate()
        .expect("distinct P2P/Lightning ports must validate");
}

#[test]
fn validate_invalid_peer_node_id() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
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
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
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
fn validate_relay_enabled_requires_durable_on_real_backend() {
    // A real (non-Mock) Lightning backend with [relay].enabled but no
    // durable_db_path would silently use the in-memory store and lose held mail
    // on restart. validate() must fail closed.
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Full, // Full => Ldk (non-Mock) backend, settlement-verify on
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    // Avoid #321's P2P/LDK default port-collision guard so this test reaches
    // the durable-relay validation path it is actually asserting.
    config.network.listen_addr = "0.0.0.0:9736".parse().unwrap();
    config.peers.clear();
    config.relay.enabled = true;
    config.relay.durable_db_path = None;
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string().contains("durable_db_path"),
        "expected the live-tier durable-relay guard, got: {err}"
    );
}

#[test]
fn validate_relay_enabled_inmemory_ok_on_mock_dev_smoke() {
    // The smoke/dev escape must keep working: on the Mock backend the in-memory
    // relay store is allowed (it is explicitly smoke-test only). The guard keys
    // on a *real* backend, so it must NOT fire here. (verify_lightning_settlement
    // is opted on so the separate settlement-gated 2d guard passes.)
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light, // Light => Mock backend
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.relay.enabled = true;
    config.relay.durable_db_path = None;
    config.payment_gate.verify_lightning_settlement = Some(true);
    assert!(
        config.validate().is_ok(),
        "Mock-backend in-memory relay (dev/smoke) must remain allowed"
    );
}

#[test]
fn validate_missing_mnemonic_file() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/nonexistent/path/mnemonic.txt"),
        Path::new("/nonexistent/path"),
    );
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string().contains("mnemonic file not found"),
        "got: {err}"
    );
}

#[test]
fn validate_empty_jwt_secret_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.api.jwt_secret = Some(String::new());
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("api.jwt_secret"), "got: {err}");
    assert!(err.to_string().contains("empty"), "got: {err}");
}

#[test]
fn validate_short_jwt_secret_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.api.jwt_secret = Some("too-short".into());
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("api.jwt_secret"), "got: {err}");
    assert!(err.to_string().contains("too short"), "got: {err}");
}

#[test]
fn validate_strong_jwt_secret_accepted() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.api.jwt_secret = Some("a".repeat(32));
    assert!(config.validate().is_ok());
}

#[test]
fn validate_unset_jwt_secret_accepted() {
    // Omitting the secret is fine — the node derives one from its identity.
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.api.jwt_secret = None;
    assert!(config.validate().is_ok());
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
    assert_eq!(config.tier.to_sovereignty_tier(), SovereigntyTier::T1);
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
    assert!(matches!(
        config.storage,
        StorageConfig::Sqlite {
            encrypted: true,
            ..
        }
    ));
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
fn default_config_ships_no_bootstrap_peers() {
    // Boundary invariant (PUB-1): the open-core binary must not embed any live
    // mesh topology. Bootstrap peers are supplied by operator config or
    // environment at deploy time, never compiled into the published source.
    // Asserted for every tier so a public download ships an empty peer list.
    for tier in [NodeTier::Light, NodeTier::Full, NodeTier::Cloud] {
        let label = tier.to_string();
        let config = NodeConfig::default_for_tier(
            tier,
            PathBuf::from("/tmp/mnemonic.txt"),
            Path::new("/tmp"),
        );
        assert!(
            config.peers.is_empty(),
            "{label} tier must ship no compiled-in bootstrap peers (PUB-1 boundary)"
        );
    }
}

// ─── Config validation hardening tests ──────────────────────────────────

#[test]
fn validate_zero_longform_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.pricing.longform_msat = 0;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("pricing"), "got: {err}");
}

#[test]
fn validate_zero_file_ref_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.pricing.file_ref_msat = 0;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("pricing"), "got: {err}");
}

#[test]
fn validate_zero_control_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.pricing.control_msat = 0;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("pricing"), "got: {err}");
}

#[test]
fn validate_zero_realtime_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.pricing.realtime_signal_msat = 0;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("pricing"), "got: {err}");
}

#[test]
fn validate_different_ports_ok() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.network.listen_addr = "0.0.0.0:9735".parse().unwrap();
    config.api.listen_addr = "127.0.0.1:3141".parse().unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_same_port_different_specific_ips_ok() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    // Two distinct specific IPs on same port should not collide
    config.network.listen_addr = "10.0.0.1:3141".parse().unwrap();
    config.api.listen_addr = "10.0.0.2:3141".parse().unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn validate_peer_short_node_id_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
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
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
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
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
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
        assert!(
            !config.relay.enabled,
            "generated {tier:?} config must keep relay advertisement disabled by default"
        );
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
    assert!(NodeTier::Cloud
        .description()
        .to_lowercase()
        .contains("cloud"));
    assert!(NodeTier::Light
        .description()
        .to_lowercase()
        .contains("light"));
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

    let config = NodeConfig::default_for_tier(NodeTier::Light, mnemonic_path.clone(), dir.path());

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
fn cloud_tier_rejects_unencrypted_storage() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic = dir.path().join("mnemonic.txt");
    std::fs::write(
        &mnemonic,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    )
    .unwrap();
    let config_path = dir.path().join("konsensus.toml");
    std::fs::write(
        &config_path,
        format!(
            r#"
tier = "cloud"

[identity]
mnemonic_file = "{}"

[network]

[lightning]
backend = "mock"

[chain]
backend = "mock"

[storage]
backend = "sqlite"
path = "{}"
encrypted = false
"#,
            mnemonic.display(),
            dir.path().join("konsensus.db").display(),
        ),
    )
    .unwrap();

    let err = NodeConfig::load(&config_path).unwrap_err().to_string();
    assert!(
        err.contains("cloud tier requires encrypted storage"),
        "unexpected error: {err}"
    );
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
    assert!(
        result.is_err(),
        "Typo in nested lightning config must be rejected"
    );
}

// ── SEC3: settlement-verification boot assertion ──────────────────────────

#[test]
fn validate_rejects_settlement_off_on_non_mock_backend() {
    // A real (non-Mock) backend with verify_lightning_settlement = Some(false) must be
    // rejected — it silently downgrades the payment gate to preimage-only (Principle 2).
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Full, // Full tier uses a non-Mock Ldk backend
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    // Full tier defaults P2P and Lightning both to 0.0.0.0:9735; separate them
    // so this test isolates the settlement guard, not the port-collision guard.
    config.network.listen_addr = "0.0.0.0:9736".parse().unwrap();
    assert!(
        !matches!(config.lightning, LightningConfig::Mock { .. }),
        "precondition: Full tier must use a non-Mock backend"
    );
    config.payment_gate.verify_lightning_settlement = Some(false);

    let err = config.validate().unwrap_err();
    assert!(
        err.to_string().contains("verify_lightning_settlement"),
        "got: {err}"
    );
}

#[test]
fn validate_allows_settlement_off_on_mock_backend() {
    // Mock backend may disable settlement verification — there is no real Lightning
    // payment to settle, so this is not a downgrade.
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light, // Light tier uses a Mock backend
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    assert!(matches!(config.lightning, LightningConfig::Mock { .. }));
    config.payment_gate.verify_lightning_settlement = Some(false);

    assert!(
        config.validate().is_ok(),
        "Mock + settlement-off must be allowed"
    );
}

// 2d (Codex #3): relay/price-open admission is settlement-gated, so it must fail
// closed on a Mock backend (settlement resolves off by default) unless the
// operator explicitly opts in. A Mock relay/price-open node that silently ran
// would admit unsettled/forged proofs.
#[test]
fn validate_rejects_relay_enabled_with_mock_settlement_off() {
    let mut config =
        NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    assert!(matches!(config.lightning, LightningConfig::Mock { .. }));
    config.relay.enabled = true; // settlement defaults OFF for Mock → must bail
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("verify_lightning_settlement"), "got: {err}");
    assert!(err.to_string().contains("relay"), "got: {err}");
}

#[test]
fn validate_rejects_price_open_with_mock_settlement_off() {
    let mut config =
        NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    assert!(matches!(config.lightning, LightningConfig::Mock { .. }));
    config.admission_mode = konsensus_message::ReachabilityMode::PriceOpen;
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("verify_lightning_settlement"), "got: {err}");
    assert!(err.to_string().contains("price_open"), "got: {err}");
}

#[test]
fn validate_allows_relay_on_mock_with_explicit_settlement_on() {
    // The explicit dev/smoke escape: setting verify_lightning_settlement = true
    // on a Mock backend opts into the settlement-verification path (the mock's
    // own settled-keysend path), so relay/price-open may be mounted for testing.
    let mut config =
        NodeConfig::default_for_tier(NodeTier::Light, PathBuf::from("/dev/null"), Path::new("/tmp"));
    config.peers.clear();
    assert!(matches!(config.lightning, LightningConfig::Mock { .. }));
    config.relay.enabled = true;
    config.admission_mode = konsensus_message::ReachabilityMode::PriceOpen;
    config.payment_gate.verify_lightning_settlement = Some(true);
    assert!(
        config.validate().is_ok(),
        "Mock + relay/price_open + explicit settlement-on must be allowed (dev escape)"
    );
}

#[test]
fn validate_allows_settlement_on_with_non_mock_backend() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Full,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    // Full tier defaults P2P and Lightning both to 0.0.0.0:9735; separate them
    // so a clean settlement-on config validates without tripping the
    // port-collision guard.
    config.network.listen_addr = "0.0.0.0:9736".parse().unwrap();
    config.payment_gate.verify_lightning_settlement = Some(true);

    assert!(
        config.validate().is_ok(),
        "non-Mock + settlement-on must be allowed"
    );
}
