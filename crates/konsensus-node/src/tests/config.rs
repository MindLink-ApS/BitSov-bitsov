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
    assert_eq!(config.disk_free_floor_bytes, 2147483648);
    assert_eq!(config.logging.max_file_size_bytes.get(), 10 * 1024 * 1024);
    assert_eq!(config.logging.max_files.get(), 5);
    let override_config: NodeConfig = toml::from_str(&format!("disk_free_floor_bytes = 4096\n{toml}")).unwrap();
    assert_eq!(override_config.disk_free_floor_bytes, 4096);
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
    assert!(config.remote_access.listen_addr.is_none());
}

#[test]
fn remote_access_requires_loopback_plaintext_api_and_advertised_endpoint() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.remote_access.listen_addr = Some("0.0.0.0:18443".parse().unwrap());
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("advertised_endpoint"), "{error}");

    config.remote_access.advertised_endpoint = Some("node.example:18443".into());
    config.api.listen_addr = "0.0.0.0:18080".parse().unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("must be loopback"), "{error}");
}

#[test]
fn hosted_by_is_bounded_trimmed_and_printable() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    for label in [
        None,
        Some("Rasmus's Pi".to_string()),
        Some("Øresund-boks 🟠".to_string()),
        Some("𝔅".repeat(64)),
    ] {
        config.node.hosted_by = label.clone();
        config
            .validate()
            .unwrap_or_else(|error| panic!("{label:?} should be accepted: {error}"));
    }
    for (label, reason) in [
        ("", "empty"),
        ("   ", "empty"),
        (" Pi", "whitespace"),
        ("Pi\n", "whitespace"),
        ("Rasmus\u{7}Pi", "printable"),
        ("Rasmus\u{1b}[31mPi", "printable"),
        ("Pi\u{202E}kcab", "printable"),
        ("Pi\u{200B}", "printable"),
        ("Pi\u{2066}x\u{2069}", "printable"),
    ] {
        config.node.hosted_by = Some(label.into());
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains("hosted_by") && error.contains(reason),
            "{label:?}: {error}"
        );
    }
    config.node.hosted_by = Some("x".repeat(65));
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("at most 64"), "{error}");
}

#[test]
fn remote_access_rejects_tcp_port_collisions() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.remote_access.listen_addr =
        Some(format!("0.0.0.0:{}", config.network.listen_addr.port()).parse().unwrap());
    config.remote_access.advertised_endpoint = Some("node.example:18443".into());
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("same TCP port"), "{error}");
}

#[test]
fn remote_access_endpoint_uses_the_apps_host_grammar() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.remote_access.listen_addr = Some("0.0.0.0:18443".parse().unwrap());

    for endpoint in [
        "bad_name.example:18443",
        "-bad.example:18443",
        "bad-.example:18443",
        "bad..example:18443",
    ] {
        config.remote_access.advertised_endpoint = Some(endpoint.into());
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("valid host:port"), "{endpoint}: {error}");
    }

    for endpoint in [
        "node.example:18443",
        "203.0.113.8:18443",
        "[2001:db8::8]:18443",
    ] {
        config.remote_access.advertised_endpoint = Some(endpoint.into());
        config.validate().unwrap_or_else(|error| {
            panic!("{endpoint} should match the app host grammar: {error}")
        });
    }
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
    assert_eq!(config.pricing.call_msat, 10_000);
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

/// An operator who hand-edits BOTH the P2P network listener and the LDK Lightning
/// listener onto 0.0.0.0:9735 must be rejected at validation — at runtime the
/// collision silently hangs the node (LDK shuts down + the transport listener never
/// returns + the API never binds). Reproduced on 2 hosts during R4.5 staging. Until
/// genome #56 this was also what `default_for_tier(Full)` produced; the defaults no
/// longer collide (see `default_for_tier_defaults_validate_for_every_tier`).
#[test]
fn validate_p2p_lightning_port_collision() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Full,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    // Force the collision explicitly (the defaults are distinct since #56).
    config.network.listen_addr = "0.0.0.0:9735".parse().unwrap();
    if let LightningConfig::Ldk {
        listening_address, ..
    } = &mut config.lightning
    {
        *listening_address = Some("0.0.0.0:9735".to_string());
    } else {
        panic!("full tier should default to an LDK Lightning backend");
    }
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

/// Genome #56: a fresh `init` for every tier must produce a config that `start` accepts
/// with zero edits — the P2P, API and (Full tier) Lightning listeners all default to
/// distinct ports.
#[test]
fn default_for_tier_defaults_validate_for_every_tier() {
    for tier in [NodeTier::Cloud, NodeTier::Light, NodeTier::Full] {
        let config =
            NodeConfig::default_for_tier(tier, PathBuf::from("/dev/null"), Path::new("/tmp"));
        assert_ne!(
            config.network.listen_addr.port(),
            config.api.listen_addr.port(),
            "{tier:?}: P2P and API defaults must differ"
        );
        if let LightningConfig::Ldk {
            listening_address: Some(addr),
            ..
        } = &config.lightning
        {
            let ln_port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
            assert_ne!(
                config.network.listen_addr.port(),
                ln_port,
                "{tier:?}: P2P and Lightning defaults must differ"
            );
        }
        config
            .validate()
            .unwrap_or_else(|e| panic!("{tier:?}: fresh defaults must validate: {e}"));
    }
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
fn validate_web_content_below_one_sat_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    for amount in [999, 500, 1, 0] {
        config.pricing.web_content_msat = amount;
        let err = config.validate().unwrap_err().to_string();
        assert!(
            err.contains("pricing.web_content_msat") && err.contains("1000"),
            "amount={amount}: {err}"
        );
    }
}

#[test]
fn validate_web_content_at_or_above_one_sat_accepts_other_subsat_prices() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.pricing.chat_msat = 1;
    config.pricing.control_msat = 1;
    for amount in [1_000, 1_001, 2_000] {
        config.pricing.web_content_msat = amount;
        config.validate().unwrap();
    }
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
fn validate_zero_call_pricing_rejected() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    config.pricing.call_msat = 0;
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

#[test]
fn config_save_atomic_replace_leaves_no_tmp_and_survives_reread() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("custom.toml");
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Full,
        dir.path().join("first-mnemonic.txt"),
        dir.path(),
    );
    config.save(&path).unwrap();

    config.identity.mnemonic_file = dir.path().join("aligned-mnemonic.txt");
    config.save(&path).unwrap();

    assert!(
        !path.with_extension("toml.tmp").exists(),
        "durable save must not leave a sibling temp file after publish"
    );
    let loaded = NodeConfig::load_before_identity_validation(&path).unwrap();
    assert_eq!(
        loaded.identity.mnemonic_file,
        dir.path().join("aligned-mnemonic.txt")
    );
}

#[test]
fn config_save_dir_sync_failure_propagates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("custom.toml");
    let config = NodeConfig::default_for_tier(
        NodeTier::Full,
        dir.path().join("mnemonic.txt"),
        dir.path(),
    );
    config.save(&path).unwrap();

    super::fail_next_config_dir_sync();
    let err = config
        .save(&path)
        .expect_err("injected directory sync failure must surface");
    assert!(
        err.to_string().contains("sync"),
        "expected sync error, got: {err}"
    );
    assert!(
        !path.with_extension("toml.tmp").exists(),
        "failed sync after rename must not leave a temp sibling"
    );
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
            ..
        } => {
            assert_eq!(api_url, "https://primary.example.com");
            assert_eq!(
                esplora_url_fallback,
                Some("https://fallback.example.com".to_string())
            );
        }
        ChainConfig::Mock | ChainConfig::Bitcoind(_) | ChainConfig::Electrum(_) => panic!("expected esplora config"),
    }
}

/// genome #66 round 2 (Codex R2): an EXISTING config that omits the primary URL
/// must keep resolving to the provider it resolved to before. The first attempt
/// at #66 changed the `#[serde(default = ...)]` helpers, which would have moved
/// every such config from mempool.space to Blockstream on upgrade — the same
/// silent-provider-change the fallback decision was written to prevent, one line
/// away. The deserialization defaults are frozen; only construction paths carry
/// the new pair.
#[test]
fn issue66_existing_config_omitting_primary_keeps_its_provider() {
    // [chain] stanza present, api_url omitted -> legacy default, no fallback.
    let chain: ChainConfig = toml::from_str("backend = \"esplora\"\n").unwrap();
    match chain {
        ChainConfig::Esplora {
            api_url,
            esplora_url_fallback,
            ..
        } => {
            assert_eq!(
                api_url, "https://mempool.space",
                "upgrading the binary must not move an existing config's chain provider"
            );
            assert_eq!(
                esplora_url_fallback, None,
                "and must not inject a third-party fallback it never chose"
            );
        }
        ChainConfig::Mock | ChainConfig::Bitcoind(_) | ChainConfig::Electrum(_) => panic!("expected esplora"),
    }

    // [lightning] backend = "ldk", esplora_url omitted -> legacy default, no fallback.
    let ldk: LightningConfig = toml::from_str("backend = \"ldk\"\n").unwrap();
    match ldk {
        LightningConfig::Ldk {
            esplora_url,
            esplora_url_fallback,
            ..
        } => {
            assert_eq!(
                esplora_url, "https://mempool.space/api",
                "upgrading the binary must not move an existing config's LDK provider"
            );
            assert_eq!(esplora_url_fallback, None);
        }
        other => panic!("expected ldk, got {other:?}"),
    }
}

/// An explicit primary is always honoured, with or without a fallback.
#[test]
fn issue66_explicit_primary_is_never_overridden() {
    let chain: ChainConfig =
        toml::from_str("backend = \"esplora\"\napi_url = \"https://esplora.mine.internal\"\n")
            .unwrap();
    match chain {
        ChainConfig::Esplora {
            api_url,
            esplora_url_fallback,
            ..
        } => {
            assert_eq!(api_url, "https://esplora.mine.internal");
            assert_eq!(
                esplora_url_fallback, None,
                "an operator running their own Esplora must not silently gain a public one"
            );
        }
        ChainConfig::Mock | ChainConfig::Bitcoind(_) | ChainConfig::Electrum(_) => panic!("expected esplora"),
    }
}

/// genome #66, half one: a node created by `init` ships with TWO chain
/// providers, written into its own config where the operator can see and edit
/// them. A single unreachable or degraded provider must not stop a fresh node
/// from starting.
#[test]
fn issue66_fresh_full_tier_config_ships_a_chain_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let config =
        NodeConfig::default_for_tier(NodeTier::Full, dir.path().join("mnemonic.txt"), dir.path());

    match &config.lightning {
        LightningConfig::Ldk {
            esplora_url,
            esplora_url_fallback,
            ..
        } => {
            let fallback = esplora_url_fallback
                .as_deref()
                .expect("init must write an LDK esplora fallback (#66)");
            assert_ne!(
                fallback, esplora_url,
                "a fallback identical to the primary is not a fallback"
            );
        }
        other => panic!("full tier must use LDK, got {other:?}"),
    }

    match &config.chain {
        ChainConfig::Esplora {
            api_url,
            esplora_url_fallback,
            ..
        } => {
            let fallback = esplora_url_fallback
                .as_deref()
                .expect("init must write a chain esplora fallback (#66)");
            assert_ne!(fallback, api_url, "fallback must differ from the primary");
        }
        other => panic!("full tier must use esplora chain, got {other:?}"),
    }
}

/// genome #66, half two: parsing an EXISTING config that names no fallback must
/// leave it unset. Injecting one would silently point an operator's node at a
/// third-party endpoint they never chose, disclosing its existence and query
/// pattern to a public service behind their back. Resilience is offered at
/// `init`, never imposed on a configuration already in service.
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
            ..
        } => {
            assert_eq!(api_url, "https://legacy.example.com");
            assert_eq!(esplora_url_fallback, None);
        }
        ChainConfig::Mock | ChainConfig::Bitcoind(_) | ChainConfig::Electrum(_) => panic!("expected esplora config"),
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
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    assert!(matches!(config.lightning, LightningConfig::Mock { .. }));
    config.relay.enabled = true; // settlement defaults OFF for Mock → must bail
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string().contains("verify_lightning_settlement"),
        "got: {err}"
    );
    assert!(err.to_string().contains("relay"), "got: {err}");
}

#[test]
fn validate_rejects_price_open_with_mock_settlement_off() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    config.peers.clear();
    assert!(matches!(config.lightning, LightningConfig::Mock { .. }));
    config.admission_mode = konsensus_message::ReachabilityMode::PriceOpen;
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string().contains("verify_lightning_settlement"),
        "got: {err}"
    );
    assert!(err.to_string().contains("price_open"), "got: {err}");
}

#[test]
fn validate_allows_relay_on_mock_with_explicit_settlement_on() {
    // The explicit dev/smoke escape: setting verify_lightning_settlement = true
    // on a Mock backend opts into the settlement-verification path (the mock's
    // own settled-keysend path), so relay/price-open may be mounted for testing.
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
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

#[test]
fn configured_endpoint_reports_its_source_and_blank_advertised_is_unset() {
    let mut net = NetworkConfig { listen_addr: "0.0.0.0:9000".parse().unwrap(), ..Default::default() };
    assert_eq!(net.configured_endpoint(), None, "wildcard alone needs discovery");
    net.advertised_addr = Some("   ".into());
    assert_eq!(net.configured_endpoint(), None, "a blank advertised_addr is unset");
    net.listen_addr = "192.168.1.5:9000".parse().unwrap();
    assert_eq!(net.configured_endpoint(), Some(("192.168.1.5:9000".into(), "listen")));
    net.advertised_addr = Some(" node.example.org:9000 ".into());
    assert_eq!(net.configured_endpoint(), Some(("node.example.org:9000".into(), "advertised")));
    // A stun_server never changes the configured endpoint.
    net.stun_server = Some("stun:stun.example.org:3478".into());
    assert_eq!(net.configured_endpoint(), Some(("node.example.org:9000".into(), "advertised")));
}

#[test]
fn stun_server_is_parsed_and_validated() {
    use crate::config::parse_stun_server;
    assert_eq!(parse_stun_server("stun:stun.example.org:3478").unwrap(), "stun.example.org:3478");
    assert_eq!(parse_stun_server(" 203.0.113.7:3478 ").unwrap(), "203.0.113.7:3478");
    assert_eq!(parse_stun_server("stun:[2001:db8::1]:3478").unwrap(), "[2001:db8::1]:3478");
    for bad in [
        "",
        "stun:",
        "stun:host",
        "host:0",
        "host:99999",
        "host:x",
        ":3478",
        "bad host:3478",
        "[nope]:3478",
        "a/b:1",
        "stuns:stun.example.org:5349",
        "STUNS:stun.example.org:5349",
        "stuns:[2001:db8::1]:3478",
    ] {
        assert!(parse_stun_server(bad).is_err(), "{bad:?} must be rejected");
    }
    let stuns_err = parse_stun_server("stuns:stun.example.org:5349").unwrap_err();
    assert!(
        stuns_err.contains("stuns:") && stuns_err.contains("not supported"),
        "clear reason, got {stuns_err}"
    );
    let mut net = NetworkConfig::default();
    assert_eq!(net.stun_server_addr(), Ok(None));
    net.stun_server = Some("  ".into());
    assert_eq!(net.stun_server_addr(), Ok(None));
    net.stun_server = Some("stun:h.example:3478".into());
    assert_eq!(net.stun_server_addr(), Ok(Some("h.example:3478".into())));
    net.stun_server = Some("stuns:h.example:5349".into());
    assert!(net.stun_server_addr().unwrap_err().contains("stuns:"));
    net.stun_server = Some("h.example".into());
    assert!(net.stun_server_addr().is_err());
    let toml_net: NetworkConfig = toml::from_str("stun_server = \"stun:h.example:3478\"").unwrap();
    assert_eq!(toml_net.stun_server.as_deref(), Some("stun:h.example:3478"));
}

#[test]
fn introduction_endpoint_prefers_advertised_and_skips_wildcards() {
    let mut net = NetworkConfig { listen_addr: "0.0.0.0:9000".parse().unwrap(), ..Default::default() };
    assert_eq!(net.configured_endpoint(), None, "a wildcard bind is not dialable");
    net.listen_addr = "192.168.1.5:9000".parse().unwrap();
    assert_eq!(net.configured_endpoint().map(|e| e.0).as_deref(), Some("192.168.1.5:9000"));
    net.advertised_addr = Some(" node.example.org:9000 ".into());
    assert_eq!(net.configured_endpoint().map(|e| e.0).as_deref(), Some("node.example.org:9000"));
    let toml_net: NetworkConfig = toml::from_str("advertised_addr = \"n.example:1\"").unwrap();
    assert_eq!(toml_net.advertised_addr.as_deref(), Some("n.example:1"));
}

#[test]
fn introduction_network_normalizes_ldk_names() {
    for (configured, canonical) in [
        ("mainnet", Some("bitcoin")), ("BITCOIN", Some("bitcoin")),
        ("testnet3", Some("testnet")), ("Testnet", Some("testnet")),
        ("Signet", Some("signet")), ("Regtest", Some("regtest")),
        ("unknown", None),
    ] {
        let config: LightningConfig = toml::from_str(&format!("backend = \"ldk\"\nnetwork = \"{configured}\"\n")).unwrap();
        assert_eq!(config.bitcoin_network().as_deref(), canonical, "{configured}");
    }
}

#[test]
fn sponsor_is_off_by_default_and_clamped_to_the_spec() {
    let cfg: SponsorConfig = toml::from_str("").unwrap();
    assert!(!cfg.enabled);
    assert!(!cfg.policy().unwrap().enabled);
    let on: SponsorConfig = toml::from_str("enabled = true\ngift_sats = 20000\nfee_sats = 100\npurse_sats = 100000\nkits_per_day = 2").unwrap();
    let p = on.policy().unwrap();
    assert_eq!((p.gift_msat, p.fee_msat, p.purse_msat, p.kits_per_day), (20_000_000, 100_000, 100_000_000, 2));
    for bad in [
        "enabled = true\ngift_sats = 50000\nfee_sats = 100",
        "enabled = true\npurse_sats = 200000",
        "enabled = true\nkits_per_day = 5",
        "enabled = true\nfee_sats = 1000",
    ] {
        let cfg: SponsorConfig = toml::from_str(bad).unwrap();
        assert!(cfg.policy().is_err(), "{bad}");
    }
    assert!(toml::from_str::<SponsorConfig>("enabled = true\nfree_lane = true").is_err(), "unknown keys refused");
}

#[test]
fn channel_fee_subsidy_defaults_to_zero_ceiling() {
    let default = serde_json::to_value(crate::config::SubsidyConfig::default()).unwrap();
    assert_eq!(default["max_funding_fee_rate_sat_per_vb"], 0);
    let old_config: crate::config::SubsidyConfig = serde_json::from_value(serde_json::json!({
        "enabled": true, "max_channel_sats": 50_000, "max_total_budget_sats": 100_000,
        "allowlist": ["01".repeat(32)]
    }))
    .unwrap();
    assert_eq!(
        serde_json::to_value(old_config).unwrap()["max_funding_fee_rate_sat_per_vb"],
        0
    );
}

#[test]
fn calls_stun_listen_is_off_by_default_and_parses() {
    let base = r#"
[identity]
mnemonic_file = "/tmp/m.txt"
[network]
[lightning]
backend = "mock"
[chain]
backend = "mock"
[storage]
backend = "sqlite"
"#;
    let off: NodeConfig = toml::from_str(base).unwrap();
    assert!(off.calls.stun_listen.is_none(), "no STUN socket unless the owner sets one");

    let on: NodeConfig = toml::from_str(&format!("{base}\n[calls]\nstun_listen = \"0.0.0.0:3478\"\n")).unwrap();
    assert_eq!(on.calls.stun_listen, Some("0.0.0.0:3478".parse().unwrap()));

    assert!(toml::from_str::<NodeConfig>(&format!("{base}\n[calls]\nturn_listen = \"0.0.0.0:3478\"\n")).is_err());
    assert!(toml::from_str::<NodeConfig>(&format!("{base}\n[calls]\nstun_listen = \"not-an-addr\"\n")).is_err());
}

#[test]
fn bitcoind_config_accepts_file_auth_and_rejects_inline_secrets() {
    for auth in [
        "cookie_file = '/tmp/bitcoin.cookie'",
        "rpc_user = 'bitsov'\nrpc_password_file = '/tmp/rpc.pass'",
    ] {
        let parsed: ChainConfig = toml::from_str(&format!(
            "backend = 'bitcoind'\nrpc_host = '127.0.0.1'\nrpc_port = 18443\n{auth}"
        )).expect("file-authenticated Bitcoin Core must be supported");
        assert_eq!(parsed.backend_name(), "bitcoind");
    }
    for auth in [
        "rpc_user = 'bitsov'\nrpc_password = 'INLINE_SECRET'",
        "cookie = 'user:INLINE_SECRET'",
        "rpc_url = 'http://user:INLINE_SECRET@localhost:18443'",
    ] {
        assert!(toml::from_str::<ChainConfig>(&format!(
            "backend = 'bitcoind'\nrpc_host = '127.0.0.1'\nrpc_port = 18443\n{auth}"
        )).is_err());
    }
}

#[test]
fn rejected_inline_rpc_secret_is_absent_from_startup_errors() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.toml");
    let mut config = NodeConfig::default_for_tier(NodeTier::Full, dir.path().join("mnemonic"), dir.path());
    config.chain = ChainConfig::Mock;
    let content = toml::to_string(&config).unwrap().replace("backend = \"mock\"", "backend = \"bitcoind\"\nrpc_password = \"NEVER_LOG_THIS_PASSWORD\"");
    std::fs::write(&path, content).unwrap();
    let error = NodeConfig::load(&path).unwrap_err();
    assert!(!format!("{error:?}").contains("NEVER_LOG_THIS_PASSWORD"));
    assert!(!format!("{error:#}").contains("NEVER_LOG_THIS_PASSWORD"));
}

#[test]
fn electrum_config_accepts_explicit_servers_and_operator() {
    for (url, operator) in [
        ("tcp://127.0.0.1:50001", ""),
        ("tcp://192.168.1.2:50001", "operator = 'own'"),
        ("tcp://[::1]:50001", ""),
        ("ssl://electrum.example:50002", "operator = 'third_party'"),
    ] {
        let parsed: ChainConfig = toml::from_str(&format!(
            "backend = 'electrum'\nserver_url = '{url}'\n{operator}"
        ))
        .unwrap();
        assert_eq!(parsed.backend_name(), "electrum");
    }
}

#[test]
fn electrum_config_rejects_onion_servers_without_a_proxy_setting() {
    for scheme in ["tcp", "ssl"] {
        for host in ["server.onion", "SERVER.ONION", "server.OnIoN"] {
            let url = format!("{scheme}://{host}:50001");
            let error = toml::from_str::<ChainConfig>(&format!(
                "backend = 'electrum'\nserver_url = '{url}'"
            ))
            .expect_err(&format!("accepted {url}"));
            assert!(
                error.to_string().contains(
                    "Tor/.onion Electrum servers are not supported yet: no proxy setting"
                ),
                "{url}: {error}"
            );
        }
    }
}

#[test]
fn electrum_config_rejects_missing_invalid_or_fallback_settings() {
    for fields in [
        "",
        "server_url = ''",
        "server_url = 'tcp://8.8.8.8:50001'",
        "server_url = 'tcp://electrum.example:50001'",
        "server_url = 'http://127.0.0.1:50001'",
        "server_url = 'ssl://user:secret@electrum.example:50002'",
        "server_url = 'ssl://electrum.example:0'",
        "server_url = 'ssl://electrum.example'",
        "server_url = 'ssl://electrum.example:50002/path'",
        "server_url = 'ssl://electrum.example:50002'\noperator = 'trusted'",
        "server_url = 'tcp://127.0.0.1:50001'\nesplora_url_fallback = 'https://example.invalid'",
    ] {
        assert!(
            toml::from_str::<ChainConfig>(&format!("backend = 'electrum'\n{fields}")).is_err(),
            "accepted {fields}"
        );
    }
}

#[test]
fn logging_config_accepts_bounded_rotation_settings() {
    let config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/dev/null"),
        Path::new("/tmp"),
    );
    let mut value = toml::Value::try_from(config).unwrap();
    value.as_table_mut().unwrap().insert(
        "logging".into(),
        toml::from_str::<toml::Value>("max_file_size_bytes = 128\nmax_files = 3").unwrap(),
    );
    let parsed: Result<NodeConfig, _> = value.try_into();
    let parsed = parsed.expect("logging rotation settings must be accepted");
    assert_eq!(parsed.logging.max_file_size_bytes.get(), 128);
    assert_eq!(parsed.logging.max_files.get(), 3);
}

#[test]
fn logging_config_defaults_partial_sections_and_rejects_invalid_limits() {
    use konsensus_core::logging::LoggingConfig;
    let config: LoggingConfig = toml::from_str("max_files = 2").unwrap();
    assert_eq!(config.max_files.get(), 2);
    assert_eq!(config.max_file_size_bytes.get(), 10 * 1024 * 1024);
    let config: LoggingConfig = toml::from_str("max_file_size_bytes = 128").unwrap();
    assert_eq!(config.max_files.get(), 5);
    for invalid in [
        "max_files = 0",
        "max_file_size_bytes = 0",
        "max_files = -1",
        "max_size = 128",
    ] {
        assert!(toml::from_str::<LoggingConfig>(invalid).is_err());
    }
}

#[test]
fn issue204_chain_accepts_api_url_fallback_alias() {
    let chain: ChainConfig = toml::from_str(r#"
backend = "esplora"
api_url = "https://primary.invalid"
api_url_fallback = "https://fallback.invalid/api"
"#).unwrap();
    assert!(matches!(chain, ChainConfig::Esplora { esplora_url_fallback: Some(url), .. } if url == "https://fallback.invalid/api"));
}

#[test]
fn issue204_chain_fallback_resolution_keeps_primary_and_reuses_ldk() {
    let chain: ChainConfig = toml::from_str("backend = 'esplora'\napi_url = 'https://chain.invalid'\n").unwrap();
    let ldk: LightningConfig = toml::from_str("backend = 'ldk'\nesplora_url = 'https://ldk.invalid/api'\nesplora_url_fallback = 'https://backup.invalid/api'\n").unwrap();
    assert_eq!(chain.esplora_fallbacks(&ldk), vec!["https://ldk.invalid/api", "https://backup.invalid/api"]);
    let explicit: ChainConfig = toml::from_str("backend = 'esplora'\napi_url_fallback = 'https://explicit.invalid'\n").unwrap();
    assert_eq!(explicit.esplora_fallbacks(&ldk), vec!["https://explicit.invalid"]);
    assert!(chain.esplora_fallbacks(&LightningConfig::Mock { initial_balance_msat: 0 }).is_empty());
}

#[test]
fn oauth_credentials_files_are_explicit_and_optional() {
    let chain: ChainConfig = toml::from_str("backend = 'esplora'\napi_url = 'https://paid.invalid/api'\ncredentials_file = '/private/chain.toml'").unwrap();
    assert!(matches!(chain, ChainConfig::Esplora { credentials_file: Some(path), .. } if path == std::path::Path::new("/private/chain.toml")));
    let ldk: LightningConfig = toml::from_str("backend = 'ldk'\ncredentials_file = '/private/ldk.toml'").unwrap();
    assert!(matches!(ldk, LightningConfig::Ldk { credentials_file: Some(path), .. } if path == std::path::Path::new("/private/ldk.toml")));
    let chain: ChainConfig = toml::from_str("backend = 'esplora'").unwrap();
    assert!(matches!(chain, ChainConfig::Esplora { credentials_file: None, .. }));
    let ldk: LightningConfig = toml::from_str("backend = 'ldk'").unwrap();
    assert!(matches!(ldk, LightningConfig::Ldk { credentials_file: None, .. }));
}

#[test]
fn ldk_sync_intervals_parse_and_round_trip() {
    let input = r#"
backend = "ldk"
onchain_wallet_sync_interval_secs = 600
lightning_wallet_sync_interval_secs = 60
fee_rate_cache_update_interval_secs = 1800
"#;
    let lightning: LightningConfig = toml::from_str(input).expect("accept optional sync intervals");
    let output = toml::to_string(&lightning).unwrap();
    for setting in [
        "onchain_wallet_sync_interval_secs = 600",
        "lightning_wallet_sync_interval_secs = 60",
        "fee_rate_cache_update_interval_secs = 1800",
    ] {
        assert!(output.contains(setting), "missing {setting}: {output}");
    }
}

#[test]
fn ldk_sync_intervals_validate_each_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic = dir.path().join("mnemonic");
    std::fs::write(&mnemonic, "test mnemonic").unwrap();
    for field in [
        "onchain_wallet_sync_interval_secs",
        "lightning_wallet_sync_interval_secs",
        "fee_rate_cache_update_interval_secs",
    ] {
        for value in [0, 9, 10, 3600, 3601, i64::MAX] {
            let mut config =
                NodeConfig::default_for_tier(NodeTier::Full, mnemonic.clone(), dir.path());
            config.lightning =
                toml::from_str(&format!("backend = \"ldk\"\n{field} = {value}\n")).unwrap();
            let result = config.validate();
            if (10..=3600).contains(&value) {
                result.unwrap_or_else(|e| panic!("{field}={value}: {e}"));
            } else {
                let error = result.unwrap_err().to_string();
                assert!(error.contains(field), "{field}={value}: {error}");
                assert!(error.contains("10") && error.contains("3600"), "{error}");
            }
        }
    }
}

#[test]
fn ldk_sync_intervals_reject_bad_types_and_unknown_keys() {
    for field in [
        "onchain_wallet_sync_interval_secs",
        "lightning_wallet_sync_interval_secs",
        "fee_rate_cache_update_interval_secs",
    ] {
        for value in ["-1", "10.5", "true", "\"600\""] {
            assert!(toml::from_str::<LightningConfig>(&format!(
                "backend = \"ldk\"\n{field} = {value}\n"
            ))
            .is_err());
        }
        assert!(toml::from_str::<LightningConfig>(&format!(
            "backend = \"ldk\"\n{field}_typo = 600\n"
        ))
        .is_err());
    }
}

#[test]
fn ldk_sync_intervals_reach_esplora_config_with_independent_defaults() {
    use ldk_node::config::{BackgroundSyncConfig, EsploraSyncConfig};
    let omitted: LightningConfig = toml::from_str("backend = 'ldk'").unwrap();
    assert_eq!(
        omitted.esplora_sync_intervals().to_sync_config().unwrap(),
        EsploraSyncConfig::default()
    );
    let serialized = toml::to_string(&omitted).unwrap();
    assert!(!serialized.contains("_interval_secs"));
    for (settings, expected) in [
        ("", (80, 30, 600)),
        ("onchain_wallet_sync_interval_secs = 600", (600, 30, 600)),
        ("lightning_wallet_sync_interval_secs = 60", (80, 60, 600)),
        ("fee_rate_cache_update_interval_secs = 1800", (80, 30, 1800)),
        ("onchain_wallet_sync_interval_secs = 600\nlightning_wallet_sync_interval_secs = 60\nfee_rate_cache_update_interval_secs = 1800", (600, 60, 1800)),
    ] {
        let lightning: LightningConfig = toml::from_str(&format!("backend = 'ldk'\n{settings}")).unwrap();
        assert_eq!(lightning.esplora_sync_intervals().to_sync_config().unwrap(), EsploraSyncConfig {
            background_sync_config: Some(BackgroundSyncConfig {
                onchain_wallet_sync_interval_secs: expected.0,
                lightning_wallet_sync_interval_secs: expected.1,
                fee_rate_cache_update_interval_secs: expected.2,
            }),
        });
    }
}

#[test]
fn private_forwarding_is_opt_in_and_round_trips() {
    for (setting, expected) in [
        ("", false),
        ("forward_to_private_channels = false", false),
        ("forward_to_private_channels = true", true),
    ] {
        let config: LightningConfig = toml::from_str(&format!("backend = 'ldk'\n{setting}")).unwrap();
        let serialized = toml::to_string(&config).unwrap();
        let table: toml::Value = toml::from_str(&serialized).unwrap();
        assert_eq!(table["forward_to_private_channels"].as_bool(), Some(expected));
        let round_trip: LightningConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(toml::to_string(&round_trip).unwrap(), serialized);
    }
}

#[test]
fn private_forwarding_rejects_non_boolean_values() {
    for value in ["1", "'true'", "[]"] {
        assert!(toml::from_str::<LightningConfig>(&format!(
            "backend = 'ldk'\nforward_to_private_channels = {value}"
        )).is_err());
    }
}

#[test]
fn lsps2_service_is_opt_in_and_round_trips() {
    let omitted: LightningConfig = toml::from_str("backend = 'ldk'").unwrap();
    let table: toml::Value = toml::from_str(&toml::to_string(&omitted).unwrap()).unwrap();
    assert_eq!(table["lsps2_service"]["enabled"].as_bool(), Some(false));
    let config: LightningConfig = toml::from_str("backend = 'ldk'\n[lsps2_service]\nenabled = true\nrequire_token = 'pilot-secret'\nforwarding_fee_ppm = 500\nforwarding_fee_base_msat = 1000").unwrap();
    let serialized = toml::to_string(&config).unwrap();
    let round_trip: LightningConfig = toml::from_str(&serialized).unwrap();
    assert_eq!(toml::to_string(&round_trip).unwrap(), serialized);
    assert!(!format!("{config:?}").contains("pilot-secret"));
}

#[test]
fn lsps2_service_rejects_unknown_or_mistyped_fields() {
    for settings in [
        "enabled = 'true'",
        "forwarding_fee_ppm = -1",
        "forwarding_fee_base_msat = 4294967296",
        "advertise_service = true",
        "client_trusts_lsp = true",
        "require_tokne = 'secret'",
    ] {
        assert!(
            toml::from_str::<LightningConfig>(&format!(
                "backend = 'ldk'\n[lsps2_service]\n{settings}"
            ))
            .is_err(),
            "{settings}"
        );
    }
}

#[test]
fn lsps2_service_validation_precedes_node_startup() {
    let mut config = NodeConfig::default_for_tier(
        NodeTier::Light,
        PathBuf::from("/nonexistent-mnemonic"),
        Path::new("/tmp"),
    );
    config.lightning = toml::from_str("backend = 'ldk'\n[lsps2_service]\nenabled = true\nrequire_token = 'secret'\n[liquidity]\nenabled = true").unwrap();
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("mutually exclusive"));
}
