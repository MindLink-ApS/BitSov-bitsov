use konsensus_lightning::{
    liquidity::{LiquidityConfig, LspConfig},
    lsps2_service::Lsps2ServiceConfig,
    LdkConfig, LnbitsConfig, LndConfig, LndProvider,
};

fn assert_redacted(value: &impl std::fmt::Debug, secrets: &[&str], visible: &[&str]) {
    for output in [format!("{value:?}"), format!("{value:#?}")] {
        for secret in secrets {
            assert!(!output.contains(secret), "credential leaked through Debug");
        }
        assert!(output.contains("<redacted>"));
        for field in visible {
            assert!(output.contains(field), "missing diagnostic field: {field}");
        }
    }
}

#[test]
fn lnd_config_and_provider_debug_redact_macaroon() {
    let config = LndConfig {
        api_url: "https://localhost:8080".into(),
        macaroon_hex: "deadbeef0123456789".into(),
        tls_cert_path: Some("/certs/lnd.pem".into()),
    };
    assert_redacted(
        &config,
        &[&config.macaroon_hex],
        &["macaroon_hex", "https://localhost:8080", "/certs/lnd.pem"],
    );
    let provider = LndProvider::with_client(config, reqwest::Client::new());
    assert_redacted(
        &provider,
        &["deadbeef0123456789"],
        &["LndProvider", "payment_capable", "https://localhost:8080"],
    );
}

#[test]
fn lnbits_debug_redacts_admin_key() {
    let config = LnbitsConfig {
        api_url: "http://localhost:5000".into(),
        admin_key: "lnbits-secret-admin-key".into(),
    };
    assert_redacted(
        &config,
        &[&config.admin_key],
        &["admin_key", "http://localhost:5000"],
    );
}

#[test]
fn liquidity_debug_redacts_nested_provider_tokens() {
    let config = LiquidityConfig {
        enabled: true,
        providers: vec![LspConfig {
            node_id: "public-node-id".into(),
            address: "localhost:9735".into(),
            token: Some("private-provider-token".into()),
        }],
        selected_provider: Some("public-node-id".into()),
    };
    assert_redacted(
        &config.providers[0],
        &["private-provider-token"],
        &["token", "public-node-id", "localhost:9735"],
    );
    assert_redacted(
        &config,
        &["private-provider-token"],
        &["providers", "public-node-id"],
    );
}

#[test]
fn lsps2_service_debug_redacts_token_and_keeps_limits() {
    let config = Lsps2ServiceConfig {
        require_token: Some("private-service-token".into()),
        ..Default::default()
    };
    assert_redacted(
        &config,
        &["private-service-token"],
        &[
            "require_token",
            "max_funding_fee_sats",
            "max_jit_capital_sats",
            "forwarding_fee_ppm",
        ],
    );
}

#[test]
fn ldk_debug_redacts_seed_passphrase_and_token() {
    let mut config = LdkConfig {
        tower: Default::default(),
        forward_to_private_channels: false,
        our_to_self_delay_blocks: Some(2016),
        logging: Default::default(),
        bitcoind: None,
        electrum: None,
        liquidity: Default::default(),
        lsps2_service: Default::default(),
        channel_peers: None,
        storage_dir: "/data/ldk".into(),
        scb_backup_dir: None,
        scb_rotation_count: 3,
        mnemonic: "private mnemonic seed phrase".into(),
        passphrase: Some("private-bip39-passphrase".into()),
        network: "regtest".into(),
        esplora_url: "http://localhost:3002".into(),
        esplora_url_fallback: None,
        esplora_sync_intervals: Default::default(),
        credentials_file: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: Some("private-ldk-token".into()),
        listening_address: None,
    };
    assert_redacted(
        &config,
        &[
            &config.mnemonic,
            "private-bip39-passphrase",
            "private-ldk-token",
        ],
        &[
            "mnemonic",
            "passphrase",
            "lsp_token",
            "regtest",
            "/data/ldk",
            "http://localhost:3002",
            "2016",
        ],
    );
    for url in [
        "https://alice:private-url-password@localhost:8080",
        "https://localhost:8080?api_key=private-url-password",
        "https://localhost:8080#private-url-password",
    ] {
        config.esplora_url = url.into();
        config.esplora_url_fallback = Some(url.into());
        config.rgs_url = Some(url.into());
        assert_redacted(
            &config,
            &["private-url-password"],
            &["esplora_url", "esplora_url_fallback", "rgs_url"],
        );
    }
}

#[test]
fn endpoint_debug_redacts_url_credentials() {
    for url in [
        "https://alice:private-url-password@localhost:8080",
        "https://localhost:8080?api_key=private-url-password",
        "https://localhost:8080#private-url-password",
    ] {
        let lnd = LndConfig {
            api_url: url.into(),
            macaroon_hex: "test".into(),
            tls_cert_path: None,
        };
        assert_redacted(&lnd, &["private-url-password"], &["api_url"]);
        assert_redacted(
            &LndProvider::with_client(lnd, reqwest::Client::new()),
            &["private-url-password"],
            &["config"],
        );
        let lnbits = LnbitsConfig {
            api_url: url.into(),
            admin_key: "test".into(),
        };
        assert_redacted(&lnbits, &["private-url-password"], &["api_url"]);
    }
}
