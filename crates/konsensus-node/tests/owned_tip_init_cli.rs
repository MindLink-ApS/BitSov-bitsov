//! Fresh Full onboarding owns the tip; public explorers require consent.
use std::{
    path::Path,
    process::{Command, Output},
};

use konsensus_core::traits::chain::{ChainProvider, TrustLevel};

fn init(dir: &Path, tier: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["init", "--non-interactive", "--tier", tier, "--dir"])
        .arg(dir)
        .args(args)
        .output()
        .unwrap()
}

fn written_config(dir: &Path, output: &Output) -> toml::Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    toml::from_str(&std::fs::read_to_string(dir.join("konsensus.toml")).unwrap()).unwrap()
}

fn assert_no_explorers(dir: &Path, config: &toml::Value) {
    let text = std::fs::read_to_string(dir.join("konsensus.toml")).unwrap();
    assert!(!text.contains("blockstream.info"));
    assert!(!text.contains("mempool.space"));
    assert_eq!(config["lightning"]["esplora_url"].as_str(), Some(""));
    assert!(config["lightning"].get("esplora_url_fallback").is_none());
}

#[test]
fn full_init_defaults_to_owned_bitcoind_without_explorer_urls() {
    for args in [vec![], vec!["--chain", "bitcoind"]] {
        let dir = tempfile::tempdir().unwrap();
        let output = init(dir.path(), "full", &args);
        let config = written_config(dir.path(), &output);
        assert_eq!(config["chain"]["backend"].as_str(), Some("bitcoind"));
        let mut chain = config["chain"].clone();
        chain.as_table_mut().unwrap().remove("backend");
        let rpc: konsensus_chain::BitcoindConfig = chain.try_into().unwrap();
        rpc.validate().unwrap();
        assert_eq!(rpc.rpc_host, "127.0.0.1");
        assert_eq!(rpc.rpc_port, 8332);
        let cookie = rpc.cookie_file.unwrap();
        assert!(cookie.ends_with(".bitcoin/.cookie"));
        assert!(cookie.is_absolute(), "init should expand HOME");
        assert_eq!(config["lightning"]["network"].as_str(), Some("bitcoin"));
        assert_no_explorers(dir.path(), &config);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("owned tip"), "{stdout}");
        assert!(stdout.contains("third_party"), "{stdout}");
    }
}

#[test]
fn full_esplora_without_acceptance_writes_nothing() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("node");
    let output = init(&dir, "full", &["--chain", "esplora"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--accept-third-party-tip"), "{stderr}");
    assert!(!dir.exists() || std::fs::read_dir(dir).unwrap().next().is_none());
}

#[test]
fn accepted_esplora_is_written_and_reported_as_third_party() {
    let dir = tempfile::tempdir().unwrap();
    let output = init(
        dir.path(),
        "full",
        &["--chain", "esplora", "--accept-third-party-tip"],
    );
    let config = written_config(dir.path(), &output);
    assert_eq!(config["chain"]["backend"].as_str(), Some("esplora"));
    assert_eq!(
        config["chain"]["api_url"].as_str(),
        Some("https://blockstream.info")
    );
    assert_eq!(
        config["lightning"]["esplora_url"].as_str(),
        Some("https://blockstream.info/api")
    );
    assert_eq!(
        config["chain"]["esplora_url_fallback"].as_str(),
        Some("https://mempool.space")
    );
    assert_eq!(
        config["lightning"]["esplora_url_fallback"].as_str(),
        Some("https://mempool.space/api")
    );
    let provider = konsensus_chain::EsploraProvider::new(konsensus_chain::EsploraConfig::custom(
        config["chain"]["api_url"].as_str().unwrap().into(),
        TrustLevel::ServerTrust,
    ))
    .unwrap();
    assert_eq!(provider.chain_view().trust_level, "third_party");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("third_party tip"), "{stdout}");
    assert!(!stdout.contains("starts on an owned tip"), "{stdout}");
}

#[test]
fn electrum_requires_operator_details_without_writing_state() {
    for (args, expected_error) in [
        (vec!["--chain", "electrum"], "--electrum-server-url"),
        (
            vec![
                "--chain",
                "electrum",
                "--electrum-server-url",
                "tcp://127.0.0.1:50001",
            ],
            "--electrum-operator",
        ),
        (
            vec![
                "--chain",
                "electrum",
                "--electrum-server-url",
                "tcp://public.example:50001",
                "--electrum-operator",
                "own",
            ],
            "tcp requires loopback or a private LAN IP",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let output = init(&dir, "full", &args);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected_error), "{stderr}");
        assert!(!dir.exists() || std::fs::read_dir(dir).unwrap().next().is_none());
    }
}

#[test]
fn full_electrum_uses_the_declared_server_without_explorers() {
    for (operator, trust) in [("own", "own_node"), ("third_party", "third_party")] {
        let dir = tempfile::tempdir().unwrap();
        let output = init(
            dir.path(),
            "full",
            &[
                "--chain",
                "electrum",
                "--electrum-server-url",
                "tcp://127.0.0.1:50001",
                "--electrum-operator",
                operator,
            ],
        );
        let config = written_config(dir.path(), &output);
        assert_eq!(config["chain"]["backend"].as_str(), Some("electrum"));
        let mut chain = config["chain"].clone();
        chain.as_table_mut().unwrap().remove("backend");
        let server: konsensus_chain::ElectrumConfig = chain.try_into().unwrap();
        assert_eq!(server.server_url, "tcp://127.0.0.1:50001");
        let provider = konsensus_chain::ElectrumProvider::new(server).unwrap();
        assert_eq!(provider.chain_view().trust_level, trust);
        assert_no_explorers(dir.path(), &config);
    }
}

#[test]
fn light_and_cloud_keep_mock_backends() {
    for tier in ["light", "cloud"] {
        let dir = tempfile::tempdir().unwrap();
        let output = init(dir.path(), tier, &[]);
        let config = written_config(dir.path(), &output);
        assert_eq!(config["chain"]["backend"].as_str(), Some("mock"));
        assert_eq!(config["lightning"]["backend"].as_str(), Some("mock"));
    }
}

#[test]
fn chain_options_reject_wrong_tiers_or_conflicting_details() {
    for (tier, args) in [
        (
            "light",
            vec!["--chain", "esplora", "--accept-third-party-tip"],
        ),
        (
            "cloud",
            vec![
                "--chain",
                "electrum",
                "--electrum-server-url",
                "tcp://127.0.0.1:50001",
                "--electrum-operator",
                "own",
            ],
        ),
        (
            "full",
            vec![
                "--chain",
                "bitcoind",
                "--electrum-server-url",
                "tcp://127.0.0.1:50001",
            ],
        ),
        ("full", vec!["--chain", "unknown"]),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let output = init(&dir, tier, &args);
        assert!(!output.status.success());
        assert!(!dir.exists() || std::fs::read_dir(dir).unwrap().next().is_none());
    }
}
