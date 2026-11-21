use super::*;
use crate::config::NodeTier;
use clap::Parser;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

fn config_with(dir: &std::path::Path, chain: &str, lightning: &str) -> NodeConfig {
    let mnemonic = dir.join("mnemonic.txt");
    std::fs::write(&mnemonic, MNEMONIC).unwrap();
    let base = NodeConfig::default_for_tier(NodeTier::Light, mnemonic, dir);
    let mut table = toml::Table::try_from(&base).unwrap();
    table.insert("chain".into(), toml::Value::Table(toml::from_str(chain).unwrap()));
    table.insert(
        "lightning".into(),
        toml::Value::Table(toml::from_str(lightning).unwrap()),
    );
    toml::from_str(&toml::to_string(&table).unwrap()).unwrap()
}

#[test]
fn describe_names_each_source_by_host() {
    let dir = tempfile::tempdir().unwrap();
    for (chain, lightning, expected) in [
        (
            "backend = \"bitcoind\"\nrpc_host = \"127.0.0.1\"\nrpc_port = 38332\n\
             cookie_file = \"/home/b/.bitcoin/signet/.cookie\"",
            "backend = \"ldk\"\nnetwork = \"signet\"",
            "owned tip: Bitcoin Core RPC at 127.0.0.1:38332 (own_node)",
        ),
        (
            "backend = \"electrum\"\nserver_url = \"tcp://127.0.0.1:50001\"\noperator = \"own\"",
            "backend = \"ldk\"\nnetwork = \"signet\"",
            "owned tip: Electrum server 127.0.0.1 you declared as yours (own_node)",
        ),
        (
            "backend = \"electrum\"\nserver_url = \"tcp://127.0.0.1:50001\"",
            "backend = \"mock\"",
            "third_party: an Electrum server not declared as yours",
        ),
        (
            "backend = \"esplora\"\napi_url = \"https://mempool.space/signet\"\n\
             accept_third_party_tip = true",
            "backend = \"mock\"",
            "third_party: public Esplora at mempool.space, accepted (accept_third_party_tip = true)",
        ),
        (
            "backend = \"esplora\"\napi_url = \"https://esplora.mine.internal/api\"",
            "backend = \"mock\"",
            "third_party: Esplora at esplora.mine.internal",
        ),
        (
            "backend = \"esplora\"\napi_url = \"https://mempool.space/signet\"",
            "backend = \"mock\"",
            "third_party, explorer_default: a public explorer this node never explicitly accepted \
             ([chain] mempool.space)",
        ),
        (
            "backend = \"mock\"",
            "backend = \"mock\"",
            "mock: no chain source (simulated data)",
        ),
    ] {
        let config = config_with(dir.path(), chain, lightning);
        assert_eq!(describe(&config), expected, "{chain}");
    }
}

/// Only `--config`: there is no flag that could write.
#[test]
fn the_command_takes_only_a_config_path() {
    let cli = crate::cli::Cli::try_parse_from(["konsensus", "chain-tip", "--config", "/x/k.toml"])
        .unwrap();
    match cli.command {
        crate::cli::Command::ChainTip(args) => {
            assert_eq!(args.config, PathBuf::from("/x/k.toml"));
        }
        _ => panic!("expected the chain-tip command"),
    }
    for flag in ["--accept-third-party-tip", "--chain", "--electrum-server-url", "--cookie-file"] {
        assert!(
            crate::cli::Cli::try_parse_from(["konsensus", "chain-tip", flag, "x"]).is_err(),
            "{flag}"
        );
    }
}
