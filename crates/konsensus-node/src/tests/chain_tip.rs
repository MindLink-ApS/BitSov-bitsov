use super::*;
use crate::config::{NodeConfig, NodeTier};
use konsensus_chain::MockChainProvider;

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

/// A generated config with `[chain]` and `[lightning]` replaced by TOML, so
/// serde defaults apply exactly as they do for a file on disk.
fn config_with(dir: &std::path::Path, chain: &str, lightning: &str) -> NodeConfig {
    let mnemonic = dir.join("mnemonic.txt");
    std::fs::write(&mnemonic, MNEMONIC).unwrap();
    let base = NodeConfig::default_for_tier(NodeTier::Light, mnemonic, dir);
    let mut table = toml::Table::try_from(&base).unwrap();
    table.insert(
        "chain".into(),
        toml::Value::Table(toml::from_str(chain).unwrap()),
    );
    table.insert(
        "lightning".into(),
        toml::Value::Table(toml::from_str(lightning).unwrap()),
    );
    toml::from_str(&toml::to_string(&table).unwrap()).unwrap()
}

fn sources(found: Option<ExplorerDefault>) -> Vec<(&'static str, &'static str)> {
    found
        .map(|f| f.sources.iter().map(|s| (s.stanza, s.host)).collect())
        .unwrap_or_default()
}

const LDK_OMITTED_URLS: &str = "backend = \"ldk\"\nnetwork = \"signet\"";

#[test]
fn frozen_url_defaults_are_an_explorer_default() {
    // An old config that never wrote any URL: both frozen defaults apply.
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(dir.path(), "backend = \"esplora\"", LDK_OMITTED_URLS);
    assert_eq!(
        sources(explorer_default(&config)),
        [("chain", "mempool.space"), ("lightning", "mempool.space")]
    );
}

#[test]
fn an_older_generated_pair_is_an_explorer_default() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(
        dir.path(),
        "backend = \"esplora\"\napi_url = \"https://blockstream.info\"\n\
         esplora_url_fallback = \"https://mempool.space\"",
        "backend = \"ldk\"\nnetwork = \"bitcoin\"\nesplora_url = \"https://blockstream.info/api\"\n\
         esplora_url_fallback = \"https://mempool.space/api\"",
    );
    assert_eq!(
        sources(explorer_default(&config)),
        [
            ("chain", "blockstream.info"),
            ("chain", "mempool.space"),
            ("lightning", "blockstream.info"),
            ("lightning", "mempool.space"),
        ]
    );
}

#[test]
fn documented_network_paths_count_too() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(
        dir.path(),
        "backend = \"esplora\"\napi_url = \"https://mempool.space/signet\"",
        "backend = \"ldk\"\nnetwork = \"signet\"\nesplora_url = \"https://mempool.space/signet/api\"",
    );
    assert_eq!(
        sources(explorer_default(&config)),
        [("chain", "mempool.space"), ("lightning", "mempool.space")]
    );
}

#[test]
fn an_explicit_acceptance_is_not_an_explorer_default() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(
        dir.path(),
        "backend = \"esplora\"\naccept_third_party_tip = true",
        LDK_OMITTED_URLS,
    );
    assert!(explorer_default(&config).is_none());
    assert!(matches!(
        config.chain,
        ChainConfig::Esplora {
            accept_third_party_tip: true,
            ..
        }
    ));
}

#[test]
fn acceptance_defaults_off_and_is_never_written_when_off() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(dir.path(), "backend = \"esplora\"", LDK_OMITTED_URLS);
    assert!(matches!(
        config.chain,
        ChainConfig::Esplora {
            accept_third_party_tip: false,
            ..
        }
    ));
    let text = toml::to_string(&config).unwrap();
    assert!(!text.contains("accept_third_party_tip"), "{text}");
}

#[test]
fn chosen_sources_are_not_explorer_defaults() {
    let dir = tempfile::tempdir().unwrap();
    for (chain, lightning) in [
        // Your own Esplora.
        (
            "backend = \"esplora\"\napi_url = \"https://esplora.mine.internal\"",
            "backend = \"ldk\"\nnetwork = \"signet\"\nesplora_url = \"https://esplora.mine.internal/api\"",
        ),
        // A paid source with credentials.
        (
            "backend = \"esplora\"\napi_url = \"https://enterprise.blockstream.info/api\"\n\
             credentials_file = \"/secrets/chain-api.toml\"",
            "backend = \"ldk\"\nnetwork = \"bitcoin\"\nesplora_url = \"https://enterprise.blockstream.info/api\"\n\
             credentials_file = \"/secrets/chain-api.toml\"",
        ),
        // Credentials on a public host: a paid account the owner chose.
        (
            "backend = \"esplora\"\napi_url = \"https://blockstream.info/api\"\n\
             credentials_file = \"/secrets/chain-api.toml\"\n\
             esplora_url_fallback = \"https://esplora.mine.internal\"",
            "backend = \"ldk\"\nnetwork = \"bitcoin\"\nesplora_url = \"https://blockstream.info/api\"\n\
             credentials_file = \"/secrets/chain-api.toml\"",
        ),
        // Core or Electrum: LDK follows [chain]; its frozen URL default is unused.
        (
            "backend = \"bitcoind\"\nrpc_host = \"127.0.0.1\"\nrpc_port = 38332\n\
             cookie_file = \"/home/b/.bitcoin/signet/.cookie\"",
            LDK_OMITTED_URLS,
        ),
        (
            "backend = \"electrum\"\nserver_url = \"tcp://127.0.0.1:50001\"\noperator = \"own\"",
            LDK_OMITTED_URLS,
        ),
        // Nothing real at all.
        ("backend = \"mock\"", "backend = \"mock\""),
    ] {
        let config = config_with(dir.path(), chain, lightning);
        assert_eq!(explorer_default(&config), None, "{chain}");
    }
}

#[test]
fn embedded_lightning_alone_on_a_public_explorer_counts() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(dir.path(), "backend = \"mock\"", LDK_OMITTED_URLS);
    assert_eq!(
        sources(explorer_default(&config)),
        [("lightning", "mempool.space")]
    );
}

#[test]
fn public_explorer_hosts_match_exactly() {
    for url in [
        "https://mempool.space",
        "https://mempool.space/api",
        "http://MEMPOOL.space/testnet/api",
        "https://blockstream.info./api",
        " https://blockstream.info/signet/api ",
    ] {
        assert!(public_explorer_host(url).is_some(), "{url}");
    }
    for url in [
        "https://mempool.space.example.com",
        "https://evilmempool.space",
        "https://enterprise.blockstream.info/api",
        "ssl://blockstream.info:700",
        "mempool.space",
        "",
    ] {
        assert!(public_explorer_host(url).is_none(), "{url}");
    }
}

#[test]
fn the_warning_names_the_source_and_both_ways_out() {
    let found = ExplorerDefault {
        sources: vec![
            ExplorerSource {
                stanza: "chain",
                host: "mempool.space",
            },
            ExplorerSource {
                stanza: "lightning",
                host: "blockstream.info",
            },
        ],
    };
    let warning = found.warning();
    for needle in [
        "[chain] mempool.space",
        "[lightning] blockstream.info",
        "third_party",
        "Nothing was changed",
        "konsensus chain-tip",
        "--chain bitcoind",
        "--chain electrum",
        "--accept-third-party-tip",
    ] {
        assert!(warning.contains(needle), "{needle}: {warning}");
    }
}

#[tokio::test]
async fn the_label_marks_owner_status_and_passes_reads_through() {
    let found = ExplorerDefault {
        sources: vec![ExplorerSource {
            stanza: "lightning",
            host: "mempool.space",
        }],
    };
    let inner: Arc<dyn ChainProvider> = Arc::new(MockChainProvider::new());
    let labelled = label(Arc::clone(&inner), Some(&found));
    let view = labelled.chain_view();
    assert_eq!(view.backend, "mock");
    assert_eq!(view.trust_level, "third_party");
    assert!(view.explorer_default);
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["explorer_default"], true);
    assert_eq!(
        labelled.get_block_height().await.unwrap(),
        inner.get_block_height().await.unwrap()
    );
    assert_eq!(labelled.is_synced().await, inner.is_synced().await);
    assert_eq!(labelled.trust_level(), inner.trust_level());

    let plain = label(Arc::clone(&inner), None);
    let json = serde_json::to_value(plain.chain_view()).unwrap();
    assert!(json.get("explorer_default").is_none(), "{json}");
    assert_eq!(json["trust_level"], "simulated");
}

/// Start labels the node and never touches its config file.
#[tokio::test]
async fn start_labels_without_changing_the_config() {
    for (chain, expected) in [
        ("backend = \"esplora\"", true),
        (
            "backend = \"esplora\"\naccept_third_party_tip = true",
            false,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        // Mock Lightning: no network is contacted while the node is built.
        let config = config_with(
            dir.path(),
            chain,
            "backend = \"mock\"\ninitial_balance_msat = 1000",
        );
        let path = dir.path().join("konsensus.toml");
        config.save(&path).unwrap();
        let before = std::fs::read(&path).unwrap();
        let loaded = NodeConfig::load(&path).unwrap();
        let node = crate::node::KonsensusNode::from_config(loaded, None)
            .await
            .unwrap();
        let view = node.chain().chain_view();
        assert_eq!(view.backend, "esplora");
        assert_eq!(view.trust_level, "third_party");
        assert_eq!(view.explorer_default, expected, "{chain}");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "start must not edit the config"
        );
    }
}
