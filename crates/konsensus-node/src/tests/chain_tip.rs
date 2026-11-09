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
        acceptable: true,
    };
    let warning = found.warning();
    for needle in [
        "[chain] mempool.space",
        "[lightning] blockstream.info",
        "third_party",
        "still someone else's view",
        "Nothing was changed",
        "backend = \"bitcoind\"",
        "backend = \"electrum\"",
        "operator = \"own\"",
        "accept_third_party_tip = true",
        "docs/CHAIN-SOURCE.md",
    ] {
        assert!(warning.contains(needle), "{needle}: {warning}");
    }
    // It points to hand edits only: no command that writes the config.
    assert!(!warning.contains("--chain"), "{warning}");
    assert!(!warning.contains("--accept"), "{warning}");
}

/// With `[chain] backend = "mock"` there is nowhere to record acceptance:
/// the warning offers only the move to an owned tip, which works for that config.
#[test]
fn an_ldk_only_explorer_is_not_offered_acceptance() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(dir.path(), "backend = \"mock\"", LDK_OMITTED_URLS);
    let found = explorer_default(&config).unwrap();
    assert!(!found.acceptable);
    let warning = found.warning();
    assert!(!warning.contains("accept_third_party_tip"), "{warning}");
    assert!(warning.contains("backend = \"bitcoind\""), "{warning}");
    assert!(warning.contains("[chain] is mock"), "{warning}");
    let esplora = config_with(dir.path(), "backend = \"esplora\"", LDK_OMITTED_URLS);
    assert!(explorer_default(&esplora).unwrap().acceptable);
}

#[tokio::test]
async fn the_label_marks_owner_status_and_passes_reads_through() {
    let found = ExplorerDefault {
        sources: vec![ExplorerSource {
            stanza: "lightning",
            host: "mempool.space",
        }],
        acceptable: false,
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

#[test]
fn an_explicit_false_acceptance_is_still_an_explorer_default() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(
        dir.path(),
        "backend = \"esplora\"\napi_url = \"https://blockstream.info/testnet\"\n\
         accept_third_party_tip = false",
        "backend = \"mock\"",
    );
    assert_eq!(
        sources(explorer_default(&config)),
        [("chain", "blockstream.info")]
    );
}

/// Acceptance lives only in `[chain]`: it also covers embedded LDK's explorer.
#[test]
fn acceptance_also_covers_embedded_lightning() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(
        dir.path(),
        "backend = \"esplora\"\napi_url = \"https://mempool.space/signet\"\n\
         accept_third_party_tip = true",
        "backend = \"ldk\"\nnetwork = \"signet\"\nesplora_url = \"https://blockstream.info/signet/api\"",
    );
    assert_eq!(explorer_default(&config), None);
}

/// Core or Electrum in `[chain]` also select LDK's source: an explorer URL
/// written in `[lightning]` is unused and not flagged.
#[test]
fn owned_chain_sources_ignore_explicit_ldk_explorer_urls() {
    let dir = tempfile::tempdir().unwrap();
    let ldk = "backend = \"ldk\"\nnetwork = \"signet\"\n\
               esplora_url = \"https://mempool.space/signet/api\"\n\
               esplora_url_fallback = \"https://blockstream.info/signet/api\"";
    for chain in [
        "backend = \"bitcoind\"\nrpc_host = \"127.0.0.1\"\nrpc_port = 38332\n\
         cookie_file = \"/home/b/.bitcoin/signet/.cookie\"",
        "backend = \"electrum\"\nserver_url = \"tcp://127.0.0.1:50001\"\noperator = \"own\"",
        "backend = \"electrum\"\nserver_url = \"tcp://127.0.0.1:50001\"\noperator = \"third_party\"",
    ] {
        let config = config_with(dir.path(), chain, ldk);
        assert_eq!(explorer_default(&config), None, "{chain}");
    }
}

/// The warning carries hosts from a fixed list, never a configured URL.
#[test]
fn the_warning_never_carries_a_configured_url() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(
        dir.path(),
        "backend = \"esplora\"\napi_url = \"https://mempool.space/signet\"\n\
         esplora_url_fallback = \"https://blockstream.info/signet/\"",
        "backend = \"ldk\"\nnetwork = \"signet\"\n\
         esplora_url = \"https://mempool.space/signet/api\"",
    );
    let found = explorer_default(&config).unwrap();
    for text in [found.describe(), found.warning()] {
        assert!(!text.contains("://"), "{text}");
        assert!(!text.contains("/signet"), "{text}");
        assert!(!text.contains("/api"), "{text}");
    }
}

/// The start-time warning is logged once and names hosts only.
#[tokio::test]
async fn start_warns_once_with_hosts_only() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(
        dir.path(),
        "backend = \"esplora\"\napi_url = \"https://mempool.space/signet\"\n\
         esplora_url_fallback = \"https://blockstream.info/signet\"",
        "backend = \"mock\"\ninitial_balance_msat = 1000",
    );
    let log = tempfile::NamedTempFile::new().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(log.reopen().unwrap())
        .finish();
    let node = {
        let _guard = tracing::subscriber::set_default(subscriber);
        crate::node::KonsensusNode::from_config(config, None)
            .await
            .unwrap()
    };
    assert!(node.chain().chain_view().explorer_default);
    let text = std::fs::read_to_string(log.path()).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("public explorer this node never explicitly accepted"))
        .collect();
    assert_eq!(lines.len(), 1, "{text}");
    let line = lines[0];
    assert!(line.contains("WARN"), "{line}");
    assert!(line.contains("[chain] mempool.space"), "{line}");
    assert!(line.contains("[chain] blockstream.info"), "{line}");
    assert!(!line.contains("://"), "{line}");
    assert!(!line.contains("/signet"), "{line}");
}

/// No warning when the node reads no unaccepted explorer.
#[tokio::test]
async fn start_does_not_warn_without_an_explorer_default() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(
        dir.path(),
        "backend = \"esplora\"\napi_url = \"https://mempool.space/signet\"\n\
         accept_third_party_tip = true",
        "backend = \"mock\"\ninitial_balance_msat = 1000",
    );
    let log = tempfile::NamedTempFile::new().unwrap();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(log.reopen().unwrap())
        .finish();
    let node = {
        let _guard = tracing::subscriber::set_default(subscriber);
        crate::node::KonsensusNode::from_config(config, None)
            .await
            .unwrap()
    };
    assert!(!node.chain().chain_view().explorer_default);
    let text = std::fs::read_to_string(log.path()).unwrap();
    assert!(!text.contains("explorer_default"), "{text}");
    assert!(!text.contains("never explicitly accepted"), "{text}");
}

/// The same paid public endpoint as the authenticated `[chain]` primary and
/// LDK primary, with no fallback: the chain provider merges LDK's URL into its
/// authenticated primary, so nothing is counted.
#[test]
fn an_authenticated_primary_repeated_by_ldk_is_not_counted() {
    let dir = tempfile::tempdir().unwrap();
    for (chain_url, ldk_url) in [
        ("https://blockstream.info", "https://blockstream.info/api"),
        ("https://blockstream.info/api/", "https://blockstream.info"),
        ("https://mempool.space/signet", "https://mempool.space/signet/api"),
    ] {
        let config = config_with(
            dir.path(),
            &format!(
                "backend = \"esplora\"\napi_url = \"{chain_url}\"\n\
                 credentials_file = \"/secrets/chain-api.toml\""
            ),
            &format!(
                "backend = \"ldk\"\nnetwork = \"bitcoin\"\nesplora_url = \"{ldk_url}\"\n\
                 credentials_file = \"/secrets/chain-api.toml\""
            ),
        );
        assert_eq!(explorer_default(&config), None, "{chain_url} / {ldk_url}");
    }
}

/// A distinct unauthenticated public fallback is still counted next to an
/// authenticated primary on the same host.
#[test]
fn a_distinct_public_fallback_next_to_an_authenticated_primary_counts() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_with(
        dir.path(),
        "backend = \"esplora\"\napi_url = \"https://blockstream.info\"\n\
         credentials_file = \"/secrets/chain-api.toml\"",
        "backend = \"ldk\"\nnetwork = \"bitcoin\"\nesplora_url = \"https://blockstream.info/api\"\n\
         credentials_file = \"/secrets/chain-api.toml\"\n\
         esplora_url_fallback = \"https://mempool.space/api\"",
    );
    assert_eq!(
        sources(explorer_default(&config)),
        [("chain", "mempool.space"), ("lightning", "mempool.space")]
    );
}

/// A chain source with a best block of a chosen age and a refusal latch.
struct TipSource {
    age_secs: std::sync::atomic::AtomicU64,
    refused: std::sync::atomic::AtomicBool,
}

impl TipSource {
    fn new(age_secs: u64) -> Arc<Self> {
        Arc::new(Self {
            age_secs: age_secs.into(),
            refused: false.into(),
        })
    }
}

#[async_trait]
impl ChainProvider for TipSource {
    fn chain_view(&self) -> ChainView {
        ChainView {
            backend: "esplora",
            trust_level: "third_party",
            host: Some("mempool.space".into()),
            explorer_default: false,
        }
    }
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::ServerTrust
    }
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        Ok(800_000)
    }
    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Ok(BlockHeader {
            height,
            hash: format!("{height:064x}"),
            timestamp: now - self.age_secs.load(std::sync::atomic::Ordering::SeqCst),
            bits: 0x1d00_ffff,
        })
    }
    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        Ok(FeeEstimate {
            target_blocks,
            sat_per_vbyte: 1.0,
        })
    }
    async fn is_tx_confirmed(&self, _txid: &str, _min: u32) -> Result<bool, ChainError> {
        Ok(false)
    }
    async fn is_synced(&self) -> bool {
        true
    }
    fn refusal(&self) -> Result<(), ChainError> {
        if self.refused.load(std::sync::atomic::Ordering::SeqCst) {
            Err(ChainError::NotAvailable("source is on another network".into()))
        } else {
            Ok(())
        }
    }
}

fn labelled_fresh_tip(source: &Arc<TipSource>) -> Arc<dyn ChainProvider> {
    let found = ExplorerDefault {
        sources: vec![ExplorerSource {
            stanza: "chain",
            host: "mempool.space",
        }],
        acceptable: true,
    };
    let bounded = konsensus_chain::FreshTip::wrap(
        Arc::clone(source) as Arc<dyn ChainProvider>,
        Some("bitcoin"),
    );
    label(bounded, Some(&found))
}

/// Through the label, the bounded tip's age check still refuses a stale tip.
#[tokio::test]
async fn the_label_keeps_the_tip_age_check() {
    let fresh = TipSource::new(60);
    let chain = labelled_fresh_tip(&fresh);
    assert!(chain.chain_view().explorer_default);
    assert!(chain.tip_is_fresh().await);
    assert_eq!(chain.get_block_height().await.unwrap(), 800_000);

    let stale = TipSource::new(4 * 3600);
    let chain = labelled_fresh_tip(&stale);
    assert!(chain.chain_view().explorer_default);
    assert!(!chain.tip_is_fresh().await, "a stale tip must not count as fresh");
    assert!(chain.get_block_height().await.is_err());
    assert!(chain.get_best_block_header().await.is_err());
}

/// Through the label, a source's latched network refusal still refuses.
#[tokio::test]
async fn the_label_keeps_the_refusal_latch() {
    let source = TipSource::new(60);
    let chain = labelled_fresh_tip(&source);
    assert!(chain.refusal().is_ok());
    assert!(chain.tip_is_fresh().await);
    source
        .refused
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(chain.refusal().is_err(), "the latch must reach the caller");
    assert!(!chain.tip_is_fresh().await, "a refused source has no fresh tip");
    assert!(chain.get_block_height().await.is_err());
}

/// The trait's methods as declared in its source, and those the label names.
fn method_names(source: &str, start: &str) -> Vec<String> {
    let body = source
        .split(start)
        .nth(1)
        .unwrap_or_else(|| panic!("{start} not found"));
    let body = &body[..body.find("\n}\n").expect("end of block")];
    body.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = line
                .strip_prefix("async fn ")
                .or_else(|| line.strip_prefix("fn "))?;
            Some(rest.split(['(', '<']).next()?.trim().to_owned())
        })
        .collect()
}

/// Fails when `ChainProvider` gains a method the label does not forward:
/// a default there would silently replace the inner source's answer.
#[test]
fn the_label_forwards_every_chain_provider_method() {
    let declared = method_names(
        include_str!("../../../konsensus-core/src/traits/chain.rs"),
        "pub trait ChainProvider",
    );
    for expected in ["chain_view", "get_block_height", "tip_is_fresh", "refusal"] {
        assert!(declared.iter().any(|m| m == expected), "{expected}: {declared:?}");
    }
    let forwarded = method_names(
        include_str!("../chain_tip.rs"),
        "impl ChainProvider for ExplorerDefaultLabel",
    );
    let missing: Vec<&String> = declared.iter().filter(|m| !forwarded.contains(m)).collect();
    assert!(missing.is_empty(), "not forwarded by the label: {missing:?}");
}

/// Embedded LDK's authenticated transport merges a fallback equal to its paid
/// primary (trailing slash aside): that fallback is not a public explorer.
#[test]
fn an_ldk_fallback_repeating_the_paid_primary_is_not_counted() {
    let dir = tempfile::tempdir().unwrap();
    for (primary, fallback, expected) in [
        ("https://blockstream.info/api", "https://blockstream.info/api/", vec![]),
        ("https://blockstream.info/api/", "https://blockstream.info/api", vec![]),
        (
            "https://blockstream.info/api",
            "https://mempool.space/api",
            vec![("lightning", "mempool.space")],
        ),
    ] {
        let config = config_with(
            dir.path(),
            "backend = \"mock\"",
            &format!(
                "backend = \"ldk\"\nnetwork = \"bitcoin\"\nesplora_url = \"{primary}\"\n\
                 credentials_file = \"/secrets/chain-api.toml\"\n\
                 esplora_url_fallback = \"{fallback}\""
            ),
        );
        assert_eq!(sources(explorer_default(&config)), expected, "{primary} / {fallback}");
    }
}
