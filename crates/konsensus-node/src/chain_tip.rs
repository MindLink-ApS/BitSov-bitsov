//! Existing nodes whose chain tip is a public explorer they never accepted.
//!
//! Older generated configs, and configs that omit the Esplora URLs (whose
//! deserialization defaults stay frozen, #66), read a public explorer. This
//! module only detects and labels that: it warns once at start and marks owner
//! status `explorer_default: true`. It never edits a config; moving to an owned
//! tip or accepting the explorer is the explicit `konsensus chain-tip` command.

use std::sync::Arc;

use async_trait::async_trait;
use konsensus_core::traits::chain::{
    BlockHeader, ChainError, ChainProvider, ChainView, FeeEstimate, TrustLevel,
};

use crate::config::{ChainConfig, LightningConfig, NodeConfig};

/// Public explorers this project has written into configs or documented as
/// examples. Matched on the URL host, on any network path.
pub const PUBLIC_EXPLORER_HOSTS: [&str; 2] = ["mempool.space", "blockstream.info"];

/// One place a public explorer is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorerSource {
    /// `chain` (the node's chain provider) or `lightning` (embedded LDK).
    pub stanza: &'static str,
    /// Host only: URLs may carry secrets.
    pub host: &'static str,
}

/// A node whose chain tip is a public explorer it never explicitly accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplorerDefault {
    pub sources: Vec<ExplorerSource>,
    /// `--accept-third-party-tip` can record acceptance: `[chain]` is Esplora.
    /// With `[chain] backend = "mock"` only embedded LDK reads the explorer and
    /// there is no `[chain]` Esplora table to record it in.
    pub acceptable: bool,
}

/// The public explorer host of `url`, if it is one.
pub fn public_explorer_host(url: &str) -> Option<&'static str> {
    let parsed = reqwest::Url::parse(url.trim()).ok()?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return None;
    }
    let host = parsed
        .host_str()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    PUBLIC_EXPLORER_HOSTS
        .into_iter()
        .find(|known| *known == host)
}

/// Detect a public explorer tip that was never explicitly accepted.
///
/// Counts the endpoints the node would actually use: the `[chain]` Esplora
/// primary and fallbacks, and embedded LDK's Esplora primary and fallback when
/// `[chain]` does not select Bitcoin Core or Electrum for it. A primary with a
/// credentials file is a paid source the owner chose, so it is not counted.
/// `accept_third_party_tip = true` in `[chain]` turns detection off.
pub fn explorer_default(config: &NodeConfig) -> Option<ExplorerDefault> {
    let mut sources = Vec::new();
    match &config.chain {
        ChainConfig::Esplora {
            accept_third_party_tip: true,
            ..
        } => return None,
        ChainConfig::Esplora {
            api_url,
            credentials_file,
            ..
        } => {
            let primary = credentials_file.is_none().then_some(api_url.as_str());
            let fallbacks = config.chain.esplora_fallbacks(&config.lightning);
            for url in primary
                .into_iter()
                .chain(fallbacks.iter().map(String::as_str))
            {
                push(&mut sources, "chain", url);
            }
        }
        ChainConfig::Mock => {}
        // LDK follows [chain] for Core and Electrum, and the node's own reads
        // do too: no explorer is read.
        ChainConfig::Bitcoind(_) | ChainConfig::Electrum(_) => return None,
    }
    if let LightningConfig::Ldk {
        esplora_url,
        esplora_url_fallback,
        credentials_file,
        ..
    } = &config.lightning
    {
        let primary = credentials_file.is_none().then_some(esplora_url.as_str());
        for url in primary.into_iter().chain(esplora_url_fallback.as_deref()) {
            push(&mut sources, "lightning", url);
        }
    }
    let acceptable = matches!(config.chain, ChainConfig::Esplora { .. });
    (!sources.is_empty()).then_some(ExplorerDefault {
        sources,
        acceptable,
    })
}

fn push(sources: &mut Vec<ExplorerSource>, stanza: &'static str, url: &str) {
    if let Some(host) = public_explorer_host(url) {
        let source = ExplorerSource { stanza, host };
        if !sources.contains(&source) {
            sources.push(source);
        }
    }
}

impl ExplorerDefault {
    /// `[chain] mempool.space, [lightning] blockstream.info`.
    pub fn describe(&self) -> String {
        self.sources
            .iter()
            .map(|s| format!("[{}] {}", s.stanza, s.host))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// The one start-time warning: names the source and only commands that
    /// work for this config.
    pub fn warning(&self) -> String {
        let keep = if self.acceptable {
            "To keep this explorer and silence this warning, run `konsensus chain-tip \
             --config <config> --accept-third-party-tip`."
        } else {
            "[chain] is mock, so only embedded Lightning reads this explorer and \
             acceptance cannot be recorded; moving to a tip you own is the way to \
             clear this warning."
        };
        format!(
            "chain tip is a public explorer this node never explicitly accepted \
             (third_party): {}. Nothing was changed. To move to a tip you own, stop \
             the node and run `konsensus chain-tip --config <config> --chain bitcoind` \
             (your Bitcoin Core) or `--chain electrum --electrum-server-url <url> \
             --electrum-operator own` (your Electrum server). {keep} \
             See docs/CHAIN-SOURCE.md.",
            self.describe()
        )
    }
}

/// Log the warning once, at start, when it applies. Returns the detection.
pub fn warn_at_start(config: &NodeConfig) -> Option<ExplorerDefault> {
    let detected = explorer_default(config)?;
    tracing::warn!(
        explorer_default = true,
        sources = %detected.describe(),
        "{}",
        detected.warning()
    );
    Some(detected)
}

/// Label the node's chain provider for owner status; reads pass through.
pub fn label(
    chain: Arc<dyn ChainProvider>,
    detected: Option<&ExplorerDefault>,
) -> Arc<dyn ChainProvider> {
    match detected {
        Some(_) => Arc::new(ExplorerDefaultLabel { inner: chain }),
        None => chain,
    }
}

/// Reports `third_party` with `explorer_default: true`; every read is the
/// inner provider's.
pub struct ExplorerDefaultLabel {
    inner: Arc<dyn ChainProvider>,
}

#[async_trait]
impl ChainProvider for ExplorerDefaultLabel {
    fn chain_view(&self) -> ChainView {
        ChainView {
            trust_level: "third_party",
            explorer_default: true,
            ..self.inner.chain_view()
        }
    }
    fn trust_level(&self) -> TrustLevel {
        self.inner.trust_level()
    }
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        self.inner.get_block_height().await
    }
    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        self.inner.get_block_header(height).await
    }
    async fn get_best_block_header(&self) -> Result<BlockHeader, ChainError> {
        self.inner.get_best_block_header().await
    }
    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        self.inner.estimate_fee(target_blocks).await
    }
    async fn is_tx_confirmed(
        &self,
        txid: &str,
        min_confirmations: u32,
    ) -> Result<bool, ChainError> {
        self.inner.is_tx_confirmed(txid, min_confirmations).await
    }
    async fn is_synced(&self) -> bool {
        self.inner.is_synced().await
    }
    async fn is_synced_with_height(&self, height: u64) -> bool {
        self.inner.is_synced_with_height(height).await
    }
}

#[cfg(test)]
#[path = "tests/chain_tip.rs"]
mod tests;
