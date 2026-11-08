//! Chain-source network identity.
//!
//! A node configured for one Bitcoin network must never read another
//! network's chain. Each provider can carry the configured network; until the
//! source has shown which chain it serves, the provider serves no chain data.
//! A source on a different network is refused for the life of the provider,
//! with no fallback to another source.
//!
//! How each source identifies its network:
//! - Bitcoin Core: `getblockchaininfo.chain` (`main`, `test`, `testnet4`,
//!   `signet`, `regtest`).
//! - Electrum: the hash of the server's block header at height 0.
//! - Esplora: the block hash at height 0 (`/block-height/0`).
//!
//! Signet: every signet, including one with a custom challenge, shares the
//! same genesis block, and Core reports `signet` for all of them. A custom
//! signet therefore matches a configured `signet`. That is also what the
//! embedded Lightning node sees, since it identifies chains by genesis hash.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;

use bitcoin::{BlockHash, Network};
use konsensus_core::traits::chain::ChainError;

/// Every network a source can be on, in a fixed order.
const NETWORKS: [Network; 5] = [
    Network::Bitcoin,
    Network::Testnet,
    Network::Testnet4,
    Network::Signet,
    Network::Regtest,
];

/// Parse a configured network name (`[lightning] network`). Unknown names
/// return `None`; the caller's own validation rejects them.
pub fn parse_configured_network(name: &str) -> Option<Network> {
    match name.to_ascii_lowercase().as_str() {
        "bitcoin" | "mainnet" => Some(Network::Bitcoin),
        "testnet" | "testnet3" => Some(Network::Testnet),
        "testnet4" => Some(Network::Testnet4),
        "signet" => Some(Network::Signet),
        "regtest" => Some(Network::Regtest),
        _ => None,
    }
}

/// Operator-facing network name, matching the configuration values.
pub fn network_name(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "bitcoin (mainnet)",
        Network::Testnet => "testnet (testnet3)",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

/// What a source reported about its chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedNetwork {
    Known(Network),
    /// An answer naming no known network. Its text is never echoed.
    Unrecognised,
}

impl ReportedNetwork {
    /// From Bitcoin Core's `getblockchaininfo.chain`.
    pub fn from_core_chain(chain: &str) -> Self {
        Network::from_core_arg(chain)
            .map(Self::Known)
            .unwrap_or(Self::Unrecognised)
    }

    /// From a source's block hash at height 0.
    pub fn from_genesis_hash(hash: BlockHash) -> Self {
        NETWORKS
            .into_iter()
            .find(|network| {
                bitcoin::blockdata::constants::genesis_block(*network).block_hash() == hash
            })
            .map(Self::Known)
            .unwrap_or(Self::Unrecognised)
    }
}

impl fmt::Display for ReportedNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(network) => f.write_str(network_name(*network)),
            Self::Unrecognised => f.write_str("an unrecognised network"),
        }
    }
}

/// The configured network and the source's network disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkMismatch {
    pub configured: Network,
    /// Source kind only (`bitcoind`, `electrum`, `esplora`); never a URL.
    pub source: &'static str,
    pub reported: ReportedNetwork,
}

impl fmt::Display for NetworkMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "chain source network mismatch: the configured network is {} but the {} chain source is on {}. \
             Refusing to use it and trying no other source. Point the chain source at a {} node, \
             or set the configured network to match, then restart.",
            network_name(self.configured),
            self.source,
            self.reported,
            network_name(self.configured),
        )
    }
}

impl std::error::Error for NetworkMismatch {}

/// Outcome of verifying a source's network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkCheck {
    /// Every configured endpoint answered on the configured network.
    Verified,
    /// A configured endpoint is on another network. Refuse to start.
    Mismatch(NetworkMismatch),
    /// Not yet known: an endpoint did not answer usably. Chain data stays
    /// unavailable until it does; nothing else changes.
    Unavailable,
    /// The provider was built without a configured network.
    NotConfigured,
}

/// Per-provider verification state: one slot per configured endpoint, and a
/// mismatch that, once seen, refuses the whole provider.
pub(crate) struct NetworkGate {
    expected: Network,
    source: &'static str,
    verified: Vec<AtomicBool>,
    mismatch: OnceLock<NetworkMismatch>,
}

impl NetworkGate {
    pub(crate) fn new(expected: Network, source: &'static str, endpoints: usize) -> Self {
        Self {
            expected,
            source,
            verified: (0..endpoints.max(1))
                .map(|_| AtomicBool::new(false))
                .collect(),
            mismatch: OnceLock::new(),
        }
    }

    /// Err once any endpoint has been seen on another network.
    pub(crate) fn refusal(&self) -> Result<(), ChainError> {
        match self.mismatch.get() {
            Some(mismatch) => Err(ChainError::NotAvailable(mismatch.to_string())),
            None => Ok(()),
        }
    }

    pub(crate) fn is_verified(&self, endpoint: usize) -> bool {
        self.verified[endpoint].load(Ordering::Acquire)
    }

    /// Record an endpoint's answer. A different or unrecognised network
    /// refuses the provider from now on.
    pub(crate) fn record(
        &self,
        endpoint: usize,
        reported: ReportedNetwork,
    ) -> Result<(), ChainError> {
        if reported == ReportedNetwork::Known(self.expected) {
            self.verified[endpoint].store(true, Ordering::Release);
            return self.refusal();
        }
        let mismatch = NetworkMismatch {
            configured: self.expected,
            source: self.source,
            reported,
        };
        if self.mismatch.set(mismatch).is_ok() {
            if let Some(mismatch) = self.mismatch.get() {
                tracing::error!(source = self.source, "{mismatch}");
            }
        }
        self.refusal()
    }

    pub(crate) fn check(&self) -> NetworkCheck {
        if let Some(mismatch) = self.mismatch.get() {
            return NetworkCheck::Mismatch(mismatch.clone());
        }
        if self
            .verified
            .iter()
            .all(|verified| verified.load(Ordering::Acquire))
        {
            NetworkCheck::Verified
        } else {
            NetworkCheck::Unavailable
        }
    }
}

/// One-off check of Esplora API URLs used as given (the embedded Lightning
/// node's `esplora_url` convention, which already includes `/api`). Only the
/// first URL uses `primary_transport`; the rest are plain requests, as they
/// are at use. A wrong network on any URL is a mismatch.
pub async fn verify_esplora_api_urls<T>(
    expected: Network,
    urls: &[&str],
    primary_transport: Option<&T>,
) -> NetworkCheck
where
    T: esplora_client::r#async::HttpTransport + ?Sized,
{
    let gate = NetworkGate::new(expected, "esplora", urls.len());
    let Ok(client) = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .build()
    else {
        return NetworkCheck::Unavailable;
    };
    for (index, url) in urls.iter().enumerate() {
        let request = client.get(format!("{}/block-height/0", url.trim_end_matches('/')));
        let response = match primary_transport.filter(|_| index == 0) {
            Some(transport) => transport.execute(request).await.ok(),
            None => request.send().await.ok(),
        };
        let Some(response) = response.filter(|r| r.status().is_success()) else {
            continue;
        };
        let Some(hash) = response
            .text()
            .await
            .ok()
            .and_then(|text| text.trim().parse::<BlockHash>().ok())
        else {
            continue;
        };
        if gate
            .record(index, ReportedNetwork::from_genesis_hash(hash))
            .is_err()
        {
            break;
        }
    }
    gate.check()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_chain_names_map_exactly() {
        for (chain, network) in [
            ("main", Network::Bitcoin),
            ("test", Network::Testnet),
            ("testnet4", Network::Testnet4),
            ("signet", Network::Signet),
            ("regtest", Network::Regtest),
        ] {
            assert_eq!(
                ReportedNetwork::from_core_chain(chain),
                ReportedNetwork::Known(network)
            );
        }
        for chain in ["bitcoin", "mainnet", "testnet", "Main", "", "liquidv1"] {
            assert_eq!(
                ReportedNetwork::from_core_chain(chain),
                ReportedNetwork::Unrecognised
            );
        }
    }

    #[test]
    fn genesis_hashes_identify_each_network() {
        for network in NETWORKS {
            let hash = bitcoin::blockdata::constants::genesis_block(network).block_hash();
            assert_eq!(
                ReportedNetwork::from_genesis_hash(hash),
                ReportedNetwork::Known(network)
            );
        }
        assert_eq!(
            ReportedNetwork::from_genesis_hash("07".repeat(32).parse::<BlockHash>().unwrap()),
            ReportedNetwork::Unrecognised
        );
    }

    #[test]
    fn configured_names_map_exactly() {
        assert_eq!(parse_configured_network("bitcoin"), Some(Network::Bitcoin));
        assert_eq!(parse_configured_network("Mainnet"), Some(Network::Bitcoin));
        assert_eq!(parse_configured_network("testnet"), Some(Network::Testnet));
        assert_eq!(
            parse_configured_network("testnet4"),
            Some(Network::Testnet4)
        );
        assert_eq!(parse_configured_network("signet"), Some(Network::Signet));
        assert_eq!(parse_configured_network("regtest"), Some(Network::Regtest));
        assert_eq!(parse_configured_network("main"), None);
    }

    #[test]
    fn mismatch_latches_and_names_both_networks() {
        let gate = NetworkGate::new(Network::Signet, "bitcoind", 1);
        assert_eq!(gate.check(), NetworkCheck::Unavailable);
        let error = gate
            .record(0, ReportedNetwork::Known(Network::Bitcoin))
            .unwrap_err()
            .to_string();
        assert!(error.contains("configured network is signet"), "{error}");
        assert!(
            error.contains("bitcoind chain source is on bitcoin (mainnet)"),
            "{error}"
        );
        // A later matching answer never clears the refusal.
        assert!(gate
            .record(0, ReportedNetwork::Known(Network::Signet))
            .is_err());
        assert!(matches!(gate.check(), NetworkCheck::Mismatch(_)));
    }

    #[test]
    fn every_endpoint_must_verify() {
        let gate = NetworkGate::new(Network::Bitcoin, "esplora", 2);
        gate.record(0, ReportedNetwork::Known(Network::Bitcoin))
            .unwrap();
        assert!(gate.is_verified(0) && !gate.is_verified(1));
        assert_eq!(gate.check(), NetworkCheck::Unavailable);
        gate.record(1, ReportedNetwork::Known(Network::Bitcoin))
            .unwrap();
        assert_eq!(gate.check(), NetworkCheck::Verified);
        assert!(gate.record(1, ReportedNetwork::Unrecognised).is_err());
        assert!(gate.refusal().is_err());
    }
}
