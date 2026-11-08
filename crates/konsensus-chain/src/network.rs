//! Chain-source network identity.
//!
//! A node configured for one Bitcoin network must never read another
//! network's chain. Each provider can carry the configured network; until the
//! source has shown which chain it serves, the provider serves no chain data.
//! A source on a different network is refused for the life of the provider,
//! with no fallback to another source. An unverified source is not a pass:
//! a missing or malformed answer leaves the provider serving nothing.
//!
//! How each source identifies its network:
//! - Bitcoin Core: `getblockchaininfo.chain` (`main`, `test`, `testnet4`,
//!   `signet`, `regtest`).
//! - Electrum: the hash of the server's block header at height 0.
//! - Esplora: the hash of the header at height 0, computed locally
//!   (`/block-height/0`, then `/block/<hash>/header`).
//!
//! A successful check lasts until the connection to that source fails (a
//! reconnect) and at most `VERIFICATION_TTL`; the source is then asked again
//! before its next use. Electrum opens a new connection for every query, so
//! it is asked on every query.
//!
//! Signet: every signet, including one with a custom challenge, shares the
//! same genesis block, and Core reports `signet` for all of them. A custom
//! signet therefore matches a configured `signet`. That is also what the
//! embedded Lightning node sees, since it identifies chains by genesis hash.

use std::fmt;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

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

/// How long one successful identity check lasts. A failed request to the
/// source ends it sooner (see each provider for what counts as a reconnect).
pub const VERIFICATION_TTL: Duration = Duration::from_secs(60);

/// Per-provider verification state: one slot per configured endpoint, and a
/// mismatch that, once seen, refuses the whole provider.
pub(crate) struct NetworkGate {
    expected: Network,
    source: &'static str,
    ttl: Duration,
    verified_at: Vec<Mutex<Option<Instant>>>,
    mismatch: OnceLock<NetworkMismatch>,
}

impl NetworkGate {
    pub(crate) fn new(expected: Network, source: &'static str, endpoints: usize) -> Self {
        Self::with_ttl(expected, source, endpoints, VERIFICATION_TTL)
    }

    pub(crate) fn with_ttl(
        expected: Network,
        source: &'static str,
        endpoints: usize,
        ttl: Duration,
    ) -> Self {
        Self {
            expected,
            source,
            ttl,
            verified_at: (0..endpoints.max(1)).map(|_| Mutex::new(None)).collect(),
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
        self.verified_at[endpoint]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_some_and(|at| at.elapsed() < self.ttl)
    }

    /// The endpoint must show its network again before its next use.
    pub(crate) fn invalidate(&self, endpoint: usize) {
        *self.verified_at[endpoint]
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    pub(crate) fn invalidate_all(&self) {
        for endpoint in 0..self.verified_at.len() {
            self.invalidate(endpoint);
        }
    }

    /// Record an endpoint's answer. A different or unrecognised network
    /// refuses the provider from now on.
    pub(crate) fn record(
        &self,
        endpoint: usize,
        reported: ReportedNetwork,
    ) -> Result<(), ChainError> {
        if reported == ReportedNetwork::Known(self.expected) {
            *self.verified_at[endpoint]
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Instant::now());
            return self.refusal();
        }
        self.invalidate(endpoint);
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
        if (0..self.verified_at.len()).all(|endpoint| self.is_verified(endpoint)) {
            NetworkCheck::Verified
        } else {
            NetworkCheck::Unavailable
        }
    }
}

/// An Esplora source's genesis hash, computed here from the height-0 header
/// it serves (`/block-height/0`, then `/block/<hash>/header`). A header that
/// does not hash to the hash the server named is not an answer.
pub(crate) async fn esplora_genesis<F, Fut>(get: F) -> Result<BlockHash, ChainError>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, ChainError>>,
{
    let invalid = || ChainError::Backend("invalid Esplora genesis block".into());
    let named: BlockHash = get("/block-height/0".into())
        .await?
        .trim()
        .parse()
        .map_err(|_| invalid())?;
    let header = get(format!("/block/{named}/header")).await?;
    let header: bitcoin::block::Header =
        bitcoin::consensus::encode::deserialize_hex(header.trim()).map_err(|_| invalid())?;
    let hash = header.block_hash();
    if hash != named {
        return Err(invalid());
    }
    Ok(hash)
}

/// Result of checking a list of Esplora API URLs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsploraUrlsCheck {
    pub check: NetworkCheck,
    /// Per URL, in order: answered on the configured network.
    pub verified: Vec<bool>,
}

/// One-off check of Esplora API URLs used as given (the embedded Lightning
/// node's `esplora_url` convention, which already includes `/api`). Only the
/// first URL uses `primary_transport`; the rest are plain requests, as they
/// are at use. A wrong network on any URL is a mismatch.
pub async fn verify_esplora_api_urls<T>(
    expected: Network,
    urls: &[&str],
    primary_transport: Option<&T>,
) -> EsploraUrlsCheck
where
    T: esplora_client::r#async::HttpTransport + ?Sized,
{
    let gate = NetworkGate::new(expected, "esplora", urls.len());
    let unavailable = || EsploraUrlsCheck {
        check: NetworkCheck::Unavailable,
        verified: vec![false; urls.len()],
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .build()
    else {
        return unavailable();
    };
    for (index, url) in urls.iter().enumerate() {
        let base = url.trim_end_matches('/');
        let transport = primary_transport.filter(|_| index == 0);
        let genesis = esplora_genesis(|path| {
            let request = client.get(format!("{base}{path}"));
            async move {
                let response = match transport {
                    Some(transport) => transport.execute(request).await.ok(),
                    None => request.send().await.ok(),
                }
                .filter(|response| response.status().is_success())
                .ok_or_else(|| ChainError::Connection("Esplora unavailable".into()))?;
                response
                    .text()
                    .await
                    .map_err(|_| ChainError::Connection("Esplora unavailable".into()))
            }
        })
        .await;
        if let Ok(hash) = genesis {
            if gate
                .record(index, ReportedNetwork::from_genesis_hash(hash))
                .is_err()
            {
                break;
            }
        }
    }
    EsploraUrlsCheck {
        check: gate.check(),
        verified: (0..urls.len())
            .map(|index| gate.is_verified(index))
            .collect(),
    }
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

    #[test]
    fn a_check_ends_on_failure_or_after_its_lifetime() {
        let gate = NetworkGate::new(Network::Signet, "bitcoind", 1);
        gate.record(0, ReportedNetwork::Known(Network::Signet))
            .unwrap();
        assert!(gate.is_verified(0));
        gate.invalidate(0);
        assert!(!gate.is_verified(0));
        assert_eq!(gate.check(), NetworkCheck::Unavailable);

        let gate = NetworkGate::with_ttl(Network::Signet, "bitcoind", 1, Duration::ZERO);
        gate.record(0, ReportedNetwork::Known(Network::Signet))
            .unwrap();
        assert!(!gate.is_verified(0), "expired at once");
    }

    #[tokio::test]
    async fn esplora_identity_is_the_hash_of_the_served_header() {
        let block = bitcoin::blockdata::constants::genesis_block(Network::Signet);
        let hash = block.block_hash().to_string();
        let header = bitcoin::consensus::encode::serialize_hex(&block.header);
        let serve = |named: String, header: Option<String>| {
            move |path: String| {
                let reply = if path == "/block-height/0" {
                    Ok(named.clone())
                } else if path == format!("/block/{named}/header") {
                    header.clone().ok_or(ChainError::Backend("404".into()))
                } else {
                    Err(ChainError::Backend("404".into()))
                };
                std::future::ready(reply)
            }
        };
        assert_eq!(
            esplora_genesis(serve(hash.clone(), Some(header.clone())))
                .await
                .unwrap(),
            block.block_hash()
        );
        // The right hash string alone is not an answer.
        assert!(esplora_genesis(serve(hash.clone(), None)).await.is_err());
        // A header that does not hash to the named hash is not an answer.
        let other = bitcoin::consensus::encode::serialize_hex(
            &bitcoin::blockdata::constants::genesis_block(Network::Bitcoin).header,
        );
        assert!(esplora_genesis(serve(hash.clone(), Some(other)))
            .await
            .is_err());
        assert!(esplora_genesis(serve("not a hash".into(), Some(header)))
            .await
            .is_err());
    }
}
