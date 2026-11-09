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

/// Largest body accepted as an Esplora genesis answer.
///
/// `/block-height/0` is a 64-character block hash. `/block/<hash>/header` is
/// 160 hex characters (an 80-byte header). Either may have surrounding
/// whitespace. A longer body is not that answer, and it is not buffered.
pub const MAX_GENESIS_ANSWER_BYTES: usize = 1024;

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

/// Read a response body that is only useful up to `max` bytes.
///
/// A `Content-Length` above `max` is refused before the body is read. A body
/// with no length is still stopped once `max` bytes have arrived, so a chunked
/// reply cannot grow the buffer past that.
pub(crate) async fn read_limited_text(
    mut response: reqwest::Response,
    max: usize,
) -> Result<String, ChainError> {
    if response
        .content_length()
        .is_some_and(|len| len > max as u64)
    {
        return Err(ChainError::Backend("invalid Esplora genesis block".into()));
    }
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if body.len().saturating_add(chunk.len()) > max {
                    return Err(ChainError::Backend("invalid Esplora genesis block".into()));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                return Err(ChainError::Connection("Esplora body unavailable".into()));
            }
        }
    }
    String::from_utf8(body).map_err(|_| ChainError::Backend("invalid Esplora genesis block".into()))
}

fn genesis_answer(text: &str) -> Result<&str, ChainError> {
    let text = text.trim();
    if text.len() > MAX_GENESIS_ANSWER_BYTES {
        return Err(ChainError::Backend("invalid Esplora genesis block".into()));
    }
    Ok(text)
}

/// An Esplora source's genesis hash, computed here from the height-0 header
/// it serves (`/block-height/0`, then `/block/<hash>/header`). A header that
/// does not hash to the hash the server named is not an answer. An answer
/// longer than [`MAX_GENESIS_ANSWER_BYTES`] is not parsed.
pub(crate) async fn esplora_genesis<F, Fut>(get: F) -> Result<BlockHash, ChainError>
where
    F: Fn(String) -> Fut,
    Fut: std::future::Future<Output = Result<String, ChainError>>,
{
    let invalid = || ChainError::Backend("invalid Esplora genesis block".into());
    let named: BlockHash = genesis_answer(&get("/block-height/0".into()).await?)?
        .parse()
        .map_err(|_| invalid())?;
    let header = get(format!("/block/{named}/header")).await?;
    let header: bitcoin::block::Header =
        bitcoin::consensus::encode::deserialize_hex(genesis_answer(&header)?)
            .map_err(|_| invalid())?;
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

/// Bound on one identity request to an Esplora endpoint. Set on each
/// request, so it also holds when an authenticated transport sends it.
const ESPLORA_IDENTITY_REQUEST_TIMEOUT: Duration = Duration::from_secs(4);

/// Bound on one Esplora endpoint's whole identity check, including any token
/// request. Endpoints are checked side by side, each within its own bound, so
/// a slow or silent endpoint never discards another endpoint's answer.
pub const ESPLORA_ENDPOINT_CHECK_TIMEOUT: Duration = Duration::from_secs(10);

/// One-off check of Esplora API URLs used as given (the embedded Lightning
/// node's `esplora_url` convention, which already includes `/api`). Only the
/// first URL uses `primary_transport`; the rest are plain requests, as they
/// are at use. A wrong network on any URL is a mismatch. Returns within
/// `ESPLORA_ENDPOINT_CHECK_TIMEOUT`.
pub async fn verify_esplora_api_urls<T>(
    expected: Network,
    urls: &[&str],
    primary_transport: Option<&T>,
) -> EsploraUrlsCheck
where
    T: esplora_client::r#async::HttpTransport + ?Sized,
{
    verify_esplora_api_urls_within(
        expected,
        urls,
        primary_transport,
        ESPLORA_ENDPOINT_CHECK_TIMEOUT,
    )
    .await
}

pub(crate) async fn verify_esplora_api_urls_within<T>(
    expected: Network,
    urls: &[&str],
    primary_transport: Option<&T>,
    per_endpoint: Duration,
) -> EsploraUrlsCheck
where
    T: esplora_client::r#async::HttpTransport + ?Sized,
{
    let gate = NetworkGate::new(expected, "esplora", urls.len());
    let Ok(client) = reqwest::Client::builder()
        .timeout(ESPLORA_IDENTITY_REQUEST_TIMEOUT)
        .build()
    else {
        return EsploraUrlsCheck {
            check: NetworkCheck::Unavailable,
            verified: vec![false; urls.len()],
        };
    };
    let checks = urls.iter().enumerate().map(|(index, url)| {
        let (client, gate) = (&client, &gate);
        let base = url.trim_end_matches('/');
        let transport = primary_transport.filter(|_| index == 0);
        async move {
            let genesis = esplora_genesis(|path| {
                let request = client
                    .get(format!("{base}{path}"))
                    .timeout(ESPLORA_IDENTITY_REQUEST_TIMEOUT);
                async move {
                    let response = match transport {
                        Some(transport) => transport.execute(request).await.ok(),
                        None => request.send().await.ok(),
                    }
                    .filter(|response| response.status().is_success())
                    .ok_or_else(|| ChainError::Connection("Esplora unavailable".into()))?;
                    read_limited_text(response, MAX_GENESIS_ANSWER_BYTES).await
                }
            });
            // An endpoint that does not answer in time is unverified; it
            // leaves every other endpoint's answer in place.
            if let Ok(Ok(hash)) = tokio::time::timeout(per_endpoint, genesis).await {
                // A wrong network latches in the gate; the result reports it.
                let _ = gate.record(index, ReportedNetwork::from_genesis_hash(hash));
            }
        }
    });
    futures::future::join_all(checks).await;
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

    #[tokio::test]
    async fn an_oversized_genesis_answer_is_not_parsed() {
        let huge = "ab".repeat(MAX_GENESIS_ANSWER_BYTES);
        let result = esplora_genesis(|_path| {
            let huge = huge.clone();
            async move { Ok(huge) }
        })
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn a_declared_oversized_body_is_refused_before_it_is_read() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/api", listener.local_addr().unwrap());
        let serve = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10000000\r\nConnection: close\r\n\r\n",
                )
                .await;
            // Stay open. A reader that honors Content-Length would block here.
            let _ = socket.read(&mut buf).await;
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(4))
            .build()
            .unwrap();
        let response = client
            .get(format!("{url}/block-height/0"))
            .send()
            .await
            .unwrap();
        let started = Instant::now();
        let error = read_limited_text(response, MAX_GENESIS_ANSWER_BYTES)
            .await
            .unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "refused only after waiting for the body"
        );
        assert!(error.to_string().contains("invalid Esplora genesis block"));
        serve.abort();
    }

    #[tokio::test]
    async fn a_chunked_genesis_body_stops_at_the_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/api", listener.local_addr().unwrap());
        let serve = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = socket.read(&mut buf).await;
            let chunk = "a".repeat(512);
            let mut body =
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                    .to_vec();
            for _ in 0..8 {
                body.extend(format!("{:x}\r\n{chunk}\r\n", chunk.len()).into_bytes());
            }
            body.extend(b"0\r\n\r\n");
            let _ = socket.write_all(&body).await;
        });
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{url}/block-height/0"))
            .send()
            .await
            .unwrap();
        let error = read_limited_text(response, MAX_GENESIS_ANSWER_BYTES)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("invalid Esplora genesis block"));
        serve.abort();
    }

    /// Records each request's timeout and serves the signet identity.
    #[cfg(unix)]
    #[derive(Debug, Default)]
    struct TimedWire {
        api_timeouts: Mutex<Vec<Option<Duration>>>,
    }

    #[cfg(unix)]
    impl esplora_client::r#async::HttpTransport for TimedWire {
        fn execute(
            &self,
            request: reqwest::RequestBuilder,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>>
                    + Send
                    + '_,
            >,
        > {
            Box::pin(async move {
                let request = request.build().unwrap();
                let block = bitcoin::blockdata::constants::genesis_block(Network::Signet);
                let hash = block.block_hash().to_string();
                let path = request.url().path().to_owned();
                let body = if path == "/token" {
                    r#"{"access_token":"private-token","expires_in":300}"#.to_owned()
                } else {
                    self.api_timeouts
                        .lock()
                        .unwrap()
                        .push(request.timeout().copied());
                    if path == "/api/block-height/0" {
                        hash
                    } else if path == format!("/api/block/{hash}/header") {
                        bitcoin::consensus::encode::serialize_hex(&block.header)
                    } else {
                        panic!("unexpected request")
                    }
                };
                Ok(http::Response::builder().body(body).unwrap().into())
            })
        }
    }

    /// Identity requests through the authenticated transport carry their own
    /// timeout; that client sets none of its own.
    #[cfg(unix)]
    #[tokio::test]
    async fn authenticated_identity_requests_are_bounded() {
        let wire = std::sync::Arc::new(TimedWire::default());
        let auth = crate::bearer::tests::auth_with_wire(wire.clone());
        let primary = "https://identity-primary.invalid/api";
        let transport = crate::bearer::BearerFailover::new(auth, primary, Vec::new()).unwrap();
        let result =
            verify_esplora_api_urls(Network::Signet, &[primary], Some(transport.as_ref())).await;
        assert_eq!(result.check, NetworkCheck::Verified);
        let timeouts = wire.api_timeouts.lock().unwrap().clone();
        assert_eq!(timeouts.len(), 2);
        assert!(
            timeouts
                .iter()
                .all(|timeout| *timeout == Some(ESPLORA_IDENTITY_REQUEST_TIMEOUT)),
            "{timeouts:?}"
        );
    }

    /// A slow endpoint that answers within its own bound keeps its answer,
    /// whatever the other endpoint does.
    #[tokio::test]
    async fn each_endpoint_is_bounded_on_its_own() {
        #[derive(Debug)]
        struct Answers {
            delay: Duration,
        }
        impl esplora_client::r#async::HttpTransport for Answers {
            fn execute(
                &self,
                request: reqwest::RequestBuilder,
            ) -> std::pin::Pin<
                Box<
                    dyn std::future::Future<
                            Output = Result<reqwest::Response, esplora_client::Error>,
                        > + Send
                        + '_,
                >,
            > {
                Box::pin(async move {
                    tokio::time::sleep(self.delay).await;
                    let request = request.build().unwrap();
                    let block = bitcoin::blockdata::constants::genesis_block(Network::Signet);
                    let hash = block.block_hash().to_string();
                    let body = if request.url().path().ends_with("/block-height/0") {
                        hash
                    } else {
                        bitcoin::consensus::encode::serialize_hex(&block.header)
                    };
                    Ok(http::Response::builder().body(body).unwrap().into())
                })
            }
        }
        // A silent second endpoint on a loopback port that accepts and
        // never replies.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent = format!("http://{}/api", listener.local_addr().unwrap());
        let hold = tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let answers = Answers {
            delay: Duration::from_millis(150),
        };
        let result = verify_esplora_api_urls_within(
            Network::Signet,
            &["https://slow-primary.invalid/api", &silent],
            Some(&answers),
            Duration::from_millis(600),
        )
        .await;
        assert_eq!(result.verified, [true, false]);
        assert_eq!(result.check, NetworkCheck::Unavailable);
        hold.abort();
    }
}
