//! Explicit Electrum endpoint; no discovery, default server, or fallback.
use std::net::IpAddr;

use async_trait::async_trait;
use electrum_client::{Client, ConfigBuilder, ElectrumApi};
use konsensus_core::traits::chain::{
    BlockHeader, ChainError, ChainProvider, ChainView, FeeEstimate, TrustLevel,
};
use serde::{Deserialize, Serialize};

/// An owner declaration, not verification of server ownership or validation.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ElectrumOperator {
    Own,
    #[default]
    ThirdParty,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawConfig")]
pub struct ElectrumConfig {
    pub server_url: String,
    pub operator: ElectrumOperator,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    server_url: String,
    #[serde(default)]
    operator: ElectrumOperator,
}

impl TryFrom<RawConfig> for ElectrumConfig {
    type Error = &'static str;
    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        let config = Self {
            server_url: raw.server_url,
            operator: raw.operator,
        };
        config.validate()?;
        Ok(config)
    }
}

impl ElectrumConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.host().map(|_| ())
    }

    // Validate the exact authority passed to electrum-client, without DNS or
    // URL normalization that could reinterpret a public IP as a local one.
    fn host(&self) -> Result<&str, &'static str> {
        let invalid = "electrum requires ssl://host:port or tcp://local-host:port without credentials, path, query or fragment";
        let (scheme, authority) = self.server_url.split_once("://").ok_or(invalid)?;
        if !matches!(scheme, "ssl" | "tcp") {
            return Err(invalid);
        }
        let (raw_host, port) = authority.rsplit_once(':').ok_or(invalid)?;
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok().filter(|p| *p > 0).is_none()
        {
            return Err(invalid);
        }
        let host = if let Some(host) = raw_host.strip_prefix('[').and_then(|h| h.strip_suffix(']'))
        {
            host.parse::<std::net::Ipv6Addr>().map_err(|_| invalid)?;
            // electrum-client 0.24 splits TLS server names at the first colon.
            // Fail explicitly instead of accepting an endpoint it cannot use.
            if scheme == "ssl" {
                return Err("electrum TLS over IPv6 requires a DNS hostname; IPv6 literals are unsupported by the pinned client");
            }
            host
        } else {
            if raw_host.is_empty()
                || raw_host.len() > 253
                || !raw_host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return Err(invalid);
            }
            raw_host
        };
        if host.to_ascii_lowercase().ends_with(".onion") {
            return Err("Tor/.onion Electrum servers are not supported yet: no proxy setting");
        }
        let local = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => ip.is_loopback() || ip.is_private(),
            Ok(IpAddr::V6(ip)) => {
                ip.is_loopback()
                    || ip.is_unique_local()
                    || ip
                        .to_ipv4_mapped()
                        .is_some_and(|ip| ip.is_loopback() || ip.is_private())
            }
            Err(_) => host.eq_ignore_ascii_case("localhost"),
        };
        if scheme == "tcp" && !local {
            return Err(
                "electrum tcp requires loopback or a private LAN IP; use ssl for other hosts",
            );
        }
        Ok(host)
    }
}

pub struct ElectrumProvider {
    config: ElectrumConfig,
}

impl ElectrumProvider {
    /// Validation only. Network I/O happens on bounded blocking workers at use.
    pub fn new(config: ElectrumConfig) -> Result<Self, ChainError> {
        config
            .validate()
            .map_err(|e| ChainError::Backend(e.into()))?;
        Ok(Self { config })
    }

    pub(crate) async fn query<T: Send + 'static>(
        &self,
        operation: impl FnOnce(Client) -> Result<T, ChainError> + Send + 'static,
    ) -> Result<T, ChainError> {
        let url = self.config.server_url.clone();
        tokio::task::spawn_blocking(move || {
            let config = ConfigBuilder::new().timeout(Some(10)).retry(0).build();
            let client = Client::from_config(&url, config)
                .map_err(|_| ChainError::Connection("Electrum connection failed".into()))?;
            operation(client)
        })
        .await
        .map_err(|_| ChainError::Backend("Electrum worker failed".into()))?
    }

    /// A returned transaction proves presence at any confirmation depth.
    /// Electrum not-found (including -5 during propagation) cannot prove absence.
    pub async fn funding_present(&self, txid: &str) -> Result<bool, ChainError> {
        let txid = parse_txid(txid)?;
        self.query(move |client| funding_presence(txid, client.transaction_get(&txid)))
            .await
    }

    /// Used after LDK's asynchronous broadcast, against this endpoint only.
    pub async fn tx_visible(&self, txid: &str) -> Result<bool, ChainError> {
        let txid = parse_txid(txid)?;
        self.query(move |client| {
            match client.transaction_get(&txid) {
                Ok(tx) if tx.compute_txid() == txid => Ok(true),
                Ok(_) => Err(ChainError::Backend(
                    "Electrum transaction ID mismatch".into(),
                )),
                // Core's not-found code can be forwarded by an Electrum server
                // while LDK's asynchronous broadcast is still propagating.
                Err(electrum_client::Error::Protocol(error)) if error["code"] == -5 => Ok(false),
                Err(error) => Err(rpc_error(error)),
            }
        })
        .await
    }
}

fn funding_presence(
    txid: bitcoin::Txid,
    result: Result<bitcoin::Transaction, electrum_client::Error>,
) -> Result<bool, ChainError> {
    let tx = result.map_err(rpc_error)?;
    if tx.compute_txid() != txid {
        return Err(ChainError::Backend(
            "Electrum transaction ID mismatch".into(),
        ));
    }
    Ok(true)
}

fn parse_txid(txid: &str) -> Result<bitcoin::Txid, ChainError> {
    txid.parse()
        .map_err(|_| ChainError::TxNotFound("invalid txid".into()))
}

fn rpc_error(_: electrum_client::Error) -> ChainError {
    // Remote error text may contain server-supplied secrets or wallet data.
    ChainError::Backend("Electrum request failed".into())
}

#[async_trait]
impl ChainProvider for ElectrumProvider {
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::ServerTrust
    }

    fn chain_view(&self) -> ChainView {
        ChainView {
            backend: "electrum",
            trust_level: match self.config.operator {
                ElectrumOperator::Own => "own_node",
                ElectrumOperator::ThirdParty => "third_party",
            },
            host: self.config.host().ok().map(str::to_owned),
        }
    }

    async fn get_block_height(&self) -> Result<u64, ChainError> {
        self.query(|client| Ok(client.block_headers_subscribe().map_err(rpc_error)?.height as u64))
            .await
    }

    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        let index = usize::try_from(height).map_err(|_| ChainError::BlockNotFound(height))?;
        self.query(move |client| {
            let header = client.block_header(index).map_err(rpc_error)?;
            Ok(BlockHeader {
                height,
                hash: header.block_hash().to_string(),
                timestamp: u64::from(header.time),
                bits: header.bits.to_consensus(),
            })
        })
        .await
    }

    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        self.query(move |client| {
            let rate = client
                .estimate_fee(target_blocks.max(1) as usize)
                .map_err(rpc_error)?;
            let sat_per_vbyte = rate * 100_000.0;
            if !sat_per_vbyte.is_finite() || sat_per_vbyte <= 0.0 {
                return Err(ChainError::FeeEstimationFailed(
                    "Electrum has no fee estimate".into(),
                ));
            }
            Ok(FeeEstimate {
                target_blocks,
                sat_per_vbyte,
            })
        })
        .await
    }

    async fn is_tx_confirmed(
        &self,
        txid: &str,
        min_confirmations: u32,
    ) -> Result<bool, ChainError> {
        let txid = parse_txid(txid)?;
        self.query(move |client| {
            // Standard Electrum history works with electrs as well as Fulcrum;
            // verbose transaction.get (a nonstandard extension) is not needed.
            let tx = client.transaction_get(&txid).map_err(rpc_error)?;
            if tx.compute_txid() != txid {
                return Err(ChainError::Backend(
                    "Electrum transaction ID mismatch".into(),
                ));
            }
            for output in tx.output {
                let history = client
                    .script_get_history(&output.script_pubkey)
                    .map_err(rpc_error)?;
                if let Some(entry) = history.iter().find(|entry| entry.tx_hash == txid) {
                    if entry.height <= 0 {
                        return Ok(false);
                    }
                    let tip = client.block_headers_subscribe().map_err(rpc_error)?.height as u64;
                    let height = entry.height as u64;
                    if height > tip {
                        return Err(ChainError::NotAvailable(
                            "Electrum history exceeds tip".into(),
                        ));
                    }
                    return Ok(tip - height + 1 >= u64::from(min_confirmations.max(1)));
                }
            }
            Err(ChainError::NotAvailable(
                "Electrum transaction history unavailable".into(),
            ))
        })
        .await
    }

    async fn is_synced(&self) -> bool {
        // Like Esplora, this means a tip is available, not proof of freshness.
        self.get_block_height().await.is_ok()
    }

    async fn is_synced_with_height(&self, _height: u64) -> bool {
        // This backend defines sync as availability of a tip. The caller's
        // successful bounded-age height read already established that.
        true
    }
}

#[cfg(test)]
mod funding_tests {
    use super::*;

    #[tokio::test]
    async fn known_height_satisfies_height_only_sync_without_another_lookup() {
        // Deliberately unconnectable configuration: no network is needed when
        // readiness already has a successful, bounded-age height observation.
        let provider = ElectrumProvider {
            config: ElectrumConfig {
                server_url: "unsupported://no-network".into(),
                operator: ElectrumOperator::ThirdParty,
            },
        };
        assert!(provider.is_synced_with_height(900_000).await);
    }

    #[test]
    fn returned_funding_is_present_without_a_confirmation_query() {
        // transaction.get returns the same raw transaction whether confirmed
        // or in the mempool; neither status needs a history/tip lookup.
        let tx = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).txdata[0]
            .clone();
        assert!(funding_presence(tx.compute_txid(), Ok(tx.clone())).unwrap());
        assert!(funding_presence("ab".repeat(32).parse().unwrap(), Ok(tx)).is_err());
    }

    #[test]
    fn electrum_cannot_prove_absence_including_minus_five() {
        let txid = "ab".repeat(32).parse().unwrap();
        for code in [-5, -1, -32603] {
            assert!(funding_presence(
                txid,
                Err(electrum_client::Error::Protocol(
                    serde_json::json!({"code":code,"message":"not found"}),
                ))
            )
            .is_err());
        }
        assert!(funding_presence(
            txid,
            Err(electrum_client::Error::IOError(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "offline"
            ),))
        )
        .is_err());
    }
}
