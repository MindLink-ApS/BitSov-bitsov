//! Bitcoin Core RPC. Credentials stay in files; no public-chain fallback.
use std::path::PathBuf;

use async_trait::async_trait;
use konsensus_core::traits::chain::{
    BlockHeader, ChainError, ChainProvider, ChainView, FeeEstimate, TrustLevel,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// File-backed RPC authentication, shared with the embedded Lightning node.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "RawConfig")]
pub struct BitcoindConfig {
    pub rpc_host: String,
    pub rpc_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cookie_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_password_file: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    rpc_host: String,
    rpc_port: u16,
    cookie_file: Option<PathBuf>,
    rpc_user: Option<String>,
    rpc_password_file: Option<PathBuf>,
}

impl TryFrom<RawConfig> for BitcoindConfig {
    type Error = &'static str;
    fn try_from(raw: RawConfig) -> Result<Self, Self::Error> {
        let config = Self {
            rpc_host: raw.rpc_host,
            rpc_port: raw.rpc_port,
            cookie_file: raw.cookie_file,
            rpc_user: raw.rpc_user,
            rpc_password_file: raw.rpc_password_file,
        };
        config.validate()?;
        Ok(config)
    }
}

impl BitcoindConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        // Accept only a hostname or IP, never a URL, credentials, path or query.
        let host = &self.rpc_host;
        let ip = host.parse::<std::net::IpAddr>().is_ok();
        if self.rpc_port == 0
            || host.is_empty()
            || (!ip
                && !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
        {
            return Err("bitcoind requires a bare RPC hostname/IP and a nonzero port");
        }
        match (&self.cookie_file, &self.rpc_user, &self.rpc_password_file) {
            (Some(path), None, None) if !path.as_os_str().is_empty() => Ok(()),
            (None, Some(user), Some(path))
                if !user.is_empty()
                    && !user.contains([':', '\r', '\n'])
                    && !path.as_os_str().is_empty() =>
            {
                Ok(())
            }
            _ => Err("bitcoind requires cookie_file OR rpc_user + rpc_password_file"),
        }
    }

    /// Read at point of use so the provider follows Core's cookie rotation.
    /// The LDK RPC client captures these at startup; restart BitSov after Core
    /// rotates its cookie. Neither errors nor Debug contain file contents.
    pub fn credentials(&self) -> Result<(Zeroizing<String>, Zeroizing<String>), ChainError> {
        self.validate().map_err(|e| ChainError::Backend(e.into()))?;
        let path = self
            .cookie_file
            .as_ref()
            .or(self.rpc_password_file.as_ref())
            .expect("validated auth");
        let contents =
            Zeroizing::new(std::fs::read_to_string(path).map_err(|_| {
                ChainError::Backend("cannot read bitcoind authentication file".into())
            })?);
        let text = contents.trim_end_matches(['\r', '\n']);
        let (user, password) = if self.cookie_file.is_some() {
            text.split_once(':')
                .ok_or_else(|| ChainError::Backend("invalid bitcoind cookie file".into()))?
        } else {
            (self.rpc_user.as_deref().expect("validated user"), text)
        };
        if user.is_empty()
            || password.is_empty()
            || user.contains(['\r', '\n'])
            || password.contains(['\r', '\n'])
        {
            return Err(ChainError::Backend(
                "invalid bitcoind authentication file".into(),
            ));
        }
        Ok((Zeroizing::new(user.into()), Zeroizing::new(password.into())))
    }

    fn url(&self) -> String {
        if self.rpc_host.contains(':') {
            format!("http://[{}]:{}", self.rpc_host, self.rpc_port)
        } else {
            format!("http://{}:{}", self.rpc_host, self.rpc_port)
        }
    }
}

pub struct BitcoindProvider {
    config: BitcoindConfig,
    client: reqwest::Client,
}

#[derive(Deserialize)]
struct RpcResponse {
    result: Value,
    error: Option<RpcError>,
}
#[derive(Deserialize)]
struct RpcError {
    code: i64,
}

impl BitcoindProvider {
    pub fn new(config: BitcoindConfig) -> Result<Self, ChainError> {
        config
            .validate()
            .map_err(|e| ChainError::Backend(e.into()))?;
        config.credentials()?;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|_| ChainError::Connection("cannot build bitcoind RPC client".into()))?;
        Ok(Self { config, client })
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Result<Value, i64>, ChainError> {
        let (user, password) = self.config.credentials()?;
        let response = self
            .client
            .post(self.config.url())
            .basic_auth(user.as_str(), Some(password.as_str()))
            .json(&json!({"jsonrpc":"1.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| ChainError::Connection("bitcoind RPC request failed".into()))?;
        // Core returns HTTP 500 for JSON-RPC errors. Never echo the response
        // body, error message, authentication header or a secret-bearing URL.
        if response.status() != reqwest::StatusCode::INTERNAL_SERVER_ERROR
            && !response.status().is_success()
        {
            return Err(ChainError::Connection(format!(
                "bitcoind RPC HTTP {}",
                response.status().as_u16()
            )));
        }
        let response: RpcResponse = response
            .json()
            .await
            .map_err(|_| ChainError::Backend("invalid bitcoind RPC response".into()))?;
        Ok(match response.error {
            Some(error) => Err(error.code),
            None => Ok(response.result),
        })
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        self.rpc(method, params)
            .await?
            .map_err(|code| ChainError::Backend(format!("bitcoind {method} failed (RPC {code})")))
    }

    /// Visibility check for LDK's asynchronous broadcast; never queries Esplora.
    pub async fn tx_visible(&self, txid: &str) -> Result<bool, ChainError> {
        match self.rpc("getrawtransaction", json!([txid, true])).await? {
            Ok(_) => Ok(true),
            Err(-5) => Ok(false),
            Err(code) => Err(ChainError::Backend(format!(
                "bitcoind transaction lookup failed (RPC {code})"
            ))),
        }
    }
}

fn number(value: &Value, field: &str) -> Result<u64, ChainError> {
    value[field]
        .as_u64()
        .ok_or_else(|| ChainError::Backend(format!("invalid bitcoind {field}")))
}

#[async_trait]
impl ChainProvider for BitcoindProvider {
    fn trust_level(&self) -> TrustLevel {
        TrustLevel::FullValidation
    }
    fn chain_view(&self) -> ChainView {
        ChainView {
            backend: "bitcoind",
            trust_level: "trustless",
            host: Some(self.config.rpc_host.clone()),
        }
    }
    async fn get_block_height(&self) -> Result<u64, ChainError> {
        self.call("getblockcount", json!([]))
            .await?
            .as_u64()
            .ok_or_else(|| ChainError::Backend("invalid bitcoind height".into()))
    }
    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
        let hash = self.call("getblockhash", json!([height])).await?;
        let header = self.call("getblockheader", json!([hash, true])).await?;
        Ok(BlockHeader {
            height: number(&header, "height")?,
            hash: header["hash"]
                .as_str()
                .ok_or_else(|| ChainError::Backend("invalid block hash".into()))?
                .into(),
            timestamp: number(&header, "time")?,
            bits: u32::from_str_radix(header["bits"].as_str().unwrap_or(""), 16)
                .map_err(|_| ChainError::Backend("invalid block bits".into()))?,
        })
    }
    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
        let result = self
            .call("estimatesmartfee", json!([target_blocks.max(2)]))
            .await?;
        let rate = result["feerate"]
            .as_f64()
            .filter(|rate| rate.is_finite() && *rate > 0.0)
            .ok_or_else(|| {
                ChainError::FeeEstimationFailed("Bitcoin Core has no fee estimate yet".into())
            })?;
        Ok(FeeEstimate {
            target_blocks,
            sat_per_vbyte: rate * 100_000.0,
        })
    }
    async fn is_tx_confirmed(
        &self,
        txid: &str,
        min_confirmations: u32,
    ) -> Result<bool, ChainError> {
        let txid = txid
            .parse::<bitcoin::Txid>()
            .map_err(|_| ChainError::TxNotFound("invalid txid".into()))?
            .to_string();
        match self.rpc("getrawtransaction", json!([txid, true])).await? {
            Ok(tx) => {
                return Ok(tx["confirmations"].as_u64().unwrap_or(0)
                    >= u64::from(min_confirmations.max(1)))
            }
            Err(-5) => {} // No txindex (including pruned nodes): inspect retained recent blocks.
            Err(code) => {
                return Err(ChainError::Backend(format!(
                    "bitcoind transaction lookup failed (RPC {code})"
                )))
            }
        }
        let info = self.call("getblockchaininfo", json!([])).await?;
        let tip = number(&info, "blocks")?;
        // Bound the work for txid-only lookups. Older transactions need txindex
        // on a full node; unknown/pruned is an error, never an assertion of absence.
        let floor = tip
            .saturating_sub(287)
            .max(info["pruneheight"].as_u64().unwrap_or(0));
        for height in (floor..=tip).rev() {
            let hash = self.call("getblockhash", json!([height])).await?;
            let block = self.call("getblock", json!([hash, 1])).await?;
            let txs = block["tx"]
                .as_array()
                .ok_or_else(|| ChainError::Backend("invalid block transactions".into()))?;
            if txs.iter().any(|tx| tx.as_str() == Some(txid.as_str())) {
                // Use Core's active-chain confirmation count; an orphan has -1.
                return Ok(block["confirmations"].as_u64().unwrap_or(0)
                    >= u64::from(min_confirmations.max(1)));
            }
        }
        Err(ChainError::NotAvailable("transaction not found in mempool/index or last 288 retained blocks; historical confirmation unavailable".into()))
    }
    async fn is_synced(&self) -> bool {
        match self.call("getblockchaininfo", json!([])).await {
            Ok(info) => {
                info["initialblockdownload"].as_bool() == Some(false)
                    && info["blocks"].as_u64().is_some()
                    && info["blocks"].as_u64() == info["headers"].as_u64()
            }
            Err(_) => false,
        }
    }
}
