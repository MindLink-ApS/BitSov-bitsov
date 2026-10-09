//! Core Lightning clnrest receive/read preview. Outgoing payments remain disabled.
use std::{
    collections::HashMap,
    fmt,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use async_trait::async_trait;
use rand::RngCore;
use reqwest::{header::HeaderValue, Client, Url};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::json;
use zeroize::Zeroizing;

use konsensus_core::traits::lightning::{
    ChannelInfo, Invoice, LightningError, LightningProvider, PaymentDetails, PaymentDirection,
    PaymentStatus, RoutingFeePolicy, WalletBalanceBreakdown,
};

pub fn default_minimum_version() -> String {
    "v24.11".into()
}

/// No inline credentials: the rune is read once from a private file at startup.
#[derive(Clone)]
pub struct ClnConfig {
    pub rest_url: String,
    /// Override DNS while retaining the URL hostname for TLS verification.
    pub resolve_ip: Option<IpAddr>,
    pub ca_cert_path: PathBuf,
    pub rune_file: PathBuf,
    /// Exact CLN network name: bitcoin, testnet, signet or regtest.
    pub network: String,
    /// May raise, but never lower, the v24.11 release floor.
    pub minimum_version: String,
}
impl fmt::Debug for ClnConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClnConfig")
            .field(
                "rest_url",
                &konsensus_core::logging::redact_url_for_debug(&self.rest_url),
            )
            .field("resolve_ip", &self.resolve_ip)
            .field("ca_cert_path", &self.ca_cert_path)
            .field("rune_file", &self.rune_file)
            .field("network", &self.network)
            .field("minimum_version", &self.minimum_version)
            .finish()
    }
}

pub struct ClnProvider {
    client: Client,
    endpoint: Url,
    rune: HeaderValue,
    network: String,
    minimum_version: (u32, u32, u32),
    routing_fee_policy: RoutingFeePolicy,
}
impl fmt::Debug for ClnProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClnProvider")
            .field("rune", &"<redacted>")
            .field("network", &self.network)
            .field("minimum_version", &self.minimum_version)
            .field("payment_capable", &false)
            .finish_non_exhaustive()
    }
}

fn error(message: &'static str) -> LightningError {
    LightningError::Backend(message.into())
}

/// Accept releases and CLN git-describe builds after a release; reject prereleases
/// and malformed versions instead of guessing from a numeric prefix.
fn release_version(raw: &str) -> Option<(u32, u32, u32)> {
    let raw = raw.strip_prefix('v').unwrap_or(raw);
    let base = if let Some((base, suffix)) = raw.split_once('-') {
        let (count, hash) = suffix.split_once("-g")?;
        if count.is_empty()
            || !count.bytes().all(|b| b.is_ascii_digit())
            || hash.is_empty()
            || !hash.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        base
    } else {
        raw
    };
    let parts = base.split('.').collect::<Vec<_>>();
    if !(2..=3).contains(&parts.len())
        || parts
            .iter()
            .any(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let year = parts[0].parse().ok()?;
    let month = parts[1].parse().ok()?;
    if !(1..=12).contains(&month) {
        return None;
    }
    let patch = if parts.len() == 3 {
        parts[2].parse().ok()?
    } else {
        0
    };
    Some((year, month, patch))
}

// Build the actual verifier's store explicitly so ambient/public roots cannot
// enter through reqwest feature unification or platform certificate settings.
fn pinned_roots(pem: &[u8]) -> Result<rustls::RootCertStore, LightningError> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    let ca =
        CertificateDer::from_pem_slice(pem).map_err(|_| error("CLN CA certificate must be PEM"))?;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(ca)
        .map_err(|_| error("CLN CA certificate is invalid"))?;
    Ok(roots)
}

fn load_rune(path: &std::path::Path) -> Result<HeaderValue, LightningError> {
    let file = File::open(path).map_err(|_| error("CLN rune file cannot be opened"))?;
    let metadata = file
        .metadata()
        .map_err(|_| error("CLN rune file metadata unavailable"))?;
    if !metadata.is_file() {
        return Err(error("CLN rune must be a regular file"));
    }
    // Check the opened descriptor, not a separate path lookup, before reading.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o7777 != 0o600 {
            return Err(error("CLN rune file must have mode 0600"));
        }
    }
    #[cfg(not(unix))]
    return Err(error("CLN rune file mode verification requires Unix"));
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| error("CLN rune file cannot be read"))?;
    if bytes.len() > 16_384 {
        return Err(error("CLN rune file is too large"));
    }
    let raw = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
    if raw.is_empty() || !raw.iter().all(|b| b.is_ascii_graphic()) {
        return Err(error("CLN rune file must contain one nonempty token"));
    }
    let mut value =
        HeaderValue::from_bytes(raw).map_err(|_| error("CLN rune is not a valid header value"))?;
    value.set_sensitive(true);
    Ok(value)
}

#[derive(Deserialize)]
struct GetInfo {
    id: String,
    version: String,
    network: String,
}

// CLN uses integer msat in modern replies; accept its legacy "123msat" form
// too, without silently treating malformed or missing amounts as zero.
#[derive(Clone, Copy)]
struct Msat(u64);
impl<'de> Deserialize<'de> for Msat {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Number(u64),
            Text(String),
        }
        match Wire::deserialize(deserializer)? {
            Wire::Number(n) => Ok(Self(n)),
            Wire::Text(s) => s
                .strip_suffix("msat")
                .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|v| v.parse().ok())
                .map(Self)
                .ok_or_else(|| serde::de::Error::custom("invalid CLN amount")),
        }
    }
}
// Only an invoice's requested amount can be "any" (notably for keysend).
// It means no fixed amount; received amounts and all other msat stay numeric.
fn deserialize_invoice_amount<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Msat>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        Fixed(Msat),
        Text(String),
    }
    match Option::<Wire>::deserialize(deserializer)? {
        Some(Wire::Fixed(amount)) => Ok(Some(amount)),
        Some(Wire::Text(text)) if text == "any" => Ok(None),
        None => Ok(None),
        _ => Err(serde::de::Error::custom("invalid CLN invoice amount")),
    }
}
fn required<T>(value: Option<T>) -> Result<T, LightningError> {
    value.ok_or_else(|| error("CLN response is missing a required field"))
}
fn add(a: u64, b: u64) -> Result<u64, LightningError> {
    a.checked_add(b).ok_or_else(|| error("CLN amount overflow"))
}
fn hex32(raw: &str) -> Result<String, LightningError> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(raw, &mut bytes).map_err(|_| error("CLN hash or preimage is invalid"))?;
    Ok(hex::encode(bytes))
}
fn matching_hash(details: PaymentDetails, hash: &str) -> Result<PaymentDetails, LightningError> {
    if details.payment_hash != hash {
        return Err(error("CLN lookup returned a different payment hash"));
    }
    Ok(details)
}
fn next_index(index: Option<u64>, start: u64) -> Result<u64, LightningError> {
    required(index)?
        .checked_add(1)
        .filter(|next| *next > start)
        .ok_or_else(|| error("CLN history cursor did not advance"))
}
fn sort_payments(rows: &mut [PaymentDetails]) {
    rows.sort_by(|a, b| {
        b.timestamp
            .cmp(&a.timestamp)
            .then_with(|| a.payment_hash.cmp(&b.payment_hash))
            .then_with(|| {
                (a.direction == PaymentDirection::Outgoing)
                    .cmp(&(b.direction == PaymentDirection::Outgoing))
            })
    });
}
#[derive(Deserialize)]
struct CreatedInvoice {
    bolt11: String,
    payment_hash: String,
    expires_at: u64,
}
#[derive(Deserialize)]
struct Invoices {
    invoices: Vec<ClnInvoice>,
}
#[derive(Deserialize)]
struct ClnInvoice {
    payment_hash: String,
    status: String,
    #[serde(default, deserialize_with = "deserialize_invoice_amount")]
    amount_msat: Option<Msat>,
    amount_received_msat: Option<Msat>,
    payment_preimage: Option<String>,
    paid_at: Option<u64>,
    bolt11: Option<String>,
    description: Option<String>,
    created_index: Option<u64>,
}
impl ClnInvoice {
    fn details(self) -> Result<PaymentDetails, LightningError> {
        let status = match self.status.as_str() {
            "paid" => PaymentStatus::Settled,
            "unpaid" => PaymentStatus::Pending,
            "expired" => PaymentStatus::Expired,
            _ => return Err(error("CLN invoice status is invalid")),
        };
        let settled = status == PaymentStatus::Settled;
        let timestamp = if settled {
            required(self.paid_at)?
        } else {
            self.bolt11
                .as_deref()
                .and_then(|s| s.parse::<lightning_invoice::Bolt11Invoice>().ok())
                .map(|i| i.duration_since_epoch().as_secs())
                .unwrap_or(0)
        };
        Ok(PaymentDetails {
            payment_hash: hex32(&self.payment_hash)?,
            preimage: if settled {
                Some(hex32(&required(self.payment_preimage)?)?)
            } else {
                None
            },
            amount_msat: if settled {
                required(self.amount_received_msat)?.0
            } else {
                self.amount_msat.map_or(0, |n| n.0)
            },
            status,
            direction: PaymentDirection::Incoming,
            timestamp,
            memo: self.description,
            fee_msat: None,
        })
    }
}
#[derive(Deserialize)]
struct Pays {
    pays: Vec<ClnPay>,
}
#[derive(Deserialize)]
struct ClnPay {
    payment_hash: String,
    status: String,
    amount_msat: Option<Msat>,
    amount_sent_msat: Option<Msat>,
    preimage: Option<String>,
    created_at: u64,
    created_index: Option<u64>,
    description: Option<String>,
}
impl ClnPay {
    fn details(self) -> Result<PaymentDetails, LightningError> {
        let status = match self.status.as_str() {
            "complete" => PaymentStatus::Settled,
            "pending" => PaymentStatus::InFlight,
            "failed" => PaymentStatus::Failed,
            _ => return Err(error("CLN payment status is invalid")),
        };
        let settled = status == PaymentStatus::Settled;
        let fee_msat = match (settled, self.amount_msat, self.amount_sent_msat) {
            (true, Some(amount), Some(sent)) => Some(
                sent.0
                    .checked_sub(amount.0)
                    .ok_or_else(|| error("CLN payment amounts are inconsistent"))?,
            ),
            _ => None,
        };
        Ok(PaymentDetails {
            payment_hash: hex32(&self.payment_hash)?,
            preimage: if settled {
                Some(hex32(&required(self.preimage)?)?)
            } else {
                None
            },
            amount_msat: if settled {
                required(self.amount_msat)?.0
            } else {
                self.amount_msat.map_or(0, |n| n.0)
            },
            status,
            direction: PaymentDirection::Outgoing,
            timestamp: self.created_at,
            memo: self.description,
            fee_msat,
        })
    }
}
#[derive(Deserialize)]
struct Channels {
    channels: Vec<ClnChannel>,
}
#[derive(Deserialize)]
struct ClnChannel {
    state: String,
    peer_id: Option<String>,
    peer_connected: Option<bool>,
    channel_id: Option<String>,
    short_channel_id: Option<String>,
    total_msat: Option<Msat>,
    to_us_msat: Option<Msat>,
    spendable_msat: Option<Msat>,
}
#[derive(Deserialize)]
struct Funds {
    outputs: Vec<Output>,
}
#[derive(Deserialize)]
struct Output {
    amount_msat: Msat,
    status: String,
}

impl ClnProvider {
    /// Connect and validate before exposing the provider to the node.
    pub async fn new(config: ClnConfig) -> Result<Self, LightningError> {
        let mut endpoint = Url::parse(&config.rest_url)
            .map_err(|_| error("CLN rest_url must be an HTTPS origin"))?;
        if endpoint.scheme() != "https"
            || endpoint.host_str().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
            || endpoint.path() != "/"
        {
            return Err(error(
                "CLN rest_url must be an HTTPS origin without credentials, path, query or fragment",
            ));
        }
        if !matches!(
            config.network.as_str(),
            "bitcoin" | "testnet" | "signet" | "regtest"
        ) {
            return Err(error(
                "CLN network must be bitcoin, testnet, signet or regtest",
            ));
        }
        let minimum_version = release_version(&config.minimum_version)
            .filter(|v| *v >= (24, 11, 0))
            .ok_or_else(|| error("CLN minimum_version must be a release >= v24.11"))?;
        let ca = std::fs::read(&config.ca_cert_path)
            .map_err(|_| error("CLN CA certificate cannot be read"))?;
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| error("CLN TLS protocol configuration failed"))?
        .with_root_certificates(pinned_roots(&ca)?)
        .with_no_client_auth();
        let rune = load_rune(&config.rune_file)?;
        let mut builder = Client::builder()
            .use_preconfigured_tls(tls)
            .https_only(true)
            .tls_built_in_root_certs(false)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(10));
        if let Some(ip) = config.resolve_ip {
            builder = builder.resolve(
                endpoint
                    .host_str()
                    .ok_or_else(|| error("CLN hostname missing"))?,
                SocketAddr::new(ip, endpoint.port_or_known_default().unwrap_or(443)),
            );
        }
        let client = builder
            .build()
            .map_err(|_| error("CLN HTTPS client initialization failed"))?;
        endpoint.set_path("/v1/getinfo");
        let provider = Self {
            client,
            endpoint,
            rune,
            network: config.network,
            minimum_version,
            routing_fee_policy: RoutingFeePolicy::default(),
        };
        provider.getinfo().await?;
        Ok(provider)
    }

    async fn outgoing_status(&self, hash: &str) -> Result<PaymentDetails, LightningError> {
        let response: Pays = self.rpc("listpays", json!({"payment_hash":hash})).await?;
        if response.pays.is_empty() {
            return Err(LightningError::PaymentNotFound(hash.into()));
        }
        // External callers may retry with a new groupid. A successful attempt
        // proves settlement; otherwise any pending attempt keeps this hash in
        // flight. Only all-failed attempts allow a terminal failure result.
        let mut attempts = response
            .pays
            .into_iter()
            .map(|pay| matching_hash(pay.details()?, hash))
            .collect::<Result<Vec<_>, _>>()?;
        attempts.sort_by_key(|pay| {
            (
                match pay.status {
                    PaymentStatus::Settled => 2,
                    PaymentStatus::InFlight => 1,
                    _ => 0,
                },
                pay.timestamp,
            )
        });
        Ok(attempts.pop().unwrap())
    }

    async fn payment_history(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        // CLN pages forwards, not newest-first. Short listpays pages are not EOF:
        // the limit counts payment parts before CLN aggregates multipart rows.
        // Hydrate outgoing hashes BEFORE ranking: a partial MPP aggregate may
        // start at a later part and report a newer timestamp and partial fees.
        // Keep only the best `limit` canonical candidates while scanning.
        let mut recent = HashMap::new();
        for method in ["listinvoices", "listpays"] {
            let mut start = 0u64;
            loop {
                let params = json!({"index":"created", "start":start, "limit":100});
                let mut next = start;
                let mut rows = Vec::new();
                if method == "listinvoices" {
                    let response: Invoices = self.rpc(method, params).await?;
                    for row in response.invoices {
                        next = next.max(next_index(row.created_index, start)?);
                        rows.push(row.details()?);
                    }
                } else {
                    let response: Pays = self.rpc(method, params).await?;
                    for row in response.pays {
                        next = next.max(next_index(row.created_index, start)?);
                        rows.push(self.outgoing_status(&hex32(&row.payment_hash)?).await?);
                    }
                }
                if rows.is_empty() {
                    break;
                }
                for row in rows {
                    recent.insert((row.direction, row.payment_hash.clone()), row);
                }
                let mut ordered: Vec<_> = recent.into_values().collect();
                sort_payments(&mut ordered);
                ordered.truncate(limit as usize);
                recent = ordered
                    .into_iter()
                    .map(|row| ((row.direction, row.payment_hash.clone()), row))
                    .collect();
                start = next;
            }
        }
        let mut result: Vec<_> = recent.into_values().collect();
        sort_payments(&mut result);
        Ok(result)
    }

    pub fn with_routing_fee_policy(mut self, policy: RoutingFeePolicy) -> Self {
        self.routing_fee_policy = policy;
        self
    }

    async fn rpc<T: DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T, LightningError> {
        let mut endpoint = self.endpoint.clone();
        endpoint.set_path(&format!("/v1/{method}"));
        // Never propagate reqwest/serde errors or backend response bodies: the
        // remote server can echo the credential into any of them.
        let mut response = self
            .client
            .post(endpoint)
            .header("Rune", self.rune.clone())
            .json(&params)
            .send()
            .await
            .map_err(|_| error("CLN HTTPS request failed"))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(error("CLN RPC returned non-200 status"));
        }
        // Invoice pages contain BOLT strings and descriptions; getinfo's small
        // PR1 bound is unsuitable for history, funds and channel snapshots.
        let max_bytes = if method == "getinfo" {
            65_536
        } else {
            4 * 1024 * 1024
        };
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| error("CLN response read failed"))?
        {
            if body.len() + chunk.len() > max_bytes {
                return Err(error("CLN response is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| error("CLN response is invalid"))
    }

    async fn getinfo(&self) -> Result<GetInfo, LightningError> {
        let info: GetInfo = self.rpc("getinfo", json!({})).await?;
        if release_version(&info.version).is_none_or(|v| v < self.minimum_version) {
            return Err(error("not_supported: CLN version below configured minimum or invalid (requires >= v24.11)"));
        }
        if info.network != self.network {
            return Err(error("CLN getinfo network does not match configuration"));
        }
        if info.id.len() != 66 || info.id.parse::<bitcoin::secp256k1::PublicKey>().is_err() {
            return Err(error("CLN getinfo node public key is invalid"));
        }
        Ok(info)
    }
}

#[async_trait]
impl LightningProvider for ClnProvider {
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        let mut random = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut random)
            .map_err(|_| error("CLN invoice label generation failed"))?;
        let response: CreatedInvoice = self
            .rpc(
                "invoice",
                json!({
                    "amount_msat": amount_msat,
                    "label": format!("bitsov:{}", hex::encode(random)),
                    "description": description,
                    "expiry": expiry_secs,
                }),
            )
            .await?;
        let payment_hash = hex32(&response.payment_hash)?;
        let bolt11 = response
            .bolt11
            .parse::<lightning_invoice::Bolt11Invoice>()
            .map_err(|_| error("CLN invoice BOLT11 is invalid"))?;
        if bolt11.payment_hash().to_string() != payment_hash {
            return Err(error("CLN invoice BOLT11 payment hash does not match"));
        }
        Ok(Invoice {
            bolt11: response.bolt11,
            payment_hash,
            amount_msat,
            description: description.into(),
            expiry_secs,
            created_at: response
                .expires_at
                .checked_sub(u64::from(expiry_secs))
                .ok_or_else(|| error("CLN invoice expiry is invalid"))?,
        })
    }
    async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::PaymentNotDispatched(
            "not_supported: CLN preview payments".into(),
        ))
    }
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        let hash = hex32(payment_hash)?;
        let response: Invoices = self
            .rpc("listinvoices", json!({"payment_hash":hash}))
            .await?;
        if !response.invoices.is_empty() {
            if response.invoices.len() != 1 {
                return Err(error("CLN invoice lookup is ambiguous"));
            }
            let details = response.invoices.into_iter().next().unwrap().details()?;
            return matching_hash(details, &hash);
        }
        self.outgoing_status(&hash).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        let response: Channels = self.rpc("listpeerchannels", json!({})).await?;
        response
            .channels
            .iter()
            .filter(|ch| ch.state == "CHANNELD_NORMAL")
            .try_fold(0u64, |sum, ch| add(sum, required(ch.spendable_msat)?.0))
    }
    async fn get_balance_breakdown(&self) -> Result<WalletBalanceBreakdown, LightningError> {
        let response: Funds = self.rpc("listfunds", json!({})).await?;
        let mut total = 0;
        for output in response.outputs {
            match output.status.as_str() {
                "spent" => continue,
                "confirmed" | "unconfirmed" | "immature" => {}
                _ => return Err(error("CLN output status is invalid")),
            }
            total = add(total, output.amount_msat.0)?;
        }
        Ok(WalletBalanceBreakdown {
            onchain_total_sats: Some(total / 1000),
            // listfunds cannot establish CLN's anchor/emergency reserve, so it
            // cannot satisfy the trait's spendable-after-reserve contract.
            onchain_spendable_sats: None,
            lightning_spendable_sats: Some(self.get_balance_msat().await? / 1000),
            ..Default::default()
        })
    }
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        let response: Channels = self.rpc("listpeerchannels", json!({})).await?;
        response
            .channels
            .into_iter()
            .filter(|ch| ch.channel_id.is_some())
            .map(|ch| {
                let capacity = required(ch.total_msat)?.0;
                let local = required(ch.to_us_msat)?.0;
                Ok(ChannelInfo {
                    channel_id: hex32(&required(ch.channel_id)?)?,
                    peer_pubkey: required(ch.peer_id)?,
                    capacity_msat: capacity,
                    local_balance_msat: local,
                    remote_balance_msat: capacity
                        .checked_sub(local)
                        .ok_or_else(|| error("CLN channel balances are inconsistent"))?,
                    active: ch.state == "CHANNELD_NORMAL" && required(ch.peer_connected)?,
                    short_channel_id: ch.short_channel_id,
                })
            })
            .collect()
    }
    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        tokio::time::timeout(Duration::from_secs(30), self.payment_history(limit))
            .await
            .map_err(|_| error("CLN payment history timed out"))?
    }
    fn routing_fee_policy(&self) -> RoutingFeePolicy {
        self.routing_fee_policy
    }
    async fn is_available(&self) -> bool {
        self.getinfo().await.is_ok()
    }
    async fn get_node_pubkey(&self) -> Option<String> {
        self.getinfo().await.ok().map(|info| info.id)
    }
    async fn is_payment_capable(&self) -> bool {
        false
    }
    async fn money_ready(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_store_contains_only_configured_ca_no_public_roots() {
        use rustls::pki_types::{pem::PemObject, CertificateDer};
        let pem = include_bytes!("../tests/fixtures/cln/ca.pem");
        let roots = pinned_roots(pem).unwrap();
        let mut expected = rustls::RootCertStore::empty();
        expected
            .add(CertificateDer::from_pem_slice(pem).unwrap())
            .unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots.roots, expected.roots);
    }
}
