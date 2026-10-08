//! Core Lightning clnrest preview. Only `getinfo` is enabled in PR1.
use std::{
    fmt,
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use async_trait::async_trait;
use reqwest::{header::HeaderValue, Client, Url};
use serde::Deserialize;
use zeroize::Zeroizing;

use konsensus_core::traits::lightning::{
    Invoice, LightningError, LightningProvider, PaymentDetails, RoutingFeePolicy,
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

    pub fn with_routing_fee_policy(mut self, policy: RoutingFeePolicy) -> Self {
        self.routing_fee_policy = policy;
        self
    }

    async fn getinfo(&self) -> Result<GetInfo, LightningError> {
        // Never propagate reqwest/serde errors or backend response bodies: the
        // remote server can echo the credential into any of them.
        let mut response = self
            .client
            .post(self.endpoint.clone())
            .header("Rune", self.rune.clone())
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|_| error("CLN getinfo HTTPS request failed"))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(error("CLN getinfo returned non-200 status"));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| error("CLN getinfo response read failed"))?
        {
            if body.len() + chunk.len() > 65_536 {
                return Err(error("CLN getinfo response is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let info: GetInfo =
            serde_json::from_slice(&body).map_err(|_| error("CLN getinfo response is invalid"))?;
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
        _amount_msat: u64,
        _description: &str,
        _expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        Err(error("not_supported: CLN preview invoice creation"))
    }
    async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
        Err(LightningError::PaymentNotDispatched(
            "not_supported: CLN preview payments".into(),
        ))
    }
    async fn get_payment_status(
        &self,
        _payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        Err(error("not_supported: CLN preview payment lookup"))
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Err(error("not_supported: CLN preview balance"))
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
