//! A bounded, private invoice preview around LDK's lightning-liquidity client.
//! Negotiating is not payment: no BOLT11 leaves this store before fee authority.
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use konsensus_core::traits::lightning::{Invoice, LightningError};
use konsensus_core::traits::liquidity::{LiquidityInfo, LiquidityQuote};
use serde::{Deserialize, Serialize};

pub const QUOTE_TTL_SECS: u32 = 120;
const MAX_QUOTES: usize = 16;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LspConfig {
    pub node_id: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

// Keep credentials out of diagnostics, including nested and pretty Debug output.
impl std::fmt::Debug for LspConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LspConfig")
            .field("node_id", &self.node_id)
            .field("address", &self.address)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// One active peer per LDK Node 0.7 instance. Switching is explicit at startup,
/// retaining the same wallet/channels; this is not automatic failover.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidityConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub providers: Vec<LspConfig>,
    pub selected_provider: Option<String>,
}

impl LiquidityConfig {
    pub fn selected(&self) -> Result<Option<&LspConfig>, LightningError> {
        let mut seen = HashSet::new();
        if self.providers.len() > 16 {
            return Err(invalid("at most 16 LSPs"));
        }
        for p in &self.providers {
            let key = p
                .node_id
                .parse::<ldk_node::bitcoin::secp256k1::PublicKey>()
                .map_err(|_| invalid("invalid LSP public key"))?;
            p.address
                .parse::<ldk_node::lightning::ln::msgs::SocketAddress>()
                .map_err(|_| invalid("invalid LSP address"))?;
            if key.to_string() != p.node_id || !seen.insert(key) {
                return Err(invalid("LSP keys must be canonical and unique"));
            }
        }
        let selected = self
            .selected_provider
            .as_ref()
            .map(|id| {
                self.providers
                    .iter()
                    .find(|p| &p.node_id == id)
                    .ok_or_else(|| invalid("selected LSP is not configured"))
            })
            .transpose()?;
        if self.enabled && selected.is_none() {
            return Err(invalid("enabled liquidity needs a selected LSP"));
        }
        Ok(if self.enabled { selected } else { None })
    }

    pub fn info(&self) -> LiquidityInfo {
        LiquidityInfo {
            enabled: self.enabled,
            providers: self.providers.iter().map(|p| p.node_id.clone()).collect(),
            selected_provider: self.selected_provider.clone(),
        }
    }
}

fn invalid(message: &str) -> LightningError {
    LightningError::Backend(message.into())
}
fn unavailable() -> LightningError {
    LightningError::PaymentNotDispatched(
        "liquidity quote absent, expired, consumed or belongs to another caller".into(),
    )
}
pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Mockable LSP boundary. The production backend runs LDK's LSPS2 get_info/buy
/// exchange and durably records Bolt11Jit before returning this private invoice.
#[async_trait]
pub trait JitBackend: Send + Sync {
    async fn prepare(
        &self,
        gross_msat: u64,
        max_fee_msat: u64,
        expiry_secs: u32,
    ) -> Result<(Invoice, u64), LightningError>;
}

struct Prepared {
    owner: String,
    terms: LiquidityQuote,
    invoice: Invoice,
}

pub struct LiquidityClient {
    provider: String,
    backend: Arc<dyn JitBackend>,
    quotes: Mutex<HashMap<String, Prepared>>,
    // One detached LDK negotiation at a time, including if the HTTP caller goes away.
    negotiation: Arc<tokio::sync::Semaphore>,
}

impl LiquidityClient {
    pub fn new(provider: String, backend: Arc<dyn JitBackend>) -> Self {
        Self {
            provider,
            backend,
            quotes: Mutex::new(HashMap::new()),
            negotiation: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    pub async fn quote(
        &self,
        owner: &str,
        gross_msat: u64,
        max_fee_msat: u64,
    ) -> Result<LiquidityQuote, LightningError> {
        if gross_msat == 0 || gross_msat > 100_000_000_000 || max_fee_msat >= gross_msat {
            return Err(invalid(
                "funding must be 1..100000000000 msat and the fee cap below gross",
            ));
        }
        let permit = Arc::clone(&self.negotiation)
            .try_acquire_owned()
            .map_err(|_| invalid("LSP negotiation already in progress"))?;
        {
            let mut quotes = self
                .quotes
                .lock()
                .map_err(|_| invalid("quote store unavailable"))?;
            quotes.retain(|_, q| q.terms.expires_at > now());
            if quotes.len() >= MAX_QUOTES {
                return Err(invalid("too many outstanding liquidity quotes"));
            }
        }
        // Keep the permit inside this task until backend completion on cancellation.
        let backend = Arc::clone(&self.backend);
        let (invoice, fee) = tokio::spawn(async move {
            let _permit = permit;
            backend
                .prepare(gross_msat, max_fee_msat, QUOTE_TTL_SECS)
                .await
        })
        .await
        .map_err(|_| invalid("LSP negotiation task failed"))??;
        if invoice.amount_msat != gross_msat || fee > max_fee_msat || fee >= gross_msat {
            return Err(invalid("LSP returned terms outside the requested bounds"));
        }
        let expiry = invoice
            .created_at
            .checked_add(u64::from(invoice.expiry_secs))
            .ok_or_else(|| invalid("invalid invoice expiry"))?;
        if expiry <= now() || invoice.expiry_secs > QUOTE_TTL_SECS {
            return Err(unavailable());
        }
        let id = hex::encode(rand::random::<[u8; 32]>());
        let terms = LiquidityQuote {
            quote_id: id.clone(),
            provider: self.provider.clone(),
            gross_msat,
            max_fee_msat: fee,
            min_net_msat: gross_msat - fee,
            expires_at: expiry,
        };
        let mut quotes = self
            .quotes
            .lock()
            .map_err(|_| invalid("quote store unavailable"))?;
        if quotes.len() >= MAX_QUOTES {
            return Err(invalid("too many outstanding liquidity quotes"));
        }
        quotes.insert(
            id,
            Prepared {
                owner: owner.into(),
                terms: terms.clone(),
                invoice,
            },
        );
        Ok(terms)
    }

    pub fn terms(&self, owner: &str, id: &str) -> Result<LiquidityQuote, LightningError> {
        let quotes = self
            .quotes
            .lock()
            .map_err(|_| invalid("quote store unavailable"))?;
        let prepared = quotes
            .get(id)
            .filter(|p| p.owner == owner && p.terms.expires_at > now())
            .ok_or_else(unavailable)?;
        Ok(prepared.terms.clone())
    }

    /// Synchronous publication: caller's G1 guard covers the complete operation.
    pub fn accept(&self, owner: &str, id: &str) -> Result<Invoice, LightningError> {
        let mut quotes = self
            .quotes
            .lock()
            .map_err(|_| invalid("quote store unavailable"))?;
        quotes
            .get(id)
            .filter(|p| p.owner == owner && p.terms.expires_at > now())
            .ok_or_else(unavailable)?;
        Ok(quotes.remove(id).ok_or_else(unavailable)?.invoice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldk_node::lightning_liquidity::lsps2::utils::compute_opening_fee;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct MockLsp {
        fee: u64,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl JitBackend for MockLsp {
        async fn prepare(
            &self,
            gross: u64,
            _cap: u64,
            ttl: u32,
        ) -> Result<(Invoice, u64), LightningError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok((
                Invoice {
                    bolt11: "private-payable-invoice".into(),
                    payment_hash: "ab".repeat(32),
                    amount_msat: gross,
                    description: "BitSov wallet funding".into(),
                    expiry_secs: ttl,
                    created_at: now(),
                },
                compute_opening_fee(gross, self.fee, 0).unwrap(),
            ))
        }
    }
    fn fixture(fee: u64) -> (LiquidityClient, Arc<MockLsp>) {
        let lsp = Arc::new(MockLsp {
            fee,
            calls: AtomicUsize::new(0),
        });
        (LiquidityClient::new("provider-a".into(), lsp.clone()), lsp)
    }
    #[tokio::test]
    async fn preview_has_exact_gross_fee_net_but_no_invoice_and_accepts_once() {
        let (client, lsp) = fixture(2_000);
        let q = client.quote("alice", 100_000, 2_000).await.unwrap();
        assert_eq!(
            (q.gross_msat, q.max_fee_msat, q.min_net_msat),
            (100_000, 2_000, 98_000)
        );
        assert!(!serde_json::to_string(&q)
            .unwrap()
            .contains("private-payable"));
        assert!(client.accept("bob", &q.quote_id).is_err());
        assert_eq!(
            client.accept("alice", &q.quote_id).unwrap().bolt11,
            "private-payable-invoice"
        );
        assert!(client.accept("alice", &q.quote_id).is_err());
        assert_eq!(lsp.calls.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn malicious_above_cap_offer_never_publishes_an_invoice() {
        let (client, _) = fixture(2_001);
        assert!(client.quote("alice", 100_000, 2_000).await.is_err());
        assert!(client.quotes.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn amount_validation_happens_before_contacting_lsp() {
        let (client, lsp) = fixture(1);
        for (gross, fee) in [(0, 0), (1, 1), (100_000_000_001, 1)] {
            assert!(client.quote("alice", gross, fee).await.is_err());
        }
        assert_eq!(lsp.calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn expired_quote_and_restart_cannot_republish_invoice() {
        let (client, _) = fixture(1);
        let q = client.quote("alice", 1_000, 10).await.unwrap();
        client
            .quotes
            .lock()
            .unwrap()
            .get_mut(&q.quote_id)
            .unwrap()
            .terms
            .expires_at = now();
        assert!(client.terms("alice", &q.quote_id).is_err());
        assert!(client.accept("alice", &q.quote_id).is_err());
        let (restarted, _) = fixture(1);
        assert!(restarted.accept("alice", &q.quote_id).is_err());
    }
    #[tokio::test]
    async fn bounded_quote_store_and_concurrent_acceptance() {
        let (client, lsp) = fixture(1);
        let client = Arc::new(client);
        for _ in 0..MAX_QUOTES {
            client.quote("alice", 1_000, 10).await.unwrap();
        }
        assert!(client.quote("alice", 1_000, 10).await.is_err());
        assert_eq!(lsp.calls.load(Ordering::SeqCst), MAX_QUOTES);
        let id = client.quotes.lock().unwrap().keys().next().unwrap().clone();
        let a = Arc::clone(&client);
        let b = Arc::clone(&client);
        let id_b = id.clone();
        let (a, b) = tokio::join!(
            tokio::spawn(async move { a.accept("alice", &id) }),
            tokio::spawn(async move { b.accept("alice", &id_b) })
        );
        assert_ne!(a.unwrap().is_ok(), b.unwrap().is_ok());
    }
    #[test]
    fn provider_registry_is_off_by_default_and_requires_explicit_valid_selection() {
        assert!(LiquidityConfig::default().selected().unwrap().is_none());
        let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let mut config = LiquidityConfig {
            enabled: true,
            providers: vec![LspConfig {
                node_id: key.into(),
                address: "127.0.0.1:9735".into(),
                token: None,
            }],
            selected_provider: None,
        };
        assert!(config.selected().is_err());
        config.selected_provider = Some(key.into());
        assert_eq!(config.selected().unwrap().unwrap().node_id, key);
        config.providers.push(config.providers[0].clone());
        assert!(config.selected().is_err());
    }
}
