//! MempoolSpace fiat rate provider.
//!
//! Fetches BTC/fiat rates from the mempool.space price endpoint:
//! `GET https://mempool.space/api/v1/prices`
//!
//! The endpoint returns a flat JSON object with uppercase ISO 4217 currency
//! codes as keys and BTC prices (float) as values:
//! ```json
//! {"USD": 96500, "EUR": 88000, "GBP": 76000, ...}
//! ```

use std::collections::HashMap;

use async_trait::async_trait;
use tracing::warn;

use crate::{FiatCurrency, FiatError, FiatRateProvider, RateQuote, RateSource};

/// HTTP client wrapping the mempool.space price API.
///
/// Supports all ten [`FiatCurrency`] variants.  Any currency not present in
/// the upstream response yields [`FiatError::UnsupportedCurrency`] -- this can
/// happen if mempool.space drops a currency or the node is air-gapped.
pub struct MempoolSpaceProvider {
    client: reqwest::Client,
    url: String,
    currencies: Vec<FiatCurrency>,
}

impl MempoolSpaceProvider {
    /// Create a new provider targeting the live mempool.space endpoint.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client build cannot fail with valid config"),
            url: "https://mempool.space/api/v1/prices".to_string(),
            currencies: vec![
                FiatCurrency::Usd,
                FiatCurrency::Eur,
                FiatCurrency::Gbp,
                FiatCurrency::Jpy,
                FiatCurrency::Chf,
                FiatCurrency::Cad,
                FiatCurrency::Aud,
                FiatCurrency::Dkk,
                FiatCurrency::Nok,
                FiatCurrency::Sek,
            ],
        }
    }

    /// Create a provider with a custom endpoint URL (for testing).
    #[cfg(test)]
    pub fn with_url(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            ..Self::new()
        }
    }
}

impl Default for MempoolSpaceProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl FiatRateProvider for MempoolSpaceProvider {
    fn name(&self) -> &str {
        "MempoolSpace"
    }

    fn supported_currencies(&self) -> &[FiatCurrency] {
        &self.currencies
    }

    async fn fetch_rate(&self, currency: FiatCurrency) -> Result<RateQuote, FiatError> {
        let fetched_at = chrono::Utc::now();

        let response: HashMap<String, serde_json::Value> = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    FiatError::Network(format!("timeout contacting mempool.space: {e}"))
                } else if e.status().is_some_and(|s| s.as_u16() == 429) {
                    FiatError::RateLimited
                } else {
                    FiatError::Network(e.to_string())
                }
            })?
            .error_for_status()
            .map_err(|e| {
                if e.status().is_some_and(|s| s.as_u16() == 429) {
                    FiatError::RateLimited
                } else {
                    FiatError::Network(format!("HTTP error from mempool.space: {e}"))
                }
            })?
            .json()
            .await
            .map_err(|e| FiatError::Parse(format!("failed to parse mempool.space response: {e}")))?;

        let key = currency.to_string();
        let rate = response
            .get(&key)
            .and_then(|v| v.as_f64())
            .ok_or_else(|| {
                warn!(
                    currency = %key,
                    "mempool.space response did not include a rate for this currency"
                );
                FiatError::UnsupportedCurrency(currency)
            })?;

        if rate <= 0.0 {
            return Err(FiatError::Parse(format!(
                "mempool.space returned non-positive rate {rate} for {key}"
            )));
        }

        Ok(RateQuote {
            currency,
            rate,
            fetched_at,
            source: RateSource::MempoolSpace,
        })
    }
}
