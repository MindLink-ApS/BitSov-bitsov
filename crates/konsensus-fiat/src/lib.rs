//! konsensus-fiat — Fiat exchange-rate abstraction for BitSov.
//!
//! This crate provides:
//!
//! - [`FiatCurrency`] — ISO 4217 fiat currencies supported by the network.
//! - [`RateSource`] — identifies which upstream data source produced a quote.
//! - [`RateQuote`] — a timestamped BTC/fiat exchange rate from one source.
//! - [`FiatRateProvider`] — async trait implemented by each rate backend.
//!
//! # Design notes
//!
//! Rates are consumed by `konsensus-pricing` to display sats amounts in the
//! user's local currency.  They are **never** used to gate or price messages —
//! the Lightning gate operates in sats only (Principle 2).
//!
//! Multiple providers can be composed (median aggregation, failover) by the
//! caller; this crate only defines the primitive contract.

#![forbid(unsafe_code)]

pub mod providers;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// FiatCurrency
// ---------------------------------------------------------------------------

/// ISO 4217 fiat currencies supported by the network.
///
/// Additional variants can be added without breaking existing providers — a
/// provider that does not support a requested currency returns
/// [`FiatError::UnsupportedCurrency`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[non_exhaustive]
pub enum FiatCurrency {
    /// United States Dollar
    Usd,
    /// Euro
    Eur,
    /// British Pound Sterling
    Gbp,
    /// Japanese Yen
    Jpy,
    /// Swiss Franc
    Chf,
    /// Canadian Dollar
    Cad,
    /// Australian Dollar
    Aud,
    /// Danish Krone
    Dkk,
    /// Norwegian Krone
    Nok,
    /// Swedish Krona
    Sek,
}

impl std::fmt::Display for FiatCurrency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FiatCurrency::Usd => "USD",
            FiatCurrency::Eur => "EUR",
            FiatCurrency::Gbp => "GBP",
            FiatCurrency::Jpy => "JPY",
            FiatCurrency::Chf => "CHF",
            FiatCurrency::Cad => "CAD",
            FiatCurrency::Aud => "AUD",
            FiatCurrency::Dkk => "DKK",
            FiatCurrency::Nok => "NOK",
            FiatCurrency::Sek => "SEK",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// RateSource
// ---------------------------------------------------------------------------

/// Identifies the upstream data source that produced a [`RateQuote`].
///
/// Using a typed enum (rather than a raw string) lets callers implement
/// source-specific trust weights or failover policies without stringly-typed
/// matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RateSource {
    /// CoinGecko public price API.
    CoinGecko,
    /// Kraken spot ticker.
    Kraken,
    /// Mempool.space price endpoint (sats-native, Bitcoin-focused).
    MempoolSpace,
    /// Any other source identified by a free-form label.
    Other(String),
}

impl std::fmt::Display for RateSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateSource::CoinGecko => f.write_str("CoinGecko"),
            RateSource::Kraken => f.write_str("Kraken"),
            RateSource::MempoolSpace => f.write_str("MempoolSpace"),
            RateSource::Other(s) => write!(f, "Other({})", s),
        }
    }
}

// ---------------------------------------------------------------------------
// RateQuote
// ---------------------------------------------------------------------------

/// A timestamped BTC/fiat exchange rate from a single source.
///
/// The rate is expressed as **fiat units per 1 BTC** (e.g. `96_500.00` for
/// USD/BTC at $96,500).  Callers convert to sats by dividing by 1e8.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RateQuote {
    /// The fiat currency of this quote.
    pub currency: FiatCurrency,
    /// Fiat units per 1 BTC (always positive).
    pub rate: f64,
    /// When this quote was fetched from the upstream source (UTC).
    pub fetched_at: DateTime<Utc>,
    /// Which provider produced this quote.
    pub source: RateSource,
}

impl RateQuote {
    /// Returns how many satoshis correspond to `fiat_amount` in this quote's
    /// currency.
    ///
    /// Returns `None` if the rate is zero or negative (data integrity guard).
    #[must_use]
    pub fn fiat_to_sats(&self, fiat_amount: f64) -> Option<u64> {
        if self.rate <= 0.0 {
            return None;
        }
        let btc = fiat_amount / self.rate;
        let sats = (btc * 1e8).round();
        if sats < 0.0 {
            return None;
        }
        Some(sats as u64)
    }

    /// Returns the fiat value of `sats` satoshis using this quote.
    #[must_use]
    pub fn sats_to_fiat(&self, sats: u64) -> f64 {
        let btc = sats as f64 / 1e8;
        btc * self.rate
    }
}

// ---------------------------------------------------------------------------
// FiatError
// ---------------------------------------------------------------------------

/// Errors returned by [`FiatRateProvider`] implementations.
#[derive(Debug, Error)]
pub enum FiatError {
    /// The provider does not support the requested currency.
    #[error("unsupported currency: {0}")]
    UnsupportedCurrency(FiatCurrency),

    /// A network or HTTP error occurred while fetching the rate.
    #[error("network error: {0}")]
    Network(String),

    /// The upstream response could not be parsed.
    #[error("parse error: {0}")]
    Parse(String),

    /// The provider is temporarily rate-limited.
    #[error("rate limited by upstream provider")]
    RateLimited,

    /// Any other provider-specific error.
    #[error("provider error: {0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// FiatRateProvider
// ---------------------------------------------------------------------------

/// Async trait implemented by every fiat exchange-rate backend.
///
/// Implementors live in the [`providers`] module.  Callers (e.g.
/// `konsensus-pricing`) depend only on this trait, enabling easy swapping and
/// aggregation of providers.
#[async_trait]
pub trait FiatRateProvider: Send + Sync + 'static {
    /// A short human-readable name for this provider (e.g. `"CoinGecko"`).
    fn name(&self) -> &str;

    /// The set of currencies this provider can quote.
    fn supported_currencies(&self) -> &[FiatCurrency];

    /// Fetch the current BTC/`currency` rate.
    ///
    /// # Errors
    ///
    /// Returns [`FiatError::UnsupportedCurrency`] if the provider cannot
    /// quote the requested currency without a network call.  Providers that
    /// discover unsupported currencies only at fetch time may also return
    /// this error from here.
    async fn fetch_rate(&self, currency: FiatCurrency) -> Result<RateQuote, FiatError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn usd_quote(rate: f64) -> RateQuote {
        RateQuote {
            currency: FiatCurrency::Usd,
            rate,
            fetched_at: Utc::now(),
            source: RateSource::CoinGecko,
        }
    }

    #[test]
    fn fiat_to_sats_round_trip() {
        let q = usd_quote(100_000.0); // 1 BTC = $100k
        let sats = q.fiat_to_sats(1.0).unwrap(); // $1 → 1000 sats
        assert_eq!(sats, 1_000);
    }

    #[test]
    fn sats_to_fiat_round_trip() {
        let q = usd_quote(100_000.0);
        let fiat = q.sats_to_fiat(1_000);
        assert!((fiat - 1.0).abs() < 1e-9);
    }

    #[test]
    fn fiat_to_sats_zero_rate_returns_none() {
        let q = usd_quote(0.0);
        assert!(q.fiat_to_sats(10.0).is_none());
    }

    #[test]
    fn currency_display() {
        assert_eq!(FiatCurrency::Eur.to_string(), "EUR");
        assert_eq!(FiatCurrency::Usd.to_string(), "USD");
    }

    #[test]
    fn source_display() {
        assert_eq!(RateSource::Kraken.to_string(), "Kraken");
        assert_eq!(RateSource::Other("foo".into()).to_string(), "Other(foo)");
    }
}
