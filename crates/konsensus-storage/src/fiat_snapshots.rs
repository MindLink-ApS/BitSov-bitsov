//! Daily fiat exchange-rate snapshot model.
//!
//! One record per `(date, currency)`, written at 00:00 UTC by the background
//! snapshot task and read by the tax-export handler.

use serde::{Deserialize, Serialize};

/// A persisted daily fiat exchange-rate snapshot.
///
/// Written once per day at 00:00 UTC for every currency the configured
/// provider supports.  Upsert semantics (keyed on `(date, currency)`)
/// ensure that repeated writes for the same day are idempotent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FiatRateSnapshot {
    /// ISO-8601 date, e.g. `"2026-04-21"`.
    pub date: String,
    /// ISO 4217 currency code, e.g. `"USD"`.
    pub currency: String,
    /// Fiat units per 1 BTC (always positive).
    pub rate: f64,
    /// Short name of the upstream provider, e.g. `"MempoolSpace"`.
    pub source: String,
    /// ISO-8601 creation timestamp (set by the DB default on first insert).
    pub created_at: String,
}
