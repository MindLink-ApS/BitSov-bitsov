//! Funding-only LSPS2 bootstrap. Quotes confer no communication admission.
use serde::{Deserialize, Serialize};

/// Public configuration state; never includes provider authentication tokens.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LiquidityInfo {
    pub enabled: bool,
    pub providers: Vec<String>,
    pub selected_provider: Option<String>,
}

/// Private invoice terms. The payable invoice is released only after fee authority.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LiquidityQuote {
    pub quote_id: String,
    pub provider: String,
    pub gross_msat: u64,
    pub max_fee_msat: u64,
    pub min_net_msat: u64,
    pub expires_at: u64,
}

/// Settled JIT receipts report the actual deduction separately from net received.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityReceipt {
    pub net_received_msat: u64,
    pub lsp_fee_msat: u64,
    pub gross_msat: u64,
}
