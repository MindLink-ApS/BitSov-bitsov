//! Owner-only, decision-neutral tower coverage diagnostics.
use serde::Serialize;
use std::sync::Mutex;

#[derive(Clone, Debug, Default, Serialize)]
pub struct TowerStatus {
    pub enabled: bool,
    pub available: bool,
    /// W2a never sends, pays, or changes channel admission policy.
    pub transport_enabled: bool,
    /// Coverage counts concern pre-signed to_local justice only, never HTLCs.
    pub channels: Vec<TowerChannelStatus>,
    pub warnings: Vec<TowerWarning>,
    /// A storage/worker failure must never look like an empty healthy snapshot.
    pub error: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TowerChannelStatus {
    pub channel_id: String,
    pub total_states: usize,
    /// At least one non-counterparty tower acknowledged this state.
    pub guarded_states: usize,
    pub unguarded_states: usize,
    pub unsigned_pending: usize,
    pub signed_candidates: usize,
    pub deferred_signed: usize,
    pub quarantined_pending: usize,
    pub quarantined_candidates: usize,
    pub retired_records: usize,
    pub coverage_gap: bool,
    pub at_capacity: bool,
    pub skipped_counterparty_towers: usize,
    pub towers: Vec<TowerDeliveryStatus>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TowerDeliveryStatus {
    pub node_id: String,
    pub queued: usize,
    pub sent: usize,
    pub acked: usize,
    pub expired: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct TowerWarning {
    pub timestamp: u64,
    pub message: String,
}

static WARNINGS: Mutex<Vec<TowerWarning>> = Mutex::new(Vec::new());

/// Log bridge sink. Bounded process-local history; durable W1 record counts are
/// separately reported across restarts. No blob, key, or wallet data belongs here.
pub fn record_warning(message: &str) {
    let mut warnings = WARNINGS.lock().unwrap();
    if warnings.len() == 64 {
        warnings.remove(0);
    }
    warnings.push(TowerWarning {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        message: message.chars().take(1024).collect(),
    });
}

pub fn warnings() -> Vec<TowerWarning> {
    WARNINGS.lock().unwrap().clone()
}
