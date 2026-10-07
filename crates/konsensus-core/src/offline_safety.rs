//! Amount-free, node-local offline safety diagnostics.

use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncedBlock {
    pub height: u64,
    pub unix_secs: u64,
}

pub type SharedOfflineSafety = Arc<RwLock<OfflineSafetyStatus>>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Warning,
    Critical,
}

/// The delay we selected for the counterparty's commitment, not our spend delay.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelWindow {
    pub channel_id: String,
    pub window_blocks: Option<u16>,
}

/// Local LDK data, readable even when money operations are gated off.
pub struct OfflineChainState {
    /// Only present after successful synchronization in this running instance.
    pub last_sync: Option<SyncedBlock>,
    pub channels: Vec<ChannelWindow>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelAlert {
    pub channel_id: String,
    pub window_blocks: Option<u16>,
    pub percentage: Option<f64>,
    pub severity: Option<Severity>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OfflineReport {
    pub blocks_offline: Option<u64>,
    pub smallest_window_blocks: Option<u16>,
    pub percentage: Option<f64>,
    pub severity: Option<Severity>,
    /// True when elapsed wall time at 600 seconds/block exceeds observed lag.
    pub estimated: bool,
    /// False when heartbeat history or a delay is unknown, or channel data is cached.
    pub coverage_complete: bool,
    pub channels: Vec<ChannelAlert>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct OfflineSafetyStatus {
    #[serde(flatten)]
    pub current: OfflineReport,
    /// Retained until process exit so catch-up cannot hide the startup warning.
    pub startup_alert: Option<OfflineReport>,
    pub history_available_on_start: bool,
    pub heartbeat_error: Option<String>,
}
