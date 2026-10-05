//! Opt-in hub LSPS2 service and its post-open forwarding tariff.

use konsensus_core::traits::lightning::LightningError;
use ldk_node::config::ChannelConfig;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Pilot service terms. Opening fees apply only to JIT funding, never admission.
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Lsps2ServiceConfig {
    pub enabled: bool,
    pub require_token: Option<String>,
    pub channel_opening_fee_ppm: u32,
    pub channel_over_provisioning_ppm: u32,
    pub min_channel_opening_fee_msat: u64,
    pub min_channel_lifetime: u32,
    pub max_client_to_self_delay: u32,
    pub min_payment_size_msat: u64,
    pub max_payment_size_msat: u64,
    pub funding_priority: konsensus_core::traits::lightning::FundingPriority,
    pub max_funding_fee_sats: u64,
    pub max_concurrent_jit_opens: u32,
    pub max_jit_capital_sats: u64,
    pub forwarding_fee_ppm: u32,
    pub forwarding_fee_base_msat: u32,
}

impl Default for Lsps2ServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_token: None,
            channel_opening_fee_ppm: 10_000,
            channel_over_provisioning_ppm: 1_000_000,
            min_channel_opening_fee_msat: 1_000_000,
            min_channel_lifetime: 144,
            max_client_to_self_delay: 2016,
            min_payment_size_msat: 10_000_000,
            max_payment_size_msat: 1_000_000_000,
            funding_priority: Default::default(),
            max_funding_fee_sats: 10_000,
            max_concurrent_jit_opens: 4,
            max_jit_capital_sats: 10_000_000,
            forwarding_fee_ppm: 500,
            forwarding_fee_base_msat: 1000,
        }
    }
}

impl std::fmt::Debug for Lsps2ServiceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lsps2ServiceConfig")
            .field("enabled", &self.enabled)
            .field(
                "require_token",
                &self.require_token.as_ref().map(|_| "[redacted]"),
            )
            .field("forwarding_fee_ppm", &self.forwarding_fee_ppm)
            .field("forwarding_fee_base_msat", &self.forwarding_fee_base_msat)
            .finish_non_exhaustive()
    }
}

impl Lsps2ServiceConfig {
    /// Validate before starting network work. Bound amounts/overprovisioning so
    /// the vendored service's u64 multiplication cannot overflow.
    pub fn to_ldk(
        &self,
        client_enabled: bool,
    ) -> Result<Option<ldk_node::liquidity::LSPS2ServiceConfig>, LightningError> {
        if !self.enabled {
            return Ok(None);
        }
        let invalid = |message: &str| {
            LightningError::InvalidStartupConfig(format!("lightning.lsps2_service: {message}"))
        };
        if client_enabled {
            return Err(invalid("mutually exclusive with liquidity.enabled"));
        }
        if self
            .require_token
            .as_ref()
            .is_none_or(|t| t.trim().is_empty())
        {
            return Err(invalid("enabled service requires a nonempty require_token"));
        }
        if self.channel_opening_fee_ppm >= 1_000_000
            || self.forwarding_fee_ppm > 1_000_000
            || self.channel_over_provisioning_ppm > 10_000_000
        {
            return Err(invalid("opening ppm must be < 1000000, forwarding ppm <= 1000000, overprovisioning ppm <= 10000000"));
        }
        if self.forwarding_fee_ppm == 0 && self.forwarding_fee_base_msat == 0 {
            return Err(invalid("forwarding tariff must not be 0 base / 0 ppm"));
        }
        if self.min_payment_size_msat == 0
            || self.min_payment_size_msat > self.max_payment_size_msat
            || self.max_payment_size_msat > 100_000_000_000
        {
            return Err(invalid(
                "payment range must satisfy 0 < min <= max <= 100000000000 msat",
            ));
        }
        if self.min_channel_opening_fee_msat >= self.min_payment_size_msat {
            return Err(invalid(
                "minimum opening fee must be less than minimum payment",
            ));
        }
        if self.min_channel_lifetime == 0
            || self.max_client_to_self_delay == 0
            || self.max_client_to_self_delay > u16::MAX.into()
        {
            return Err(invalid(
                "lifetime must be positive; client delay must be 1..=65535 blocks",
            ));
        }
        if !(1..=1024).contains(&self.max_concurrent_jit_opens)
            || self.max_jit_capital_sats == 0
            || self.max_jit_capital_sats > 2_100_000_000_000_000
            || self.max_funding_fee_sats == 0
            || self.max_funding_fee_sats > self.max_jit_capital_sats
        {
            return Err(invalid("concurrent JIT opens must be 1..=1024; 0 < funding fee cap <= capital cap <= Bitcoin supply"));
        }
        use konsensus_core::traits::lightning::FundingPriority;
        let funding_priority = match self.funding_priority {
            FundingPriority::Economy => ldk_node::funding::FundingPriority::Economy,
            FundingPriority::Normal => ldk_node::funding::FundingPriority::Normal,
            FundingPriority::Fast => ldk_node::funding::FundingPriority::Fast,
        };
        Ok(Some(ldk_node::liquidity::LSPS2ServiceConfig {
            funding_priority,
            max_funding_fee_sats: self.max_funding_fee_sats,
            max_concurrent_jit_opens: self.max_concurrent_jit_opens,
            max_jit_capital_sats: self.max_jit_capital_sats,
            require_token: self.require_token.clone(),
            advertise_service: false,
            channel_opening_fee_ppm: self.channel_opening_fee_ppm,
            channel_over_provisioning_ppm: self.channel_over_provisioning_ppm,
            min_channel_opening_fee_msat: self.min_channel_opening_fee_msat,
            min_channel_lifetime: self.min_channel_lifetime,
            max_client_to_self_delay: self.max_client_to_self_delay,
            min_payment_size_msat: self.min_payment_size_msat,
            max_payment_size_msat: self.max_payment_size_msat,
            // The existing client waits for funding broadcast before claiming.
            client_trusts_lsp: false,
        }))
    }

    fn tariff(
        &self,
        outbound: bool,
        announced: bool,
        ready: bool,
        confirmations_required: Option<u32>,
        mut config: ChannelConfig,
    ) -> Option<ChannelConfig> {
        // Preserve reconciliation for pre-patch private outbound zero-conf
        // service channels. Require their entire 0/0 signature so
        // ordinary confirmed channels with manually zeroed fees are untouched.
        if !self.enabled
            || !outbound
            || announced
            || !ready
            || confirmations_required != Some(0)
            || config.forwarding_fee_base_msat != 0
            || config.forwarding_fee_proportional_millionths != 0
        {
            return None;
        }
        config.forwarding_fee_base_msat = self.forwarding_fee_base_msat;
        config.forwarding_fee_proportional_millionths = self.forwarding_fee_ppm;
        Some(config)
    }

    /// Idempotent startup/event reconciliation. Existing nonzero tariffs and
    /// every other channel parameter are preserved. The drainer schedules retries.
    pub(crate) fn apply_tariffs(&self, node: &ldk_node::Node) -> Result<(), ldk_node::NodeError> {
        if !self.enabled {
            return Ok(());
        }
        for channel in node.list_channels() {
            if let Some(config) = self.tariff(
                channel.is_outbound,
                channel.is_announced,
                channel.is_channel_ready,
                channel.confirmations_required,
                channel.config,
            ) {
                node.update_channel_config(
                    &channel.user_channel_id,
                    channel.counterparty_node_id,
                    config,
                )?;
            }
        }
        Ok(())
    }
}

/// Export through the same process-wide recorder as the node's `/metrics`.
/// Counters use durable absolute totals; gauges reflect reserved exposure.
pub(crate) fn record_metrics(node: &ldk_node::Node) {
    let m = node.lsps2_service_metrics();
    metrics::counter!("konsensus_lsps2_opens_total").absolute(m.opens);
    metrics::counter!("konsensus_lsps2_opening_fees_earned_msat_total")
        .absolute(m.opening_fees_earned_msat);
    metrics::counter!("konsensus_lsps2_failed_opens_total").absolute(m.failed_opens);
    metrics::counter!("konsensus_lsps2_open_retries_total").absolute(m.open_retries);
    metrics::gauge!("konsensus_lsps2_capital_locked_sats").set(m.capital_locked_sats as f64);
    metrics::gauge!("konsensus_lsps2_pending_opens").set(m.pending_opens as f64);
}

/// Schedule reconciliation without holding the event queue on update failures.
/// A new ChannelReady must not bypass an already pending retry's backoff.
pub(crate) struct TariffRetry {
    next_attempt: Option<Instant>,
    delay: Duration,
}

impl TariffRetry {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            next_attempt: Some(now),
            delay: Duration::from_millis(250),
        }
    }

    pub(crate) fn request(&mut self, now: Instant) {
        self.next_attempt.get_or_insert(now);
    }

    pub(crate) fn apply_if_due(
        &mut self,
        now: Instant,
        apply: impl FnOnce() -> Result<(), ldk_node::NodeError>,
    ) {
        if self.next_attempt.is_none_or(|next| now < next) {
            return;
        }
        match apply() {
            Ok(()) => {
                self.next_attempt = None;
                self.delay = Duration::from_millis(250);
            }
            Err(error) => {
                metrics::counter!("konsensus_lsps2_tariff_retries_total").increment(1);
                let delay = self.delay;
                tracing::warn!(%error, retry_in_ms = delay.as_millis(),
                    "LDK: LSPS2 forwarding tariff update failed; continuing event delivery while retry is pending");
                self.next_attempt = Some(now + delay);
                self.delay = (delay * 2).min(Duration::from_secs(30));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled() -> Lsps2ServiceConfig {
        Lsps2ServiceConfig {
            enabled: true,
            require_token: Some("private-pilot".into()),
            ..Default::default()
        }
    }

    #[test]
    fn lsps2_metrics_use_existing_prometheus_recorder() {
        let recorder = metrics_exporter_prometheus::PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        let dir = tempfile::tempdir().unwrap();
        let mut builder = ldk_node::Builder::new();
        builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
        builder.set_entropy_seed_bytes([99; 64]);
        let node = builder.build_with_fs_store().unwrap();
        metrics::with_local_recorder(&recorder, || {
            record_metrics(&node);
            let mut retry = TariffRetry::new(Instant::now());
            retry.apply_if_due(Instant::now(), || {
                Err(ldk_node::NodeError::PersistenceFailed)
            });
        });
        let text = handle.render();
        for series in [
            "konsensus_lsps2_opens_total 0",
            "konsensus_lsps2_opening_fees_earned_msat_total 0",
            "konsensus_lsps2_failed_opens_total 0",
            "konsensus_lsps2_open_retries_total 0",
            "konsensus_lsps2_capital_locked_sats 0",
            "konsensus_lsps2_pending_opens 0",
            "konsensus_lsps2_tariff_retries_total 1",
        ] {
            assert!(text.contains(series), "missing {series}: {text}");
        }
    }

    #[test]
    fn lsps2_owner_open_policy_and_caps_are_validated() {
        let config: Lsps2ServiceConfig = serde_json::from_value(serde_json::json!({
            "enabled": true, "require_token": "pilot",
            "funding_priority": "economy", "max_funding_fee_sats": 2000,
            "max_concurrent_jit_opens": 2, "max_jit_capital_sats": 500000
        }))
        .expect("owner can set funding policy and exposure caps");
        assert!(config.to_ldk(false).is_ok());
        for (key, value) in [
            ("max_concurrent_jit_opens", 0),
            ("max_concurrent_jit_opens", 1025),
            ("max_jit_capital_sats", 0),
            ("max_funding_fee_sats", 0),
        ] {
            let mut json = serde_json::to_value(&config).unwrap();
            json[key] = value.into();
            let bad: Lsps2ServiceConfig = serde_json::from_value(json).unwrap();
            assert!(bad.to_ldk(false).is_err(), "accepted invalid {key}");
        }
    }

    #[test]
    fn lsps2_tariff_retry_backs_off_without_holding_event_delivery() {
        let mut now = Instant::now();
        let mut retry = TariffRetry::new(now);
        let mut attempts = 0;
        for delay_ms in [250, 500, 1000, 2000, 4000, 8000, 16000, 30000, 30000] {
            retry.apply_if_due(now, || {
                attempts += 1;
                Err(ldk_node::NodeError::PersistenceFailed)
            });
            // Event draining can continue as soon as this attempt returns.
            // Repeated ChannelReady events must not reset the pending delay.
            let before_due = now + Duration::from_millis(delay_ms - 1);
            retry.request(before_due);
            retry.apply_if_due(before_due, || panic!("retried before backoff elapsed"));
            now += Duration::from_millis(delay_ms);
        }
        assert_eq!(attempts, 9);
        let mut recovered = false;
        retry.apply_if_due(now, || {
            recovered = true;
            Ok(())
        });
        assert!(recovered, "retry must become due even at the backoff cap");
        retry.apply_if_due(now + Duration::from_secs(60), || {
            panic!("retried after success")
        });
    }

    #[test]
    fn lsps2_tariff_retry_resets_after_recovery_for_new_channels() {
        let now = Instant::now();
        let mut retry = TariffRetry::new(now);
        retry.apply_if_due(now, || Err(ldk_node::NodeError::PersistenceFailed));
        let now = now + Duration::from_millis(250);
        retry.apply_if_due(now, || Err(ldk_node::NodeError::PersistenceFailed));
        let now = now + Duration::from_millis(500);
        retry.apply_if_due(now, || Ok(()));
        retry.request(now);
        retry.apply_if_due(now, || Err(ldk_node::NodeError::PersistenceFailed));
        retry.apply_if_due(now + Duration::from_millis(249), || {
            panic!("retried too soon")
        });
        let mut recovered = false;
        retry.apply_if_due(now + Duration::from_millis(250), || {
            recovered = true;
            Ok(())
        });
        assert!(
            recovered,
            "a new channel must start with the initial backoff"
        );
    }

    #[test]
    fn lsps2_service_defaults_disabled_and_hides_token() {
        assert!(Lsps2ServiceConfig::default()
            .to_ldk(false)
            .unwrap()
            .is_none());
        let config = enabled();
        let ldk = config.to_ldk(false).unwrap().unwrap();
        assert!(!ldk.advertise_service);
        assert!(!ldk.client_trusts_lsp);
        assert_eq!(ldk.require_token.as_deref(), Some("private-pilot"));
        assert_eq!(ldk.channel_over_provisioning_ppm, 1_000_000);
        assert!(!format!("{config:?}").contains("private-pilot"));
    }

    #[test]
    fn lsps2_service_rejects_invalid_startup_terms() {
        assert!(enabled().to_ldk(true).is_err());
        let cases: Vec<Lsps2ServiceConfig> = vec![
            Lsps2ServiceConfig {
                require_token: None,
                ..enabled()
            },
            Lsps2ServiceConfig {
                require_token: Some(" ".into()),
                ..enabled()
            },
            Lsps2ServiceConfig {
                channel_opening_fee_ppm: 1_000_000,
                ..enabled()
            },
            Lsps2ServiceConfig {
                channel_over_provisioning_ppm: 10_000_001,
                ..enabled()
            },
            Lsps2ServiceConfig {
                forwarding_fee_ppm: 1_000_001,
                ..enabled()
            },
            Lsps2ServiceConfig {
                forwarding_fee_ppm: 0,
                forwarding_fee_base_msat: 0,
                ..enabled()
            },
            Lsps2ServiceConfig {
                min_payment_size_msat: 0,
                ..enabled()
            },
            Lsps2ServiceConfig {
                max_payment_size_msat: 1,
                ..enabled()
            },
            Lsps2ServiceConfig {
                max_payment_size_msat: u64::MAX,
                ..enabled()
            },
            Lsps2ServiceConfig {
                min_channel_opening_fee_msat: 10_000_000,
                ..enabled()
            },
            Lsps2ServiceConfig {
                min_channel_lifetime: 0,
                ..enabled()
            },
            Lsps2ServiceConfig {
                max_client_to_self_delay: 0,
                ..enabled()
            },
        ];
        for config in cases {
            assert!(config.to_ldk(false).is_err(), "{config:?}");
        }
    }

    #[test]
    fn lsps2_service_tariff_leaves_ordinary_default_channel_untouched() {
        let config = ChannelConfig::default();
        assert_eq!(config.forwarding_fee_base_msat, 1000);
        assert_eq!(config.forwarding_fee_proportional_millionths, 0);
        for confirmations in [Some(0), Some(6), None] {
            assert!(enabled()
                .tariff(true, false, true, confirmations, config)
                .is_none());
        }
    }

    #[test]
    fn lsps2_service_tariff_leaves_confirmed_free_channel_untouched() {
        let config = ChannelConfig {
            forwarding_fee_base_msat: 0,
            forwarding_fee_proportional_millionths: 0,
            ..Default::default()
        };
        for confirmations in [Some(1), Some(6), None] {
            assert!(enabled()
                .tariff(true, false, true, confirmations, config)
                .is_none());
        }
    }

    #[test]
    fn lsps2_service_tariff_preserves_other_channel_settings() {
        let service = enabled();
        let original = ldk_node::config::ChannelConfig {
            forwarding_fee_base_msat: 0,
            forwarding_fee_proportional_millionths: 0,
            cltv_expiry_delta: 144,
            ..Default::default()
        };
        let changed = service
            .tariff(true, false, true, Some(0), original)
            .unwrap();
        assert_eq!(changed.cltv_expiry_delta, 144);
        assert_eq!(
            changed.forwarding_fee_base_msat,
            service.forwarding_fee_base_msat
        );
        assert_eq!(
            changed.forwarding_fee_proportional_millionths,
            service.forwarding_fee_ppm
        );
        assert!(service
            .tariff(true, false, true, Some(0), changed)
            .is_none());
        assert!(service
            .tariff(false, false, true, Some(0), original)
            .is_none());
        assert!(service
            .tariff(true, true, true, Some(0), original)
            .is_none());
        assert!(service
            .tariff(true, false, false, Some(0), original)
            .is_none());
        assert!(Lsps2ServiceConfig::default()
            .tariff(true, false, true, Some(0), original)
            .is_none());
    }
}
