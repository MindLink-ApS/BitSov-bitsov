//! Opt-in hub LSPS2 service and its post-open forwarding tariff.

use konsensus_core::traits::lightning::LightningError;
use ldk_node::config::ChannelConfig;
use serde::{Deserialize, Serialize};

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
        Ok(Some(ldk_node::liquidity::LSPS2ServiceConfig {
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
        mut config: ChannelConfig,
    ) -> Option<ChannelConfig> {
        // LDK 0.7 exposes no JIT-origin marker. Its service creates private,
        // outbound 0/0 channels; normal BitSov opens use a nonzero base fee.
        if !self.enabled
            || !outbound
            || announced
            || !ready
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
    /// every other channel parameter are preserved. Retry failures before ack.
    pub(crate) fn apply_tariffs(&self, node: &ldk_node::Node) -> Result<(), ldk_node::NodeError> {
        if !self.enabled {
            return Ok(());
        }
        for channel in node.list_channels() {
            if let Some(config) = self.tariff(
                channel.is_outbound,
                channel.is_announced,
                channel.is_channel_ready,
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
    fn lsps2_service_tariff_preserves_other_channel_settings() {
        let service = enabled();
        let original = ldk_node::config::ChannelConfig {
            forwarding_fee_base_msat: 0,
            forwarding_fee_proportional_millionths: 0,
            cltv_expiry_delta: 144,
            ..Default::default()
        };
        let changed = service.tariff(true, false, true, original).unwrap();
        assert_eq!(changed.cltv_expiry_delta, 144);
        assert_eq!(
            changed.forwarding_fee_base_msat,
            service.forwarding_fee_base_msat
        );
        assert_eq!(
            changed.forwarding_fee_proportional_millionths,
            service.forwarding_fee_ppm
        );
        assert!(service.tariff(true, false, true, changed).is_none());
        assert!(service.tariff(false, false, true, original).is_none());
        assert!(service.tariff(true, true, true, original).is_none());
        assert!(service.tariff(true, false, false, original).is_none());
        assert!(Lsps2ServiceConfig::default()
            .tariff(true, false, true, original)
            .is_none());
    }
}
