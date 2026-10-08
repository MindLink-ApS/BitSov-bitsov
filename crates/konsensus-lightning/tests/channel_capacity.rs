//! Real embedded backend, unfunded/unstarted nodes: no sockets or chain service needed.
use konsensus_core::traits::lightning::{LightningError, LightningProvider};
use konsensus_lightning::LdkProvider;
use std::sync::Arc;

#[tokio::test]
async fn real_ldk_capacity_refusals_retain_codes_through_provider() {
    for (per_channel, total, amount, code) in [
        (100_000, 200_000, 100_001, "CHANNEL_CAPACITY_EXCEEDED"),
        (100_000, 99_999, 100_000, "TOTAL_CHANNEL_CAPACITY_EXCEEDED"),
        (0, 0, 1, "CHANNEL_CAPACITY_EXCEEDED"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = ldk_node::Builder::from_config(ldk_node::config::Config {
            channel_limits: Some(ldk_node::channel_limits::ChannelLimits::new(
                per_channel,
                total,
            )),
            channel_peer_allowlist: Some(vec![
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    .parse()
                    .unwrap(),
            ]),
            ..Default::default()
        });
        builder.set_network(bitcoin::Network::Regtest);
        builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
        builder.set_entropy_seed_bytes([43; 64]);
        let node = Arc::new(builder.build().unwrap());
        let provider = LdkProvider::from_node(node.clone());
        let peer = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        for result in [
            provider
                .open_channel(peer, "127.0.0.1:9", amount, false, None)
                .await
                .map(|_| ()),
            provider
                .open_channel_with_status(peer, "127.0.0.1:9", amount, false, None)
                .await
                .map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(LightningError::PaymentNotDispatched(ref reason)) if reason == code),
                "{result:?}"
            );
        }
        assert!(node.list_channels().is_empty());
        let status = serde_json::to_value(provider.channel_safety().unwrap()).unwrap();
        assert_eq!(status["max_channel_capacity_sats"], per_channel);
        assert_eq!(status["max_total_channel_capacity_sats"], total);
        assert_eq!(status["hub_only"], true);
    }
}
