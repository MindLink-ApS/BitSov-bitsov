use konsensus_core::traits::lightning::{unique_channel_match, ChannelInfo};
fn channel(peer: &str, capacity: u64) -> ChannelInfo {
    ChannelInfo {
        is_outbound: None,
        is_announced: None,
        is_channel_ready: None,
        local_reserve_msat: None,
        initial_push_msat: None,
        channel_id: "channel".into(),
        user_channel_id: Some("7".into()),
        funding_txo: None,
        peer_pubkey: peer.into(),
        capacity_msat: capacity,
        local_balance_msat: 0,
        remote_balance_msat: 0,
        active: true,
        short_channel_id: None,
    }
}
#[test]
fn recovery_requires_exactly_one_peer_capacity_match() {
    assert!(unique_channel_match(&[], "abcd", 50_000).is_none());
    let one = vec![channel("ABCD", 50_000_000), channel("other", 50_000_000)];
    assert_eq!(
        unique_channel_match(&one, "abcd", 50_000)
            .unwrap()
            .user_channel_id
            .as_deref(),
        Some("7")
    );
    assert!(unique_channel_match(&one, "abcd", u64::MAX).is_none());
    assert!(unique_channel_match(
        &[channel("abcd", 50_000_000), channel("abcd", 50_000_000)],
        "abcd",
        50_000
    )
    .is_none());
}
