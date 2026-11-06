use konsensus_core::traits::lightning::ChannelInfo;
fn channel() -> ChannelInfo {
    ChannelInfo {
        channel_id: "aa".repeat(32),
        user_channel_id: Some("1".into()),
        funding_txo: Some(format!("{}:0", "bb".repeat(32))),
        peer_pubkey: "02".repeat(33),
        capacity_msat: 100_000_000,
        local_balance_msat: 0,
        outbound_capacity_msat: None,
        remote_balance_msat: 100_000_000,
        active: true,
        short_channel_id: None,
        is_outbound: Some(false),
        is_announced: Some(false),
        is_channel_ready: Some(true),
        local_reserve_msat: Some(0),
        initial_push_msat: Some(10_000_000),
    }
}
#[test]
fn initial_push_is_proven_even_after_spend_but_never_before_ready() {
    let mut c = channel();
    assert!(c.verifies_starter(&"02".repeat(33), 100_000, 10_000, None, None));
    c.is_channel_ready = Some(false);
    assert!(!c.verifies_starter(&"02".repeat(33), 100_000, 10_000, None, None));
}
#[test]
fn verification_rejects_each_missing_or_mismatched_proof() {
    let valid = channel();
    let check = |c: &ChannelInfo| {
        c.verifies_starter(
            &"02".repeat(33),
            100_000,
            10_000,
            Some(&"aa".repeat(32)),
            Some(&"bb".repeat(32)),
        )
    };
    assert!(check(&valid));
    for mutation in 0..11 {
        let mut c = valid.clone();
        match mutation {
            0 => c.peer_pubkey = "03".repeat(33),
            1 => c.is_outbound = Some(true),
            2 => c.is_announced = Some(true),
            3 => c.capacity_msat = 200_001_000,
            4 => c.initial_push_msat = None,
            5 => c.initial_push_msat = Some(0),
            6 => c.active = false,
            7 => c.is_channel_ready = None,
            8 => c.channel_id = "cc".repeat(32),
            9 => c.funding_txo = None,
            _ => c.is_outbound = None,
        }
        assert!(!check(&c), "mutation {mutation}");
    }
    assert!(!valid.verifies_starter(&valid.peer_pubkey, u64::MAX, u64::MAX, None, None));
}
