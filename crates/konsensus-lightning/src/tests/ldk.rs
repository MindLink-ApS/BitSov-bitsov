use super::*;

#[test]
fn channel_funding_and_close_resolve_ldk_display_ids() {
    // Preserve old wrapped IDs as well as the canonical decimal form.
    // Include values beyond u64 so parsing cannot silently narrow the ID.
    for value in [0, 42, u128::MAX] {
        let id = ldk_node::UserChannelId(value);
        assert_eq!(parse_user_channel_id(&id.to_string()).unwrap(), id);
        assert_eq!(parse_user_channel_id(&value.to_string()).unwrap(), id);
    }
    for invalid in [
        "",
        "UserChannelId()",
        "UserChannelId(42",
        "42)",
        "-1",
        "340282366920938463463374607431768211456",
    ] {
        assert!(parse_user_channel_id(invalid).is_err(), "{invalid}");
    }
}

fn test_channel_details() -> ldk_node::ChannelDetails {
    ldk_node::ChannelDetails {
        initial_push_msat: Some(10_000_000),
        channel_id: ldk_node::lightning::ln::types::ChannelId::new_zero(),
        counterparty_node_id: bitcoin::secp256k1::PublicKey::from_slice(&[2; 33]).unwrap(),
        funding_txo: Some(bitcoin::OutPoint::null()),
        short_channel_id: None,
        outbound_scid_alias: None,
        inbound_scid_alias: None,
        channel_value_sats: 100_000,
        unspendable_punishment_reserve: None,
        user_channel_id: ldk_node::UserChannelId(1),
        feerate_sat_per_1000_weight: 253,
        outbound_capacity_msat: 0,
        inbound_capacity_msat: 0,
        confirmations_required: Some(6),
        confirmations: Some(6),
        is_outbound: true,
        is_channel_ready: true,
        is_usable: false,
        is_announced: false,
        cltv_expiry_delta: None,
        counterparty_unspendable_punishment_reserve: 0,
        counterparty_outbound_htlc_minimum_msat: None,
        counterparty_outbound_htlc_maximum_msat: None,
        counterparty_forwarding_info_fee_base_msat: None,
        counterparty_forwarding_info_fee_proportional_millionths: None,
        counterparty_forwarding_info_cltv_expiry_delta: None,
        next_outbound_htlc_limit_msat: 0,
        next_outbound_htlc_minimum_msat: 0,
        force_close_spend_delay: Some(144),
        counterparty_force_close_spend_delay: Some(2016),
        inbound_htlc_minimum_msat: 0,
        inbound_htlc_maximum_msat: None,
        config: Default::default(),
    }
}

#[test]
fn offline_safety_window_uses_our_to_self_delay() {
    let channel = test_channel_details();
    let windows = offline_channel_windows(vec![channel]);
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].window_blocks, Some(2016));
}

#[test]
fn parse_network_variants() {
    assert_eq!(parse_network("bitcoin").unwrap(), bitcoin::Network::Bitcoin);
    assert_eq!(parse_network("mainnet").unwrap(), bitcoin::Network::Bitcoin);
    assert_eq!(parse_network("testnet").unwrap(), bitcoin::Network::Testnet);
    assert_eq!(parse_network("signet").unwrap(), bitcoin::Network::Signet);
    assert_eq!(parse_network("regtest").unwrap(), bitcoin::Network::Regtest);
    assert!(parse_network("invalid").is_err());
}

/// REAL-LATENCY: settle/fail events of outgoing payments wake settlement polls
/// by the hash `get_payment_status` is keyed on; inbound events do not.
#[test]
fn outgoing_update_hash_names_the_polled_payment() {
    use ldk_node::lightning::ln::channelmanager::PaymentId;
    use ldk_node::lightning_types::payment::PaymentHash;
    let hash = PaymentHash([7; 32]);
    let settled = ldk_node::Event::PaymentSuccessful {
        payment_id: Some(PaymentId([7; 32])),
        payment_hash: hash,
        payment_preimage: None,
        fee_paid_msat: Some(1000),
    };
    assert_eq!(outgoing_update_hash(&settled), Some("07".repeat(32)));
    let failed = ldk_node::Event::PaymentFailed {
        payment_id: Some(PaymentId([9; 32])),
        payment_hash: Some(hash),
        reason: None,
    };
    assert_eq!(outgoing_update_hash(&failed), Some("07".repeat(32)));
    let failed_unknown_hash = ldk_node::Event::PaymentFailed {
        payment_id: Some(PaymentId([9; 32])),
        payment_hash: None,
        reason: None,
    };
    assert_eq!(
        outgoing_update_hash(&failed_unknown_hash),
        Some("09".repeat(32))
    );
    let received = ldk_node::Event::PaymentReceived {
        payment_id: None,
        payment_hash: hash,
        amount_msat: 1,
        custom_records: vec![],
    };
    assert_eq!(outgoing_update_hash(&received), None);
}

#[test]
fn convert_status_mapping() {
    assert_eq!(
        convert_status(LdkPaymentStatus::Pending),
        PaymentStatus::Pending
    );
    assert_eq!(
        convert_status(LdkPaymentStatus::Succeeded),
        PaymentStatus::Settled
    );
    assert_eq!(
        convert_status(LdkPaymentStatus::Failed),
        PaymentStatus::Failed
    );
}

#[test]
fn convert_direction_mapping() {
    assert_eq!(
        convert_direction(ldk_node::payment::PaymentDirection::Inbound),
        PaymentDirection::Incoming
    );
    assert_eq!(
        convert_direction(ldk_node::payment::PaymentDirection::Outbound),
        PaymentDirection::Outgoing
    );
}

#[test]
fn ldk_config_construction() {
    let mut config = LdkConfig {
        tower: Default::default(),
        forward_to_private_channels: false,
        our_to_self_delay_blocks: None,
        lsps2_service: Default::default(),
        channel_peers: None,
        channel_capacity_limits: Default::default(),
        esplora_sync_intervals: Default::default(),
        logging: Default::default(),
        electrum: None,
        bitcoind: None,
        liquidity: Default::default(),
        storage_dir: PathBuf::from("/tmp/ldk_test"),
        scb_backup_dir: None,
        scb_rotation_count: 24,
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        passphrase: None,
        network: "regtest".to_string(),
        esplora_url: "http://localhost:3002".to_string(),
        esplora_url_fallback: None, credentials_file: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: None,
    };
    assert_eq!(config.network, "regtest");
    assert!(config.lsp_node_id.is_none());
    for enabled in [false, true] {
        config.forward_to_private_channels = enabled;
        let node_config = config.node_config(None);
        assert_eq!(node_config.accept_forwards_to_priv_channels, enabled);
        assert!(node_config.node_alias.is_none());
        assert!(node_config.announcement_addresses.is_none());
    }
    // Trust is scoped to the enabled, selected provider, never the registry.
    let other = "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    for (enabled, selected, trust, other_trust, expected) in [
        (true, CHANNEL_PEER, false, false, vec![]),
        (true, CHANNEL_PEER, true, false, vec![CHANNEL_PEER]),
        (true, other, true, false, vec![]),
        (true, other, true, true, vec![other]),
        (false, CHANNEL_PEER, true, true, vec![]),
    ] {
        config.liquidity = serde_json::from_value(serde_json::json!({
            "enabled":enabled, "selected_provider":selected,
            "providers":[
                {"node_id":CHANNEL_PEER,"address":"127.0.0.1:9735","trust_no_reserve":trust},
                {"node_id":other,"address":"127.0.0.1:9736","trust_no_reserve":other_trust}
            ]
        }))
        .unwrap();
        let anchors = config.node_config(None).anchor_channels_config.unwrap();
        assert_eq!(anchors.per_channel_reserve_sats, 25_000);
        assert_eq!(
            anchors
                .trusted_peers_no_reserve
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            expected
        );
    }
    assert_eq!(config.node_config(None).our_to_self_delay, None);
    for delay in [288, 500, 2016] {
        config.our_to_self_delay_blocks = Some(delay);
        assert_eq!(config.node_config(None).our_to_self_delay, Some(delay));
    }
}

#[test]
fn our_to_self_delay_bounds() {
    assert_eq!(OUR_TO_SELF_DELAY_BLOCKS, 144..=2016);
    for accepted in [None, Some(144), Some(288), Some(2016)] {
        validate_our_to_self_delay(accepted).unwrap();
    }
    for refused in [0, 143, 2017, u16::MAX] {
        let error = validate_our_to_self_delay(Some(refused)).unwrap_err();
        assert!(matches!(error, LightningError::InvalidStartupConfig(_)));
        assert!(
            error.to_string().contains(&format!("got {refused}")),
            "{error}"
        );
    }
}

// ─── derive_ldk_entropy Tests ──────────────────────────────────────

#[test]
fn ldk_entropy_is_deterministic() {
    let mnemonic: Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        .parse()
        .unwrap();
    let seed = mnemonic.to_seed("");

    let entropy1 = derive_ldk_entropy(&seed);
    let entropy2 = derive_ldk_entropy(&seed);
    assert_eq!(entropy1, entropy2, "same seed must produce same entropy");
}

#[test]
fn ldk_entropy_differs_from_identity_keys() {
    let mnemonic: Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        .parse()
        .unwrap();
    let seed = mnemonic.to_seed("");

    let ldk_entropy = derive_ldk_entropy(&seed);

    // Identity keys use different context strings — verify no overlap
    let ed25519_key = blake3::derive_key("konsensus-v2 ed25519 signing key", &seed);
    let secp_key = blake3::derive_key("konsensus-v2 secp256k1 bitcoin key", &seed);

    assert_ne!(
        &ldk_entropy[..32],
        &ed25519_key[..],
        "LDK entropy must differ from ed25519 identity key"
    );
    assert_ne!(
        &ldk_entropy[..32],
        &secp_key[..],
        "LDK entropy must differ from secp256k1 identity key"
    );
}

#[test]
fn ldk_entropy_differs_with_passphrase() {
    let mnemonic: Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        .parse()
        .unwrap();

    let seed_no_pass = mnemonic.to_seed("");
    let seed_with_pass = mnemonic.to_seed("my-passphrase");

    let entropy1 = derive_ldk_entropy(&seed_no_pass);
    let entropy2 = derive_ldk_entropy(&seed_with_pass);

    assert_ne!(
        entropy1, entropy2,
        "different passphrases must produce different LDK entropy"
    );
}

#[test]
fn ldk_entropy_is_64_bytes() {
    let mnemonic: Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        .parse()
        .unwrap();
    let seed = mnemonic.to_seed("");
    let entropy = derive_ldk_entropy(&seed);
    assert_eq!(entropy.len(), 64);
    // Ensure it's not all zeros
    assert!(entropy.iter().any(|&b| b != 0));
}

#[tokio::test]
async fn invalid_mnemonic_errors() {
    let config = LdkConfig {
        tower: Default::default(),
        forward_to_private_channels: false,
        our_to_self_delay_blocks: None,
        lsps2_service: Default::default(),
        channel_peers: None,
        channel_capacity_limits: Default::default(),
        esplora_sync_intervals: Default::default(),
        logging: Default::default(),
        electrum: None,
        bitcoind: None,
        liquidity: Default::default(),
        storage_dir: PathBuf::from("/tmp/ldk_test"),
        scb_backup_dir: None,
        scb_rotation_count: 24,
        mnemonic: "not a valid mnemonic".to_string(),
        passphrase: None,
        network: "regtest".to_string(),
        esplora_url: "http://localhost:3002".to_string(),
        esplora_url_fallback: None,
        credentials_file: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: None,
    };
    let result = LdkProvider::new(config).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("invalid mnemonic"));
}

#[tokio::test]
async fn out_of_range_our_to_self_delay_refuses_startup() {
    let config = LdkConfig {
        tower: Default::default(),
        forward_to_private_channels: false,
        our_to_self_delay_blocks: Some(143),
        lsps2_service: Default::default(),
        channel_peers: None,
        channel_capacity_limits: Default::default(),
        esplora_sync_intervals: Default::default(),
        logging: Default::default(),
        electrum: None,
        bitcoind: None,
        liquidity: Default::default(),
        storage_dir: PathBuf::from("/tmp/ldk_test"),
        scb_backup_dir: None,
        scb_rotation_count: 24,
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        passphrase: None,
        network: "regtest".to_string(),
        esplora_url: "http://localhost:3002".to_string(),
        esplora_url_fallback: None, credentials_file: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: None,
    };
    let err = LdkProvider::new(config).await.unwrap_err();
    assert!(matches!(err, LightningError::InvalidStartupConfig(_)));
    assert!(
        err.to_string().contains("our_to_self_delay_blocks"),
        "{err}"
    );
}

#[tokio::test]
async fn hub_only_allowlist_parses_hub_keys_and_refuses_the_hub_service() {
    use konsensus_core::traits::lightning::HUB_ONLY_WHILE_LOCKABLE;
    let hub = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string();
    assert!(
        channel_peer_allowlist(None, true).unwrap().is_none(),
        "no allowlist leaves the service role unchanged"
    );
    let parsed = channel_peer_allowlist(Some(std::slice::from_ref(&hub)), false)
        .unwrap()
        .unwrap();
    assert_eq!(
        parsed.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
        vec![hub.clone()]
    );
    assert_eq!(
        channel_peer_allowlist(Some(&[]), false).unwrap(),
        Some(vec![]),
        "no hub configured refuses every peer"
    );
    for error in [
        channel_peer_allowlist(Some(&["not-a-key".into()]), false).unwrap_err(),
        channel_peer_allowlist(Some(std::slice::from_ref(&hub)), true).unwrap_err(),
    ] {
        assert!(
            matches!(&error, LightningError::InvalidStartupConfig(m) if m.starts_with(HUB_ONLY_WHILE_LOCKABLE)),
            "{error}"
        );
    }
    // Wired before any key derivation or network work.
    let config = LdkConfig {
        tower: Default::default(),
        forward_to_private_channels: false,
        our_to_self_delay_blocks: None,
        lsps2_service: crate::lsps2_service::Lsps2ServiceConfig {
            enabled: true,
            require_token: Some("pilot".into()),
            ..Default::default()
        },
        channel_peers: Some(vec![hub]),
        channel_capacity_limits: Default::default(),
        esplora_sync_intervals: Default::default(),
        logging: Default::default(),
        electrum: None,
        bitcoind: None,
        liquidity: Default::default(),
        storage_dir: PathBuf::from("/tmp/ldk_test_hub_only"),
        scb_backup_dir: None,
        scb_rotation_count: 24,
        mnemonic: "not a valid mnemonic".to_string(),
        passphrase: None,
        network: "regtest".to_string(),
        esplora_url: "http://localhost:3002".to_string(),
        esplora_url_fallback: None,
        credentials_file: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: None,
    };
    let error = LdkProvider::new(config).await.err().unwrap();
    assert!(
        error.to_string().contains(HUB_ONLY_WHILE_LOCKABLE),
        "{error}"
    );
}

#[test]
fn invalid_network_errors() {
    let result = parse_network("fakenet");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("unknown network"));
}

// ─── payment_hash_from_kind Tests ──────────────────────────────────

#[test]
fn payment_hash_from_bolt11_kind() {
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentSecret};

    let hash = PaymentHash([1u8; 32]);
    let kind = LdkPaymentKind::Bolt11 {
        hash,
        preimage: None,
        secret: Some(PaymentSecret([2u8; 32])),
    };
    let result = payment_hash_from_kind(&kind);
    assert_eq!(result, Some(hash));
}

#[test]
fn payment_hash_from_spontaneous_kind() {
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};

    let hash = PaymentHash([3u8; 32]);
    let kind = LdkPaymentKind::Spontaneous {
        hash,
        preimage: Some(PaymentPreimage([4u8; 32])),
    };
    let result = payment_hash_from_kind(&kind);
    assert_eq!(result, Some(hash));
}

#[test]
fn payment_hash_from_bolt12_offer() {
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentSecret};

    let hash = PaymentHash([5u8; 32]);
    let kind = LdkPaymentKind::Bolt12Offer {
        hash: Some(hash),
        preimage: None,
        secret: Some(PaymentSecret([6u8; 32])),
        offer_id: ldk_node::lightning::offers::offer::OfferId([7u8; 32]),
        payer_note: None,
        quantity: None,
    };
    assert_eq!(payment_hash_from_kind(&kind), Some(hash));
}

#[test]
fn payment_hash_from_bolt12_offer_none() {
    use ldk_node::lightning_types::payment::PaymentSecret;

    let kind = LdkPaymentKind::Bolt12Offer {
        hash: None,
        preimage: None,
        secret: Some(PaymentSecret([8u8; 32])),
        offer_id: ldk_node::lightning::offers::offer::OfferId([9u8; 32]),
        payer_note: None,
        quantity: None,
    };
    assert_eq!(payment_hash_from_kind(&kind), None);
}

// ─── preimage_from_kind Tests ──────────────────────────────────────

#[test]
fn preimage_from_bolt11_with_preimage() {
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};

    let preimage = PaymentPreimage([10u8; 32]);
    let kind = LdkPaymentKind::Bolt11 {
        hash: PaymentHash([11u8; 32]),
        preimage: Some(preimage),
        secret: Some(PaymentSecret([12u8; 32])),
    };
    assert_eq!(preimage_from_kind(&kind), Some(preimage));
}

#[test]
fn preimage_from_bolt11_without_preimage() {
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentSecret};

    let kind = LdkPaymentKind::Bolt11 {
        hash: PaymentHash([13u8; 32]),
        preimage: None,
        secret: Some(PaymentSecret([14u8; 32])),
    };
    assert_eq!(preimage_from_kind(&kind), None);
}

#[test]
fn preimage_from_spontaneous_with_preimage() {
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};

    let preimage = PaymentPreimage([15u8; 32]);
    let kind = LdkPaymentKind::Spontaneous {
        hash: PaymentHash([16u8; 32]),
        preimage: Some(preimage),
    };
    assert_eq!(preimage_from_kind(&kind), Some(preimage));
}

// ─── convert_payment_details Tests ─────────────────────────────────

#[test]
fn convert_bolt11_payment_details() {
    use ldk_node::lightning::ln::channelmanager::PaymentId;
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};

    let hash = PaymentHash([20u8; 32]);
    let preimage = PaymentPreimage([21u8; 32]);

    let ldk_details = ldk_node::payment::PaymentDetails {
        id: PaymentId([22u8; 32]),
        kind: LdkPaymentKind::Bolt11 {
            hash,
            preimage: Some(preimage),
            secret: Some(PaymentSecret([23u8; 32])),
        },
        amount_msat: Some(25_000),
        fee_paid_msat: Some(100),
        direction: ldk_node::payment::PaymentDirection::Outbound,
        status: LdkPaymentStatus::Succeeded,
        latest_update_timestamp: 1_700_000_000,
    };

    let result = convert_payment_details(&ldk_details);

    assert_eq!(result.payment_hash, hex::encode([20u8; 32]));
    assert_eq!(result.preimage, Some(hex::encode([21u8; 32])));
    assert_eq!(result.amount_msat, 25_000);
    assert_eq!(result.fee_msat, Some(100));
    assert_eq!(result.direction, PaymentDirection::Outgoing);
    assert_eq!(result.status, PaymentStatus::Settled);
    assert_eq!(result.timestamp, 1_700_000_000);
    assert!(result.memo.is_none());
}

#[test]
fn convert_spontaneous_payment_details() {
    use ldk_node::lightning::ln::channelmanager::PaymentId;
    use ldk_node::lightning_types::payment::PaymentHash;

    let ldk_details = ldk_node::payment::PaymentDetails {
        id: PaymentId([30u8; 32]),
        kind: LdkPaymentKind::Spontaneous {
            hash: PaymentHash([31u8; 32]),
            preimage: None,
        },
        amount_msat: Some(5_000),
        fee_paid_msat: None,
        direction: ldk_node::payment::PaymentDirection::Inbound,
        status: LdkPaymentStatus::Pending,
        latest_update_timestamp: 1_700_000_100,
    };

    let result = convert_payment_details(&ldk_details);

    assert_eq!(result.payment_hash, hex::encode([31u8; 32]));
    assert!(
        result.preimage.is_none(),
        "pending payment should have no preimage"
    );
    assert_eq!(result.amount_msat, 5_000);
    assert!(result.fee_msat.is_none());
    assert_eq!(result.direction, PaymentDirection::Incoming);
    assert_eq!(result.status, PaymentStatus::Pending);
}

#[test]
fn convert_failed_payment_zero_amount() {
    use ldk_node::lightning::ln::channelmanager::PaymentId;
    use ldk_node::lightning_types::payment::PaymentHash;

    let ldk_details = ldk_node::payment::PaymentDetails {
        id: PaymentId([40u8; 32]),
        kind: LdkPaymentKind::Spontaneous {
            hash: PaymentHash([41u8; 32]),
            preimage: None,
        },
        amount_msat: None, // Unknown amount
        fee_paid_msat: None,
        direction: ldk_node::payment::PaymentDirection::Outbound,
        status: LdkPaymentStatus::Failed,
        latest_update_timestamp: 0,
    };

    let result = convert_payment_details(&ldk_details);

    assert_eq!(result.amount_msat, 0, "None amount should default to 0");
    assert_eq!(result.status, PaymentStatus::Failed);
}

// ─── R2 seam-2: binding-TLV extraction ───────────────────────────────────────

#[test]
fn extract_binding_tlv_picks_only_the_bitsov_record() {
    // The receiver pulls exactly the BitSov binding record out of the inbound
    // custom TLVs, ignoring unrelated records (e.g. the keysend preimage record
    // 5482373484). Proves seam-2 reads the right odd type_num.
    let records = vec![
        CustomTlvRecord {
            type_num: 5482373484,
            value: vec![0xAA; 32],
        },
        CustomTlvRecord {
            type_num: BITSOV_BINDING_TLV_TYPE,
            value: b"envelope-id-pointer".to_vec(),
        },
        CustomTlvRecord {
            type_num: 9999,
            value: vec![0xFF],
        },
    ];
    assert_eq!(
        extract_binding_tlv(&records),
        Ok(Some(b"envelope-id-pointer".to_vec()))
    );
}

#[test]
fn extract_binding_tlv_none_when_absent_and_type_is_odd() {
    // No BitSov record present → None (bare keysend / no binding).
    let records = vec![CustomTlvRecord {
        type_num: 5482373484,
        value: vec![0xAA; 32],
    }];
    assert_eq!(extract_binding_tlv(&records), Ok(None));
    assert_eq!(extract_binding_tlv(&[]), Ok(None));
    // Doctrine: the binding TLV type MUST be odd (BOLT-1 forward-compat).
    assert_eq!(
        BITSOV_BINDING_TLV_TYPE % 2,
        1,
        "BitSov binding TLV type must be odd"
    );
}

#[test]
fn extract_binding_tlv_rejects_duplicate_bitsov_records() {
    let records = vec![
        CustomTlvRecord {
            type_num: BITSOV_BINDING_TLV_TYPE,
            value: b"first-binding".to_vec(),
        },
        CustomTlvRecord {
            type_num: BITSOV_BINDING_TLV_TYPE,
            value: b"second-binding".to_vec(),
        },
    ];
    assert_eq!(
        extract_binding_tlv(&records),
        Err(BindingTlvError::Duplicate),
        "duplicate BitSov binding TLVs must fail loudly"
    );
}

#[test]
fn extract_binding_tlv_rejects_oversized_record() {
    let records = vec![CustomTlvRecord {
        type_num: BITSOV_BINDING_TLV_TYPE,
        value: vec![0xAB; BITSOV_BINDING_TLV_MAX_BYTES + 1],
    }];

    assert_eq!(
        extract_binding_tlv(&records),
        Err(BindingTlvError::TooLarge {
            len: BITSOV_BINDING_TLV_MAX_BYTES + 1
        }),
        "BitSov binding TLVs are pointers/digests and must stay bounded"
    );
}

#[test]
fn seam3b_send_record_round_trips_through_receive_extractor() {
    // R2 seam-3b CONTRACT (network-free): the single record the SEND-half
    // (`keysend_with_binding` → `binding_tlv_record`) attaches is EXACTLY what
    // the RECEIVE-half (`extract_binding_tlv`, seam-2) pulls back out, and a lone
    // send record is unambiguous (Ok(Some), never Err(Duplicate)). Proves
    // send↔receive agree on the wire shape without a running LDK node; the
    // on-wire send is the seam-3c regtest round-trip.
    let binding = b"envelope-id-pointer".to_vec();
    let sent = binding_tlv_record(&binding);

    // The send-side record carries the agreed odd type and the exact bytes.
    assert_eq!(sent.type_num, BITSOV_BINDING_TLV_TYPE);
    assert_eq!(sent.value, binding);

    // Round-trips through the receiver's (Result-returning) extractor verbatim,
    // and a single send record is never duplicate/oversized.
    assert_eq!(extract_binding_tlv(&[sent]), Ok(Some(binding)));
}

#[test]
fn seam3b_send_preflight_rejects_unbindable_binding() {
    // The send-half uses this exact preflight before invoking LDK, so an
    // over-cap binding returns before `send_with_custom_tlvs` can spend sats on
    // a payment the receive-half would reject as `BindingTooLarge`.
    match binding_tlv_record_for_send(&[]) {
        Err(LightningError::Backend(msg)) => {
            assert!(msg.contains("requires a non-empty binding"));
        }
        other => panic!("expected send preflight to reject empty binding, got {other:?}"),
    }

    let at_cap = vec![0xCD; BITSOV_BINDING_TLV_MAX_BYTES];
    assert_eq!(
        extract_binding_tlv(&[binding_tlv_record_for_send(&at_cap).unwrap()]),
        Ok(Some(at_cap)),
        "a binding exactly at the cap must round-trip"
    );

    let over_cap = vec![0xCD; BITSOV_BINDING_TLV_MAX_BYTES + 1];
    match binding_tlv_record_for_send(&over_cap) {
        Err(LightningError::Backend(msg)) => {
            assert!(msg.contains("binding TLV too large"));
            assert!(msg.contains("receiver would reject"));
        }
        other => panic!("expected send preflight to fail closed, got {other:?}"),
    }
}

#[test]
fn seam3b_inflight_fallback_preserves_payment_hash() {
    // LDK Node returns a PaymentId immediately for spontaneous/keysend sends,
    // while `node.payment(payment_id)` may lag. For spontaneous payments the
    // PaymentId bytes are the payment hash bytes, so the binding path must not
    // return an empty hash in that in-flight window.
    let payment_hash = [0x2A; 32];
    let details = in_flight_spontaneous_payment_details(payment_hash, 21_000, 42);

    assert_eq!(details.payment_hash, hex::encode(payment_hash));
    assert_eq!(details.amount_msat, 21_000);
    assert_eq!(details.status, PaymentStatus::InFlight);
    assert_eq!(details.direction, PaymentDirection::Outgoing);
    assert_eq!(details.timestamp, 42);
    assert!(details.preimage.is_none());
}

#[test]
fn keysend_inflight_hash_matches_settled_payment() {
    use ldk_node::lightning::ln::channelmanager::PaymentId;
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};

    let preimage = PaymentPreimage([42; 32]);
    let hash = PaymentHash::from(preimage);
    // Spontaneous sends use the hash as their PaymentId, even before a
    // payment-store record is available to the provider.
    let payment_id = PaymentId(hash.0);
    let inflight = in_flight_spontaneous_payment_details(payment_id.0, 21_000, 42);
    assert_eq!(inflight.status, PaymentStatus::InFlight);
    assert_eq!(inflight.payment_hash.len(), 64);
    assert!(inflight.preimage.is_none());

    let settled = convert_payment_details(&ldk_node::payment::PaymentDetails {
        id: payment_id,
        kind: LdkPaymentKind::Spontaneous {
            hash,
            preimage: Some(preimage),
        },
        amount_msat: Some(21_000),
        fee_paid_msat: Some(0),
        direction: ldk_node::payment::PaymentDirection::Outbound,
        status: LdkPaymentStatus::Succeeded,
        latest_update_timestamp: 43,
    });
    assert_eq!(settled.status, PaymentStatus::Settled);
    assert_eq!(inflight.payment_hash, settled.payment_hash);
    assert_eq!(settled.preimage, Some(hex::encode(preimage.0)));
}

fn inbound_payment_details(
    status: PaymentStatus,
    direction: PaymentDirection,
    preimage: Option<&str>,
) -> PaymentDetails {
    PaymentDetails {
        payment_hash: "00".repeat(32),
        preimage: preimage.map(str::to_owned),
        amount_msat: 1_000,
        status,
        direction,
        timestamp: 0,
        memo: None,
        fee_msat: None,
    }
}

fn inbound_payment_details_with_amount(
    status: PaymentStatus,
    direction: PaymentDirection,
    preimage: Option<&str>,
    amount_msat: u64,
) -> PaymentDetails {
    PaymentDetails {
        amount_msat,
        ..inbound_payment_details(status, direction, preimage)
    }
}

#[test]
fn inbound_stream_items_require_settled_incoming_preimage() {
    assert!(is_admittable_inbound_payment(&inbound_payment_details(
        PaymentStatus::Settled,
        PaymentDirection::Incoming,
        Some(&"11".repeat(32)),
    )));
    assert!(!is_admittable_inbound_payment(&inbound_payment_details(
        PaymentStatus::Settled,
        PaymentDirection::Incoming,
        None,
    )));
    assert!(!is_admittable_inbound_payment(&inbound_payment_details(
        PaymentStatus::Pending,
        PaymentDirection::Incoming,
        Some(&"11".repeat(32)),
    )));
    assert!(!is_admittable_inbound_payment(&inbound_payment_details(
        PaymentStatus::Settled,
        PaymentDirection::Outgoing,
        Some(&"11".repeat(32)),
    )));
    assert!(!is_admittable_inbound_payment(
        &inbound_payment_details_with_amount(
            PaymentStatus::Settled,
            PaymentDirection::Incoming,
            Some(&"11".repeat(32)),
            0,
        )
    ));
}

#[test]
fn inbound_payment_from_received_event_emits_single_binding() {
    let details = inbound_payment_details(
        PaymentStatus::Settled,
        PaymentDirection::Incoming,
        Some(&"11".repeat(32)),
    );
    let records = vec![CustomTlvRecord {
        type_num: BITSOV_BINDING_TLV_TYPE,
        value: b"envelope-id-pointer".to_vec(),
    }];

    let inbound = inbound_payment_from_received_event(
        [0u8; 32],
        details.amount_msat,
        Some(&details),
        &records,
    )
    .unwrap();

    assert_eq!(inbound.details.payment_hash, details.payment_hash);
    assert_eq!(inbound.binding_tlv, Some(b"envelope-id-pointer".to_vec()));
}

#[test]
fn inbound_payment_from_received_event_rejects_store_miss() {
    assert_eq!(
        inbound_payment_from_received_event([0u8; 32], 1_000, None, &[]).unwrap_err(),
        InboundPaymentRejection::MissingStoreRecord
    );
}

#[test]
fn inbound_payment_from_received_event_rejects_malformed_store_hash() {
    let mut details = inbound_payment_details(
        PaymentStatus::Settled,
        PaymentDirection::Incoming,
        Some(&"11".repeat(32)),
    );
    details.payment_hash = "not-hex".to_owned();

    assert_eq!(
        inbound_payment_from_received_event([0u8; 32], details.amount_msat, Some(&details), &[])
            .unwrap_err(),
        InboundPaymentRejection::MalformedStoreHash
    );
}

#[test]
fn inbound_payment_from_received_event_rejects_hash_mismatch() {
    let details = inbound_payment_details(
        PaymentStatus::Settled,
        PaymentDirection::Incoming,
        Some(&"11".repeat(32)),
    );

    assert_eq!(
        inbound_payment_from_received_event([0xff; 32], details.amount_msat, Some(&details), &[])
            .unwrap_err(),
        InboundPaymentRejection::HashMismatch
    );
}

#[test]
fn inbound_payment_from_received_event_rejects_amount_mismatch() {
    let details = inbound_payment_details(
        PaymentStatus::Settled,
        PaymentDirection::Incoming,
        Some(&"11".repeat(32)),
    );

    assert_eq!(
        inbound_payment_from_received_event(
            [0u8; 32],
            details.amount_msat + 1,
            Some(&details),
            &[],
        )
        .unwrap_err(),
        InboundPaymentRejection::EventStoreAmountMismatch
    );
}

#[test]
fn inbound_payment_from_received_event_rejects_non_admittable_record() {
    let details = inbound_payment_details(PaymentStatus::Pending, PaymentDirection::Incoming, None);

    assert_eq!(
        inbound_payment_from_received_event([0u8; 32], details.amount_msat, Some(&details), &[])
            .unwrap_err(),
        InboundPaymentRejection::NotAdmittableProof
    );
}

#[test]
fn inbound_payment_from_received_event_rejects_zero_amount() {
    let details = inbound_payment_details_with_amount(
        PaymentStatus::Settled,
        PaymentDirection::Incoming,
        Some(&"11".repeat(32)),
        0,
    );

    assert_eq!(
        inbound_payment_from_received_event([0u8; 32], 0, Some(&details), &[]).unwrap_err(),
        InboundPaymentRejection::NotAdmittableProof
    );
}

#[test]
fn inbound_payment_from_received_event_rejects_duplicate_binding() {
    let details = inbound_payment_details(
        PaymentStatus::Settled,
        PaymentDirection::Incoming,
        Some(&"11".repeat(32)),
    );
    let records = vec![
        CustomTlvRecord {
            type_num: BITSOV_BINDING_TLV_TYPE,
            value: b"first-binding".to_vec(),
        },
        CustomTlvRecord {
            type_num: BITSOV_BINDING_TLV_TYPE,
            value: b"second-binding".to_vec(),
        },
    ];

    assert_eq!(
        inbound_payment_from_received_event(
            [0u8; 32],
            details.amount_msat,
            Some(&details),
            &records,
        )
        .unwrap_err(),
        InboundPaymentRejection::DuplicateBinding
    );
}

#[test]
fn inbound_payment_from_received_event_rejects_oversized_binding() {
    let details = inbound_payment_details(
        PaymentStatus::Settled,
        PaymentDirection::Incoming,
        Some(&"11".repeat(32)),
    );
    let records = vec![CustomTlvRecord {
        type_num: BITSOV_BINDING_TLV_TYPE,
        value: vec![0xAB; BITSOV_BINDING_TLV_MAX_BYTES + 1],
    }];

    assert_eq!(
        inbound_payment_from_received_event(
            [0u8; 32],
            details.amount_msat,
            Some(&details),
            &records,
        )
        .unwrap_err(),
        InboundPaymentRejection::BindingTooLarge {
            len: BITSOV_BINDING_TLV_MAX_BYTES + 1
        }
    );
}

#[test]
fn wallet_sync_is_the_older_of_the_two_wallet_syncs() {
    assert_eq!(
        wallet_sync_from_timestamps(Some(1_700_000_100), Some(1_700_000_000)),
        WalletSync::SyncedAt(1_700_000_000)
    );
    assert_eq!(
        wallet_sync_from_timestamps(Some(1_700_000_000), Some(1_700_000_100)),
        WalletSync::SyncedAt(1_700_000_000)
    );
}

#[test]
fn wallet_sync_is_never_synced_until_both_wallets_have_synced() {
    assert_eq!(
        wallet_sync_from_timestamps(None, None),
        WalletSync::NeverSynced
    );
    assert_eq!(
        wallet_sync_from_timestamps(Some(1_700_000_000), None),
        WalletSync::NeverSynced
    );
    assert_eq!(
        wallet_sync_from_timestamps(None, Some(1_700_000_000)),
        WalletSync::NeverSynced
    );
}

#[test]
fn jit_purpose_fee_and_net_survive_ldk_serialization_without_admission_proof() {
    use ldk_node::lightning::ln::channelmanager::PaymentId;
    use ldk_node::lightning::util::ser::{Readable, Writeable};
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage, PaymentSecret};
    use ldk_node::payment::{LSPFeeLimits, PaymentDetails as LdkDetails};
    for fee in [None, Some(2_000)] {
        let details = LdkDetails {
            id: PaymentId([70; 32]),
            kind: LdkPaymentKind::Bolt11Jit {
                hash: PaymentHash([70; 32]),
                preimage: Some(PaymentPreimage([71; 32])),
                secret: Some(PaymentSecret([72; 32])),
                counterparty_skimmed_fee_msat: fee,
                lsp_fee_limits: LSPFeeLimits {
                    max_total_opening_fee_msat: Some(2_000),
                    max_proportional_opening_fee_ppm_msat: None,
                },
            },
            amount_msat: Some(100_000 - fee.unwrap_or(0)),
            fee_paid_msat: None,
            direction: ldk_node::payment::PaymentDirection::Inbound,
            status: LdkPaymentStatus::Succeeded,
            latest_update_timestamp: 1_700_000_000,
        };
        let bytes = details.encode();
        let restored = LdkDetails::read(&mut &bytes[..]).unwrap();
        assert!(matches!(restored.kind, LdkPaymentKind::Bolt11Jit { .. }));
        let receipt = jit_receipt(&restored).unwrap().unwrap();
        assert_eq!(receipt.gross_msat, 100_000);
        assert_eq!(receipt.net_received_msat, 100_000 - fee.unwrap_or(0));
        assert_eq!(receipt.lsp_fee_msat, fee.unwrap_or(0));
        let public = convert_payment_details(&restored);
        assert!(public.preimage.is_none());
        assert!(!is_admittable_inbound_payment(&public));
    }
}

#[test]
fn invoice_and_keysend_ldk_call_arguments_include_exact_fee_ceiling() {
    use bitcoin::hashes::{sha256, Hash};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
    let key = SecretKey::from_slice(&[42; 32]).unwrap();
    let secp = Secp256k1::new();
    let dest = key.public_key(&secp);
    let invoice = InvoiceBuilder::new(Currency::Regtest)
        .description("fee cap".into())
        .payment_hash(sha256::Hash::hash(&[7; 32]))
        .payment_secret(PaymentSecret([8; 32]))
        .current_timestamp()
        .min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(1000)
        .build_signed(|h| secp.sign_ecdsa_recoverable(h, &key))
        .unwrap();
    for ceiling in [0, 7, 1000, 100_000] {
        dispatch_invoice_with_fee_limit(&invoice, ceiling, |arg, route| {
            assert_eq!(arg, &invoice);
            assert_eq!(route.unwrap().max_total_routing_fee_msat, Some(ceiling));
        });
        dispatch_keysend_with_fee_limit(1000, dest, ceiling, |amount, recipient, route| {
            assert_eq!(amount, 1000);
            assert_eq!(recipient, dest);
            assert_eq!(route.unwrap().max_total_routing_fee_msat, Some(ceiling));
        });
    }
}

#[test]
fn dispatch_error_classification_retains_ambiguous_liabilities() {
    use ldk_node::NodeError;
    for error in [
        NodeError::PaymentSendingFailed,
        NodeError::InvalidInvoice,
        NodeError::InvalidAmount,
        NodeError::InvalidCustomTlvs,
        NodeError::NotRunning,
    ] {
        let capable = std::sync::atomic::AtomicBool::new(true);
        assert!(matches!(
            super::classify_dispatch_error(error, &capable),
            LightningError::PaymentNotDispatched(_)
        ));
        assert!(capable.load(std::sync::atomic::Ordering::Relaxed));
    }
    for error in [NodeError::PersistenceFailed, NodeError::DuplicatePayment] {
        assert!(matches!(
            super::classify_dispatch_error(error, &std::sync::atomic::AtomicBool::new(true)),
            LightningError::PaymentFailed(_)
        ));
    }
}

const CHANNEL_PEER: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

#[test]
fn channel_fee_explicit_rate_never_dispatches() {
    for announce in [false, true] {
        for rate in [5.0, 1.5, 0.0, -1.0, f32::NAN, f32::INFINITY, f32::MAX] {
            let mut node = MockChannelOpener::new();
            node.expect_open_channel().never();
            node.expect_open_announced_channel().never();
            let result = open_ldk_channel(
                &node,
                CHANNEL_PEER,
                "127.0.0.1:9735",
                50_000,
                announce,
                Some(rate),
            );
            assert!(
                matches!(result, Err(LightningError::PaymentNotDispatched(_))),
                "fee {rate}: {result:?}"
            );
        }
    }
}

#[test]
fn channel_fee_announcement_selects_ldk_method_and_preserves_args() {
    for announce in [false, true] {
        let mut node = MockChannelOpener::new();
        let matches_args =
            |peer: &bitcoin::secp256k1::PublicKey,
             addr: &ldk_node::lightning::ln::msgs::SocketAddress,
             amount: &u64,
             push: &Option<u64>,
             config: &Option<ldk_node::config::ChannelConfig>| {
                peer.to_string() == CHANNEL_PEER
                    && *addr
                        == ldk_node::lightning::ln::msgs::SocketAddress::TcpIpV4 {
                            addr: [127, 0, 0, 1],
                            port: 9735,
                        }
                    && *amount == 50_000
                    && push.is_none()
                    && config.is_none()
            };
        if announce {
            node.expect_has_node_alias().return_const(true);
            node.expect_has_listening_addresses().return_const(true);
            node.expect_open_channel().never();
            node.expect_open_announced_channel()
                .times(1)
                .withf(matches_args)
                .returning(|_, _, _, _, _| Ok(ldk_node::UserChannelId(42)));
        } else {
            node.expect_open_announced_channel().never();
            node.expect_open_channel()
                .times(1)
                .withf(matches_args)
                .returning(|_, _, _, _, _| Ok(ldk_node::UserChannelId(42)));
        }
        let id = open_ldk_channel(
            &node,
            CHANNEL_PEER,
            "127.0.0.1:9735",
            50_000,
            announce,
            None,
        )
        .unwrap();
        assert_eq!(id.0.to_string(), "42");
    }
}

#[test]
fn channel_fee_real_provider_refuses_announcement_without_alias() {
    // Cover absent, empty, and nonempty listening addresses without an alias.
    // Alias-without-addresses is rejected at build time; the mock preflight
    // test below covers that combination.
    for addresses in [
        None,
        Some(Vec::new()),
        Some(vec!["127.0.0.1:19735".parse().unwrap()]),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let config = ldk_node::config::Config {
            network: bitcoin::Network::Regtest,
            storage_dir_path: dir.path().to_str().unwrap().to_owned(),
            listening_addresses: addresses,
            ..Default::default()
        };
        let mut builder = ldk_node::Builder::from_config(config);
        builder.set_entropy_seed_bytes([42; 64]);
        let node = Arc::new(builder.build().unwrap());
        let provider = LdkProvider::from_node(node.clone());
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let result = runtime.block_on(provider.open_channel(
            CHANNEL_PEER,
            "127.0.0.1:19736",
            50_000,
            true,
            None,
        ));
        assert!(
            matches!(&result, Err(LightningError::PaymentNotDispatched(reason))
                if reason.contains("announce_unavailable")),
            "addresses={:?}: {result:?}",
            node.listening_addresses()
        );
        assert!(node.node_alias().is_none());
        assert!(node.list_channels().is_empty());
    }
}

#[test]
fn channel_fee_creation_refusal_is_not_dispatched_but_persistence_is_ambiguous() {
    // LDK can fail peer persistence after create_channel succeeds. Never mark
    // that failure retry-safe alongside its pre-dispatch creation refusal.
    for announce in [false, true] {
        for creation_refused in [false, true] {
            let mut node = MockChannelOpener::new();
            let error = if creation_refused {
                ldk_node::NodeError::ChannelCreationFailed
            } else {
                ldk_node::NodeError::PersistenceFailed
            };
            if announce {
                node.expect_has_node_alias().return_const(true);
                node.expect_has_listening_addresses().return_const(true);
                node.expect_open_channel().never();
                node.expect_open_announced_channel()
                    .times(1)
                    .return_once(move |_, _, _, _, _| Err(error));
            } else {
                node.expect_open_announced_channel().never();
                node.expect_open_channel()
                    .times(1)
                    .return_once(move |_, _, _, _, _| Err(error));
            }
            let result = open_ldk_channel(
                &node,
                CHANNEL_PEER,
                "127.0.0.1:9735",
                50_000,
                announce,
                None,
            );
            if creation_refused {
                assert!(
                    matches!(result, Err(LightningError::PaymentNotDispatched(_))),
                    "{result:?}"
                );
            } else {
                assert!(
                    matches!(result, Err(LightningError::Backend(_))),
                    "{result:?}"
                );
            }
        }
    }
}

#[test]
fn channel_fee_announcement_preflight_never_calls_ldk_when_unavailable() {
    for (alias, addresses) in [(false, false), (false, true), (true, false)] {
        let mut node = MockChannelOpener::new();
        node.expect_has_node_alias().return_const(alias);
        node.expect_has_listening_addresses()
            .return_const(addresses);
        node.expect_open_channel().never();
        node.expect_open_announced_channel().never();
        let result = open_ldk_channel(&node, CHANNEL_PEER, "127.0.0.1:9735", 50_000, true, None);
        assert!(
            matches!(result, Err(LightningError::PaymentNotDispatched(reason))
            if reason.contains("announce_unavailable"))
        );
    }
}

/// API reports must preserve the distinction between a direct-channel zero
/// and missing LDK evidence. Both invoice and keysend use this conversion.
#[test]
fn actual_fee_conversion_preserves_zero_and_unknown() {
    use ldk_node::lightning::ln::channelmanager::PaymentId;
    use ldk_node::lightning_types::payment::{PaymentHash, PaymentPreimage};
    for fee in [Some(0), Some(400), None] {
        let details = ldk_node::payment::PaymentDetails {
            id: PaymentId([1; 32]),
            kind: LdkPaymentKind::Spontaneous {
                hash: PaymentHash([2; 32]),
                preimage: Some(PaymentPreimage([3; 32])),
            },
            amount_msat: Some(1000),
            fee_paid_msat: fee,
            direction: ldk_node::payment::PaymentDirection::Outbound,
            status: LdkPaymentStatus::Succeeded,
            latest_update_timestamp: 0,
        };
        let result = convert_payment_details(&details);
        assert_eq!(result.fee_msat, fee);
        assert_eq!(result.amount_msat, 1000);
        assert_eq!(result.status, PaymentStatus::Settled);
    }
}

fn ready_sync_status(now: u64) -> ldk_node::NodeStatus {
    ldk_node::NodeStatus {
        chain_sync_failure: None,
        is_running: true,
        current_best_block: ldk_node::lightning::chain::BestBlock::from_network(
            bitcoin::Network::Regtest,
        ),
        latest_lightning_wallet_sync_timestamp: Some(now),
        latest_lightning_wallet_sync: Some((0, now)),
        latest_onchain_wallet_sync_timestamp: Some(now),
        latest_fee_rate_cache_update_timestamp: Some(now),
        latest_rgs_snapshot_timestamp: None,
        latest_pathfinding_scores_sync_timestamp: None,
        latest_node_announcement_broadcast_timestamp: None,
        latest_channel_monitor_archival_height: None,
    }
}

#[test]
fn sync_readiness_uses_two_configured_periods_for_each_update() {
    let now = 10_000;
    for intervals in [
        BackgroundSyncConfig::default(),
        BackgroundSyncConfig {
            onchain_wallet_sync_interval_secs: 600,
            lightning_wallet_sync_interval_secs: 60,
            fee_rate_cache_update_interval_secs: 1800,
        },
    ] {
        for (wallet, period) in [
            (0, intervals.onchain_wallet_sync_interval_secs),
            (1, intervals.lightning_wallet_sync_interval_secs),
            (2, intervals.fee_rate_cache_update_interval_secs),
        ] {
            for (age, expected) in [(period, true), (period * 2, true), (period * 2 + 1, false)] {
                let mut status = ready_sync_status(now);
                let timestamp = match wallet {
                    0 => &mut status.latest_onchain_wallet_sync_timestamp,
                    1 => &mut status.latest_lightning_wallet_sync_timestamp,
                    _ => &mut status.latest_fee_rate_cache_update_timestamp,
                };
                *timestamp = Some(now - age);
                assert_eq!(
                    sync_status_is_ready(&status, (None, None), &intervals, now),
                    expected,
                    "wallet {wallet}, period {period}, age {age}"
                );
            }
        }
    }
}

#[test]
fn sync_readiness_still_requires_running_and_post_startup_syncs() {
    let now = 10_000;
    let intervals = BackgroundSyncConfig::default();
    let mut status = ready_sync_status(now);
    assert!(sync_status_is_ready(&status, (None, None), &intervals, now));
    for baseline in [(Some(now), None), (None, Some(now))] {
        assert!(!sync_status_is_ready(&status, baseline, &intervals, now));
    }
    status.is_running = false;
    assert!(!sync_status_is_ready(
        &status,
        (None, None),
        &intervals,
        now
    ));
    for wallet in 0..3 {
        let mut status = ready_sync_status(now);
        match wallet {
            0 => status.latest_onchain_wallet_sync_timestamp = None,
            1 => status.latest_lightning_wallet_sync_timestamp = None,
            _ => status.latest_fee_rate_cache_update_timestamp = None,
        }
        assert!(!sync_status_is_ready(
            &status,
            (None, None),
            &intervals,
            now
        ));
    }
}

#[test]
fn owner_funding_priorities_reach_the_expected_ldk_targets() {
    use konsensus_core::traits::lightning::FundingPriority;
    for (priority, blocks) in [
        (FundingPriority::Economy, 144),
        (FundingPriority::Normal, 12),
        (FundingPriority::Fast, 6),
    ] {
        assert_eq!(
            super::ldk_funding_priority(priority).confirmation_target_blocks(),
            blocks
        );
    }
}

// A stopped real node lets us observe dispatch without opening sockets. Missing
// estimates must not replace LDK's specific NotRunning refusal with a quote
// refusal. Checking the reason (not just PaymentNotDispatched) proves dispatch
// reached the real open call even after pre-dispatch error reclassification.
#[tokio::test]
async fn default_open_reaches_ldk_without_fee_estimates() {
    for network in [
        bitcoin::Network::Regtest,
        bitcoin::Network::Signet,
        bitcoin::Network::Bitcoin,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = ldk_node::Builder::new();
        builder.set_network(network);
        builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
        let node = Arc::new(builder.build().unwrap());
        let peer = node.node_id().to_string();
        let provider = LdkProvider::from_node(node);
        assert!(matches!(
            provider.funding_fee_quote(Default::default()).await,
            Err(LightningError::PaymentNotDispatched(_))
        ));
        let result = provider
            .open_channel_with_status(&peer, "127.0.0.1:9735", 100_000, false, None)
            .await;
        assert!(
            matches!(result, Err(LightningError::PaymentNotDispatched(ref reason))
            if reason.contains(&ldk_node::NodeError::NotRunning.to_string())),
            "{result:?}"
        );
    }
}

#[test]
fn offline_safety_checkpoint_never_uses_partial_best_block() {
    let mut status = ready_sync_status(10_000);
    status.latest_lightning_wallet_sync = Some((1000, 9_900));
    status.current_best_block.height = 1170;
    // The manager has advanced during scanning, but complete sync still stands at 1000.
    let checkpoint = offline_synced_block(&status).unwrap();
    assert_eq!((checkpoint.height, checkpoint.unix_secs), (1000, 9_900));
    // A loaded manager and persisted timestamps are not a sync in this process.
    status.latest_lightning_wallet_sync = None;
    assert!(offline_synced_block(&status).is_none());
    status.latest_lightning_wallet_sync = Some((1170, 10_000));
    assert_eq!(offline_synced_block(&status).unwrap().height, 1170);
    status.is_running = false;
    assert!(offline_synced_block(&status).is_none());
}

#[path = "ldk_late_failure.rs"]
mod late_failure;

#[test]
fn channel_push_reaches_opener_with_and_without_funding_policy() {
    // Obtain the opaque policy through the real estimator; its fields are private.
    let mut server = mockito::Server::new();
    let _fees = server
        .mock("GET", "/fee-estimates")
        .with_body(r#"{"1":2.0,"6":2.0,"144":2.0}"#)
        .create();
    let dir = tempfile::tempdir().unwrap();
    let mut builder = ldk_node::Builder::new();
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
    builder.set_chain_source_esplora(server.url(), None);
    let estimator = builder.build().unwrap();
    estimator.start().unwrap();
    let funding_policy = estimator
        .funding_fee_quote(ldk_node::funding::FundingPriority::Economy, Some(1000))
        .unwrap();
    estimator.stop().unwrap();
    for announce in [false, true] {
        for use_policy in [false, true] {
            let mut node = MockChannelOpener::new();
            node.expect_has_node_alias().return_const(true);
            node.expect_has_listening_addresses().return_const(true);
            let policy = use_policy.then(|| funding_policy.clone());
            if use_policy {
                node.expect_open_with_funding_policy()
                    .times(1)
                    .withf(move |peer, _, amount, public, policy, push| {
                        policy.priority() == ldk_node::funding::FundingPriority::Economy
                            && policy.max_fee_sats() == Some(1000)
                            && peer.to_string() == CHANNEL_PEER
                            && *amount == 50_000
                            && *public == announce
                            && *push == Some(10_000_000)
                    })
                    .returning(|_, _, _, _, _, _| Ok(ldk_node::UserChannelId(42)));
            } else if announce {
                node.expect_open_announced_channel()
                    .times(1)
                    .withf(|_, _, amount, push, _| *amount == 50_000 && *push == Some(10_000_000))
                    .returning(|_, _, _, _, _| Ok(ldk_node::UserChannelId(42)));
            } else {
                node.expect_open_channel()
                    .times(1)
                    .withf(|_, _, amount, push, _| *amount == 50_000 && *push == Some(10_000_000))
                    .returning(|_, _, _, _, _| Ok(ldk_node::UserChannelId(42)));
            }
            assert_eq!(
                open_ldk_channel_with_policy(
                    &node,
                    CHANNEL_PEER,
                    "127.0.0.1:9735",
                    50_000,
                    announce,
                    policy,
                    Some(10_000_000)
                )
                .unwrap()
                .0
                .to_string(),
                "42"
            );
        }
    }
}

#[test]
fn listed_ldk_ids_are_canonical_and_resolve_for_close() {
    let mut channel = test_channel_details();
    channel.user_channel_id = ldk_node::UserChannelId(u128::MAX);
    channel.channel_id = ldk_node::lightning::ln::types::ChannelId([0xab; 32]);
    channel.funding_txo = Some(bitcoin::OutPoint {
        txid: "cd".repeat(32).parse().unwrap(),
        vout: 1,
    });
    let listed = channel_info(channel.clone());
    assert_eq!(listed.initial_push_msat, Some(10_000_000));
    assert_eq!(listed.is_outbound, Some(true));
    assert_eq!(listed.is_channel_ready, Some(true));
    assert_eq!(listed.is_announced, Some(false));
    assert_eq!(listed.local_reserve_msat, None);
    assert_eq!(
        listed.user_channel_id.as_deref(),
        Some("340282366920938463463374607431768211455")
    );
    assert_eq!(listed.channel_id, "ab".repeat(32));
    assert_eq!(listed.funding_txo, Some(format!("{}:1", "cd".repeat(32))));
    assert!(listed.short_channel_id.is_none());
    for id in [
        listed.user_channel_id.unwrap(),
        listed.channel_id.clone(),
        listed.channel_id.to_uppercase(),
        "UserChannelId(340282366920938463463374607431768211455)".into(),
    ] {
        assert_eq!(
            resolve_channel_id(std::slice::from_ref(&channel), &id).unwrap(),
            channel.user_channel_id
        );
    }
    assert!(resolve_channel_id(std::slice::from_ref(&channel), &"ef".repeat(32)).is_err());
    channel.funding_txo = None;
    assert!(channel_info(channel).funding_txo.is_none());
}

#[tokio::test(start_paused = true)]
async fn successful_ldk_dispatch_reconciles_real_ids_without_502_parse_error() {
    // rc17 converted this returned ID to `UserChannelId(n)` then parsed it as
    // u128 AFTER dispatch. rc18 accepted that wrapper; keep the whole successful
    // dispatch -> pending -> broadcast-result path covered, including >u64 IDs.
    let mut opener = MockChannelOpener::new();
    opener
        .expect_open_channel()
        .times(1)
        .returning(|_, _, _, _, _| {
            Ok(ldk_node::UserChannelId(
                88160000000000000000000000000000000001,
            ))
        });
    let id = open_ldk_channel(
        &opener,
        CHANNEL_PEER,
        "127.0.0.1:9735",
        100_000,
        false,
        None,
    )
    .unwrap();
    let mut polls = 0;
    let result = finish_ldk_channel_open(
        id,
        |pending_id| {
            assert_eq!(pending_id.0, 88160000000000000000000000000000000001);
            polls += 1;
            let mut channel = test_channel_details();
            channel.user_channel_id = pending_id;
            channel.channel_id = ldk_node::lightning::ln::types::ChannelId([0xab; 32]);
            channel.funding_txo = (polls > 1).then(|| bitcoin::OutPoint {
                txid: "cd".repeat(32).parse().unwrap(),
                vout: 1,
            });
            Ok(channel)
        },
        |txid| async move {
            assert_eq!(txid, "cd".repeat(32));
            Ok(true)
        },
    )
    .await
    .unwrap();
    assert_eq!(
        result.user_channel_id.as_deref(),
        Some("88160000000000000000000000000000000001")
    );
    assert_eq!(result.channel_id, "ab".repeat(32));
    assert_eq!(result.funding_txo, Some(format!("{}:1", "cd".repeat(32))));
    assert_eq!(result.funding_txid, Some("cd".repeat(32)));
    assert_eq!(
        result.status,
        konsensus_core::traits::lightning::ChannelOpenStatus::Opening
    );
}

#[test]
fn channel_open_pre_dispatch_refusals_release_the_operation() {
    use ldk_node::NodeError as E;
    for error in [
        E::InsufficientFunds,
        E::ConnectionFailed,
        E::InvalidSocketAddress,
        E::NotRunning,
        E::ChannelCreationFailed,
        E::ChannelCapacityExceeded,
        E::TotalChannelCapacityExceeded,
    ] {
        for announce in [false, true] {
            let mut node = MockChannelOpener::new();
            node.expect_has_node_alias().return_const(true);
            node.expect_has_listening_addresses().return_const(true);
            if announce {
                node.expect_open_announced_channel()
                    .times(1)
                    .return_once(move |_, _, _, _, _| Err(error));
            } else {
                node.expect_open_channel()
                    .times(1)
                    .return_once(move |_, _, _, _, _| Err(error));
            }
            let result = open_ldk_channel(
                &node,
                CHANNEL_PEER,
                "127.0.0.1:9735",
                50_000,
                announce,
                None,
            );
            assert!(
                matches!(&result, Err(LightningError::PaymentNotDispatched(reason)) if reason.contains(&error.to_string())),
                "{error:?}: {result:?}"
            );
        }
    }
}

#[test]
fn starter_open_and_ready_info_logs_exclude_lightning_identity_and_socket() {
    // Other tests execute these callsites without a subscriber. Isolate their
    // process-wide interest cache from this thread-local capture.
    const CHILD: &str = "BITSOV_STARTER_LOG_CAPTURE_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ldk::tests::starter_open_and_ready_info_logs_exclude_lightning_identity_and_socket", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    #[derive(Clone)]
    struct Capture(Arc<std::sync::Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let bytes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let writer = Capture(bytes.clone());
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let mut opener = MockChannelOpener::new();
        opener
            .expect_open_channel()
            .times(1)
            .returning(|_, _, _, _, _| Ok(ldk_node::UserChannelId(42)));
        open_ldk_channel_with_policy(
            &opener,
            CHANNEL_PEER,
            "192.0.2.23:9735",
            100_000,
            false,
            None,
            Some(10_000_000),
        )
        .unwrap();
        LdkProvider::log_event(&ldk_node::Event::ChannelReady {
            channel_id: ldk_node::lightning::ln::types::ChannelId([1; 32]),
            user_channel_id: ldk_node::UserChannelId(42),
            counterparty_node_id: Some(CHANNEL_PEER.parse().unwrap()),
            funding_txo: None,
        });
    });
    let log = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
    assert!(log.contains("opening initiated") && log.contains("channel ready"));
    assert!(!log.contains(CHANNEL_PEER));
    assert!(!log.contains("192.0.2.23"));
}

#[test]
fn invoice_expiry_atomic_replace_failure_preserves_previous_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("expiry.tsv");
    let before = std::collections::HashMap::from([("11".repeat(32), 123)]);
    store_invoice_expiries(&path, &before).unwrap();
    // Fail creation of the same-directory staging file, before replacement.
    std::fs::create_dir(path.with_extension("tmp")).unwrap();
    let after = std::collections::HashMap::from([("22".repeat(32), 456)]);
    assert!(store_invoice_expiries(&path, &after).is_err());
    assert_eq!(load_invoice_expiries(&path).unwrap(), before);
    std::fs::remove_dir(path.with_extension("tmp")).unwrap();
    store_invoice_expiries(&path, &after).unwrap();
    assert_eq!(load_invoice_expiries(&path).unwrap(), after);
}

#[tokio::test]
async fn invoice_persistence_failure_refuses_and_removes_unpublished_invoice() {
    let dir = tempfile::tempdir().unwrap();
    let mut builder = ldk_node::Builder::new();
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
    let node = Arc::new(builder.build().unwrap());
    let mut provider = LdkProvider::from_node(node.clone());
    let path = dir.path().join("expiry.tsv");
    std::fs::create_dir(path.with_extension("tmp")).unwrap();
    provider.invoice_expiry_path = Some(path);
    assert!(provider
        .create_invoice(1000, "unpublished", 120)
        .await
        .is_err());
    assert!(node.list_payments().is_empty());
    assert!(provider
        .pending_invoice_expiries()
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn invoice_restart_reconciles_missing_metadata_and_discards_orphan_sidecar_rows() {
    let dir = tempfile::tempdir().unwrap();
    let mut builder = ldk_node::Builder::new();
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_entropy_seed_bytes([45; 64]);
    builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
    let node = Arc::new(builder.build().unwrap());
    let provider = LdkProvider::from_node(node.clone());
    let invoice = provider.create_invoice(1000, "restart", 120).await.unwrap();
    drop(provider);
    drop(node);
    let node = builder.build().unwrap();
    let path = dir.path().join("expiry.tsv");
    // Simulate a legacy truncated sidecar: unrelated valid line and partial hash.
    std::fs::write(&path, format!("{} 10\npartial", "ff".repeat(32))).unwrap();
    let map = reconcile_invoice_expiries(&node, load_invoice_expiries(&path).unwrap());
    assert_eq!(map.len(), 1);
    assert!(map[&invoice.payment_hash] >= invoice.created_at + 120);
    store_invoice_expiries(&path, &map).unwrap();
    assert_eq!(load_invoice_expiries(&path).unwrap(), map);
}

#[test]
fn legacy_orphan_expiry_guess_is_clamped_for_service_caps() {
    let timestamp = 1_700_000_000u64;
    let legacy = timestamp.saturating_add(u64::from(u32::MAX));
    assert_eq!(
        super::migrate_service_invoice_expiry(Some(legacy), timestamp),
        timestamp.saturating_add(120)
    );
}

#[test]
fn missing_invoice_expiry_is_backfilled_from_creation_and_not_due() {
    let created = 1_700_000_000u64;
    let expires = super::migrate_service_invoice_expiry(None, created);
    // Purge deletes when `expires_at <= now`. The short orphan window is
    // already due at creation+120; the pre-upgrade hour must still be open.
    let short_window = created.saturating_add(super::SERVICE_INVOICE_ORPHAN_SECS);
    assert!(
        short_window < expires,
        "cleanup at the short orphan window must not delete a pre-upgrade invoice"
    );
    assert_eq!(
        expires,
        created.saturating_add(super::LEGACY_SERVICE_INVOICE_EXPIRY_SECS)
    );
}

#[tokio::test]
async fn invoice_restart_does_not_trust_truncated_numeric_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let mut builder = ldk_node::Builder::new();
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
    let node = Arc::new(builder.build().unwrap());
    let provider = LdkProvider::from_node(node.clone());
    let invoice = provider
        .create_invoice(1000, "truncated timestamp", 120)
        .await
        .unwrap();
    let path = dir.path().join("expiry.tsv");
    std::fs::write(&path, format!("{} 1792", invoice.payment_hash)).unwrap();
    let map = reconcile_invoice_expiries(&node, load_invoice_expiries(&path).unwrap());
    assert!(map[&invoice.payment_hash] >= invoice.created_at + 120);
}
