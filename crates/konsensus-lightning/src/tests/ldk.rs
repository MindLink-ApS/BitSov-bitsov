use super::*;

#[test]
fn parse_network_variants() {
    assert_eq!(parse_network("bitcoin").unwrap(), bitcoin::Network::Bitcoin);
    assert_eq!(parse_network("mainnet").unwrap(), bitcoin::Network::Bitcoin);
    assert_eq!(
        parse_network("testnet").unwrap(),
        bitcoin::Network::Testnet
    );
    assert_eq!(parse_network("signet").unwrap(), bitcoin::Network::Signet);
    assert_eq!(
        parse_network("regtest").unwrap(),
        bitcoin::Network::Regtest
    );
    assert!(parse_network("invalid").is_err());
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
    let config = LdkConfig {
        liquidity: Default::default(),
        storage_dir: PathBuf::from("/tmp/ldk_test"),
        scb_backup_dir: None,
        scb_rotation_count: 24,
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        passphrase: None,
        network: "regtest".to_string(),
        esplora_url: "http://localhost:3002".to_string(),
        esplora_url_fallback: None,
        rgs_url: None,
        lsp_node_id: None,
        lsp_address: None,
        lsp_token: None,
        listening_address: None,
    };
    assert_eq!(config.network, "regtest");
    assert!(config.lsp_node_id.is_none());
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
        liquidity: Default::default(),
        storage_dir: PathBuf::from("/tmp/ldk_test"),
        scb_backup_dir: None,
        scb_rotation_count: 24,
        mnemonic: "not a valid mnemonic".to_string(),
        passphrase: None,
        network: "regtest".to_string(),
        esplora_url: "http://localhost:3002".to_string(),
        esplora_url_fallback: None,
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
    assert!(result.preimage.is_none(), "pending payment should have no preimage");
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
                hash: PaymentHash([70; 32]), preimage: Some(PaymentPreimage([71; 32])),
                secret: Some(PaymentSecret([72; 32])), counterparty_skimmed_fee_msat: fee,
                lsp_fee_limits: LSPFeeLimits { max_total_opening_fee_msat: Some(2_000), max_proportional_opening_fee_ppm_msat: None },
            },
            amount_msat: Some(100_000 - fee.unwrap_or(0)), fee_paid_msat: None,
            direction: ldk_node::payment::PaymentDirection::Inbound,
            status: LdkPaymentStatus::Succeeded, latest_update_timestamp: 1_700_000_000,
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
        .current_timestamp().min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(1000)
        .build_signed(|h| secp.sign_ecdsa_recoverable(h, &key)).unwrap();
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
    for error in [NodeError::PaymentSendingFailed, NodeError::InvalidInvoice,
        NodeError::InvalidAmount, NodeError::InvalidCustomTlvs, NodeError::NotRunning] {
        let capable = std::sync::atomic::AtomicBool::new(true);
        assert!(matches!(super::classify_dispatch_error(error, &capable), LightningError::PaymentNotDispatched(_)));
        assert!(capable.load(std::sync::atomic::Ordering::Relaxed));
    }
    for error in [NodeError::PersistenceFailed, NodeError::DuplicatePayment] {
        assert!(matches!(super::classify_dispatch_error(error, &std::sync::atomic::AtomicBool::new(true)), LightningError::PaymentFailed(_)));
    }
}
