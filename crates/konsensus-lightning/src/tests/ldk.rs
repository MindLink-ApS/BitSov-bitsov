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
