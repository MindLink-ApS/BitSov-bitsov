use bitcoin::hashes::{sha256, Hash};
use konsensus_message::wire::{Frame, MAX_BOLT11_BYTES};
use lightning_invoice::{
    Currency, InvoiceBuilder, PaymentSecret, RouteHint, RouteHintHop, RoutingFees,
};

#[test]
fn signed_bolt11_with_many_route_hints_fits_wire_cap() {
    let secp = secp256k1::Secp256k1::new();
    let key = secp256k1::SecretKey::from_slice(&[7; 32]).unwrap();
    let hop = RouteHintHop {
        src_node_id: secp256k1::PublicKey::from_secret_key(&secp, &key),
        short_channel_id: 1,
        fees: RoutingFees {
            base_msat: 1,
            proportional_millionths: 100,
        },
        cltv_expiry_delta: 18,
        htlc_minimum_msat: None,
        htlc_maximum_msat: None,
    };
    let mut builder = InvoiceBuilder::new(Currency::Regtest)
        .description("long invoice with private routing alternatives".into())
        .payment_hash(sha256::Hash::from_byte_array([42; 32]))
        .payment_secret(PaymentSecret([43; 32]))
        .duration_since_epoch(std::time::Duration::from_secs(1_700_000_000))
        .min_final_cltv_expiry_delta(18)
        .amount_milli_satoshis(1000);
    // A deliberately generous stress case: 6 alternatives of 12 private hops.
    // Each route is within BOLT11's tagged-field limit, and the whole invoice
    // fits this lightning-invoice version's 7089-character checksum-code limit.
    for _ in 0..6 {
        builder = builder.private_route(RouteHint(vec![hop.clone(); 12]));
    }
    let invoice = builder
        .build_signed(|msg| secp.sign_ecdsa_recoverable(msg, &key))
        .unwrap();
    let bolt11 = invoice.to_string();
    assert!(bolt11.len() > 4 * 1024 && bolt11.len() < MAX_BOLT11_BYTES);
    let parsed: lightning_invoice::Bolt11Invoice = bolt11.parse().unwrap();
    assert_eq!(parsed.route_hints().len(), 6);
    let frame = Frame::InvoiceResponse {
        request_id: "route-hints".into(),
        bolt11: bolt11.clone(),
        payment_hash: "2a".repeat(32),
    };
    assert!(
        matches!(Frame::from_bytes(&frame.to_bytes().unwrap()).unwrap(),
        Frame::InvoiceResponse { bolt11: decoded, .. } if decoded == bolt11)
    );
}

#[test]
fn encrypted_file_payload_retains_base64_and_ratchet_headroom() {
    use base64::Engine;
    use konsensus_core::types::{NodeId, PaymentProof, Recipient};
    use konsensus_core::UkmEnvelopeBuilder;
    use konsensus_crypto::{ratchet_message_to_bytes, DoubleRatchet};

    for file_bytes in [3 * 1024 * 1024, konsensus_api::file_staging::MAX_FILE_BYTES] {
        let payload = konsensus_api::handlers::files::FilePayload {
            filename: "large.bin".into(),
            mime_type: "application/octet-stream".into(),
            size_bytes: file_bytes as u64,
            blake3_hash: "00".repeat(32),
            data_b64: base64::engine::general_purpose::STANDARD.encode(vec![0; file_bytes]),
        };
        let plaintext = serde_json::to_vec(&payload).unwrap();
        let peer_key = konsensus_crypto::x3dh::SignedPreKey::generate();
        let mut ratchet = DoubleRatchet::init_sender(&[42; 32], &peer_key.public, vec![]).unwrap();
        let ciphertext = ratchet_message_to_bytes(&ratchet.encrypt(&plaintext).unwrap());
        assert!(ciphertext.len() > 4 * 1024 * 1024);
        let envelope = UkmEnvelopeBuilder::new(
            100,
            NodeId::from_bytes([0; 32]),
            Recipient::Broadcast,
            ciphertext,
            PaymentProof::new([0; 32], [0; 32], 1),
        )
        .build();
        let frame = Frame::Message(Box::new(envelope));
        let bytes = frame.to_bytes().unwrap();
        // 3 MiB files fitted the existing outer wire cap and must keep doing so.
        // The maximum 4 MiB upload is tested here for per-field headroom only;
        // the unchanged outer cap still applies to its larger JSON byte array.
        if file_bytes == 3 * 1024 * 1024 {
            assert!(bytes.len() < konsensus_message::wire::MAX_FRAME_BYTES);
        }
        Frame::from_bytes(&bytes).unwrap();
    }
}
