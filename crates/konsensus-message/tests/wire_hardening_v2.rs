//! Hardening tests v2 — wire protocol framing boundaries, frame variant coverage,
//! large payload handling, PeerRegistry stress, and edge cases.
//!
//! Focus areas:
//! - Frame encoding/decoding for all variants with edge-case data
//! - Large frames near MAX_FRAME_SIZE boundary
//! - Hello/HelloAck federation handshake with varying capabilities
//! - PeerExchangeEntry with edge addresses
//! - PeerRegistry capacity, replace, and concurrent-like access patterns
//! - UkmEnvelope frame with large ciphertext
//! - Frame::to_bytes / from_bytes consistency

use konsensus_core::types::{NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_message::wire::*;
use konsensus_message::{PeerEntry, PeerRegistry};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

fn make_node_id(seed: u8) -> NodeId {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    NodeId::from_verifying_key(&signing.verifying_key())
}

fn make_test_envelope() -> konsensus_core::envelope::UkmEnvelope {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 10);

    UkmEnvelopeBuilder::new(
        0,
        NodeId::from_bytes([1u8; 32]),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        b"encrypted content".to_vec(),
        proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build()
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELLO / HELLOACK — FEDERATION HANDSHAKE EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn hello_empty_capabilities() {
    let frame = Frame::Hello {
        version: 2,
        node_id: make_node_id(1),
        x25519_sig: vec![0u8; 64],
        x25519_public: vec![0u8; 32],
        tier: SovereigntyTier::T1,
        capabilities: vec![],
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Hello { capabilities, version, tier, .. } => {
            assert!(capabilities.is_empty());
            assert_eq!(version, 2);
            assert_eq!(tier, SovereigntyTier::T1);
        }
        _ => panic!("expected Hello"),
    }
}

#[test]
fn hello_ack_roundtrip() {
    let frame = Frame::HelloAck {
        version: 2,
        node_id: make_node_id(2),
        x25519_sig: vec![0xAA; 64],
        x25519_public: vec![0xBB; 32],
        tier: SovereigntyTier::T4,
        capabilities: vec![Capability::X3dh, Capability::FileTransfer],
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::HelloAck { version, tier, capabilities, x25519_sig, x25519_public, .. } => {
            assert_eq!(version, 2);
            assert_eq!(tier, SovereigntyTier::T4);
            assert_eq!(capabilities.len(), 2);
            assert_eq!(x25519_sig.len(), 64);
            assert_eq!(x25519_public.len(), 32);
        }
        _ => panic!("expected HelloAck"),
    }
}

#[test]
fn hello_with_custom_capabilities() {
    let frame = Frame::Hello {
        version: 2,
        node_id: make_node_id(3),
        x25519_sig: vec![],
        x25519_public: vec![],
        tier: SovereigntyTier::T3,
        capabilities: vec![
            Capability::Custom("my-app-v1".to_string()),
            Capability::Custom("".to_string()), // empty custom capability
            Capability::Pqxdh,
        ],
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Hello { capabilities, .. } => {
            assert_eq!(capabilities.len(), 3);
            assert!(capabilities.contains(&Capability::Custom("my-app-v1".to_string())));
            assert!(capabilities.contains(&Capability::Custom("".to_string())));
        }
        _ => panic!("expected Hello"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PREKEY / SESSION FRAMES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn prekey_offer_roundtrip() {
    let bundle = serde_json::json!({
        "identity_key": "aabbccdd",
        "signed_prekey": "11223344",
        "signed_prekey_sig": "deadbeef",
        "node_id": "00112233",
    });
    let frame = Frame::PrekeyOffer { bundle: bundle.clone() };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PrekeyOffer { bundle: decoded_bundle } => {
            assert_eq!(decoded_bundle, bundle);
        }
        _ => panic!("expected PrekeyOffer"),
    }
}

#[test]
fn session_init_roundtrip() {
    let init_data = serde_json::json!({
        "identity_key": "aabb",
        "ephemeral_key": "ccdd",
        "one_time_prekey_id": 42,
    });
    let frame = Frame::SessionInit { init_data: init_data.clone() };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::SessionInit { init_data: decoded } => assert_eq!(decoded, init_data),
        _ => panic!("expected SessionInit"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// INVOICE FRAMES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn request_invoice_zero_amount() {
    let frame = Frame::RequestInvoice {
        request_id: "req-zero".to_string(),
        amount_msat: 0,
        purpose: "free tier".to_string(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::RequestInvoice { request_id, amount_msat, purpose } => {
            assert_eq!(request_id, "req-zero");
            assert_eq!(amount_msat, 0);
            assert_eq!(purpose, "free tier");
        }
        _ => panic!("expected RequestInvoice"),
    }
}

#[test]
fn request_invoice_max_amount() {
    let frame = Frame::RequestInvoice {
        request_id: "req-max".to_string(),
        amount_msat: u64::MAX,
        purpose: "stress test".to_string(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::RequestInvoice { request_id, amount_msat, .. } => {
            assert_eq!(request_id, "req-max");
            assert_eq!(amount_msat, u64::MAX);
        }
        _ => panic!("expected RequestInvoice"),
    }
}

#[test]
fn invoice_response_roundtrip() {
    let frame = Frame::InvoiceResponse {
        request_id: "req-roundtrip".to_string(),
        bolt11: "lnbc10n1pj...long_bolt11_string".to_string(),
        payment_hash: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            .to_string(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::InvoiceResponse { request_id, bolt11, payment_hash } => {
            assert_eq!(request_id, "req-roundtrip");
            assert!(bolt11.starts_with("lnbc"));
            assert_eq!(payment_hash.len(), 64);
        }
        _ => panic!("expected InvoiceResponse"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PRICE FRAMES — EDGE VALUES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn price_table_empty_prices() {
    let frame = Frame::PriceTable {
        prices: HashMap::new(),
        block_height: 0,
        valid_blocks: 0,
        trust_discount: 0.0,
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PriceTable { prices, block_height, valid_blocks, trust_discount: _ } => {
            assert!(prices.is_empty());
            assert_eq!(block_height, 0);
            assert_eq!(valid_blocks, 0);
        }
        _ => panic!("expected PriceTable"),
    }
}

#[test]
fn price_table_many_categories() {
    let mut prices = HashMap::new();
    for i in 0..20u64 {
        prices.insert(format!("category_{i}"), i * 100);
    }
    let frame = Frame::PriceTable {
        prices: prices.clone(),
        block_height: u64::MAX,
        valid_blocks: u32::MAX,
        trust_discount: 0.0,
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PriceTable { prices: dp, block_height, valid_blocks, trust_discount: _ } => {
            assert_eq!(dp.len(), 20);
            assert_eq!(block_height, u64::MAX);
            assert_eq!(valid_blocks, u32::MAX);
            assert_eq!(dp["category_5"], 500);
        }
        _ => panic!("expected PriceTable"),
    }
}

#[test]
fn price_query_kind_zero() {
    let frame = Frame::PriceQuery { kind: 0 };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PriceQuery { kind } => assert_eq!(kind, 0),
        _ => panic!("expected PriceQuery"),
    }
}

#[test]
fn price_query_kind_max() {
    let frame = Frame::PriceQuery { kind: u16::MAX };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PriceQuery { kind } => assert_eq!(kind, u16::MAX),
        _ => panic!("expected PriceQuery"),
    }
}

#[test]
fn price_response_zero_price() {
    let frame = Frame::PriceResponse {
        kind: 100,
        price_msat: 0,
        block_height: 942_000,
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PriceResponse { price_msat, .. } => assert_eq!(price_msat, 0),
        _ => panic!("expected PriceResponse"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PEER EXCHANGE — EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn peer_exchange_response_empty() {
    let frame = Frame::PeerExchangeResponse { peers: vec![] };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PeerExchangeResponse { peers } => assert!(peers.is_empty()),
        _ => panic!("expected PeerExchangeResponse"),
    }
}

#[test]
fn peer_exchange_response_many_peers() {
    let peers: Vec<PeerExchangeEntry> = (1..=50u8)
        .map(|i| PeerExchangeEntry {
            node_id: make_node_id(i),
            addr: format!("10.0.0.{i}:9735").parse().unwrap(),
            label: Some(format!("node-{i}")),
            tier: SovereigntyTier::T2,
        })
        .collect();

    let frame = Frame::PeerExchangeResponse { peers: peers.clone() };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PeerExchangeResponse { peers: dp } => {
            assert_eq!(dp.len(), 50);
            assert_eq!(dp[0].label.as_deref(), Some("node-1"));
            assert_eq!(dp[49].label.as_deref(), Some("node-50"));
        }
        _ => panic!("expected PeerExchangeResponse"),
    }
}

#[test]
fn peer_exchange_entry_no_label() {
    let entry = PeerExchangeEntry {
        node_id: make_node_id(1),
        addr: "127.0.0.1:9735".parse().unwrap(),
        label: None,
        tier: SovereigntyTier::T1,
    };
    let frame = Frame::PeerExchangeResponse { peers: vec![entry] };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PeerExchangeResponse { peers } => {
            assert!(peers[0].label.is_none());
        }
        _ => panic!("expected PeerExchangeResponse"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// FRAME::TO_BYTES / FROM_BYTES CONSISTENCY
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn frame_to_bytes_from_bytes_ping() {
    let frame = Frame::Ping { nonce: 42 };
    let bytes = frame.to_bytes().unwrap();
    let restored = Frame::from_bytes(&bytes).unwrap();
    match restored {
        Frame::Ping { nonce } => assert_eq!(nonce, 42),
        _ => panic!("expected Ping"),
    }
}

#[test]
fn frame_to_bytes_from_bytes_disconnect() {
    let frame = Frame::Disconnect {
        reason: "maintenance window".to_string(),
    };
    let bytes = frame.to_bytes().unwrap();
    let restored = Frame::from_bytes(&bytes).unwrap();
    match restored {
        Frame::Disconnect { reason } => assert_eq!(reason, "maintenance window"),
        _ => panic!("expected Disconnect"),
    }
}

#[test]
fn frame_to_bytes_from_bytes_message() {
    let env = make_test_envelope();
    let frame = Frame::Message(Box::new(env.clone()));
    let bytes = frame.to_bytes().unwrap();
    let restored = Frame::from_bytes(&bytes).unwrap();
    match restored {
        Frame::Message(decoded_env) => assert_eq!(*decoded_env, env),
        _ => panic!("expected Message"),
    }
}

#[test]
fn frame_from_bytes_empty_fails() {
    let err = Frame::from_bytes(&[]).unwrap_err();
    assert!(matches!(err, WireError::Serialization(_)));
}

#[test]
fn frame_from_bytes_garbage_fails() {
    let err = Frame::from_bytes(b"}}}}not json{{{{").unwrap_err();
    assert!(matches!(err, WireError::Serialization(_)));
}

// ═══════════════════════════════════════════════════════════════════════════════
// ENCODE / DECODE — BOUNDARY CONDITIONS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn encode_frame_size_is_correct() {
    let frame = Frame::Ping { nonce: 1 };
    let encoded = encode_frame(&frame).unwrap();

    // First 4 bytes are the length prefix
    let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
    assert_eq!(len, encoded.len() - 4);
}

#[test]
fn decode_consumed_bytes_correct() {
    let frame = Frame::Pong { nonce: 99 };
    let encoded = encode_frame(&frame).unwrap();

    // Append extra garbage bytes
    let mut buf = encoded.clone();
    buf.extend_from_slice(b"EXTRA_GARBAGE");

    let (decoded, consumed) = decode_frame(&buf).unwrap().unwrap();
    assert_eq!(consumed, encoded.len());
    assert!(matches!(decoded, Frame::Pong { nonce: 99 }));
}

#[test]
fn decode_frame_exact_max_size() {
    // Create a frame that's just under MAX_FRAME_SIZE
    // A Disconnect with a very long reason string
    let reason = "x".repeat(1024 * 1024); // 1 MiB reason string
    let frame = Frame::Disconnect { reason: reason.clone() };
    let encoded = encode_frame(&frame).unwrap();

    // Should decode successfully
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Disconnect { reason: r } => assert_eq!(r.len(), 1024 * 1024),
        _ => panic!("expected Disconnect"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// UKM ENVELOPE IN FRAMES — LARGE PAYLOADS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn message_frame_with_large_ciphertext() {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 10);

    // 100 KB ciphertext
    let large_ct = vec![0xABu8; 100 * 1024];

    let env = UkmEnvelopeBuilder::new(
        200, // KIND_FILE_REF
        NodeId::from_bytes([1u8; 32]),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        large_ct.clone(),
        proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build();

    let frame = Frame::Message(Box::new(env));
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Message(decoded_env) => {
            assert_eq!(decoded_env.ciphertext.len(), large_ct.len());
        }
        _ => panic!("expected Message"),
    }
}

#[test]
fn message_frame_with_room_recipient() {
    use konsensus_core::types::RoomId;

    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 10);

    let room_id = RoomId::new();
    let env = UkmEnvelopeBuilder::new(
        0,
        NodeId::from_bytes([1u8; 32]),
        Recipient::Room(room_id),
        b"room message".to_vec(),
        proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build();

    let frame = Frame::Message(Box::new(env));
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Message(decoded_env) => {
            assert!(matches!(decoded_env.recipient, Recipient::Room(_)));
        }
        _ => panic!("expected Message"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PEER REGISTRY — ADDITIONAL EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

fn make_entry(seed: u8, port: u16, auto_connect: bool) -> PeerEntry {
    PeerEntry {
        node_id: make_node_id(seed),
        addr: format!("10.0.0.{seed}:{port}").parse().unwrap(),
        label: Some(format!("node-{seed}")),
        auto_connect,
    }
}

#[test]
fn peer_registry_overwrite_same_node_id() {
    let mut reg = PeerRegistry::new();
    let entry1 = make_entry(1, 9735, true);
    let node_id = entry1.node_id;
    reg.add(entry1);

    // Add same node_id with different address
    let mut entry2 = make_entry(1, 9999, false);
    entry2.label = Some("updated-label".to_string());
    reg.add(entry2);

    // Registry should still have 1 entry (overwritten)
    assert_eq!(reg.len(), 1);
    let entry = reg.get(&node_id).unwrap();
    assert_eq!(entry.addr.port(), 9999);
}

#[test]
fn peer_registry_update_addr_existing() {
    let mut reg = PeerRegistry::new();
    let entry = make_entry(1, 9735, true);
    let node_id = entry.node_id;
    reg.add(entry);

    let new_addr = "192.168.1.100:8080".parse().unwrap();
    assert!(reg.update_addr(&node_id, new_addr));

    let updated = reg.get(&node_id).unwrap();
    assert_eq!(updated.addr, new_addr);
}

#[test]
fn peer_registry_whitelist_matches_all_peers() {
    let mut reg = PeerRegistry::new();
    for i in 1..=10u8 {
        reg.add(make_entry(i, 9735, i % 2 == 0));
    }

    let whitelist = reg.whitelist();
    assert_eq!(whitelist.len(), 10); // all peers in whitelist regardless of auto_connect

    let auto = reg.auto_connect_peers();
    assert_eq!(auto.len(), 5); // only even-numbered peers
}

#[test]
fn peer_registry_empty_operations() {
    let reg = PeerRegistry::new();
    assert_eq!(reg.len(), 0);
    assert!(reg.whitelist().is_empty());
    assert!(reg.auto_connect_peers().is_empty());
    assert!(reg.all().is_empty());
}

#[test]
fn peer_registry_remove_returns_entry() {
    let mut reg = PeerRegistry::new();
    let entry = make_entry(1, 9735, true);
    let node_id = entry.node_id;
    reg.add(entry.clone());

    let removed = reg.remove(&node_id);
    assert!(removed.is_some());
    assert_eq!(removed.unwrap().node_id, node_id);
    assert_eq!(reg.len(), 0);
}

// ═══════════════════════════════════════════════════════════════════════════════
// WIRE ERROR VARIANTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn wire_error_display_frame_too_large() {
    let err = WireError::FrameTooLarge {
        size: 20_000_000,
        max: MAX_FRAME_SIZE,
    };
    let msg = err.to_string();
    assert!(msg.contains("20000000"));
    assert!(msg.contains(&MAX_FRAME_SIZE.to_string()));
}

#[test]
fn wire_error_display_serialization() {
    let err = WireError::Serialization("bad json".to_string());
    assert!(err.to_string().contains("bad json"));
}

#[test]
fn wire_error_display_incomplete_frame() {
    let err = WireError::IncompleteFrame {
        expected: 100,
        got: 50,
    };
    let msg = err.to_string();
    assert!(msg.contains("100"));
    assert!(msg.contains("50"));
}

#[test]
fn wire_error_display_invalid_frame() {
    let err = WireError::InvalidFrame("unknown variant".to_string());
    assert!(err.to_string().contains("unknown variant"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SOVEREIGNTY TIER SERDE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sovereignty_tier_serde_all_variants() {
    for tier in [
        SovereigntyTier::T1,
        SovereigntyTier::T2,
        SovereigntyTier::T3,
        SovereigntyTier::T4,
    ] {
        let json = serde_json::to_string(&tier).unwrap();
        let restored: SovereigntyTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, restored);
    }
}

#[test]
fn capability_serde_all_variants() {
    let caps = vec![
        Capability::Pqxdh,
        Capability::X3dh,
        Capability::Mls,
        Capability::FileTransfer,
        Capability::Custom("test".to_string()),
    ];
    for cap in &caps {
        let json = serde_json::to_string(cap).unwrap();
        let restored: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(*cap, restored);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// RATCHET INIT AND DISCONNECT — UNICODE / SPECIAL CHARS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn disconnect_reason_unicode() {
    let frame = Frame::Disconnect {
        reason: "节点关闭 — going offline 🔒".to_string(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Disconnect { reason } => assert!(reason.contains("节点关闭")),
        _ => panic!("expected Disconnect"),
    }
}

#[test]
fn disconnect_reason_empty() {
    let frame = Frame::Disconnect {
        reason: "".to_string(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Disconnect { reason } => assert!(reason.is_empty()),
        _ => panic!("expected Disconnect"),
    }
}

#[test]
fn ratchet_init_large_payload() {
    let payload = vec![0xFFu8; 64 * 1024]; // 64 KB
    let frame = Frame::RatchetInit { payload: payload.clone() };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::RatchetInit { payload: dp } => assert_eq!(dp.len(), 64 * 1024),
        _ => panic!("expected RatchetInit"),
    }
}

#[test]
fn ratchet_init_empty_payload() {
    let frame = Frame::RatchetInit { payload: vec![] };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::RatchetInit { payload } => assert!(payload.is_empty()),
        _ => panic!("expected RatchetInit"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PING/PONG BOUNDARY VALUES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn ping_pong_zero_nonce() {
    let frame = Frame::Ping { nonce: 0 };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    assert!(matches!(decoded, Frame::Ping { nonce: 0 }));
}

#[test]
fn ping_pong_max_nonce() {
    let frame = Frame::Ping { nonce: u64::MAX };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    assert!(matches!(decoded, Frame::Ping { nonce } if nonce == u64::MAX));
}
