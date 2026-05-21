//! Hardening tests for konsensus-message — wire protocol framing edge cases,
//! frame serialization boundaries, peer registry concurrency patterns,
//! and transport config validation.

use konsensus_core::types::{MessageId, NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_message::wire::*;
use konsensus_message::{PeerEntry, PeerRegistry};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════════════════════
// WIRE PROTOCOL — FRAME ENCODING/DECODING EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

fn make_test_envelope() -> konsensus_core::envelope::UkmEnvelope {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 10);

    UkmEnvelopeBuilder::new(
        0, // KIND_CHAT
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

#[test]
fn encode_decode_roundtrip_ping() {
    let frame = Frame::Ping { nonce: 12345 };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, consumed) = decode_frame(&encoded).unwrap().unwrap();
    assert_eq!(consumed, encoded.len());
    match decoded {
        Frame::Ping { nonce } => assert_eq!(nonce, 12345),
        _ => panic!("expected Ping"),
    }
}

#[test]
fn encode_decode_roundtrip_pong() {
    let frame = Frame::Pong { nonce: 99999 };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Pong { nonce } => assert_eq!(nonce, 99999),
        _ => panic!("expected Pong"),
    }
}

#[test]
fn encode_decode_roundtrip_disconnect() {
    let frame = Frame::Disconnect {
        reason: "shutting down".to_string(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Disconnect { reason } => assert_eq!(reason, "shutting down"),
        _ => panic!("expected Disconnect"),
    }
}

#[test]
fn encode_decode_roundtrip_session_ack() {
    let frame = Frame::SessionAck;
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    assert!(matches!(decoded, Frame::SessionAck));
}

#[test]
fn encode_decode_roundtrip_message_ack() {
    let id = MessageId::from_bytes([0xBB; 32]);
    let frame = Frame::MessageAck { id };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::MessageAck { id: decoded_id } => assert_eq!(decoded_id, id),
        _ => panic!("expected MessageAck"),
    }
}

#[test]
fn encode_decode_roundtrip_message_reject() {
    let id = MessageId::from_bytes([0xCC; 32]);
    let frame = Frame::MessageReject {
        id,
        reason: "insufficient payment".to_string(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::MessageReject {
            id: decoded_id,
            reason,
        } => {
            assert_eq!(decoded_id, id);
            assert_eq!(reason, "insufficient payment");
        }
        _ => panic!("expected MessageReject"),
    }
}

#[test]
fn encode_decode_roundtrip_price_table() {
    let mut prices = HashMap::new();
    prices.insert("communication".to_string(), 10u64);
    prices.insert("files_media".to_string(), 100u64);

    let frame = Frame::PriceTable {
        prices,
        block_height: 942_000,
        valid_blocks: 144,
        trust_discount: 0.0,
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PriceTable {
            prices,
            block_height,
            valid_blocks,
            trust_discount: _,
        } => {
            assert_eq!(block_height, 942_000);
            assert_eq!(valid_blocks, 144);
            assert_eq!(prices["communication"], 10);
            assert_eq!(prices["files_media"], 100);
        }
        _ => panic!("expected PriceTable"),
    }
}

#[test]
fn encode_decode_roundtrip_request_invoice() {
    let frame = Frame::RequestInvoice {
        request_id: "req-page-001".to_string(),
        amount_msat: 25_000,
        purpose: "page request".to_string(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::RequestInvoice {
            request_id,
            amount_msat,
            purpose,
        } => {
            assert_eq!(request_id, "req-page-001");
            assert_eq!(amount_msat, 25_000);
            assert_eq!(purpose, "page request");
        }
        _ => panic!("expected RequestInvoice"),
    }
}

#[test]
fn encode_decode_roundtrip_ratchet_init() {
    let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let frame = Frame::RatchetInit {
        payload: payload.clone(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::RatchetInit {
            payload: decoded_payload,
        } => assert_eq!(decoded_payload, payload),
        _ => panic!("expected RatchetInit"),
    }
}

#[test]
fn encode_decode_roundtrip_peer_exchange_request() {
    let frame = Frame::PeerExchangeRequest;
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    assert!(matches!(decoded, Frame::PeerExchangeRequest));
}

#[test]
fn encode_decode_roundtrip_peer_exchange_response() {
    let entry = PeerExchangeEntry {
        node_id: NodeId::from_bytes([0xAA; 32]),
        addr: "10.0.0.1:9735".parse().unwrap(),
        label: Some("test-node".to_string()),
        tier: SovereigntyTier::T2,
    };
    let frame = Frame::PeerExchangeResponse {
        peers: vec![entry],
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PeerExchangeResponse { peers } => {
            assert_eq!(peers.len(), 1);
            assert_eq!(peers[0].addr, "10.0.0.1:9735".parse().unwrap());
            assert_eq!(peers[0].label.as_deref(), Some("test-node"));
            assert_eq!(peers[0].tier, SovereigntyTier::T2);
        }
        _ => panic!("expected PeerExchangeResponse"),
    }
}

#[test]
fn encode_decode_roundtrip_message_envelope() {
    let env = make_test_envelope();
    let frame = Frame::Message(Box::new(env.clone()));
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::Message(decoded_env) => assert_eq!(*decoded_env, env),
        _ => panic!("expected Message"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// WIRE PROTOCOL — DECODE EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn decode_empty_buffer_returns_none() {
    assert!(decode_frame(&[]).unwrap().is_none());
}

#[test]
fn decode_incomplete_length_prefix_returns_none() {
    assert!(decode_frame(&[0, 0]).unwrap().is_none());
    assert!(decode_frame(&[0, 0, 0]).unwrap().is_none());
}

#[test]
fn decode_length_prefix_but_no_data_returns_none() {
    // Length says 100 bytes but buffer only has the 4-byte prefix
    let buf = [0, 0, 0, 100];
    assert!(decode_frame(&buf).unwrap().is_none());
}

#[test]
fn decode_oversized_frame_length_returns_error() {
    // Length = MAX_FRAME_SIZE + 1
    let too_big = (MAX_FRAME_SIZE as u32 + 1).to_be_bytes();
    let result = decode_frame(&too_big);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, WireError::FrameTooLarge { .. }));
}

#[test]
fn decode_zero_length_frame_is_invalid_json() {
    // Length 0 means 0 bytes of frame data — empty JSON is invalid
    let buf = [0, 0, 0, 0];
    let err = decode_frame(&buf).unwrap_err();
    assert!(matches!(err, WireError::Serialization(_)));
}

#[test]
fn decode_invalid_json_returns_error() {
    let garbage = b"not valid json at all!!!";
    let len = (garbage.len() as u32).to_be_bytes();
    let mut buf = Vec::new();
    buf.extend_from_slice(&len);
    buf.extend_from_slice(garbage);

    let err = decode_frame(&buf).unwrap_err();
    assert!(matches!(err, WireError::Serialization(_)));
}

#[test]
fn decode_partial_frame_data_returns_none() {
    // Length says 50 bytes but only 10 bytes of data available
    let mut buf = vec![0, 0, 0, 50]; // 4-byte prefix claiming 50
    buf.extend_from_slice(&[0u8; 10]); // Only 10 bytes
    assert!(decode_frame(&buf).unwrap().is_none());
}

#[test]
fn decode_multiple_frames_in_buffer() {
    let f1 = Frame::Ping { nonce: 1 };
    let f2 = Frame::Pong { nonce: 2 };

    let mut buf = encode_frame(&f1).unwrap();
    let f2_encoded = encode_frame(&f2).unwrap();
    buf.extend_from_slice(&f2_encoded);

    // Decode first frame
    let (decoded1, consumed1) = decode_frame(&buf).unwrap().unwrap();
    assert!(matches!(decoded1, Frame::Ping { nonce: 1 }));

    // Decode second frame from remaining buffer
    let (decoded2, _consumed2) = decode_frame(&buf[consumed1..]).unwrap().unwrap();
    assert!(matches!(decoded2, Frame::Pong { nonce: 2 }));
}

#[test]
fn frame_to_bytes_and_from_bytes_roundtrip_all_sovereignty_tiers() {
    for tier in [
        SovereigntyTier::T1,
        SovereigntyTier::T2,
        SovereigntyTier::T3,
        SovereigntyTier::T4,
    ] {
        let frame = Frame::Hello {
            version: 2,
            node_id: NodeId::from_bytes([1u8; 32]),
            x25519_sig: vec![0u8; 64],
            x25519_public: vec![0u8; 32],
            tier,
            capabilities: vec![Capability::X3dh],
        };
        let bytes = frame.to_bytes().unwrap();
        let decoded = Frame::from_bytes(&bytes).unwrap();
        match decoded {
            Frame::Hello {
                tier: decoded_tier, ..
            } => assert_eq!(decoded_tier, tier),
            _ => panic!("expected Hello"),
        }
    }
}

#[test]
fn frame_all_capabilities_roundtrip() {
    let caps = vec![
        Capability::Pqxdh,
        Capability::X3dh,
        Capability::Mls,
        Capability::FileTransfer,
        Capability::Relay,
        Capability::Custom("sovereign-browser".to_string()),
    ];
    let frame = Frame::Hello {
        version: 2,
        node_id: NodeId::from_bytes([1u8; 32]),
        x25519_sig: vec![],
        x25519_public: vec![],
        tier: SovereigntyTier::T2,
        capabilities: caps.clone(),
    };
    let bytes = frame.to_bytes().unwrap();
    let decoded = Frame::from_bytes(&bytes).unwrap();
    match decoded {
        Frame::Hello { capabilities, .. } => {
            assert_eq!(capabilities.len(), 6);
            assert!(capabilities.contains(&Capability::Pqxdh));
            assert!(capabilities.contains(&Capability::FileTransfer));
            assert!(capabilities.contains(&Capability::Relay));
            assert!(capabilities.contains(&Capability::Custom("sovereign-browser".to_string())));
        }
        _ => panic!("expected Hello"),
    }
}

#[test]
fn price_query_response_roundtrip() {
    let query = Frame::PriceQuery { kind: 200 };
    let encoded = encode_frame(&query).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PriceQuery { kind } => assert_eq!(kind, 200),
        _ => panic!("expected PriceQuery"),
    }

    let response = Frame::PriceResponse {
        kind: 200,
        price_msat: 500,
        block_height: 942_000,
    };
    let encoded = encode_frame(&response).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PriceResponse {
            kind,
            price_msat,
            block_height,
        } => {
            assert_eq!(kind, 200);
            assert_eq!(price_msat, 500);
            assert_eq!(block_height, 942_000);
        }
        _ => panic!("expected PriceResponse"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PEER REGISTRY — BULK AND EDGE CASE OPERATIONS
// ═══════════════════════════════════════════════════════════════════════════════

fn make_node_id(seed: u8) -> NodeId {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    NodeId::from_verifying_key(&signing.verifying_key())
}

fn make_entry(seed: u8, port: u16, auto_connect: bool) -> PeerEntry {
    PeerEntry {
        node_id: make_node_id(seed),
        addr: format!("10.0.0.{seed}:{port}").parse().unwrap(),
        label: Some(format!("node-{seed}")),
        auto_connect,
    }
}

#[test]
fn peer_registry_add_many_peers() {
    let mut reg = PeerRegistry::new();
    for i in 1..=100u8 {
        reg.add(make_entry(i, 9735, i % 2 == 0));
    }
    assert_eq!(reg.len(), 100);
    assert_eq!(reg.auto_connect_peers().len(), 50);
    assert_eq!(reg.whitelist().len(), 100);
}

#[test]
fn peer_registry_remove_nonexistent() {
    let mut reg = PeerRegistry::new();
    let fake_id = make_node_id(99);
    assert!(reg.remove(&fake_id).is_none());
}

#[test]
fn peer_registry_get_nonexistent() {
    let reg = PeerRegistry::new();
    assert!(reg.get(&make_node_id(99)).is_none());
    assert!(reg.addr(&make_node_id(99)).is_none());
}

#[test]
fn peer_registry_update_addr_nonexistent() {
    let mut reg = PeerRegistry::new();
    let addr = "192.168.1.1:9999".parse().unwrap();
    assert!(!reg.update_addr(&make_node_id(99), addr));
}

#[test]
fn peer_registry_add_remove_add_same_peer() {
    let mut reg = PeerRegistry::new();
    let entry = make_entry(1, 9735, true);
    let node_id = entry.node_id;

    reg.add(entry.clone());
    assert!(reg.contains(&node_id));

    reg.remove(&node_id);
    assert!(!reg.contains(&node_id));

    reg.add(entry);
    assert!(reg.contains(&node_id));
    assert_eq!(reg.len(), 1);
}

#[test]
fn peer_registry_all_returns_all_entries() {
    let mut reg = PeerRegistry::new();
    reg.add(make_entry(1, 9735, true));
    reg.add(make_entry(2, 9736, false));
    reg.add(make_entry(3, 9737, true));

    let all = reg.all();
    assert_eq!(all.len(), 3);
}

#[test]
fn peer_registry_label_none_when_not_set() {
    let mut reg = PeerRegistry::new();
    let entry = PeerEntry {
        node_id: make_node_id(1),
        addr: "10.0.0.1:9735".parse().unwrap(),
        label: None,
        auto_connect: false,
    };
    let node_id = entry.node_id;
    reg.add(entry);

    assert!(reg.get(&node_id).unwrap().label.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// WIRE ERROR DISPLAY
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn wire_error_frame_too_large_display() {
    let err = WireError::FrameTooLarge {
        size: 20_000_000,
        max: MAX_FRAME_SIZE,
    };
    let msg = err.to_string();
    assert!(msg.contains("20000000"));
    assert!(msg.contains(&MAX_FRAME_SIZE.to_string()));
}

#[test]
fn wire_error_serialization_display() {
    let err = WireError::Serialization("bad json".to_string());
    assert!(err.to_string().contains("bad json"));
}

#[test]
fn wire_error_incomplete_frame_display() {
    let err = WireError::IncompleteFrame {
        expected: 100,
        got: 50,
    };
    let msg = err.to_string();
    assert!(msg.contains("100"));
    assert!(msg.contains("50"));
}

// ═══════════════════════════════════════════════════════════════════════════════
// SOVEREIGNTY TIER SERDE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn sovereignty_tier_serde_roundtrip() {
    for tier in [
        SovereigntyTier::T1,
        SovereigntyTier::T2,
        SovereigntyTier::T3,
        SovereigntyTier::T4,
    ] {
        let json = serde_json::to_string(&tier).unwrap();
        let decoded: SovereigntyTier = serde_json::from_str(&json).unwrap();
        assert_eq!(tier, decoded);
    }
}

#[test]
fn capability_serde_roundtrip() {
    for cap in [
        Capability::Pqxdh,
        Capability::X3dh,
        Capability::Mls,
        Capability::FileTransfer,
        Capability::Relay,
        Capability::Custom("test-cap".to_string()),
    ] {
        let json = serde_json::to_string(&cap).unwrap();
        let decoded: Capability = serde_json::from_str(&json).unwrap();
        assert_eq!(cap, decoded);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PEER EXCHANGE ENTRY SERDE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn peer_exchange_entry_serde_roundtrip() {
    let entry = PeerExchangeEntry {
        node_id: NodeId::from_bytes([0xAB; 32]),
        addr: "192.0.2.11:9735".parse().unwrap(),
        label: Some("alpha".to_string()),
        tier: SovereigntyTier::T2,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: PeerExchangeEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.node_id, entry.node_id);
    assert_eq!(decoded.addr, entry.addr);
    assert_eq!(decoded.label, entry.label);
    assert_eq!(decoded.tier, entry.tier);
}

#[test]
fn peer_exchange_entry_without_label() {
    let entry = PeerExchangeEntry {
        node_id: NodeId::from_bytes([0xCD; 32]),
        addr: "192.168.1.5:9735".parse().unwrap(),
        label: None,
        tier: SovereigntyTier::T1,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: PeerExchangeEntry = serde_json::from_str(&json).unwrap();
    assert!(decoded.label.is_none());
}

// ═══════════════════════════════════════════════════════════════════════════════
// INVOICE FRAMES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn invoice_response_roundtrip() {
    let frame = Frame::InvoiceResponse {
        request_id: "req-roundtrip".to_string(),
        bolt11: "lnbc250n1p3...long_bolt11_string".to_string(),
        payment_hash: "ab".repeat(32),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::InvoiceResponse {
            request_id,
            bolt11,
            payment_hash,
        } => {
            assert_eq!(request_id, "req-roundtrip");
            assert!(bolt11.starts_with("lnbc"));
            assert_eq!(payment_hash.len(), 64);
        }
        _ => panic!("expected InvoiceResponse"),
    }
}

#[test]
fn prekey_offer_roundtrip() {
    let bundle = serde_json::json!({
        "identity_key": "ab".repeat(32),
        "signed_prekey": "cd".repeat(32),
        "one_time_prekey": "ef".repeat(32),
    });
    let frame = Frame::PrekeyOffer {
        bundle: bundle.clone(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::PrekeyOffer {
            bundle: decoded_bundle,
        } => {
            assert_eq!(decoded_bundle, bundle);
        }
        _ => panic!("expected PrekeyOffer"),
    }
}

#[test]
fn session_init_roundtrip() {
    let init_data = serde_json::json!({
        "ephemeral_key": "11".repeat(32),
        "used_prekey_index": 0,
    });
    let frame = Frame::SessionInit {
        init_data: init_data.clone(),
    };
    let encoded = encode_frame(&frame).unwrap();
    let (decoded, _) = decode_frame(&encoded).unwrap().unwrap();
    match decoded {
        Frame::SessionInit {
            init_data: decoded_data,
        } => {
            assert_eq!(decoded_data, init_data);
        }
        _ => panic!("expected SessionInit"),
    }
}
