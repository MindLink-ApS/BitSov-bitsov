//! Boundary regressions: removing any field's deserializer must admit its
//! one-byte-over mutation and fail the corresponding test.
use konsensus_message::wire::{Frame, WireError};
use serde_json::{json, Value};

fn check_string(mut frame: Value, pointer: &str, cap: usize) {
    for (value, accepted) in [
        ("a".repeat(cap), true),
        ("a".repeat(cap + 1), false),
        ("é".repeat(cap / 2), true),
        ("é".repeat(cap / 2) + "a", false),
    ] {
        *frame.pointer_mut(pointer).unwrap() = json!(value);
        let bytes = serde_json::to_vec(&frame).unwrap();
        let result = Frame::from_bytes(&bytes);
        assert_eq!(result.is_ok(), accepted, "{pointer}: {result:?}");
        if !accepted {
            assert!(matches!(result, Err(WireError::Serialization(_))));
        }
        // Exercise serde_json's escaped-string scratch path as well.
        let escaped = String::from_utf8(bytes)
            .unwrap()
            .replace('a', "\\u0061")
            .replace('é', "\\u00e9");
        assert_eq!(
            Frame::from_bytes(escaped.as_bytes()).is_ok(),
            accepted,
            "escaped {pointer}"
        );
    }
}

macro_rules! string_cap {
    ($name:ident, $frame:expr, $pointer:literal, $cap:expr) => {
        #[test]
        fn $name() {
            check_string($frame, $pointer, $cap);
        }
    };
}
string_cap!(
    message_reject_reason,
    json!({"MessageReject": {"id": "0000000000000000000000000000000000000000000000000000000000000000", "reason": ""}}),
    "/MessageReject/reason",
    1024
);
string_cap!(
    disconnect_reason,
    json!({"Disconnect": {"reason": ""}}),
    "/Disconnect/reason",
    1024
);
string_cap!(
    request_invoice_request_id,
    json!({"RequestInvoice": {"request_id": "id", "amount_msat": 1, "purpose": ""}}),
    "/RequestInvoice/request_id",
    256
);
string_cap!(
    request_invoice_purpose,
    json!({"RequestInvoice": {"request_id": "id", "amount_msat": 1, "purpose": ""}}),
    "/RequestInvoice/purpose",
    1024
);
string_cap!(
    invoice_response_request_id,
    json!({"InvoiceResponse": {"request_id": "id", "bolt11": "invoice", "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"}}),
    "/InvoiceResponse/request_id",
    256
);
string_cap!(
    invoice_response_bolt11,
    json!({"InvoiceResponse": {"request_id": "id", "bolt11": "invoice", "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"}}),
    "/InvoiceResponse/bolt11",
    65536
);
string_cap!(
    invoice_response_payment_hash,
    json!({"InvoiceResponse": {"request_id": "id", "bolt11": "invoice", "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"}}),
    "/InvoiceResponse/payment_hash",
    128
);
string_cap!(
    invoice_error_request_id,
    json!({"InvoiceError": {"request_id": "id", "reason": ""}}),
    "/InvoiceError/request_id",
    256
);
string_cap!(
    invoice_error_reason,
    json!({"InvoiceError": {"request_id": "id", "reason": ""}}),
    "/InvoiceError/reason",
    1024
);
string_cap!(
    call_offer_session_id,
    json!({"CallOffer": {"session_id": "id", "sdp": ""}}),
    "/CallOffer/session_id",
    256
);
string_cap!(
    call_offer_sdp,
    json!({"CallOffer": {"session_id": "id", "sdp": ""}}),
    "/CallOffer/sdp",
    65536
);
string_cap!(
    call_answer_session_id,
    json!({"CallAnswer": {"session_id": "id", "sdp": ""}}),
    "/CallAnswer/session_id",
    256
);
string_cap!(
    call_answer_sdp,
    json!({"CallAnswer": {"session_id": "id", "sdp": ""}}),
    "/CallAnswer/sdp",
    65536
);
string_cap!(
    ice_candidate_session_id,
    json!({"IceCandidate": {"session_id": "id", "candidate": ""}}),
    "/IceCandidate/session_id",
    256
);
string_cap!(
    ice_candidate_candidate,
    json!({"IceCandidate": {"session_id": "id", "candidate": ""}}),
    "/IceCandidate/candidate",
    4096
);
string_cap!(
    call_end_session_id,
    json!({"CallEnd": {"session_id": "id", "reason": ""}}),
    "/CallEnd/session_id",
    256
);
string_cap!(
    call_end_reason,
    json!({"CallEnd": {"session_id": "id", "reason": ""}}),
    "/CallEnd/reason",
    1024
);
string_cap!(
    hello_custom_capability,
    json!({"Hello": {"version": 2, "node_id": "0000000000000000000000000000000000000000000000000000000000000000", "x25519_sig": [], "x25519_public": [], "tier": "T1", "capabilities": [{"Custom": ""}]}}),
    "/Hello/capabilities/0/Custom",
    128
);
string_cap!(
    helloack_custom_capability,
    json!({"HelloAck": {"version": 2, "node_id": "0000000000000000000000000000000000000000000000000000000000000000", "x25519_sig": [], "x25519_public": [], "tier": "T1", "capabilities": [{"Custom": ""}]}}),
    "/HelloAck/capabilities/0/Custom",
    128
);
string_cap!(
    prekeyoffer_json_string,
    json!({"PrekeyOffer":{"bundle":{"nested":[""]}}}),
    "/PrekeyOffer/bundle/nested/0",
    4096
);
string_cap!(
    sessioninit_json_string,
    json!({"SessionInit":{"init_data":{"nested":[""]}}}),
    "/SessionInit/init_data/nested/0",
    4096
);

#[test]
fn price_table_keys_are_bounded() {
    for len in [128, 129] {
        let bytes = serde_json::to_vec(&json!({"PriceTable": {
            "prices": {"a".repeat(len): 1}, "block_height": 1, "valid_blocks": 1
        }}))
        .unwrap();
        assert_eq!(Frame::from_bytes(&bytes).is_ok(), len == 128);
    }
}

#[test]
fn prekey_and_session_json_keys_are_bounded() {
    for (variant, field) in [("PrekeyOffer", "bundle"), ("SessionInit", "init_data")] {
        for len in [256, 257] {
            let bytes =
                serde_json::to_vec(&json!({variant: {field: {"a".repeat(len): null}}})).unwrap();
            assert_eq!(Frame::from_bytes(&bytes).is_ok(), len == 256, "{variant}");
        }
    }
}

#[test]
fn starter_status_missing_optional_strings_still_decode() {
    let frame = json!({"StarterStatus": {"request_id": uuid::Uuid::nil(), "state": "ready"}});
    assert!(matches!(
        Frame::from_bytes(&serde_json::to_vec(&frame).unwrap()).unwrap(),
        Frame::StarterStatus {
            reason: None,
            channel_id: None,
            funding_txid: None,
            ..
        }
    ));
}

#[test]
fn old_shape_frames_still_decode() {
    for frame in [
        json!({"LightningInfo": {"ln_pubkey": "02".repeat(33)}}),
        json!({"MessageAck": {"id": "00".repeat(32)}}),
        json!({"PriceTable": {"prices": {"communication": 1}, "block_height": 1, "valid_blocks": 1}}),
        json!({"PeerExchangeResponse": {"peers": [{"node_id": "00".repeat(32), "addr": "127.0.0.1:9736", "tier": "T1"}]}}),
    ] {
        Frame::from_bytes(&serde_json::to_vec(&frame).unwrap()).unwrap();
    }
}

fn envelope() -> Value {
    json!({"id": "00".repeat(32), "kind": 0, "sender": "00".repeat(32),
        "recipient": "Broadcast", "timestamp": 1, "ciphertext": [],
        "payment_proof": {"payment_hash": "00".repeat(32), "preimage": "00".repeat(32), "amount_msat": 1},
        "signature": "00".repeat(64), "nonce": "00".repeat(24), "references": []})
}

#[test]
fn envelope_ciphertext_is_bounded_in_all_frame_variants() {
    for len in [6 * 1024 * 1024, 6 * 1024 * 1024 + 1] {
        let mut env = envelope();
        env["ciphertext"] = json!(vec![0u8; len]);
        for frame in [
            json!({"Message": env}),
            json!({"Gossip": env}),
            json!({"PeerExchangePaidRequest": {"quote": quote(), "envelope": env}}),
        ] {
            assert_eq!(
                Frame::from_bytes(&serde_json::to_vec(&frame).unwrap()).is_ok(),
                len == 6 * 1024 * 1024
            );
        }
    }
}

fn quote() -> Value {
    json!({"recipient": "00".repeat(32), "requester": "00".repeat(32), "expires_at": 1,
        "amount_msat": 1, "snapshot": "", "bolt11": "", "signature": "00".repeat(64)})
}

#[test]
fn quote_bolt11_retains_single_record_reply_bound() {
    check_string(
        json!({"PeerExchangeQuote": {"quote": quote()}}),
        "/PeerExchangeQuote/quote/bolt11",
        8192,
    );
    check_string(
        json!({"PeerExchangePaidRequest": {"quote": quote(), "envelope": envelope()}}),
        "/PeerExchangePaidRequest/quote/bolt11",
        8192,
    );
}

string_cap!(
    peer_exchange_refused_reason,
    json!({"PeerExchangeRefused": {"reason": ""}}),
    "/PeerExchangeRefused/reason",
    1024
);

#[test]
fn quote_snapshot_bytes_are_bounded_in_both_variants() {
    for len in [24576, 24577] {
        let mut q = quote();
        q["snapshot"] = json!("00".repeat(len));
        for frame in [
            json!({"PeerExchangeQuote": {"quote": q}}),
            json!({"PeerExchangePaidRequest": {"quote": q, "envelope": envelope()}}),
        ] {
            assert_eq!(
                Frame::from_bytes(&serde_json::to_vec(&frame).unwrap()).is_ok(),
                len == 24576
            );
        }
    }
}

#[test]
fn handshake_byte_vectors_and_capability_counts_are_bounded_per_field() {
    for variant in ["Hello", "HelloAck"] {
        let base = json!({variant: {"version": 2, "node_id": "00".repeat(32),
            "x25519_sig": [], "x25519_public": [], "tier": "T1", "capabilities": []}});
        for field in ["x25519_sig", "x25519_public", "capabilities"] {
            for len in [256, 257] {
                let mut frame = base.clone();
                frame[variant][field] = if field == "capabilities" {
                    json!(vec!["X3dh"; len])
                } else {
                    json!(vec![0u8; len])
                };
                assert_eq!(
                    Frame::from_bytes(&serde_json::to_vec(&frame).unwrap()).is_ok(),
                    len == 256,
                    "{variant}.{field}"
                );
            }
        }
    }
}

#[test]
fn ratchet_payload_bytes_are_bounded() {
    for len in [1024 * 1024, 1024 * 1024 + 1] {
        let bytes =
            serde_json::to_vec(&json!({"RatchetInit": {"payload": vec![0u8; len]}})).unwrap();
        assert_eq!(Frame::from_bytes(&bytes).is_ok(), len == 1024 * 1024);
    }
}

#[test]
fn admission_invoice_ids_still_decode_in_request_response_and_error() {
    use konsensus_core::{admission_quote, types::NodeId};
    let request_id = admission_quote::request_id(
        &NodeId::from_bytes([1; 32]),
        &NodeId::from_bytes([2; 32]),
        u64::MAX,
    );
    assert!(request_id.len() > 128);
    for frame in [
        Frame::RequestInvoice {
            request_id: request_id.clone(),
            amount_msat: 1000,
            purpose: admission_quote::PURPOSE.into(),
        },
        Frame::InvoiceResponse {
            request_id: request_id.clone(),
            bolt11: "lnbc".into(),
            payment_hash: "00".repeat(32),
        },
        Frame::InvoiceError {
            request_id,
            reason: "unavailable".into(),
        },
    ] {
        Frame::from_bytes(&frame.to_bytes().unwrap()).unwrap();
    }
}
