//! These tests kill bypasses of the standalone envelope adapter and preflight.
use konsensus_core::{NodeId, PaymentProof, Recipient, UkmEnvelope, UkmEnvelopeBuilder};
use konsensus_message::wire::envelope_from_bytes;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct MeasuredAllocator;
thread_local! {
    static LARGEST: Cell<Option<usize>> = const { Cell::new(None) };
    static TOTAL: Cell<usize> = const { Cell::new(0) };
}
fn record(size: usize) {
    let _ = LARGEST.try_with(|largest| {
        if let Some(previous) = largest.get() {
            largest.set(Some(previous.max(size)));
            TOTAL.with(|total| total.set(total.get() + size));
        }
    });
}
// SAFETY: all operations forward the original pointer/layout to System.
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        record(size);
        unsafe { System.realloc(ptr, layout, size) }
    }
}
#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

fn envelope() -> UkmEnvelope {
    UkmEnvelopeBuilder::new(
        0,
        NodeId::from_bytes([1; 32]),
        Recipient::Node(NodeId::from_bytes([2; 32])),
        vec![1, 2, 3],
        PaymentProof::new([3; 32], [4; 32], 100),
    )
    .build()
}

fn reject(json: &str) {
    TOTAL.set(0);
    LARGEST.set(Some(0));
    let result = envelope_from_bytes(json.as_bytes());
    let largest = LARGEST.replace(None).unwrap();
    let total = TOTAL.get();
    assert!(result.is_err(), "hostile envelope accepted");
    assert_eq!(result.unwrap_err().to_string(), "invalid wire JSON");
    assert!(
        largest <= 4096 && total <= 16384,
        "largest={largest}, total={total}"
    );
}

#[test]
fn relay_envelope_wrong_types_and_escaped_unknown_keys_are_bounded() {
    for size in [393_217, 2 * 1024 * 1024] {
        for prefix in ["", r"\n", r"\u0078", r#"\"\\"#] {
            let token = format!("{prefix}{}", "x".repeat(size));
            for json in [
                format!(r#"{{"timestamp":"{token}"}}"#),
                format!(r#"{{"payment_proof":{{"amount_msat":"{token}"}}}}"#),
                format!(r#"{{"{token}":null}}"#),
                format!(r#"{{"future":"{token}"}}"#),
                format!(r#""{token}""#),
            ] {
                reject(&json);
            }
        }
    }
}

#[test]
fn relay_envelope_uses_frame_field_bounds_below_global_ceiling() {
    let token = format!(r"\n{}", "x".repeat(128 * 1024));
    for json in [
        format!(r#"{{"id":"{token}"}}"#),
        format!(r#"{{"sender":"{token}"}}"#),
        format!(r#"{{"signature":"{token}"}}"#),
        format!(r#"{{"nonce":"{token}"}}"#),
        format!(r#"{{"recipient":{{"Node":"{token}"}}}}"#),
        format!(r#"{{"recipient":{{"Room":"{token}"}}}}"#),
        format!(r#"{{"payment_proof":{{"preimage":"{token}"}}}}"#),
        format!(r#"{{"references":["{token}"]}}"#),
        format!(r#"{{"ciphertext":["{token}"]}}"#),
    ] {
        reject(&json);
    }
}

#[test]
fn honest_standalone_envelopes_roundtrip_including_escaped_identifiers() {
    let expected = envelope();
    let json = serde_json::to_string(&expected).unwrap();
    assert_eq!(envelope_from_bytes(json.as_bytes()).unwrap(), expected);
    // Escape a string field only (numeric JSON tokens must stay numbers).
    let mut value = serde_json::to_value(&expected).unwrap();
    value["sender"] = serde_json::json!("MARKER");
    let escaped = serde_json::to_string(&value)
        .unwrap()
        .replace("MARKER", &r"\u0030\u0031".repeat(32));
    assert_eq!(envelope_from_bytes(escaped.as_bytes()).unwrap(), expected);
    for token in ["x".repeat(393_216), r"\u0078".repeat(65_536)] {
        let extended = format!("{{\"{token}\":0,{}", &json[1..]);
        assert_eq!(envelope_from_bytes(extended.as_bytes()).unwrap(), expected);
    }
}

#[test]
fn envelope_errors_never_echo_peer_text() {
    for json in [
        r#"{"kind":"PEER_SECRET\n"}"#,
        r#"{"recipient":{"PEER_SECRET":null}}"#,
        r#"{"payment_proof":{"amount_msat":"PEER_SECRET"}}"#,
    ] {
        assert_eq!(
            envelope_from_bytes(json.as_bytes())
                .unwrap_err()
                .to_string(),
            "invalid wire JSON"
        );
    }
}
