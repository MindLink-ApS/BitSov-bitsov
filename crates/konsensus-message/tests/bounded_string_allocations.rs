//! Allocation regression: no oversized string copy, including JSON unescaping.
use konsensus_message::wire::Frame;
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

#[test]
fn oversized_plain_and_escaped_strings_do_not_allocate_payload_sized_buffers() {
    let mut failures = Vec::new();
    for prefix in ["", r"\n", r"\u0061", r"\ud83d\ude00"] {
        let value = format!("{prefix}{}", "x".repeat(4 * 1024 * 1024));
        // Escaped field names also select the bounded helpers.
        let cases = [
            format!(
                r#"{{"StarterRequest":{{"v":1,"request_id":"00000000-0000-0000-0000-000000000000","net\u0077ork":"{value}","ln_pubkey":"02","ln_sig":"sig"}}}}"#
            ),
            format!(r#"{{"LightningInfo":{{"ln_pubkey":"02","ln_addr":"{value}"}}}}"#),
            format!(
                r#"{{"PeerExchangeResponse":{{"peers":[{{"node_id":"{}","addr":"10.0.0.1:9735","label":"{value}","tier":"T2"}}]}}}}"#,
                "ab".repeat(32)
            ),
        ];
        for (case, json) in cases.iter().enumerate() {
            LARGEST.with(|largest| largest.set(Some(0)));
            let result = Frame::from_bytes(json.as_bytes());
            let largest = LARGEST.with(|largest| largest.replace(None).unwrap());
            assert!(result.is_err());
            if largest > 4096 {
                failures.push((prefix, case, largest));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "oversized decode allocations: {failures:?}"
    );
}

#[test]
fn deeply_nested_wrong_type_is_rejected_without_a_large_parser_stack() {
    let nested = format!("{}0{}", "[".repeat(1024 * 1024), "]".repeat(1024 * 1024));
    let json = format!(r#"{{"LightningInfo":{{"ln_pubkey":"02","ln_addr":{nested}}}}}"#);
    LARGEST.with(|largest| largest.set(Some(0)));
    let result = Frame::from_bytes(json.as_bytes());
    let largest = LARGEST.with(|largest| largest.replace(None).unwrap());
    assert!(result.is_err());
    assert!(largest <= 4096, "wrong-type parser allocation: {largest}");
}

fn assert_bounded_rejection(json: &str, label: &str) {
    TOTAL.set(0);
    LARGEST.set(Some(0));
    let result = Frame::from_bytes(json.as_bytes());
    let largest = LARGEST.replace(None).unwrap();
    let total = TOTAL.get();
    assert!(result.is_err(), "{label}: accepted");
    assert!(
        largest <= 4096 && total <= 16384,
        "{label}: largest={largest}, total={total}"
    );
}

#[test]
fn l4_escaped_strings_reject_before_parser_scratch_allocation() {
    // Build inputs before enabling the thread-local counting allocator.
    for prefix in ["", r"\n", r"\u00e9", r"\ud83d\ude00"] {
        let value = format!("{prefix}{}", "x".repeat(1024 * 1024));
        let cases = [
            format!(r#"{{"Disconnect":{{"reason":"{value}"}}}}"#),
            format!(
                r#"{{"RequestInvoice":{{"request_id":"{value}","amount_msat":1,"purpose":"ok"}}}}"#
            ),
            format!(
                r#"{{"InvoiceResponse":{{"bolt11":"{value}","request_id":"id","payment_hash":"00"}}}}"#
            ),
            format!(r#"{{"CallOffer":{{"session_id":"id","sdp":"{value}"}}}}"#),
            format!(r#"{{"IceCandidate":{{"session_id":"id","candidate":"{value}"}}}}"#),
            format!(r#"{{"Hello":{{"capabilities":[{{"Custom":"{value}"}}]}}}}"#),
            format!(r#"{{"PriceTable":{{"prices":{{"{value}":1}}}}}}"#),
            format!(r#"{{"PrekeyOffer":{{"bundle":{{"{value}":1}}}}}}"#),
            format!(r#"{{"PrekeyOffer":{{"bundle":{{"nested":["{value}"]}}}}}}"#),
            format!(r#"{{"SessionInit":{{"init_data":[{{"nested":"{value}"}}]}}}}"#),
            format!(r#"{{"PeerExchangeQuote":{{"quote":{{"snapshot":"{value}"}}}}}}"#),
        ];
        for (i, json) in cases.iter().enumerate() {
            assert_bounded_rejection(json, &format!("L4 {i} {prefix}"));
        }
    }
}

#[test]
fn unknown_variant_tags_reject_before_copying_or_formatting() {
    for prefix in ["", r"\n", r"\u00e9", r"\ud83d\ude00"] {
        let value = format!("{prefix}{}", "x".repeat(4 * 1024 * 1024));
        for json in [
            format!(r#"{{"{value}":{{}}}}"#),
            format!(r#""{value}""#),
            format!(r#"{{"Hello":{{"capabilities":["{value}"]}}}}"#),
            format!(r#"{{"Hello":{{"capabilities":[{{"{value}":null}}]}}}}"#),
            format!(r#"{{"Hello":{{"tier":"{value}"}}}}"#),
            format!(r#"{{"Message":{{"recipient":{{"{value}":null}}}}}}"#),
        ] {
            assert_bounded_rejection(&json, prefix);
        }
    }
}

#[test]
fn every_l4_string_field_rejects_escaped_over_cap_without_large_allocations() {
    use serde_json::json;
    let cases = [
        (
            json!({"MessageReject": {"id": "0000000000000000000000000000000000000000000000000000000000000000", "reason": ""}}),
            "/MessageReject/reason",
        ),
        (json!({"Disconnect": {"reason": ""}}), "/Disconnect/reason"),
        (
            json!({"RequestInvoice": {"request_id": "id", "amount_msat": 1, "purpose": ""}}),
            "/RequestInvoice/request_id",
        ),
        (
            json!({"RequestInvoice": {"request_id": "id", "amount_msat": 1, "purpose": ""}}),
            "/RequestInvoice/purpose",
        ),
        (
            json!({"InvoiceResponse": {"request_id": "id", "bolt11": "invoice", "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"}}),
            "/InvoiceResponse/request_id",
        ),
        (
            json!({"InvoiceResponse": {"request_id": "id", "bolt11": "invoice", "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"}}),
            "/InvoiceResponse/bolt11",
        ),
        (
            json!({"InvoiceResponse": {"request_id": "id", "bolt11": "invoice", "payment_hash": "0000000000000000000000000000000000000000000000000000000000000000"}}),
            "/InvoiceResponse/payment_hash",
        ),
        (
            json!({"InvoiceError": {"request_id": "id", "reason": ""}}),
            "/InvoiceError/request_id",
        ),
        (
            json!({"InvoiceError": {"request_id": "id", "reason": ""}}),
            "/InvoiceError/reason",
        ),
        (
            json!({"CallOffer": {"session_id": "id", "sdp": ""}}),
            "/CallOffer/session_id",
        ),
        (
            json!({"CallOffer": {"session_id": "id", "sdp": ""}}),
            "/CallOffer/sdp",
        ),
        (
            json!({"CallAnswer": {"session_id": "id", "sdp": ""}}),
            "/CallAnswer/session_id",
        ),
        (
            json!({"CallAnswer": {"session_id": "id", "sdp": ""}}),
            "/CallAnswer/sdp",
        ),
        (
            json!({"IceCandidate": {"session_id": "id", "candidate": ""}}),
            "/IceCandidate/session_id",
        ),
        (
            json!({"IceCandidate": {"session_id": "id", "candidate": ""}}),
            "/IceCandidate/candidate",
        ),
        (
            json!({"CallEnd": {"session_id": "id", "reason": ""}}),
            "/CallEnd/session_id",
        ),
        (
            json!({"CallEnd": {"session_id": "id", "reason": ""}}),
            "/CallEnd/reason",
        ),
        (
            json!({"Hello": {"version": 2, "node_id": "0000000000000000000000000000000000000000000000000000000000000000", "x25519_sig": [], "x25519_public": [], "tier": "T1", "capabilities": [{"Custom": ""}]}}),
            "/Hello/capabilities/0/Custom",
        ),
        (
            json!({"HelloAck": {"version": 2, "node_id": "0000000000000000000000000000000000000000000000000000000000000000", "x25519_sig": [], "x25519_public": [], "tier": "T1", "capabilities": [{"Custom": ""}]}}),
            "/HelloAck/capabilities/0/Custom",
        ),
        (
            json!({"PrekeyOffer":{"bundle":{"nested":[""]}}}),
            "/PrekeyOffer/bundle/nested/0",
        ),
        (
            json!({"SessionInit":{"init_data":{"nested":[""]}}}),
            "/SessionInit/init_data/nested/0",
        ),
        (
            json!({"PeerExchangeRefused": {"reason": ""}}),
            "/PeerExchangeRefused/reason",
        ),
    ];
    for prefix in ["", r"\n", r"\u00e9", r"\ud83d\ude00"] {
        let value = format!("{prefix}{}", "x".repeat(1024 * 1024));
        for (mut frame, pointer) in cases.clone() {
            *frame.pointer_mut(pointer).unwrap() = json!("ALLOCATION_MARKER");
            let json = serde_json::to_string(&frame)
                .unwrap()
                .replace("ALLOCATION_MARKER", &value);
            assert_bounded_rejection(&json, pointer);
        }
    }
}

#[test]
fn typed_text_fields_reject_escaped_over_cap_without_large_allocations() {
    let value = format!(r"\n{}", "x".repeat(1024 * 1024));
    for json in [
        format!(r#"{{"Message":{{"recipient":{{"Room":"{value}"}}}}}}"#),
        format!(r#"{{"StarterRequest":{{"request_id":"{value}"}}}}"#),
        format!(r#"{{"StarterStatus":{{"request_id":"{value}"}}}}"#),
        format!(r#"{{"StarterStatus":{{"original_request_id":"{value}"}}}}"#),
        format!(r#"{{"PeerExchangeResponse":{{"peers":[{{"addr":"{value}"}}]}}}}"#),
        format!(r#"{{"PorchQuoteResponse":{{"status":"{value}"}}}}"#),
    ] {
        assert_bounded_rejection(&json, "typed text");
    }
}

#[test]
fn escaped_known_tags_and_typed_fields_remain_compatible() {
    for json in [
        r#""Session\u0041ck""#.to_owned(),
        r#" { "P\u0069ng": {"nonce":1} } "#.to_owned(),
        format!(r#"{{"Hello":{{"version":2,"node_id":"{}","x25519_sig":[],"x25519_public":[],"tier":"T\u0031","capabilities":["M\u006cs",{{"C\u0075stom":"ok"}}]}}}}"#, "00".repeat(32)),
        format!(r#"{{"PeerExchangeResponse":{{"peers":[{{"node_id":"{}","addr":"[\u003a:1]:9735","tier":"T2"}}]}}}}"#, "00".repeat(32)),
        r#"{"StarterStatus":{"request_id":"urn:uuid:00000000-0000-0000-0000-000000000000","state":"ready","original_request_id":"{00000000-0000-0000-0000-000000000000}"}}"#.to_owned(),
    ] {
        Frame::from_bytes(json.as_bytes()).unwrap();
    }
}

#[test]
fn wrong_type_byte_arrays_and_elements_do_not_copy_hostile_strings() {
    let value = format!(r"\n{}", "x".repeat(1024 * 1024));
    for json in [
        format!(r#"{{"Hello":{{"x25519_sig":"{value}"}}}}"#),
        format!(r#"{{"Hello":{{"x25519_public":["{value}"]}}}}"#),
        format!(r#"{{"Hello":{{"capabilities":"{value}"}}}}"#),
        format!(r#"{{"RatchetInit":{{"payload":"{value}"}}}}"#),
        format!(r#"{{"RatchetInit":{{"payload":["{value}"]}}}}"#),
        format!(r#"{{"Message":{{"ciphertext":"{value}"}}}}"#),
        format!(r#"{{"Message":{{"ciphertext":["{value}"]}}}}"#),
        format!(r#"{{"Message":{{"references":"{value}"}}}}"#),
        format!(r#"{{"PeerExchangeResponse":{{"peers":"{value}"}}}}"#),
    ] {
        assert_bounded_rejection(&json, "wrong type bytes/array");
    }
}

#[test]
fn starter_lightning_porch_and_quote_hooks_reject_without_large_allocations() {
    for prefix in ["", r"\n", r"\u00e9", r"\ud83d\ude00"] {
        let value = format!("{prefix}{}", "x".repeat(1024 * 1024));
        for (variant, field) in [
            ("StarterRequest", "network"),
            ("StarterRequest", "ln_pubkey"),
            ("StarterRequest", "ln_sig"),
            ("StarterStatus", "state"),
            ("StarterStatus", "reason"),
            ("StarterStatus", "channel_id"),
            ("StarterStatus", "funding_txid"),
            ("LightningInfo", "ln_pubkey"),
            ("LightningInfo", "ln_addr"),
            ("PorchQuoteRequest", "request_id"),
            ("PorchQuoteRequest", "path"),
            ("PorchQuoteResponse", "request_id"),
            ("PorchQuoteResponse", "path"),
        ] {
            let json = format!(r#"{{"{variant}":{{"{field}":"{value}"}}}}"#);
            assert_bounded_rejection(&json, &format!("{variant}.{field}"));
        }
        let json = format!(r#"{{"PeerExchangeQuote":{{"quote":{{"bolt11":"{value}"}}}}}}"#);
        assert_bounded_rejection(&json, "quote.bolt11");
    }
}
