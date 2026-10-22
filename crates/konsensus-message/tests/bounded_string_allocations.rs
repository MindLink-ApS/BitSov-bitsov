//! Allocation regression: no oversized string copy, including JSON unescaping.
use konsensus_message::wire::Frame;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct MeasuredAllocator;
thread_local! {
    static LARGEST: Cell<Option<usize>> = const { Cell::new(None) };
}
fn record(size: usize) {
    let _ = LARGEST.try_with(|largest| {
        if let Some(previous) = largest.get() {
            largest.set(Some(previous.max(size)));
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
