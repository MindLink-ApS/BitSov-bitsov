//! Fixed-size wire identifiers must reject oversized hex before allocating it.
use konsensus_message::wire::Frame;
use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;
thread_local! {
    static TRACK: Cell<bool> = const { Cell::new(false) };
    static LARGEST: Cell<usize> = const { Cell::new(0) };
}
fn record(size: usize) {
    let _ = TRACK.try_with(|track| {
        if track.get() {
            let _ = LARGEST.try_with(|largest| largest.set(largest.get().max(size)));
        }
    });
}
// SAFETY: every allocation/deallocation is forwarded unchanged to System;
// thread-local counters only observe requested sizes and never allocate.
unsafe impl GlobalAlloc for CountingAllocator {
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
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn fixed_hex_fields_reject_before_owned_allocation() {
    let base = json!({"Message": {
        "id": "00".repeat(32), "kind": 0, "sender": "00".repeat(32),
        "recipient": {"Node": "00".repeat(32)}, "timestamp": 1, "ciphertext": [1],
        "payment_proof": {"payment_hash": "00".repeat(32), "preimage": "00".repeat(32), "amount_msat": 1},
        "signature": "00".repeat(64), "nonce": "00".repeat(24), "references": ["00".repeat(32)]
    }});
    Frame::from_bytes(&serde_json::to_vec(&base).unwrap()).unwrap();
    for (pointer, cap) in [
        ("/Message/id", 64),
        ("/Message/sender", 64),
        ("/Message/recipient/Node", 64),
        ("/Message/payment_proof/payment_hash", 64),
        ("/Message/payment_proof/preimage", 64),
        ("/Message/signature", 128),
        ("/Message/nonce", 48),
        ("/Message/references/0", 64),
    ] {
        for len in [cap + 1, 128 * 1024] {
            let mut frame: Value = base.clone();
            *frame.pointer_mut(pointer).unwrap() = json!("0".repeat(len));
            let bytes = serde_json::to_vec(&frame).unwrap();
            LARGEST.set(0);
            TRACK.set(true);
            let result = Frame::from_bytes(&bytes);
            TRACK.set(false);
            assert!(result.is_err(), "{pointer}");
            assert!(
                LARGEST.get() < 4096,
                "{pointer} allocated {} bytes",
                LARGEST.get()
            );
        }
    }
}
