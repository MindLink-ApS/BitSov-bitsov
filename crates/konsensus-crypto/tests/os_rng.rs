//! The backup nonce and sender-key chain keys are direct operating-system
//! draws. A userspace generator seeded once per thread is copied by `fork` and
//! not reseeded in the child, so the parent's and child's next draws match; a
//! direct OS read gives each process independent bytes. Each fork runs in a
//! single-threaded re-run of the test.
#![cfg(unix)]

use konsensus_crypto::scb::encrypt_scb;
use konsensus_crypto::sender_keys::SenderKeyState;

/// The chain key as published in a distribution message (the field itself is private).
fn chain_key(state: &SenderKeyState) -> Vec<u8> {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let sender = konsensus_core::NodeId::from_verifying_key(&signing.verifying_key());
    state.distribution([0u8; 32], sender).chain_key.to_vec()
}

#[path = "support/fork_probe.rs"]
mod fork_probe;
use fork_probe::{draws_differ_across_fork, in_single_thread_probe};

#[test]
fn backup_nonce_is_a_fresh_os_draw() {
    in_single_thread_probe(module_path!(), "backup_nonce_is_a_fresh_os_draw", || {
        // Layout: 8-byte magic, 12-byte nonce, ciphertext.
        let nonce = || encrypt_scb(b"channel backup", &[7u8; 32]).unwrap()[8..20].to_vec();
        assert!(draws_differ_across_fork(nonce), "backup nonce repeats across fork");
    });
}

#[test]
fn chain_keys_are_fresh_os_draws() {
    in_single_thread_probe(module_path!(), "chain_keys_are_fresh_os_draws", || {
        assert!(
            draws_differ_across_fork(|| chain_key(&SenderKeyState::generate())),
            "generated chain key repeats across fork"
        );
        let rotated = || {
            let mut state = SenderKeyState::generate();
            state.rotate();
            chain_key(&state)
        };
        assert!(draws_differ_across_fork(rotated), "rotated chain key repeats across fork");
    });
    let mut state = SenderKeyState::generate();
    let before = chain_key(&state);
    state.rotate();
    assert_ne!(before, chain_key(&state), "rotation kept the chain key");
}
