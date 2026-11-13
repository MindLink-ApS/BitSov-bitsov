//! The backup nonce and sender-key chain keys are direct operating-system
//! draws. A userspace generator seeded once per thread is copied by `fork` and
//! not reseeded in the child, so the parent's and child's next draws match; a
//! direct OS read gives each process independent bytes. This target runs its own
//! `main` instead of libtest: `main` runs every check on the only thread,
//! so each fork happens in a single-threaded process.

#[cfg(unix)]
#[path = "support/fork_probe.rs"]
mod fork_probe;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    fork_probe::run(&[
        ("backup_nonce_is_a_fresh_os_draw", checks::backup_nonce_is_a_fresh_os_draw),
        ("chain_keys_are_fresh_os_draws", checks::chain_keys_are_fresh_os_draws),
    ])
}

#[cfg(not(unix))]
fn main() {}

#[cfg(unix)]
mod checks {
    use super::fork_probe::draws_differ_across_fork;
    use konsensus_crypto::scb::encrypt_scb;
    use konsensus_crypto::sender_keys::SenderKeyState;

    /// The chain key as published in a distribution message (the field itself is private).
    fn chain_key(state: &SenderKeyState) -> Vec<u8> {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let sender = konsensus_core::NodeId::from_verifying_key(&signing.verifying_key());
        state.distribution([0u8; 32], sender).chain_key.to_vec()
    }

    pub fn backup_nonce_is_a_fresh_os_draw() {
        // Layout: 8-byte magic, 12-byte nonce, ciphertext.
        let nonce = || encrypt_scb(b"channel backup", &[7u8; 32]).unwrap()[8..20].to_vec();
        assert!(draws_differ_across_fork(nonce), "backup nonce repeats across fork");
    }

    pub fn chain_keys_are_fresh_os_draws() {
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
        let mut state = SenderKeyState::generate();
        let before = chain_key(&state);
        state.rotate();
        assert_ne!(before, chain_key(&state), "rotation kept the chain key");
    }
}
