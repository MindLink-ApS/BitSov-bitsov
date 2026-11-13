//! The backup nonce and sender-key chain keys are direct operating-system
//! draws. A userspace generator seeded once per thread is copied by `fork` and
//! not reseeded in the child, so the parent's and child's next draws match; a
//! direct OS read gives each process independent bytes.
#![cfg(unix)]

use konsensus_crypto::scb::encrypt_scb;
use konsensus_crypto::sender_keys::SenderKeyState;

/// The chain key as published in a distribution message (the field itself is private).
fn chain_key(state: &SenderKeyState) -> Vec<u8> {
    let signing = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let sender = konsensus_core::NodeId::from_verifying_key(&signing.verifying_key());
    state.distribution([0u8; 32], sender).chain_key.to_vec()
}

fn draws_differ_across_fork(draw: impl Fn() -> Vec<u8>) -> bool {
    let _warm = draw();
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds has room for two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    // SAFETY: the child only draws, writes to the pipe and exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        let code = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(&draw)) {
            Ok(bytes) => {
                // SAFETY: valid buffer and descriptor.
                let n = unsafe { libc::write(fds[1], bytes.as_ptr().cast(), bytes.len()) };
                if n as usize == bytes.len() { 0 } else { 2 }
            }
            Err(_) => 1,
        };
        // SAFETY: leave the child without running the parent's destructors.
        unsafe { libc::_exit(code) };
    }
    let ours = draw();
    let mut theirs = vec![0u8; ours.len()];
    // SAFETY: close our copy of the write end so a dead child yields EOF.
    unsafe { libc::close(fds[1]) };
    let mut poll = libc::pollfd { fd: fds[0], events: libc::POLLIN, revents: 0 };
    // SAFETY: one valid pollfd; 20 s bound.
    let ready = unsafe { libc::poll(&mut poll, 1, 20_000) };
    let n = if ready == 1 {
        // SAFETY: valid buffer of theirs.len() bytes.
        unsafe { libc::read(fds[0], theirs.as_mut_ptr().cast(), theirs.len()) }
    } else {
        // SAFETY: pid is our child.
        unsafe { libc::kill(pid, libc::SIGKILL) };
        -1
    };
    let mut status = 0;
    // SAFETY: reap our child; close the read end.
    unsafe {
        libc::waitpid(pid, &mut status, 0);
        libc::close(fds[0]);
    }
    assert_eq!(n as usize, ours.len(), "the forked child did not report its draw");
    ours != theirs
}

#[test]
fn backup_nonce_is_a_fresh_os_draw() {
    // Layout: 8-byte magic, 12-byte nonce, ciphertext.
    let nonce = || encrypt_scb(b"channel backup", &[7u8; 32]).unwrap()[8..20].to_vec();
    assert!(draws_differ_across_fork(nonce), "backup nonce repeats across fork");
}

#[test]
fn chain_keys_are_fresh_os_draws() {
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
