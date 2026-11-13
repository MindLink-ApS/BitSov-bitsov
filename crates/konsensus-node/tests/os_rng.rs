//! The mnemonic file's salt and nonce are direct operating-system draws: a
//! forked process does not repeat the parent's next values (a per-thread
//! userspace generator would). `mnemonic_crypto` belongs to the binary, so this
//! target compiles the same source file. It runs its own `main`
//! instead of libtest, so each fork happens in a single-threaded process.

#[cfg(unix)]
#[path = "support/fork_probe.rs"]
mod fork_probe;

// Its unit-test module comes along but is not run here, so only its imports remain.
#[cfg(unix)]
#[allow(dead_code, unused_imports)]
#[path = "../src/mnemonic_crypto.rs"]
mod mnemonic_crypto;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    fork_probe::run(&[("salt_and_nonce_are_fresh_os_draws", salt_and_nonce_are_fresh_os_draws)])
}

#[cfg(not(unix))]
fn main() {}

/// Header layout of an encrypted mnemonic file: version byte, 16-byte salt, 12-byte nonce.
#[cfg(unix)]
const SALT: std::ops::Range<usize> = 1..17;
#[cfg(unix)]
const NONCE: std::ops::Range<usize> = 17..29;

#[cfg(unix)]
fn salt_and_nonce_are_fresh_os_draws() {
    let file = || {
        mnemonic_crypto::encrypt_mnemonic(
            "abandon ability able about above absent absorb abstract absurd abuse access accident",
            "a long enough password",
        )
        .unwrap()
    };
    // Each field on its own: a fresh other field must not hide a repeated one.
    assert!(fork_probe::draws_differ_across_fork(|| file()[SALT].to_vec()), "salt repeats across fork");
    assert!(fork_probe::draws_differ_across_fork(|| file()[NONCE].to_vec()), "nonce repeats across fork");
}
