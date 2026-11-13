//! The ingress cookie secret is a direct operating-system draw: a forked
//! process does not repeat the parent's next secret (a per-thread userspace
//! generator copied by `fork` would). The secret is reached through the
//! test-support feature. This target runs its own `main` instead of libtest,
//! so the fork happens in a single-threaded process.

#[cfg(unix)]
#[path = "support/fork_probe.rs"]
mod fork_probe;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    fork_probe::run(&[("cookie_secret_is_a_fresh_os_draw", cookie_secret_is_a_fresh_os_draw)])
}

#[cfg(not(unix))]
fn main() {}

#[cfg(unix)]
fn cookie_secret_is_a_fresh_os_draw() {
    let draw = || konsensus_message::transport::__fresh_cookie_secret().to_vec();
    assert!(fork_probe::draws_differ_across_fork(draw), "cookie secret repeats across fork");
}
