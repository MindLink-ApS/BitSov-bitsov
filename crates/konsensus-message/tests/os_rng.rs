//! The ingress cookie secret is a direct operating-system draw: a forked
//! process does not repeat the parent's next secret (a per-thread userspace
//! generator copied by `fork` would). The fork runs in a single-threaded re-run
//! of the test; the secret is reached through the test-support feature.
#![cfg(unix)]

#[path = "support/fork_probe.rs"]
mod fork_probe;
use fork_probe::{draws_differ_across_fork, in_single_thread_probe};

#[test]
fn cookie_secret_is_a_fresh_os_draw() {
    in_single_thread_probe(module_path!(), "cookie_secret_is_a_fresh_os_draw", || {
        let draw = || konsensus_message::transport::__fresh_cookie_secret().to_vec();
        assert!(draws_differ_across_fork(draw), "cookie secret repeats across fork");
    });
}
