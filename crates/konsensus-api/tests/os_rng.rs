//! A newly created box transport key is a direct operating-system draw: a
//! forked process creating its own key does not repeat the parent's (a per-thread
//! userspace generator copied by `fork` would). The fork runs in a
//! single-threaded re-run of the test.
#![cfg(unix)]

use konsensus_api::pairing::load_box_transport_key;

#[path = "support/fork_probe.rs"]
mod fork_probe;
use fork_probe::{draws_differ_across_fork, in_single_thread_probe};

#[test]
fn new_box_transport_keys_are_fresh_os_draws() {
    in_single_thread_probe(module_path!(), "new_box_transport_keys_are_fresh_os_draws", || {
        let draw = || {
            let dir = tempfile::tempdir().unwrap();
            load_box_transport_key(dir.path()).unwrap().to_vec()
        };
        assert!(draws_differ_across_fork(draw), "box transport key repeats across fork");
    });
}
