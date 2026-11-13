//! A newly created box transport key is a direct operating-system draw: a
//! forked process creating its own key does not repeat the parent's (a per-thread
//! userspace generator copied by `fork` would). This target runs its own `main`
//! instead of libtest, so the fork happens in a single-threaded process.

#[cfg(unix)]
#[path = "support/fork_probe.rs"]
mod fork_probe;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    fork_probe::run(&[("new_box_transport_keys_are_fresh_os_draws", new_box_transport_keys_are_fresh_os_draws)])
}

#[cfg(not(unix))]
fn main() {}

#[cfg(unix)]
fn new_box_transport_keys_are_fresh_os_draws() {
    let draw = || {
        let dir = tempfile::tempdir().unwrap();
        konsensus_api::pairing::load_box_transport_key(dir.path()).unwrap().to_vec()
    };
    assert!(fork_probe::draws_differ_across_fork(draw), "box transport key repeats across fork");
}
