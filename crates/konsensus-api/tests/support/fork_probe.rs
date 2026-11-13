//! Fork-based test helper shared by the os_rng integration tests.
#![allow(dead_code)]

pub const PROBE_ENV: &str = "OS_RNG_FORK_PROBE";

/// Run `body` in a fresh, single-threaded run of this same test (re-executing
/// the test binary with `--exact --test-threads=1`), so the `fork` inside
/// happens in a process with no other threads. `module` is `module_path!()`
/// and `name` the test function, which together give libtest's test name.
pub fn in_single_thread_probe(module: &str, name: &str, body: impl FnOnce()) {
    if std::env::var_os(PROBE_ENV).is_some() {
        body();
        return;
    }
    let test = match module.split_once("::") {
        Some((_, path)) => format!("{path}::{name}"),
        None => name.to_string(),
    };
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([test.as_str(), "--exact", "--test-threads=1"])
        .env(PROBE_ENV, "1")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success() && stdout.contains("test result: ok. 1 passed"),
        "single-threaded probe of {test} failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Inside a probe: draw once, fork, draw in parent and child, and report
/// whether the two draws differ. A per-thread userspace generator copied by
/// `fork` repeats; a direct operating-system read does not.
pub fn draws_differ_across_fork(draw: impl Fn() -> Vec<u8>) -> bool {
    assert!(std::env::var_os(PROBE_ENV).is_some(), "call inside in_single_thread_probe");
    let _warm = draw();
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds has room for two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    // SAFETY: this process runs a single thread (see in_single_thread_probe),
    // so the child may allocate and run library code before it exits.
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
