//! Fork-based checks shared by the os_rng test targets. Each target runs its own
//! `main` instead of libtest, so `main` runs on the process's only thread and
//! every `fork` below happens before any other thread exists. That invariant is
//! checked (`thread_count`), not assumed.
#![allow(dead_code)]

use std::process::ExitCode;

/// Threads in this process, where the platform reports it.
#[cfg(target_os = "linux")]
pub fn thread_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/task").ok().map(|d| d.count())
}

/// Threads in this process, where the platform reports it.
#[cfg(target_os = "macos")]
pub fn thread_count() -> Option<usize> {
    // SAFETY: proc_taskinfo is plain data, so all-zero bytes are a valid value.
    let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
    // SAFETY: `info` is a writable buffer of `size` bytes for our own pid.
    let n = unsafe {
        libc::proc_pidinfo(libc::getpid(), libc::PROC_PIDTASKINFO, 0, (&mut info as *mut libc::proc_taskinfo).cast(), size)
    };
    (n == size).then_some(info.pti_threadnum as usize)
}

/// Threads in this process, where the platform reports it.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn thread_count() -> Option<usize> {
    None
}

/// Run each named check in order on the main thread; print libtest-style lines
/// and fail the target if any check panics.
pub fn run(checks: &[(&str, fn())]) -> ExitCode {
    let mut failed = 0;
    for (name, check) in checks {
        if std::panic::catch_unwind(*check).is_ok() {
            println!("test {name} ... ok");
        } else {
            println!("test {name} ... FAILED");
            failed += 1;
        }
    }
    let verdict = if failed == 0 { "ok" } else { "FAILED" };
    println!("\ntest result: {verdict}. {} passed; {failed} failed", checks.len() - failed);
    if failed == 0 { ExitCode::SUCCESS } else { ExitCode::FAILURE }
}

/// Draw once, fork, draw in parent and child, and report whether the two draws
/// differ. A per-thread userspace generator copied by `fork` repeats; a direct
/// operating-system read does not. The warm-up and both measured draws stay in
/// this one process.
pub fn draws_differ_across_fork(draw: impl Fn() -> Vec<u8>) -> bool {
    let _warm = draw();
    let threads = thread_count();
    // Linux and macOS report the count, so a missing answer fails rather than skips.
    if cfg!(any(target_os = "linux", target_os = "macos")) || threads.is_some() {
        assert_eq!(threads, Some(1), "fork needs a single-threaded process");
    }
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: fds has room for two descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    // SAFETY: the process has exactly one thread (checked above), so the child
    // may allocate and run library code before it exits.
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
