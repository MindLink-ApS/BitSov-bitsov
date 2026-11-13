//! A newly created box transport key is a direct operating-system draw: a
//! forked process creating its own key does not repeat the parent's (a per-thread
//! userspace generator copied by `fork` would).
#![cfg(unix)]

use konsensus_api::pairing::load_box_transport_key;

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
fn new_box_transport_keys_are_fresh_os_draws() {
    let draw = || {
        let dir = tempfile::tempdir().unwrap();
        load_box_transport_key(dir.path()).unwrap().to_vec()
    };
    assert!(draws_differ_across_fork(draw), "box transport key repeats across fork");
}
