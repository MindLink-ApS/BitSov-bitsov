//! `konsensus seed encrypt` and `start --password-file` at the binary boundary.
//! The migration itself (with a typed password) is unit-tested in
//! `cli/seed.rs`; here: nothing changes without a terminal or while the node
//! runs, and a loose password file is refused before anything boots.
#![cfg(unix)]

use std::process::{Command, Stdio};

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
    detach(&mut cmd);
    cmd
}

/// Run the command in a new session with no controlling terminal, so a
/// password prompt fails at once even when the tests run in a terminal.
fn detach(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: `setsid` is async-signal-safe and touches no Rust state; it runs
    // in the forked child before exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}


fn init() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let ok = bin()
        .args(["init", "--dir"])
        .arg(dir.path())
        .args(["--non-interactive", "--tier", "light"])
        .stdout(Stdio::null())
        .status()
        .unwrap()
        .success();
    assert!(ok);
    dir
}

fn snapshot(dir: &std::path::Path) -> (Vec<u8>, Vec<u8>, bool) {
    (
        std::fs::read(dir.join("mnemonic.txt")).unwrap(),
        std::fs::read(dir.join("konsensus.toml")).unwrap(),
        dir.join("mnemonic.enc").exists(),
    )
}

#[test]
fn without_a_terminal_for_the_password_nothing_changes() {
    let dir = init();
    let before = snapshot(dir.path());
    let out = bin()
        .args(["seed", "encrypt", "--config"])
        .arg(dir.path().join("konsensus.toml"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("failed to read the password from the terminal"), "failed for the right reason: {stderr}");
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn it_refuses_while_the_node_is_running() {
    let dir = init();
    let before = snapshot(dir.path());
    let _running = std::os::unix::net::UnixListener::bind(dir.path().join("control.sock")).unwrap();
    let out = bin()
        .args(["seed", "encrypt", "--config"])
        .arg(dir.path().join("konsensus.toml"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("Stop it first"));
    assert_eq!(snapshot(dir.path()), before);
}

#[test]
fn a_password_file_others_can_read_is_refused_before_start() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("pw");
    std::fs::write(&file, "correct horse battery\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    let out = bin()
        .args(["start", "--config"])
        .arg(dir.path().join("missing.toml"))
        .arg("--password-file")
        .arg(&file)
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("chmod 600"), "{stderr}");
    assert!(stderr.contains("other OS users only"), "the owner is told what the file does not protect: {stderr}");
}
