//! `[pairing] unattended_device_approvals` through the real `konsensus start`.
#![cfg(unix)]

use std::os::unix::fs::{FileExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "unattended-test-password";

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
    // SAFETY: only an async-signal-safe syscall runs between fork and exec.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd
}

struct Node {
    dir: tempfile::TempDir,
    config: std::path::PathBuf,
    password_file: std::path::PathBuf,
}

fn initialized_node() -> Node {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let mut init = bin()
        .args(["init", "--non-interactive", "--tier", "light", "--dir"])
        .arg(dir.path())
        .args(["--password-fd", "0"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    init.stdin
        .take()
        .unwrap()
        .write_all(PASSWORD.as_bytes())
        .unwrap();
    assert!(init.wait().unwrap().success());
    assert!(dir.path().join("mnemonic.enc").exists());

    let config = dir.path().join("konsensus.toml");
    let mut toml_config: toml::Value = std::fs::read_to_string(&config)
        .unwrap()
        .parse()
        .unwrap();
    toml_config["network"]["listen_addr"] = "127.0.0.1:0".into();
    let api_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    toml_config["api"]["listen_addr"] = api_port.local_addr().unwrap().to_string().into();
    std::fs::write(&config, toml::to_string(&toml_config).unwrap()).unwrap();

    let password_file = dir.path().join("pw");
    std::fs::write(&password_file, format!("{PASSWORD}\n")).unwrap();
    std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    Node {
        dir,
        config,
        password_file,
    }
}

fn set_setting(config: &Path, on: bool) {
    let mut value: toml::Value = std::fs::read_to_string(config).unwrap().parse().unwrap();
    let table = value.as_table_mut().unwrap();
    let pairing = table
        .entry("pairing")
        .or_insert_with(|| toml::Value::Table(Default::default()));
    pairing
        .as_table_mut()
        .unwrap()
        .insert("unattended_device_approvals".into(), on.into());
    std::fs::write(config, toml::to_string(&value).unwrap()).unwrap();
}

/// Start until the API listens, kill the node, and return everything it printed.
fn start_log(node: &Node) -> String {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let output = tempfile::tempfile().unwrap();
    let mut child = Child(
        bin()
            .args(["start", "--config"])
            .arg(&node.config)
            .arg("--password-file")
            .arg(&node.password_file)
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output.try_clone().unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let mut bytes = vec![0; output.metadata().unwrap().len() as usize];
        output.read_exact_at(&mut bytes, 0).unwrap();
        let log = String::from_utf8_lossy(&bytes).into_owned();
        assert!(!log.contains(PASSWORD), "password in output");
        if log.contains("API server listening") {
            return log;
        }
        assert!(child.0.try_wait().unwrap().is_none(), "node exited: {log}");
        assert!(Instant::now() < deadline, "startup timed out: {log}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_password_file_start_follows_the_owner_setting_and_says_which_mode_it_is_in() {
    let node = initialized_node();

    // Default: nothing in the config, approvals off, the setting named as the way on.
    let log = start_log(&node);
    assert!(log.contains("device approvals (Touch ID) are OFF"), "{log}");
    assert!(log.contains("seed_password_not_typed"), "{log}");
    assert!(log.contains("unattended_device_approvals"), "{log}");
    assert!(!log.contains("device approvals (Touch ID) enabled"), "{log}");

    // Explicitly off is the same.
    set_setting(&node.config, false);
    let log = start_log(&node);
    assert!(log.contains("seed_password_not_typed"), "{log}");

    // On: enabled, the mode and the trade are stated, and no console appears.
    set_setting(&node.config, true);
    let log = start_log(&node);
    assert!(log.contains("device approvals (Touch ID) enabled"), "{log}");
    assert!(log.contains("owner_setting"), "{log}");
    assert!(
        log.contains("whoever gets this disk and the password can approve as the owner"),
        "{log}"
    );
    assert!(!log.contains("seed_password_not_typed"), "{log}");
    assert!(!node.dir.path().join("control.sock").exists());
    assert!(!std::fs::read_to_string(node.dir.path().join("node.log"))
        .unwrap()
        .contains(PASSWORD));

    // Removing the setting returns to off on the same data.
    set_setting(&node.config, false);
    let log = start_log(&node);
    assert!(log.contains("seed_password_not_typed"), "{log}");
}

#[test]
fn a_hosted_box_keeps_approvals_off_and_says_why() {
    let node = initialized_node();
    set_setting(&node.config, true);
    let mut value: toml::Value = std::fs::read_to_string(&node.config)
        .unwrap()
        .parse()
        .unwrap();
    value["identity"]
        .as_table_mut()
        .unwrap()
        .insert("hosted".into(), true.into());
    std::fs::write(&node.config, toml::to_string(&value).unwrap()).unwrap();
    let log = start_log(&node);
    assert!(log.contains("seed_password_not_typed"), "{log}");
    assert!(log.contains("is set but does not apply"), "{log}");
    assert!(log.contains("run for someone else"), "{log}");
    assert!(!log.contains("device approvals (Touch ID) enabled"), "{log}");
}

#[test]
fn a_too_open_password_file_is_refused_with_the_setting_on() {
    let node = initialized_node();
    set_setting(&node.config, true);
    for mode in [0o640, 0o604] {
        std::fs::set_permissions(&node.password_file, std::fs::Permissions::from_mode(mode))
            .unwrap();
        let out = bin()
            .args(["start", "--config"])
            .arg(&node.config)
            .arg("--password-file")
            .arg(&node.password_file)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!out.status.success(), "{mode:o}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("readable by its owner only"), "{stderr}");
        assert!(!stderr.contains(PASSWORD));
    }
}

#[test]
fn a_wrong_password_in_the_file_starts_nothing() {
    let node = initialized_node();
    set_setting(&node.config, true);
    std::fs::write(&node.password_file, "not-the-password\n").unwrap();
    let out = bin()
        .args(["start", "--config"])
        .arg(&node.config)
        .arg("--password-file")
        .arg(&node.password_file)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!all.contains("device approvals (Touch ID) enabled"), "{all}");
    assert!(!all.contains("not-the-password"), "{all}");
}
