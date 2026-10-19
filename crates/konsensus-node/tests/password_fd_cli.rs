//! Password handoff through stdin and an inherited Unix descriptor.
#![cfg(unix)]

#[allow(dead_code)] // The fixture reader does not use every production crypto entry point.
#[path = "../src/mnemonic_crypto.rs"]
mod mnemonic_crypto;

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::{net::UnixStream, process::CommandExt};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "  Keychain-test-secret-é  ";

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

fn no_secret(bytes: &[u8]) {
    assert!(!String::from_utf8_lossy(bytes).contains(PASSWORD));
}

fn input(mut cmd: Command, password: &[u8], inherited: bool) -> Output {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    writer.write_all(password).unwrap();
    drop(writer); // EOF is part of the handoff protocol.
    let fd = reader.as_raw_fd();
    if inherited {
        cmd.args(["--password-fd", "9"]).stdin(Stdio::null());
        // SAFETY: fd stays open through spawn; dup2 is async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(fd, 9) == -1 || libc::fcntl(9, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    } else {
        cmd.args(["--password-fd", "0"])
            .stdin(Stdio::from(std::os::fd::OwnedFd::from(
                reader.try_clone().unwrap(),
            )));
    }
    let out = cmd.output().unwrap();
    no_secret(&out.stdout);
    no_secret(&out.stderr);
    if let Ok(secret) = std::str::from_utf8(password) {
        let secret = secret.trim_end_matches(['\r', '\n']);
        if !secret.is_empty() {
            assert!(!String::from_utf8_lossy(&out.stdout).contains(secret));
            assert!(!String::from_utf8_lossy(&out.stderr).contains(secret));
        }
    }
    out
}

fn init(dir: &Path, inherited: bool) -> Output {
    let mut cmd = bin();
    cmd.args(["init", "--non-interactive", "--tier", "light", "--dir"])
        .arg(dir);
    input(cmd, format!("{PASSWORD}\r\n").as_bytes(), inherited)
}

const CHALLENGE: &str =
    "bitsov-auth-v1:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff:1700000000";

fn sign_challenge(path_flag: &str, path: &Path) -> Command {
    let mut cmd = bin();
    cmd.args(["sign-challenge", "--challenge", CHALLENGE, path_flag])
        .arg(path);
    cmd
}

#[test]
fn sign_challenge_encrypted_seed_matches_plaintext_identity() {
    use ed25519_dalek::Verifier;

    let dir = tempfile::tempdir().unwrap();
    assert!(init(dir.path(), false).status.success());
    let encrypted = dir.path().join("mnemonic.enc");
    let original = std::fs::read(&encrypted).unwrap();
    let mnemonic = mnemonic_crypto::read_mnemonic(&encrypted, Some(PASSWORD)).unwrap();
    let plaintext = dir.path().join("mnemonic.txt");
    std::fs::write(&plaintext, mnemonic.as_str()).unwrap();
    let identity = konsensus_core::NodeIdentity::from_mnemonic(&mnemonic, "").unwrap();
    let plain = sign_challenge("--mnemonic", &plaintext)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(plain.status.success());
    assert!(plain.stderr.is_empty(), "plaintext must not prompt");
    let signature = ed25519_dalek::Signature::from_slice(
        &hex::decode(String::from_utf8_lossy(&plain.stdout).trim()).unwrap(),
    )
    .unwrap();
    identity
        .ed25519_verifying_key()
        .verify(CHALLENGE.as_bytes(), &signature)
        .unwrap();

    for inherited in [false, true] {
        for (flag, path) in [
            ("--mnemonic", encrypted.clone()),
            ("--config", dir.path().join("konsensus.toml")),
        ] {
            let out = input(
                sign_challenge(flag, &path),
                format!("{PASSWORD}\r\n").as_bytes(),
                inherited,
            );
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(out.stdout, plain.stdout);
            assert!(out.stderr.is_empty(), "descriptor input must not prompt");
        }
    }
    assert_eq!(std::fs::read(&encrypted).unwrap(), original);
    assert_eq!(
        std::fs::read_to_string(&plaintext).unwrap(),
        mnemonic.as_str()
    );
}

#[test]
fn sign_challenge_wrong_password_fails_without_signature_or_secret() {
    let dir = tempfile::tempdir().unwrap();
    assert!(init(dir.path(), false).status.success());
    let encrypted = dir.path().join("mnemonic.enc");
    let original = std::fs::read(&encrypted).unwrap();
    for inherited in [false, true] {
        let out = input(
            sign_challenge("--mnemonic", &encrypted),
            b"wrong-signing-password",
            inherited,
        );
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("decryption failed"));
        assert!(!String::from_utf8_lossy(&out.stderr).contains("panicked"));
    }
    assert_eq!(std::fs::read(&encrypted).unwrap(), original);
}

#[test]
fn sign_challenge_encrypted_seed_requires_terminal_or_explicit_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    assert!(init(dir.path(), false).status.success());
    let encrypted = dir.path().join("mnemonic.enc");
    let out = sign_challenge("--mnemonic", &encrypted)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(String::from_utf8_lossy(&out.stderr).contains("failed to read password from terminal"));

    let out = sign_challenge("--mnemonic", &encrypted)
        .args(["--password-fd", "2147483647"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let error = String::from_utf8_lossy(&out.stderr);
    assert!(error.contains("cannot read password descriptor"));
    assert!(!error.contains("Enter password"));
}

#[test]
fn sign_challenge_plaintext_needs_no_password_input() {
    let dir = tempfile::tempdir().unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about\n";
    let path = dir.path().join("mnemonic.txt");
    std::fs::write(&path, mnemonic).unwrap();
    // An unusable descriptor must not be read for a plaintext mnemonic.
    let out = sign_challenge("--mnemonic", &path)
        .args(["--password-fd", "2147483647"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.stderr.is_empty());
    assert_eq!(out.stdout.len(), 129);
    assert_eq!(std::fs::read_to_string(path).unwrap(), mnemonic);
}

#[test]
fn empty_invalid_and_oversized_input_fail_before_creating_identity() {
    for password in [vec![], b"\r\n".to_vec(), vec![0xff], vec![b'x'; 4097]] {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = bin();
        cmd.args(["init", "--non-interactive", "--dir"])
            .arg(dir.path());
        let out = input(cmd, &password, false);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("password"));
        assert!(!dir.path().join("mnemonic.txt").exists());
        assert!(!dir.path().join("mnemonic.enc").exists());
        assert!(!dir.path().join("NODE_INITIALIZED").exists());
    }
}

#[test]
fn closed_descriptor_fails_without_prompting() {
    for command in ["init", "start"] {
        let out = bin()
            .args([command, "--password-fd", "2147483647"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read password descriptor"));
    }
}

#[test]
fn init_encrypts_and_start_decrypts_from_a_single_handoff_without_logging_it() {
    for inherited in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let out = init(dir.path(), inherited);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(dir.path().join("mnemonic.enc").exists());
        assert!(!dir.path().join("mnemonic.txt").exists());
        let config_path = dir.path().join("konsensus.toml");
        let mut config: toml::Value = std::fs::read_to_string(&config_path)
            .unwrap()
            .parse()
            .unwrap();
        config["network"]["listen_addr"] = "127.0.0.1:0".into();
        let api_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        config["api"]["listen_addr"] = api_port.local_addr().unwrap().to_string().into();
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();

        let mut wrong = bin();
        wrong.args(["start", "--config"]).arg(&config_path);
        let out = input(wrong, b"wrong-password", inherited);
        assert!(!out.status.success());
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("decryption failed"),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );

        drop(api_port);
        // Reuse the same initialized data across starts. Removing the local
        // flag after an enabled start must return to descriptor refusal.
        for local_owner in [false, true, false] {
            // Redirect both output streams to a file so a child cannot block on a
            // full output pipe. A guard always kills/reaps it, including on panic.
            let output = tempfile::tempfile().unwrap();
            let (reader, mut writer) = UnixStream::pair().unwrap();
            writer.write_all(PASSWORD.as_bytes()).unwrap();
            drop(writer);
            let fd = reader.as_raw_fd();
            let mut cmd = bin();
            cmd.args(["start", "--config"]).arg(&config_path);
            if local_owner {
                cmd.arg("--local-owner-device");
            }
            if inherited {
                cmd.args(["--password-fd", "9"]).stdin(Stdio::null());
                // SAFETY: same descriptor handoff as in input(), before exec only.
                unsafe {
                    cmd.pre_exec(move || {
                        if libc::dup2(fd, 9) == -1 || libc::fcntl(9, libc::F_SETFD, 0) == -1 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            } else {
                cmd.args(["--password-fd", "0"])
                    .stdin(Stdio::from(std::os::fd::OwnedFd::from(
                        reader.try_clone().unwrap(),
                    )));
            }
            cmd.stdout(output.try_clone().unwrap())
                .stderr(output.try_clone().unwrap());
            struct Child(std::process::Child);
            impl Drop for Child {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let mut child = Child(cmd.spawn().unwrap());
            let deadline = Instant::now() + Duration::from_secs(45);
            loop {
                use std::os::unix::fs::FileExt;
                let mut bytes = vec![0; output.metadata().unwrap().len() as usize];
                output.read_exact_at(&mut bytes, 0).unwrap();
                no_secret(&bytes);
                let log = String::from_utf8_lossy(&bytes);
                if log.contains("API server listening") {
                    assert!(log.contains("node built"));
                    if local_owner {
                        assert!(log.contains("device approvals (Touch ID) enabled"), "{log}");
                        assert!(!log.contains("seed_password_not_typed"), "{log}");
                    } else {
                        assert!(log.contains("seed_password_not_typed"), "{log}");
                    }
                    assert!(!dir.path().join("control.sock").exists());
                    break;
                }
                assert!(child.0.try_wait().unwrap().is_none(), "node exited: {log}");
                assert!(Instant::now() < deadline, "startup timed out: {log}");
                std::thread::sleep(Duration::from_millis(50));
            }
            drop(child);
            no_secret(&std::fs::read(dir.path().join("node.log")).unwrap());
        }
    }
}

fn directory_snapshot(dir: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
    let mut snapshot = std::collections::BTreeMap::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            snapshot.insert(path.clone(), Vec::new());
            snapshot.extend(directory_snapshot(&path));
        } else {
            snapshot.insert(path.clone(), std::fs::read(path).unwrap());
        }
    }
    snapshot
}

#[test]
fn local_owner_unavailable_verifier_refuses_start_without_writing_files() {
    for case in [
        "plaintext",
        "wrong-password",
        "plaintext-sibling",
        "unusable-seed",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let out = init(dir.path(), false);
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let config_path = dir.path().join("konsensus.toml");
        let mut config: toml::Value = std::fs::read_to_string(&config_path)
            .unwrap()
            .parse()
            .unwrap();
        config["network"]["listen_addr"] = "127.0.0.1:0".into();
        let api_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        config["api"]["listen_addr"] = api_port.local_addr().unwrap().to_string().into();
        drop(api_port);
        if matches!(case, "plaintext" | "plaintext-sibling") {
            std::fs::write(dir.path().join("mnemonic.txt"),
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        }
        if case == "plaintext" {
            config["identity"]["mnemonic_file"] =
                dir.path().join("mnemonic.txt").to_str().unwrap().into();
            std::fs::remove_file(dir.path().join("mnemonic.enc")).unwrap();
        } else if case == "unusable-seed" {
            std::fs::write(dir.path().join("mnemonic.enc"), b"invalid encrypted seed").unwrap();
        }
        std::fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let before = directory_snapshot(dir.path());
        let output = tempfile::tempfile().unwrap();
        let mut child = bin()
            .args([
                "start",
                "--local-owner-device",
                "--password-fd",
                "0",
                "--config",
            ])
            .arg(&config_path)
            .stdin(Stdio::piped())
            .stdout(output.try_clone().unwrap())
            .stderr(output.try_clone().unwrap())
            .spawn()
            .unwrap();
        let password = if case == "wrong-password" {
            "wrong-password"
        } else {
            PASSWORD
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(password.as_bytes())
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{case}: local owner startup must refuse without a verifier");
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        use std::os::unix::fs::FileExt;
        let mut bytes = vec![0; output.metadata().unwrap().len() as usize];
        output.read_exact_at(&mut bytes, 0).unwrap();
        no_secret(&bytes);
        let log = String::from_utf8_lossy(&bytes);
        assert!(!status.success(), "{case}: {log}");
        assert!(
            log.contains("--local-owner-device requires an available owner verifier"),
            "{case}: {log}"
        );
        assert_eq!(
            directory_snapshot(dir.path()),
            before,
            "{case}: refused startup wrote files"
        );
    }
}
