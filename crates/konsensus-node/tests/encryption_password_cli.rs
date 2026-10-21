//! Encryption intent must never silently fall back to plaintext.
use std::{
    io::Write,
    process::{Command, Output, Stdio},
};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

fn run(command: &str, dir: &std::path::Path, args: &[&str], input: &str) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
    cmd.args([command, "--dir"])
        .arg(dir)
        .args(["--tier", "full"]);
    let mut child = cmd
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = if command == "restore" {
        format!("{input}{PHRASE}\n")
    } else {
        input.to_owned()
    };
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn legacy_blank_explicit_passwords_write_nothing_with_opt_in() {
    for command in ["init", "restore"] {
        for password in ["", "   ", "\t", "\u{2003}\u{a0}"] {
            for existing_dir in [false, true] {
                let temp = tempfile::tempdir().unwrap();
                let dir = temp.path().join("node");
                if existing_dir {
                    std::fs::create_dir(&dir).unwrap();
                }
                let mut args = vec!["--encrypt", password, "--insecure-argv"];
                if command == "init" {
                    args.push("--non-interactive");
                }
                let out = run(command, &dir, &args, "");
                assert!(!out.status.success(), "{command} accepted a blank password");
                let error = String::from_utf8_lossy(&out.stderr);
                assert!(
                    error.contains("must not be empty or whitespace-only"),
                    "{error}"
                );
                assert!(!dir.exists() || std::fs::read_dir(&dir).unwrap().count() == 0);
            }
        }
    }
}

#[test]
fn blank_prompt_passwords_write_nothing() {
    for command in ["init", "restore"] {
        for input in ["\n", "   \n", "\t\n"] {
            let temp = tempfile::tempdir().unwrap();
            let dir = temp.path().join("node");
            let out = run(command, &dir, &["--encrypt"], input);
            assert!(!out.status.success());
            let error = String::from_utf8_lossy(&out.stderr);
            assert!(
                error.contains("must not be empty or whitespace-only"),
                "{error}"
            );
            assert!(!dir.exists() || std::fs::read_dir(&dir).unwrap().count() == 0);
        }
    }
}

#[test]
fn non_interactive_encrypt_requires_a_password() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path().join("node");
    let out = run("init", &dir, &["--non-interactive", "--encrypt"], "");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires a password"));
    assert!(!dir.exists());
}

#[test]
fn safe_normal_password_creates_only_encrypted_mnemonic() {
    for command in ["init", "restore"] {
        let temp = tempfile::tempdir().unwrap();
        let args: &[&str] = if command == "init" {
            &["--non-interactive", "--password-fd", "0"]
        } else {
            &["--encrypt"]
        };
        let out = run(command, temp.path(), args, "  normal password  \n");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(!temp.path().join("mnemonic.txt").exists());
        let bytes = std::fs::read(temp.path().join("mnemonic.enc")).unwrap();
        assert_eq!(bytes[0], 1);
        assert!(std::fs::read_to_string(temp.path().join("konsensus.toml"))
            .unwrap()
            .contains("mnemonic.enc"));
    }
}

#[cfg(unix)]
#[test]
fn blank_init_descriptor_password_writes_nothing() {
    for input in ["\n", "          \n", "\t\n"] {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let out = run(
            "init",
            &dir,
            &["--non-interactive", "--password-fd", "0"],
            input,
        );
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("empty"));
        assert!(!dir.exists());
    }
}

#[test]
fn blank_bootstrap_password_writes_nothing() {
    for password in ["", "          "] {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let mut child = Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .arg("start")
            .arg("--config")
            .arg(dir.join("konsensus.toml"))
            .args(["--password-fd", "0"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        writeln!(child.stdin.take().unwrap(), "{password}").unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(!out.status.success());
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(
            error.contains("must not be empty or whitespace-only")
                || error.contains("descriptor is empty"),
            "{error}"
        );
        assert!(
            !dir.exists(),
            "bootstrap wrote files before rejecting the password"
        );
    }
}

#[test]
fn piped_restore_reads_password_before_mnemonic() {
    let temp = tempfile::tempdir().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["restore", "--dir"])
        .arg(temp.path())
        .args(["--tier", "full", "--encrypt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    writeln!(
        child.stdin.take().unwrap(),
        "  piped password-é  \r\n{PHRASE}"
    )
    .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("piped password"));
    assert!(temp.path().join("mnemonic.enc").exists());
    assert!(!temp.path().join("mnemonic.txt").exists());
}
