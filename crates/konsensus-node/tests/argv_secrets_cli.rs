//! Legacy argv secrets require explicit opt-in, before any command side effects.
use std::process::{Command, Stdio};

const SECRET: &str = "argv-test-secret-never-echo";

#[test]
fn refuses_all_argv_secret_options_before_io() {
    let cases = [
        vec!["start", "--password", SECRET],
        vec!["node-id", "--config", "missing", "--password", SECRET],
        vec![
            "sign-challenge",
            "--config",
            "missing",
            "--challenge",
            "unused",
            "--password",
            SECRET,
        ],
        vec!["whitelist", "backup", "--password", SECRET],
        vec![
            "whitelist",
            "restore",
            "--from",
            "missing",
            "--password",
            SECRET,
        ],
        vec!["scb", "restore", "--from", "missing", "--password", SECRET],
        vec!["restore", "--mnemonic", SECRET],
        vec!["restore", "-m", SECRET],
        vec![
            "approve-replacement",
            "--op",
            "unused",
            "--mnemonic",
            SECRET,
        ],
        vec!["init", "--encrypt", SECRET],
        vec!["restore", "--encrypt", SECRET],
        vec!["node-id", "--config", "missing", "--passphrase", SECRET],
        vec![
            "sign-challenge",
            "--config",
            "missing",
            "--challenge",
            "unused",
            "--passphrase",
            SECRET,
        ],
        vec!["start", "--password=argv-test-secret-never-echo"],
        vec!["start", "--password="],
    ];
    for args in cases {
        let dir = tempfile::tempdir().unwrap();
        // A malformed config prevents an ungated regression from starting a server.
        std::fs::write(dir.path().join("konsensus.toml"), "invalid config").unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .args(&args)
            .current_dir(dir.path())
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!out.status.success(), "{args:?}");
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("WARNING")
                && err.contains("deprecated")
                && err.contains("--insecure-argv"),
            "{args:?}: {err}"
        );
        assert!(
            err.contains("--password-fd") && err.contains("--password-file"),
            "{err}"
        );
        assert!(!err.contains(SECRET), "secret leaked: {err}");
        assert!(out.stdout.is_empty());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[test]
fn explicit_opt_in_warns_and_allows_legacy_encryption_and_mnemonic() {
    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    for global_first in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
        if global_first {
            cmd.arg("--insecure-argv");
        }
        cmd.args([
            "restore",
            "--mnemonic",
            PHRASE,
            "--encrypt",
            SECRET,
            "--tier",
            "light",
            "--dir",
        ])
        .arg(dir.path());
        if !global_first {
            cmd.arg("--insecure-argv");
        }
        let out = cmd.stdin(Stdio::null()).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "{err}");
        assert!(
            err.contains("WARNING") && err.contains("--mnemonic") && err.contains("--encrypt"),
            "{err}"
        );
        assert!(!err.contains(SECRET) && !err.contains(PHRASE));
        assert!(dir.path().join("mnemonic.enc").exists());
        assert!(!dir.path().join("mnemonic.txt").exists());
        let out = Command::new(env!("CARGO_BIN_EXE_konsensus"))
            .args([
                "node-id",
                "--password",
                SECRET,
                "--insecure-argv",
                "--config",
            ])
            .arg(dir.path().join("konsensus.toml"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("WARNING"));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim().len(), 64);
    }
}
