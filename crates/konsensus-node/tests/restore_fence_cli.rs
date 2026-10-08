//! Real CLI boundary: init binds, refusal precedes seed loading, pipes cannot rebind.
#![cfg(unix)]
use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

fn bin() -> Command {
    use std::os::unix::process::CommandExt;
    let mut command = Command::new(env!("CARGO_BIN_EXE_konsensus"));
    // SAFETY: setsid is async-signal-safe; no Rust state is touched before exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command
}

fn init() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let output = bin()
        .args(["init", "--non-interactive", "--dir"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dir.path().join("ldk/INSTANCE").is_file());
    dir
}

#[test]
fn real_start_refuses_binding_and_journal_before_loading_seed() {
    for journal in [false, true] {
        let dir = init();
        fs::write(dir.path().join("mnemonic.txt"), "invalid seed").unwrap();
        if journal {
            fs::write(
                dir.path().join("ldk/recover.json"),
                r#"{"version":1,"state":"open"}"#,
            )
            .unwrap();
        } else {
            let path = dir.path().join("ldk/INSTANCE");
            let mut record: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            record["binding"] = serde_json::Value::String("0".repeat(64));
            fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        }
        let output = bin()
            .args(["start", "--config"])
            .arg(dir.path().join("konsensus.toml"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains("konsensus recover"), "{error}");
        assert!(
            error.contains(if journal {
                "recover.json"
            } else {
                "host_binding_mismatch"
            }),
            "{error}"
        );
        assert!(!dir.path().join("ldk/ldk_node_data.sqlite").exists());
    }
}

#[test]
fn exact_piped_confirmation_cannot_replace_owner_console() {
    let dir = init();
    let path = dir.path().join("ldk/INSTANCE");
    let before = fs::read(&path).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&before).unwrap();
    // Even the exact valid challenge for this host must not work via stdin.
    let answer = format!(
        "REBIND {} TO {}\n",
        record["instance_id"].as_str().unwrap(),
        record["binding"].as_str().unwrap()
    );
    let mut child = bin()
        .args(["rebind-instance", "--config"])
        .arg(dir.path().join("konsensus.toml"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(answer.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("controlling console"));
    assert_eq!(fs::read(path).unwrap(), before);
}
