//! Real CLI boundary: init binds, refusal precedes seed loading, pipes cannot rebind.
#![cfg(unix)]
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
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

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let dest = to.join(entry.file_name());
        let file_type = entry.file_type().unwrap();
        assert!(
            !file_type.is_symlink(),
            "snapshot copy expects regular files, found {}",
            entry.path().display()
        );
        if file_type.is_dir() {
            copy_tree(&entry.path(), &dest);
        } else {
            fs::copy(entry.path(), &dest).unwrap();
        }
    }
}

/// Fields `default_for_tier` roots in the node directory. The mnemonic keeps the
/// path passed to init; the database, audit log, and backup directory are
/// canonicalized (`NodeConfig::default_for_tier`).
const NODE_DIR_FIELDS: &[(&str, &str)] = &[
    ("identity", "mnemonic_file"),
    ("storage", "path"),
    ("backup", "scb_dir"),
    ("api", "audit_log_path"),
];

fn toml_table<'a>(value: &'a toml::Value, key: &str) -> &'a toml::Table {
    value
        .get(key)
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("missing [{key}]"))
}

fn toml_string(table: &toml::Table, key: &str) -> String {
    table
        .get(key)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("missing {key}"))
        .to_owned()
}

/// Rebase `path` onto `to_root` by a path-component prefix, never a substring.
/// Canonical is tried before the lexical root: on macOS `/var/...` is not a
/// component prefix of `/private/var/...`, so the lexical form cannot cut the
/// canonical fields in half.
fn rebase_rooted(path: &Path, from_roots: &[&Path], to_root: &Path) -> PathBuf {
    for root in from_roots {
        if let Ok(rest) = path.strip_prefix(root) {
            return to_root.join(rest);
        }
    }
    panic!(
        "{} is not under the original node directory",
        path.display()
    );
}

fn lies_under_snapshot(path: &Path, snapshot_root: &Path) -> bool {
    path.starts_with(snapshot_root)
}

/// Point the copied config at the snapshot. Init writes absolute paths.
fn retarget_snapshot(snapshot: &Path, original: &Path) {
    let config = snapshot.join("konsensus.toml");
    let raw = fs::read_to_string(&config).unwrap();
    let snapshot_root = snapshot.canonicalize().unwrap();
    let original_canonical = original.canonicalize().unwrap();
    let parsed: toml::Value = toml::from_str(&raw).expect("init config is toml");
    let from_roots = [original_canonical.as_path(), original];
    let mut pairs: Vec<(String, PathBuf)> = NODE_DIR_FIELDS
        .iter()
        .map(|(table, key)| {
            let current = toml_string(toml_table(&parsed, table), key);
            let next = rebase_rooted(Path::new(&current), &from_roots, &snapshot_root);
            (current, next)
        })
        .collect();
    // Longer full paths first, so one field value cannot split another.
    pairs.sort_by_key(|left| std::cmp::Reverse(left.0.len()));
    let mut updated = raw;
    for (current, next) in &pairs {
        assert!(
            lies_under_snapshot(next, &snapshot_root),
            "malformed retargeted path {}",
            next.display()
        );
        assert!(
            updated.contains(current),
            "config is missing the parsed path {current}"
        );
        updated = updated.replacen(current, &next.display().to_string(), 1);
    }
    let snapshot_text = snapshot_root.display().to_string();
    assert!(
        updated.contains(&snapshot_text),
        "snapshot config must name its own directory"
    );
    assert!(
        !updated.contains(&original_canonical.display().to_string()),
        "snapshot config must not keep the original directory"
    );
    let checked: toml::Value = toml::from_str(&updated).expect("retargeted config is toml");
    for (table, key) in NODE_DIR_FIELDS {
        let path = PathBuf::from(toml_string(toml_table(&checked, table), key));
        assert!(
            lies_under_snapshot(&path, &snapshot_root),
            "{table}.{key} = {} is outside {}",
            path.display(),
            snapshot_root.display()
        );
    }
    fs::write(config, updated).unwrap();
}

#[test]
fn retarget_rejects_a_doubled_prefix_the_substring_replace_accepted() {
    let lexical = Path::new("/var/folders/ab/original");
    let canonical = Path::new("/private/var/folders/ab/original");
    let snapshot = Path::new("/private/var/folders/ab/snapshot");
    let roots = [canonical, lexical];
    let database = rebase_rooted(&canonical.join("konsensus.db"), &roots, snapshot);
    let mnemonic = rebase_rooted(&lexical.join("mnemonic.txt"), &roots, snapshot);
    let backups = rebase_rooted(&canonical.join("backups"), &roots, snapshot);
    let audit = rebase_rooted(&canonical.join("audit.jsonl"), &roots, snapshot);
    assert_eq!(database, snapshot.join("konsensus.db"));
    assert_eq!(mnemonic, snapshot.join("mnemonic.txt"));
    assert_eq!(backups, snapshot.join("backups"));
    assert_eq!(audit, snapshot.join("audit.jsonl"));
    for path in [&database, &mnemonic, &backups, &audit] {
        assert!(lies_under_snapshot(path, snapshot), "{}", path.display());
    }

    // Lexical-then-canonical substring replacement produced this path. The old
    // assertions accepted it: the snapshot root is a substring, and the
    // original canonical root is no longer present.
    let doubled = Path::new("/private/private/var/folders/ab/snapshot/konsensus.db");
    let rendered = doubled.display().to_string();
    assert!(rendered.contains(&snapshot.display().to_string()));
    assert!(!rendered.contains(&canonical.display().to_string()));
    assert!(
        !lies_under_snapshot(doubled, snapshot),
        "a doubled /private prefix is not the snapshot root"
    );
}

fn snapshot_copy() -> (tempfile::TempDir, tempfile::TempDir) {
    let original = init();
    let snapshot = tempfile::tempdir().unwrap();
    assert!(
        !snapshot
            .path()
            .display()
            .to_string()
            .contains(&original.path().display().to_string()),
        "temp paths must not overlap"
    );
    copy_tree(original.path(), snapshot.path());
    retarget_snapshot(snapshot.path(), original.path());
    fs::write(
        snapshot.path().join("ldk/ldk_node_data.sqlite"),
        b"not-a-wallet",
    )
    .unwrap();
    (original, snapshot)
}

struct Terminal {
    master: Option<File>,
    slave: Option<File>,
    child: Child,
    output: String,
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.child.kill();
        drop(self.master.take());
        drop(self.slave.take());
        let _ = self.child.wait();
    }
}

impl Terminal {
    /// Same controlling-terminal setup as `encryption_password_tty.rs`.
    fn rebind(config: &Path) -> Self {
        use std::os::unix::process::CommandExt;
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
        cmd.args(["rebind-instance", "--config"]).arg(config);
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: openpty initializes both descriptors; optional settings are null.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        // SAFETY: successful openpty returned distinct owned descriptors.
        let (master, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        for fd in [&master, &slave] {
            // SAFETY: each descriptor is valid. Do not leak the PTY master into the child.
            assert_eq!(
                unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
        }
        // SAFETY: master is a valid descriptor; only its status flags change.
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        // SAFETY: only syscalls run after fork. The slave is fd 0; setsid plus
        // TIOCSCTTY makes /dev/tty this isolated PTY.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Self {
            master: Some(master),
            slave: Some(slave),
            child: cmd.spawn().unwrap(),
            output: String::new(),
        }
    }

    fn read_until(&mut self, expected: &str) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self.output.contains(expected) {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {expected:?}: {}",
                self.output
            );
            let mut poll = libc::pollfd {
                fd: self.master.as_ref().unwrap().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll points to one initialized pollfd with a valid descriptor.
            let ready = unsafe { libc::poll(&mut poll, 1, 100) };
            if ready < 0 {
                let error = std::io::Error::last_os_error();
                assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
                continue;
            }
            if ready > 0 {
                let mut bytes = [0; 4096];
                let n = match self.master.as_mut().unwrap().read(&mut bytes) {
                    Ok(n) => n,
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        continue
                    }
                    Err(error) => panic!("terminal read failed: {error}: {}", self.output),
                };
                assert!(
                    n > 0,
                    "terminal closed before {expected:?}: {}",
                    self.output
                );
                self.output.push_str(&String::from_utf8_lossy(&bytes[..n]));
            }
        }
    }

    fn finish(&mut self) -> ExitStatus {
        drop(self.master.take());
        drop(self.slave.take());
        self.child.wait().unwrap()
    }
}

#[test]
fn rebind_instance_on_a_snapshot_copy_warns_and_refuses_a_mismatched_confirmation() {
    let (original, snapshot) = snapshot_copy();
    let instance = snapshot.path().join("ldk/INSTANCE");
    let store = snapshot.path().join("ldk/ldk_node_data.sqlite");
    let before = fs::read(&instance).unwrap();
    let original_before = fs::read(original.path().join("ldk/INSTANCE")).unwrap();
    let mut terminal = Terminal::rebind(&snapshot.path().join("konsensus.toml"));
    terminal.read_until("Type exactly to authorize");
    assert!(
        terminal.output.contains("does not prove state freshness"),
        "{}",
        terminal.output
    );
    assert!(
        terminal
            .output
            .contains("Never rebind a backup or snapshot"),
        "{}",
        terminal.output
    );
    assert!(
        terminal.output.contains("after disabling the old node"),
        "{}",
        terminal.output
    );
    writeln!(terminal.master.as_mut().unwrap(), "not-the-challenge").unwrap();
    terminal.read_until("INSTANCE unchanged");
    assert!(!terminal.finish().success());
    assert_eq!(fs::read(&instance).unwrap(), before);
    assert_eq!(fs::read(&store).unwrap(), b"not-a-wallet");
    assert_eq!(
        fs::read(original.path().join("ldk/INSTANCE")).unwrap(),
        original_before
    );
}

#[test]
fn rebind_instance_refuses_a_snapshot_copy_with_move_home_or_recovery_journal() {
    for (name, expected) in [
        ("move-home.json", "move-home migration journal exists"),
        (
            "recover.json",
            "resume konsensus recover on the owner console",
        ),
    ] {
        let (_original, snapshot) = snapshot_copy();
        let instance = snapshot.path().join("ldk/INSTANCE");
        let before = fs::read(&instance).unwrap();
        let journal = if name == "recover.json" {
            r#"{"version":1,"state":"open"}"#
        } else {
            "{}"
        };
        fs::write(snapshot.path().join("ldk").join(name), journal).unwrap();
        let output = bin()
            .args(["rebind-instance", "--config"])
            .arg(snapshot.path().join("konsensus.toml"))
            .output()
            .unwrap();
        assert!(!output.status.success(), "{name}");
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(error.contains(expected), "{name}: {error}");
        assert!(
            !error.contains("does not prove state freshness"),
            "{name} reached the rebind warning: {error}"
        );
        assert!(
            !String::from_utf8_lossy(&output.stdout).contains("Instance rebound"),
            "{name}"
        );
        assert_eq!(fs::read(&instance).unwrap(), before, "{name}");
        assert_eq!(
            fs::read(snapshot.path().join("ldk/ldk_node_data.sqlite")).unwrap(),
            b"not-a-wallet",
            "{name}"
        );
    }
}

#[test]
fn rebind_instance_refuses_while_the_old_node_holds_the_state_lease() {
    let dir = init();
    let instance = dir.path().join("ldk/INSTANCE");
    let before = fs::read(&instance).unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dir.path().join("STATE_GENERATION.lock"))
        .unwrap();
    // SAFETY: lock owns a valid descriptor for the node's lease file.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let output = bin()
        .args(["rebind-instance", "--config"])
        .arg(dir.path().join("konsensus.toml"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(error.contains("state_generation_busy"), "{error}");
    assert!(
        !error.contains("does not prove state freshness"),
        "a live node must be refused before the rebind warning: {error}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Instance rebound"));
    assert_eq!(fs::read(instance).unwrap(), before);
    drop(lock);
}
