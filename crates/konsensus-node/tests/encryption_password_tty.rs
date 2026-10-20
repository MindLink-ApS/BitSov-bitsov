//! Exercise the real terminal password path, including terminal echo restoration.
#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Terminal {
    master: Option<File>,
    slave: Option<File>,
    child: Child,
    output: String,
}

impl Drop for Terminal {
    fn drop(&mut self) {
        // Also reap the child when an assertion fails or init is awaiting backup confirmation.
        let _ = self.child.kill();
        // Close both ends before waiting: macOS can drain terminal output during
        // process exit, which would otherwise wait for this harness to read it.
        drop(self.master.take());
        drop(self.slave.take());
        let _ = self.child.wait();
    }
}

impl Terminal {
    fn spawn(command: &str, dir: &std::path::Path) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
        cmd.args([command, "--dir"])
            .arg(dir)
            .args(["--tier", "full", "--encrypt"]);
        Self::spawn_command(cmd)
    }

    fn spawn_command(mut cmd: Command) -> Self {
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
        // Keep reads bounded even if poll wakes during a terminal mode change.
        // SAFETY: master is a valid descriptor; only its status flags change.
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        cmd.stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave.try_clone().unwrap()));
        // SAFETY: only syscalls run after fork. Stdio has installed the slave on fd 0;
        // a new session plus TIOCSCTTY makes /dev/tty resolve to this isolated PTY.
        unsafe {
            cmd.pre_exec(|| {
                if libc::setsid() == -1 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        Self {
            master: Some(master),
            slave: Some(slave),
            child,
            output: String::new(),
        }
    }

    fn echo_enabled(&self) -> bool {
        let mut term = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: slave is valid and tcgetattr initializes term on success.
        assert_eq!(
            unsafe { libc::tcgetattr(self.slave.as_ref().unwrap().as_raw_fd(), term.as_mut_ptr()) },
            0
        );
        // SAFETY: tcgetattr succeeded.
        unsafe { term.assume_init().c_lflag & libc::ECHO != 0 }
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

    fn enter_password(&mut self, password: &str) {
        self.read_until("Enter a non-empty password to encrypt your mnemonic:");
        self.type_password(password);
    }

    fn type_password(&mut self, password: &str) {
        // The prompt is flushed just before rpassword disables echo. Synchronize
        // on terminal state instead of racing that transition with password input.
        // Still send on timeout so the regression also observes the actual echo.
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.echo_enabled() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        writeln!(self.master.as_mut().unwrap(), "{password}").unwrap();
    }
}

#[test]
fn node_id_prompts_for_encrypted_mnemonic_without_echoing() {
    const PASSWORD: &str = "node-id-terminal-secret";
    let dir = tempfile::tempdir().unwrap();
    let initialized = Command::new(env!("CARGO_BIN_EXE_konsensus"))
        .args(["init", "--non-interactive", "--tier", "light", "--dir"])
        .arg(dir.path())
        .args(["--encrypt", PASSWORD])
        .output()
        .unwrap();
    assert!(initialized.status.success());
    let stdout = String::from_utf8(initialized.stdout).unwrap();
    let expected = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Node ID:"))
        .unwrap()
        .trim();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_konsensus"));
    cmd.args(["node-id", "--mnemonic"])
        .arg(dir.path().join("mnemonic.enc"));
    let mut terminal = Terminal::spawn_command(cmd);
    terminal.read_until("Encrypted mnemonic file detected. Enter password:");
    terminal.type_password(PASSWORD);
    terminal.read_until(expected);
    assert!(!terminal.output.contains(PASSWORD));
    assert!(terminal.echo_enabled());
    assert!(terminal.child.wait().unwrap().success());
}

#[test]
fn interactive_encryption_password_is_not_echoed() {
    const PASSWORD: &str = "  tty-secret-é-123  ";
    for command in ["init", "restore"] {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let mut terminal = Terminal::spawn(command, &dir);
        terminal.enter_password(PASSWORD);
        let next_prompt = if command == "init" {
            "Word #"
        } else {
            "Enter your 24-word recovery phrase"
        };
        terminal.read_until(next_prompt);
        assert!(
            !terminal.output.contains("tty-secret"),
            "{command} echoed the password"
        );
        assert!(
            terminal.echo_enabled(),
            "{command} did not restore terminal echo"
        );
        if command == "restore" {
            writeln!(terminal.master.as_mut().unwrap(), "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
            terminal.read_until("restored successfully");
            assert!(!terminal.output.contains("tty-secret"));
            assert!(dir.join("mnemonic.enc").exists());
            assert!(!dir.join("mnemonic.txt").exists());
        }
    }
}

#[test]
fn blank_terminal_password_restores_echo_and_writes_nothing() {
    for command in ["init", "restore"] {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("node");
        let mut terminal = Terminal::spawn(command, &dir);
        terminal.enter_password("   ");
        terminal.read_until("must not be empty or whitespace-only");
        assert!(terminal.echo_enabled());
        assert!(!dir.exists());
    }
}
