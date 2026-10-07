use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use konsensus_core::logging::{LoggingConfig, RotatingLog};

/// Keeps stdout diagnostics available while startup loads and validates config.
/// File output is attached once startup has resolved the directory and limits.
pub(crate) struct FileLogging(std::sync::Arc<std::sync::Mutex<Option<RotatingLog>>>);

impl FileLogging {
    pub(crate) fn enable(
        &self,
        path: &std::path::Path,
        config: LoggingConfig,
    ) -> std::io::Result<()> {
        // Check before open(): it can trim existing logs, while an inherited
        // launcher fd would keep writing to the old inode after rotation.
        #[cfg(unix)]
        if launcher_redirects_to(path) {
            use std::io::Write;
            // This startup warning must remain visible even with RUST_LOG=off.
            // Write only to stdout so a shared stdout/stderr fd cannot duplicate it.
            let _ = writeln!(
                std::io::stdout().lock(),
                "WARNING: stdout or stderr already redirects to node.log; file logging disabled; remove the launcher redirect to enable bounded log rotation"
            );
            return Ok(());
        }
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let writer = RotatingLog::open(path, config)?;
        *self.0.lock().expect("file logging lock poisoned") = Some(writer);
        Ok(())
    }
}

#[cfg(unix)]
fn launcher_redirects_to(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    [libc::STDOUT_FILENO, libc::STDERR_FILENO]
        .into_iter()
        .any(|fd| {
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            // SAFETY: fstat writes to a valid stat buffer. We only read it on
            // success, and neither take ownership of nor close the inherited fd.
            let stat = unsafe {
                if libc::fstat(fd, stat.as_mut_ptr()) != 0 {
                    return false;
                }
                stat.assume_init()
            };
            stat.st_dev as u64 == metadata.dev() && stat.st_ino as u64 == metadata.ino()
        })
}

/// LogTracer carries facade targets as `log.target`; native tracing uses metadata.
/// Capture only tower warnings, independently of console filters, for owner status.
struct TowerLogBridge;
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for TowerLogBridge {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        #[derive(Default)]
        struct Fields {
            target: Option<String>,
            message: String,
        }
        impl tracing::field::Visit for Fields {
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "log.target" {
                    self.target = Some(value.into());
                } else if field.name() == "message" {
                    self.message.push_str(value);
                }
            }
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if matches!(field.name(), "message" | "error") {
                    if !self.message.is_empty() {
                        self.message.push(' ');
                    }
                    self.message.push_str(&format!("{value:?}"));
                }
            }
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        let target = fields
            .target
            .as_deref()
            .unwrap_or(event.metadata().target());
        if target.starts_with("ldk_node::tower_hook")
            || target.starts_with("konsensus_lightning::tower")
        {
            konsensus_core::tower::record_warning(&fields.message);
        }
    }
}

pub(crate) fn init() -> FileLogging {
    let file = std::sync::Arc::new(std::sync::Mutex::new(None::<RotatingLog>));
    let handle = FileLogging(file.clone());
    // Initialize tracing.
    //
    // Output layers are composed with the plaintext guard:
    // 1. `fmt` layer — journal/stdout output with env-filter.
    // 2. `PlaintextGuardLayer` (Principle 4) — shuts the node down immediately
    //    if any log event records a non-empty `plaintext` field, preventing
    //    accidental exfiltration of E2EE message content through the log stream.
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,konsensus=debug"))
        // Keep this bounded diagnostic visible even with a restrictive RUST_LOG.
        // Other ldk_node targets retain their existing environment/default levels.
        .add_directive(
            "ldk_node::chain_sync=warn"
                .parse()
                .expect("valid static directive"),
        );

    // The explicitly enabled tracing-log feature makes init() install LogTracer
    // and set log::max_level once, together with the global subscriber.
    let file_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_target(true)
        .with_writer(move || -> Box<dyn std::io::Write + Send> {
            match file.lock().expect("file logging lock poisoned").as_ref() {
                Some(writer) => Box::new(writer.clone()),
                None => Box::new(std::io::sink()),
            }
        })
        .with_filter(env_filter.clone());
    tracing_subscriber::registry()
        // Inner layers receive events first: reject plaintext before formatting
        // it to either output (including the new persistent file).
        .with(konsensus_api::metrics::PlaintextGuardLayer)
        .with(
            TowerLogBridge.with_filter(tracing_subscriber::filter::filter_fn(|m| {
                *m.level() <= tracing::Level::WARN
            })),
        )
        .with(file_layer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_filter(env_filter),
        )
        .init();
    handle
}

#[cfg(test)]
mod tests {
    // Run startup in a subprocess: both the log facade and tracing subscriber
    // are process-global, and other node tests may install their own subscriber.
    #[test]
    fn chain_sync_log_reaches_node_subscriber_without_noise() {
        const CHILD: &str = "BITSOV_TEST_LOG_BRIDGE";
        if std::env::var_os(CHILD).is_some() {
            super::init();
            assert!(log::max_level() >= log::LevelFilter::Warn);
            log::error!(target: "ldk_node::chain_sync",
                "chain_sync_failed operation=onchain kind=sync_failed retry_in_secs=10");
            log::warn!(target: "ldk_node::chain_sync", "chain_sync_warning");
            log::info!(target: "ldk_node::chain_sync", "chain_sync_info_noise");
            log::debug!(target: "ldk_node::chain_sync", "chain_sync_debug_noise");
            log::trace!(target: "ldk_node::chain_sync", "chain_sync_trace_noise");
            log::info!(target: "ldk_node::other", "other_ldk_info");
            log::debug!(target: "ldk_node::other", "other_ldk_debug");
            return;
        }
        for (filter, other_info, other_debug) in [
            (None, true, false),
            (Some("off"), false, false),
            (Some("off,ldk_node=debug"), true, true),
            (Some("info,ldk_node::chain_sync=off"), true, false),
            (Some("info,ldk_node::chain_sync=trace"), true, false),
        ] {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            let working_dir = tempfile::tempdir().unwrap();
            command.current_dir(working_dir.path());
            command
                .args([
                    "--exact",
                    "logging::tests::chain_sync_log_reaches_node_subscriber_without_noise",
                    "--nocapture",
                ])
                .env(CHILD, "1");
            if let Some(filter) = filter {
                command.env("RUST_LOG", filter);
            } else {
                command.env_remove("RUST_LOG");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                std::fs::read_dir(working_dir.path())
                    .unwrap()
                    .next()
                    .is_none(),
                "stdout/journal logging must not create an unbounded node.log"
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert_eq!(
                stdout
                    .matches(
                        "chain_sync_failed operation=onchain kind=sync_failed retry_in_secs=10"
                    )
                    .count(),
                1,
                "{stdout}"
            );
            assert!(stdout.contains("chain_sync_warning"), "{stdout}");
            assert!(!stdout.contains("chain_sync_info_noise"), "{stdout}");
            assert!(!stdout.contains("chain_sync_debug_noise"), "{stdout}");
            assert!(!stdout.contains("chain_sync_trace_noise"), "{stdout}");
            assert_eq!(stdout.contains("other_ldk_info"), other_info, "{stdout}");
            assert_eq!(stdout.contains("other_ldk_debug"), other_debug, "{stdout}");
        }
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn launcher_redirect_skips_file_writer_and_warns_once() {
        const CHILD: &str = "BITSOV_TEST_LAUNCHER_LOG_REDIRECT";
        if std::env::var_os(CHILD).is_some() {
            let handle = init();
            handle
                .enable(
                    std::path::Path::new("node.log"),
                    LoggingConfig {
                        max_file_size_bytes: 256.try_into().unwrap(),
                        max_files: 3.try_into().unwrap(),
                    },
                )
                .unwrap();
            tracing::warn!("launcher-redirect-canary");
            return;
        }

        for (mode, filter) in [
            ("stdout", "warn"),
            ("stderr", "warn"),
            ("both", "warn"),
            ("hardlink", "warn"),
            ("both", "off"),
            ("unrelated", "warn"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let log_path = dir.path().join("node.log");
            let redirected = mode != "unrelated";
            // A matched redirect must be detected before open() can truncate
            // an oversized existing log or rotate a newly written record.
            let existing = "legacy launcher output\n".repeat(32);
            std::fs::write(&log_path, if redirected { &existing } else { "" }).unwrap();
            let redirect_path = dir.path().join("launcher.log");
            if mode == "hardlink" {
                std::fs::hard_link(&log_path, &redirect_path).unwrap();
            }
            let redirect_file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(if matches!(mode, "hardlink" | "unrelated") {
                    &redirect_path
                } else {
                    &log_path
                })
                .unwrap();
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "logging::file_tests::launcher_redirect_skips_file_writer_and_warns_once",
                    "--nocapture",
                ])
                .current_dir(dir.path())
                .env(CHILD, "1")
                .env("RUST_LOG", filter);
            if mode != "stderr" {
                command.stdout(redirect_file.try_clone().unwrap());
            }
            if matches!(mode, "stderr" | "both") {
                command.stderr(redirect_file);
            }
            let output = command.output().unwrap();
            assert!(output.status.success(), "mode={mode}: {output:?}");
            let log = std::fs::read_to_string(&log_path).unwrap();
            let console = if mode == "stderr" {
                String::from_utf8(output.stdout).unwrap()
            } else if matches!(mode, "hardlink" | "unrelated") {
                std::fs::read_to_string(&redirect_path).unwrap()
            } else {
                log.clone()
            };
            assert_eq!(
                console.matches("launcher-redirect-canary").count(),
                usize::from(filter != "off"),
                "mode={mode}: {console}"
            );
            assert_eq!(
                console.matches("remove the launcher redirect").count(),
                usize::from(redirected),
                "mode={mode}: {console}"
            );
            assert!(!dir.path().join("node.log.1").exists(), "mode={mode}");
            if redirected {
                assert!(
                    log.starts_with(&existing),
                    "mode={mode}: existing log was truncated"
                );
                if mode == "stderr" {
                    assert_eq!(
                        log, existing,
                        "stderr-only redirect must leave logging on stdout"
                    );
                }
            } else {
                assert_eq!(log.matches("launcher-redirect-canary").count(), 1);
            }
        }
    }

    #[test]
    fn node_file_rotates_and_plaintext_never_reaches_outputs() {
        const CHILD: &str = "BITSOV_TEST_ROTATING_NODE_LOG";
        if let Ok(mode) = std::env::var(CHILD) {
            let handle = init();
            tracing::warn!("startup config warning");
            handle
                .enable(
                    std::path::Path::new("node.log"),
                    LoggingConfig {
                        max_file_size_bytes: 256.try_into().unwrap(),
                        max_files: 3.try_into().unwrap(),
                    },
                )
                .unwrap();
            for n in 0..100 {
                tracing::warn!(sequence = n, "safe rotation diagnostic");
            }
            if mode == "plaintext" {
                tracing::error!(plaintext = "secret-plaintext-canary", "forbidden content");
                panic!("plaintext guard did not terminate the process");
            }
            return;
        }
        for mode in ["normal", "plaintext"] {
            let dir = tempfile::tempdir().unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "logging::file_tests::node_file_rotates_and_plaintext_never_reaches_outputs",
                    "--nocapture",
                ])
                .current_dir(dir.path())
                .env(CHILD, mode)
                .env_remove("RUST_LOG")
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(if mode == "normal" { 0 } else { 1 })
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("startup config warning"));
            assert!(!String::from_utf8_lossy(&output.stdout).contains("secret-plaintext-canary"));
            assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-plaintext-canary"));
            if mode == "plaintext" {
                assert!(String::from_utf8_lossy(&output.stderr).contains("SECURITY VIOLATION"));
            }
            let logs: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|e| std::fs::read(e.unwrap().path()).unwrap())
                .collect();
            assert_eq!(logs.len(), 3);
            assert!(dir.path().join("node.log.2").exists());
            assert!(logs.iter().all(|b| b.len() <= 256));
            assert!(logs.iter().map(Vec::len).sum::<usize>() <= 768);
            for log in logs {
                let text = String::from_utf8(log).unwrap();
                assert!(text.contains("safe rotation diagnostic"));
                assert!(!text.contains("secret-plaintext-canary"));
            }
        }
    }
}

#[cfg(test)]
mod tower_tests {
    #[test]
    fn tower_log_bridge_keeps_w1_warnings_bounded_even_with_rust_log_off() {
        const CHILD: &str = "BITSOV_TEST_TOWER_LOG_BRIDGE";
        if std::env::var_os(CHILD).is_some() {
            super::init();
            for n in 0..100 {
                log::warn!(target: "ldk_node::tower_hook", "Quarantined tower test record {}", n);
            }
            log::info!(target: "ldk_node::tower_hook", "not a warning");
            log::warn!(target: "ldk_node::unrelated", "unrelated warning");
            let warnings = konsensus_core::tower::warnings();
            assert_eq!(warnings.len(), 64);
            assert!(warnings[0].message.contains("record 36"));
            assert!(warnings[63].message.contains("record 99"));
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "logging::tower_tests::tower_log_bridge_keeps_w1_warnings_bounded_even_with_rust_log_off", "--nocapture"])
            .env(CHILD, "1").env("RUST_LOG", "off").output().unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
