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
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let writer = RotatingLog::open(path, config)?;
        *self.0.lock().expect("file logging lock poisoned") = Some(writer);
        Ok(())
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
