use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub(crate) fn init() {
    // Initialize tracing.
    //
    // Two layers are composed:
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
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_filter(env_filter),
        )
        .with(konsensus_api::metrics::PlaintextGuardLayer)
        .init();
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
            assert!(std::fs::read_dir(working_dir.path()).unwrap().next().is_none(),
                "stdout/journal logging must not create an unbounded node.log");
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
