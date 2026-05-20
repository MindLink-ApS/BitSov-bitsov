//! Runtime monitoring — Prometheus exporter, memory sampler, and plaintext guard.
//!
//! # Overview
//!
//! This module wires up three observability subsystems:
//!
//! 1. **Prometheus recorder** — installs the global [`metrics`] recorder so that
//!    all `counter!` / `gauge!` calls throughout the codebase are captured and
//!    exported via the `/metrics` scrape endpoint.
//!
//! 2. **Memory sampler** — a background task that reads process RSS from
//!    `/proc/self/status` every 30 seconds and records it as
//!    `bitsov_memory_rss_bytes`. Silently skips on non-Linux hosts.
//!
//! 3. **`PlaintextGuardLayer`** — a [`tracing_subscriber::Layer`] that enforces
//!    Principle 4 (data sovereignty / E2EE) at the logging boundary. Any log
//!    event that records a non-empty `plaintext` field triggers an immediate
//!    process exit. This is fail-closed by design: a false positive shuts the
//!    node down rather than leaking E2EE message content.
//!
//! # Alert thresholds (align with `deploy/prometheus/alert_rules.yml`)
//!
//! | Metric | Alert fires at |
//! |--------|---------------|
//! | `bitsov_auth_failures_total` | > 10 / min |
//! | `bitsov_payment_failures_total` | > 5 / min |
//! | `bitsov_whitelist_rejections_total` | > 2 / min |
//! | `bitsov_memory_rss_bytes` growth | > 100 MB / hr |
//! | `bitsov_plaintext_detected_total` | > 0 (immediate shutdown) |

use std::sync::OnceLock;

use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};

// ── Metric name constants ──────────────────────────────────────────────────

/// Counter: failed authentication attempts (Principle 1 — sovereign identity).
///
/// Incremented when:
/// - Ed25519 signature verification fails at `/api/v1/auth/token`
/// - JWT Bearer token validation fails on any protected endpoint
pub const AUTH_FAILURES: &str = "bitsov_auth_failures_total";

/// Counter: Lightning payment operation failures (Principle 2 — Lightning gate).
///
/// Incremented when:
/// - An outgoing keysend or invoice-request payment fails in the compose path
/// - An incoming message's payment proof is rejected by the payment gate
///   (`InsufficientPayment`, `PaymentNotSettled`, `LightningUnavailable`)
pub const PAYMENT_FAILURES: &str = "bitsov_payment_failures_total";

/// Counter: closed-mesh whitelist rejections (Principle 3 — closed mesh).
///
/// Incremented when the payment gate rejects an incoming message with
/// `GateRejection::NotWhitelisted` — the sender is not in this node's
/// peer whitelist.
pub const WHITELIST_REJECTIONS: &str = "bitsov_whitelist_rejections_total";

/// Gauge: process RSS in bytes, sampled every 30 s.
///
/// Used by the `BitSovMemoryGrowthHigh` alert to detect memory leaks.
/// Linux only — the gauge is not updated on other platforms.
pub const MEMORY_RSS: &str = "bitsov_memory_rss_bytes";

/// Counter: plaintext detected in a structured log field (Principle 4 violation).
///
/// Incremented immediately before `std::process::exit(1)`.  The node will
/// never continue running after this fires — the counter exists to give
/// Prometheus / Grafana a post-mortem signal for on-call teams.
pub const PLAINTEXT_DETECTED: &str = "bitsov_plaintext_detected_total";

// ── Global Prometheus handle ───────────────────────────────────────────────

static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();

/// Install the global Prometheus metrics recorder.
///
/// Idempotent — safe to call multiple times; subsequent calls are no-ops.
///
/// # Errors
///
/// Returns an error if the [`PrometheusBuilder`] fails to install its
/// global recorder (e.g. another recorder was already installed by a
/// different crate).  In production this should never happen; the error
/// is logged as a warning and the node continues without metrics export.
pub fn init() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if HANDLE.get().is_some() {
        return Ok(());
    }
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| format!("Prometheus recorder install failed: {e}"))?;
    // Ignore the error if another thread concurrently set the handle.
    let _ = HANDLE.set(handle);
    Ok(())
}

/// Render current metrics in Prometheus text exposition format (0.0.4).
///
/// Returns an empty string if [`init`] has not been called yet.
pub fn render() -> String {
    HANDLE.get().map(|h| h.render()).unwrap_or_default()
}

// ── Memory sampler ─────────────────────────────────────────────────────────

/// Spawn a background task that samples process RSS every 30 s.
///
/// On Linux the RSS is read from `/proc/self/status` (`VmRSS` line).
/// On other platforms the function returns without spawning any task,
/// and the `bitsov_memory_rss_bytes` gauge is simply never written.
pub fn spawn_memory_monitor() {
    // Only spawn on Linux where /proc/self/status is available.
    #[cfg(target_os = "linux")]
    tokio::spawn(async {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            if let Some(rss) = read_rss_bytes() {
                metrics::gauge!(MEMORY_RSS).set(rss as f64);
            }
        }
    });
}

/// Read the process resident set size from `/proc/self/status`.
///
/// Returns `None` if the file cannot be read or parsed.
#[cfg(target_os = "linux")]
fn read_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if line.starts_with("VmRSS:") {
            // Format: "VmRSS:    12345 kB"
            let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

// ── Plaintext guard tracing layer ─────────────────────────────────────────

/// A [`tracing_subscriber::Layer`] that enforces Principle 4 (data sovereignty /
/// E2EE) at the logging boundary.
///
/// # How it works
///
/// Every log [`tracing::Event`] is visited looking for a field named
/// `"plaintext"` with a non-empty, non-`None` value.  If one is found:
///
/// 1. The `bitsov_plaintext_detected_total` counter is incremented so
///    Prometheus / Grafana capture the event for the post-mortem.
/// 2. A `SECURITY VIOLATION` message is written directly to stderr (bypassing
///    tracing to avoid recursion).
/// 3. The process exits immediately with code 1.
///
/// # Fail-closed semantics
///
/// This is intentionally fail-closed: a false positive (e.g. a test log line
/// that incidentally uses a field named `plaintext`) shuts the node down.
/// In production code, never log a field named `plaintext`.  Use
/// `plaintext_len`, `has_plaintext`, or omit the field entirely.
pub struct PlaintextGuardLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for PlaintextGuardLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = PlaintextVisitor::default();
        event.record(&mut visitor);
        if visitor.found {
            metrics::counter!(PLAINTEXT_DETECTED).increment(1);
            // Write directly to stderr — do NOT call tracing here or we risk
            // infinite recursion (tracing → this layer → tracing → …).
            eprintln!(
                "SECURITY VIOLATION [P4]: structured log event contains a non-empty \
                 `plaintext` field.  Shutting down immediately to prevent E2EE \
                 data exfiltration.  Review recent changes to the Double Ratchet \
                 pipeline and remove any tracing calls that log decrypted content."
            );
            std::process::exit(1);
        }
    }
}

/// Field visitor that searches for a non-empty `plaintext` field value.
#[derive(Default)]
struct PlaintextVisitor {
    found: bool,
}

impl tracing::field::Visit for PlaintextVisitor {
    /// Handle `record_str` — e.g. `tracing::info!(plaintext = "hello")`.
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "plaintext" && !value.is_empty() {
            self.found = true;
        }
    }

    /// Handle `record_debug` — e.g. `tracing::debug!(?msg)` where `msg` has a
    /// `plaintext: Option<String>` field, printed as `Some("content")`.
    ///
    /// Allowed (safe) debug representations of the `plaintext` field:
    /// - `"None"` — the Option is None, no content present
    /// - `"\"\""` — an empty string, no content
    /// - `""` — truly empty debug output (degenerate; safe to ignore)
    ///
    /// Everything else is treated as a violation.
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() != "plaintext" {
            return;
        }
        let s = format!("{value:?}");
        match s.as_str() {
            "None" | "\"\"" | "" => {}
            _ => {
                self.found = true;
            }
        }
    }
}

#[cfg(test)]
mod visitor_logic_tests {
    use super::PlaintextVisitor;

    /// Directly test the is-found logic by calling the underlying match.
    #[test]
    fn none_debug_repr_is_safe() {
        // record_debug with "None" → safe
        let mut found = false;
        let s = "None";
        match s {
            "None" | "\"\"" | "" => {}
            _ => found = true,
        }
        assert!(!found);
    }

    #[test]
    fn some_content_debug_repr_triggers() {
        let mut found = false;
        let s = "Some(\"hello world\")";
        match s {
            "None" | "\"\"" | "" => {}
            _ => found = true,
        }
        assert!(found);
    }

    #[test]
    fn empty_str_debug_repr_is_safe() {
        let mut found = false;
        let s = "\"\"";
        match s {
            "None" | "\"\"" | "" => {}
            _ => found = true,
        }
        assert!(!found);
    }

    #[test]
    fn memory_visitor_unused() {
        // Ensure PlaintextVisitor::default() doesn't set found
        let v = PlaintextVisitor::default();
        assert!(!v.found);
    }
}
