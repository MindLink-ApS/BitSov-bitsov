//! Audit logging — immutable append-only log of security-relevant events.
//!
//! Every sensitive operation (authentication, message sending, peer changes,
//! payment operations) is recorded to a structured JSON-lines log file.
//! This log is append-only and never truncated by the application.
//!
//! Each entry includes a monotonic sequence number, ISO 8601 timestamp,
//! event type, actor (node ID), and event-specific details.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use chrono::Utc;
use serde::Serialize;
use tracing::{debug, error, warn};

/// The audit log — append-only, structured, tamper-evident.
///
/// Thread-safe via `Mutex<BufWriter<File>>`. The file is opened in
/// append mode and flushed after every write to minimize data loss
/// on crash.
pub struct AuditLog {
    /// The underlying file writer.
    writer: Mutex<BufWriter<File>>,
    /// Monotonic sequence number.
    seq: AtomicU64,
    /// Path for diagnostic messages.
    path: PathBuf,
}

/// A single audit log entry.
#[derive(Debug, Serialize)]
pub struct AuditEntry<'a> {
    /// Monotonic sequence number (starts at 1).
    pub seq: u64,
    /// ISO 8601 timestamp.
    pub timestamp: String,
    /// Event category.
    pub event: &'a str,
    /// Actor (node ID hex, or "system" for internal events).
    pub actor: &'a str,
    /// Event-specific details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

/// Audit event types.
pub mod events {
    /// Authentication attempt (success or failure).
    pub const AUTH_ATTEMPT: &str = "auth.attempt";
    /// Token issued successfully.
    pub const AUTH_TOKEN_ISSUED: &str = "auth.token_issued";
    /// Message sent via API.
    pub const MESSAGE_SENT: &str = "message.sent";
    /// Message deleted via API.
    pub const MESSAGE_DELETED: &str = "message.deleted";
    /// Incoming P2P message received and stored.
    pub const MESSAGE_RECEIVED: &str = "message.received";
    /// Incoming P2P message rejected by payment gate.
    pub const MESSAGE_REJECTED: &str = "message.rejected";
    /// Peer added to registry.
    pub const PEER_ADDED: &str = "peer.added";
    /// Peer removed from registry.
    pub const PEER_REMOVED: &str = "peer.removed";
    /// Audit event emitted when a peer's metadata is updated.
    pub const PEER_UPDATED: &str = "peer.updated";
    /// Peer list exported.
    pub const PEERS_EXPORTED: &str = "peers.exported";
    /// Peers imported from backup.
    pub const PEERS_IMPORTED: &str = "peers.imported";
    /// Room created.
    pub const ROOM_CREATED: &str = "room.created";
    /// Room deleted.
    pub const ROOM_DELETED: &str = "room.deleted";
    /// Room member added.
    pub const ROOM_MEMBER_ADDED: &str = "room.member_added";
    /// Room member removed.
    pub const ROOM_MEMBER_REMOVED: &str = "room.member_removed";
    /// Lightning invoice created.
    pub const PAYMENT_INVOICE: &str = "payment.invoice_created";
    /// Lightning payment sent.
    pub const PAYMENT_SENT: &str = "payment.sent";
    /// Node started.
    pub const NODE_STARTED: &str = "node.started";
    /// Node shutdown.
    pub const NODE_SHUTDOWN: &str = "node.shutdown";
    /// Rate limit exceeded.
    pub const RATE_LIMITED: &str = "rate.limited";
    /// E2EE session established with a peer.
    pub const SESSION_ESTABLISHED: &str = "session.established";
    /// Message composed (plaintext → encrypted → signed → sent).
    pub const MESSAGE_COMPOSED: &str = "message.composed";
    /// File uploaded to local storage.
    pub const FILE_UPLOADED: &str = "file.uploaded";
    /// File deleted from local storage.
    pub const FILE_DELETED: &str = "file.deleted";
    /// File sent to a peer via E2EE transport.
    pub const FILE_SENT: &str = "file.sent";
    /// File received from a peer.
    pub const FILE_RECEIVED: &str = "file.received";
    /// Received file failed blake3 integrity check.
    pub const FILE_INTEGRITY_FAILED: &str = "file.integrity_failed";
    /// Invite token generated.
    pub const INVITE_GENERATED: &str = "invite.generated";
    /// Invite token redeemed (peer added from invite).
    pub const INVITE_REDEEMED: &str = "invite.redeemed";
}

impl AuditLog {
    /// Open or create an audit log file.
    ///
    /// The file is opened in append mode. If it doesn't exist, it is created.
    /// On reopening an existing log, the sequence number is initialized to
    /// max(existing_seq) + 1 to maintain monotonicity across restarts.
    /// Returns an error if the file cannot be opened.
    pub fn open(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        
        // Read the last sequence number from the existing file (if any)
        let last_seq = if path.exists() {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            let mut max_seq = 0u64;
            
            for line in reader.lines().map_while(Result::ok) {
                if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) {
                    if let Some(seq) = entry.get("seq").and_then(|s| s.as_u64()) {
                        max_seq = max_seq.max(seq);
                    }
                }
            }
            max_seq
        } else {
            0
        };
        
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        let writer = BufWriter::new(file);

        Ok(Self {
            writer: Mutex::new(writer),
            seq: AtomicU64::new(last_seq + 1),
            path,
        })
    }

    /// Record an audit event.
    ///
    /// This is a synchronous write — the entry is flushed to disk immediately.
    /// If the write fails, the error is logged via tracing but does not
    /// propagate (audit failures must not break the application).
    pub fn record(&self, event: &str, actor: &str, detail: Option<serde_json::Value>) {
        let entry = AuditEntry {
            seq: self.seq.fetch_add(1, Ordering::Relaxed),
            timestamp: Utc::now().to_rfc3339(),
            event,
            actor,
            detail,
        };

        match serde_json::to_string(&entry) {
            Ok(json) => {
                let mut writer = self.writer.lock().unwrap_or_else(|e| {
                    warn!("audit log mutex was poisoned, recovering");
                    e.into_inner()
                });
                if let Err(e) = writeln!(writer, "{json}") {
                    error!(
                        error = %e,
                        event = entry.event,
                        path = %self.path.display(),
                        "failed to write audit log entry"
                    );
                    return;
                }
                if let Err(e) = writer.flush() {
                    error!(error = %e, "failed to flush audit log");
                }
                debug!(seq = entry.seq, event = entry.event, "audit event recorded");
            }
            Err(e) => {
                error!(error = %e, "failed to serialize audit entry");
            }
        }
    }

    /// Get the log file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::NamedTempFile;

    #[test]
    fn creates_log_and_writes_entries() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        let log = AuditLog::open(&path).unwrap();

        log.record(events::NODE_STARTED, "system", None);
        log.record(
            events::AUTH_TOKEN_ISSUED,
            "aabb",
            Some(serde_json::json!({"ip": "127.0.0.1"})),
        );

        // Read the file and verify
        let mut contents = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 2);

        let entry1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(entry1["event"], "node.started");
        assert_eq!(entry1["actor"], "system");
        assert_eq!(entry1["seq"], 1);

        let entry2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(entry2["event"], "auth.token_issued");
        assert_eq!(entry2["actor"], "aabb");
        assert_eq!(entry2["seq"], 2);
        assert_eq!(entry2["detail"]["ip"], "127.0.0.1");
    }

    #[test]
    fn sequence_numbers_are_monotonic() {
        let tmp = NamedTempFile::new().unwrap();
        let log = AuditLog::open(tmp.path()).unwrap();

        for i in 1..=10 {
            log.record("test", "system", None);
            assert_eq!(log.seq.load(Ordering::Relaxed), i + 1);
        }
    }

    #[test]
    fn entries_without_detail_omit_field() {
        let tmp = NamedTempFile::new().unwrap();
        let log = AuditLog::open(tmp.path()).unwrap();

        log.record(events::NODE_SHUTDOWN, "system", None);

        let mut contents = String::new();
        File::open(tmp.path())
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        let entry: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert!(entry.get("detail").is_none());
    }

    #[test]
    fn sequence_numbers_persist_across_reopens() {
        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        // First session: write 3 entries
        {
            let log = AuditLog::open(&path).unwrap();
            log.record("event1", "system", None);
            log.record("event2", "system", None);
            log.record("event3", "system", None);
        }

        // Second session: reopen and write 2 more entries
        {
            let log = AuditLog::open(&path).unwrap();
            log.record("event4", "system", None);
            log.record("event5", "system", None);
        }

        // Verify all sequence numbers are monotonic
        let mut contents = String::new();
        File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();

        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 5);

        for (i, line) in lines.iter().enumerate() {
            let entry: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(entry["seq"], i as u64 + 1);
        }
    }
}
