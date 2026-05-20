//! Message reaction storage models.

use serde::{Deserialize, Serialize};

/// A stored emoji reaction on a message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionRecord {
    /// The message this reaction belongs to.
    pub message_id: String,
    /// Sender node ID (hex).
    pub sender: String,
    /// Unicode emoji character(s).
    pub emoji: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
}
