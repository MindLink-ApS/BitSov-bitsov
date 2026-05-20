//! MediaTransport trait — voice/video transport (WebRTC). **DEFERRED** to post-launch.
//!
//! This trait is defined for interface stability but will not be implemented in v2.0.

use async_trait::async_trait;
use thiserror::Error;

use crate::types::NodeId;

/// Errors from media transport operations.
#[derive(Debug, Error)]
pub enum MediaError {
    /// Media transport is not implemented / not available.
    #[error("media transport not available: {0}")]
    NotAvailable(String),

    /// General media error.
    #[error("media error: {0}")]
    Other(String),
}

/// Voice/video transport over WebRTC. **DEFERRED** — not implemented in v2.0.
///
/// This trait exists for forward compatibility. All methods return
/// `MediaError::NotAvailable` in v2.0.
#[async_trait]
pub trait MediaTransport: Send + Sync {
    /// Initiate a media session with a peer.
    async fn initiate(&self, peer: &NodeId) -> Result<(), MediaError>;

    /// Accept an incoming media session from a peer.
    async fn accept(&self, peer: &NodeId) -> Result<(), MediaError>;

    /// Terminate an active media session.
    async fn hangup(&self, peer: &NodeId) -> Result<(), MediaError>;

    /// Check whether media transport is available.
    fn is_available(&self) -> bool {
        false
    }
}
