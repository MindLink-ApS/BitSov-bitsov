//! Notification sinks for onboarding channel-open outcomes.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;
use thiserror::Error;
use tokio::sync::broadcast;

use konsensus_api::state::WsDeliveryStatus;
use konsensus_core::types::NodeId;

/// Structured channel-open notification sent to UI or ops sinks.
#[derive(Debug, Clone, Serialize)]
pub struct ChannelOpenNotice {
    pub invite_id: uuid::Uuid,
    pub peer_id: NodeId,
    pub ln_pubkey: String,
    pub amount_sats: u64,
    pub status: &'static str,
    pub reason: Option<String>,
    pub channel_id: Option<String>,
}

#[derive(Debug, Error)]
pub enum NotifyError {
    #[allow(dead_code)]
    #[error("notification sink error: {0}")]
    Backend(String),
}

/// Pluggable notification sink. Local UI is the default; ops sinks are opt-in.
#[async_trait]
pub trait NotificationSink: Send + Sync {
    async fn notify(&self, notice: ChannelOpenNotice) -> Result<(), NotifyError>;
}

/// Broadcasts channel-open status to local WebSocket clients.
pub struct LocalUiNotifier {
    tx: broadcast::Sender<Arc<WsDeliveryStatus>>,
}

impl LocalUiNotifier {
    pub fn new(tx: broadcast::Sender<Arc<WsDeliveryStatus>>) -> Self {
        Self { tx }
    }
}

#[async_trait]
impl NotificationSink for LocalUiNotifier {
    async fn notify(&self, notice: ChannelOpenNotice) -> Result<(), NotifyError> {
        let event_type = match notice.status {
            "opened" | "already_open" => "channel_opened",
            _ => "channel_open_aborted",
        };
        let status = match notice.channel_id.as_deref() {
            Some(channel_id) => format!("{}:{channel_id}", notice.status),
            None => notice.status.to_string(),
        };
        let _ = self.tx.send(Arc::new(WsDeliveryStatus {
            event_type,
            message_id: notice.invite_id.to_string(),
            status,
            reason: notice.reason,
        }));
        Ok(())
    }
}

/// Posts channel-open outcomes to a Slack-compatible webhook.
#[allow(dead_code)]
pub struct SlackNotifier {
    webhook_url: String,
    client: reqwest::Client,
}

impl SlackNotifier {
    #[allow(dead_code)]
    pub fn new(webhook_url: String) -> Self {
        Self {
            webhook_url,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl NotificationSink for SlackNotifier {
    async fn notify(&self, notice: ChannelOpenNotice) -> Result<(), NotifyError> {
        let text = match notice.reason.as_deref() {
            Some(reason) => format!(
                "BitSov ONB5 {}: invite={} peer={} amount_sats={} reason={}",
                notice.status, notice.invite_id, notice.peer_id, notice.amount_sats, reason
            ),
            None => format!(
                "BitSov ONB5 {}: invite={} peer={} amount_sats={} channel={}",
                notice.status,
                notice.invite_id,
                notice.peer_id,
                notice.amount_sats,
                notice.channel_id.as_deref().unwrap_or("unknown")
            ),
        };
        self.client
            .post(&self.webhook_url)
            .json(&serde_json::json!({ "text": text }))
            .send()
            .await
            .map_err(|e| NotifyError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| NotifyError::Backend(e.to_string()))?;
        Ok(())
    }
}
