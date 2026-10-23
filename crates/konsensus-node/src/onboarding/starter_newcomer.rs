//! Persistent newcomer delivery and local reconciliation. Network silence never
//! proves non-dispatch. Only an authenticated terminal refusal permits a new UUID.
use super::starter_hub::canonical;
use konsensus_api::handlers::starter_channel::StarterSettings;
use konsensus_core::{
    traits::{lightning::LightningProvider, transport::MessageTransport},
    NodeId,
};
use konsensus_message::{wire::Frame, NoiseTransport};
use konsensus_storage::{starter_request::StarterRequest, Storage};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};

pub struct StarterNewcomer {
    pub settings: StarterSettings,
    pub storage: Arc<dyn Storage>,
    pub lightning: Arc<dyn LightningProvider>,
    pub node_id: NodeId,
    pub audit_log: Arc<konsensus_api::AuditLog>,
}
fn retryable(reason: &str) -> bool {
    matches!(
        reason,
        "daily_cap_reached"
            | "hub_busy"
            | "rate_limited"
            | "ln_peer_not_connected"
            | "hub_insufficient_funds"
            | "fee_too_high"
            | "open_failed"
    )
}
fn backoff(attempts: i64) -> i64 {
    match attempts {
        0 | 1 => 15,
        2 => 30,
        3 => 60,
        4 => 120,
        _ => 300,
    }
}
impl StarterNewcomer {
    async fn save_progress(&self, r: &StarterRequest) -> anyhow::Result<()> {
        self.storage.starter_request_save(r).await?;
        // Terminal storage updates are monotonic; audit the persisted winner.
        if let Some(stored) = self.storage.starter_request_get(&r.request_id).await? {
            self.audit_log.starter_progress_async(&stored).await?;
        }
        Ok(())
    }

    fn enabled(&self) -> bool {
        self.settings
            .precondition(self.lightning.starter_network().as_deref())
            .is_none()
    }
    /// Only the configured, Noise-authenticated mesh peer can supply terms.
    pub async fn handle(&self, peer: NodeId, frame: Frame, now: i64) -> anyhow::Result<()> {
        if !self.enabled() || peer.to_hex() != self.settings.config.hub_node_id {
            return Ok(());
        }
        let Frame::StarterStatus {
            request_id,
            state,
            reason,
            retry_after_unix,
            original_request_id,
            capacity_sats,
            push_sats,
            channel_id,
            funding_txid,
        } = frame
        else {
            return Ok(());
        };
        let Some(mut r) = self
            .storage
            .starter_request_get(&request_id.to_string())
            .await?
        else {
            return Ok(());
        };
        if !self.settings.matches(&r) || r.terminal() {
            return Ok(());
        }
        // Adoption may have revived this UUID just before a crash. Journal its
        // nonterminal lifecycle before a queued status can make it terminal again.
        self.audit_log.starter_progress_async(&r).await?;
        if !matches!(state.as_str(), "received" | "opening" | "ready" | "refused") {
            return Ok(());
        }
        if state == "refused" {
            r.state = "refused".into();
            r.reason = reason.filter(|v| v.len() <= 64);
            r.retry_allowed = r.reason.as_deref().is_some_and(retryable);
            // Local lower bound prevents a hub refusal from producing a hot loop.
            r.retry_after_unix = if r.retry_allowed {
                Some(
                    retry_after_unix
                        .and_then(|t| i64::try_from(t).ok())
                        .unwrap_or(now + 600)
                        .max(now + 600),
                )
            } else {
                None
            };
            if r.reason.as_deref() == Some("already_served") {
                // The hub's target is not our local lineage root. Keep both
                // durable so a crash before adoption cannot reset the budget.
                r.detail = original_request_id
                    .filter(|id| id.get_version_num() == 4 && *id != request_id)
                    .map(|id| format!("adopt:{id}"));
            }
            r.updated_at = now;
            self.save_progress(&r).await?;
            // Adopt only an explicit authenticated original grant; never dispatch
            // a replacement for already_served. A crash is repaired on poll below.
            if r.reason.as_deref() == Some("already_served") {
                if let Some(original) =
                    original_request_id.filter(|id| id.get_version_num() == 4 && *id != request_id)
                {
                    self.adopt(&r, &original.to_string(), now).await?;
                }
            }
            return Ok(());
        }
        // Do not accept malformed or changing terms, or infer a push from balance.
        let (Some(capacity), Some(push)) = (capacity_sats, push_sats) else {
            return Ok(());
        };
        if capacity == 0
            || capacity > 200_000
            || push == 0
            || push > capacity / 2
            || r.capacity_sats.is_some_and(|v| v != capacity as i64)
            || r.push_sats.is_some_and(|v| v != push as i64)
            || channel_id
                .as_ref()
                .is_some_and(|v| v.len() != 64 || hex::decode(v).is_err())
            || funding_txid
                .as_ref()
                .is_some_and(|v| v.len() != 64 || hex::decode(v).is_err())
        {
            return Ok(());
        }
        r.capacity_sats = Some(capacity as i64);
        r.push_sats = Some(push as i64);
        if channel_id.is_some() {
            r.channel_id = channel_id;
        }
        if funding_txid.is_some() {
            r.funding_txid = funding_txid;
        }
        if state != "received" {
            r.state = "opening".into();
        }
        r.detail = Some("channel_pending".into());
        r.updated_at = now;
        self.save_progress(&r).await?;
        self.reconcile(r, now).await?;
        Ok(())
    }
    async fn adopt(&self, r: &StarterRequest, original: &str, now: i64) -> anyhow::Result<()> {
        let mut adopted = StarterRequest::new(
            original.into(),
            r.hub_node_id.clone(),
            r.hub_ln_pubkey.clone(),
            r.network.clone(),
            now.max(r.created_at + 1),
        );
        adopted.detail = Some("adopted".into());
        adopted.original_request_id = (original != r.root_id()).then(|| r.root_id().to_owned());
        let storage = self.storage.clone();
        self.audit_log
            .starter_admitted(move |log| async move {
                let stored = storage.starter_request_adopt(&adopted).await?;
                log.starter_progress_async(&stored).await?;
                Ok::<_, anyhow::Error>(())
            })
            .await??;
        Ok(())
    }
    async fn reconcile(&self, mut r: StarterRequest, now: i64) -> anyhow::Result<StarterRequest> {
        if r.terminal() {
            return Ok(r);
        }
        let channels = self.lightning.list_channels().await?;
        let peers: Vec<_> = channels
            .iter()
            .filter(|c| c.peer_pubkey.eq_ignore_ascii_case(&r.hub_ln_pubkey))
            .collect();
        if let (Some(capacity), Some(push)) = (r.capacity_sats, r.push_sats) {
            let matches: Vec<_> = peers
                .iter()
                .filter(|c| {
                    c.verifies_starter(
                        &r.hub_ln_pubkey,
                        capacity as u64,
                        push as u64,
                        r.channel_id.as_deref(),
                        r.funding_txid.as_deref(),
                    )
                })
                .collect();
            if matches.len() == 1 {
                let channel = matches[0];
                r.state = "ready".into();
                r.detail = None;
                r.verified_at = Some(now);
                r.channel_id = Some(channel.channel_id.clone());
                r.user_channel_id = channel.user_channel_id.clone();
                r.funding_txid = channel
                    .funding_txo
                    .as_deref()
                    .and_then(|v| v.split_once(':'))
                    .map(|(id, _)| id.to_owned());
            } else if !peers.is_empty() {
                r.state = "opening".into();
                r.detail = Some("verify_mismatch".into());
            }
        } else if !peers.is_empty() {
            r.state = "opening".into();
            r.detail = Some("channel_pending".into());
        }
        if r.state == "requested"
            && r.capacity_sats.is_none()
            && now.saturating_sub(r.created_at) >= 86400
        {
            r.detail = Some("hub_silent_24h".into());
        }
        r.updated_at = now;
        self.save_progress(&r).await?;
        Ok(r)
    }
    /// Called every 15s and on status arrival. A send attempt is persisted BEFORE
    /// connecting/signing/transmitting; cancellation and restart retain its UUID.
    pub async fn poll(&self, now: i64, connected: bool) -> anyhow::Result<Option<Frame>> {
        // A later owner request may have replaced the current row after a crash.
        // Repair all pending audit intents, not only the current operation.
        self.audit_log
            .starter_reconcile(self.storage.clone())
            .await?;
        if !self.enabled() {
            return Ok(None);
        }
        let Some(mut r) = self.storage.starter_request_current().await? else {
            return Ok(None);
        };
        if !self.settings.matches(&r) {
            return Ok(None);
        }
        // Repair an outcome saved just before a crash/audit failure, before retry.
        self.audit_log.starter_progress_async(&r).await?;
        if r.state == "refused" && r.reason.as_deref() == Some("already_served") {
            if let Some(original) = r.detail.as_deref().and_then(|v| v.strip_prefix("adopt:")) {
                if let Ok(id) = original.parse::<uuid::Uuid>() {
                    if id.get_version_num() == 4 && original != r.request_id {
                        self.adopt(&r, original, now).await?;
                    }
                }
            }
            return Ok(None);
        }
        if r.state == "refused" && r.retry_allowed {
            let storage = self.storage.clone();
            let id = r.request_id.clone();
            r = self
                .audit_log
                .starter_admitted(move |log| async move {
                    let row = storage.starter_request_retry(&id, now).await?;
                    log.starter_progress_async(&row).await?;
                    Ok::<_, anyhow::Error>(row)
                })
                .await??;
        }
        if r.terminal() {
            return Ok(None);
        }
        r = self.reconcile(r, now).await?;
        if r.terminal() {
            return Ok(None);
        }
        if !connected {
            return Ok(None);
        }
        if r.send_attempts >= 8 {
            if r.detail.as_deref() != Some("hub_silent_24h") {
                r.detail = Some("delivery_retry_exhausted".into());
                self.save_progress(&r).await?;
            }
            return Ok(None);
        }
        if r.last_sent_at
            .is_some_and(|t| now.saturating_sub(t) < backoff(r.send_attempts))
        {
            return Ok(None);
        }
        if !self.lightning.money_ready().await {
            return Ok(None);
        }
        r.send_attempts += 1;
        r.last_sent_at = Some(now);
        r.updated_at = now;
        self.save_progress(&r).await?;
        let prepare = async {
            self.lightning
                .connect_peer(&r.hub_ln_pubkey, &self.settings.hub_ln_address, true)
                .await?;
            let key = self
                .lightning
                .get_node_pubkey()
                .await
                .ok_or_else(|| anyhow::anyhow!("LN key unavailable"))?;
            let hub = NodeId::from_hex(&r.hub_node_id)?;
            let id = r.request_id.parse()?;
            let sig = self
                .lightning
                .sign_message(canonical(&r.network, &hub, &self.node_id, id, &key).as_bytes())
                .await?;
            Ok::<_, anyhow::Error>(Frame::StarterRequest {
                v: 1,
                request_id: id,
                network: r.network.clone(),
                ln_pubkey: key,
                ln_sig: sig,
            })
        };
        match tokio::time::timeout(Duration::from_secs(10), prepare).await {
            Ok(Ok(frame)) => Ok(Some(frame)),
            _ => {
                r.detail = Some("hub_unreachable".into());
                self.save_progress(&r).await?;
                Ok(None)
            }
        }
    }
}
pub async fn run(
    client: StarterNewcomer,
    transport: Arc<NoiseTransport>,
    mut rx: mpsc::Receiver<(NodeId, Frame)>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut connection = None;
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some((peer, frame)) = rx.recv() => {
                if client.handle(peer, frame, chrono::Utc::now().timestamp()).await.is_err() {
                    tracing::warn!("starter status persistence unavailable");
                }
            },
            _ = interval.tick() => {
                let hub = NodeId::from_hex(&client.settings.config.hub_node_id).ok();
                let since = if let Some(hub) = hub {
                    transport.connected_since(&hub).await
                } else {
                    None
                };
                if since.is_some() && since != connection {
                    if let Ok(Some(r)) = client.storage.starter_request_current().await {
                        if client.settings.matches(&r) {
                            let _ = client.storage.starter_request_rearm(&r.request_id).await;
                        }
                    }
                }
                connection = since;
                match client.poll(chrono::Utc::now().timestamp(), since.is_some()).await {
                    Ok(Some(frame)) => {
                        if let Ok(hub) = NodeId::from_hex(&client.settings.config.hub_node_id) {
                            let _ = transport.enqueue_control_frame(&hub, &frame).await;
                        }
                    },
                    Ok(None) => {},
                    Err(_) => tracing::warn!("starter reconciliation unavailable"),
                }
            }
        }
    }
}
