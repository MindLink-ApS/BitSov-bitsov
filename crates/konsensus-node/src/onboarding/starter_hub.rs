//! Invite-only, explicitly requested starter grants. The database claim is the
//! dispatch boundary; a timeout or missing channel never authorizes a retry.
use konsensus_core::{
    traits::lightning::{
        unique_channel_match, FundingOptions, FundingPriority, LightningError, LightningProvider,
        FUNDING_FEE_CAP_EXCEEDED,
    },
    NodeId,
};
use konsensus_message::{wire::Frame, NoiseTransport};
use konsensus_storage::{starter::*, ChannelOpenOperation, InviteState, Storage};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StarterHubConfig {
    pub enabled: bool,
    pub capacity_sats: u64,
    pub push_sats: u64,
    pub funding_priority: FundingPriority,
    pub max_funding_fee_sats: u64,
    pub max_opens_per_day: u32,
    pub max_concurrent_opens: u32,
    pub lifetime_budget_sats: u64,
    pub allow_mainnet: bool,
}
impl Default for StarterHubConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            capacity_sats: 100_000,
            push_sats: 10_000,
            funding_priority: FundingPriority::Economy,
            max_funding_fee_sats: 2_000,
            max_opens_per_day: 20,
            max_concurrent_opens: 4,
            lifetime_budget_sats: 2_000_000,
            allow_mainnet: false,
        }
    }
}
impl StarterHubConfig {
    pub fn validate(
        &self,
        network: Option<&str>,
        capacity_limit: Option<u64>,
        lockable: bool,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(!self.allow_mainnet, "starter_mainnet_not_approved");
        if !self.enabled {
            return Ok(());
        }
        anyhow::ensure!(
            matches!(network, Some("signet" | "regtest")) && capacity_limit.is_some(),
            "starter_network_not_allowed"
        );
        anyhow::ensure!(!lockable, "starter_hub_requires_non_lockable_node");
        anyhow::ensure!(
            self.capacity_sats > 0
                && self.capacity_sats <= 200_000
                && self.capacity_sats <= capacity_limit.unwrap_or(0)
                && self.push_sats <= self.capacity_sats / 2,
            "starter_invalid_sizes"
        );
        anyhow::ensure!(
            self.max_funding_fee_sats > 0
                && self.max_funding_fee_sats <= 2_100_000_000_000_000
                && self.lifetime_budget_sats <= i64::MAX as u64
                && self.max_opens_per_day > 0
                && self.max_concurrent_opens > 0,
            "starter_invalid_caps"
        );
        Ok(())
    }
    fn limits(&self) -> StarterLimits {
        StarterLimits {
            max_opens_per_day: i64::from(self.max_opens_per_day),
            max_concurrent_opens: i64::from(self.max_concurrent_opens),
            lifetime_budget_sats: self.lifetime_budget_sats as i64,
        }
    }
}
pub fn canonical(network: &str, hub: &NodeId, peer: &NodeId, id: Uuid, key: &str) -> String {
    format!("bitsov-starter-v1\n{network}\n{hub}\n{peer}\n{id}\n{key}")
}
pub struct StarterHub {
    pub config: StarterHubConfig,
    pub storage: Arc<dyn Storage>,
    pub lightning: Arc<dyn LightningProvider>,
    pub hub_id: NodeId,
    pub network: String,
}
fn refusal(id: Uuid, reason: &str, retry: Option<i64>, original: Option<String>) -> Frame {
    Frame::StarterStatus {
        request_id: id,
        state: "refused".into(),
        reason: Some(reason.into()),
        retry_after_unix: retry.and_then(|v| v.try_into().ok()),
        original_request_id: original.and_then(|id| id.parse().ok()),
        capacity_sats: None,
        push_sats: None,
        channel_id: None,
        funding_txid: None,
    }
}
fn status(g: &StarterGrant) -> Frame {
    Frame::StarterStatus {
        request_id: g.request_id.parse().expect("validated request UUID"),
        state: match g.state.as_str() {
            "admitted" => "received",
            "resolved" => "opening",
            s => s,
        }
        .into(),
        reason: g.reason.clone(),
        retry_after_unix: g.retry_after_unix.and_then(|v| v.try_into().ok()),
        original_request_id: None,
        capacity_sats: Some(g.capacity_sats as u64),
        push_sats: Some(g.push_sats as u64),
        channel_id: g.channel_id.clone(),
        funding_txid: g.funding_txid.clone(),
    }
}
impl StarterHub {
    fn network_allowed(&self) -> bool {
        self.config.enabled
            && !self.config.allow_mainnet
            && matches!(self.network.as_str(), "signet" | "regtest")
            && self.lightning.starter_network().as_deref() == Some(self.network.as_str())
    }
    pub async fn handle(
        &self,
        peer: NodeId,
        frame: Frame,
        time: Option<i64>,
    ) -> anyhow::Result<Frame> {
        let now = time.unwrap_or_else(|| chrono::Utc::now().timestamp());
        let Frame::StarterRequest {
            v,
            request_id,
            network,
            ln_pubkey,
            ln_sig,
        } = frame
        else {
            anyhow::bail!("not a starter request");
        };
        if !self.config.enabled {
            return Ok(refusal(request_id, "starter_disabled", None, None));
        }
        if !self.network_allowed() || network != self.network {
            return Ok(refusal(request_id, "network_mismatch", None, None));
        }
        if v != 1 || request_id.get_version_num() != 4 {
            return Ok(refusal(request_id, "invalid_request", None, None));
        }
        if ln_pubkey.len() != 66
            || ln_sig.len() > 1024
            || !self
                .lightning
                .verify_message(
                    canonical(&network, &self.hub_id, &peer, request_id, &ln_pubkey).as_bytes(),
                    &ln_sig,
                    &ln_pubkey,
                )
                .await
                .unwrap_or(false)
        {
            return Ok(refusal(request_id, "ln_signature_invalid", None, None));
        }
        let key = ln_pubkey.to_ascii_lowercase();
        let grants = self.storage.starter_grants().await?;
        if let Some(g) = grants
            .iter()
            .find(|g| g.request_id == request_id.to_string())
        {
            if g.requester_node_id != peer.to_hex() || g.ln_pubkey != key || g.network != network {
                return Ok(refusal(request_id, "operation_mismatch", None, None));
            }
            return Ok(status(g));
        }
        if let Some(g) = grants.iter().find(|g| {
            g.state != "refused" && (g.requester_node_id == peer.to_hex() || g.ln_pubkey == key)
        }) {
            return Ok(refusal(
                request_id,
                "already_served",
                None,
                Some(g.request_id.clone()),
            ));
        }
        let invite = self
            .storage
            .find_pending_invite_for_invitee(peer.as_bytes())
            .await?;
        let Some(invite) = invite.filter(|i| i.expiry_unix > now as u64) else {
            return Ok(refusal(request_id, "not_invited", None, None));
        };
        let mut grant = StarterGrant::new(
            request_id.to_string(),
            peer.to_hex(),
            key.clone(),
            network,
            invite.id.to_string(),
            self.config.capacity_sats as i64,
            self.config.push_sats as i64,
            now,
        );
        let channels = self.lightning.list_channels().await?;
        let onb5 = self.storage.list_invites_issued().await?.iter().any(|i| {
            i.invitee_pubkey == *peer.as_bytes()
                && matches!(i.state, InviteState::Opening | InviteState::Accepted)
        });
        let mut deny = if onb5
            || channels
                .iter()
                .any(|c| c.peer_pubkey.eq_ignore_ascii_case(&key))
        {
            Some(("already_served", None))
        } else {
            None
        };
        if deny.is_none() {
            if let Some(last) = grants
                .iter()
                .filter(|g| g.requester_node_id == peer.to_hex())
                .map(|g| g.created_at)
                .max()
                .filter(|t| now - *t < 600)
            {
                deny = Some(("rate_limited", Some(last + 600)));
            }
        }
        if deny.is_none()
            && !self
                .lightning
                .list_peers()
                .await?
                .iter()
                .any(|p| p.connected && p.pubkey.eq_ignore_ascii_case(&key))
        {
            deny = Some(("ln_peer_not_connected", Some(now + 600)));
        }
        let required = self.config.capacity_sats + self.config.max_funding_fee_sats + 25_000;
        if deny.is_none()
            && (!self.lightning.money_ready().await
                || self
                    .lightning
                    .get_balance_breakdown()
                    .await?
                    .onchain_spendable_sats
                    .is_none_or(|v| v < required))
        {
            deny = Some(("hub_insufficient_funds", Some(now + 3600)));
        }
        if deny.is_none() {
            if let Some(safety) = self.lightning.channel_safety() {
                let total = channels
                    .iter()
                    .try_fold(0u64, |n, c| n.checked_add(c.capacity_msat / 1000));
                if grant.capacity_sats as u64 > safety.limits.max_channel_capacity_sats
                    || total
                        .and_then(|n| n.checked_add(grant.capacity_sats as u64))
                        .is_none_or(|n| n > safety.limits.max_total_channel_capacity_sats)
                {
                    deny = Some(("hub_capacity", None));
                }
            }
        }
        if let Some((reason, retry)) = deny {
            grant.state = "refused".into();
            grant.reason = Some(reason.into());
            grant.retry_after_unix = retry;
        }
        let out = self
            .storage
            .starter_update(
                StarterUpdate::Admit {
                    grant,
                    limits: self.config.limits(),
                },
                time,
            )
            .await?;
        metrics::counter!("konsensus_starter_requests_total","result"=>if out.reason.is_some(){"refused"}else{"admitted"}).increment(1);
        if let Some(ref reason) = out.reason {
            metrics::counter!("konsensus_starter_refusals_total","reason"=>reason.clone())
                .increment(1);
        }
        Ok(match out.grant {
            Some(g) => status(&g),
            None => refusal(
                request_id,
                out.reason.as_deref().unwrap_or("already_served"),
                None,
                out.original_request_id,
            ),
        })
    }
    pub async fn tick(&self, time: Option<i64>) -> anyhow::Result<()> {
        let now = time.unwrap_or_else(|| chrono::Utc::now().timestamp());
        self.storage
            .starter_update(StarterUpdate::Rebuild, time)
            .await?;
        let grants = self.storage.starter_grants().await?;
        for g in grants {
            let result: anyhow::Result<()> = async {
                if matches!(g.state.as_str(), "opening" | "resolved") {
                    self.reconcile(&g, time).await?;
                } else if g.state == "admitted" {
                    self.dispatch(&g, time).await?;
                }
                // Repair invite bookkeeping if ready committed before a crash.
                if g.state == "ready" {
                    self.storage
                        .mark_invite_accepted(&g.invite_id.parse()?, now as u64)
                        .await?;
                }
                Ok(())
            }
            .await;
            if result.is_err() {
                // An individual failure must not starve recovery of other grants.
                // Backend errors may contain peer addresses: log fixed text only.
                tracing::warn!(request_id=%g.request_id, "starter grant reconciliation unavailable; reservation retained");
            }
        }
        let c = self.storage.starter_counters().await?;
        metrics::gauge!("konsensus_starter_capital_committed_sats").set(c.committed_sats as f64);
        Ok(())
    }
    async fn dispatch(&self, g: &StarterGrant, time: Option<i64>) -> anyhow::Result<()> {
        // Validate even while offline: an expired admission must not reserve
        // capital forever. Storage proves no operation exists before releasing it.
        let checked = self
            .storage
            .starter_update(
                StarterUpdate::CancelInvalidInvite {
                    id: g.request_id.clone(),
                },
                time,
            )
            .await?;
        if checked.grant.is_none_or(|grant| grant.state != "admitted") {
            return Ok(());
        }
        if !self.network_allowed()
            || g.network != self.network
            || !self.lightning.money_ready().await
        {
            return Ok(());
        }
        let peers = self.lightning.list_peers().await?;
        let Some(peer) = peers
            .iter()
            .find(|p| p.connected && p.pubkey.eq_ignore_ascii_case(&g.ln_pubkey))
        else {
            return Ok(());
        };
        // Removing an old stored address and pinning its suppression precedes any
        // open. Failure here cannot leak the observed address through PeerInfo.
        self.lightning.suppress_peer_address(&g.ln_pubkey).await?;
        let request = serde_json::to_vec(
            &serde_json::json!({"peer_pubkey":g.ln_pubkey,"amount_sats":g.capacity_sats,"push_sats":g.push_sats,"announce":false}),
        )?;
        let operation = ChannelOpenOperation::pending(
            g.request_id.clone(),
            blake3::hash(&request).to_hex().to_string(),
            request,
        );
        let out = self
            .storage
            .starter_update(
                StarterUpdate::Claim {
                    id: g.request_id.clone(),
                    operation,
                },
                time,
            )
            .await?;
        if !out.claimed {
            return Ok(());
        }
        let claimed = out.grant.expect("successful claim returns grant");
        let result = tokio::time::timeout(
            Duration::from_secs(120),
            self.lightning.open_channel_with_funding(
                &claimed.ln_pubkey,
                &peer.address,
                claimed.capacity_sats as u64,
                false,
                FundingOptions {
                    priority: self.config.funding_priority,
                    max_funding_fee_sats: Some(self.config.max_funding_fee_sats),
                },
                Some(claimed.push_sats as u64 * 1000),
            ),
        )
        .await;
        match result {
            Ok(Ok(opened)) => {
                let result = serde_json::to_vec(&opened)?;
                self.storage
                    .resolve_channel_open_operation(&g.request_id, "opened", Some(&result), None)
                    .await?;
                self.storage
                    .starter_update(
                        StarterUpdate::Observe {
                            id: g.request_id.clone(),
                            channel_id: opened.channel_id,
                            user_channel_id: opened.user_channel_id,
                            funding_txid: opened.funding_txid,
                            ready: false,
                        },
                        time,
                    )
                    .await?;
                metrics::counter!("konsensus_starter_opens_total").increment(1);
            }
            Ok(Err(LightningError::PaymentNotDispatched(reason))) => {
                let fee = reason == FUNDING_FEE_CAP_EXCEEDED;
                self.storage
                    .starter_update(
                        StarterUpdate::NonDispatch {
                            id: g.request_id.clone(),
                            reason: if fee { "fee_too_high" } else { "open_failed" }.into(),
                            terminal: fee || claimed.attempts >= 3,
                        },
                        time,
                    )
                    .await?;
            }
            _ => { /* Uncertain: retain pending operation and every reservation. */ }
        }
        Ok(())
    }
    async fn reconcile(&self, g: &StarterGrant, time: Option<i64>) -> anyhow::Result<()> {
        let now = time.unwrap_or_else(|| chrono::Utc::now().timestamp());
        let channels = self.lightning.list_channels().await?;
        let matched = if g.channel_id.is_some() || g.user_channel_id.is_some() {
            channels.iter().find(|c| {
                c.peer_pubkey.eq_ignore_ascii_case(&g.ln_pubkey)
                    && c.capacity_msat == g.capacity_sats as u64 * 1000
                    && (g.channel_id.as_ref() == Some(&c.channel_id)
                        || g.user_channel_id
                            .as_ref()
                            .is_some_and(|id| c.user_channel_id.as_ref() == Some(id)))
            })
        } else {
            unique_channel_match(&channels, &g.ln_pubkey, g.capacity_sats as u64)
        };
        let op = self
            .storage
            .get_channel_open_operation(&g.open_operation_id)
            .await?;
        if let Some(c) = matched {
            // Read persisted readiness even for an opened/uncertain operation.
            // The LDK event may already have been acknowledged before a crash.
            let ready = self.lightning.channel_is_ready(&c.channel_id).await?;
            let txid = c
                .funding_txo
                .as_deref()
                .and_then(|v| v.split_once(':'))
                .map(|(v, _)| v.to_owned());
            self.storage
                .starter_update(
                    StarterUpdate::Observe {
                        id: g.request_id.clone(),
                        channel_id: c.channel_id.clone(),
                        user_channel_id: c.user_channel_id.clone(),
                        funding_txid: txid,
                        ready,
                    },
                    time,
                )
                .await?;
            if let Some(op) = op {
                if op.state == "pending" {
                    self.storage
                        .resolve_channel_open_operation(
                            &g.request_id,
                            "opened",
                            Some(&serde_json::to_vec(c)?),
                            None,
                        )
                        .await?;
                }
            }
            if ready {
                self.storage
                    .mark_invite_accepted(&g.invite_id.parse()?, now as u64)
                    .await?;
                metrics::counter!("konsensus_starter_gift_sats_total")
                    .increment(g.push_sats as u64);
            }
        } else if let Some(op) = op {
            if now.saturating_mul(1000) - op.created_at >= 600_000
                && matches!(op.state.as_str(), "pending" | "opened")
            {
                self.storage
                    .starter_update(
                        StarterUpdate::MarkUncertain {
                            id: g.request_id.clone(),
                        },
                        time,
                    )
                    .await?;
                metrics::counter!("konsensus_starter_uncertain_opens").increment(1);
                tracing::warn!(request_id=%g.request_id,node_id=%g.requester_node_id,"starter open uncertain; operator resolution required");
            }
        }
        Ok(())
    }
}
pub async fn run(
    hub: StarterHub,
    transport: Arc<NoiseTransport>,
    mut rx: mpsc::Receiver<(NodeId, Frame)>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            _=shutdown.changed()=>break,
            Some((peer,frame))=rx.recv()=>{
                match hub.handle(peer,frame,None).await {
                    Ok(frame)=>{let _=transport.enqueue_control_frame(&peer,&frame).await;},
                    Err(_)=>tracing::warn!("starter admission unavailable; request may be replayed"),
                }
            }
            _=interval.tick()=>{
                let now=chrono::Utc::now().timestamp();
                if hub.tick(None).await.is_err(){tracing::warn!("starter reconciliation unavailable; reservations retained");}
                if let Ok(grants)=hub.storage.starter_grants().await {
                    for g in grants.iter().filter(|g|g.updated_at>=now-15) {
                        if let Ok(peer)=NodeId::from_hex(&g.requester_node_id) {let _=transport.enqueue_control_frame(&peer,&status(g)).await;}
                    }
                }
            }
        }
    }
}

// TODO(PR-2, Codex C3): persist initial push evidence or prevent spending before
// newcomer verification; current balance after spending is not initial-push proof.
// TODO(PR-2, Fool F4): automatically mint a new UUID after a retryable refusal,
// respecting retry_after_unix and the hub's ten-minute admission throttle.
#[cfg(test)]
#[path = "starter_hub_tests.rs"]
mod tests;
