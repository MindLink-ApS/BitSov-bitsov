//! ONB5 auto-channel-open worker.
//!
//! This worker only opens channels after a peer has advertised both its
//! Lightning pubkey and a dialable Lightning address. The BitSov invite `addr`
//! is the inviter's P2P address for first contact, not the invitee's Lightning
//! endpoint, so using it here would spend sats against the wrong endpoint.

use std::sync::Arc;

use thiserror::Error;
use tokio::sync::{mpsc, watch};
use tracing::{debug, info, warn};

use konsensus_core::traits::chain::ChainProvider;
use konsensus_core::traits::lightning::{
    ChannelInfo, FundingOptions, FundingPriority, LightningError, LightningProvider,
};
use konsensus_core::types::NodeId;
use konsensus_storage::{InviteIssuedRecord, InviteState, Storage, StorageError};

use super::notify::{ChannelOpenNotice, NotificationSink};

use crate::config::SubsidyConfig;

const DEFAULT_CHANNEL_SIZE_SATS: u64 = 50_000;
const DEFAULT_MAX_FEE_RATE_SAT_PER_VB: u32 = 50;
const FEE_ESTIMATE_TARGET_BLOCKS: u32 = 6;
const FUNDING_TX_VBYTES_ESTIMATE: u64 = 300;

#[derive(Debug, Clone)]
pub enum AutoChannelEvent {
    PeerLightningInfo {
        peer_id: NodeId,
        ln_pubkey: String,
        ln_addr: Option<String>,
    },
}

pub struct AutoChannelDeps {
    pub storage: Arc<dyn Storage>,
    pub lightning: Arc<dyn LightningProvider>,
    pub chain: Arc<dyn ChainProvider>,
    pub notifier: Arc<dyn NotificationSink>,
    pub event_rx: mpsc::Receiver<AutoChannelEvent>,
    pub shutdown_rx: watch::Receiver<bool>,
    /// R1-a onboarding subsidy policy. OFF by default → the worker is inert.
    pub subsidy: SubsidyConfig,
    /// LDK uses estimator-selected funding; None preserves exact-rate backends.
    pub funding_priority: Option<FundingPriority>,
}

#[derive(Debug, Error)]
pub enum AutoChannelError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("lightning error: {0}")]
    Lightning(#[from] LightningError),
    #[error("chain error: {0}")]
    Chain(#[from] konsensus_core::traits::chain::ChainError),
    #[error("invalid peer Lightning address: {0}")]
    InvalidAddress(String),
}

pub async fn run(mut deps: AutoChannelDeps) {
    loop {
        tokio::select! {
            event = deps.event_rx.recv() => {
                let Some(event) = event else {
                    info!("auto-channel event channel closed, worker exiting");
                    break;
                };
                if let Err(e) = handle_event(
                    event,
                    Arc::clone(&deps.storage),
                    Arc::clone(&deps.lightning),
                    Arc::clone(&deps.chain),
                    Arc::clone(&deps.notifier),
                    deps.subsidy.clone(),
                    deps.funding_priority,
                ).await {
                    warn!(error = %e, "auto-channel event failed");
                }
            }
            _ = deps.shutdown_rx.changed() => {
                info!("auto-channel worker shutting down");
                break;
            }
        }
    }
}

pub async fn handle_event(
    event: AutoChannelEvent,
    storage: Arc<dyn Storage>,
    lightning: Arc<dyn LightningProvider>,
    chain: Arc<dyn ChainProvider>,
    notifier: Arc<dyn NotificationSink>,
    subsidy: SubsidyConfig,
    funding_priority: Option<FundingPriority>,
) -> Result<(), AutoChannelError> {
    match event {
        AutoChannelEvent::PeerLightningInfo {
            peer_id,
            ln_pubkey,
            ln_addr,
        } => {
            handle_peer_lightning_info(
                peer_id,
                ln_pubkey,
                ln_addr,
                storage,
                lightning,
                chain,
                notifier,
                subsidy,
                funding_priority,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_peer_lightning_info(
    peer_id: NodeId,
    ln_pubkey: String,
    ln_addr: Option<String>,
    storage: Arc<dyn Storage>,
    lightning: Arc<dyn LightningProvider>,
    chain: Arc<dyn ChainProvider>,
    notifier: Arc<dyn NotificationSink>,
    subsidy: SubsidyConfig,
    funding_priority: Option<FundingPriority>,
) -> Result<(), AutoChannelError> {
    // R1-a LOAD-BEARING DRIFT-DEATH: the onboarding subsidy is OFF by default, so
    // on the live mesh an invite's `Pending` membership authorizes ZERO spend —
    // this worker is inert until an operator explicitly opts in. Payment, never
    // membership, is what may move sats.
    if !subsidy.enabled {
        debug!(peer = %peer_id, "onboarding subsidy disabled; auto-channel noop");
        return Ok(());
    }

    let Some(invite) = storage
        .find_pending_invite_for_invitee(peer_id.as_bytes())
        .await?
    else {
        debug!(peer = %peer_id, "no pending issued invite for peer; auto-channel noop");
        return Ok(());
    };

    // R1-a: invite membership is necessary but NOT sufficient — the operator must
    // also list the peer. An empty allowlist (the default) makes nobody eligible.
    if !subsidy.is_allowlisted(peer_id.as_bytes()) {
        debug!(
            peer = %peer_id,
            "peer holds a pending invite but is not in onboarding_subsidy.allowlist; auto-channel noop"
        );
        return Ok(());
    }

    // R1-a: the operator's per-channel cap replaces the invitee-supplied hint — a
    // malicious or generous hint can only ever lower the spend, never raise it.
    let requested_sats = u64::from(
        invite
            .channel_size_hint_sats
            .unwrap_or(DEFAULT_CHANNEL_SIZE_SATS as u32),
    );
    let amount_sats = requested_sats.min(subsidy.max_channel_sats);
    if amount_sats == 0 {
        notify_abort(
            notifier.as_ref(),
            &invite,
            peer_id,
            &ln_pubkey,
            amount_sats,
            "subsidy_zero_amount".to_string(),
        )
        .await;
        warn!(
            invite_id = %invite.id,
            peer = %peer_id,
            requested_sats,
            max_channel_sats = subsidy.max_channel_sats,
            "auto-channel aborted: subsidy cap clamped channel amount to zero"
        );
        return Ok(());
    }
    let max_fee_rate = invite
        .max_fee_rate_sat_per_vb
        .unwrap_or(DEFAULT_MAX_FEE_RATE_SAT_PER_VB)
        .min(subsidy.max_funding_fee_rate_sat_per_vb);

    let funding_options = funding_priority.map(|priority| FundingOptions {
        priority,
        // Use the already-budgeted fee buffer as a hard transaction fee cap.
        max_funding_fee_sats: Some(funding_fee_buffer_sats(max_fee_rate)),
    });
    let current_fee_rate = if let Some(options) = &funding_options {
        let quote = lightning.funding_fee_quote(options.clone()).await?;
        checked_fee_rate_sat_per_vb(quote.estimated_fee_rate_sat_per_vb)?
    } else {
        estimate_fee_rate_sat_per_vb(chain.as_ref()).await?
    };
    if current_fee_rate > max_fee_rate {
        notify_abort(
            notifier.as_ref(),
            &invite,
            peer_id,
            &ln_pubkey,
            amount_sats,
            format!("fee_too_high:{current_fee_rate}>{max_fee_rate}"),
        )
        .await;
        warn!(
            invite_id = %invite.id,
            peer = %peer_id,
            current_fee_rate,
            max_fee_rate,
            "auto-channel aborted: fee guard"
        );
        return Ok(());
    }

    let now = now_unix();
    let intent_expiry = invite
        .channel_open_intent_expiry_unix
        .unwrap_or(invite.expiry_unix);
    if now >= intent_expiry {
        let _ = storage.mark_invite_expired(&invite.id, now).await?;
        notify_abort(
            notifier.as_ref(),
            &invite,
            peer_id,
            &ln_pubkey,
            amount_sats,
            "expired".to_string(),
        )
        .await;
        warn!(
            invite_id = %invite.id,
            peer = %peer_id,
            now,
            intent_expiry,
            "auto-channel aborted: expiry guard"
        );
        return Ok(());
    }

    let Some(ln_addr) = ln_addr.filter(|addr| !addr.trim().is_empty()) else {
        notify_abort(
            notifier.as_ref(),
            &invite,
            peer_id,
            &ln_pubkey,
            amount_sats,
            "missing_lightning_addr".to_string(),
        )
        .await;
        warn!(
            invite_id = %invite.id,
            peer = %peer_id,
            "auto-channel aborted: peer did not advertise Lightning address"
        );
        return Ok(());
    };
    validate_host_port(&ln_addr)?;

    if existing_channel_to_peer(lightning.as_ref(), &ln_pubkey).await? {
        let _ = storage.mark_invite_accepted(&invite.id, now).await?;
        notify_opened(
            notifier.as_ref(),
            &invite,
            peer_id,
            &ln_pubkey,
            amount_sats,
            "already_open".to_string(),
        )
        .await;
        info!(
            invite_id = %invite.id,
            peer = %peer_id,
            "auto-channel idempotency: existing channel already covers peer"
        );
        return Ok(());
    }

    // R1-a: gate the actual spend on the operator's per-peer and aggregate caps.
    // The already-open idempotency path above returns BEFORE this, so a tight
    // budget never blocks a no-cost re-confirmation. One issued-invite scan
    // (only when subsidy is enabled) covers both caps.
    {
        let issued = storage.list_invites_issued().await?;
        let peer_opens = issued
            .iter()
            .filter(|record| &record.invitee_pubkey == peer_id.as_bytes())
            .filter(|record| matches!(record.state, InviteState::Opening | InviteState::Accepted))
            .count() as u32;
        if peer_opens >= subsidy.per_peer_max_opens {
            notify_abort(
                notifier.as_ref(),
                &invite,
                peer_id,
                &ln_pubkey,
                amount_sats,
                format!(
                    "subsidy_per_peer_cap:{peer_opens}>={}",
                    subsidy.per_peer_max_opens
                ),
            )
            .await;
            warn!(
                invite_id = %invite.id,
                peer = %peer_id,
                peer_opens,
                per_peer_max_opens = subsidy.per_peer_max_opens,
                "auto-channel aborted: per-peer subsidy cap"
            );
            return Ok(());
        }

        // Budget sums CLAMPED amounts over in-flight `Opening` invites ONLY.
        // `Accepted` includes already-open no-spend confirmations, so counting it
        // would falsely starve the budget — count only what is actually spending.
        let committed_sats: u64 = issued
            .iter()
            .filter(|record| matches!(record.state, InviteState::Opening))
            .map(|record| {
                u64::from(
                    record
                        .channel_size_hint_sats
                        .unwrap_or(DEFAULT_CHANNEL_SIZE_SATS as u32),
                )
                .min(subsidy.max_channel_sats)
            })
            .fold(0u64, |acc, sats| acc.saturating_add(sats));
        if committed_sats.saturating_add(amount_sats) > subsidy.max_total_budget_sats {
            notify_abort(
                notifier.as_ref(),
                &invite,
                peer_id,
                &ln_pubkey,
                amount_sats,
                format!(
                    "subsidy_budget_exhausted:{committed_sats}+{amount_sats}>{}",
                    subsidy.max_total_budget_sats
                ),
            )
            .await;
            warn!(
                invite_id = %invite.id,
                peer = %peer_id,
                committed_sats,
                amount_sats,
                max_total_budget_sats = subsidy.max_total_budget_sats,
                "auto-channel aborted: aggregate subsidy budget exhausted"
            );
            return Ok(());
        }
    }

    let balance_msat = lightning.get_balance_msat().await?;
    let balance_sats = balance_msat / 1000;
    let fee_buffer_sats = funding_fee_buffer_sats(max_fee_rate);
    let required_sats = amount_sats.saturating_add(fee_buffer_sats);
    if balance_sats < required_sats {
        notify_abort(
            notifier.as_ref(),
            &invite,
            peer_id,
            &ln_pubkey,
            amount_sats,
            format!("insufficient_balance:{balance_sats}<{required_sats}"),
        )
        .await;
        warn!(
            invite_id = %invite.id,
            peer = %peer_id,
            balance_sats,
            required_sats,
            "auto-channel aborted: balance guard"
        );
        return Ok(());
    }

    let opening = storage.mark_invite_opening(&invite.id, now).await?;
    if !opening {
        info!(
            invite_id = %invite.id,
            peer = %peer_id,
            "auto-channel idempotency: invite is no longer pending"
        );
        return Ok(());
    }

    let open_result = if let Some(options) = funding_options {
        // LDK refuses exact caller rates. Keep this private and zero-push, with
        // a fresh estimator policy and a fee cap enforced during construction.
        lightning
            .open_channel_with_funding(&ln_pubkey, &ln_addr, amount_sats, false, options, None)
            .await
            .map(|result| result.user_channel_id.unwrap_or(result.channel_id))
    } else {
        lightning
            .open_channel(
                &ln_pubkey,
                &ln_addr,
                amount_sats,
                false,
                Some(current_fee_rate as f32),
            )
            .await
    };
    let channel_id = match open_result {
        Ok(channel_id) => channel_id,
        Err(e) => {
            // Only proven non-dispatch permits retry. An uncertain outcome stays
            // Opening so later events cannot reopen and both subsidy caps count it.
            if matches!(
                e,
                LightningError::PaymentNotDispatched(_) | LightningError::NotReady
            ) {
                let _ = storage.mark_invite_pending(&invite.id).await?;
            } else {
                warn!(
                    invite_id = %invite.id,
                    peer = %peer_id,
                    error = %e,
                    "auto-channel outcome uncertain; retaining Opening; inspect channel before retrying"
                );
            }
            return Err(e.into());
        }
    };
    let accepted = storage.mark_invite_accepted(&invite.id, now).await?;
    if !accepted {
        warn!(
            invite_id = %invite.id,
            peer = %peer_id,
            channel_id = %channel_id,
            "auto-channel opened but invite was no longer pending"
        );
    }
    notify_opened(
        notifier.as_ref(),
        &invite,
        peer_id,
        &ln_pubkey,
        amount_sats,
        channel_id.clone(),
    )
    .await;
    info!(
        invite_id = %invite.id,
        peer = %peer_id,
        channel_id = %channel_id,
        amount_sats,
        current_fee_rate,
        "auto-channel opened"
    );
    Ok(())
}

async fn estimate_fee_rate_sat_per_vb(chain: &dyn ChainProvider) -> Result<u32, AutoChannelError> {
    let estimate = chain.estimate_fee(FEE_ESTIMATE_TARGET_BLOCKS).await?;
    checked_fee_rate_sat_per_vb(estimate.sat_per_vbyte)
}

fn checked_fee_rate_sat_per_vb(estimate: f64) -> Result<u32, AutoChannelError> {
    let fee = estimate.ceil();
    if !fee.is_finite()
        || fee < 1.0
        || fee > f64::from(konsensus_core::fee_rate::MAX_FEE_RATE_SAT_PER_VB)
    {
        return Err(AutoChannelError::Chain(
            konsensus_core::traits::chain::ChainError::FeeEstimationFailed(format!(
                "invalid funding fee estimate: {estimate}"
            )),
        ));
    }
    // The sanity bound also makes the later u32 -> f32 dispatch lossless.
    Ok(fee as u32)
}

fn funding_fee_buffer_sats(max_fee_rate_sat_per_vb: u32) -> u64 {
    u64::from(max_fee_rate_sat_per_vb).saturating_mul(FUNDING_TX_VBYTES_ESTIMATE)
}

async fn existing_channel_to_peer(
    lightning: &dyn LightningProvider,
    ln_pubkey: &str,
) -> Result<bool, LightningError> {
    let channels: Vec<ChannelInfo> = lightning.list_channels().await?;
    // Pending funding and temporarily unusable channels still cover this peer.
    // Hex case is not identity: LDK prints lowercase, and the peer chooses the
    // case in LightningInfo. A case-sensitive compare misses that channel and
    // funds another one.
    Ok(channels
        .iter()
        .any(|channel| channel.peer_pubkey.eq_ignore_ascii_case(ln_pubkey)))
}

fn validate_host_port(addr: &str) -> Result<(), AutoChannelError> {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return Err(AutoChannelError::InvalidAddress("missing port".into()));
    };
    if host.trim().is_empty() {
        return Err(AutoChannelError::InvalidAddress("empty host".into()));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| AutoChannelError::InvalidAddress("invalid port".into()))?;
    if port == 0 {
        return Err(AutoChannelError::InvalidAddress("zero port".into()));
    }
    Ok(())
}

async fn notify_abort(
    notifier: &dyn NotificationSink,
    invite: &InviteIssuedRecord,
    peer_id: NodeId,
    ln_pubkey: &str,
    amount_sats: u64,
    reason: String,
) {
    let _ = notifier
        .notify(ChannelOpenNotice {
            invite_id: invite.id,
            peer_id,
            ln_pubkey: ln_pubkey.to_string(),
            amount_sats,
            status: "aborted",
            reason: Some(reason),
            channel_id: None,
        })
        .await;
}

async fn notify_opened(
    notifier: &dyn NotificationSink,
    invite: &InviteIssuedRecord,
    peer_id: NodeId,
    ln_pubkey: &str,
    amount_sats: u64,
    channel_id: String,
) {
    let _ = notifier
        .notify(ChannelOpenNotice {
            invite_id: invite.id,
            peer_id,
            ln_pubkey: ln_pubkey.to_string(),
            amount_sats,
            status: "opened",
            reason: None,
            channel_id: Some(channel_id),
        })
        .await;
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use tokio::sync::{Mutex, Notify};

    use konsensus_core::traits::chain::{BlockHeader, ChainError, FeeEstimate, TrustLevel};
    use konsensus_core::traits::lightning::{
        ChannelOpenResult, FundingFeeEstimate, Invoice, PaymentDetails, PaymentDirection,
        PaymentStatus,
    };
    use konsensus_storage::{InviteState, SqliteStorage};

    const LN_PUBKEY: &str = "02abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab";

    struct TestChain {
        fee_rate: f64,
    }

    #[async_trait]
    impl ChainProvider for TestChain {
        fn trust_level(&self) -> TrustLevel {
            TrustLevel::ServerTrust
        }

        async fn get_block_height(&self) -> Result<u64, ChainError> {
            Ok(949_214)
        }

        async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError> {
            Ok(BlockHeader {
                height,
                hash: "00".repeat(32),
                timestamp: 1_700_000_000,
                bits: 0,
            })
        }

        async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeEstimate, ChainError> {
            Ok(FeeEstimate {
                target_blocks,
                sat_per_vbyte: self.fee_rate,
            })
        }

        async fn is_tx_confirmed(
            &self,
            _txid: &str,
            _min_confirmations: u32,
        ) -> Result<bool, ChainError> {
            Ok(true)
        }

        async fn is_synced(&self) -> bool {
            true
        }
    }

    type ChannelOpen = (String, String, u64, Option<f32>, bool);

    #[derive(Default)]
    struct TestLightning {
        balance_msat: u64,
        ldk: Option<konsensus_lightning::LdkProvider>,
        channels: Mutex<Vec<ChannelInfo>>,
        opens: Mutex<Vec<ChannelOpen>>,
        open_error: Mutex<Option<LightningError>>,
        reject_fee_requests: bool,
        open_started: Option<Arc<Notify>>,
        release_open: Option<Arc<Notify>>,
    }

    #[async_trait]
    impl LightningProvider for TestLightning {
        async fn create_invoice(
            &self,
            _amount_msat: u64,
            _description: &str,
            _expiry_secs: u32,
        ) -> Result<Invoice, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }

        async fn pay_invoice(&self, _bolt11: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }

        async fn get_payment_status(
            &self,
            _payment_hash: &str,
        ) -> Result<PaymentDetails, LightningError> {
            Ok(PaymentDetails {
                payment_hash: "00".repeat(32),
                preimage: None,
                amount_msat: 0,
                status: PaymentStatus::Settled,
                direction: PaymentDirection::Incoming,
                timestamp: 0,
                memo: None,
                fee_msat: None,
            })
        }

        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(self.balance_msat)
        }

        async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
            Ok(self.channels.lock().await.clone())
        }

        async fn is_available(&self) -> bool {
            true
        }

        async fn open_channel(
            &self,
            peer_pubkey: &str,
            peer_addr: &str,
            amount_sats: u64,
            announce: bool,
            fee_rate_sat_per_vb: Option<f32>,
        ) -> Result<String, LightningError> {
            if let Some(ldk) = &self.ldk {
                return ldk
                    .open_channel(
                        peer_pubkey,
                        peer_addr,
                        amount_sats,
                        announce,
                        fee_rate_sat_per_vb,
                    )
                    .await;
            }
            if self.reject_fee_requests && fee_rate_sat_per_vb.is_some() {
                return Err(LightningError::PaymentNotDispatched(
                    "funding fee override unsupported".into(),
                ));
            }
            if let Some(rate) = fee_rate_sat_per_vb {
                konsensus_core::fee_rate::validate_fee_rate_sat_per_vb(rate)
                    .map_err(|e| LightningError::PaymentNotDispatched(e.to_string()))?;
            }
            self.opens.lock().await.push((
                peer_pubkey.to_string(),
                peer_addr.to_string(),
                amount_sats,
                fee_rate_sat_per_vb,
                announce,
            ));
            if let Some(open_started) = &self.open_started {
                open_started.notify_waiters();
            }
            if let Some(release_open) = &self.release_open {
                release_open.notified().await;
            }
            if let Some(error) = self.open_error.lock().await.take() {
                return Err(error);
            }
            Ok("temp-channel-id".to_string())
        }

        async fn funding_fee_quote(
            &self,
            options: FundingOptions,
        ) -> Result<FundingFeeEstimate, LightningError> {
            self.ldk
                .as_ref()
                .expect("only LDK uses funding policy")
                .funding_fee_quote(options)
                .await
        }

        async fn open_channel_with_funding(
            &self,
            peer_pubkey: &str,
            peer_addr: &str,
            amount_sats: u64,
            announce: bool,
            options: FundingOptions,
            push_msat: Option<u64>,
        ) -> Result<ChannelOpenResult, LightningError> {
            assert_eq!(
                options.priority,
                konsensus_core::traits::lightning::FundingPriority::Fast
            );
            assert_eq!(options.max_funding_fee_sats, Some(1500));
            assert!(!announce);
            assert_eq!(push_msat, None);
            self.opens.lock().await.push((
                peer_pubkey.to_string(),
                peer_addr.to_string(),
                amount_sats,
                None,
                announce,
            ));
            if let Some(error) = self.open_error.lock().await.take() {
                return Err(error);
            }
            self.ldk
                .as_ref()
                .expect("only LDK uses funding policy")
                .open_channel_with_funding(
                    peer_pubkey,
                    peer_addr,
                    amount_sats,
                    announce,
                    options,
                    push_msat,
                )
                .await
        }
    }

    #[derive(Default)]
    struct RecordingNotifier {
        notices: Mutex<Vec<ChannelOpenNotice>>,
    }

    #[async_trait]
    impl NotificationSink for RecordingNotifier {
        async fn notify(
            &self,
            notice: ChannelOpenNotice,
        ) -> Result<(), super::super::notify::NotifyError> {
            self.notices.lock().await.push(notice);
            Ok(())
        }
    }

    async fn storage_with_invite(
        invitee: NodeId,
        max_fee_rate: u32,
        channel_size_hint_sats: Option<u32>,
        intent_expiry_unix: u64,
    ) -> Arc<SqliteStorage> {
        let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());

        storage
            .add_invite_issued(&InviteIssuedRecord {
                id: uuid::Uuid::new_v4(),
                invitee_pubkey: *invitee.as_bytes(),
                expiry_unix: intent_expiry_unix.saturating_add(3600),
                channel_size_hint_sats,
                addr: "inviter.example:9736".to_string(),
                max_fee_rate_sat_per_vb: Some(max_fee_rate),
                channel_open_intent_expiry_unix: Some(intent_expiry_unix),
                nonce: [7u8; 16],
                state: InviteState::Pending,
                created_at: 1,
                accepted_at: None,
                revoked_at: None,
            })
            .await
            .unwrap();
        storage
    }

    type TestDeps = (
        Arc<dyn Storage>,
        Arc<dyn LightningProvider>,
        Arc<dyn ChainProvider>,
        Arc<dyn NotificationSink>,
    );

    fn deps(
        storage: Arc<dyn Storage>,
        lightning: Arc<TestLightning>,
        fee_rate: f64,
        notifier: Arc<RecordingNotifier>,
    ) -> TestDeps {
        (
            storage,
            lightning,
            Arc::new(TestChain { fee_rate }),
            notifier,
        )
    }

    /// Enabled subsidy with every test peer (`[1;32]..=[9;32]`) allowlisted and
    /// generous caps, so the pre-R1-a downstream-guard tests keep exercising the
    /// same path now that membership alone no longer authorizes a spend.
    fn test_subsidy() -> SubsidyConfig {
        SubsidyConfig {
            enabled: true,
            max_channel_sats: 1_000_000,
            max_total_budget_sats: 100_000_000,
            max_funding_fee_rate_sat_per_vb: 50,
            per_peer_max_opens: 1,
            allowlist: (1u8..=9u8).map(|n| hex::encode([n; 32])).collect(),
        }
    }

    // Unless open_error is injected, only the wallet balance is faked: both open
    // APIs and fee quotes use the real LdkProvider. NotRunning comes from LDK's
    // opener, after the exact-rate refusal, so it proves dispatch without dialing
    // or spending funds.
    async fn ldk_fixture(fees: &str) -> (tempfile::TempDir, Arc<TestLightning>, String) {
        let mut server = mockito::Server::new_async().await;
        let _fees = server
            .mock("GET", "/fee-estimates")
            .with_body(fees)
            .create_async()
            .await;
        let dir = tempfile::tempdir().unwrap();
        let mut builder = ldk_node::Builder::new();
        builder.set_network(bitcoin::Network::Regtest);
        builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
        builder.set_listening_addresses(vec![]).unwrap();
        builder.set_gossip_source_p2p();
        builder.set_chain_source_esplora(
            server.url(),
            Some(ldk_node::config::EsploraSyncConfig {
                background_sync_config: None,
            }),
        );
        let node = Arc::new(builder.build().unwrap());
        node.start().unwrap();
        node.stop().unwrap();
        let ln_pubkey = node.node_id().to_string();
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            ldk: Some(konsensus_lightning::LdkProvider::from_node(node)),
            ..Default::default()
        });
        (dir, lightning, ln_pubkey)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn onb5_ldk_open_reaches_dispatch() {
        let (_dir, lightning, ln_pubkey) = ldk_fixture(r#"{"1":2.0,"6":2.0,"144":2.0}"#).await;
        let peer = NodeId::from_bytes([1; 32]);
        let storage = storage_with_invite(peer, 5, Some(10_000), now_unix() + 60).await;
        let notifier = Arc::new(RecordingNotifier::default());
        let (s, l, c, n) = deps(storage.clone(), lightning, 100.0, notifier.clone());
        let result = handle_event(
            AutoChannelEvent::PeerLightningInfo {
                peer_id: peer,
                ln_pubkey,
                ln_addr: Some("127.0.0.1:9735".into()),
            },
            s,
            l,
            c,
            n,
            test_subsidy(),
            Some(FundingPriority::Fast),
        )
        .await;
        assert!(
            matches!(result,
            Err(AutoChannelError::Lightning(LightningError::PaymentNotDispatched(ref reason)))
                if reason.contains(&ldk_node::NodeError::NotRunning.to_string())),
            "{result:?}"
        );
        assert_eq!(
            storage.list_invites_issued().await.unwrap()[0].state,
            InviteState::Pending
        );
        assert!(notifier.notices.lock().await.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn uncertain_open_blocks_duplicate_event_and_retains_subsidy_caps() {
        for funding_priority in [None, Some(FundingPriority::Fast)] {
            let (_dir, ldk, _) = ldk_fixture(r#"{"1":2.0,"6":2.0,"144":2.0}"#).await;
            for reason in [
                "funding transaction unavailable after 60s; outcome uncertain",
                "open_channel worker failed",
                "channel disappeared before funding was verified",
            ] {
                let peer = NodeId::from_bytes([1; 32]);
                let storage = storage_with_invite(peer, 5, Some(10_000), now_unix() + 60).await;
                let lightning = if funding_priority.is_some() {
                    ldk.clone()
                } else {
                    Arc::new(TestLightning {
                        balance_msat: 100_000_000,
                        ..Default::default()
                    })
                };
                lightning.opens.lock().await.clear();
                *lightning.open_error.lock().await = Some(LightningError::Backend(reason.into()));
                let notifier = Arc::new(RecordingNotifier::default());
                let event = AutoChannelEvent::PeerLightningInfo {
                    peer_id: peer,
                    ln_pubkey: LN_PUBKEY.into(),
                    ln_addr: Some("127.0.0.1:9735".into()),
                };
                let subsidy = SubsidyConfig {
                    max_total_budget_sats: 10_000,
                    ..test_subsidy()
                };
                let (s, l, c, n) = deps(storage.clone(), lightning.clone(), 2.0, notifier.clone());
                let result =
                    handle_event(event.clone(), s, l, c, n, subsidy.clone(), funding_priority)
                        .await;
                assert!(matches!(result,
                    Err(AutoChannelError::Lightning(LightningError::Backend(ref message)))
                        if message == reason));

                // No channel is visible yet: the durable invite must prevent retry.
                let (s, l, c, n) = deps(storage.clone(), lightning.clone(), 2.0, notifier.clone());
                let retry =
                    handle_event(event, s, l, c, n, subsidy.clone(), funding_priority).await;
                assert_eq!(lightning.opens.lock().await.len(), 1, "{reason}");
                retry.unwrap();
                let uncertain = storage.list_invites_issued().await.unwrap().remove(0);
                assert_eq!(uncertain.state, InviteState::Opening);
                assert!(notifier.notices.lock().await.is_empty());

                // A fresh invite cannot bypass either the peer cap or the budget.
                for (next_peer, expected_reason) in [
                    (peer, "subsidy_per_peer_cap"),
                    (NodeId::from_bytes([2; 32]), "subsidy_budget_exhausted"),
                ] {
                    let mut fresh = uncertain.clone();
                    fresh.id = uuid::Uuid::new_v4();
                    fresh.nonce = *fresh.id.as_bytes();
                    fresh.invitee_pubkey = *next_peer.as_bytes();
                    fresh.state = InviteState::Pending;
                    fresh.accepted_at = None;
                    storage.add_invite_issued(&fresh).await.unwrap();
                    let (s, l, c, n) =
                        deps(storage.clone(), lightning.clone(), 2.0, notifier.clone());
                    handle_event(
                        AutoChannelEvent::PeerLightningInfo {
                            peer_id: next_peer,
                            ln_pubkey: LN_PUBKEY.into(),
                            ln_addr: Some("127.0.0.1:9735".into()),
                        },
                        s,
                        l,
                        c,
                        n,
                        subsidy.clone(),
                        funding_priority,
                    )
                    .await
                    .unwrap();
                    assert_eq!(lightning.opens.lock().await.len(), 1);
                    let notices = notifier.notices.lock().await;
                    assert!(notices
                        .last()
                        .unwrap()
                        .reason
                        .as_deref()
                        .unwrap()
                        .starts_with(expected_reason));
                }
            }
        }
    }

    #[tokio::test]
    async fn proven_non_dispatch_allows_retry() {
        for error in [
            LightningError::NotReady,
            LightningError::PaymentNotDispatched("refused".into()),
        ] {
            let peer = NodeId::from_bytes([1; 32]);
            let storage = storage_with_invite(peer, 5, Some(10_000), now_unix() + 60).await;
            let lightning = Arc::new(TestLightning {
                balance_msat: 100_000_000,
                open_error: Mutex::new(Some(error)),
                ..Default::default()
            });
            let notifier = Arc::new(RecordingNotifier::default());
            for attempt in 0..2 {
                let (s, l, c, n) = deps(storage.clone(), lightning.clone(), 2.0, notifier.clone());
                let result = handle_event(
                    AutoChannelEvent::PeerLightningInfo {
                        peer_id: peer,
                        ln_pubkey: LN_PUBKEY.into(),
                        ln_addr: Some("127.0.0.1:9735".into()),
                    },
                    s,
                    l,
                    c,
                    n,
                    test_subsidy(),
                    None,
                )
                .await;
                let expected_state = if attempt == 0 {
                    assert!(matches!(
                        result,
                        Err(AutoChannelError::Lightning(
                            LightningError::NotReady | LightningError::PaymentNotDispatched(_)
                        ))
                    ));
                    InviteState::Pending
                } else {
                    result.unwrap();
                    InviteState::Accepted
                };
                assert_eq!(
                    storage.list_invites_issued().await.unwrap()[0].state,
                    expected_state
                );
            }
            assert_eq!(lightning.opens.lock().await.len(), 2);
        }
    }

    #[tokio::test]
    async fn pending_channel_prevents_another_open() {
        let peer = NodeId::from_bytes([1; 32]);
        let storage = storage_with_invite(peer, 5, Some(10_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            channels: Mutex::new(vec![ChannelInfo {
                is_outbound: None,
                is_announced: None,
                is_channel_ready: None,
                local_reserve_msat: None,
                initial_push_msat: None,
                channel_id: "pending-channel".into(),
                user_channel_id: None,
                funding_txo: None,
                peer_pubkey: LN_PUBKEY.into(),
                capacity_msat: 10_000_000,
                local_balance_msat: 10_000_000,
                outbound_capacity_msat: None,
                remote_balance_msat: 0,
                active: false,
                short_channel_id: None,
            }]),
            ..Default::default()
        });
        assert!(
            !existing_channel_to_peer(lightning.as_ref(), "another-peer")
                .await
                .unwrap()
        );
        let (s, l, c, n) = deps(
            storage.clone(),
            lightning.clone(),
            2.0,
            Arc::new(RecordingNotifier::default()),
        );
        handle_event(
            AutoChannelEvent::PeerLightningInfo {
                peer_id: peer,
                ln_pubkey: LN_PUBKEY.into(),
                ln_addr: Some("127.0.0.1:9735".into()),
            },
            s,
            l,
            c,
            n,
            test_subsidy(),
            None,
        )
        .await
        .unwrap();
        assert!(lightning.opens.lock().await.is_empty());
        assert_eq!(
            storage.list_invites_issued().await.unwrap()[0].state,
            InviteState::Accepted
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn onb5_ldk_quote_above_either_rate_cap_never_opens() {
        let (_dir, lightning, ln_pubkey) = ldk_fixture(r#"{"1":2.0,"6":2.0,"144":2.0}"#).await;
        for (operator_cap, invite_cap) in [(1, 5), (5, 1)] {
            let peer = NodeId::from_bytes([1; 32]);
            let storage =
                storage_with_invite(peer, invite_cap, Some(10_000), now_unix() + 60).await;
            let notifier = Arc::new(RecordingNotifier::default());
            let mut subsidy = test_subsidy();
            subsidy.max_funding_fee_rate_sat_per_vb = operator_cap;
            let (s, l, c, n) = deps(storage.clone(), lightning.clone(), 1.0, notifier.clone());
            handle_peer_lightning_info(
                peer,
                ln_pubkey.clone(),
                Some("127.0.0.1:9735".into()),
                s,
                l,
                c,
                n,
                subsidy,
                Some(FundingPriority::Fast),
            )
            .await
            .unwrap();
            assert_eq!(
                storage.list_invites_issued().await.unwrap()[0].state,
                InviteState::Pending
            );
            let notices = notifier.notices.lock().await;
            assert_eq!(notices.len(), 1);
            assert_eq!(notices[0].status, "aborted");
            assert_eq!(notices[0].reason.as_deref(), Some("fee_too_high:2>1"));
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn onb5_ldk_missing_quote_refuses_without_falling_back() {
        let (_dir, lightning, ln_pubkey) = ldk_fixture("{}").await;
        let peer = NodeId::from_bytes([1; 32]);
        let storage = storage_with_invite(peer, 5, Some(10_000), now_unix() + 60).await;
        let notifier = Arc::new(RecordingNotifier::default());
        let (s, l, c, n) = deps(storage.clone(), lightning, 1.0, notifier.clone());
        let result = handle_peer_lightning_info(
            peer,
            ln_pubkey,
            Some("127.0.0.1:9735".into()),
            s,
            l,
            c,
            n,
            test_subsidy(),
            Some(FundingPriority::Fast),
        )
        .await;
        assert!(
            matches!(result,
            Err(AutoChannelError::Lightning(LightningError::PaymentNotDispatched(ref reason)))
                if reason.contains("funding estimate unavailable or invalid")),
            "{result:?}"
        );
        assert_eq!(
            storage.list_invites_issued().await.unwrap()[0].state,
            InviteState::Pending
        );
        assert!(notifier.notices.lock().await.is_empty());
    }

    #[tokio::test]
    async fn onb5_ldk_policy_does_not_enable_subsidy() {
        let mut disabled = test_subsidy();
        disabled.enabled = false;
        for subsidy in [SubsidyConfig::default(), disabled] {
            let peer = NodeId::from_bytes([1; 32]);
            let storage = storage_with_invite(peer, 5, Some(10_000), now_unix() + 60).await;
            // A funding quote or open would panic: no LDK is installed. Even a
            // fully provisioned policy with only enabled=false must be inert.
            let lightning = Arc::new(TestLightning {
                balance_msat: 100_000_000,
                ..Default::default()
            });
            let notifier = Arc::new(RecordingNotifier::default());
            let (s, l, c, n) = deps(storage.clone(), lightning.clone(), 1.0, notifier.clone());
            handle_peer_lightning_info(
                peer,
                LN_PUBKEY.into(),
                Some("127.0.0.1:9735".into()),
                s,
                l,
                c,
                n,
                subsidy,
                Some(FundingPriority::Fast),
            )
            .await
            .unwrap();
            assert!(lightning.opens.lock().await.is_empty());
            assert_eq!(
                storage.list_invites_issued().await.unwrap()[0].state,
                InviteState::Pending
            );
            assert!(notifier.notices.lock().await.is_empty());
        }
    }

    #[tokio::test]
    async fn channel_fee_operator_cap_and_rounded_quote_are_enforced() {
        for (quote, operator_cap, invite_cap, expected_rate) in [
            (5.0, 4, 50, None),
            (5.0, 0, 50, None),
            (4.01, 4, 50, None),
            (4.0, 4, 50, Some(4.0)),
            (5.0, 50, 4, None),
            (4.0, 50, 4, Some(4.0)),
            (3.1, 4, 50, Some(4.0)),
        ] {
            let peer = NodeId::from_bytes([1; 32]);
            let storage =
                storage_with_invite(peer, invite_cap, Some(10_000), now_unix() + 60).await;
            let lightning = Arc::new(TestLightning {
                balance_msat: 100_000_000,
                ..Default::default()
            });
            let notifier = Arc::new(RecordingNotifier::default());
            let mut policy = serde_json::to_value(test_subsidy()).unwrap();
            policy["max_funding_fee_rate_sat_per_vb"] = operator_cap.into();
            let subsidy = serde_json::from_value(policy).unwrap();
            let (s, l, c, n) = deps(storage.clone(), lightning.clone(), quote, notifier.clone());
            handle_peer_lightning_info(
                peer,
                LN_PUBKEY.into(),
                Some("127.0.0.1:9735".into()),
                s,
                l,
                c,
                n,
                subsidy,
                None,
            )
            .await
            .unwrap();
            let opens = lightning.opens.lock().await;
            match expected_rate {
                Some(rate) => {
                    assert_eq!(opens.len(), 1);
                    assert_eq!(opens[0].3, Some(rate));
                    assert!(!opens[0].4);
                }
                None => {
                    assert!(
                        opens.is_empty(),
                        "quote {quote}, operator cap {operator_cap}, invite cap {invite_cap}"
                    );
                    assert_eq!(
                        storage.list_invites_issued().await.unwrap()[0].state,
                        InviteState::Pending
                    );
                    assert_eq!(notifier.notices.lock().await[0].status, "aborted");
                }
            }
        }
    }

    #[tokio::test]
    async fn channel_fee_unsupported_backend_leaves_invite_pending_without_open() {
        let peer = NodeId::from_bytes([1; 32]);
        let storage = storage_with_invite(peer, 50, Some(10_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            reject_fee_requests: true,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (s, l, c, n) = deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());
        let err = handle_peer_lightning_info(
            peer,
            LN_PUBKEY.into(),
            Some("127.0.0.1:9735".into()),
            s,
            l,
            c,
            n,
            test_subsidy(),
            None,
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            AutoChannelError::Lightning(LightningError::PaymentNotDispatched(_))
        ));
        assert!(lightning.opens.lock().await.is_empty());
        assert_eq!(
            storage.list_invites_issued().await.unwrap()[0].state,
            InviteState::Pending
        );
        assert!(notifier
            .notices
            .lock()
            .await
            .iter()
            .all(|n| n.status != "opened"));
    }

    #[tokio::test]
    async fn channel_fee_invalid_estimates_fail_closed() {
        for fee_rate in [
            f64::NAN,
            f64::INFINITY,
            0.0,
            -1.0,
            10_000.1,
            u32::MAX as f64,
        ] {
            assert!(estimate_fee_rate_sat_per_vb(&TestChain { fee_rate })
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn fee_guard_aborts() {
        let peer = NodeId::from_bytes([1u8; 32]);
        let storage = storage_with_invite(peer, 10, Some(10_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 25.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            test_subsidy(),
            None,
        )
        .await
        .unwrap();

        assert!(lightning.opens.lock().await.is_empty());
        let notices = notifier.notices.lock().await;
        assert_eq!(notices[0].status, "aborted");
        assert!(notices[0]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("fee_too_high"));
    }

    #[tokio::test]
    async fn expiry_guard_aborts_and_marks_expired() {
        let peer = NodeId::from_bytes([2u8; 32]);
        let storage =
            storage_with_invite(peer, 50, Some(10_000), now_unix().saturating_sub(1)).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            test_subsidy(),
            None,
        )
        .await
        .unwrap();

        assert!(lightning.opens.lock().await.is_empty());
        let invite = storage.list_invites_issued().await.unwrap().remove(0);
        assert_eq!(invite.state, InviteState::Expired);
    }

    #[tokio::test]
    async fn balance_guard_aborts() {
        let peer = NodeId::from_bytes([3u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(50_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 1_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage, lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            test_subsidy(),
            None,
        )
        .await
        .unwrap();

        assert!(lightning.opens.lock().await.is_empty());
        assert!(notifier.notices.lock().await[0]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("insufficient_balance"));
    }

    #[tokio::test]
    async fn missing_lightning_addr_aborts() {
        let peer = NodeId::from_bytes([4u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(10_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage, lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            None,
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            test_subsidy(),
            None,
        )
        .await
        .unwrap();

        assert!(lightning.opens.lock().await.is_empty());
        assert_eq!(
            notifier.notices.lock().await[0].reason.as_deref(),
            Some("missing_lightning_addr")
        );
    }

    #[tokio::test]
    async fn happy_path_opens_channel_and_marks_accepted() {
        let peer = NodeId::from_bytes([5u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(10_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            test_subsidy(),
            None,
        )
        .await
        .unwrap();

        let opens = lightning.opens.lock().await;
        assert_eq!(opens.len(), 1);
        assert_eq!(opens[0].1, "127.0.0.1:9735");
        drop(opens);

        let invite = storage.list_invites_issued().await.unwrap().remove(0);
        assert_eq!(invite.state, InviteState::Accepted);
        assert_eq!(notifier.notices.lock().await[0].status, "opened");
    }

    #[tokio::test]
    async fn duplicate_event_does_not_open_second_channel() {
        let peer = NodeId::from_bytes([6u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(10_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());

        for _ in 0..2 {
            let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
                deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());
            handle_peer_lightning_info(
                peer,
                LN_PUBKEY.to_string(),
                Some("127.0.0.1:9735".to_string()),
                storage_dyn,
                lightning_dyn,
                chain_dyn,
                notifier_dyn,
                test_subsidy(),
                None,
            )
            .await
            .unwrap();
        }

        assert_eq!(lightning.opens.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn duplicate_event_during_open_does_not_open_second_channel() {
        let peer = NodeId::from_bytes([7u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(10_000), now_unix() + 60).await;
        let open_started = Arc::new(Notify::new());
        let release_open = Arc::new(Notify::new());
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            open_started: Some(open_started.clone()),
            release_open: Some(release_open.clone()),
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());

        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());
        let first = tokio::spawn(handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            test_subsidy(),
            None,
        ));

        open_started.notified().await;

        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());
        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            test_subsidy(),
            None,
        )
        .await
        .unwrap();

        assert_eq!(lightning.opens.lock().await.len(), 1);

        release_open.notify_waiters();
        first.await.unwrap().unwrap();

        assert_eq!(lightning.opens.lock().await.len(), 1);
        let invite = storage.list_invites_issued().await.unwrap().remove(0);
        assert_eq!(invite.state, InviteState::Accepted);
    }

    #[tokio::test]
    async fn subsidy_disabled_pending_invite_does_not_open_channel() {
        // THE R1-a kill: a Pending invite (membership) is present and the peer
        // would otherwise pass every downstream guard, yet a DISABLED subsidy
        // (the mesh-wide default) spends nothing and leaves the invite untouched.
        let peer = NodeId::from_bytes([11u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(10_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            SubsidyConfig::default(),
            None,
        )
        .await
        .unwrap();

        assert!(
            lightning.opens.lock().await.is_empty(),
            "disabled subsidy must not open a channel"
        );
        assert!(
            notifier.notices.lock().await.is_empty(),
            "disabled subsidy is a silent noop, not an abort"
        );
        let invite = storage.list_invites_issued().await.unwrap().remove(0);
        assert_eq!(
            invite.state,
            InviteState::Pending,
            "invite stays Pending — membership never touched"
        );
    }

    #[tokio::test]
    async fn peer_not_allowlisted_no_open() {
        // Subsidy enabled with generous caps, but the allowlist is empty → invite
        // membership is necessary-not-sufficient, so no spend occurs.
        let peer = NodeId::from_bytes([12u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(10_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            SubsidyConfig {
                enabled: true,
                max_channel_sats: 1_000_000,
                max_total_budget_sats: 100_000_000,
                max_funding_fee_rate_sat_per_vb: 50,
                per_peer_max_opens: 1,
                allowlist: Vec::new(),
            },
            None,
        )
        .await
        .unwrap();

        assert!(lightning.opens.lock().await.is_empty());
        let invite = storage.list_invites_issued().await.unwrap().remove(0);
        assert_eq!(invite.state, InviteState::Pending);
    }

    #[tokio::test]
    async fn amount_clamped_to_operator_max() {
        // Invitee asks for 500k; the operator cap is 50k → the channel opens for
        // exactly 50k. The operator, not the invitee, sizes the spend.
        let peer = NodeId::from_bytes([13u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(500_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 1_000_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            SubsidyConfig {
                enabled: true,
                max_channel_sats: 50_000,
                max_total_budget_sats: 100_000_000,
                max_funding_fee_rate_sat_per_vb: 50,
                per_peer_max_opens: 1,
                allowlist: vec![hex::encode(peer.as_bytes())],
            },
            None,
        )
        .await
        .unwrap();

        let opens = lightning.opens.lock().await;
        assert_eq!(opens.len(), 1);
        assert_eq!(
            opens[0].2, 50_000,
            "channel amount must be clamped to the operator max, not the invitee hint"
        );
    }

    #[tokio::test]
    async fn budget_cap_blocks() {
        // The single open (50k) exceeds the aggregate budget (10k) → aborted.
        let peer = NodeId::from_bytes([14u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(50_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 1_000_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            SubsidyConfig {
                enabled: true,
                max_channel_sats: 50_000,
                max_total_budget_sats: 10_000,
                max_funding_fee_rate_sat_per_vb: 50,
                per_peer_max_opens: 1,
                allowlist: vec![hex::encode(peer.as_bytes())],
            },
            None,
        )
        .await
        .unwrap();

        assert!(lightning.opens.lock().await.is_empty());
        assert!(notifier.notices.lock().await[0]
            .reason
            .as_deref()
            .unwrap()
            .starts_with("subsidy_budget_exhausted"));
    }

    #[tokio::test]
    async fn per_peer_cap_blocks() {
        // Peer already has one Accepted (consumed) open; per_peer_max_opens = 1,
        // so a fresh Pending invite for the same peer is refused.
        let peer = NodeId::from_bytes([15u8; 32]);
        let storage = Arc::new(SqliteStorage::in_memory().await.unwrap());
        storage
            .add_invite_issued(&InviteIssuedRecord {
                id: uuid::Uuid::new_v4(),
                invitee_pubkey: *peer.as_bytes(),
                expiry_unix: now_unix() + 7200,
                channel_size_hint_sats: Some(10_000),
                addr: "inviter.example:9736".to_string(),
                max_fee_rate_sat_per_vb: Some(50),
                channel_open_intent_expiry_unix: Some(now_unix() + 3600),
                nonce: [1u8; 16],
                state: InviteState::Accepted,
                created_at: 1,
                accepted_at: Some(2),
                revoked_at: None,
            })
            .await
            .unwrap();
        storage
            .add_invite_issued(&InviteIssuedRecord {
                id: uuid::Uuid::new_v4(),
                invitee_pubkey: *peer.as_bytes(),
                expiry_unix: now_unix() + 7200,
                channel_size_hint_sats: Some(10_000),
                addr: "inviter.example:9736".to_string(),
                max_fee_rate_sat_per_vb: Some(50),
                channel_open_intent_expiry_unix: Some(now_unix() + 3600),
                nonce: [2u8; 16],
                state: InviteState::Pending,
                created_at: 3,
                accepted_at: None,
                revoked_at: None,
            })
            .await
            .unwrap();

        let lightning = Arc::new(TestLightning {
            balance_msat: 1_000_000_000,
            ..Default::default()
        });
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            SubsidyConfig {
                enabled: true,
                max_channel_sats: 1_000_000,
                max_total_budget_sats: 100_000_000,
                max_funding_fee_rate_sat_per_vb: 50,
                per_peer_max_opens: 1,
                allowlist: vec![hex::encode(peer.as_bytes())],
            },
            None,
        )
        .await
        .unwrap();

        assert!(
            lightning.opens.lock().await.is_empty(),
            "per-peer cap must block a second subsidised open"
        );
        assert!(notifier.notices.lock().await.iter().any(|n| n
            .reason
            .as_deref()
            .map(|r| r.starts_with("subsidy_per_peer_cap"))
            .unwrap_or(false)));
    }

    #[tokio::test]
    async fn subsidy_already_open_idempotency_does_not_charge_budget() {
        // An already-open channel re-confirms the invite at ZERO cost and must NOT
        // be blocked by a tight budget — the budget counts only `Opening` spends
        // (the-fool phantom-spend fix).
        let peer = NodeId::from_bytes([16u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(50_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 100,
            ..Default::default()
        });
        *lightning.channels.lock().await = vec![ChannelInfo {
            is_outbound: None,
            is_announced: None,
            is_channel_ready: None,
            local_reserve_msat: None,
            initial_push_msat: None,
            user_channel_id: None,
            funding_txo: None,
            channel_id: "1".to_string(),
            peer_pubkey: LN_PUBKEY.to_string(),
            capacity_msat: 50_000_000,
            local_balance_msat: 25_000_000,
            outbound_capacity_msat: None,
            remote_balance_msat: 25_000_000,
            active: true,
            short_channel_id: Some("100x1x0".to_string()),
        }];
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_string(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            SubsidyConfig {
                enabled: true,
                max_channel_sats: 50_000,
                max_total_budget_sats: 1,
                max_funding_fee_rate_sat_per_vb: 50,
                per_peer_max_opens: 1,
                allowlist: vec![hex::encode(peer.as_bytes())],
            },
            None,
        )
        .await
        .unwrap();

        assert!(
            lightning.opens.lock().await.is_empty(),
            "already-open path must not open a NEW channel"
        );
        let notices = notifier.notices.lock().await;
        assert_eq!(notices[0].status, "opened");
        assert_eq!(notices[0].channel_id.as_deref(), Some("already_open"));
        drop(notices);
        let invite = storage.list_invites_issued().await.unwrap().remove(0);
        assert_eq!(invite.state, InviteState::Accepted);
    }

    #[tokio::test]
    async fn already_open_channel_matches_pubkey_regardless_of_hex_case() {
        // LDK stores the counterparty key in lowercase. A peer can advertise the
        // same key in uppercase. That must still count as the existing channel:
        // the balance here is enough to fund a second open, so a case-sensitive
        // miss would spend.
        let peer = NodeId::from_bytes([17u8; 32]);
        let storage = storage_with_invite(peer, 50, Some(50_000), now_unix() + 60).await;
        let lightning = Arc::new(TestLightning {
            balance_msat: 1_000_000_000,
            ..Default::default()
        });
        *lightning.channels.lock().await = vec![ChannelInfo {
            is_outbound: Some(true),
            is_announced: Some(false),
            is_channel_ready: Some(true),
            local_reserve_msat: None,
            initial_push_msat: None,
            user_channel_id: None,
            funding_txo: None,
            channel_id: "1".to_string(),
            peer_pubkey: LN_PUBKEY.to_string(),
            capacity_msat: 50_000_000,
            local_balance_msat: 25_000_000,
            remote_balance_msat: 25_000_000,
            active: true,
            short_channel_id: Some("100x1x0".to_string()),
            outbound_capacity_msat: None,
        }];
        let notifier = Arc::new(RecordingNotifier::default());
        let (storage_dyn, lightning_dyn, chain_dyn, notifier_dyn) =
            deps(storage.clone(), lightning.clone(), 5.0, notifier.clone());

        handle_peer_lightning_info(
            peer,
            LN_PUBKEY.to_ascii_uppercase(),
            Some("127.0.0.1:9735".to_string()),
            storage_dyn,
            lightning_dyn,
            chain_dyn,
            notifier_dyn,
            SubsidyConfig {
                enabled: true,
                max_channel_sats: 50_000,
                max_total_budget_sats: 100_000_000,
                max_funding_fee_rate_sat_per_vb: 50,
                per_peer_max_opens: 1,
                allowlist: vec![hex::encode(peer.as_bytes())],
            },
            None,
        )
        .await
        .unwrap();

        assert!(
            lightning.opens.lock().await.is_empty(),
            "uppercase Lightning pubkey must not fund a second channel"
        );
        let notices = notifier.notices.lock().await;
        assert_eq!(notices[0].status, "opened");
        assert_eq!(notices[0].channel_id.as_deref(), Some("already_open"));
        drop(notices);
        let invite = storage.list_invites_issued().await.unwrap().remove(0);
        assert_eq!(invite.state, InviteState::Accepted);
    }

    #[tokio::test]
    async fn local_ui_notifier_emits_ws_status() {
        let (tx, mut rx) = tokio::sync::broadcast::channel(4);
        let notifier = super::super::notify::LocalUiNotifier::new(tx);
        let invite_id = uuid::Uuid::new_v4();
        notifier
            .notify(ChannelOpenNotice {
                invite_id,
                peer_id: NodeId::from_bytes([9u8; 32]),
                ln_pubkey: LN_PUBKEY.to_string(),
                amount_sats: 10_000,
                status: "aborted",
                reason: Some("fee_too_high:25>10".to_string()),
                channel_id: None,
            })
            .await
            .unwrap();

        let status = rx.recv().await.unwrap();
        assert_eq!(status.event_type, "channel_open_aborted");
        assert_eq!(status.message_id, invite_id.to_string());
        assert_eq!(status.status, "aborted");
        assert_eq!(status.reason.as_deref(), Some("fee_too_high:25>10"));
    }
}
