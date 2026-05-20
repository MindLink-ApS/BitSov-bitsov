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
use konsensus_core::traits::lightning::{ChannelInfo, LightningError, LightningProvider};
use konsensus_core::types::NodeId;
use konsensus_storage::{InviteIssuedRecord, Storage, StorageError};

use super::notify::{ChannelOpenNotice, NotificationSink};

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
) -> Result<(), AutoChannelError> {
    match event {
        AutoChannelEvent::PeerLightningInfo {
            peer_id,
            ln_pubkey,
            ln_addr,
        } => {
            handle_peer_lightning_info(
                peer_id, ln_pubkey, ln_addr, storage, lightning, chain, notifier,
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
) -> Result<(), AutoChannelError> {
    let Some(invite) = storage
        .find_pending_invite_for_invitee(peer_id.as_bytes())
        .await?
    else {
        debug!(peer = %peer_id, "no pending issued invite for peer; auto-channel noop");
        return Ok(());
    };

    let amount_sats = u64::from(
        invite
            .channel_size_hint_sats
            .unwrap_or(DEFAULT_CHANNEL_SIZE_SATS as u32),
    );
    let max_fee_rate = invite
        .max_fee_rate_sat_per_vb
        .unwrap_or(DEFAULT_MAX_FEE_RATE_SAT_PER_VB);

    let current_fee_rate = estimate_fee_rate_sat_per_vb(chain.as_ref()).await?;
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

    let channel_id = match lightning
        .open_channel(
            &ln_pubkey,
            &ln_addr,
            amount_sats,
            false,
            Some(current_fee_rate as f32),
        )
        .await
    {
        Ok(channel_id) => channel_id,
        Err(e) => {
            let _ = storage.mark_invite_pending(&invite.id).await?;
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
    let fee = estimate.sat_per_vbyte.ceil();
    if !fee.is_finite() || fee <= 0.0 {
        return Err(AutoChannelError::Chain(
            konsensus_core::traits::chain::ChainError::FeeEstimationFailed(format!(
                "non-positive fee estimate: {}",
                estimate.sat_per_vbyte
            )),
        ));
    }
    Ok(fee.min(u32::MAX as f64) as u32)
}

fn funding_fee_buffer_sats(max_fee_rate_sat_per_vb: u32) -> u64 {
    u64::from(max_fee_rate_sat_per_vb).saturating_mul(FUNDING_TX_VBYTES_ESTIMATE)
}

async fn existing_channel_to_peer(
    lightning: &dyn LightningProvider,
    ln_pubkey: &str,
) -> Result<bool, LightningError> {
    let channels: Vec<ChannelInfo> = lightning.list_channels().await?;
    Ok(channels
        .iter()
        .any(|channel| channel.peer_pubkey == ln_pubkey && channel.active))
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
        Invoice, PaymentDetails, PaymentDirection, PaymentStatus,
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

    #[derive(Default)]
    struct TestLightning {
        balance_msat: u64,
        channels: Mutex<Vec<ChannelInfo>>,
        opens: Mutex<Vec<(String, String, u64, Option<f32>)>>,
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
            _announce: bool,
            fee_rate_sat_per_vb: Option<f32>,
        ) -> Result<String, LightningError> {
            self.opens.lock().await.push((
                peer_pubkey.to_string(),
                peer_addr.to_string(),
                amount_sats,
                fee_rate_sat_per_vb,
            ));
            if let Some(open_started) = &self.open_started {
                open_started.notify_waiters();
            }
            if let Some(release_open) = &self.release_open {
                release_open.notified().await;
            }
            Ok("temp-channel-id".to_string())
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

    fn deps(
        storage: Arc<dyn Storage>,
        lightning: Arc<TestLightning>,
        fee_rate: f64,
        notifier: Arc<RecordingNotifier>,
    ) -> (
        Arc<dyn Storage>,
        Arc<dyn LightningProvider>,
        Arc<dyn ChainProvider>,
        Arc<dyn NotificationSink>,
    ) {
        (
            storage,
            lightning,
            Arc::new(TestChain { fee_rate }),
            notifier,
        )
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
        )
        .await
        .unwrap();

        assert!(lightning.opens.lock().await.is_empty());
        let notices = notifier.notices.lock().await;
        assert_eq!(notices[0].status, "aborted");
        assert!(
            notices[0]
                .reason
                .as_deref()
                .unwrap()
                .starts_with("fee_too_high")
        );
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
        )
        .await
        .unwrap();

        assert!(lightning.opens.lock().await.is_empty());
        assert!(
            notifier.notices.lock().await[0]
                .reason
                .as_deref()
                .unwrap()
                .starts_with("insufficient_balance")
        );
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
