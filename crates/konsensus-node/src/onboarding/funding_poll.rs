use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;
use tracing::{info, warn};

use konsensus_api::state::WsDeliveryStatus;
use konsensus_core::traits::lightning::LightningProvider;
use konsensus_core::NodeId;
use konsensus_storage::{OnboardingStateRecord, Storage};

#[allow(dead_code)]
const POLL_INTERVAL: Duration = Duration::from_secs(10);

#[allow(dead_code)]
fn active_nodes() -> &'static Mutex<HashSet<String>> {
    static ACTIVE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashSet::new()))
}

#[allow(dead_code)]
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[allow(dead_code)]
pub async fn ensure_poll_task(
    node_id_hex: String,
    storage: Arc<dyn Storage>,
    lightning: Arc<dyn LightningProvider>,
    ws_delivery_tx: tokio::sync::broadcast::Sender<Arc<WsDeliveryStatus>>,
) {
    {
        let mut active = active_nodes().lock().await;
        if active.contains(&node_id_hex) {
            return;
        }
        active.insert(node_id_hex.clone());
    }

    tokio::spawn(async move {
        info!(node_id = %node_id_hex, "funding poll worker started");
        loop {
            match poll_once(storage.as_ref(), lightning.as_ref(), Some(&ws_delivery_tx)).await {
                Ok(done) => {
                    if done {
                        break;
                    }
                }
                Err(e) => warn!(node_id = %node_id_hex, error = %e, "funding poll tick failed"),
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }

        let mut active = active_nodes().lock().await;
        active.remove(&node_id_hex);
        info!(node_id = %node_id_hex, "funding poll worker stopped");
    });
}

#[allow(dead_code)]
pub async fn poll_once(
    storage: &dyn Storage,
    lightning: &dyn LightningProvider,
    ws_delivery_tx: Option<&tokio::sync::broadcast::Sender<Arc<WsDeliveryStatus>>>,
) -> Result<bool, konsensus_storage::StorageError> {
    let Some(mut state) = storage.get_onboarding_state().await? else {
        return Ok(true);
    };

    if state.current_step == "funding" {
        let required = state.funding_amount_sats_required.unwrap_or(0);
        if required == 0 {
            return Ok(true);
        }

        let balance_msat = match lightning.get_balance_msat().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "funding poll: wallet balance read failed");
                return Ok(false);
            }
        };

        let observed_sats = (balance_msat / 1000).min(u64::from(u32::MAX)) as u32;
        state.funding_amount_sats_received = observed_sats;
        state.last_poll_at = Some(now_unix());

        if observed_sats >= required {
            state.current_step = "funding-seen".to_string();
            state.funding_evidence = Some("wallet_balance_observed".to_string());
        }

        storage.upsert_onboarding_state(&state).await?;
        return Ok(state.current_step != "funding");
    }

    if state.current_step == "waiting_for_inviter_channel"
        || state.current_step == "channel_pending"
    {
        state.last_poll_at = Some(now_unix());
        let Some(inviter_ln_pubkey) = state.inviter_ln_pubkey.clone() else {
            storage.upsert_onboarding_state(&state).await?;
            return Ok(false);
        };
        let channels = match lightning.list_channels().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "onboarding channel poll: list_channels failed");
                return Ok(false);
            }
        };

        let matching_inviter_channels = channels
            .iter()
            .filter(|channel| channel.peer_pubkey.eq_ignore_ascii_case(&inviter_ln_pubkey));

        let mut saw_inviter_channel = false;
        let mut saw_active_inviter_channel = false;
        for channel in matching_inviter_channels {
            saw_inviter_channel = true;
            if channel.active {
                saw_active_inviter_channel = true;
                break;
            }
        }

        let next = if saw_active_inviter_channel {
            "channel_ready"
        } else if saw_inviter_channel {
            "channel_pending"
        } else {
            "waiting_for_inviter_channel"
        };

        if next != state.current_step {
            state.current_step = next.to_string();
            storage.upsert_onboarding_state(&state).await?;
            emit_progress(ws_delivery_tx, next, progress_text(next));
            return Ok(next == "channel_ready");
        }

        storage.upsert_onboarding_state(&state).await?;
        return Ok(false);
    }

    Ok(true)
}

pub async fn emit_progress_step(
    storage: &dyn Storage,
    ws_delivery_tx: &tokio::sync::broadcast::Sender<Arc<WsDeliveryStatus>>,
    peer_id: &NodeId,
    step: &str,
    text: &str,
) -> Result<(), konsensus_storage::StorageError> {
    let Some(mut state) = storage.get_onboarding_state().await? else {
        return Ok(());
    };
    if !state_matches_inviter(&state, peer_id)
        || !step_allows_onboarding_progress(&state.current_step)
    {
        return Ok(());
    }
    if state.current_step != step {
        state.current_step = step.to_string();
        state.last_poll_at = Some(now_unix());
        storage.upsert_onboarding_state(&state).await?;
    }
    emit_progress(Some(ws_delivery_tx), step, text);
    Ok(())
}

pub async fn record_inviter_lightning_info(
    storage: &dyn Storage,
    ws_delivery_tx: &tokio::sync::broadcast::Sender<Arc<WsDeliveryStatus>>,
    peer_id: &NodeId,
    ln_pubkey: &str,
) -> Result<bool, konsensus_storage::StorageError> {
    let Some(mut state) = storage.get_onboarding_state().await? else {
        return Ok(false);
    };
    if !state_matches_inviter(&state, peer_id)
        || !step_allows_onboarding_progress(&state.current_step)
    {
        return Ok(false);
    }
    state.inviter_ln_pubkey = Some(ln_pubkey.to_string());
    state.current_step = "waiting_for_inviter_channel".to_string();
    state.last_poll_at = Some(now_unix());
    storage.upsert_onboarding_state(&state).await?;
    emit_progress(
        Some(ws_delivery_tx),
        "waiting_for_inviter_channel",
        progress_text("waiting_for_inviter_channel"),
    );
    Ok(true)
}

fn state_matches_inviter(state: &OnboardingStateRecord, peer_id: &NodeId) -> bool {
    state
        .inviter_pubkey
        .as_ref()
        .is_some_and(|inviter| inviter.as_slice() == peer_id.as_bytes())
}

fn step_allows_onboarding_progress(step: &str) -> bool {
    matches!(
        step,
        "connecting"
            | "noise_connected"
            | "lightning_info_sent"
            | "waiting_for_inviter_channel"
            | "channel_pending"
            | "funding-seen"
    )
}

fn emit_progress(
    ws_delivery_tx: Option<&tokio::sync::broadcast::Sender<Arc<WsDeliveryStatus>>>,
    step: &str,
    text: &str,
) {
    let Some(tx) = ws_delivery_tx else {
        return;
    };
    let _ = tx.send(Arc::new(WsDeliveryStatus {
        event_type: "onboarding_progress",
        message_id: "onboarding".to_string(),
        status: step.to_string(),
        reason: Some(text.to_string()),
    }));
}

fn progress_text(step: &str) -> &'static str {
    match step {
        "noise_connected" => "Secure transport connected",
        "lightning_info_sent" => "Lightning details shared",
        "waiting_for_inviter_channel" => "Waiting for inviter channel",
        "channel_pending" => "Channel opening is pending",
        "channel_ready" => "Channel is ready",
        "channel_failed" => "Channel opening failed",
        _ => "Onboarding progress updated",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use konsensus_core::traits::lightning::{
        ChannelInfo, Invoice, LightningError, LightningProvider, PaymentDetails,
    };
    use konsensus_storage::OnboardingStateRecord;

    struct TestLightning {
        balance_msat: u64,
        channels: Vec<ChannelInfo>,
    }

    #[async_trait::async_trait]
    impl LightningProvider for TestLightning {
        async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }
        async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }
        async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
            Err(LightningError::Backend("unused".into()))
        }
        async fn get_balance_msat(&self) -> Result<u64, LightningError> {
            Ok(self.balance_msat)
        }
        async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
            Ok(self.channels.clone())
        }
        async fn is_available(&self) -> bool {
            true
        }
    }

    fn state_for_step(step: &str) -> OnboardingStateRecord {
        OnboardingStateRecord {
            invite_id: None,
            inviter_pubkey: Some([0x42; 32]),
            inviter_ln_pubkey: None,
            current_step: step.into(),
            tier: Some("light".into()),
            funding_address: None,
            funding_amount_sats_required: None,
            funding_amount_sats_received: 0,
            last_poll_at: None,
            funding_evidence: None,
        }
    }

    fn channel(peer_pubkey: &str, active: bool) -> ChannelInfo {
        ChannelInfo {
            peer_pubkey: peer_pubkey.to_string(),
            capacity_msat: 50_000_000,
            local_balance_msat: 50_000_000,
            remote_balance_msat: 0,
            active,
            short_channel_id: None,
        }
    }

    #[tokio::test]
    async fn funding_poll_marks_funding_seen() {
        let storage = konsensus_storage::SqliteStorage::in_memory().await.unwrap();
        storage
            .upsert_onboarding_state(&OnboardingStateRecord {
                invite_id: None,
                inviter_pubkey: None,
                inviter_ln_pubkey: None,
                current_step: "funding".into(),
                tier: Some("full".into()),
                funding_address: Some("bcrt1qtest".into()),
                funding_amount_sats_required: Some(50_000),
                funding_amount_sats_received: 0,
                last_poll_at: None,
                funding_evidence: None,
            })
            .await
            .unwrap();

        let done = poll_once(
            &storage,
            &TestLightning {
                balance_msat: 50_000_000,
                channels: vec![],
            },
            None,
        )
        .await
        .unwrap();
        assert!(done);

        let state = storage.get_onboarding_state().await.unwrap().unwrap();
        assert_eq!(state.current_step, "funding-seen");
        assert_eq!(
            state.funding_evidence.as_deref(),
            Some("wallet_balance_observed")
        );
        assert_eq!(state.funding_amount_sats_received, 50_000);
        assert!(state.last_poll_at.is_some());
    }

    #[tokio::test]
    async fn progress_step_ignores_unrelated_peer_and_terminal_state() {
        let storage = konsensus_storage::SqliteStorage::in_memory().await.unwrap();
        let (ws_tx, mut ws_rx) = tokio::sync::broadcast::channel::<Arc<WsDeliveryStatus>>(8);

        storage
            .upsert_onboarding_state(&state_for_step("complete"))
            .await
            .unwrap();
        emit_progress_step(
            &storage,
            &ws_tx,
            &NodeId::from_bytes([0x42; 32]),
            "noise_connected",
            "Secure transport connected",
        )
        .await
        .unwrap();
        assert!(ws_rx.try_recv().is_err());
        assert_eq!(
            storage
                .get_onboarding_state()
                .await
                .unwrap()
                .unwrap()
                .current_step,
            "complete"
        );

        storage
            .upsert_onboarding_state(&state_for_step("connecting"))
            .await
            .unwrap();
        emit_progress_step(
            &storage,
            &ws_tx,
            &NodeId::from_bytes([0x99; 32]),
            "noise_connected",
            "Secure transport connected",
        )
        .await
        .unwrap();
        assert!(ws_rx.try_recv().is_err());
        assert_eq!(
            storage
                .get_onboarding_state()
                .await
                .unwrap()
                .unwrap()
                .current_step,
            "connecting"
        );
    }

    #[tokio::test]
    async fn channel_poll_requires_inviter_lightning_channel() {
        let storage = konsensus_storage::SqliteStorage::in_memory().await.unwrap();
        let inviter_ln = format!("02{:064}", 1);
        let other_ln = format!("02{:064}", 2);
        let mut state = state_for_step("waiting_for_inviter_channel");
        state.inviter_ln_pubkey = Some(inviter_ln.clone());
        storage.upsert_onboarding_state(&state).await.unwrap();

        let done = poll_once(
            &storage,
            &TestLightning {
                balance_msat: 0,
                channels: vec![channel(&other_ln, true)],
            },
            None,
        )
        .await
        .unwrap();
        assert!(!done);
        assert_eq!(
            storage
                .get_onboarding_state()
                .await
                .unwrap()
                .unwrap()
                .current_step,
            "waiting_for_inviter_channel"
        );

        let done = poll_once(
            &storage,
            &TestLightning {
                balance_msat: 0,
                channels: vec![channel(&inviter_ln, true)],
            },
            None,
        )
        .await
        .unwrap();
        assert!(done);
        assert_eq!(
            storage
                .get_onboarding_state()
                .await
                .unwrap()
                .unwrap()
                .current_step,
            "channel_ready"
        );
    }
}
