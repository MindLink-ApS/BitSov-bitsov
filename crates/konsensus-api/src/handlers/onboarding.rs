use std::collections::HashSet;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use tracing::warn;

use konsensus_storage::OnboardingStateRecord;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

const FUNDING_EVIDENCE_WALLET_BALANCE_OBSERVED: &str = "wallet_balance_observed";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartOnboardingRequest {
    pub tier: String,
    #[serde(default)]
    pub funding_amount_sats: Option<u32>,
    #[serde(default)]
    pub invite_id: Option<uuid::Uuid>,
    #[serde(default)]
    pub inviter_pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct OnboardingStateResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inviter_ln_pubkey: Option<String>,
    pub current_step: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funding_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funding_amount_sats_required: Option<u32>,
    pub funding_amount_sats_received: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_poll_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funding_evidence: Option<String>,
}

fn active_nodes() -> &'static Mutex<HashSet<String>> {
    static ACTIVE: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(HashSet::new()))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn map_state(record: OnboardingStateRecord) -> OnboardingStateResponse {
    OnboardingStateResponse {
        invite_id: record.invite_id,
        inviter_pubkey: record.inviter_pubkey.map(hex::encode),
        inviter_ln_pubkey: record.inviter_ln_pubkey,
        current_step: record.current_step,
        tier: record.tier,
        funding_address: record.funding_address,
        funding_amount_sats_required: record.funding_amount_sats_required,
        funding_amount_sats_received: record.funding_amount_sats_received,
        last_poll_at: record.last_poll_at,
        funding_evidence: record.funding_evidence,
    }
}

fn parse_optional_pubkey_hex(value: Option<String>, field: &str) -> Result<Option<[u8; 32]>, ApiError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bytes = hex::decode(&value)
        .map_err(|e| ApiError::BadRequest(format!("invalid {field} hex: {e}")))?;
    let pubkey = bytes
        .try_into()
        .map_err(|_| ApiError::BadRequest(format!("{field} must be 32 bytes")))?;
    Ok(Some(pubkey))
}

async fn spawn_funding_poll_if_needed(state: Arc<AppState>) {
    let node_id = state.identity.node_id().to_hex();
    {
        let mut active = active_nodes().lock().await;
        if active.contains(&node_id) {
            return;
        }
        active.insert(node_id.clone());
    }

    tokio::spawn(async move {
        loop {
            let Some(mut onboarding_state) = state.storage.get_onboarding_state().await.ok().flatten() else {
                break;
            };
            if onboarding_state.current_step != "funding" {
                break;
            }

            let required = onboarding_state.funding_amount_sats_required.unwrap_or(0);
            if required == 0 {
                break;
            }

            match state.lightning.get_balance_msat().await {
                Ok(balance_msat) => {
                    onboarding_state.funding_amount_sats_received = (balance_msat / 1000).min(u64::from(u32::MAX)) as u32;
                    onboarding_state.last_poll_at = Some(now_unix());
                    if onboarding_state.funding_amount_sats_received >= required {
                        onboarding_state.current_step = "funding-seen".to_string();
                        onboarding_state.funding_evidence = Some(FUNDING_EVIDENCE_WALLET_BALANCE_OBSERVED.to_string());
                    }
                    if let Err(e) = state.storage.upsert_onboarding_state(&onboarding_state).await {
                        warn!(error=%e, "onboarding funding poll write failed");
                    }
                }
                Err(e) => warn!(error=%e, "onboarding funding poll read failed"),
            }

            tokio::time::sleep(Duration::from_secs(10)).await;
        }

        let mut active = active_nodes().lock().await;
        active.remove(&node_id);
    });
}

async fn start_onboarding(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartOnboardingRequest>,
) -> Result<Json<OnboardingStateResponse>, ApiError> {
    let tier = req.tier.to_lowercase();
    let inviter_pubkey = parse_optional_pubkey_hex(req.inviter_pubkey, "inviter_pubkey")?;
    match tier.as_str() {
        "light" => {
            let record = OnboardingStateRecord {
                invite_id: req.invite_id,
                inviter_pubkey,
                inviter_ln_pubkey: None,
                current_step: "connecting".to_string(),
                tier: Some("light".to_string()),
                funding_address: None,
                funding_amount_sats_required: None,
                funding_amount_sats_received: 0,
                last_poll_at: None,
                funding_evidence: None,
            };
            state.storage.upsert_onboarding_state(&record).await.map_err(|e| ApiError::Storage(e.to_string()))?;
            Ok(Json(map_state(record)))
        }
        "full" => {
            let required = req
                .funding_amount_sats
                .ok_or_else(|| ApiError::BadRequest("funding_amount_sats required for full tier".into()))?;
            let funding_address = state
                .lightning
                .get_funding_address()
                .await
                .ok_or_else(|| ApiError::Lightning("lightning backend does not expose a funding address".into()))?;

            let record = OnboardingStateRecord {
                invite_id: req.invite_id,
                inviter_pubkey,
                inviter_ln_pubkey: None,
                current_step: "funding".to_string(),
                tier: Some("full".to_string()),
                funding_address: Some(funding_address),
                funding_amount_sats_required: Some(required),
                funding_amount_sats_received: 0,
                last_poll_at: None,
                funding_evidence: None,
            };
            state.storage.upsert_onboarding_state(&record).await.map_err(|e| ApiError::Storage(e.to_string()))?;
            spawn_funding_poll_if_needed(Arc::clone(&state)).await;
            Ok(Json(map_state(record)))
        }
        _ => Err(ApiError::BadRequest("tier must be 'light' or 'full'".into())),
    }
}

async fn onboarding_state(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<OnboardingStateResponse>, ApiError> {
    let record = state
        .storage
        .get_onboarding_state()
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound("onboarding state not initialized".into()))?;
    Ok(Json(map_state(record)))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/onboarding/start", post(start_onboarding))
        .route("/api/v1/onboarding/state", get(onboarding_state))
}
