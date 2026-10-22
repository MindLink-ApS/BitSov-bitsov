//! Durable on-chain send receipts. Recovery only reads; it never dispatches.
//!
//! Reuse the existing encrypted channel-open operation store. Its pending-only
//! CAS and opaque request/result blobs fit sends without a migration. Prefixes
//! isolate these rows from channel-open UUIDs and their channel reconciliation.
//! `opened` means a returned txid here; `uncertain` holds ambiguous outcomes.
use super::SendOnchainRequest;
use crate::{error::ApiError, state::AppState};
use axum::{http::StatusCode, Json};
use konsensus_core::fee_rate::validate_fee_rate_sat_per_vb;
use konsensus_storage::{
    channel_open::{CHANNEL_OPEN_OPENED, CHANNEL_OPEN_UNCERTAIN},
    ChannelOpenOperation,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

type Response = Result<(StatusCode, Json<Value>), ApiError>;

#[derive(Serialize, Deserialize)]
enum Receipt {
    Returned { status: u16, body: Value },
    NotDispatched(String),
    NotReady,
}

impl Receipt {
    fn response(self) -> Response {
        match self {
            Self::Returned { status, body } => {
                Ok((StatusCode::from_u16(status).map_err(storage)?, Json(body)))
            }
            Self::NotDispatched(reason) => Err(ApiError::NotDispatched(reason)),
            Self::NotReady => Err(ApiError::NotReady),
        }
    }
}

fn storage(error: impl std::fmt::Display) -> ApiError {
    tracing::warn!(%error, "on-chain operation storage failure");
    ApiError::Storage("on-chain operation unavailable".into())
}

fn unresolved(id: &str, uncertain: bool) -> Response {
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "request_id": id,
            "status": if uncertain { "outcome_uncertain" } else { "pending" },
            "message": "The send is in flight or its outcome was not recorded. Retries will not dispatch while this operation remains pending or uncertain. Inspect the wallet and chain before considering a new request_id; a missing receipt does not prove non-dispatch.",
        })),
    ))
}

fn replay(op: ChannelOpenOperation, id: &str, hash: &str) -> Response {
    if op.request_hash != hash {
        return Err(ApiError::OperationConflict("operation_mismatch"));
    }
    if let Some(bytes) = op.result {
        return serde_json::from_slice::<Receipt>(&bytes)
            .map_err(storage)?
            .response();
    }
    // No provider method correlates an on-chain send with a client UUID. Never
    // infer non-dispatch from a crash, elapsed time, an address or an amount.
    // Leave pending rows intact: another process may still be recording a txid.
    unresolved(id, op.state == CHANNEL_OPEN_UNCERTAIN)
}

pub(super) async fn send(state: Arc<AppState>, req: SendOnchainRequest) -> Response {
    if req.request_id.is_none() {
        tracing::warn!("send-onchain without request_id: legacy request has no retry protection");
        validate(&state, &req).await?;
        return dispatch(&state, &req).await;
    }
    // A dropped HTTP future detaches this task. The insert, backend call and
    // receipt write must survive together, including blocking wallet work.
    tokio::spawn(run(state, req)).await.map_err(|error| {
        tracing::error!(%error, "on-chain send task failed");
        ApiError::Internal("on-chain send task failed".into())
    })?
}

async fn run(state: Arc<AppState>, req: SendOnchainRequest) -> Response {
    let id = uuid::Uuid::parse_str(req.request_id.as_deref().unwrap_or_default())
        .map_err(|_| ApiError::BadRequest("request_id must be a UUIDv4".into()))?;
    if id.get_version_num() != 4 || id.get_variant() != uuid::Variant::RFC4122 {
        return Err(ApiError::BadRequest("request_id must be a UUIDv4".into()));
    }
    let id = id.to_string();
    let key = format!("send-onchain:{id}");
    let request = serde_json::to_vec(&json!({
        "address": req.address,
        "amount_sats": req.amount_sats,
        "fee_rate_sat_per_vb_bits": req.fee_rate_sat_per_vb.map(f32::to_bits),
    }))
    .map_err(storage)?;
    let hash = hex::encode(Sha256::digest(&request));
    // Saved receipts remain readable even while the wallet is not money-ready.
    if let Some(op) = state
        .storage
        .get_channel_open_operation(&key)
        .await
        .map_err(storage)?
    {
        return replay(op, &id, &hash);
    }
    validate(&state, &req).await?;
    let pending = ChannelOpenOperation::pending(key.clone(), hash.clone(), request);
    if !state
        .storage
        .insert_channel_open_operation(&pending)
        .await
        .map_err(storage)?
    {
        let op = state
            .storage
            .get_channel_open_operation(&key)
            .await
            .map_err(storage)?
            .ok_or_else(|| storage("missing operation after duplicate insert"))?;
        return replay(op, &id, &hash);
    }
    // Only the durable insert winner reaches the money-moving call. Only its
    // proven pre-dispatch refusal can release the binding.
    let mut last_error = None;
    let (outcome, receipt) = match dispatch(&state, &req).await {
        Ok((status, Json(mut body))) => {
            body["request_id"] = id.clone().into();
            (
                CHANNEL_OPEN_OPENED,
                Some(Receipt::Returned {
                    status: status.as_u16(),
                    body,
                }),
            )
        }
        Err(error @ (ApiError::NotDispatched(_) | ApiError::NotReady)) => {
            // Do not retry deletion: after an ambiguous DB acknowledgement,
            // another request could already own a new pending row under this id.
            if let Err(storage) = state
                .storage
                .delete_pending_channel_open_operation(&key)
                .await
            {
                tracing::warn!(request_id = %id, %storage, "on-chain refusal not released");
            }
            return Err(error);
        }
        Err(error) => {
            tracing::warn!(request_id = %id, %error, "on-chain send outcome uncertain; retry will not dispatch");
            // Preserve diagnostic evidence, including any txid carried in a
            // Backend error, without interpreting free text as dispatch proof.
            last_error = Some(error.to_string());
            (CHANNEL_OPEN_UNCERTAIN, None)
        }
    };
    let bytes = receipt
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(storage)?;
    if !record_outcome(
        &state,
        &key,
        outcome,
        bytes.as_deref(),
        last_error.as_deref(),
    )
    .await
    {
        // Keep the known wallet response even if its receipt cannot be saved.
        // Retry persistence independently of the HTTP lifetime; never dispatch.
        tokio::spawn(async move {
            for delay_ms in [100, 500, 1_000, 5_000, 30_000] {
                tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                if record_outcome(
                    &state,
                    &key,
                    outcome,
                    bytes.as_deref(),
                    last_error.as_deref(),
                )
                .await
                {
                    return;
                }
            }
            tracing::error!(operation_id = %key, "on-chain outcome persistence retries exhausted; inspect wallet before any new send");
        });
    }
    match receipt {
        Some(receipt) => receipt.response(),
        None => unresolved(&id, true),
    }
}

// True means no further write is needed. A lost CAS must never overwrite a
// terminal receipt. Only storage errors warrant retrying this pending-only CAS.
async fn record_outcome(
    state: &AppState,
    key: &str,
    outcome: &str,
    bytes: Option<&[u8]>,
    last_error: Option<&str>,
) -> bool {
    match state
        .storage
        .resolve_channel_open_operation(key, outcome, bytes, last_error)
        .await
    {
        Ok(true) => true,
        Ok(false) => {
            tracing::warn!(operation_id = %key, "on-chain pending operation changed before outcome recording");
            true
        }
        Err(error) => {
            tracing::warn!(operation_id = %key, %error, "on-chain outcome not recorded; retrying persistence");
            false
        }
    }
}

async fn validate(state: &AppState, req: &SendOnchainRequest) -> Result<(), ApiError> {
    crate::error::require_money_ready(state).await?;
    if let Some(rate) = req.fee_rate_sat_per_vb {
        validate_fee_rate_sat_per_vb(rate).map_err(|e| ApiError::NotDispatched(e.to_string()))?;
    }
    Ok(())
}

async fn dispatch(state: &AppState, req: &SendOnchainRequest) -> Response {
    // L0f: distinguish between "broadcast confirmed visible" (HTTP 200) and
    // "broadcast initiated, but the chain provider couldn't confirm
    // visibility within the verification timeout" (HTTP 202 Accepted with
    // the txid). The 202 path lets the client poll for confirmation
    // rather than treating the silent-fail as success — covers the
    // documented 2026-04-23 ba91a6ac…45ef incident class.
    match state
        .lightning
        .send_onchain(&req.address, req.amount_sats, req.fee_rate_sat_per_vb)
        .await
    {
        Ok(txid) => Ok((
            StatusCode::OK,
            Json(serde_json::json!({
                "txid": txid,
                "address": req.address,
                "amount_sats": req.amount_sats,
                "broadcast_status": "confirmed_visible",
            })),
        )),
        Err(konsensus_core::traits::lightning::LightningError::BroadcastUnconfirmed { txid }) => {
            Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({
                    "txid": txid,
                    "address": req.address,
                    "amount_sats": req.amount_sats,
                    "broadcast_status": "unconfirmed",
                    "message": "Backend returned a txid but the chain provider could not verify mempool visibility within 10s. Poll mempool.space or call /tx/<txid> to confirm; the tx may still propagate.",
                })),
            ))
        }
        Err(e) => Err(ApiError::from(e)),
    }
}
