//! Durable single-recipient compose operations. Recovery never dispatches money.
use super::compose::{ComposeRequest, ComposeResponse};
use crate::{
    error::ApiError,
    metered::{Debit, MeteredSpend},
    spend_budget::Reservation,
    state::AppState,
};
use axum::{
    extract::{Path, State},
    Json,
};
use konsensus_core::{
    traits::lightning::{LightningError, PaymentDetails, PaymentDirection, PaymentStatus},
    MessageId, NodeId, PaymentProof, UkmEnvelope,
};
use konsensus_storage::OutboxOperation;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};

#[derive(Clone, Default, Serialize, Deserialize)]
struct Recovery {
    caller: Option<String>,
    #[serde(default)]
    execution_id: Option<String>,
    #[serde(default)]
    budget_admission_msat: u64,
    draft: Option<UkmEnvelope>,
    #[serde(default)]
    envelope_ready: bool,
    dispatched: bool,
    expected_msat: u64,
    settlement: Option<PaymentDetails>,
    reservation: Option<Reservation>,
    fee_ceiling_msat: u64,
    admission_msat: u64,
    admission_fee_msat: Option<u64>,
    #[serde(default)]
    admission_pending: bool,
    #[serde(default)]
    admission_expected_msat: u64,
    #[serde(default)]
    admission_is_readmission: bool,
    #[serde(default)]
    admission_reservation: Option<Reservation>,
    #[serde(default)]
    resend_after_ms: i64,
    #[serde(default)]
    resend_delay_ms: u64,
}

fn storage(e: impl std::fmt::Display) -> ApiError {
    ApiError::Storage(format!("outbox operation: {e}"))
}
fn recovery(op: &OutboxOperation) -> Result<Recovery, ApiError> {
    if op.recovery.is_empty() && op.operation_id.starts_with("legacy:") {
        return Ok(Recovery::default());
    }
    serde_json::from_slice(&op.recovery).map_err(storage)
}
fn encode(op: &mut OutboxOperation, data: &Recovery) -> Result<(), ApiError> {
    op.recovery = serde_json::to_vec(data).map_err(storage)?;
    Ok(())
}
async fn save(state: &AppState, op: &mut OutboxOperation) -> Result<(), ApiError> {
    op.updated_at = chrono::Utc::now().timestamp_millis();
    if !state
        .storage
        .update_outbox_operation(op)
        .await
        .map_err(storage)?
    {
        return Err(ApiError::Conflict(
            "operation changed concurrently; read its current state".into(),
        ));
    }
    op.version += 1;
    Ok(())
}
fn caller(auth: &MeteredSpend) -> Option<String> {
    auth.user
        .pairing
        .as_ref()
        .map(|p| format!("{}:{}", p.client_id, p.epoch))
}
fn operation_id(id: Option<&str>) -> Result<String, ApiError> {
    let id = match id {
        Some(s) => uuid::Uuid::parse_str(s)
            .map_err(|_| ApiError::BadRequest("operation_id must be a UUIDv4".into()))?,
        None => uuid::Uuid::new_v4(),
    };
    if id.get_version_num() != 4 || id.get_variant() != uuid::Variant::RFC4122 {
        return Err(ApiError::BadRequest("operation_id must be a UUIDv4".into()));
    }
    Ok(id.to_string())
}
// Weak entries are pruned and the live map is bounded; no permanent UUID lock leak.
fn operation_lock(state: &AppState, id: &str) -> Result<Arc<tokio::sync::Mutex<()>>, ApiError> {
    type Locks = HashMap<String, Weak<tokio::sync::Mutex<()>>>;
    static LOCKS: OnceLock<Mutex<Locks>> = OnceLock::new();
    let key = format!("{}:{id}", state.identity.node_id());
    let mutex = {
        let mut locks = LOCKS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        locks.retain(|_, v| v.strong_count() > 0);
        if let Some(existing) = locks.get(&key).and_then(Weak::upgrade) {
            existing
        } else {
            if locks.len() >= 1024 {
                return Err(ApiError::TooManyRequests(
                    "too many active operations".into(),
                ));
            }
            let mutex = Arc::new(tokio::sync::Mutex::new(()));
            locks.insert(key, Arc::downgrade(&mutex));
            mutex
        }
    };
    Ok(mutex)
}
async fn lock(state: &AppState, id: &str) -> Result<tokio::sync::OwnedMutexGuard<()>, ApiError> {
    Ok(operation_lock(state, id)?.lock_owned().await)
}

/// Durable handle for one execution. Message and admission attempts keep separate identities.
#[derive(Clone)]
pub(crate) struct Operation {
    state: Arc<AppState>,
    pub(crate) id: String,
    execution_id: String,
}
impl Operation {
    async fn load(&self) -> Result<OutboxOperation, ApiError> {
        let op = self
            .state
            .storage
            .get_outbox_operation(&self.id)
            .await
            .map_err(storage)?
            .ok_or_else(|| storage("missing operation"))?;
        if recovery(&op)?.execution_id.as_deref() != Some(self.execution_id.as_str()) {
            return Err(ApiError::PaymentUnresolved(
                "operation execution was superseded; recovery owns its reservation".into(),
            ));
        }
        Ok(op)
    }
    pub(crate) async fn resend(&self) -> Result<bool, ApiError> {
        let op = self.load().await?;
        if op.state == "acked" {
            return Ok(true);
        }
        resend(&self.state, &op).await
    }
    pub(crate) async fn attach_debit(&self, debit: &Debit) -> Result<(), ApiError> {
        let mut op = self.load().await?;
        let mut data = recovery(&op)?;
        data.reservation = debit.reservation();
        data.budget_admission_msat = 0;
        data.admission_fee_msat = Some(0);
        encode(&mut op, &data)?;
        save(&self.state, &mut op).await
    }
    pub(crate) async fn admission_started(
        &self,
        hash: String,
        amount: u64,
        readmission: bool,
        debit: &Debit,
    ) -> Result<(), ApiError> {
        let mut op = self.load().await?;
        let mut data = recovery(&op)?;
        op.admission_payment_hash = Some(hash);
        data.admission_pending = true;
        data.admission_expected_msat = amount;
        data.admission_is_readmission = readmission;
        data.admission_reservation = debit.reservation();
        encode(&mut op, &data)?;
        save(&self.state, &mut op).await
    }
    pub(crate) async fn admission_not_dispatched(&self) -> Result<(), ApiError> {
        let mut op = self.load().await?;
        let mut data = recovery(&op)?;
        data.admission_pending = false;
        encode(&mut op, &data)?;
        save(&self.state, &mut op).await
    }
    pub(crate) async fn admission_settled(&self, details: &PaymentDetails) -> Result<(), ApiError> {
        let mut op = self.load().await?;
        let mut data = recovery(&op)?;
        if op.admission_payment_hash.as_deref() != Some(details.payment_hash.as_str())
            || details.amount_msat != data.admission_expected_msat
            || details.direction != PaymentDirection::Outgoing
            || details.status != PaymentStatus::Settled
        {
            return Err(ApiError::PaymentUnresolved(
                "admission operation identity mismatch".into(),
            ));
        }
        if data.admission_pending {
            if data.admission_is_readmission {
                op.readmission_msat = op
                    .readmission_msat
                    .saturating_add(details.amount_msat as i64);
            } else {
                data.admission_msat = data.admission_msat.saturating_add(details.amount_msat);
                data.budget_admission_msat = data
                    .budget_admission_msat
                    .saturating_add(details.amount_msat);
                data.admission_fee_msat = data
                    .admission_fee_msat
                    .and_then(|a| details.fee_msat.and_then(|b| a.checked_add(b)));
            }
        }
        data.admission_pending = false;
        encode(&mut op, &data)?;
        save(&self.state, &mut op).await
    }
    pub(crate) async fn draft(
        &self,
        draft: UkmEnvelope,
        expected_msat: u64,
        fee_ceiling: u64,
        admission_msat: u64,
        readmission_msat: u64,
    ) -> Result<(), ApiError> {
        let mut op = self.load().await?;
        let mut data = recovery(&op)?;
        op.message_id = Some(draft.id.to_hex());
        data.draft = Some(draft);
        data.expected_msat = expected_msat;
        data.fee_ceiling_msat = fee_ceiling;
        if data.admission_msat < admission_msat {
            data.admission_msat = admission_msat;
            data.budget_admission_msat = admission_msat;
            data.admission_fee_msat = None; // absent historical evidence is never a zero fee
        }
        op.readmission_msat = i64::try_from(readmission_msat).map_err(storage)?;
        if let Some(attempt) = super::admission_journal::load(
            &self.state,
            &NodeId::from_hex(&op.recipient).map_err(storage)?,
        )? {
            op.admission_payment_hash = Some(attempt.payment_hash);
        }
        encode(&mut op, &data)?;
        save(&self.state, &mut op).await
    }
    pub(crate) async fn dispatch<F>(
        &self,
        debit: &Debit,
        hash: Option<String>,
        amount: u64,
        future: F,
    ) -> Result<Result<PaymentDetails, LightningError>, ApiError>
    where
        F: std::future::Future<Output = Result<PaymentDetails, LightningError>>,
    {
        let mut op = self.load().await?;
        let mut data = recovery(&op)?;
        if data.dispatched {
            return Err(ApiError::PaymentUnresolved(
                "operation already dispatched".into(),
            ));
        }
        data.dispatched = true;
        data.expected_msat = amount;
        data.settlement = None;
        op.payment_hash = hash;
        op.state = "paying".into();
        encode(&mut op, &data)?;
        save(&self.state, &mut op).await?;
        let mut result = debit.dispatch(future).await;
        match &mut result {
            Ok(Ok(details)) => {
                if details.payment_hash.is_empty() {
                    details.payment_hash = op.payment_hash.clone().unwrap_or_default();
                }
                self.record(details).await.map_err(|e| {
                    ApiError::PaymentUnresolved(format!(
                        "dispatch completed but journal failed: {e}"
                    ))
                })?;
            }
            Ok(Err(LightningError::NotReady | LightningError::PaymentNotDispatched(_)))
            | Err(ApiError::BudgetExceeded(_)) => {
                let mut op = self.load().await?;
                let mut data = recovery(&op)?;
                data.dispatched = false;
                op.payment_hash = None;
                encode(&mut op, &data)?;
                save(&self.state, &mut op).await?;
            }
            _ => {} // durable dispatch intent remains unresolved
        }
        result
    }
    pub(crate) async fn record(&self, details: &PaymentDetails) -> Result<(), ApiError> {
        let mut op = self.load().await?;
        let mut data = recovery(&op)?;
        if op
            .payment_hash
            .as_ref()
            .is_some_and(|hash| !details.payment_hash.is_empty() && hash != &details.payment_hash)
            || details.amount_msat != data.expected_msat
            || details.direction != PaymentDirection::Outgoing
        {
            return Err(ApiError::PaymentUnresolved(
                "operation payment identity mismatch".into(),
            ));
        }
        if !details.payment_hash.is_empty() {
            op.payment_hash = Some(details.payment_hash.clone());
        }
        let mut details = details.clone();
        if details.payment_hash.is_empty() {
            details.payment_hash = op.payment_hash.clone().unwrap_or_default();
        }
        data.settlement = Some(details);
        encode(&mut op, &data)?;
        save(&self.state, &mut op).await
    }
    pub(crate) async fn settled_envelope(
        &self,
        proof: PaymentProof,
        fee_ceiling_msat: u64,
    ) -> Result<UkmEnvelope, ApiError> {
        let mut op = self.load().await?;
        let mut data = recovery(&op)?;
        data.fee_ceiling_msat = fee_ceiling_msat;
        let mut env = data
            .draft
            .clone()
            .ok_or_else(|| storage("missing encrypted draft"))?;
        if data.expected_msat > 0
            && (op.payment_hash.as_deref() != Some(hex::encode(proof.payment_hash).as_str())
                || !data.settlement.as_ref().is_some_and(|p| {
                    p.status == PaymentStatus::Settled && p.amount_msat == proof.amount_msat
                }))
        {
            return Err(ApiError::PaymentProofUnavailable {
                amount_msat: data.expected_msat,
                reason: "settled operation proof identity mismatch".into(),
            });
        }
        env.payment_proof = proof;
        env.signature = konsensus_core::Signature::from_ed25519(
            &self.state.identity.sign(&env.signable_bytes()),
        );
        // Save the proof before either messages or pending_deliveries is written.
        data.draft = Some(env.clone());
        data.envelope_ready = true;
        op.payment_hash = Some(hex::encode(env.payment_proof.payment_hash));
        op.settled_msat = i64::try_from(env.payment_proof.amount_msat).map_err(storage)?;
        encode(&mut op, &data)?;
        save(&self.state, &mut op).await?;
        materialize(&self.state, &mut op, &env).await?;
        Ok(env)
    }
}

async fn materialize(
    state: &AppState,
    op: &mut OutboxOperation,
    env: &UkmEnvelope,
) -> Result<(), ApiError> {
    op.state = "paid".into();
    op.updated_at = chrono::Utc::now().timestamp_millis();
    if !state
        .storage
        .commit_outbox_envelope(op, env)
        .await
        .map_err(storage)?
    {
        return Err(ApiError::Conflict(
            "operation changed during paid commit".into(),
        ));
    }
    op.version += 1;
    Ok(())
}

fn response(op: &OutboxOperation, delivered: bool) -> Result<ComposeResponse, ApiError> {
    let data = recovery(op)?;
    Ok(ComposeResponse {
        operation_id: Some(op.operation_id.clone()),
        state: op.state.clone(),
        accepted: op.state == "acked",
        payment_hash: op.payment_hash.clone(),
        retry_allowed: matches!(
            op.state.as_str(),
            "prepared" | "released" | "paid" | "sent" | "rejected_retryable"
        ),
        max_routing_fee_msat: data.fee_ceiling_msat,
        member_outcomes: None,
        message_id: op.message_id.clone().unwrap_or_default(),
        delivered,
        amount_msat: (op.settled_msat as u64).saturating_add(data.admission_msat),
        readmission_msat: (op.readmission_msat > 0).then_some(op.readmission_msat as u64),
    })
}
fn contextual(error: ApiError, op: &OutboxOperation) -> ApiError {
    ApiError::Operation {
        source: Box::new(error),
        operation_id: op.operation_id.clone(),
        state: op.state.clone(),
        payment_hash: op.payment_hash.clone(),
        retry_allowed: matches!(
            op.state.as_str(),
            "prepared" | "released" | "paid" | "sent" | "rejected_retryable"
        ),
    }
}

pub(super) async fn compose(
    auth: MeteredSpend,
    state: Arc<AppState>,
    req: ComposeRequest,
    references: Vec<MessageId>,
) -> Result<Json<ComposeResponse>, ApiError> {
    let peer = NodeId::from_hex(&req.recipient)
        .map_err(|e| ApiError::BadRequest(format!("invalid recipient: {e}")))?;
    let id = operation_id(req.operation_id.as_deref())?;
    let _guard = lock(&state, &id).await?;
    // Length-delimited canonical representation prevents ambiguous concatenation.
    let request = serde_json::to_vec(&(peer.to_hex(), req.kind, &req.plaintext, &req.references))
        .map_err(storage)?;
    let digest = blake3::hash(&request).to_hex().to_string();
    let mut op = OutboxOperation::prepared(id.clone(), peer.to_hex(), req.kind, digest.clone());
    encode(
        &mut op,
        &Recovery {
            caller: caller(&auth),
            admission_fee_msat: Some(0),
            ..Default::default()
        },
    )?;
    let inserted = state
        .storage
        .insert_outbox_operation(&op)
        .await
        .map_err(storage)?;
    if !inserted {
        op = state
            .storage
            .get_outbox_operation(&id)
            .await
            .map_err(storage)?
            .ok_or_else(|| storage("missing operation"))?;
        if caller(&auth).is_some() && caller(&auth) != recovery(&op)?.caller {
            return Err(ApiError::Forbidden(
                "operation belongs to another caller".into(),
            ));
        }
        if op.request_hash != digest {
            return Err(contextual(
                ApiError::OperationConflict("operation_mismatch"),
                &op,
            ));
        }
        if matches!(op.state.as_str(), "paying" | "payment_unknown") {
            reconcile(&state, &mut op).await?;
        }
        match op.state.as_str() {
            "acked" => return Ok(Json(response(&op, true)?)),
            "paid" | "sent" | "rejected_retryable" => {
                let delivered = resend(&state, &op).await?;
                return wait_response(&state, &id, req.wait_ack_ms, delivered).await;
            }
            "prepared" | "released" => {}
            "failed_paid" => {
                return Err(contextual(ApiError::OperationConflict("failed_paid"), &op))
            }
            _ => {
                return Err(contextual(
                    ApiError::OperationConflict("payment_unresolved"),
                    &op,
                ))
            }
        }
    }
    // The CAS also serializes processes sharing a database. A claimed operation
    // never re-enters the paying handler without positive nonpayment evidence.
    op.state = "paying".into();
    let mut data = recovery(&op)?;
    data.dispatched = false;
    data.settlement = None;
    let execution_id = uuid::Uuid::new_v4().to_string();
    data.execution_id = Some(execution_id.clone());
    data.reservation = None;
    op.payment_hash = None;
    encode(&mut op, &data)?;
    save(&state, &mut op).await?;
    let operation = Operation {
        state: state.clone(),
        id: id.clone(),
        execution_id,
    };
    let wait = req.wait_ack_ms;
    let result =
        super::compose::compose_peer(auth, state.clone(), req, references, operation.clone()).await;
    match result {
        Ok(result) => wait_response(&state, &id, wait, result.0.delivered).await,
        Err(error) => {
            op = operation.load().await?;
            if op.state == "paying" {
                let data = recovery(&op)?;
                if !data.dispatched && !data.admission_pending {
                    op.state = "prepared".into();
                } else {
                    op.state = "payment_unknown".into();
                }
                op.last_error = Some(error.to_string());
                save(&state, &mut op).await?;
            }
            Err(contextual(error, &op))
        }
    }
}

async fn resend(state: &AppState, op: &OutboxOperation) -> Result<bool, ApiError> {
    let id = MessageId::from_hex(
        op.message_id
            .as_deref()
            .ok_or_else(|| storage("missing message id"))?,
    )
    .map_err(storage)?;
    let peer = NodeId::from_hex(&op.recipient).map_err(storage)?;
    let mut env = state
        .storage
        .get_message(&id)
        .await
        .map_err(storage)?
        .ok_or_else(|| storage("paid envelope missing"))?;
    if env.sender == *state.identity.node_id()
        && env.kind == konsensus_core::kind::KIND_CHAT
        && env.ciphertext == b"konsensus:admission:v1"
    {
        let mut terminal = op.clone();
        terminal.state = "failed_paid".into();
        terminal.last_error =
            Some("legacy admission proof belongs to its original connection".into());
        save(state, &mut terminal).await?;
        state.storage.delete_message(&id).await.map_err(storage)?;
        return Ok(false);
    }
    if env
        .refresh_for_resend(
            &state.identity,
            chrono::Utc::now().timestamp_millis() as u64,
        )
        .map_err(storage)?
    {
        state
            .storage
            .update_message_wrapper(&env)
            .await
            .map_err(storage)?;
    }
    // Respect slice 1 rejection backoff and terminal gating.
    if op.state == "rejected_retryable"
        && !state
            .storage
            .get_pending_for_peer(&peer)
            .await
            .map_err(storage)?
            .iter()
            .any(|(pending, _)| pending == &id)
    {
        return Ok(false);
    }
    if let Err(error) = state.storage.mark_pending_sent(&id, &peer).await {
        if state
            .storage
            .get_outbox_operation(&op.operation_id)
            .await
            .map_err(storage)?
            .is_some_and(|current| current.state == "acked")
        {
            return Ok(true);
        }
        return Err(storage(error));
    }
    let delivered = state.transport.send(&peer, &env).await.is_ok();
    if delivered {
        state
            .storage
            .record_outbox_sent(&id, &peer)
            .await
            .map_err(storage)?;
    }
    Ok(delivered)
}

async fn wait_response(
    state: &AppState,
    id: &str,
    wait: Option<u64>,
    delivered: bool,
) -> Result<Json<ComposeResponse>, ApiError> {
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(wait.unwrap_or(5000).min(30_000));
    loop {
        let op = state
            .storage
            .get_outbox_operation(id)
            .await
            .map_err(storage)?
            .ok_or_else(|| storage("missing operation"))?;
        if !delivered
            || matches!(
                op.state.as_str(),
                "acked" | "failed_paid" | "rejected_retryable"
            )
            || tokio::time::Instant::now() >= deadline
        {
            return Ok(Json(response(&op, delivered)?));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

pub(super) async fn get_operation(
    _auth: crate::auth::scoped::ScopedAuth<crate::auth::scoped::Read>,
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<ComposeResponse>, ApiError> {
    let id = if id.starts_with("legacy:") {
        id
    } else {
        operation_id(Some(&id))?
    };
    let op = state
        .storage
        .get_outbox_operation(&id)
        .await
        .map_err(storage)?
        .ok_or_else(|| ApiError::NotFound("operation not found".into()))?;
    Ok(Json(response(
        &op,
        op.last_sent_at.is_some() || op.state == "acked",
    )?))
}

async fn reconcile(state: &AppState, op: &mut OutboxOperation) -> Result<(), ApiError> {
    let mut data = recovery(op)?;
    // Settlement evidence is monotonic even while proof retrieval is incomplete.
    if let Some(details) = data.settlement.as_ref().filter(|d| settlement_matches(op, &data, d)) {
        op.settled_msat = i64::try_from(details.amount_msat).map_err(storage)?;
    }
    if data.admission_pending && !data.dispatched {
        let details = match &op.admission_payment_hash {
            Some(hash) => state.lightning.get_payment_status(hash).await.ok(),
            None => None,
        };
        if let Some(details) = details.filter(|d| {
            Some(&d.payment_hash) == op.admission_payment_hash.as_ref()
                && d.amount_msat == data.admission_expected_msat
                && d.direction == PaymentDirection::Outgoing
        }) {
            if matches!(
                details.status,
                PaymentStatus::Settled | PaymentStatus::Failed | PaymentStatus::Expired
            ) {
                let principal = if details.status == PaymentStatus::Settled {
                    details.amount_msat
                } else {
                    0
                };
                let fee = if principal > 0 {
                    details.fee_msat
                } else {
                    Some(0)
                };
                let admission_reservation = data.admission_reservation.clone();
                if data.admission_is_readmission {
                    op.readmission_msat = op.readmission_msat.saturating_add(principal as i64);
                } else {
                    data.admission_msat = data.admission_msat.saturating_add(principal);
                    data.admission_fee_msat = None;
                }
                data.admission_pending = false;
                // Invalidate the old worker before resolving its admission-only
                // liability. A new POST must pass today's caps and grant checks.
                data.reservation = None;
                data.execution_id = None;
                op.state = "prepared".into();
                encode(op, &data)?;
                save(state, op).await?;
                if let (Some(service), Some(reservation), Some(fee)) =
                    (&state.pairing, &admission_reservation, fee)
                {
                    if let Some(total) = principal.checked_add(fee) {
                        service.resolve_spend(reservation, &op.recipient, total);
                    }
                }
                return Ok(());
            }
        }
        op.state = "payment_unknown".into();
        save(state, op).await?;
        return Ok(());
    }
    if !data.dispatched && !data.envelope_ready {
        let original = data.clone();
        data.reservation = None;
        data.execution_id = None;
        op.state = "prepared".into();
        encode(op, &data)?;
        save(state, op).await?;
        resolve_budget(state, &original, &op.recipient, 0, Some(0));
        return Ok(());
    }
    if data.envelope_ready {
        let Some(env) = data.draft.as_ref() else {
            op.state = "payment_unknown".into();
            op.last_error = Some("settled payment missing encrypted draft".into());
            save(state, op).await?;
            return Ok(());
        };
        materialize(state, op, env).await?;
        if let Some(details) = &data.settlement {
            resolve_budget(
                state,
                &data,
                &op.recipient,
                details.amount_msat,
                details.fee_msat,
            );
        }
        return Ok(());
    }
    let details = match &data.settlement {
        Some(p)
            if matches!(p.status, PaymentStatus::Failed | PaymentStatus::Expired)
                || (p.status == PaymentStatus::Settled && settlement_preimage(p).is_some()) =>
        {
            Some(p.clone())
        }
        _ => match &op.payment_hash {
            Some(hash) => state.lightning.get_payment_status(hash).await.ok(),
            None => None,
        },
    };
    let Some(details) = details else {
        op.state = "payment_unknown".into();
        save(state, op).await?;
        return Ok(());
    };
    if Some(&details.payment_hash) != op.payment_hash.as_ref()
        || details.amount_msat != data.expected_msat
        || details.direction != PaymentDirection::Outgoing
    {
        op.state = "payment_unknown".into();
        op.last_error = Some("payment identity mismatch".into());
        save(state, op).await?;
        return Ok(());
    }
    match details.status {
        PaymentStatus::Failed | PaymentStatus::Expired if op.settled_msat > 0 => {
            op.state = "payment_unknown".into();
            op.last_error = Some("backend failure contradicts recorded settlement".into());
            save(state, op).await?;
        }
        PaymentStatus::Failed | PaymentStatus::Expired => {
            op.state = "released".into();
            save(state, op).await?;
            resolve_budget(state, &data, &op.recipient, 0, Some(0));
        }
        PaymentStatus::Pending | PaymentStatus::InFlight => {
            op.state = "payment_unknown".into();
            save(state, op).await?;
        }
        PaymentStatus::Settled => {
            op.settled_msat = i64::try_from(details.amount_msat).map_err(storage)?;
            resolve_budget(
                state,
                &data,
                &op.recipient,
                details.amount_msat,
                details.fee_msat,
            );
            let Some(preimage) = settlement_preimage(&details) else {
                op.state = "payment_unknown".into();
                op.last_error = Some("settled payment has no valid proof".into());
                save(state, op).await?;
                return Ok(());
            };
            let Some(mut env) = data.draft.clone() else {
                op.state = "payment_unknown".into();
                op.last_error = Some("settled payment missing encrypted draft".into());
                save(state, op).await?;
                return Ok(());
            };
            let hash: [u8; 32] = Sha256::digest(preimage).into();
            env.payment_proof = PaymentProof::new(hash, preimage, details.amount_msat);
            env.signature = konsensus_core::Signature::from_ed25519(
                &state.identity.sign(&env.signable_bytes()),
            );
            op.settled_msat = i64::try_from(details.amount_msat).map_err(storage)?;
            // Carry the recovered evidence through the paid transaction so a
            // second crash can still resolve the original pairing reservation.
            data.settlement = Some(details.clone());
            data.draft = Some(env.clone());
            data.envelope_ready = true;
            encode(op, &data)?;
            materialize(state, op, &env).await?;
            resolve_budget(
                state,
                &data,
                &op.recipient,
                details.amount_msat,
                details.fee_msat,
            );
        }
    }
    Ok(())
}
fn settlement_preimage(details: &PaymentDetails) -> Option<[u8; 32]> {
    details
        .preimage
        .as_ref()
        .and_then(|p| hex::decode(p).ok())
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .filter(|p| hex::encode(Sha256::digest(p)) == details.payment_hash)
}

fn resolve_budget(
    state: &AppState,
    data: &Recovery,
    recipient: &str,
    principal: u64,
    fee: Option<u64>,
) {
    if let (Some(service), Some(reservation), Some(fee), Some(admission_fee)) = (
        &state.pairing,
        &data.reservation,
        fee,
        data.admission_fee_msat,
    ) {
        if let Some(total) = principal
            .checked_add(fee)
            .and_then(|v| v.checked_add(data.budget_admission_msat))
            .and_then(|v| v.checked_add(admission_fee))
        {
            service.resolve_spend(reservation, recipient, total);
        }
    }
}

/// Run at startup and periodically. It only queries payment status and repairs
/// delivery state; neither grants nor invoice/keysend dispatch are recreated.
pub async fn reconcile_operations(state: &Arc<AppState>) -> Result<(), ApiError> {
    for candidate in state
        .storage
        .list_recoverable_operations()
        .await
        .map_err(storage)?
    {
        let Ok(_guard) = operation_lock(state, &candidate.operation_id)?.try_lock_owned() else {
            continue;
        };
        let result = async {
            let Some(mut op) = state
                .storage
                .get_outbox_operation(&candidate.operation_id)
                .await
                .map_err(storage)?
            else {
                return Ok::<(), ApiError>(());
            };
            if matches!(op.state.as_str(), "paying" | "payment_unknown") {
                reconcile(state, &mut op).await?;
            }
            if matches!(op.state.as_str(), "paid" | "sent" | "acked" | "rejected_retryable" | "failed_paid") {
                recover_budget(state, &op)?;
            }
            if op.state == "paid" {
                recover_paid(state, &mut op).await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(operation_id = %candidate.operation_id, %error, "operation recovery deferred");
        }
    }
    Ok(())
}


fn settlement_matches(op: &OutboxOperation, data: &Recovery, details: &PaymentDetails) -> bool {
    details.status == PaymentStatus::Settled
        && details.direction == PaymentDirection::Outgoing
        && Some(&details.payment_hash) == op.payment_hash.as_ref()
        && details.amount_msat == data.expected_msat
}

fn recover_budget(state: &AppState, op: &OutboxOperation) -> Result<(), ApiError> {
    let data = recovery(op)?;
    // Original reservation/grant IDs make this idempotent even after an ACK or
    // reject won the race with recovery. Delivery never gates accounting.
    if let Some(details) = data.settlement.as_ref().filter(|d| settlement_matches(op, &data, d)) {
        resolve_budget(state, &data, &op.recipient, details.amount_msat, details.fee_msat);
    } else if data.envelope_ready && !data.dispatched && data.expected_msat == 0
        && data.draft.as_ref().is_some_and(|env| env.payment_proof.amount_msat == 0)
    {
        // Free messages have no Lightning settlement record, but their admission
        // can still hold a reservation. Unknown admission fees remain reserved.
        resolve_budget(state, &data, &op.recipient, 0, Some(0));
    }
    Ok(())
}

async fn recover_paid(state: &AppState, op: &mut OutboxOperation) -> Result<(), ApiError> {
    let mut data = recovery(op)?;
    let now = chrono::Utc::now().timestamp_millis();
    if now < data.resend_after_ms {
        return Ok(());
    }
    let peer = NodeId::from_hex(&op.recipient).map_err(storage)?;
    if !state.transport.is_connected(&peer).await {
        data.resend_delay_ms = data.resend_delay_ms.saturating_mul(2).clamp(15_000, 300_000);
        data.resend_after_ms = now.saturating_add(data.resend_delay_ms as i64);
        encode(op, &data)?;
        save(state, op).await?;
        return Ok(());
    }
    if data.resend_delay_ms != 0 || data.resend_after_ms != 0 {
        data.resend_delay_ms = 0;
        data.resend_after_ms = 0;
        encode(op, &data)?;
        save(state, op).await?;
    }
    resend(state, op).await?;
    Ok(())
}
