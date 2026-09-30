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
    budget_resolutions: Vec<BudgetResolution>,
}

#[derive(Clone, Serialize, Deserialize)]
struct BudgetResolution {
    reservation: Reservation,
    // None keeps the full liability when any fee is unknown.
    actual_msat: Option<u64>,
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
    op.accounting_pending = data.reservation.is_some()
        || data.admission_reservation.is_some()
        || data.admission_pending
        || !data.budget_resolutions.is_empty();
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
pub(super) fn operation_id(id: Option<&str>) -> Result<String, ApiError> {
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
    pub(crate) fn reservation_link(&self, readmission: bool) -> crate::spend_budget::OperationReservationLink {
        crate::spend_budget::OperationReservationLink {
            operation_id: self.id.clone(), execution_id: self.execution_id.clone(), readmission,
        }
    }
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
        if data.admission_is_readmission {
            if let Some(reservation) = data.admission_reservation.clone() {
                queue_resolution(&mut data, reservation, Some(0));
            }
        } else {
            queue_message_resolution(&mut data, 0, Some(0));
        }
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
        if data.admission_is_readmission {
            if let Some(reservation) = data.admission_reservation.clone() {
                queue_resolution(&mut data, reservation, details.fee_msat.and_then(|fee| details.amount_msat.checked_add(fee)));
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

/// The request an operation id is bound to (`OutboxOperation::request_hash`).
pub(super) fn request_digest(peer: &NodeId, req: &ComposeRequest) -> Result<String, ApiError> {
    // Length-delimited canonical representation prevents ambiguous concatenation.
    let request = serde_json::to_vec(&(peer.to_hex(), req.kind, &req.plaintext, &req.references))
        .map_err(storage)?;
    Ok(blake3::hash(&request).to_hex().to_string())
}

/// The refusal for an operation id reused with a different request.
pub(super) fn mismatch(op: &OutboxOperation) -> ApiError {
    contextual(ApiError::OperationConflict("operation_mismatch"), op)
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
    compose_locked(auth, state, req, references, peer, id).await
}

/// A 1:1 call signal (kinds 400-403). Its reservation is made, the operation
/// run, and the reservation resolved all under the one per-operation lock
/// (Codex delta3 #1), so concurrent requests for the same operation (same
/// payload, different caps) run one after another: a refused one resolves
/// only its own reservation before the next reserves, and can never release
/// a reservation another request is paying under.
pub(super) async fn compose_call(
    auth: MeteredSpend,
    state: Arc<AppState>,
    mut req: ComposeRequest,
    references: Vec<MessageId>,
) -> Result<Json<ComposeResponse>, ApiError> {
    let peer = NodeId::from_hex(&req.recipient)
        .map_err(|e| ApiError::BadRequest(format!("invalid recipient: {e}")))?;
    // The journal's canonical key, for the reservation too (Codex delta2 #1).
    let id = operation_id(req.operation_id.as_deref())?;
    req.operation_id = Some(id.clone());
    let _guard = lock(&state, &id).await?;
    // One operation id, one request (Fable N2): an id reused for another
    // signal is refused before any reservation. A retry of an operation that
    // already paid is answered from the journal, without reserving.
    let request_hash = request_digest(&peer, &req)?;
    let journal = state.storage.get_outbox_operation(&id).await.map_err(storage)?;
    if let Some(op) = journal.as_ref().filter(|op| op.request_hash != request_hash) {
        return Err(mismatch(op));
    }
    let paid = journal.as_ref().is_some_and(|op| {
        konsensus_core::payloads::call::settlement(Some(&op.state)) == konsensus_core::payloads::call::Settlement::Paid
    });
    let plaintext = req.plaintext.clone();
    if !paid {
        crate::calls::reserve_outgoing(state.storage.as_ref(), state.identity.node_id(), &peer, req.kind, &plaintext, &id, &request_hash).await?;
    }
    let result = compose_locked(auth, Arc::clone(&state), req, references, peer, id.clone()).await;
    crate::calls::resolve_outgoing(state.storage.as_ref(), &peer, &plaintext, &id, &request_hash).await;
    result
}

/// The operation itself; the caller holds its per-operation lock.
async fn compose_locked(
    auth: MeteredSpend,
    state: Arc<AppState>,
    req: ComposeRequest,
    references: Vec<MessageId>,
    peer: NodeId,
    id: String,
) -> Result<Json<ComposeResponse>, ApiError> {
    let digest = request_digest(&peer, &req)?;
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
            return Err(mismatch(&op));
        }
        recover_budget(&state, &mut op).await?;
        // Pre-fix rows may have terminalized incomplete settlement as failed_paid.
        // Reopen those only; genuine terminal rejects stay failed_paid.
        // Compaction strips recovery evidence (dispatched/envelope_ready) but is
        // payload retention, not re-payment authorization — never reopen compacted.
        if op.state == "failed_paid"
            && !op.recovery_compacted
            && incomplete_settled_recovery(&op)
        {
            op.state = "payment_unknown".into();
            save(&state, &mut op).await?;
        }
        if matches!(op.state.as_str(), "paying" | "payment_unknown") {
            reconcile(&state, &mut op).await?;
        }
        // A call signal this retry found paid is committed before the resend,
        // so the callee's immediate answer finds a ringing call (Codex
        // delta2 #3). Never a release here: an unpaid one is paid again below.
        crate::calls::settle_operation(state.storage.as_ref(), &op, false).await;
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
    data.admission_reservation = None;
    data.budget_admission_msat = 0;
    data.admission_fee_msat = Some(0);
    data.envelope_ready = false;
    data.draft = None;
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
                op.state = if proven_unpaid(&state, &op, &data).await {
                    "released"
                } else if !data.dispatched && !data.admission_pending {
                    "prepared"
                } else {
                    "payment_unknown"
                }
                .into();
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

/// Checkpoint the original operation before another compose clears its peer
/// journal. A failed/ambiguous SQL write leaves the false dispatch marker intact.
pub(super) async fn record_undispatched_admission(
    state: &AppState, peer: &NodeId, link: &crate::spend_budget::OperationReservationLink,
    reservation: Option<&Reservation>,
) -> Result<(), ApiError> {
    let Some(mut op) = state.storage.get_outbox_operation(&link.operation_id).await.map_err(storage)? else { return Ok(()); };
    let mut data = recovery(&op)?;
    if op.recipient != peer.to_hex() || data.execution_id.as_deref() != Some(&link.execution_id) {
        return Ok(());
    }
    if data.dispatched {
        return Err(ApiError::PaymentUnresolved("cannot undo admission after message dispatch".into()));
    }
    // Fence even an admission_started UPDATE still queued in the SQL worker.
    // Its fields may not be visible yet, but its old version must never commit
    // after we remove the only durable proof of nondispatch.
    if link.readmission {
        if let Some(reservation) = reservation {
            queue_resolution(&mut data, reservation.clone(), Some(0));
        }
    }
    queue_message_resolution(&mut data, 0, Some(0));
    data.admission_pending = false;
    data.execution_id = None;
    op.state = "prepared".into();
    encode(&mut op, &data)?;
    save(state, &mut op).await?;
    drain_resolutions(state, &mut op).await
}

async fn reconcile(state: &AppState, op: &mut OutboxOperation) -> Result<(), ApiError> {
    recover_budget(state, op).await?;
    let mut data = recovery(op)?;
    // Settlement evidence is monotonic even while proof retrieval is incomplete.
    if let Some(details) = data.settlement.as_ref().filter(|d| settlement_matches(op, &data, d)) {
        op.settled_msat = i64::try_from(details.amount_msat).map_err(storage)?;
    }
    if data.admission_pending && !data.dispatched {
        let peer = NodeId::from_hex(&op.recipient).map_err(storage)?;
        if let Some(hash) = op.admission_payment_hash.clone() {
            if super::admission_journal::load(state, &peer)?.is_some_and(|a| a.payment_hash == hash && !a.dispatch_started) {
                data.admission_pending = false;
                if let Some(reservation) = data.admission_reservation.take() {
                    queue_resolution(&mut data, reservation, Some(0));
                }
                queue_message_resolution(&mut data, 0, Some(0));
                data.execution_id = None;
                op.state = "prepared".into();
                encode(op, &data)?;
                save(state, op).await?;
                drain_resolutions(state, op).await?;
                super::compose::clear_undispatched_admission(state, &peer, &hash).await?;
                return Ok(());
            }
        }
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
                    data.budget_admission_msat = data.budget_admission_msat.saturating_add(principal);
                    data.admission_fee_msat = data.admission_fee_msat.and_then(|prior| fee.and_then(|f| prior.checked_add(f)));
                }
                if data.admission_is_readmission {
                    if let Some(reservation) = admission_reservation {
                        queue_resolution(&mut data, reservation, fee.and_then(|f| principal.checked_add(f)));
                    }
                }
                queue_message_resolution(&mut data, 0, Some(0));
                data.admission_pending = false;
                // Invalidate the old worker before resolving its admission-only
                // liability. A new POST must pass today's caps and grant checks.
                data.reservation = None;
                data.execution_id = None;
                op.state = "prepared".into();
                encode(op, &data)?;
                save(state, op).await?;
                drain_resolutions(state, op).await?;
                return Ok(());
            }
        }
        op.state = "payment_unknown".into();
        save(state, op).await?;
        return Ok(());
    }
    if !data.dispatched && !data.envelope_ready {
        // Defense in depth: a prior settlement (or recorded payment_hash) means
        // this is not a fresh attempt — never authorize another payment by
        // resetting to prepared (e.g. after recovery compaction stripped flags).
        if op.settled_msat > 0 || op.payment_hash.is_some() {
            op.state = "payment_unknown".into();
            save(state, op).await?;
            return Ok(());
        }
        queue_message_resolution(&mut data, 0, Some(0));
        data.reservation = None;
        data.execution_id = None;
        op.state = "prepared".into();
        encode(op, &data)?;
        save(state, op).await?;
        drain_resolutions(state, op).await?;
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
        recover_budget(state, op).await?;
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
            data.settlement = Some(details.clone());
            queue_message_resolution(&mut data, 0, Some(0));
            op.state = "released".into();
            encode(op, &data)?;
            save(state, op).await?;
            drain_resolutions(state, op).await?;
        }
        PaymentStatus::Pending | PaymentStatus::InFlight => {
            op.state = "payment_unknown".into();
            save(state, op).await?;
        }
        PaymentStatus::Settled => {
            op.settled_msat = i64::try_from(details.amount_msat).map_err(storage)?;
            data.settlement = Some(details.clone());
            queue_message_resolution(&mut data, details.amount_msat, details.fee_msat);
            let Some(preimage) = settlement_preimage(&details) else {
                op.state = "payment_unknown".into();
                op.last_error = Some("settled payment has no valid proof".into());
                encode(op, &data)?;
                save(state, op).await?;
                drain_resolutions(state, op).await?;
                return Ok(());
            };
            let Some(mut env) = data.draft.clone() else {
                op.state = "payment_unknown".into();
                op.last_error = Some("settled payment missing encrypted draft".into());
                encode(op, &data)?;
                save(state, op).await?;
                drain_resolutions(state, op).await?;
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
            drain_resolutions(state, op).await?;
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

fn queue_resolution(data: &mut Recovery, reservation: Reservation, actual_msat: Option<u64>) {
    if let Some(existing) = data.budget_resolutions.iter_mut().find(|r| r.reservation.id == reservation.id && r.reservation.op_id == reservation.op_id) {
        if existing.actual_msat.is_none() { existing.actual_msat = actual_msat; }
    } else {
        data.budget_resolutions.push(BudgetResolution { reservation, actual_msat });
    }
}

fn queue_message_resolution(data: &mut Recovery, principal: u64, fee: Option<u64>) {
    if let Some(reservation) = data.reservation.clone() {
        let total = fee.and_then(|fee| principal.checked_add(fee))
            .and_then(|v| v.checked_add(data.budget_admission_msat))
            .and_then(|v| data.admission_fee_msat.and_then(|fee| v.checked_add(fee)));
        queue_resolution(data, reservation, total);
    }
}

async fn drain_resolutions(state: &AppState, op: &mut OutboxOperation) -> Result<(), ApiError> {
    let Some(service) = &state.pairing else { return Ok(()); };
    let mut data = recovery(op)?;
    let before = data.budget_resolutions.len();
    for resolution in &data.budget_resolutions {
        if let Some(actual) = resolution.actual_msat {
            service.try_resolve_spend(&resolution.reservation, &op.recipient, actual).map_err(storage)?;
            if data.reservation.as_ref().is_some_and(|r| r.id == resolution.reservation.id && r.op_id == resolution.reservation.op_id) {
                data.reservation = None;
            }
            if data.admission_reservation.as_ref().is_some_and(|r| r.id == resolution.reservation.id && r.op_id == resolution.reservation.op_id) {
                data.admission_reservation = None;
            }
        }
    }
    data.budget_resolutions.retain(|r| r.actual_msat.is_none());
    if before != data.budget_resolutions.len() {
        encode(op, &data)?;
        save(state, op).await?;
    }
    Ok(())
}

type LinkedReservation = (crate::spend_budget::OperationReservationLink, Reservation);

/// Run at startup and periodically. It only queries payment status and repairs
/// delivery state; neither grants nor invoice/keysend dispatch are recreated.
pub async fn reconcile_operations(state: &Arc<AppState>) -> Result<(), ApiError> {
    // One ledger lock per sweep, proportional to unresolved links rather than
    // all-time SQL history. Union the IDs: a late debit from an execution fenced
    // by another process can appear after its operation left the SQL predicate.
    let mut links: HashMap<String, Vec<LinkedReservation>> = HashMap::new();
    if let Some(service) = &state.pairing {
        for (link, reservation) in service.pending_operation_reservations() {
            links
                .entry(link.operation_id.clone())
                .or_default()
                .push((link, reservation));
        }
    }
    let mut ids: std::collections::BTreeSet<String> = state
        .storage
        .list_recoverable_operations()
        .await
        .map_err(storage)?
        .into_iter()
        .map(|op| op.operation_id)
        .collect();
    ids.extend(links.keys().cloned());
    // Never let this listing hold up recovery of paid or unresolved rows.
    if let Err(error) = release_failed_prepared(state).await {
        tracing::warn!(%error, "failed operation release deferred");
    }
    for id in ids.clone() {
        let Ok(_guard) = operation_lock(state, &id)?.try_lock_owned() else {
            continue;
        };
        let result = async {
            let Some(mut op) = state
                .storage
                .get_outbox_operation(&id)
                .await
                .map_err(storage)?
            else {
                return Ok::<(), ApiError>(());
            };
            if let Some(linked) = links.get(&id) {
                attach_recovered_reservations(state, &mut op, linked).await?;
            }
            // No sweep-side failed_paid→payment_unknown reopen: list_recoverable
            // never selects failed_paid unless accounting_pending. Compose owns
            // mistagged reopen (with recovery_compacted guard).
            if matches!(op.state.as_str(), "paying" | "payment_unknown") {
                reconcile(state, &mut op).await?;
            }
            recover_budget(state, &mut op).await?;
            // A call signal's reservation follows its operation here too, and
            // before any resend (Fable N1).
            crate::calls::settle_operation(state.storage.as_ref(), &op, true).await;
            if op.state == "paid" {
                recover_paid(state, &mut op).await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(operation_id = %id, %error, "operation recovery deferred");
        }
    }
    prune_paces(state, &ids);
    compact_terminal_operations(state, &links).await
}

/// Positive evidence that an operation holds no payment: nothing was
/// dispatched or left pending, no settlement, proof or admission was recorded,
/// the peer's admission journal (every retained attempt) shows no dispatch or
/// settlement, and the wallet knows no payment for any admission hash involved.
/// Any doubt (an unreadable journal, another operation's attempt, a hash that
/// does not match, a wallet that cannot answer) is not evidence.
async fn proven_unpaid(state: &AppState, op: &OutboxOperation, data: &Recovery) -> bool {
    if data.dispatched
        || data.admission_pending
        || data.envelope_ready
        || data.settlement.is_some()
        || data.admission_msat != 0
        || op.payment_hash.is_some()
        || op.settled_msat != 0
        || op.readmission_msat != 0
    {
        return false;
    }
    let Ok(peer) = NodeId::from_hex(&op.recipient) else {
        return false;
    };
    // The journal is written before an admission reaches this row, and a
    // recovered attempt may never reach it: wallet absence alone proves nothing.
    let Ok(journal) = super::admission_journal::load(state, &peer) else {
        return false;
    };
    let mut hashes = Vec::new();
    let mut attempt = journal.as_ref();
    while let Some(a) = attempt {
        if a.dispatch_started
            || a.message_may_have_dispatched
            || a.envelope.is_some()
            || a.settled_at_unix.is_some()
            || a.readmission.as_ref().is_some_and(|r| r.reported)
            || a.operation.as_ref().is_some_and(|l| l.operation_id != op.operation_id)
        {
            return false;
        }
        hashes.push(a.payment_hash.clone());
        attempt = a.previous_attempt.as_deref();
    }
    if let Some(hash) = &op.admission_payment_hash {
        if journal.is_some() && !hashes.contains(hash) {
            return false;
        }
        hashes.push(hash.clone());
    }
    for hash in hashes {
        if !matches!(
            state.lightning.get_payment_status(&hash).await,
            Err(LightningError::PaymentNotFound(_))
        ) {
            return false;
        }
    }
    true
}

/// Rows left `prepared` with a `last_error` by builds before the failure path
/// released them: a compose that failed before paying. Release each one proven
/// unpaid; anything else stays as it is.
async fn release_failed_prepared(state: &AppState) -> Result<(), ApiError> {
    for candidate in state
        .storage
        .list_failed_prepared_operations()
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
            if op.state != "prepared" || op.last_error.is_none() {
                return Ok(());
            }
            let data = recovery(&op)?;
            if !proven_unpaid(state, &op, &data).await {
                return Ok(());
            }
            op.state = "released".into();
            save(state, &mut op).await?;
            recover_budget(state, &mut op).await
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(operation_id = %candidate.operation_id, %error, "failed operation release deferred");
        }
    }
    Ok(())
}

async fn attach_recovered_reservations(
    state: &AppState,
    op: &mut OutboxOperation,
    linked: &[LinkedReservation],
) -> Result<(), ApiError> {
    let mut data = recovery(op)?;
    let before = op.recovery.clone();
    let was_pending = op.accounting_pending;
    for (link, reservation) in linked {
        if data
            .budget_resolutions
            .iter()
            .any(|r| r.reservation.id == reservation.id && r.reservation.op_id == reservation.op_id)
        {
            continue;
        }
        if op.recovery_compacted {
            // Compaction required empty accounting and no linked liabilities.
            // A link appearing afterwards is a late, unattached debit from a
            // fenced worker; do not infer its fee from the compacted receipt.
            queue_resolution(&mut data, reservation.clone(), Some(0));
        } else if data.execution_id.as_deref() != Some(&link.execution_id)
            && data.execution_id.is_some()
        {
            // A superseded execution cannot dispatch: attach_debit/load checks
            // execution identity before admission or message wallet calls.
            queue_resolution(&mut data, reservation.clone(), Some(0));
        } else if link.readmission {
            if data
                .admission_reservation
                .as_ref()
                .is_none_or(|r| r.id != reservation.id)
            {
                queue_resolution(&mut data, reservation.clone(), Some(0));
            }
        } else if data.reservation.is_none() {
            data.reservation = Some(reservation.clone());
        }
    }
    encode(op, &data)?;
    if op.recovery != before || op.accounting_pending != was_pending {
        save(state, op).await?;
    }
    Ok(())
}

// Retain full recovery evidence for 30 days after the last terminal/accounting
// change, then compact at most 100 rows per sweep. Never expire operation IDs:
// deleting the tombstone would authorize another payment on duplicate POST.
const TERMINAL_RECOVERY_RETENTION_MS: i64 = 30 * 24 * 60 * 60 * 1000;
async fn compact_terminal_operations(
    state: &AppState,
    links: &HashMap<String, Vec<LinkedReservation>>,
) -> Result<(), ApiError> {
    let cutoff = chrono::Utc::now().timestamp_millis() - TERMINAL_RECOVERY_RETENTION_MS;
    for candidate in state
        .storage
        .list_compactable_operations(cutoff, 100)
        .await
        .map_err(storage)?
    {
        if links.contains_key(&candidate.operation_id) {
            continue;
        }
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
            if op.accounting_pending
                || op.recovery_compacted
                || op.updated_at >= cutoff
                || !matches!(op.state.as_str(), "acked" | "failed_paid")
            {
                return Ok(());
            }
            let data = recovery(&op)?;
            // Defense in depth: retain any liabilities even if metadata came
            // from an older/inconsistent writer. CAS protects concurrent ACKs.
            encode(&mut op, &data)?;
            if op.accounting_pending {
                return save(state, &mut op).await;
            }
            let receipt = Recovery {
                caller: data.caller,
                fee_ceiling_msat: data.fee_ceiling_msat,
                admission_msat: data.admission_msat,
                ..Default::default()
            };
            encode(&mut op, &receipt)?;
            op.recovery_compacted = true;
            save(state, &mut op).await
        }
        .await;
        if let Err(error) = result {
            tracing::warn!(operation_id = %candidate.operation_id, %error, "operation retention deferred");
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

async fn recover_budget(state: &AppState, op: &mut OutboxOperation) -> Result<(), ApiError> {
    if !op.accounting_pending { return Ok(()); }
    let mut data = recovery(op)?;
    let before = op.recovery.clone();
    let was_pending = op.accounting_pending;
    if let Some(details) = data.settlement.clone().filter(|d| settlement_matches(op, &data, d)) {
        queue_message_resolution(&mut data, details.amount_msat, details.fee_msat);
    } else if op.state == "released"
        || (!data.dispatched && !data.admission_pending && !data.envelope_ready)
        || (data.envelope_ready && !data.dispatched && data.expected_msat == 0
            && data.draft.as_ref().is_some_and(|env| env.payment_proof.amount_msat == 0))
    {
        queue_message_resolution(&mut data, 0, Some(0));
    }
    encode(op, &data)?;
    if op.recovery != before || op.accounting_pending != was_pending { save(state, op).await?; }
    drain_resolutions(state, op).await
}

/// First retry delay after a failed resend; doubles per consecutive failure.
const RESEND_BASE: Duration = Duration::from_secs(15);
/// Upper bound on the resend delay while a peer stays unreachable.
const RESEND_CAP: Duration = Duration::from_secs(600);

/// What the sweep last saw of the peer's connection.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Link {
    Offline,
    /// Connection generation, when the transport tracks one.
    Online(Option<std::time::Instant>),
}

/// Volatile resend pacing for one paid operation. It never touches the row:
/// payment state, the paid envelope and its pending delivery are unchanged,
/// and a restart simply retries once before backing off again.
struct Pace {
    failures: u32,
    due: tokio::time::Instant,
    link: Link,
}

// Scoped to the storage instance rather than the node: pacing belongs to the
// rows one server sweeps, and a reopened database starts afresh like a restart.
fn pace_prefix(state: &AppState) -> String {
    format!("{:p}:", Arc::as_ptr(&state.storage))
}
fn pace_key(state: &AppState, id: &str) -> String {
    format!("{}{id}", pace_prefix(state))
}
fn paces() -> std::sync::MutexGuard<'static, HashMap<String, Pace>> {
    static PACES: OnceLock<Mutex<HashMap<String, Pace>>> = OnceLock::new();
    PACES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}
/// Drop pacing for operations that are no longer recoverable.
fn prune_paces(state: &AppState, live: &std::collections::BTreeSet<String>) {
    let prefix = pace_prefix(state);
    paces().retain(|key, _| {
        key.strip_prefix(&prefix)
            .is_none_or(|id| live.contains(id))
    });
}

/// Exponential delay capped at [`RESEND_CAP`], with deterministic
/// per-operation jitter in `[base/2, base]` so one peer's backlog does not
/// retry in lockstep.
fn resend_delay(operation_id: &str, failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(16);
    let base = RESEND_BASE.saturating_mul(1 << doublings).min(RESEND_CAP);
    let hash = blake3::hash(format!("{operation_id}:{failures}").as_bytes());
    let jitter = u32::from(u16::from_le_bytes([hash.as_bytes()[0], hash.as_bytes()[1]]));
    base / 2 + base / 2 * jitter / u32::from(u16::MAX)
}

async fn recover_paid(state: &AppState, op: &mut OutboxOperation) -> Result<(), ApiError> {
    // Paid without a durable envelope cannot be resent and must never re-pay.
    // Fail closed before pacing so a missing envelope cannot linger as paid.
    let message_id = match op.message_id.as_deref() {
        Some(hex) => MessageId::from_hex(hex).map_err(storage)?,
        None => {
            op.state = "payment_unknown".into();
            op.last_error = Some("paid operation missing message id".into());
            save(state, op).await?;
            return Ok(());
        }
    };
    if state
        .storage
        .get_message(&message_id)
        .await
        .map_err(storage)?
        .is_none()
    {
        op.state = "payment_unknown".into();
        op.last_error = Some("paid envelope missing".into());
        save(state, op).await?;
        return Ok(());
    }
    let peer = NodeId::from_hex(&op.recipient).map_err(storage)?;
    let link = if state.transport.is_connected(&peer).await {
        Link::Online(state.transport.connected_since(&peer).await)
    } else {
        Link::Offline
    };
    let key = pace_key(state, &op.operation_id);
    let now = tokio::time::Instant::now();
    {
        let mut paces = paces();
        if let Some(pace) = paces.get_mut(&key) {
            let reconnected = link != Link::Offline && link != pace.link;
            pace.link = link;
            if reconnected {
                // A fresh connection deserves a prompt delivery attempt.
                paces.remove(&key);
            } else if link == Link::Offline || now < pace.due {
                return Ok(());
            }
        } else if link == Link::Offline {
            // Nothing is sent while offline; remember it so the next
            // connection counts as a reconnect.
            paces.insert(key, Pace { failures: 0, due: now, link });
            return Ok(());
        }
    }
    let result = resend(state, op).await;
    let mut paces = paces();
    if matches!(result, Ok(true)) {
        paces.remove(&key);
    } else {
        let pace = paces.entry(key).or_insert(Pace { failures: 0, due: now, link });
        pace.failures = pace.failures.saturating_add(1);
        pace.due = now + resend_delay(&op.operation_id, pace.failures);
        pace.link = link;
    }
    result.map(|_| ())

}

/// Early #113 builds terminalized settled-without-proof / missing-draft as
/// `failed_paid`. Those must reopen to `payment_unknown` so later backend proof
/// can still complete delivery — without authorizing another payment.
fn incomplete_settled_recovery(op: &OutboxOperation) -> bool {
    matches!(
        op.last_error.as_deref(),
        Some("settled payment has no valid proof")
            | Some("settled payment missing encrypted draft")
    )
}
