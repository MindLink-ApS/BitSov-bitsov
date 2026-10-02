//! File endpoints — upload, download, list, send, and delete files.
//!
//! Uploads use bounded, expiring memory staging; received files are persisted. The node
//! handles E2EE encryption for file transfer — the frontend sends raw
//! file bytes (base64-encoded), and the node encrypts them via Double
//! Ratchet before transmission. Received files are decrypted and stored.
//!
//! File transfer uses `KIND_FILE_REF` (200) UKM envelopes. The plaintext
//! payload is a JSON `FilePayload` containing metadata + base64 file data.

use crate::auth::scoped::{ScopedAuth, Admin, Read};
use crate::metered::MeteredSpend;
use crate::spend_budget::Charge;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use konsensus_core::kind::KIND_FILE_REF;
use konsensus_core::types::{NodeId, Recipient};
use konsensus_crypto::ratchet_message_to_bytes;
use konsensus_storage::FileRecord;

use crate::audit::events;
use crate::error::ApiError;
use crate::handlers::messages::create_metered_payment_proof;
use crate::state::AppState;
use crate::handlers::list_diagnostics::ListDiagnostics;

/// Maximum file size: 4 MiB (fits within 16 MiB wire frame with overhead).
const MAX_FILE_SIZE: usize = crate::file_staging::MAX_FILE_BYTES;

/// JSON payload for file data inside a KIND_FILE_REF envelope.
///
/// This struct is serialized to JSON, encrypted by Double Ratchet, and
/// placed in the UKM envelope ciphertext field.
#[derive(Debug, Serialize, Deserialize)]
pub struct FilePayload {
    /// Original filename.
    pub filename: String,
    /// MIME type.
    pub mime_type: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// blake3 hash of the file data (hex).
    pub blake3_hash: String,
    /// File data (base64-encoded).
    pub data_b64: String,
}

/// Request to upload a file to the local node.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadRequest {
    /// Original filename.
    pub filename: String,
    /// MIME type (defaults to application/octet-stream).
    #[serde(default = "default_mime")]
    pub mime_type: String,
    /// File data (base64-encoded).
    pub data_b64: String,
}

fn default_mime() -> String {
    "application/octet-stream".into()
}

/// Response after uploading a file.
#[derive(Serialize)]
pub struct UploadResponse {
    /// File ID (UUID).
    pub file_id: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// blake3 hash (hex).
    pub blake3_hash: String,
}

/// File metadata in API responses.
#[derive(Serialize)]
pub struct FileResponse {
    /// File ID (UUID).
    pub id: String,
    /// Original filename.
    pub filename: String,
    /// MIME type.
    pub mime_type: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// blake3 hash of the file data (hex).
    pub blake3_hash: String,
    /// Node ID (hex) of the sender (or self for local uploads).
    pub sender: String,
    /// Associated message ID, if the file was received via a message.
    pub message_id: Option<String>,
    /// ISO 8601 timestamp when the file was stored.
    pub created_at: String,
}

impl From<konsensus_storage::FileMetadata> for FileResponse {
    fn from(m: konsensus_storage::FileMetadata) -> Self {
        Self {
            id: m.id,
            filename: m.filename,
            mime_type: m.mime_type,
            size_bytes: m.size_bytes,
            blake3_hash: m.blake3_hash,
            sender: m.sender,
            message_id: m.message_id,
            created_at: m.created_at,
        }
    }
}

/// File download response (metadata + data).
#[derive(Serialize)]
pub struct DownloadResponse {
    /// File ID (UUID).
    pub id: String,
    /// Original filename.
    pub filename: String,
    /// MIME type.
    pub mime_type: String,
    /// Size in bytes.
    pub size_bytes: u64,
    /// blake3 hash of the file data (hex).
    pub blake3_hash: String,
    /// Node ID (hex) of the sender.
    pub sender: String,
    /// File data (base64-encoded).
    pub data_b64: String,
}

/// Maximum allowed limit for file list queries.
const MAX_FILE_LIST_LIMIT: u32 = 1000;

/// Query parameters for listing files.
#[derive(Deserialize)]
pub struct ListFilesQuery {
    /// Maximum number of files to return (capped at 1000).
    #[serde(default = "default_file_limit")]
    pub limit: u32,
    /// Resume using the timestamp/ID returned in scan continuation headers.
    pub before: Option<String>,
    pub before_id: Option<String>,
}

fn default_file_limit() -> u32 {
    50
}

/// Request to send a file to a peer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendFileRequest {
    #[serde(default)]
    pub max_routing_fee_msat: Option<u64>,
    #[serde(default)]
    pub max_total_msat: Option<u64>,
    /// Recipient node ID (hex).
    pub recipient: String,
}

/// Response after sending a file.
#[derive(Serialize)]
pub struct SendFileResponse {
    pub max_routing_fee_msat: u64,
    /// The message ID of the UKM envelope.
    pub message_id: String,
    /// Whether the file was delivered to a connected peer.
    pub delivered: bool,
    /// Amount paid in millisatoshis.
    pub amount_msat: u64,
}

/// Maximum filename length in bytes.
const MAX_FILENAME_LEN: usize = 255;

/// Maximum MIME type length in bytes.
const MAX_MIME_TYPE_LEN: usize = 255;

/// Validate a filename for safety: no path traversal, no null bytes, bounded length.
fn validate_filename(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::BadRequest("filename cannot be empty".into()));
    }
    if name.len() > MAX_FILENAME_LEN {
        return Err(ApiError::BadRequest(format!(
            "filename too long: {} bytes (max {MAX_FILENAME_LEN})",
            name.len()
        )));
    }
    if name.contains('\0') {
        return Err(ApiError::BadRequest("filename contains null bytes".into()));
    }
    // Reject path separators and traversal
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(ApiError::BadRequest(
            "filename contains path separators or traversal sequences".into(),
        ));
    }
    Ok(())
}

/// `POST /api/v1/files` — upload a file to the local node.
async fn upload_file(
    auth: crate::auth::AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UploadRequest>,
) -> Result<Json<UploadResponse>, ApiError> {
    // Staging costs no Lightning principal. AuthUser revalidates the paired
    // grant on every request; do not use the paid-route Spend extractor here.
    if !auth.has(crate::auth::Scope::Admin) && !auth.has(crate::auth::Scope::Spend) {
        return Err(ApiError::Forbidden("file upload requires spend or admin".into()));
    }
    // Validate filename and MIME type
    validate_filename(&req.filename)?;
    if req.mime_type.len() > MAX_MIME_TYPE_LEN {
        return Err(ApiError::BadRequest(format!(
            "MIME type too long: {} bytes (max {MAX_MIME_TYPE_LEN})",
            req.mime_type.len()
        )));
    }
    if req.mime_type.contains('\0') {
        return Err(ApiError::BadRequest("MIME type contains null bytes".into()));
    }

    // Pre-check base64 string length before decoding to prevent OOM.
    // Base64 encodes 3 bytes into 4 chars, so max base64 length is ~4/3 * MAX_FILE_SIZE.
    let max_b64_len = MAX_FILE_SIZE * 4 / 3 + 64;
    if req.data_b64.len() > max_b64_len {
        return Err(ApiError::BadRequest(format!(
            "file data too large: base64 payload {} bytes (max {max_b64_len})",
            req.data_b64.len()
        )));
    }

    // Decode base64
    let data = base64::engine::general_purpose::STANDARD
        .decode(&req.data_b64)
        .map_err(|e| ApiError::BadRequest(format!("invalid base64: {e}")))?;

    if data.len() > MAX_FILE_SIZE {
        return Err(ApiError::BadRequest(format!(
            "file too large: {} bytes (max {})",
            data.len(),
            MAX_FILE_SIZE
        )));
    }

    if data.is_empty() {
        return Err(ApiError::BadRequest("file data is empty".into()));
    }

    // Compute blake3 hash
    let hash = blake3::hash(&data).to_hex().to_string();

    let file_id = format!("stage-{}", Uuid::new_v4());
    let size_bytes = u64::try_from(data.len()).unwrap_or(u64::MAX);

    let file = FileRecord {
        id: file_id.clone(),
        filename: req.filename.clone(),
        mime_type: req.mime_type,
        size_bytes,
        blake3_hash: hash.clone(),
        sender: state.identity.node_id().to_hex(),
        message_id: None,
        data,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    // Revalidate the current paired spend grant after body decoding; the
    // temporary blob never enters the permanent file table.
    state.file_staging.lock().unwrap_or_else(|e| e.into_inner())
        .insert(&state, &auth, file)?;

    state.audit_log.record(
        events::FILE_UPLOADED,
        &state.identity.node_id().to_hex(),
        Some(serde_json::json!({
            "file_id": file_id,
            "filename": req.filename,
            "size_bytes": size_bytes,
        })),
    );

    Ok(Json(UploadResponse {
        file_id,
        size_bytes,
        blake3_hash: hash,
    }))
}

async fn load_file(
    state: &AppState,
    auth: &crate::auth::AuthUser,
    id: &str,
) -> Result<Arc<FileRecord>, ApiError> {
    if id.starts_with("stage-") {
        return state
            .file_staging
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(state, auth, id)
            .ok_or_else(|| ApiError::NotFound("staged file unavailable or expired".into()));
    }
    state
        .storage
        .get_file(id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .map(Arc::new)
        .ok_or_else(|| ApiError::NotFound(format!("file {id} not found")))
}

/// Stored and staged timestamps can have different fractional precision.
fn compare_file_positions(a: &konsensus_storage::ListCursor<String>, b: &konsensus_storage::ListCursor<String>) -> std::cmp::Ordering {
    match (chrono::DateTime::parse_from_rfc3339(&a.timestamp), chrono::DateTime::parse_from_rfc3339(&b.timestamp)) {
        (Ok(a_time), Ok(b_time)) => (a_time, &a.id).cmp(&(b_time, &b.id)),
        _ => (&a.timestamp, &a.id).cmp(&(&b.timestamp, &b.id)),
    }
}

/// `GET /api/v1/files/:id` — download a file (metadata + data).
async fn download_file(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
) -> Result<Json<DownloadResponse>, ApiError> {
    let file = load_file(&state, &auth, &file_id).await?;

    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&file.data);

    Ok(Json(DownloadResponse {
        id: file.id.clone(),
        filename: file.filename.clone(),
        mime_type: file.mime_type.clone(),
        size_bytes: file.size_bytes,
        blake3_hash: file.blake3_hash.clone(),
        sender: file.sender.clone(),
        data_b64,
    }))
}

/// `GET /api/v1/files` — list file metadata.
async fn list_files(
    auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListFilesQuery>,
) -> Result<(ListDiagnostics, Json<Vec<FileResponse>>), ApiError> {
    if params.before_id.is_some() && params.before.is_none() {
        return Err(ApiError::BadRequest("before_id requires before".into()));
    }
    let cursor = params.before.map(|timestamp| konsensus_storage::ListCursor {
        timestamp, id: params.before_id.unwrap_or_default(),
    });
    let rows = state
        .storage
        .file_page_with_diagnostics(params.limit.min(MAX_FILE_LIST_LIMIT), cursor.as_ref())
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    let mut diagnostics = ListDiagnostics::from(&rows);
    let positions: std::collections::HashMap<_, _> = rows.readable_cursors.into_iter()
        .map(|at| (at.id.clone(), at)).collect();
    let position = |file: &konsensus_storage::FileMetadata| positions.get(&file.id).cloned()
        .unwrap_or_else(|| konsensus_storage::ListCursor { timestamp: file.created_at.clone(), id: file.id.clone() });
    let mut files = rows.items;
    let staged = state.file_staging.lock().unwrap_or_else(|e| e.into_inner()).list(&state, &auth);
    // The next request excludes the raw boundary. Include staged files at or
    // above it now, and defer older uploads to the source window containing them.
    files.extend(staged.into_iter().filter(|file| {
        let at = position(file);
        cursor.as_ref().is_none_or(|cursor| compare_file_positions(&at, cursor).is_lt())
            && diagnostics.continuation.as_ref().is_none_or(|raw| !compare_file_positions(&at, raw).is_lt())
    }));
    files.sort_by(|a, b| compare_file_positions(&position(b), &position(a)));
    let limit = params.limit.min(MAX_FILE_LIST_LIMIT) as usize;
    files.truncate(limit);
    // Public PostgreSQL metadata is rounded; full pages need the precise cursor
    // too. Never advance beyond a raw scan boundary over unscanned DB files.
    if limit > 0 && files.len() == limit {
        if let Some(last) = files.last() {
            let at = position(last);
            if diagnostics.next_before.as_ref().is_none_or(|raw| compare_file_positions(&at, raw).is_gt()) {
                diagnostics.next_before = Some(at);
            }
        }
    }
    Ok((diagnostics, Json(files.into_iter().map(FileResponse::from).collect())))
}

/// `DELETE /api/v1/files/:id` — delete a file.
async fn delete_file(
    _auth: ScopedAuth<Admin>,
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let staged = state.file_staging.lock().unwrap_or_else(|e| e.into_inner()).remove(&file_id);
    let deleted = if staged { true } else {
        state.storage.delete_file(&file_id).await.map_err(|e| ApiError::Storage(e.to_string()))?
    };

    if deleted {
        state.audit_log.record(
            events::FILE_DELETED,
            &_auth.node_id,
            Some(serde_json::json!({"file_id": file_id})),
        );
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

async fn send_file_observed(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
    Json(req): Json<SendFileRequest>,
) -> Result<Json<SendFileResponse>, ApiError> {
    let recipient = crate::membrane::parse_recipient(&req.recipient, false);
    let cap = req.max_total_msat;
    let result = send_file(auth, State(Arc::clone(&state)), Path(file_id), Json(req)).await;
    if let Err(e) = &result {
        state.audit_log.membrane().outbound_refused(
            e,
            recipient.as_ref(),
            Some(KIND_FILE_REF),
            cap,
        );
    }
    result
}

/// `POST /api/v1/files/:id/send` — send a file to a peer.
///
/// The node reads the file from local storage, builds a `FilePayload` JSON,
/// encrypts it via Double Ratchet, creates a UKM envelope with KIND_FILE_REF,
/// and delivers it. Same pipeline as compose_message but for files.
async fn send_file(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
    Json(req): Json<SendFileRequest>,
) -> Result<Json<SendFileResponse>, ApiError> {
    // Refuse before pricing, grant debits, staged-file claims, or ratchet changes.
    crate::error::require_money_ready(&state).await?;
    let deadline = state.file_staging.lock().unwrap_or_else(|e| e.into_inner()).deadline(&file_id);
    // Keep authorized ceilings outside the cancelled future, including any
    // separately approved re-admission recorded before its wallet dispatch.
    let ceiling = std::sync::Mutex::new(None);
    // Files are not chat: a confirmed cap refuses reconnect re-admission before
    // any quote (Some(0)), matching pre-#111 fail-closed behaviour.
    let readmission = super::messages::Readmission::for_cap(req.max_total_msat.map(|_| 0));
    let result = tokio::time::timeout_at(deadline, send_file_inner(auth, state, file_id, req, &ceiling, &readmission)).await
        .unwrap_or_else(|_| Err(ApiError::PaymentUnresolved("file send deadline exceeded; payment may have dispatched; do not retry automatically".into())));
    let approved = *ceiling.lock().unwrap_or_else(|e| e.into_inner());
    result.map_err(|error| match approved {
        Some(fee) => error.with_routing_fee(fee.saturating_add(readmission.fee_ceiling_msat())),
        None => error,
    })
}

async fn send_file_inner(
    auth: MeteredSpend, state: Arc<AppState>, file_id: String, req: SendFileRequest,
    ceiling: &std::sync::Mutex<Option<u64>>, readmission: &super::messages::Readmission,
) -> Result<Json<SendFileResponse>, ApiError> {
    // Parse recipient
    let peer_id = NodeId::from_hex(&req.recipient)
        .map_err(|e| ApiError::BadRequest(format!("invalid recipient: {e}")))?;
    let recipient = Recipient::Node(peer_id);

    // Pricing for file transfer
    let price_msat = state
        .pricing
        .get_price_msat(KIND_FILE_REF)
        .await
        .map_err(|e| ApiError::Internal(format!("pricing error: {e}")))?;

    let all_in = super::messages::caps::check_payment(&state, super::messages::caps::payable(price_msat), req.max_routing_fee_msat, req.max_total_msat)?;
    *ceiling.lock().unwrap_or_else(|e| e.into_inner()) = Some(all_in - super::messages::caps::payable(price_msat));

    // Do not retain bytes across pricing awaits: deletion or expiry could
    // otherwise release their quota while this future still owns the blob.
    let file = load_file(&state, &auth, &file_id).await?;

    // Build FilePayload JSON
    let payload = FilePayload {
        filename: file.filename.clone(),
        mime_type: file.mime_type.clone(),
        size_bytes: file.size_bytes,
        blake3_hash: file.blake3_hash.clone(),
        data_b64: base64::engine::general_purpose::STANDARD.encode(&file.data),
    };
    let payload_json = serde_json::to_vec(&payload)
        .map_err(|e| ApiError::Internal(format!("payload serialization: {e}")))?;

    // Reject budget limits before advancing the ratchet or requesting an invoice.
    let peer_key = peer_id.to_hex();
    let debit = auth.debit(
        &state,
        vec![Charge {
            recipient: peer_key.clone(),
            amount_msat: all_in,
        }],
    ).map_err(|e| e.with_routing_fee(all_in - super::messages::caps::payable(price_msat)))?.with_fee_limit(req.max_routing_fee_msat);

    // Reserve this staged blob through every await. Cap refusals leave it
    // available; an attempted send consumes it even on error/cancellation.
    let _staged_send = if file_id.starts_with("stage-") {
        Some(crate::file_staging::FileStaging::claim(&state, &auth, &file_id)
            .and_then(|file| file.ok_or_else(|| ApiError::NotFound("staged file expired".into())))
            .inspect_err(|_| debit.released(&peer_key))?)
    } else { None };

    // E2EE encrypt via Double Ratchet
    let ratchet_msg = state
        .session_manager
        .encrypt(&peer_id, &payload_json)
        .await
        .map_err(|e| {
            debit.released(&peer_key);
            ApiError::BadRequest(format!(
                "E2EE encryption failed (session may not be established): {e}"
            ))
        })?;
    let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

    // Create real payment proof — requests invoice from recipient (Principle 2).
    let mut admission = super::messages::FirstContactCharge::default();
    let paid = create_metered_payment_proof(&state, price_msat, &peer_id, &debit, readmission, Some(KIND_FILE_REF), &mut admission).await.map_err(|error| admission.error(error));
    if matches!(&paid, Err(ApiError::PaymentUnresolved(_))) && admission.readmission_blocks_message {
        debit.settled(&peer_key, admission.settled_msat.saturating_sub(admission.readmission_msat));
    } else if let Err(ApiError::PaymentProofUnavailable { amount_msat, .. }) = &paid {
        debit.settled(&peer_key, amount_msat.saturating_sub(admission.readmission_msat));
    } else {
        debit.resolve_proof(&peer_key, &paid);
    }
    let (payment_hash, preimage, amount_msat) = paid.map_err(|e| e.with_routing_fee(debit.fee_limit(&state, super::messages::caps::payable(price_msat)).saturating_add(readmission.fee_ceiling_msat())))?;
    let proof =
        konsensus_core::PaymentProof::new(payment_hash, preimage, amount_msat);
    let amount_msat = amount_msat.saturating_add(admission.settled_msat);

    // Build envelope
    let sender = *state.identity.node_id();
    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        KIND_FILE_REF, sender, recipient, ciphertext, proof,
    )
    .build();

    // Sign
    let sig = state.identity.sign(&envelope.signable_bytes());
    envelope.signature = konsensus_core::Signature::from_ed25519(&sig);

    // Store message
    state
        .storage
        .store_message(&envelope)
        .await
        .map_err(|e| ApiError::PaymentProofUnavailable { amount_msat, reason: format!("file payment settled but storing message failed: {e}") })?;

    // Update file record with message_id (best effort)
    // We don't have an update_file method, but the association is recorded
    // in the audit log below.

    state.storage.prepare_delivery(&envelope.id, &peer_id).await.map_err(|e| ApiError::PaymentProofUnavailable {
        amount_msat,
        reason: format!("file payment settled; saved envelope {} requires delivery reconciliation: {e}", envelope.id.to_hex()),
    })?;
    // Deliver
    let delivered = if state.transport.is_connected(&peer_id).await {
        state
            .transport
            .send(&peer_id, &envelope)
            .await
            .map_err(|e| ApiError::PaymentProofUnavailable { amount_msat, reason: format!("file payment settled but delivery failed: {e}") })?;
        true
    } else {
        false
    };

    // Broadcast to WebSocket
    if let Err(e) = state.ws_broadcast.send(Arc::new(crate::state::WsMessage {
        envelope: envelope.clone(),
        plaintext: None, // file payloads are not broadcast as plaintext
    })) {
        tracing::debug!(error = %e, "no WebSocket clients connected for file broadcast");
    }

    state.audit_log.record(
        events::FILE_SENT,
        &sender.to_hex(),
        Some(serde_json::json!({
            "file_id": file_id,
            "message_id": envelope.id.to_hex(),
            "filename": file.filename,
            "recipient": req.recipient,
            "delivered": delivered,
            "amount_msat": amount_msat,
            "size_bytes": file.size_bytes,
        })),
    );

    Ok(Json(SendFileResponse {
        max_routing_fee_msat: (all_in - super::messages::caps::payable(price_msat)).saturating_add(readmission.fee_ceiling_msat()),
        message_id: envelope.id.to_hex(),
        delivered,
        amount_msat,
    }))
}

/// Registers file management routes for upload, download, list, delete, and send operations.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/files", post(upload_file).get(list_files)
            .layer(axum::extract::DefaultBodyLimit::max(MAX_FILE_SIZE * 4 / 3 + 2048)))
        .route(
            "/api/v1/files/:id",
            get(download_file).delete(delete_file),
        )
        .route("/api/v1/files/:id/send", post(send_file_observed))
}

#[cfg(test)]
mod tests {
    #[test]
    fn precise_file_positions_order_submillisecond_rows_before_id_ties() {
        let cursor = |timestamp: &str, id: &str| konsensus_storage::ListCursor { timestamp: timestamp.into(), id: id.into() };
        let mut positions = [
            cursor("2026-01-01T00:00:00.123100Z", "b"),
            cursor("2026-01-01T00:00:00.123900Z", "a"),
            cursor("2026-01-01T00:00:00.12395+00:00", "stage-c"),
        ];
        positions.sort_by(|a, b| super::compare_file_positions(b, a));
        assert_eq!(positions.map(|at| at.id), ["stage-c", "a", "b"]);
    }

    use super::*;

    #[test]
    fn validate_filename_rejects_empty() {
        assert!(validate_filename("").is_err());
    }

    #[test]
    fn validate_filename_rejects_null_bytes() {
        assert!(validate_filename("file\0.txt").is_err());
    }

    #[test]
    fn validate_filename_rejects_path_traversal() {
        assert!(validate_filename("../etc/passwd").is_err());
        assert!(validate_filename("foo/bar.txt").is_err());
        assert!(validate_filename("foo\\bar.txt").is_err());
    }

    #[test]
    fn validate_filename_rejects_too_long() {
        let long_name = "a".repeat(MAX_FILENAME_LEN + 1);
        assert!(validate_filename(&long_name).is_err());
    }

    #[test]
    fn validate_filename_accepts_valid() {
        assert!(validate_filename("document.pdf").is_ok());
        assert!(validate_filename("my file (1).txt").is_ok());
        assert!(validate_filename("image.png").is_ok());
    }
}
