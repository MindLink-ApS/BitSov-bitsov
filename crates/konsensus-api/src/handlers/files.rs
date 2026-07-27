//! File endpoints — upload, download, list, send, and delete files.
//!
//! Files are stored as encrypted blobs in the storage backend. The node
//! handles E2EE encryption for file transfer — the frontend sends raw
//! file bytes (base64-encoded), and the node encrypts them via Double
//! Ratchet before transmission. Received files are decrypted and stored.
//!
//! File transfer uses `KIND_FILE_REF` (200) UKM envelopes. The plaintext
//! payload is a JSON `FilePayload` containing metadata + base64 file data.

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
use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::handlers::messages::create_payment_proof;
use crate::state::AppState;

/// Maximum file size: 4 MiB (fits within 16 MiB wire frame with overhead).
const MAX_FILE_SIZE: usize = 4 * 1024 * 1024;

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
}

fn default_file_limit() -> u32 {
    50
}

/// Request to send a file to a peer.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendFileRequest {
    /// Recipient node ID (hex).
    pub recipient: String,
}

/// Response after sending a file.
#[derive(Serialize)]
pub struct SendFileResponse {
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
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Json(req): Json<UploadRequest>,
) -> Result<Json<UploadResponse>, ApiError> {
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

    let file_id = Uuid::new_v4().to_string();
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
        created_at: String::new(), // default from DB
    };

    state
        .storage
        .store_file(&file)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

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

/// `GET /api/v1/files/:id` — download a file (metadata + data).
async fn download_file(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
) -> Result<Json<DownloadResponse>, ApiError> {
    let file = state
        .storage
        .get_file(&file_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("file {file_id} not found")))?;

    let data_b64 = base64::engine::general_purpose::STANDARD.encode(&file.data);

    Ok(Json(DownloadResponse {
        id: file.id,
        filename: file.filename,
        mime_type: file.mime_type,
        size_bytes: file.size_bytes,
        blake3_hash: file.blake3_hash,
        sender: file.sender,
        data_b64,
    }))
}

/// `GET /api/v1/files` — list file metadata.
async fn list_files(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListFilesQuery>,
) -> Result<Json<Vec<FileResponse>>, ApiError> {
    let files = state
        .storage
        .list_files(params.limit.min(MAX_FILE_LIST_LIMIT))
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    Ok(Json(files.into_iter().map(FileResponse::from).collect()))
}

/// `DELETE /api/v1/files/:id` — delete a file.
async fn delete_file(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let deleted = state
        .storage
        .delete_file(&file_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    if deleted {
        state.audit_log.record(
            events::FILE_DELETED,
            &_auth.node_id,
            Some(serde_json::json!({"file_id": file_id})),
        );
    }

    Ok(Json(serde_json::json!({ "deleted": deleted })))
}

/// `POST /api/v1/files/:id/send` — send a file to a peer.
///
/// The node reads the file from local storage, builds a `FilePayload` JSON,
/// encrypts it via Double Ratchet, creates a UKM envelope with KIND_FILE_REF,
/// and delivers it. Same pipeline as compose_message but for files.
async fn send_file(
    _auth: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(file_id): Path<String>,
    Json(req): Json<SendFileRequest>,
) -> Result<Json<SendFileResponse>, ApiError> {
    // Load the file
    let file = state
        .storage
        .get_file(&file_id)
        .await
        .map_err(|e| ApiError::Storage(e.to_string()))?
        .ok_or_else(|| ApiError::NotFound(format!("file {file_id} not found")))?;

    // Parse recipient
    let peer_id = NodeId::from_hex(&req.recipient)
        .map_err(|e| ApiError::BadRequest(format!("invalid recipient: {e}")))?;
    let recipient = Recipient::Node(peer_id);

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

    // E2EE encrypt via Double Ratchet
    let ratchet_msg = state
        .session_manager
        .encrypt(&peer_id, &payload_json)
        .await
        .map_err(|e| {
            ApiError::BadRequest(format!(
                "E2EE encryption failed (session may not be established): {e}"
            ))
        })?;
    let ciphertext = ratchet_message_to_bytes(&ratchet_msg);

    // Pricing for file transfer
    let price_msat = state
        .pricing
        .get_price_msat(KIND_FILE_REF)
        .await
        .map_err(|e| ApiError::Internal(format!("pricing error: {e}")))?;

    // Create real payment proof — requests invoice from recipient (Principle 2).
    let (payment_hash, preimage, amount_msat) =
        create_payment_proof(&state, price_msat, &peer_id).await?;
    let proof =
        konsensus_core::PaymentProof::new(payment_hash, preimage, amount_msat);

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
        .map_err(|e| ApiError::Storage(e.to_string()))?;

    // Update file record with message_id (best effort)
    // We don't have an update_file method, but the association is recorded
    // in the audit log below.

    // Deliver
    let delivered = if state.transport.is_connected(&peer_id).await {
        state
            .transport
            .send(&peer_id, &envelope)
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        true
    } else {
        if let Err(e) = state
            .storage
            .queue_pending_delivery(&envelope.id, &peer_id)
            .await
        {
            tracing::warn!(error = %e, "failed to queue pending file delivery");
        }
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
        message_id: envelope.id.to_hex(),
        delivered,
        amount_msat,
    }))
}

/// Registers file management routes for upload, download, list, delete, and send operations.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/files", post(upload_file).get(list_files))
        .route(
            "/api/v1/files/:id",
            get(download_file).delete(delete_file),
        )
        .route("/api/v1/files/:id/send", post(send_file))
}

#[cfg(test)]
mod tests {
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
