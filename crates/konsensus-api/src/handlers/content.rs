//! Content management endpoints for the sovereign browser.
//!
//! These endpoints let the node operator manage pages served by the
//! ContentServer. Pages are markdown files stored in the node's content
//! directory. All endpoints require authentication.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::auth::AuthUser;
use crate::error::ApiError;
use crate::state::AppState;

/// A page in the content directory.
#[derive(Debug, Serialize)]
pub struct PageInfo {
    /// The page path (e.g., "/index.md").
    pub path: String,
    /// Page title extracted from H1 heading, or filename.
    pub title: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Last modified timestamp (milliseconds since epoch).
    pub modified_ms: u64,
    /// Content type (e.g., "text/markdown").
    pub content_type: String,
}

/// Response for the page list endpoint.
#[derive(Debug, Serialize)]
pub struct PageListResponse {
    /// Whether the content server is enabled.
    pub enabled: bool,
    /// The content directory path.
    pub content_dir: String,
    /// List of pages.
    pub pages: Vec<PageInfo>,
}

/// Request body for creating or updating a page.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PageWriteRequest {
    /// The page content (markdown text).
    pub content: String,
}

/// Response after creating/updating/deleting a page.
#[derive(Debug, Serialize)]
pub struct PageWriteResponse {
    /// The page path (e.g., "/index.md").
    pub path: String,
    /// Page title extracted from H1 heading, or filename.
    pub title: String,
    /// File size in bytes after write.
    pub size_bytes: u64,
}

/// Response for reading a single page.
#[derive(Debug, Serialize)]
pub struct PageReadResponse {
    /// The page path (e.g., "/index.md").
    pub path: String,
    /// Page title extracted from H1 heading, or filename.
    pub title: String,
    /// Full page content (markdown text).
    pub content: String,
    /// File size in bytes.
    pub size_bytes: u64,
    /// Content type (e.g., "text/markdown").
    pub content_type: String,
}

/// Web manifest response — what visitors see before browsing.
#[derive(Debug, Serialize)]
pub struct ManifestResponse {
    /// Site name.
    pub site_name: String,
    /// Available pages with paths, titles, and optional per-page pricing.
    pub pages: Vec<ManifestPageInfo>,
    /// Default price per page in millisatoshi.
    pub default_price_msat: u64,
    /// Paths that are free (no payment required).
    pub free_paths: Vec<String>,
    /// Current Bitcoin block height (for price table validity).
    pub block_height: u64,
}

/// A page entry in the manifest.
#[derive(Debug, Serialize)]
pub struct ManifestPageInfo {
    /// The page path (e.g., "/index.md").
    pub path: String,
    /// Page title extracted from H1 heading, or filename.
    pub title: String,
    /// First paragraph of content as description.
    pub description: String,
    /// Per-page price override in millisatoshis (`None` = use default).
    pub price_msat: Option<u64>,
}

/// Build content management routes.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/content/pages", get(list_pages))
        .route("/api/v1/content/manifest", get(get_manifest))
        .route("/api/v1/content/pages/*path", get(read_page))
        .route("/api/v1/content/pages/*path", put(write_page))
        .route("/api/v1/content/pages/*path", post(write_page))
        .route("/api/v1/content/pages/*path", delete(delete_page))
}

/// Get the content directory, returning an error if the content server is disabled.
fn get_content_dir(state: &AppState) -> Result<&std::path::Path, ApiError> {
    state
        .content_dir
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("content server is not enabled".to_string()))
}

/// Maximum page path length in bytes.
const MAX_PAGE_PATH_LEN: usize = 255;

/// Maximum number of pages returned in directory listings.
///
/// Prevents memory exhaustion and I/O amplification if the content directory
/// contains a very large number of files.
const MAX_PAGE_LISTING: usize = 1_000;

/// Validate a page filename — must end in .md or .txt, no path traversal.
fn validate_page_path(path: &str) -> Result<String, ApiError> {
    let clean = path.trim_start_matches('/');

    if clean.is_empty() {
        return Err(ApiError::BadRequest("empty page path".to_string()));
    }
    if clean.len() > MAX_PAGE_PATH_LEN {
        return Err(ApiError::BadRequest(format!(
            "page path too long: {} bytes (max {MAX_PAGE_PATH_LEN})",
            clean.len()
        )));
    }
    if clean.contains("..") || clean.contains('\\') || clean.contains('\0') {
        return Err(ApiError::BadRequest("invalid page path".to_string()));
    }
    if clean.contains('/') {
        return Err(ApiError::BadRequest(
            "subdirectories not supported — use flat filenames".to_string(),
        ));
    }
    if !(clean.ends_with(".md") || clean.ends_with(".txt")) {
        return Err(ApiError::BadRequest(
            "page must end in .md or .txt".to_string(),
        ));
    }

    Ok(clean.to_string())
}

/// Extract H1 title from markdown content.
fn extract_title(content: &str) -> Option<String> {
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(title) = trimmed.strip_prefix("# ") {
            return Some(title.trim().to_string());
        }
    }
    None
}

/// Content type from file extension.
fn content_type_for(filename: &str) -> &'static str {
    if filename.ends_with(".md") {
        "text/markdown"
    } else {
        "text/plain"
    }
}

/// List all pages in the content directory.
async fn list_pages(
    _user: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<PageListResponse>, ApiError> {
    let content_dir = match &state.content_dir {
        Some(dir) => dir,
        None => {
            return Ok(Json(PageListResponse {
                enabled: false,
                content_dir: String::new(),
                pages: Vec::new(),
            }));
        }
    };

    let mut pages = Vec::new();

    let entries = std::fs::read_dir(content_dir).map_err(|e| {
        warn!(error = %e, "failed to read content directory");
        ApiError::Internal(format!("failed to read content directory: {e}"))
    })?;

    for entry in entries.flatten() {
        if pages.len() >= MAX_PAGE_LISTING {
            warn!(
                limit = MAX_PAGE_LISTING,
                "content directory listing truncated at limit"
            );
            break;
        }

        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let filename = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        if !(filename.ends_with(".md") || filename.ends_with(".txt")) {
            continue;
        }

        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                warn!(file = %path.display(), error = %e, "skipping page: failed to read metadata");
                continue;
            }
        };

        let title = if filename.ends_with(".md") {
            match std::fs::read_to_string(&path) {
                Ok(c) => extract_title(&c).unwrap_or_else(|| filename.clone()),
                Err(e) => {
                    warn!(file = %path.display(), error = %e, "failed to read markdown for title extraction");
                    filename.clone()
                }
            }
        } else {
            filename.clone()
        };

        let modified_ms = match metadata.modified() {
            Ok(t) => t
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(0))
                .unwrap_or(0),
            Err(e) => {
                warn!(file = %path.display(), error = %e, "failed to read file modification time");
                0
            }
        };

        pages.push(PageInfo {
            path: format!("/{filename}"),
            title,
            size_bytes: metadata.len(),
            modified_ms,
            content_type: content_type_for(&filename).to_string(),
        });
    }

    pages.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(Json(PageListResponse {
        enabled: true,
        content_dir: content_dir.display().to_string(),
        pages,
    }))
}

/// Read a single page's content.
async fn read_page(
    _user: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(page_path): Path<String>,
) -> Result<Json<PageReadResponse>, ApiError> {
    let content_dir = get_content_dir(&state)?;
    let filename = validate_page_path(&page_path)?;

    let file_path = content_dir.join(&filename);
    if !file_path.is_file() {
        return Err(ApiError::NotFound(format!("page not found: /{filename}")));
    }

    let content = std::fs::read_to_string(&file_path).map_err(|e| {
        ApiError::Internal(format!("failed to read page: {e}"))
    })?;

    let title = extract_title(&content).unwrap_or_else(|| filename.clone());

    Ok(Json(PageReadResponse {
        path: format!("/{filename}"),
        title,
        size_bytes: content.len() as u64,
        content,
        content_type: content_type_for(&filename).to_string(),
    }))
}

/// Create or update a page.
async fn write_page(
    _user: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(page_path): Path<String>,
    Json(body): Json<PageWriteRequest>,
) -> Result<Json<PageWriteResponse>, ApiError> {
    let content_dir = get_content_dir(&state)?;
    let filename = validate_page_path(&page_path)?;

    // Enforce max page size: 4 MiB
    if body.content.len() > 4 * 1024 * 1024 {
        return Err(ApiError::BadRequest("page content too large (max 4 MiB)".to_string()));
    }

    let file_path = content_dir.join(&filename);

    // Ensure content directory exists
    if !content_dir.exists() {
        std::fs::create_dir_all(content_dir).map_err(|e| {
            ApiError::Internal(format!("failed to create content directory: {e}"))
        })?;
    }

    std::fs::write(&file_path, &body.content).map_err(|e| {
        ApiError::Internal(format!("failed to write page: {e}"))
    })?;

    let title = extract_title(&body.content).unwrap_or_else(|| filename.clone());

    Ok(Json(PageWriteResponse {
        path: format!("/{filename}"),
        title,
        size_bytes: body.content.len() as u64,
    }))
}

/// Delete a page.
async fn delete_page(
    _user: AuthUser,
    State(state): State<Arc<AppState>>,
    Path(page_path): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let content_dir = get_content_dir(&state)?;
    let filename = validate_page_path(&page_path)?;

    let file_path = content_dir.join(&filename);
    if !file_path.is_file() {
        return Err(ApiError::NotFound(format!("page not found: /{filename}")));
    }

    std::fs::remove_file(&file_path).map_err(|e| {
        ApiError::Internal(format!("failed to delete page: {e}"))
    })?;

    Ok(Json(serde_json::json!({
        "deleted": format!("/{filename}")
    })))
}

/// Get the node's web manifest — lists available pages and pricing.
///
/// This is the same data that remote peers receive via KIND_WEB_MANIFEST (510).
/// Useful for content publishers to preview what visitors will see.
async fn get_manifest(
    _user: AuthUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<ManifestResponse>, ApiError> {
    let content_dir = match &state.content_dir {
        Some(dir) => dir,
        None => {
            return Ok(Json(ManifestResponse {
                site_name: "BitSov Node".to_string(),
                pages: Vec::new(),
                default_price_msat: 0,
                free_paths: Vec::new(),
                block_height: state.chain.get_block_height().await.unwrap_or(0),
            }));
        }
    };

    let mut pages = Vec::new();

    match std::fs::read_dir(content_dir) {
        Ok(entries) => { for entry in entries.flatten() {
            if pages.len() >= MAX_PAGE_LISTING {
                tracing::warn!(
                    limit = MAX_PAGE_LISTING,
                    "manifest page listing truncated at limit"
                );
                break;
            }

            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let filename = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if !(filename.ends_with(".md") || filename.ends_with(".txt")) {
                continue;
            }

            let title = if filename.ends_with(".md") {
                std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|c| extract_title(&c))
                    .unwrap_or_else(|| filename.clone())
            } else {
                filename.clone()
            };

            pages.push(ManifestPageInfo {
                path: format!("/{filename}"),
                title,
                description: String::new(),
                price_msat: None,
            });
        } }
        Err(e) => {
            tracing::warn!(dir = %content_dir.display(), error = %e, "failed to read content directory");
        }
    }

    pages.sort_by(|a, b| a.path.cmp(&b.path));

    // Default price from web config or fallback to 50 msat
    let default_price_msat = state
        .web_page_price_msat
        .unwrap_or(50);

    let block_height = state.chain.get_block_height().await.unwrap_or(0);

    Ok(Json(ManifestResponse {
        site_name: "BitSov Node".to_string(),
        pages,
        default_price_msat,
        free_paths: Vec::new(),
        block_height,
    }))
}
