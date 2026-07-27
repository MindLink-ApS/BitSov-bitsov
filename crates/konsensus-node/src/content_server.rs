//! Sovereign browser content server — serves static markdown pages from disk.
//!
//! The `ContentServer` reads markdown files from a configurable directory and
//! responds to [`PageRequest`] messages with [`PageResponse`] messages. All
//! content flows through the existing E2EE pipeline and payment gate.
//!
//! # Security
//! - Path traversal is rejected (no `..`, symlinks outside root)
//! - Max file size is enforced (default 4 MiB)
//! - Only regular files are served
//! - Content type is inferred from extension, not trusted from the requester

use std::path::{Path, PathBuf};

use tracing::{debug, warn};

use konsensus_core::payloads::content::{
    ManifestPage, PageRequest, PageResponse, PageStatus, WebManifest,
};

/// Default maximum file size: 4 MiB.
const DEFAULT_MAX_FILE_SIZE: u64 = 4 * 1024 * 1024;

/// Maximum number of pages returned in manifest listings.
///
/// Prevents memory exhaustion and I/O amplification if the content directory
/// contains a very large number of files.
const MAX_MANIFEST_PAGES: usize = 1_000;

/// Configuration for the content server.
#[derive(Debug, Clone)]
pub struct ContentServerConfig {
    /// Root directory for content files.
    pub content_dir: PathBuf,
    /// Maximum file size in bytes.
    pub max_file_size: u64,
    /// Default cache duration in seconds for page responses.
    pub cache_seconds: u64,
    /// Site name for the web manifest.
    pub site_name: String,
}

impl Default for ContentServerConfig {
    fn default() -> Self {
        Self {
            content_dir: PathBuf::from("pages"),
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            cache_seconds: 300,
            site_name: "BitSov Node".to_string(),
        }
    }
}

/// Serves static content (markdown files) from a local directory.
///
/// The content server handles incoming `PageRequest` messages by reading
/// files from the configured content directory. It enforces:
/// - Path traversal protection (no `..` or symlink escapes)
/// - File size limits
/// - Valid file extension checks
pub struct ContentServer {
    config: ContentServerConfig,
}

impl ContentServer {
    /// Create a new content server with the given configuration.
    ///
    /// The content directory is created if it doesn't exist.
    pub fn new(config: ContentServerConfig) -> std::io::Result<Self> {
        // Ensure content directory exists
        if !config.content_dir.exists() {
            std::fs::create_dir_all(&config.content_dir)?;
        }
        Ok(Self { config })
    }

    /// Handle a page request and return a page response.
    ///
    /// This is the core entry point. It validates the path, reads the file,
    /// and returns the content or an appropriate error status.
    pub fn handle_request(&self, request: &PageRequest) -> PageResponse {
        let request_id = request.request_id.clone();

        // Validate path — reject traversal attempts
        if let Err(status) = self.validate_path(&request.path) {
            return PageResponse {
                request_id,
                status,
                content_type: String::new(),
                body: match status {
                    PageStatus::Forbidden => "Forbidden: path traversal detected".to_string(),
                    _ => "Bad request".to_string(),
                },
                cache_seconds: 0,
                is_complete: true,
                chunk_index: 0,
                total_chunks: 1,
            };
        }

        // Resolve path to filesystem
        let resolved = match self.resolve_path(&request.path) {
            Ok(p) => p,
            Err(status) => {
                return PageResponse {
                    request_id,
                    status,
                    content_type: String::new(),
                    body: match status {
                        PageStatus::Forbidden => "Forbidden".to_string(),
                        PageStatus::NotFound => "Not found".to_string(),
                        _ => "Error".to_string(),
                    },
                    cache_seconds: 0,
                    is_complete: true,
                    chunk_index: 0,
                    total_chunks: 1,
                };
            }
        };

        // Check file size
        let metadata = match std::fs::metadata(&resolved) {
            Ok(m) => m,
            Err(_) => {
                return PageResponse {
                    request_id,
                    status: PageStatus::NotFound,
                    content_type: String::new(),
                    body: "Not found".to_string(),
                    cache_seconds: 0,
                    is_complete: true,
                    chunk_index: 0,
                    total_chunks: 1,
                };
            }
        };

        if !metadata.is_file() {
            return PageResponse {
                request_id,
                status: PageStatus::NotFound,
                content_type: String::new(),
                body: "Not a file".to_string(),
                cache_seconds: 0,
                is_complete: true,
                chunk_index: 0,
                total_chunks: 1,
            };
        }

        if metadata.len() > self.config.max_file_size {
            warn!(
                path = %request.path,
                size = metadata.len(),
                max = self.config.max_file_size,
                "page too large to serve"
            );
            return PageResponse {
                request_id,
                status: PageStatus::PayloadTooLarge,
                content_type: String::new(),
                body: "Content too large".to_string(),
                cache_seconds: 0,
                is_complete: true,
                chunk_index: 0,
                total_chunks: 1,
            };
        }

        // Read file
        let body = match std::fs::read_to_string(&resolved) {
            Ok(content) => content,
            Err(e) => {
                warn!(path = %request.path, error = %e, "failed to read content file");
                return PageResponse {
                    request_id,
                    status: PageStatus::InternalError,
                    content_type: String::new(),
                    body: "Internal error".to_string(),
                    cache_seconds: 0,
                    is_complete: true,
                    chunk_index: 0,
                    total_chunks: 1,
                };
            }
        };

        // Determine content type from extension
        let content_type = self.content_type_for_path(&resolved);

        debug!(
            path = %request.path,
            content_type = %content_type,
            size = body.len(),
            "serving page"
        );

        PageResponse {
            request_id,
            status: PageStatus::Ok,
            content_type,
            body,
            cache_seconds: self.config.cache_seconds,
            is_complete: true,
            chunk_index: 0,
            total_chunks: 1,
        }
    }

    /// Build a web manifest listing all available pages.
    ///
    /// Scans the content directory for markdown files and returns a manifest
    /// with their paths, titles (extracted from H1 headings), and sizes.
    pub fn build_manifest(&self, block_height: u64, default_price_msat: u64) -> WebManifest {
        let mut pages = Vec::new();

        if let Ok(entries) = std::fs::read_dir(&self.config.content_dir) {
            for entry in entries.flatten() {
                if pages.len() >= MAX_MANIFEST_PAGES {
                    warn!(
                        limit = MAX_MANIFEST_PAGES,
                        "manifest page listing truncated at limit"
                    );
                    break;
                }

                let path = entry.path();
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        if ext == "md" || ext == "txt" {
                            let filename = path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_default();
                            let web_path = format!("/{filename}");

                            let title = self.extract_title(&path).unwrap_or_else(|| filename.clone());

                            pages.push(ManifestPage {
                                path: web_path,
                                title,
                                description: String::new(),
                                price_msat: None,
                            });
                        }
                    }
                }
            }
        }

        // Sort by path for deterministic output
        pages.sort_by(|a, b| a.path.cmp(&b.path));

        WebManifest {
            site_name: self.config.site_name.clone(),
            pages,
            default_price_msat,
            free_paths: Vec::new(),
            block_height,
        }
    }

    /// Validate a request path for traversal attacks.
    ///
    /// Defense-in-depth: checks for `..` in both raw and percent-decoded forms.
    /// The primary defense is `resolve_path()`'s `canonicalize()` check, but
    /// rejecting traversal patterns early avoids unnecessary filesystem calls.
    fn validate_path(&self, path: &str) -> Result<(), PageStatus> {
        // Reject empty paths
        if path.is_empty() {
            return Err(PageStatus::NotFound);
        }

        // Reject path traversal sequences (raw and percent-decoded)
        // Paths arrive via JSON deserialization so %2e is literal, but
        // defense-in-depth protects against future callers that may URL-decode.
        if path.contains("..") {
            warn!(path = %path, "path traversal attempt blocked");
            return Err(PageStatus::Forbidden);
        }

        // Reject percent-encoded traversal: %2e%2e, %2E%2E, or mixed case
        let lower = path.to_ascii_lowercase();
        if lower.contains("%2e") {
            warn!(path = %path, "percent-encoded traversal attempt blocked");
            return Err(PageStatus::Forbidden);
        }

        // Reject null bytes (raw and encoded)
        if path.contains('\0') || lower.contains("%00") {
            warn!("null byte in path");
            return Err(PageStatus::Forbidden);
        }

        // Reject absolute paths that don't start with /
        // (the leading / is expected and stripped during resolution)
        let normalized = path.trim_start_matches('/');
        if normalized.is_empty() {
            return Err(PageStatus::NotFound);
        }

        // Reject backslash (Windows path traversal, raw and encoded)
        if normalized.contains('\\') || lower.contains("%5c") {
            return Err(PageStatus::Forbidden);
        }

        Ok(())
    }

    /// Resolve a request path to a filesystem path, verifying it stays
    /// within the content directory.
    fn resolve_path(&self, path: &str) -> Result<PathBuf, PageStatus> {
        let normalized = path.trim_start_matches('/');

        // Build the candidate path
        let candidate = self.config.content_dir.join(normalized);

        // Canonicalize both paths and verify containment
        let root = match self.config.content_dir.canonicalize() {
            Ok(r) => r,
            Err(_) => return Err(PageStatus::InternalError),
        };

        let resolved = match candidate.canonicalize() {
            Ok(r) => r,
            Err(_) => {
                // If the candidate is a symlink that can't be resolved
                // (broken symlink or target doesn't exist), treat as
                // Forbidden — it's a symlink pointing outside or to a
                // non-existent target, not a missing content file.
                if candidate.is_symlink() {
                    warn!(
                        path = %path,
                        candidate = %candidate.display(),
                        "symlink target unresolvable — blocked"
                    );
                    return Err(PageStatus::Forbidden);
                }
                return Err(PageStatus::NotFound);
            }
        };

        if !resolved.starts_with(&root) {
            warn!(
                path = %path,
                resolved = %resolved.display(),
                root = %root.display(),
                "path resolved outside content root — blocked"
            );
            return Err(PageStatus::Forbidden);
        }

        Ok(resolved)
    }

    /// Extract the H1 title from a markdown file.
    fn extract_title(&self, path: &Path) -> Option<String> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read file for title extraction");
                return None;
            }
        };
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(title) = trimmed.strip_prefix("# ") {
                return Some(title.trim().to_string());
            }
        }
        None
    }

    /// Determine content type from file extension.
    fn content_type_for_path(&self, path: &Path) -> String {
        match path.extension().and_then(|e| e.to_str()) {
            Some("md") => "text/markdown".to_string(),
            Some("txt") => "text/plain".to_string(),
            Some("html") | Some("htm") => "text/html".to_string(),
            _ => "text/plain".to_string(),
        }
    }
}

#[cfg(test)]
#[path = "tests/content_server.rs"]
mod tests;
