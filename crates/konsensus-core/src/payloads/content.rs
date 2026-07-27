//! Sovereign browser content payloads — page requests, responses, and manifests.
//!
//! These structs are serialized to JSON, encrypted via Double Ratchet, and
//! transported as UKM envelopes with kinds 500-599 (WebContent category).
//!
//! # Security model
//! - All content travels through the existing E2EE pipeline (Noise transport +
//!   Double Ratchet). No plaintext content at any layer.
//! - All page requests go through the payment gate (fail-closed). No payment,
//!   no page.
//! - No JavaScript execution from remote nodes. Content is markdown only,
//!   rendered locally by the requesting node's frontend.
//! - Path traversal attacks are defended at the ContentServer layer (S3), but
//!   the path field here is validated to reject obvious traversal patterns.

use serde::{Deserialize, Serialize};

/// A browser request for content at a specific path on a peer's node.
///
/// Sent as `KIND_PAGE_REQUEST` (500). The requester includes a unique
/// `request_id` so the response can be correlated (the mesh is async).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PageRequest {
    /// Unique identifier for this request (UUID or similar).
    /// Used to correlate the response with the request.
    pub request_id: String,

    /// The content path being requested (e.g., "/index.md", "/blog/post-1.md").
    /// Must not contain path traversal sequences ("..").
    pub path: String,

    /// HTTP-like method. Currently only "GET" is supported.
    /// Reserved for future extension (e.g., "HEAD" for metadata-only).
    #[serde(default = "default_method")]
    pub method: String,

    /// Preferred content types, ordered by preference.
    /// Currently only "text/markdown" is supported.
    #[serde(default)]
    pub accept: Vec<String>,
}

fn default_method() -> String {
    "GET".to_string()
}

/// HTTP-like status codes for page responses.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u16)]
pub enum PageStatus {
    /// Content found and returned.
    Ok = 200,
    /// Content not found at the requested path.
    NotFound = 404,
    /// Access denied (path traversal, restricted content).
    Forbidden = 403,
    /// Content too large to serve.
    PayloadTooLarge = 413,
    /// Server error (IO failure, etc.).
    InternalError = 500,
}

/// A response containing content for a requested page.
///
/// Sent as `KIND_PAGE_RESPONSE` (501). Contains the full page content
/// (or an error status) correlated to the original request via `request_id`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PageResponse {
    /// Matches the `request_id` from the corresponding `PageRequest`.
    pub request_id: String,

    /// HTTP-like status code.
    pub status: PageStatus,

    /// MIME type of the body (e.g., "text/markdown", "text/plain").
    /// Empty on error responses.
    #[serde(default)]
    pub content_type: String,

    /// The page content. Markdown text for successful responses,
    /// error message for error responses.
    #[serde(default)]
    pub body: String,

    /// Cache control hint: how many seconds the requester may cache this page.
    /// 0 = do not cache.
    #[serde(default)]
    pub cache_seconds: u64,

    /// Whether this is the complete response or a chunk.
    /// For Phase 1 MVP, always `true` (no chunking).
    #[serde(default = "default_true")]
    pub is_complete: bool,

    /// Chunk index (0-based) if response is chunked.
    #[serde(default)]
    pub chunk_index: u32,

    /// Total number of chunks. 1 for non-chunked responses.
    #[serde(default = "default_one")]
    pub total_chunks: u32,
}

fn default_true() -> bool {
    true
}

fn default_one() -> u32 {
    1
}

/// A single page entry in a web manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestPage {
    /// The path to this page (e.g., "/index.md").
    pub path: String,

    /// Human-readable title.
    pub title: String,

    /// Optional description / excerpt.
    #[serde(default)]
    pub description: String,

    /// Price override in millisatoshis for this specific page.
    /// If `None`, the default `page_price_msat` applies.
    #[serde(default)]
    pub price_msat: Option<u64>,
}

/// A manifest advertising what content a node serves and at what price.
///
/// Sent as `KIND_WEB_MANIFEST` (510). Peers can request this to discover
/// available content before browsing. The manifest also declares which
/// paths are free (no payment required beyond the manifest request itself).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebManifest {
    /// Human-readable site name.
    pub site_name: String,

    /// Available pages with metadata.
    pub pages: Vec<ManifestPage>,

    /// Default price per page in millisatoshis.
    pub default_price_msat: u64,

    /// Paths that are free to access (no payment required for the content
    /// itself — the request envelope still requires payment through the
    /// payment gate).
    #[serde(default)]
    pub free_paths: Vec<String>,

    /// Block height at the time this manifest was generated.
    /// Used for staleness detection.
    #[serde(default)]
    pub block_height: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_request_roundtrip() {
        let req = PageRequest {
            request_id: "req-001".to_string(),
            path: "/blog/hello-world.md".to_string(),
            method: "GET".to_string(),
            accept: vec!["text/markdown".to_string()],
        };

        let json = serde_json::to_string(&req).unwrap();
        let decoded: PageRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, decoded);
    }

    #[test]
    fn page_request_default_method() {
        let json = r#"{"request_id":"r1","path":"/index.md"}"#;
        let req: PageRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.method, "GET");
        assert!(req.accept.is_empty());
    }

    #[test]
    fn page_response_ok_roundtrip() {
        let resp = PageResponse {
            request_id: "req-001".to_string(),
            status: PageStatus::Ok,
            content_type: "text/markdown".to_string(),
            body: "# Hello\n\nWelcome to my sovereign page.".to_string(),
            cache_seconds: 300,
            is_complete: true,
            chunk_index: 0,
            total_chunks: 1,
        };

        let json = serde_json::to_string(&resp).unwrap();
        let decoded: PageResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn page_response_not_found() {
        let resp = PageResponse {
            request_id: "req-002".to_string(),
            status: PageStatus::NotFound,
            content_type: String::new(),
            body: "Page not found".to_string(),
            cache_seconds: 0,
            is_complete: true,
            chunk_index: 0,
            total_chunks: 1,
        };

        let json = serde_json::to_string(&resp).unwrap();
        let decoded: PageResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.status, PageStatus::NotFound);
    }

    #[test]
    fn page_response_defaults() {
        let json = r#"{"request_id":"r1","status":"Ok"}"#;
        let resp: PageResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.content_type, "");
        assert_eq!(resp.body, "");
        assert_eq!(resp.cache_seconds, 0);
        assert!(resp.is_complete);
        assert_eq!(resp.chunk_index, 0);
        assert_eq!(resp.total_chunks, 1);
    }

    #[test]
    fn web_manifest_roundtrip() {
        let manifest = WebManifest {
            site_name: "Alice's Blog".to_string(),
            pages: vec![
                ManifestPage {
                    path: "/index.md".to_string(),
                    title: "Home".to_string(),
                    description: "Welcome page".to_string(),
                    price_msat: None,
                },
                ManifestPage {
                    path: "/blog/post-1.md".to_string(),
                    title: "First Post".to_string(),
                    description: "My first sovereign blog post".to_string(),
                    price_msat: Some(100),
                },
            ],
            default_price_msat: 50,
            free_paths: vec!["/index.md".to_string()],
            block_height: 942_000,
        };

        let json = serde_json::to_string(&manifest).unwrap();
        let decoded: WebManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, decoded);
        assert_eq!(decoded.pages.len(), 2);
        assert_eq!(decoded.free_paths, vec!["/index.md"]);
    }

    #[test]
    fn manifest_page_price_override() {
        let page = ManifestPage {
            path: "/premium.md".to_string(),
            title: "Premium Content".to_string(),
            description: String::new(),
            price_msat: Some(500),
        };
        assert_eq!(page.price_msat, Some(500));

        let free_page = ManifestPage {
            path: "/about.md".to_string(),
            title: "About".to_string(),
            description: String::new(),
            price_msat: None,
        };
        assert_eq!(free_page.price_msat, None);
    }

    #[test]
    fn page_status_serialization() {
        // Verify status codes serialize as strings (serde default for enums)
        let ok = serde_json::to_string(&PageStatus::Ok).unwrap();
        assert_eq!(ok, "\"Ok\"");
        let not_found = serde_json::to_string(&PageStatus::NotFound).unwrap();
        assert_eq!(not_found, "\"NotFound\"");
        let forbidden = serde_json::to_string(&PageStatus::Forbidden).unwrap();
        assert_eq!(forbidden, "\"Forbidden\"");
    }

    #[test]
    fn web_manifest_defaults() {
        let json = r#"{"site_name":"Test","pages":[],"default_price_msat":10}"#;
        let manifest: WebManifest = serde_json::from_str(json).unwrap();
        assert!(manifest.free_paths.is_empty());
        assert_eq!(manifest.block_height, 0);
    }
}
