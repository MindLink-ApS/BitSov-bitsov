//! Hardening tests for konsensus-node — content server edge cases, mnemonic crypto
//! edge cases, and config validation boundaries.

use konsensus_core::payloads::content::{PageRequest, PageStatus};
use konsensus_node::content_server::{ContentServer, ContentServerConfig};

// ═══════════════════════════════════════════════════════════════════════════════
// CONTENT SERVER — ADVANCED EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

fn setup_content_server(
    files: Vec<(&str, &str)>,
    max_file_size: u64,
) -> (ContentServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    for (name, content) in files {
        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&path, content).unwrap();
    }
    let config = ContentServerConfig {
        content_dir: dir.path().to_path_buf(),
        max_file_size,
        cache_seconds: 300,
        site_name: "Test Node".to_string(),
    };
    let server = ContentServer::new(config).unwrap();
    (server, dir)
}

fn make_request(path: &str) -> PageRequest {
    PageRequest {
        request_id: "test".into(),
        path: path.into(),
        method: "GET".into(),
        accept: Vec::new(),
    }
}

#[test]
fn content_server_unicode_filename() {
    let (server, _dir) = setup_content_server(
        vec![("日本語.md", "# Unicode\nHello 世界")],
        1024 * 1024,
    );

    let resp = server.handle_request(&make_request("/日本語.md"));
    assert_eq!(resp.status, PageStatus::Ok);
    assert!(resp.body.contains("Unicode"));
}

#[test]
fn content_server_deeply_nested_path() {
    let (server, _dir) = setup_content_server(
        vec![("a/b/c/d/e/deep.md", "# Deep\nNested content")],
        1024 * 1024,
    );

    let resp = server.handle_request(&make_request("/a/b/c/d/e/deep.md"));
    assert_eq!(resp.status, PageStatus::Ok);
    assert!(resp.body.contains("Nested content"));
}

#[test]
fn content_server_double_slash_path() {
    let (server, _dir) = setup_content_server(
        vec![("test.md", "# Test\ncontent")],
        1024 * 1024,
    );

    let resp = server.handle_request(&make_request("//test.md"));
    // Double slash should normalize or return 404, not panic
    assert!(resp.status == PageStatus::Ok || resp.status == PageStatus::NotFound);
}

#[test]
fn content_server_encoded_traversal_rejected() {
    let (server, _dir) = setup_content_server(
        vec![("test.md", "# Test")],
        1024 * 1024,
    );

    // URL-encoded path traversal (..%2f)
    let resp = server.handle_request(&make_request("/..%2f..%2fetc%2fpasswd"));
    // Should be rejected (not found or forbidden), never Ok
    assert_ne!(resp.status, PageStatus::Ok);
}

#[test]
fn content_server_manifest_with_multiple_h1_uses_first() {
    let (server, _dir) = setup_content_server(
        vec![("multi.md", "# First Title\nContent\n# Second Title\nMore")],
        1024 * 1024,
    );

    let manifest = server.build_manifest(850_000, 25);
    let page = manifest.pages.iter().find(|p| p.path == "/multi.md");
    assert!(page.is_some());
    assert_eq!(page.unwrap().title, "First Title");
}

#[test]
fn content_server_manifest_unicode_h1() {
    let (server, _dir) = setup_content_server(
        vec![("unicode.md", "# 日本語タイトル\nBody text")],
        1024 * 1024,
    );

    let manifest = server.build_manifest(850_000, 25);
    let page = manifest.pages.iter().find(|p| p.path == "/unicode.md");
    assert!(page.is_some());
    assert_eq!(page.unwrap().title, "日本語タイトル");
}

#[test]
fn content_server_manifest_h1_with_inline_code() {
    let (server, _dir) = setup_content_server(
        vec![("code.md", "# `Hello` World\nBody")],
        1024 * 1024,
    );

    let manifest = server.build_manifest(850_000, 25);
    let page = manifest.pages.iter().find(|p| p.path == "/code.md");
    assert!(page.is_some());
    assert!(page.unwrap().title.contains("Hello"));
}

#[test]
fn content_server_many_files_manifest() {
    let mut files = Vec::new();
    for i in 0..50 {
        let name = format!("page_{i:03}.md");
        let name: &'static str = Box::leak(name.into_boxed_str());
        let content = format!("# Page {i}\nContent for page {i}");
        let content: &'static str = Box::leak(content.into_boxed_str());
        files.push((name, content));
    }

    let (server, _dir) = setup_content_server(files, 1024 * 1024);
    let manifest = server.build_manifest(850_000, 25);
    assert_eq!(manifest.pages.len(), 50);

    // Verify they're sorted deterministically
    let paths: Vec<&str> = manifest.pages.iter().map(|p| p.path.as_str()).collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted);
}

#[test]
fn content_server_binary_file_rejected_from_manifest() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("image.png"),
        &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
    )
    .unwrap();
    std::fs::write(dir.path().join("page.md"), "# Test\nContent").unwrap();

    let config = ContentServerConfig {
        content_dir: dir.path().to_path_buf(),
        max_file_size: 1024 * 1024,
        cache_seconds: 300,
        site_name: "Test".into(),
    };
    let server = ContentServer::new(config).unwrap();
    let manifest = server.build_manifest(850_000, 25);

    let has_png = manifest.pages.iter().any(|p| p.path.contains("png"));
    assert!(!has_png);
    let has_md = manifest.pages.iter().any(|p| p.path.contains("page.md"));
    assert!(has_md);
}

#[test]
fn content_server_request_id_preserved() {
    let (server, _dir) = setup_content_server(
        vec![("test.md", "# Test")],
        1024 * 1024,
    );

    let req = PageRequest {
        request_id: "unique-request-id-12345".into(),
        path: "/test.md".into(),
        method: "GET".into(),
        accept: Vec::new(),
    };

    let resp = server.handle_request(&req);
    assert_eq!(resp.request_id, "unique-request-id-12345");
}

#[test]
fn content_server_not_found_request_id_preserved() {
    let (server, _dir) = setup_content_server(vec![], 1024 * 1024);

    let req = PageRequest {
        request_id: "not-found-req".into(),
        path: "/nonexistent.md".into(),
        method: "GET".into(),
        accept: Vec::new(),
    };

    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::NotFound);
    assert_eq!(resp.request_id, "not-found-req");
}

#[test]
fn content_server_content_type_html() {
    let (server, _dir) = setup_content_server(
        vec![("page.html", "<h1>Hello</h1>")],
        1024 * 1024,
    );

    let resp = server.handle_request(&make_request("/page.html"));
    assert_eq!(resp.status, PageStatus::Ok);
    assert_eq!(resp.content_type, "text/html");
}

#[test]
fn content_server_content_type_txt() {
    let (server, _dir) = setup_content_server(
        vec![("readme.txt", "Plain text content")],
        1024 * 1024,
    );

    let resp = server.handle_request(&make_request("/readme.txt"));
    assert_eq!(resp.status, PageStatus::Ok);
    assert_eq!(resp.content_type, "text/plain");
}

#[test]
fn content_server_max_size_boundary() {
    let content_at_limit = "x".repeat(512);
    let content_over_limit = "x".repeat(513);

    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("exact.txt"), &content_at_limit).unwrap();
    std::fs::write(dir.path().join("over.txt"), &content_over_limit).unwrap();

    let config = ContentServerConfig {
        content_dir: dir.path().to_path_buf(),
        max_file_size: 512,
        cache_seconds: 300,
        site_name: "Test".into(),
    };
    let server = ContentServer::new(config).unwrap();

    let resp_exact = server.handle_request(&make_request("/exact.txt"));
    assert_eq!(resp_exact.status, PageStatus::Ok);

    let resp_over = server.handle_request(&make_request("/over.txt"));
    assert_eq!(resp_over.status, PageStatus::PayloadTooLarge);
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTENT SERVER — TRAVERSAL ATTACK VARIANTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn content_server_traversal_variants() {
    let (server, _dir) = setup_content_server(vec![("test.md", "# Test")], 1024);

    let attacks = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32",
        "/./../../etc/shadow",
        "test/../../etc/hosts",
        "\0/etc/passwd",
        "/test\0.md",
    ];

    for attack in attacks {
        let resp = server.handle_request(&make_request(attack));
        assert_ne!(
            resp.status,
            PageStatus::Ok,
            "path traversal should be rejected: {attack}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// CONTENT SERVER — LIFECYCLE EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn content_server_nonexistent_content_dir_created() {
    let dir = tempfile::tempdir().unwrap();
    let content_dir = dir.path().join("does_not_exist_yet");

    let config = ContentServerConfig {
        content_dir: content_dir.clone(),
        max_file_size: 1024,
        cache_seconds: 300,
        site_name: "Test".into(),
    };
    let server = ContentServer::new(config).unwrap();

    assert!(content_dir.exists());

    let resp = server.handle_request(&make_request("/anything.md"));
    assert_eq!(resp.status, PageStatus::NotFound);
}

#[test]
fn content_server_empty_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let config = ContentServerConfig {
        content_dir: dir.path().to_path_buf(),
        max_file_size: 1024,
        cache_seconds: 300,
        site_name: "Test".into(),
    };
    let server = ContentServer::new(config).unwrap();

    let manifest = server.build_manifest(850_000, 25);
    assert!(manifest.pages.is_empty());
    assert_eq!(manifest.default_price_msat, 25);
}

#[test]
fn content_server_manifest_site_name() {
    let (server, _dir) = setup_content_server(vec![], 1024 * 1024);
    let manifest = server.build_manifest(850_000, 25);
    assert_eq!(manifest.site_name, "Test Node");
}

#[test]
fn content_server_manifest_block_height() {
    let (server, _dir) = setup_content_server(vec![], 1024 * 1024);
    let manifest = server.build_manifest(999_999, 100);
    assert_eq!(manifest.block_height, 999_999);
    assert_eq!(manifest.default_price_msat, 100);
}

#[test]
fn content_server_markdown_content_type() {
    let (server, _dir) = setup_content_server(
        vec![("page.md", "# Markdown\nTest content")],
        1024 * 1024,
    );

    let resp = server.handle_request(&make_request("/page.md"));
    assert_eq!(resp.status, PageStatus::Ok);
    assert_eq!(resp.content_type, "text/markdown");
    assert!(resp.body.contains("# Markdown"));
}

#[test]
fn content_server_cache_seconds_from_config() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("test.md"), "# Test").unwrap();

    let config = ContentServerConfig {
        content_dir: dir.path().to_path_buf(),
        max_file_size: 1024 * 1024,
        cache_seconds: 3600,
        site_name: "Test".into(),
    };
    let server = ContentServer::new(config).unwrap();

    let resp = server.handle_request(&make_request("/test.md"));
    assert_eq!(resp.status, PageStatus::Ok);
    assert_eq!(resp.cache_seconds, 3600);
}

#[test]
fn content_server_error_response_zero_cache() {
    let (server, _dir) = setup_content_server(vec![], 1024 * 1024);

    let resp = server.handle_request(&make_request("/missing.md"));
    assert_eq!(resp.status, PageStatus::NotFound);
    assert_eq!(resp.cache_seconds, 0);
}

#[test]
fn content_server_complete_response_metadata() {
    let (server, _dir) = setup_content_server(
        vec![("test.md", "# Hello\nWorld")],
        1024 * 1024,
    );

    let resp = server.handle_request(&make_request("/test.md"));
    assert!(resp.is_complete);
    assert_eq!(resp.chunk_index, 0);
    assert_eq!(resp.total_chunks, 1);
}
