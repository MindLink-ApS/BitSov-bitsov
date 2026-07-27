use super::*;
use tempfile::TempDir;

fn setup() -> (TempDir, ContentServer) {
    let dir = TempDir::new().unwrap();
    let config = ContentServerConfig {
        content_dir: dir.path().to_path_buf(),
        max_file_size: 1024,
        cache_seconds: 300,
        site_name: "Test Site".to_string(),
    };
    let server = ContentServer::new(config).unwrap();
    (dir, server)
}

#[test]
fn serve_markdown_file() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("hello.md"), "# Hello World\n\nWelcome!").unwrap();

    let req = PageRequest {
        request_id: "r1".to_string(),
        path: "/hello.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::Ok);
    assert_eq!(resp.request_id, "r1");
    assert_eq!(resp.content_type, "text/markdown");
    assert!(resp.body.contains("Hello World"));
    assert!(resp.is_complete);
    assert_eq!(resp.cache_seconds, 300);
}

#[test]
fn not_found() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "r2".to_string(),
        path: "/nonexistent.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::NotFound);
}

#[test]
fn path_traversal_blocked() {
    let (dir, server) = setup();
    // Create a file outside the content dir
    std::fs::write(dir.path().join("secret.txt"), "top secret").unwrap();

    let req = PageRequest {
        request_id: "r3".to_string(),
        path: "/../secret.txt".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::Forbidden);
}

#[test]
fn double_dot_rejected() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "r4".to_string(),
        path: "/../../etc/passwd".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::Forbidden);
}

#[test]
fn null_byte_rejected() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "r5".to_string(),
        path: "/file\0.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::Forbidden);
}

#[test]
fn file_too_large() {
    let (dir, server) = setup();
    // Config has max 1024 bytes
    let big_content = "x".repeat(2000);
    std::fs::write(dir.path().join("big.md"), &big_content).unwrap();

    let req = PageRequest {
        request_id: "r6".to_string(),
        path: "/big.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::PayloadTooLarge);
}

#[test]
fn empty_path() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "r7".to_string(),
        path: "".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::NotFound);
}

#[test]
fn root_path_only() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "r8".to_string(),
        path: "/".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::NotFound);
}

#[test]
fn manifest_lists_files() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("index.md"), "# Home\n\nWelcome").unwrap();
    std::fs::write(dir.path().join("about.md"), "# About\n\nInfo").unwrap();
    std::fs::write(dir.path().join("notes.txt"), "Some notes").unwrap();
    std::fs::write(dir.path().join("image.png"), &[0u8; 10]).unwrap(); // not served

    let manifest = server.build_manifest(942_000, 50);

    assert_eq!(manifest.site_name, "Test Site");
    assert_eq!(manifest.default_price_msat, 50);
    assert_eq!(manifest.block_height, 942_000);
    // Should include .md and .txt files, not .png
    assert_eq!(manifest.pages.len(), 3);

    let paths: Vec<&str> = manifest.pages.iter().map(|p| p.path.as_str()).collect();
    assert!(paths.contains(&"/about.md"));
    assert!(paths.contains(&"/index.md"));
    assert!(paths.contains(&"/notes.txt"));
}

#[test]
fn manifest_extracts_h1_title() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("post.md"), "# My Great Post\n\nContent here.").unwrap();

    let manifest = server.build_manifest(0, 50);
    assert_eq!(manifest.pages.len(), 1);
    assert_eq!(manifest.pages[0].title, "My Great Post");
}

#[test]
fn text_file_served_as_plain() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("notes.txt"), "plain text notes").unwrap();

    let req = PageRequest {
        request_id: "r9".to_string(),
        path: "/notes.txt".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::Ok);
    assert_eq!(resp.content_type, "text/plain");
    assert_eq!(resp.body, "plain text notes");
}

#[test]
fn backslash_rejected() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "r10".to_string(),
        path: "/..\\etc\\passwd".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    assert_eq!(resp.status, PageStatus::Forbidden);
}

#[test]
fn creates_content_dir_if_missing() {
    let dir = TempDir::new().unwrap();
    let pages_dir = dir.path().join("subdir").join("pages");
    assert!(!pages_dir.exists());

    let config = ContentServerConfig {
        content_dir: pages_dir.clone(),
        ..ContentServerConfig::default()
    };
    let _server = ContentServer::new(config).unwrap();

    assert!(pages_dir.exists());
}

// ─── Size boundary tests ────────────────────────────────────────────────

#[test]
fn file_exactly_at_size_limit_succeeds() {
    let (dir, server) = setup();
    // Config max is 1024 bytes
    let content = "x".repeat(1024);
    std::fs::write(dir.path().join("exact.md"), &content).unwrap();

    let req = PageRequest {
        request_id: "size1".to_string(),
        path: "/exact.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Ok);
    assert_eq!(resp.body.len(), 1024);
}

#[test]
fn file_one_byte_over_limit_rejected() {
    let (dir, server) = setup();
    let content = "x".repeat(1025);
    std::fs::write(dir.path().join("over.md"), &content).unwrap();

    let req = PageRequest {
        request_id: "size2".to_string(),
        path: "/over.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::PayloadTooLarge);
}

#[test]
fn empty_file_served_ok() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("empty.md"), "").unwrap();

    let req = PageRequest {
        request_id: "empty".to_string(),
        path: "/empty.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Ok);
    assert!(resp.body.is_empty());
}

// ─── Path traversal variant tests ───────────────────────────────────────

#[test]
fn dot_dot_in_middle_rejected() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "trav1".to_string(),
        path: "/subdir/../../../etc/passwd".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Forbidden);
}

#[test]
fn null_byte_in_middle_rejected() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "null".to_string(),
        path: "/legit\0/../etc/passwd".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Forbidden);
}

#[test]
fn whitespace_only_path_not_found() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "ws".to_string(),
        path: "/   ".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    // Whitespace path resolves to non-existent file
    assert_eq!(resp.status, PageStatus::NotFound);
}

#[test]
fn very_long_path_not_found() {
    let (_dir, server) = setup();

    let long_path = format!("/{}", "a".repeat(4096));
    let req = PageRequest {
        request_id: "long".to_string(),
        path: long_path,
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    // Should not crash — just return not found
    assert_eq!(resp.status, PageStatus::NotFound);
}

#[cfg(unix)]
#[test]
fn symlink_escape_blocked() {
    let (dir, server) = setup();

    // Create a symlink inside content_dir pointing to /etc/hostname
    let symlink_path = dir.path().join("escape.md");
    std::os::unix::fs::symlink("/etc/hostname", &symlink_path).unwrap();

    let req = PageRequest {
        request_id: "symlink".to_string(),
        path: "/escape.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);

    // canonicalize() resolves the symlink to /etc/hostname, which is
    // outside content_dir — should be Forbidden
    assert_eq!(resp.status, PageStatus::Forbidden);
}

#[test]
fn directory_rejected_not_served() {
    let (dir, server) = setup();

    // Create a subdirectory (not a file)
    std::fs::create_dir_all(dir.path().join("subdir")).unwrap();

    let req = PageRequest {
        request_id: "dir".to_string(),
        path: "/subdir".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::NotFound);
    assert_eq!(resp.body, "Not a file");
}

// ─── Content type tests ─────────────────────────────────────────────────

#[test]
fn html_file_served_with_correct_type() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("page.html"), "<h1>Hello</h1>").unwrap();

    let req = PageRequest {
        request_id: "html".to_string(),
        path: "/page.html".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Ok);
    assert_eq!(resp.content_type, "text/html");
}

#[test]
fn unknown_extension_defaults_to_plain() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("data.json"), "{}").unwrap();

    let req = PageRequest {
        request_id: "json".to_string(),
        path: "/data.json".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Ok);
    assert_eq!(resp.content_type, "text/plain");
}

// ─── Manifest edge case tests ───────────────────────────────────────────

#[test]
fn manifest_empty_directory() {
    let (_dir, server) = setup();

    let manifest = server.build_manifest(1_000_000, 100);
    assert_eq!(manifest.pages.len(), 0);
    assert_eq!(manifest.site_name, "Test Site");
}

#[test]
fn manifest_file_without_h1_uses_filename() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("no-heading.md"), "Just some text without a heading.").unwrap();

    let manifest = server.build_manifest(0, 50);
    assert_eq!(manifest.pages.len(), 1);
    // Should fallback to filename as title
    assert_eq!(manifest.pages[0].title, "no-heading.md");
}

#[test]
fn manifest_ignores_non_text_files() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("image.png"), &[0u8; 10]).unwrap();
    std::fs::write(dir.path().join("data.json"), "{}").unwrap();
    std::fs::write(dir.path().join("binary.bin"), &[0xFF; 10]).unwrap();
    std::fs::write(dir.path().join("actual.md"), "# Real Page").unwrap();

    let manifest = server.build_manifest(0, 50);
    assert_eq!(manifest.pages.len(), 1);
    assert_eq!(manifest.pages[0].path, "/actual.md");
}

#[test]
fn percent_encoded_traversal_rejected() {
    let (_dir, server) = setup();

    // %2e%2e = ".." URL-encoded
    let req = PageRequest {
        request_id: "enc1".to_string(),
        path: "/%2e%2e/etc/passwd".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Forbidden);

    // Mixed case: %2E%2e
    let req2 = PageRequest {
        request_id: "enc2".to_string(),
        path: "/%2E%2e/etc/passwd".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp2 = server.handle_request(&req2);
    assert_eq!(resp2.status, PageStatus::Forbidden);
}

#[test]
fn percent_encoded_null_byte_rejected() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "null1".to_string(),
        path: "/test%00.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Forbidden);
}

#[test]
fn percent_encoded_backslash_rejected() {
    let (_dir, server) = setup();

    let req = PageRequest {
        request_id: "bs1".to_string(),
        path: "/..%5c..%5cetc/passwd".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Forbidden);
}

#[test]
fn manifest_sort_order_deterministic() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("z-last.md"), "# Z").unwrap();
    std::fs::write(dir.path().join("a-first.md"), "# A").unwrap();
    std::fs::write(dir.path().join("m-middle.md"), "# M").unwrap();

    let m1 = server.build_manifest(0, 50);
    let m2 = server.build_manifest(0, 50);

    // Same order both times
    let paths1: Vec<&str> = m1.pages.iter().map(|p| p.path.as_str()).collect();
    let paths2: Vec<&str> = m2.pages.iter().map(|p| p.path.as_str()).collect();
    assert_eq!(paths1, paths2);

    // Sorted alphabetically
    assert_eq!(paths1, vec!["/a-first.md", "/m-middle.md", "/z-last.md"]);
}

/// H1 extraction only matches lines that START with "# ", not mid-line occurrences.
#[test]
fn extract_title_ignores_mid_line_hash() {
    let (dir, server) = setup();
    std::fs::write(
        dir.path().join("tricky.md"),
        "This has # Not A Title in the middle\n\n# Real Title\n\nBody text.",
    )
    .unwrap();

    let manifest = server.build_manifest(0, 50);
    let page = manifest.pages.iter().find(|p| p.path == "/tricky.md").unwrap();
    assert_eq!(page.title, "Real Title");
}

/// File with no H1 heading falls back to filename for title.
#[test]
fn extract_title_no_h1_falls_back_to_filename() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("no-heading.md"), "Just body text.\nNo heading here.").unwrap();

    let manifest = server.build_manifest(0, 50);
    let page = manifest.pages.iter().find(|p| p.path == "/no-heading.md").unwrap();
    assert_eq!(page.title, "no-heading.md", "should fall back to filename when no H1");
}

/// Filename with spaces is served correctly.
#[test]
fn serve_file_with_spaces_in_name() {
    let (dir, server) = setup();
    std::fs::write(dir.path().join("my document.md"), "# Spaced\n\nContent").unwrap();

    let req = PageRequest {
        request_id: "sp1".to_string(),
        path: "/my document.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::Ok);
    assert!(resp.body.contains("Content"));
}

/// Very long filename (within OS limits) returns NotFound, not a crash.
#[test]
fn very_long_filename_returns_not_found() {
    let (_dir, server) = setup();
    let long_name = format!("/{}.md", "a".repeat(300));

    let req = PageRequest {
        request_id: "long1".to_string(),
        path: long_name,
        method: "GET".to_string(),
        accept: vec![],
    };
    let resp = server.handle_request(&req);
    assert_eq!(resp.status, PageStatus::NotFound);
}

// ─── Manifest listing cap tests ────────────────────────────────────────

#[test]
fn manifest_capped_at_max_pages() {
    let dir = TempDir::new().unwrap();
    let config = ContentServerConfig {
        content_dir: dir.path().to_path_buf(),
        max_file_size: 1024,
        cache_seconds: 300,
        site_name: "Cap Test".to_string(),
    };
    let server = ContentServer::new(config).unwrap();

    // Create more files than MAX_MANIFEST_PAGES
    let count = MAX_MANIFEST_PAGES + 50;
    for i in 0..count {
        std::fs::write(dir.path().join(format!("page_{i:05}.md")), format!("# Page {i}"))
            .unwrap();
    }

    let manifest = server.build_manifest(0, 50);
    assert_eq!(manifest.pages.len(), MAX_MANIFEST_PAGES);
}

#[test]
fn manifest_under_cap_returns_all() {
    let (dir, server) = setup();
    for i in 0..5 {
        std::fs::write(dir.path().join(format!("p{i}.md")), format!("# P{i}")).unwrap();
    }

    let manifest = server.build_manifest(0, 50);
    assert_eq!(manifest.pages.len(), 5);
}
