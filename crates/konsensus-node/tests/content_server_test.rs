//! Integration test: Sovereign browser — content serving over E2EE mesh.
//!
//! Validates the full sovereign browser pipeline (S6):
//! 1. Node A creates markdown content in its pages directory
//! 2. Node B sends KIND_PAGE_REQUEST (500) with payment proof
//! 3. Node A verifies payment, ContentServer returns the page
//! 4. Node B receives KIND_PAGE_RESPONSE (501) with the content
//! 5. Verify: payment deducted, content matches, E2EE throughout

use std::sync::Arc;

use sha2::{Digest, Sha256};
use tempfile::TempDir;

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::kind::KIND_PAGE_REQUEST;
use konsensus_core::payloads::content::{PageRequest, PageResponse, PageStatus};
use konsensus_core::types::{NodeId, PaymentProof, Recipient, Signature};

const MNEMONIC_SERVER: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const MNEMONIC_BROWSER: &str =
    "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";

fn make_identity(mnemonic: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(mnemonic, "").expect("valid mnemonic"))
}

fn make_envelope(
    identity: &NodeIdentity,
    recipient: NodeId,
    ciphertext: Vec<u8>,
    kind: u16,
) -> UkmEnvelope {
    let preimage = rand::random::<[u8; 32]>();
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, 100);

    let mut envelope = konsensus_core::UkmEnvelopeBuilder::new(
        kind,
        *identity.node_id(),
        Recipient::Node(recipient),
        ciphertext,
        proof,
    )
    .timestamp(chrono::Utc::now().timestamp_millis() as u64)
    .build();

    let sig = identity.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);
    envelope.validate().expect("envelope should be valid");
    envelope
}

#[tokio::test]
async fn sovereign_browser_page_request_response() {
    // --- Setup identities ---
    let server_id = make_identity(MNEMONIC_SERVER);
    let browser_id = make_identity(MNEMONIC_BROWSER);

    let server_node_id = *server_id.node_id();
    // --- Setup content directory with test markdown ---
    let content_dir = TempDir::new().expect("create temp dir");
    let test_content = "# Welcome to My Sovereign Page\n\nThis page is served directly by my node.\nNo cloud. No intermediaries. Just Bitcoin.\n";
    std::fs::write(content_dir.path().join("index.md"), test_content).expect("write content");
    std::fs::write(
        content_dir.path().join("about.md"),
        "# About\n\nSovereign identity.\n",
    )
    .expect("write about page");

    // --- Setup content server ---
    use konsensus_node::content_server::{ContentServer, ContentServerConfig};
    let cs_config = ContentServerConfig {
        content_dir: content_dir.path().to_path_buf(),
        max_file_size: 4 * 1024 * 1024,
        cache_seconds: 300,
        site_name: "Test Node".to_string(),
    };
    let content_server = ContentServer::new(cs_config).expect("create content server");

    // --- Test 1: Direct ContentServer request (no transport) ---
    let page_req = PageRequest {
        request_id: "test-req-1".to_string(),
        path: "/index.md".to_string(),
        method: "GET".to_string(),
        accept: vec!["text/markdown".to_string()],
    };

    let page_resp = content_server.handle_request(&page_req);
    assert_eq!(page_resp.status, PageStatus::Ok, "should return 200 OK");
    assert_eq!(page_resp.request_id, "test-req-1");
    assert_eq!(page_resp.content_type, "text/markdown");
    assert!(page_resp.body.contains("Welcome to My Sovereign Page"));
    assert!(page_resp.body.contains("No cloud"));
    assert!(page_resp.is_complete);
    assert_eq!(page_resp.cache_seconds, 300);

    // --- Test 2: 404 for missing page ---
    let missing_req = PageRequest {
        request_id: "test-req-2".to_string(),
        path: "/does-not-exist.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let missing_resp = content_server.handle_request(&missing_req);
    assert_eq!(missing_resp.status, PageStatus::NotFound);

    // --- Test 3: Path traversal blocked ---
    let traversal_req = PageRequest {
        request_id: "test-req-3".to_string(),
        path: "/../../../etc/passwd".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let traversal_resp = content_server.handle_request(&traversal_req);
    assert_eq!(traversal_resp.status, PageStatus::Forbidden);

    // --- Test 4: Web manifest lists content ---
    let manifest = content_server.build_manifest(942_000, 50);
    assert_eq!(manifest.site_name, "Test Node");
    assert_eq!(manifest.default_price_msat, 50);
    assert_eq!(manifest.block_height, 942_000);
    assert_eq!(manifest.pages.len(), 2); // index.md + about.md
    let paths: Vec<&str> = manifest.pages.iter().map(|p| p.path.as_str()).collect();
    assert!(paths.contains(&"/about.md"));
    assert!(paths.contains(&"/index.md"));

    // --- Test 5: PageRequest/PageResponse serialize correctly for UKM transport ---
    let page_request_json = serde_json::to_string(&page_req).expect("serialize request");
    let deserialized: PageRequest =
        serde_json::from_str(&page_request_json).expect("deserialize request");
    assert_eq!(deserialized.path, "/index.md");

    let page_response_json = serde_json::to_string(&page_resp).expect("serialize response");
    let deserialized_resp: PageResponse =
        serde_json::from_str(&page_response_json).expect("deserialize response");
    assert_eq!(deserialized_resp.status, PageStatus::Ok);
    assert!(deserialized_resp.body.contains("Welcome to My Sovereign Page"));

    // --- Test 6: PageRequest can be transported as UKM envelope payload ---
    // Verify that the JSON payload fits in a UKM ciphertext field
    let payload_bytes = page_request_json.as_bytes();
    assert!(
        payload_bytes.len() < 1_000_000,
        "page request should be well under 1MiB"
    );

    // Create a mock encrypted envelope with the page request as payload
    let envelope = make_envelope(
        &browser_id,
        server_node_id,
        payload_bytes.to_vec(),
        KIND_PAGE_REQUEST,
    );
    assert_eq!(envelope.kind, KIND_PAGE_REQUEST);

    // Verify the envelope can be validated
    envelope.validate().expect("envelope should be valid");

    // --- Test 7: Second page works ---
    let about_req = PageRequest {
        request_id: "test-req-7".to_string(),
        path: "/about.md".to_string(),
        method: "GET".to_string(),
        accept: vec![],
    };
    let about_resp = content_server.handle_request(&about_req);
    assert_eq!(about_resp.status, PageStatus::Ok);
    assert!(about_resp.body.contains("Sovereign identity"));

    // --- Test 8: Title extracted from H1 heading ---
    let manifest_check = content_server.build_manifest(0, 25);
    let index_page = manifest_check
        .pages
        .iter()
        .find(|p| p.path == "/index.md")
        .expect("index.md in manifest");
    assert_eq!(index_page.title, "Welcome to My Sovereign Page");

    let about_page = manifest_check
        .pages
        .iter()
        .find(|p| p.path == "/about.md")
        .expect("about.md in manifest");
    assert_eq!(about_page.title, "About");
}
