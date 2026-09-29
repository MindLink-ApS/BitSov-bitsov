//! #129 residuals R1/R2: the outstanding paid web-request table is durable
//! (a restart between paying a 500/510 and its reply keeps the binding) and
//! expired entries are swept with a bound. Real SQLite file, real gate.

use std::sync::Arc;

use sha2::{Digest, Sha256};

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::gate::{GateRejection, PaymentGate};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::kind::{KIND_PAGE_REQUEST, KIND_PAGE_RESPONSE, KIND_WEB_MANIFEST};
use konsensus_core::types::{PaymentProof, Recipient, Signature};
use konsensus_core::{reply_bound_proof, OutstandingWebRequest, OUTSTANDING_TTL_MS};
use konsensus_storage::{SqliteStorage, Storage, StorageNonceAdapter};

const REQUESTER: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SERVER: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
const OTHER: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";

fn id(m: &str) -> NodeIdentity {
    NodeIdentity::from_mnemonic(m, "").unwrap()
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis() as u64
}

fn signed(mut e: UkmEnvelope, by: &NodeIdentity) -> UkmEnvelope {
    e.signature = Signature::from_ed25519(&by.sign(&e.signable_bytes()));
    e
}

/// A paid request from `requester` to `server`.
fn request(requester: &NodeIdentity, server: &NodeIdentity, kind: u16) -> UkmEnvelope {
    let preimage = rand::random::<[u8; 32]>();
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    signed(
        konsensus_core::UkmEnvelopeBuilder::new(kind, *requester.node_id(), Recipient::Node(*server.node_id()), b"req".to_vec(), PaymentProof::new(hash, preimage, 50))
            .timestamp(now_ms())
            .build(),
        requester,
    )
}

/// `from`'s zero-amount reply bound to `req`.
fn reply(from: &NodeIdentity, requester: &NodeIdentity, req: &UkmEnvelope, kind: u16) -> UkmEnvelope {
    signed(
        konsensus_core::UkmEnvelopeBuilder::new(kind, *from.node_id(), Recipient::Node(*requester.node_id()), b"body".to_vec(), reply_bound_proof(&req.payment_proof))
            .references(vec![req.id])
            .timestamp(now_ms())
            .build(),
        from,
    )
}

fn outstanding(req: &UkmEnvelope, server: &NodeIdentity, kind: u16, expires_at_ms: u64) -> OutstandingWebRequest {
    OutstandingWebRequest { request_id: req.id, peer: *server.node_id(), expected_reply_kind: kind, expires_at_ms }
}

async fn open(path: &std::path::Path) -> Arc<SqliteStorage> {
    Arc::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap())
}

/// The requester's gate (settlement verification off, as on Mock) over `db`.
async fn verify(db: &Arc<SqliteStorage>, envelope: &UkmEnvelope, requester: &NodeIdentity) -> Result<(), GateRejection> {
    let store = StorageNonceAdapter::new(Arc::clone(db) as Arc<dyn Storage>);
    let pricing = konsensus_pricing::StaticPricingEngine::new(Default::default());
    PaymentGate::new().verify(envelope, &store, &pricing, None, None, 0.0, Some(requester.node_id())).await
}

#[tokio::test]
async fn an_honest_reply_after_a_restart_is_still_bound_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let (requester, server) = (id(REQUESTER), id(SERVER));
    let page = request(&requester, &server, KIND_PAGE_REQUEST);
    let manifest = request(&requester, &server, KIND_WEB_MANIFEST);
    {
        let db = open(&path).await;
        db.record_outgoing_web_request(&page.payment_proof.payment_hash, outstanding(&page, &server, KIND_PAGE_RESPONSE, now_ms() + OUTSTANDING_TTL_MS)).await.unwrap();
        db.record_outgoing_web_request(&manifest.payment_proof.payment_hash, outstanding(&manifest, &server, KIND_WEB_MANIFEST, now_ms() + OUTSTANDING_TTL_MS)).await.unwrap();
        db.pool().close().await;
    }
    // Node restarts between paying and the replies.
    let db = open(&path).await;
    assert!(verify(&db, &reply(&server, &requester, &page, KIND_PAGE_RESPONSE), &requester).await.is_ok());
    assert!(verify(&db, &reply(&server, &requester, &manifest, KIND_WEB_MANIFEST), &requester).await.is_ok());
    // One-shot: a fresh envelope on the same hash is back at the price floor.
    let again = reply(&server, &requester, &page, KIND_PAGE_RESPONSE);
    assert!(matches!(verify(&db, &again, &requester).await, Err(GateRejection::InsufficientPayment { .. })));
    assert!(db.take_outstanding_web_request(&page.payment_proof.payment_hash).await.unwrap().is_none());
}

#[tokio::test]
async fn prior_probes_still_refuse_after_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let (requester, server, other) = (id(REQUESTER), id(SERVER), id(OTHER));
    let [wrong_kind, wrong_peer, expired] = [(); 3].map(|_| request(&requester, &server, KIND_PAGE_REQUEST));
    {
        let db = open(&path).await;
        for (req, expires) in [(&wrong_kind, now_ms() + OUTSTANDING_TTL_MS), (&wrong_peer, now_ms() + OUTSTANDING_TTL_MS), (&expired, now_ms() - 1)] {
            db.record_outgoing_web_request(&req.payment_proof.payment_hash, outstanding(req, &server, KIND_PAGE_RESPONSE, expires)).await.unwrap();
        }
        db.pool().close().await;
    }
    let db = open(&path).await;
    // Reply of another kind: unbound, and the slot is consumed (later honest reply hits the floor).
    assert!(matches!(verify(&db, &reply(&server, &requester, &wrong_kind, KIND_WEB_MANIFEST), &requester).await, Err(GateRejection::WebReplyUnbound)));
    assert!(matches!(verify(&db, &reply(&server, &requester, &wrong_kind, KIND_PAGE_RESPONSE), &requester).await, Err(GateRejection::InsufficientPayment { .. })));
    // Another peer holding the preimage.
    assert!(matches!(verify(&db, &reply(&other, &requester, &wrong_peer, KIND_PAGE_RESPONSE), &requester).await, Err(GateRejection::WebReplyUnbound)));
    // After expiry.
    assert!(matches!(verify(&db, &reply(&server, &requester, &expired, KIND_PAGE_RESPONSE), &requester).await, Err(GateRejection::WebReplyUnbound)));
    // No entry at all (a request never recorded): price floor.
    let never = request(&requester, &server, KIND_PAGE_REQUEST);
    assert!(matches!(verify(&db, &reply(&server, &requester, &never, KIND_PAGE_RESPONSE), &requester).await, Err(GateRejection::InsufficientPayment { .. })));
}

#[tokio::test]
async fn expired_entries_are_swept_with_a_bound_and_live_ones_survive() {
    let dir = tempfile::tempdir().unwrap();
    let db = open(&dir.path().join("node.sqlite")).await;
    let (requester, server) = (id(REQUESTER), id(SERVER));
    let now = now_ms();
    let expired: Vec<_> = (0..5).map(|_| request(&requester, &server, KIND_PAGE_REQUEST)).collect();
    for (i, req) in expired.iter().enumerate() {
        db.record_outgoing_web_request(&req.payment_proof.payment_hash, outstanding(req, &server, KIND_PAGE_RESPONSE, now - 1000 + i as u64)).await.unwrap();
    }
    let live = request(&requester, &server, KIND_PAGE_REQUEST);
    db.record_outgoing_web_request(&live.payment_proof.payment_hash, outstanding(&live, &server, KIND_PAGE_RESPONSE, now + OUTSTANDING_TTL_MS)).await.unwrap();
    // Bounded: at most `max` per sweep, oldest first.
    assert_eq!(db.sweep_outstanding_web_requests(now, 3).await.unwrap(), 3);
    assert!(db.take_outstanding_web_request(&expired[0].payment_proof.payment_hash).await.unwrap().is_none());
    assert_eq!(db.sweep_outstanding_web_requests(now, 3).await.unwrap(), 2);
    assert_eq!(db.sweep_outstanding_web_requests(now, 3).await.unwrap(), 0);
    let kept = db.take_outstanding_web_request(&live.payment_proof.payment_hash).await.unwrap().unwrap();
    assert_eq!(kept, outstanding(&live, &server, KIND_PAGE_RESPONSE, now + OUTSTANDING_TTL_MS));
    // Re-recording the same hash replaces the row rather than failing.
    db.record_outgoing_web_request(&live.payment_proof.payment_hash, outstanding(&live, &server, KIND_PAGE_RESPONSE, now + 1)).await.unwrap();
    db.record_outgoing_web_request(&live.payment_proof.payment_hash, outstanding(&live, &server, KIND_PAGE_RESPONSE, now + 2)).await.unwrap();
    assert_eq!(db.take_outstanding_web_request(&live.payment_proof.payment_hash).await.unwrap().unwrap().expires_at_ms, now + 2);
}
