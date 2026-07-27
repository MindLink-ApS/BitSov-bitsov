//! DBH2 — the sibling authority-listing queries that DBH1 (`list_peers`) missed
//! are unbounded, so the durable authorities they back survive a >1000-row mesh.
//!
//! Before DBH2 both of these FAILED:
//! - `list_sessions()` capped at `LIMIT 1000`, silently dropping the overflow
//!   E2EE ratchet state that `restore_sessions()` resumes at boot (the cap
//!   ordered `updated_at DESC`, so it discarded the *oldest* sessions first).
//! - `get_pending_peers()` capped at `LIMIT 1000`, silently never enumerating the
//!   overflow recipients of the durable outbound delivery queue, so their
//!   already-accepted messages were never flushed on reconnect.
//!
//! Both are Principle-2 fail-opens at scale, the same shape as the `list_peers`
//! truncation DBH1 fixed. (`get_room_members` had a `LIMIT 10000`; its uncap is
//! proven by `get_room_members_returns_more_than_10000` below — a live >10000-row
//! seed that actually crosses the old cap — backed by the `dbh2_guard`
//! string-assertion unit tests in `sqlite.rs` / `postgres.rs`.)
//!
//! These tests exercise the SQLite backend live. The Postgres backend shares the
//! identical query constants and is guarded by the `dbh2_guard` string-assertion
//! unit tests in `postgres.rs` (CI has no Postgres service; the true Postgres
//! proof is the operator's GA-drill against a live Postgres node).

use konsensus_core::types::{NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_core::{UkmEnvelope, UkmEnvelopeBuilder};
use konsensus_storage::{SqliteStorage, Storage};

/// Number of rows to seed — chosen to exceed the old `LIMIT 1000` cap.
const N: u32 = 1500;

/// 1500 distinct `NodeId`s. The `make_node_id(seed: u8)` helper used elsewhere
/// only yields 256 distinct ids, so derive from a 32-byte big-endian counter
/// instead — DBH2 is specifically about the >1000 regime.
fn node_id_n(i: u32) -> NodeId {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&i.to_be_bytes());
    NodeId::from_bytes(bytes)
}

/// A unique envelope per `i`: the ciphertext embeds `i`, so `MessageId::compute`
/// yields a distinct id for every row (the `pending_deliveries` PK is
/// `(message_id, recipient_id)` and `message_id` is a FK into `messages`).
fn envelope_n(i: u32) -> UkmEnvelope {
    let sender = node_id_n(0);
    let recipient = Recipient::Node(node_id_n(i));
    let preimage = [42u8; 32];
    let hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(preimage).into()
    };
    let proof = PaymentProof::new(hash, preimage, 100);
    let ciphertext = format!("encrypted-pending-{i}").into_bytes();
    UkmEnvelopeBuilder::new(0, sender, recipient, ciphertext, proof)
        .timestamp(1_700_000_000 + u64::from(i))
        .signature(Signature::from_bytes([0u8; 64]))
        .nonce(Nonce::from_bytes([i as u8; 24]))
        .build()
}

/// Path (a): `list_sessions()` is what `restore_sessions()` reads at boot to
/// resume every E2EE session. Before DBH2 this returned 1000; after DBH2 it
/// returns all 1500.
#[tokio::test]
async fn list_sessions_returns_more_than_1000() {
    let db = SqliteStorage::in_memory().await.unwrap();

    for i in 0..N {
        // The blob content is opaque to storage; a per-peer marker is enough.
        db.store_session(&node_id_n(i), format!("ratchet-{i}").as_bytes())
            .await
            .unwrap();
    }

    let sessions = db.list_sessions().await.unwrap();
    assert_eq!(
        sessions.len() as u32,
        N,
        "list_sessions must return all {N} sessions — a LIMIT here drops resumable \
         E2EE ratchet state at boot (DBH2 fail-open)"
    );
}

/// Path (b): `get_pending_peers()` enumerates every distinct recipient with
/// queued mail in the durable delivery queue. Before DBH2 this returned 1000;
/// after DBH2 it returns all 1500 distinct recipients.
#[tokio::test]
async fn get_pending_peers_returns_more_than_1000() {
    let db = SqliteStorage::in_memory().await.unwrap();

    for i in 0..N {
        let env = envelope_n(i);
        // message_id is a FK into messages with ON DELETE CASCADE — store first.
        db.store_message(&env).await.unwrap();
        db.queue_pending_delivery(&env.id, &node_id_n(i))
            .await
            .unwrap();
    }

    let peers = db.get_pending_peers().await.unwrap();
    assert_eq!(
        peers.len() as u32,
        N,
        "get_pending_peers must return all {N} distinct recipients — a LIMIT here \
         strands queued mail that never flushes on reconnect (DBH2 fail-open)"
    );
}

/// Path (c): `get_room_members()` is the fan-out membership authority for room
/// message delivery. Before DBH2 it capped at `LIMIT 10000`, silently dropping
/// the overflow members of a large room — a Principle-2 fail-open: those members
/// never receive room messages. Unlike the 1500-row paths above, this cap only
/// bites past 10000, so the `dbh2_guard` string-assertion alone never crosses it
/// — a live >10000 seed is the only runtime proof of the actual authority.
#[tokio::test]
async fn get_room_members_returns_more_than_10000() {
    let db = SqliteStorage::in_memory().await.unwrap();

    // One full row past the old `LIMIT 10000` cap.
    const ROOM_N: u32 = 10_001;

    let room = konsensus_storage::models::Room::new("dbh2-large-room".to_string(), node_id_n(0));
    db.create_room(&room).await.unwrap();
    let room_id = room.id; // RoomId: Copy

    for i in 0..ROOM_N {
        db.add_room_member(&room_id, &node_id_n(i)).await.unwrap();
    }

    let members = db.get_room_members(&room_id).await.unwrap();
    assert_eq!(
        members.len() as u32,
        ROOM_N,
        "get_room_members must return all {ROOM_N} members — a LIMIT here drops \
         room-message recipients beyond 10000 (DBH2 fail-open)"
    );
}
