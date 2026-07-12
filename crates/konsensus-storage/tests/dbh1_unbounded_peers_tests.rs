//! DBH1 — the peer-listing query is unbounded, so the durable gate-whitelist
//! authority and the RV-RESTORE backup survive a >1000-peer mesh.
//!
//! Before DBH1 both of these FAILED: `list_peers()` capped at `LIMIT 1000`,
//! silently truncating BOTH the boot-loaded gate whitelist (`merge_persisted_peers`)
//! AND the backup set (`WhitelistBackup::collect`) on any node with more than
//! 1000 whitelisted peers — so previously-paid counterparties were rejected
//! `NotWhitelisted` after a restart/restore (Principle-2 fail-open).
//!
//! These tests exercise the SQLite backend live. The Postgres backend shares the
//! identical query constant and is guarded by the `dbh1_guard` string-assertion
//! unit test in `postgres.rs` (CI has no Postgres service; the true Postgres
//! proof is the operator's GA-drill against a live Postgres node).

use konsensus_core::types::NodeId;
use konsensus_storage::models::Peer;
use konsensus_storage::{SqliteStorage, Storage, WhitelistBackup};

const KEY: [u8; 32] = [0x11; 32];
const N: u32 = 1500;

/// 1500 distinct `NodeId`s. The shared `make_node_id(seed: u8)` helper used by the
/// other suites only yields 256 distinct ids, so derive from a 32-byte big-endian
/// counter instead (DBH1 is specifically about the >1000 regime).
fn peer_n(i: u32) -> Peer {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&i.to_be_bytes());
    let mut peer = Peer::new(NodeId::from_bytes(bytes));
    peer.display_name = Some(format!("peer-{i}"));
    peer
}

async fn seed_peers(db: &SqliteStorage, n: u32) {
    for i in 0..n {
        db.upsert_peer(&peer_n(i)).await.unwrap();
    }
}

/// Path (a): the raw enumerator the boot-load reads. Before DBH1 this returned
/// 1000; after DBH1 it returns all 1500.
#[tokio::test]
async fn list_peers_returns_more_than_1000() {
    let db = SqliteStorage::in_memory().await.unwrap();
    seed_peers(&db, N).await;

    let peers = db.list_peers().await.unwrap();
    assert_eq!(
        peers.len() as u32,
        N,
        "list_peers must return all {N} peers — a LIMIT here is a gate-whitelist fail-open (DBH1)"
    );
}

/// Path (b): the RV-RESTORE backup inherits the same `list_peers()` call, so a
/// whitelist of more than 1000 peers must survive the full collect -> seal -> open -> restore
/// round-trip onto a FRESH node. This is the consumer that actually matters for
/// fresh-hardware recovery — fixing the source query fixes the backup.
#[tokio::test]
async fn whitelist_backup_survives_more_than_1000_peers() {
    let src = SqliteStorage::in_memory().await.unwrap();
    seed_peers(&src, N).await;

    let backup = WhitelistBackup::collect(&src, 1_800_000_000).await.unwrap();
    assert_eq!(
        backup.peers.len() as u32,
        N,
        "collect must capture all {N} peers (it reads the same list_peers())"
    );

    let sealed = backup.seal(&KEY).unwrap();
    let reopened = WhitelistBackup::open(&sealed, &KEY).unwrap();

    let dst = SqliteStorage::in_memory().await.unwrap();
    assert!(
        dst.list_peers().await.unwrap().is_empty(),
        "fresh node must start with an empty whitelist"
    );

    let restored = reopened.restore_into(&dst).await.unwrap();
    assert_eq!(restored as u32, N, "restore_into must write all {N} peers");
    assert_eq!(
        dst.list_peers().await.unwrap().len() as u32,
        N,
        "a >1000-peer whitelist must survive backup+restore end-to-end (DBH1 + RV-RESTORE)"
    );
}
