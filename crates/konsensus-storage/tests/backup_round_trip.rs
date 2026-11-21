use konsensus_core::NodeId;
use konsensus_storage::{AcceptedInviteRecord, Peer, SqliteStorage, Storage, WhitelistBackup};

const NOW: u64 = 1_800_000_000;

async fn populate(db: &SqliteStorage) {
    for tag in 1..=3 {
        let mut peer = Peer::new(NodeId::from_bytes([tag; 32]));
        peer.address = Some(format!("peer-{tag}.invalid:9735"));
        peer.last_seen = Some("2026-11-18T00:00:00Z".into());
        peer.display_name = Some(format!("peer-{tag}"));
        peer.metadata = serde_json::json!({"tag": tag, "nested": [true, null, "æ"]});
        db.upsert_peer(&peer).await.unwrap();
        db.add_accepted_invite(&AcceptedInviteRecord {
            nonce: [tag; 16],
            inviter_pubkey: [tag; 32],
            expiry_unix: NOW + 100,
            accepted_at: NOW - 100,
        })
        .await
        .unwrap();
    }
}

async fn rows(db: &SqliteStorage) -> serde_json::Value {
    let mut peers = db.list_peers().await.unwrap();
    peers.sort_by_key(|p| p.node_id.to_hex());
    let mut invites = db.list_active_accepted_invites(NOW).await.unwrap();
    invites.sort_by_key(|i| i.nonce);
    serde_json::json!({"peers": peers, "invites": invites})
}

#[tokio::test]
async fn file_backup_wipe_restore_preserves_all_whitelist_fields() {
    let dir = tempfile::tempdir().unwrap();
    let db_dir = dir.path().join("database");
    std::fs::create_dir(&db_dir).unwrap();
    let path = db_dir.join("store.sqlite");
    let backup_path = dir.path().join("whitelist.aes");
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    populate(&db).await;
    let expected = rows(&db).await;
    let backup = WhitelistBackup::collect(&db, NOW).await.unwrap();
    assert_eq!(backup.peers.len(), 3);
    assert_eq!(backup.accepted_invites.len(), 3);
    std::fs::write(&backup_path, backup.seal(&[7; 32]).unwrap()).unwrap();
    db.pool().close().await;
    drop(db);
    // Wipe the database together with any WAL and shared-memory sidecars.
    std::fs::remove_dir_all(&db_dir).unwrap();
    assert!(!path.exists());

    let restored_path = dir.path().join("restored.sqlite");
    let restored = SqliteStorage::open(restored_path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        rows(&restored).await,
        serde_json::json!({"peers": [], "invites": []})
    );
    let sealed = std::fs::read(&backup_path).unwrap();
    let opened = WhitelistBackup::open(&sealed, &[7; 32]).unwrap();
    assert_eq!(opened.restore_into(&restored).await.unwrap(), 3);
    assert_eq!(rows(&restored).await, expected);
    assert_eq!(opened.restore_into(&restored).await.unwrap(), 3);
    assert_eq!(rows(&restored).await, expected);
    restored.pool().close().await;
    let reopened = SqliteStorage::open(restored_path.to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(rows(&reopened).await, expected);
    reopened.pool().close().await;
}

#[tokio::test]
async fn damaged_backups_are_refused_before_restore_writes_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.sqlite");
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    populate(&db).await;
    let backup = WhitelistBackup::collect(&db, NOW).await.unwrap();
    let sealed = backup.seal(&[7; 32]).unwrap();
    let before = rows(&db).await;

    for end in 0..sealed.len() {
        assert!(
            WhitelistBackup::open(&sealed[..end], &[7; 32]).is_err(),
            "truncated at {end}"
        );
    }
    for offset in 0..sealed.len() {
        let mut damaged = sealed.clone();
        damaged[offset] ^= 1;
        assert!(
            WhitelistBackup::open(&damaged, &[7; 32]).is_err(),
            "modified at {offset}"
        );
    }
    assert!(WhitelistBackup::open(&sealed, &[8; 32]).is_err());
    let mut unsupported = backup;
    unsupported.version = 2;
    assert!(WhitelistBackup::open(&unsupported.seal(&[7; 32]).unwrap(), &[7; 32]).is_err());
    assert_eq!(rows(&db).await, before);
    db.pool().close().await;
}

#[tokio::test]
async fn backup_refuses_unreadable_invites_instead_of_emitting_partial_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.sqlite");
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    populate(&db).await;
    assert_eq!(
        WhitelistBackup::collect(&db, NOW)
            .await
            .unwrap()
            .accepted_invites
            .len(),
        3
    );
    sqlx::query("UPDATE accepted_invites SET inviter_pubkey = X'01'")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        WhitelistBackup::collect(&db, NOW).await.is_err(),
        "an unreadable invite must prevent a partial replacement backup"
    );
    db.pool().close().await;
}

#[tokio::test]
async fn backup_refuses_invite_query_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source.sqlite");
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    populate(&db).await;
    sqlx::query("DROP TABLE accepted_invites")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(WhitelistBackup::collect(&db, NOW).await.is_err());
    db.pool().close().await;
}
