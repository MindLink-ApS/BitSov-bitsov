//! open-channel idempotency records (#331).
use konsensus_storage::{
    channel_open::{CHANNEL_OPEN_OPENED, CHANNEL_OPEN_PENDING, CHANNEL_OPEN_UNCERTAIN},
    ChannelOpenOperation, EncryptedStorage, SqliteStorage, Storage,
};

#[tokio::test]
async fn insert_once_resolve_once_and_survive_restart() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("channels.db");
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let op = ChannelOpenOperation::pending("op".into(), "digest".into(), b"{}".to_vec());
    assert!(db.insert_channel_open_operation(&op).await.unwrap());
    let other = ChannelOpenOperation::pending("op".into(), "other".into(), b"[]".to_vec());
    assert!(
        !db.insert_channel_open_operation(&other).await.unwrap(),
        "a duplicate never overwrites"
    );
    assert_eq!(
        db.get_channel_open_operation("op")
            .await
            .unwrap()
            .unwrap()
            .request_hash,
        "digest"
    );
    assert!(db
        .resolve_channel_open_operation("op", CHANNEL_OPEN_UNCERTAIN, None, Some("timeout"))
        .await
        .unwrap());
    assert!(
        !db.resolve_channel_open_operation("op", CHANNEL_OPEN_OPENED, Some(b"r"), None)
            .await
            .unwrap(),
        "a resolved record is never rewritten"
    );
    assert!(
        !db.delete_pending_channel_open_operation("op")
            .await
            .unwrap(),
        "only pending rows are removed"
    );
    drop(db);
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let loaded = db.get_channel_open_operation("op").await.unwrap().unwrap();
    assert_eq!(loaded.state, CHANNEL_OPEN_UNCERTAIN);
    assert_eq!(loaded.last_error.as_deref(), Some("timeout"));
    assert_eq!(loaded.result, None);
    assert!(db
        .get_channel_open_operation("missing")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn pending_rows_can_be_released_after_proven_non_dispatch() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let op = ChannelOpenOperation::pending("op".into(), "digest".into(), b"{}".to_vec());
    assert!(db.insert_channel_open_operation(&op).await.unwrap());
    assert!(db
        .delete_pending_channel_open_operation("op")
        .await
        .unwrap());
    assert!(db.get_channel_open_operation("op").await.unwrap().is_none());
    assert!(db.insert_channel_open_operation(&op).await.unwrap());
    assert_eq!(
        db.get_channel_open_operation("op")
            .await
            .unwrap()
            .unwrap()
            .state,
        CHANNEL_OPEN_PENDING
    );
}

#[tokio::test]
async fn encrypted_storage_seals_request_and_result() {
    let store = EncryptedStorage::new(SqliteStorage::in_memory().await.unwrap(), &[9; 32]);
    let op = ChannelOpenOperation::pending("op".into(), "digest".into(), b"peer params".to_vec());
    assert!(store.insert_channel_open_operation(&op).await.unwrap());
    assert!(store
        .resolve_channel_open_operation("op", CHANNEL_OPEN_OPENED, Some(b"channel result"), None)
        .await
        .unwrap());
    let raw = store
        .inner()
        .get_channel_open_operation("op")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(raw.request, b"peer params");
    assert_ne!(raw.result.as_deref(), Some(&b"channel result"[..]));
    let read = store
        .get_channel_open_operation("op")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read.request, b"peer params");
    assert_eq!(read.result.as_deref(), Some(&b"channel result"[..]));
    assert_eq!(read.state, CHANNEL_OPEN_OPENED);
}
