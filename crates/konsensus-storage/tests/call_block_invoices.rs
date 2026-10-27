use konsensus_core::NodeId;
use konsensus_storage::{EncryptedStorage, SqliteStorage, Storage};

#[tokio::test]
async fn block_invoice_binding_survives_restart_is_exact_and_is_swept() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("calls.sqlite");
    let peer = NodeId::from_bytes([1; 32]);
    let other = NodeId::from_bytes([2; 32]);
    let call_id = "0123456789abcdef0123456789abcdef";
    {
        let db = EncryptedStorage::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap(), &[7; 32]);
        db.record_call_block_invoice(&peer, call_id, 0, &[3; 32], 90_000).await.unwrap();
        assert!(db.record_call_block_invoice(&other, call_id, 1, &[3; 32], 90_000).await.is_err());
    }
    let db = EncryptedStorage::new(SqliteStorage::open(path.to_str().unwrap()).await.unwrap(), &[7; 32]);
    assert!(db.has_call_block_invoice(&peer, call_id, 0, &[3; 32]).await.unwrap());
    for (p, id, seq, hash) in [
        (other, call_id, 0, [3; 32]), (peer, "different", 0, [3; 32]),
        (peer, call_id, 1, [3; 32]), (peer, call_id, 0, [4; 32]),
    ] {
        assert!(!db.has_call_block_invoice(&p, id, seq, &hash).await.unwrap());
    }
    db.call_sweep(90_000, 1).await.unwrap();
    assert!(db.has_call_block_invoice(&peer, call_id, 0, &[3; 32]).await.unwrap());
    db.record_call_block_invoice(&peer, call_id, 1, &[4; 32], 90_001).await.unwrap();
    db.call_sweep(90_002, 1).await.unwrap();
    assert!(!db.has_call_block_invoice(&peer, call_id, 0, &[3; 32]).await.unwrap());
    assert!(db.has_call_block_invoice(&peer, call_id, 1, &[4; 32]).await.unwrap());
    db.call_sweep(90_002, 1).await.unwrap();
    assert!(!db.has_call_block_invoice(&peer, call_id, 1, &[4; 32]).await.unwrap());
}
