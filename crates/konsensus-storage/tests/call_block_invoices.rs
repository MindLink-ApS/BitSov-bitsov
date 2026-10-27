use konsensus_core::NodeId;
use konsensus_storage::{EncryptedStorage, SqliteStorage, Storage};

async fn assert_binding_cap(db: std::sync::Arc<dyn Storage>) {
    let peer = NodeId::from_bytes([41; 32]);
    let other = NodeId::from_bytes([42; 32]);
    let call_id = "0123456789abcdef0123456789abcdef";
    let mut requests = tokio::task::JoinSet::new();
    for i in 0..16 {
        let db = db.clone();
        requests.spawn(async move {
            (i, db.record_call_block_invoice(&peer, call_id, 0, &[i; 32], 90_000).await.is_ok())
        });
    }
    let mut accepted = Vec::new();
    let mut refused = Vec::new();
    while let Some(result) = requests.join_next().await {
        let (i, ok) = result.unwrap();
        if ok { accepted.push(i); } else { refused.push(i); }
    }
    assert_eq!(accepted.len(), 8, "concurrent issuance must respect the per-block cap");
    for i in &accepted {
        assert!(db.has_call_block_invoice(&peer, call_id, 0, &[*i; 32]).await.unwrap(), "never evict a possibly paid invoice");
    }
    for i in refused {
        assert!(!db.has_call_block_invoice(&peer, call_id, 0, &[i; 32]).await.unwrap());
    }
    // Capacity is scoped to the peer, call, and sequence, not the whole node.
    for (p, id, seq, hash) in [(other, call_id, 0, 20), (peer, "another-call", 0, 21), (peer, call_id, 1, 22)] {
        db.record_call_block_invoice(&p, id, seq, &[hash; 32], 90_000).await.unwrap();
    }
    db.call_sweep(90_001, 100).await.unwrap();
    db.record_call_block_invoice(&peer, call_id, 0, &[23; 32], 180_000).await.unwrap();
    assert!(db.has_call_block_invoice(&peer, call_id, 0, &[23; 32]).await.unwrap());
}

#[tokio::test]
async fn sqlite_block_invoice_bindings_are_capped_per_peer_call_and_sequence() {
    let dir = tempfile::tempdir().unwrap();
    let db = SqliteStorage::open(dir.path().join("cap.sqlite").to_str().unwrap()).await.unwrap();
    assert_binding_cap(std::sync::Arc::new(db)).await;
}

#[tokio::test]
#[ignore = "requires BITSOV_TEST_POSTGRES_URL pointing to a disposable PostgreSQL server"]
async fn postgres_block_invoice_bindings_are_capped_per_peer_call_and_sequence() {
    let url = std::env::var("BITSOV_TEST_POSTGRES_URL").unwrap();
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("block_cap_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
    let db_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    let db = konsensus_storage::PostgresStorage::connect(&db_url).await.unwrap();
    assert_binding_cap(std::sync::Arc::new(db)).await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)")).execute(&admin).await.unwrap();
    admin.close().await;
}

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
