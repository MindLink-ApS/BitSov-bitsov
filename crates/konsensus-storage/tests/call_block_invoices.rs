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

/// A paid block's grant and the release of its admission hold stand or fall
/// together (Codex P1 on #441): a failing hold delete rolls the grant back,
/// so no committed grant can stay behind a hold the sweep would withdraw;
/// once committed, the sweep finds nothing of it to withdraw.
async fn assert_block_commit_is_atomic(
    db: std::sync::Arc<dyn Storage>,
    fail_release: std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
    heal_release: std::pin::Pin<Box<dyn std::future::Future<Output = ()>>>,
) {
    use konsensus_core::payloads::call;
    let env = konsensus_core::UkmEnvelopeBuilder::new(404, NodeId::from_bytes([51; 32]),
        konsensus_core::Recipient::Node(NodeId::from_bytes([52; 32])), vec![3; 16],
        konsensus_core::PaymentProof::new([53; 32], [54; 32], 10_000))
        .timestamp(1).nonce(konsensus_core::Nonce::from_bytes([55; 24]))
        .signature(konsensus_core::Signature::from_bytes([0; 64])).build();
    let peer = env.sender;
    let call_id = "fedcba9876543210fedcba9876543210";
    let before = call::receive(None, konsensus_core::kind::KIND_CALL_INVITE, None, 1_000).unwrap();
    db.call_put(&peer, call_id, &before).await.unwrap();
    let granted = call::CallEntry { paid_until_ms: Some(61_000), next_block_seq: 1, ..before.clone() };
    assert!(db.call_admission_hold(&env, 1_000).await.unwrap());

    fail_release.await;
    assert!(db.call_commit_admitted(&peer, call_id, &granted, &env.id).await.is_err());
    assert_eq!(db.call_get(&peer, call_id).await.unwrap(), Some(before.clone()), "a failed release must roll the grant back");
    assert!(db.call_admission_held(&env.id).await.unwrap());

    heal_release.await;
    db.call_commit_admitted(&peer, call_id, &granted, &env.id).await.unwrap();
    assert_eq!(db.call_get(&peer, call_id).await.unwrap(), Some(granted.clone()));
    assert!(!db.call_admission_held(&env.id).await.unwrap(), "the grant releases its hold");
    // Restart recovery withdraws every remaining hold: none is left for this grant.
    assert_eq!(db.call_admission_withdraw(u64::MAX).await.unwrap(), 0);
    assert_eq!(db.call_get(&peer, call_id).await.unwrap(), Some(granted));
}

#[tokio::test]
async fn sqlite_block_commit_and_hold_release_are_one_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("atomic.sqlite");
    let inner = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let pool = inner.pool().clone();
    // Through the encrypted wrapper, as the node runs it: it must forward.
    let db = std::sync::Arc::new(EncryptedStorage::new(inner, &[7; 32]));
    let (fail, heal) = (pool.clone(), pool);
    assert_block_commit_is_atomic(db,
        Box::pin(async move {
            sqlx::query("CREATE TRIGGER fail_release BEFORE DELETE ON call_admission_hold BEGIN SELECT RAISE(ABORT, 'injected hold release failure'); END")
                .execute(&fail).await.unwrap();
        }),
        Box::pin(async move {
            sqlx::query("DROP TRIGGER fail_release").execute(&heal).await.unwrap();
        }),
    ).await;
}

#[tokio::test]
#[ignore = "requires BITSOV_TEST_POSTGRES_URL pointing to a disposable PostgreSQL server"]
async fn postgres_block_commit_and_hold_release_are_one_transaction() {
    let url = std::env::var("BITSOV_TEST_POSTGRES_URL").unwrap();
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("block_atomic_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}")).execute(&admin).await.unwrap();
    let db_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    let db = konsensus_storage::PostgresStorage::connect(&db_url).await.unwrap();
    let pool = sqlx::PgPool::connect(&db_url).await.unwrap();
    let (fail, heal) = (pool.clone(), pool.clone());
    assert_block_commit_is_atomic(std::sync::Arc::new(db),
        Box::pin(async move {
            sqlx::raw_sql("CREATE FUNCTION fail_release() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'injected hold release failure'; END $$ LANGUAGE plpgsql; \
                CREATE TRIGGER fail_release BEFORE DELETE ON call_admission_hold FOR EACH ROW EXECUTE FUNCTION fail_release();")
                .execute(&fail).await.unwrap();
        }),
        Box::pin(async move {
            sqlx::raw_sql("DROP TRIGGER fail_release ON call_admission_hold; DROP FUNCTION fail_release();")
                .execute(&heal).await.unwrap();
        }),
    ).await;
    pool.close().await;
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)")).execute(&admin).await.unwrap();
    admin.close().await;
}
