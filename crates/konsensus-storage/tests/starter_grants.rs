use konsensus_storage::starter::*;
use konsensus_storage::{SqliteStorage, Storage};

fn grant(n: u32, now: i64) -> StarterGrant {
    StarterGrant::new(
        format!("request-{n}"),
        format!("node-{n}"),
        format!("key-{n}"),
        "regtest".into(),
        uuid::Uuid::from_u128(n as u128 + 1).to_string(),
        50_000,
        5_000,
        now,
    )
}
fn limits() -> StarterLimits {
    StarterLimits {
        max_opens_per_day: 20,
        max_concurrent_opens: 100,
        lifetime_budget_sats: 10_000_000,
    }
}
async fn admit(db: &dyn Storage, n: u32, now: i64) -> StarterOutcome {
    db.starter_update(
        StarterUpdate::Admit {
            grant: grant(n, now),
            limits: limits(),
        },
        Some(now),
    )
    .await
    .unwrap()
}
async fn seed_invite(db: &dyn Storage, id: &str) {
    let g = db
        .starter_grants()
        .await
        .unwrap()
        .into_iter()
        .find(|g| g.request_id == id)
        .unwrap();
    let invite_id = uuid::Uuid::parse_str(&g.invite_id).unwrap();
    db.add_invite_issued(&konsensus_storage::InviteIssuedRecord {
        id: invite_id,
        invitee_pubkey: [1; 32],
        expiry_unix: 4_000_000_000,
        channel_size_hint_sats: None,
        addr: String::new(),
        max_fee_rate_sat_per_vb: None,
        channel_open_intent_expiry_unix: None,
        nonce: *invite_id.as_bytes(),
        state: konsensus_storage::InviteState::Pending,
        created_at: 1,
        accepted_at: None,
        revoked_at: None,
    })
    .await
    .unwrap();
}
async fn claim(db: &dyn Storage, id: &str, now: i64) {
    seed_invite(db, id).await;
    let op =
        konsensus_storage::ChannelOpenOperation::pending(id.into(), "hash".into(), b"{}".to_vec());
    assert!(
        db.starter_update(
            StarterUpdate::Claim {
                id: id.into(),
                operation: op
            },
            Some(now)
        )
        .await
        .unwrap()
        .claimed
    );
}
#[tokio::test]
async fn midnight_refund_neither_underflows_nor_allows_twenty_first_open() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let yesterday = 1_800_000_000 / 86400 * 86400;
    let today = yesterday + 86400;
    admit(&db, 0, yesterday).await;
    claim(&db, "request-0", yesterday).await;
    db.starter_update(
        StarterUpdate::NonDispatch {
            id: "request-0".into(),
            reason: "fee_too_high".into(),
            terminal: true,
        },
        Some(today),
    )
    .await
    .unwrap();
    for n in 1..=20 {
        assert!(admit(&db, n, today).await.reason.is_none());
    }
    assert_eq!(
        admit(&db, 21, today).await.reason.as_deref(),
        Some("daily_cap_reached")
    );
    let counters = db.starter_counters().await.unwrap();
    assert_eq!(counters.day_count, 20);
    assert_eq!(counters.committed_sats, 1_000_000);
}
#[tokio::test]
async fn late_refund_does_not_discount_already_full_today() {
    let db = SqliteStorage::in_memory().await.unwrap();
    admit(&db, 0, 86400).await;
    claim(&db, "request-0", 86400).await;
    for n in 1..=20 {
        admit(&db, n, 172800).await;
    }
    db.starter_update(
        StarterUpdate::NonDispatch {
            id: "request-0".into(),
            reason: "open_failed".into(),
            terminal: true,
        },
        Some(172800),
    )
    .await
    .unwrap();
    assert_eq!(
        admit(&db, 21, 172800).await.reason.as_deref(),
        Some("daily_cap_reached")
    );
}
#[tokio::test]
async fn racing_identity_maps_to_already_served() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let first = grant(1, 86400);
    let mut second = first.clone();
    second.request_id = "second".into();
    let (a, b) = tokio::join!(
        db.starter_update(
            StarterUpdate::Admit {
                grant: first,
                limits: limits()
            },
            Some(86400)
        ),
        db.starter_update(
            StarterUpdate::Admit {
                grant: second,
                limits: limits()
            },
            Some(86400)
        )
    );
    let results = [a.unwrap(), b.unwrap()];
    assert_eq!(results.iter().filter(|r| r.reason.is_none()).count(), 1);
    assert_eq!(
        results.iter().find_map(|r| r.reason.as_deref()),
        Some("already_served")
    );
    assert_eq!(db.starter_counters().await.unwrap().day_count, 1);
}
#[tokio::test]
async fn resolve_uncertain_releases_only_inflight_and_lifetime_is_separate() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let mut cap = limits();
    cap.lifetime_budget_sats = 50_000;
    db.starter_update(
        StarterUpdate::Admit {
            grant: grant(1, 86400),
            limits: cap.clone(),
        },
        Some(86400),
    )
    .await
    .unwrap();
    claim(&db, "request-1", 86400).await;
    db.resolve_channel_open_operation("request-1", "uncertain", None, None)
        .await
        .unwrap();
    db.starter_update(
        StarterUpdate::ResolveUncertain {
            id: "request-1".into(),
        },
        Some(172800),
    )
    .await
    .unwrap();
    let c = db.starter_counters().await.unwrap();
    assert_eq!(
        (c.day_count, c.inflight_count, c.committed_sats),
        (0, 0, 50_000)
    );
    let out = db
        .starter_update(
            StarterUpdate::Admit {
                grant: grant(2, 172800),
                limits: cap,
            },
            Some(172800),
        )
        .await
        .unwrap();
    assert_eq!(out.reason.as_deref(), Some("budget_exhausted"));
    assert_eq!(admit(&db, 1, 172800).await.grant.unwrap().state, "resolved");
}
#[tokio::test]
async fn dispatch_requires_grant_and_claims_only_once() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let op =
        konsensus_storage::ChannelOpenOperation::pending("request-1".into(), "h".into(), vec![]);
    assert!(
        !db.starter_update(
            StarterUpdate::Claim {
                id: "request-1".into(),
                operation: op.clone()
            },
            Some(86400)
        )
        .await
        .unwrap()
        .claimed
    );
    admit(&db, 1, 86400).await;
    seed_invite(&db, "request-1").await;
    assert!(
        db.starter_update(
            StarterUpdate::Claim {
                id: "request-1".into(),
                operation: op.clone()
            },
            Some(86400)
        )
        .await
        .unwrap()
        .claimed
    );
    assert!(
        !db.starter_update(
            StarterUpdate::Claim {
                id: "request-1".into(),
                operation: op
            },
            Some(86400)
        )
        .await
        .unwrap()
        .claimed
    );
}

#[tokio::test]
async fn encrypted_claim_recovery_and_refusal_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("starter.db");
    {
        let db = konsensus_storage::EncryptedStorage::new(
            SqliteStorage::open(path.to_str().unwrap()).await.unwrap(),
            &[9; 32],
        );
        admit(&db, 1, 86400).await;
        claim(&db, "request-1", 86400).await;
        assert_eq!(
            db.get_channel_open_operation("request-1")
                .await
                .unwrap()
                .unwrap()
                .request,
            b"{}"
        );
    }
    let db = konsensus_storage::EncryptedStorage::new(
        SqliteStorage::open(path.to_str().unwrap()).await.unwrap(),
        &[9; 32],
    );
    assert_eq!(db.starter_grants().await.unwrap()[0].state, "opening");
    db.starter_update(StarterUpdate::Rebuild, Some(172800))
        .await
        .unwrap();
    assert_eq!(db.starter_counters().await.unwrap().day_count, 0);
    assert_eq!(db.starter_counters().await.unwrap().committed_sats, 50_000);
}

#[tokio::test]
async fn sqlite_two_connections_serialize_last_daily_slot_and_ln_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("race.db");
    let a = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let b = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    for n in 0..19 {
        admit(&a, n, 86400).await;
    }
    let (x, y) = tokio::join!(admit(&a, 20, 86400), admit(&b, 21, 86400));
    assert_eq!(
        [x, y]
            .iter()
            .filter(|r| r.reason.as_deref() == Some("daily_cap_reached"))
            .count(),
        1
    );
    assert_eq!(a.starter_counters().await.unwrap().day_count, 20);
    let mut duplicate = grant(99, 172800);
    duplicate.ln_pubkey = "KEY-0".to_ascii_lowercase();
    let result = b
        .starter_update(
            StarterUpdate::Admit {
                grant: duplicate,
                limits: limits(),
            },
            Some(172800),
        )
        .await
        .unwrap();
    assert_eq!(result.reason.as_deref(), Some("already_served"));
    assert_eq!(result.original_request_id.as_deref(), Some("request-0"));
}

#[tokio::test]
#[ignore = "requires BITSOV_TEST_POSTGRES_URL pointing to a disposable PostgreSQL server"]
async fn postgres_starter_migration_caps_and_identity_races() {
    let url = std::env::var("BITSOV_TEST_POSTGRES_URL").unwrap();
    let admin = sqlx::PgPool::connect(&url).await.unwrap();
    let name = format!("starter_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let db_url = format!("{}/{name}", url.rsplit_once('/').unwrap().0);
    let a = konsensus_storage::PostgresStorage::connect(&db_url)
        .await
        .unwrap();
    let b = konsensus_storage::PostgresStorage::connect(&db_url)
        .await
        .unwrap();
    let (x, y) = tokio::join!(admit(&a, 1, 86400), admit(&b, 1, 86400));
    assert!(x.grant.is_some() && y.grant.is_some());
    for n in 2..20 {
        admit(&a, n, 86400).await;
    }
    let (x, y) = tokio::join!(admit(&a, 20, 86400), admit(&b, 21, 86400));
    assert_eq!(
        [x, y]
            .iter()
            .filter(|r| r.reason.as_deref() == Some("daily_cap_reached"))
            .count(),
        1
    );
    claim(&a, "request-1", 86400).await;
    a.starter_update(
        StarterUpdate::NonDispatch {
            id: "request-1".into(),
            reason: "fee_too_high".into(),
            terminal: true,
        },
        Some(172800),
    )
    .await
    .unwrap();
    assert_eq!(a.starter_counters().await.unwrap().day_count, 0);
    assert_eq!(a.starter_counters().await.unwrap().committed_sats, 950_000);
    drop(a);
    drop(b);
    sqlx::query(&format!("DROP DATABASE {name} WITH (FORCE)"))
        .execute(&admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn invalid_invite_cancellation_never_refunds_an_existing_operation() {
    let db = SqliteStorage::in_memory().await.unwrap();
    admit(&db, 0, 10).await;
    db.insert_channel_open_operation(&konsensus_storage::ChannelOpenOperation::pending(
        "request-0".into(),
        "hash".into(),
        b"{}".to_vec(),
    ))
    .await
    .unwrap();
    db.starter_update(
        StarterUpdate::CancelInvalidInvite {
            id: "request-0".into(),
        },
        Some(20),
    )
    .await
    .unwrap();
    let c = db.starter_counters().await.unwrap();
    assert_eq!((c.inflight_count, c.committed_sats), (1, 50_000));
    assert_eq!(db.starter_grants().await.unwrap()[0].state, "admitted");
}
