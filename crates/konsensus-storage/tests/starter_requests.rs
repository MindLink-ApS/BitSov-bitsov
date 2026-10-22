use konsensus_storage::{starter_request::*, SqliteStorage, Storage};

#[tokio::test]
async fn concurrent_create_and_retry_have_one_durable_operation() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let request = StarterRequest::new(
        uuid::Uuid::new_v4().to_string(),
        "hub".into(),
        "ln".into(),
        "regtest".into(),
        100,
    );
    let mut other = request.clone();
    other.request_id = uuid::Uuid::new_v4().to_string();
    let (a, b) = tokio::join!(
        db.starter_request_create(&request),
        db.starter_request_create(&other)
    );
    let (a, created_a) = a.unwrap();
    let (b, created_b) = b.unwrap();
    assert_eq!(a.request_id, b.request_id);
    assert_ne!(created_a, created_b);
    let mut row = db.starter_request_current().await.unwrap().unwrap();
    row.state = "refused".into();
    row.reason = Some("hub_busy".into());
    row.retry_allowed = true;
    row.retry_after_unix = Some(700);
    db.starter_request_save(&row).await.unwrap();
    assert_eq!(
        db.starter_request_retry(&row.request_id, 699)
            .await
            .unwrap()
            .request_id,
        row.request_id
    );
    let (a, b) = tokio::join!(
        db.starter_request_retry(&row.request_id, 700),
        db.starter_request_retry(&row.request_id, 700)
    );
    let child = a.unwrap();
    assert_eq!(child.request_id, b.unwrap().request_id);
    assert_ne!(child.request_id, row.request_id);
    assert_eq!(child.original_request_id, Some(row.request_id.clone()));
    assert_eq!(
        db.starter_request_get(&row.request_id)
            .await
            .unwrap()
            .unwrap()
            .state,
        "refused"
    );
    // A delayed status from the refused operation cannot regress its replacement.
    row.state = "opening".into();
    db.starter_request_save(&row).await.unwrap();
    assert_eq!(
        db.starter_request_current()
            .await
            .unwrap()
            .unwrap()
            .request_id,
        child.request_id
    );
}

#[tokio::test]
async fn retries_are_bounded_across_restart_and_timeouts_keep_the_id() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("starter.sqlite");
    let mut db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    let request = StarterRequest::new(
        uuid::Uuid::new_v4().to_string(),
        "hub".into(),
        "ln".into(),
        "regtest".into(),
        100,
    );
    db.starter_request_create(&request).await.unwrap();
    assert_eq!(
        db.starter_request_retry(&request.request_id, 10000)
            .await
            .unwrap()
            .request_id,
        request.request_id
    );
    let mut row = request;
    for (n, (refused_at, due)) in [(100, 700), (700, 1900), (1900, 4300), (4300, 9100)]
        .into_iter()
        .enumerate()
    {
        row.state = "refused".into();
        row.retry_allowed = true;
        row.retry_after_unix = Some(refused_at + 600);
        row.updated_at = refused_at;
        db.starter_request_save(&row).await.unwrap();
        drop(db);
        db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        assert_eq!(
            db.starter_request_retry(&row.request_id, due - 1)
                .await
                .unwrap()
                .request_id,
            row.request_id
        );
        let next = db
            .starter_request_retry(&row.request_id, due)
            .await
            .unwrap();
        if n == 3 {
            assert_eq!(next.request_id, row.request_id);
        } else {
            assert_ne!(next.request_id, row.request_id);
        }
        row = next;
    }
}

#[tokio::test]
async fn authenticated_adoption_can_recover_a_previously_refused_id() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let mut original = StarterRequest::new(
        uuid::Uuid::new_v4().to_string(),
        "hub".into(),
        "ln".into(),
        "regtest".into(),
        100,
    );
    db.starter_request_create(&original).await.unwrap();
    original.state = "refused".into();
    db.starter_request_save(&original).await.unwrap();
    let adopted = db.starter_request_adopt(&original).await.unwrap();
    assert_eq!(adopted.state, "requested");
    assert_eq!(adopted.request_id, original.request_id);
    let mut other = original.clone();
    other.request_id = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        db.starter_request_adopt(&other).await.unwrap().request_id,
        original.request_id
    );
}
