//! Expiry retention checks use the real store and scheduler, never a node/wallet.
use super::*;

async fn expiring_fixture() -> (Fx, i64) {
    let mut fx = fixture().await;
    fx.grant(None, GrantTerms::new(10_000)).await;
    let path = fx.tmp.path().join("pairing/clients.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let now = chrono::Utc::now().timestamp();
    let expiry = now + 3;
    file["grants"][0]["granted_at"] = json!(now - 100);
    file["grants"][0]["expires_at"] = json!(expiry);
    std::fs::write(path, serde_json::to_vec(&file).unwrap()).unwrap();
    fx.restart();
    (fx, expiry)
}

async fn wait_for_expiry(expiry: i64) {
    while chrono::Utc::now().timestamp_millis() < expiry * 1000 + 100 {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

fn disk_grants(fx: &Fx) -> Value {
    let file: Value =
        serde_json::from_slice(&std::fs::read(fx.tmp.path().join("pairing/clients.json")).unwrap())
            .unwrap();
    file["grants"].clone()
}

#[tokio::test]
async fn expiry_scheduler_purges_idle_store_at_deadline() {
    let (fx, expiry) = expiring_fixture().await;
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(control::sweep_expired_grants(Arc::clone(&fx.service), rx));
    wait_for_expiry(expiry).await;
    // Read the bytes directly: a service read must not mask a broken scheduler.
    let grants = disk_grants(&fx);
    stop.send(true).unwrap();
    task.await.unwrap();
    assert_eq!(grants, json!([]), "idle store retained an expired grant");
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn expiry_snapshot_purges_before_returning() {
    let (fx, expiry) = expiring_fixture().await;
    wait_for_expiry(expiry).await;
    assert!(fx.service.snapshot().grants.is_empty());
    assert_eq!(disk_grants(&fx), json!([]));
}

#[tokio::test]
async fn expiry_grant_read_purges_before_returning() {
    let (fx, expiry) = expiring_fixture().await;
    wait_for_expiry(expiry).await;
    assert!(fx.service.grant_view_for(&fx.client_id).is_none());
    assert_eq!(disk_grants(&fx), json!([]));
}

#[tokio::test]
async fn expiry_disk_reload_purges_before_returning() {
    let (fx, expiry) = expiring_fixture().await;
    wait_for_expiry(expiry).await;
    assert!(fx.service.reload_from_disk().unwrap().grants.is_empty());
    assert_eq!(disk_grants(&fx), json!([]));
}

#[tokio::test]
async fn expiry_restart_purges_before_store_is_available() {
    let (mut fx, expiry) = expiring_fixture().await;
    wait_for_expiry(expiry).await;
    assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
    fx.restart();
    assert_eq!(disk_grants(&fx), json!([]));
    assert!(fx.service.snapshot().grants.is_empty());
    let token = fx.token().await;
    assert_eq!(fx.compose(&token).await.0, StatusCode::FORBIDDEN);
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn expiry_failed_read_cleanup_hides_grant_and_retries() {
    let (fx, expiry) = expiring_fixture().await;
    let blocker = fx.tmp.path().join("pairing/clients.json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    wait_for_expiry(expiry).await;
    assert!(
        fx.service.snapshot().grants.is_empty(),
        "never serve expired records"
    );
    assert!(
        fx.service.reload_from_disk().is_err(),
        "fallible reads report cleanup failure"
    );
    assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
    std::fs::remove_dir(blocker).unwrap();
    assert!(fx.service.snapshot().grants.is_empty());
    assert_eq!(
        disk_grants(&fx),
        json!([]),
        "a later read must retry deletion"
    );
}

#[tokio::test]
async fn expiry_restart_refuses_until_durable_cleanup_succeeds() {
    let (mut fx, expiry) = expiring_fixture().await;
    let blocker = fx.tmp.path().join("pairing/clients.json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    wait_for_expiry(expiry).await;
    assert!(
        PairingService::open(fx.tmp.path(), fx.service.bound_fingerprint(), true,).is_err(),
        "startup must not ignore a failed purge"
    );
    std::fs::remove_dir(blocker).unwrap();
    fx.restart();
    assert_eq!(disk_grants(&fx), json!([]));
}

#[tokio::test]
async fn expiry_scheduler_retries_without_a_read_after_storage_recovers() {
    let (fx, expiry) = expiring_fixture().await;
    let blocker = fx.tmp.path().join("pairing/clients.json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    let (stop, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(control::sweep_expired_grants(Arc::clone(&fx.service), rx));
    wait_for_expiry(expiry).await;
    assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
    std::fs::remove_dir(blocker).unwrap();
    let result = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while disk_grants(&fx) != json!([]) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await;
    stop.send(true).unwrap();
    task.await.unwrap();
    result.expect("scheduler did not retry deletion after storage recovered");
}

async fn abandoned_temporary_grant_is_removed(keep_live_grant: bool) {
    let mut fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    assert_eq!(fx.compose(&token).await.0, StatusCode::OK);
    let path = fx.tmp.path().join("pairing/clients.json");
    let mut authoritative: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut abandoned = authoritative.clone();
    let now = chrono::Utc::now().timestamp();
    abandoned["grants"][0]["granted_at"] = json!(now - 100);
    abandoned["grants"][0]["expires_at"] = json!(now - 1);
    if !keep_live_grant {
        authoritative["grants"] = json!([]);
        std::fs::write(&path, serde_json::to_vec(&authoritative).unwrap()).unwrap();
    }
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec(&abandoned).unwrap()).unwrap();
    fx.restart();
    assert!(
        !tmp.exists(),
        "restart retained an abandoned expired grant file"
    );
    assert_eq!(
        disk_grants(&fx),
        authoritative["grants"],
        "never promote the abandoned transaction"
    );
    if keep_live_grant {
        assert_eq!(
            fx.used(),
            1000,
            "cleanup must preserve the live grant's tally"
        );
    }
}

#[tokio::test]
async fn expiry_restart_removes_abandoned_temporary_grant() {
    abandoned_temporary_grant_is_removed(false).await;
}

#[tokio::test]
async fn expiry_restart_preserves_live_grant_when_removing_temporary_file() {
    abandoned_temporary_grant_is_removed(true).await;
}
