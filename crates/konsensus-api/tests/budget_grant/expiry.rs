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

#[tokio::test]
async fn expiry_shutdown_already_signalled_purges_before_task_returns() {
    let (fx, expiry) = expiring_fixture().await;
    wait_for_expiry(expiry).await;
    assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
    let (_stop, rx) = tokio::sync::watch::channel(true);
    control::sweep_expired_grants(Arc::clone(&fx.service), rx).await;
    assert_eq!(disk_grants(&fx), json!([]), "shutdown skipped its purge");
}

#[tokio::test]
async fn expiry_shutdown_wakes_sleeping_sweeper_and_preserves_live_grants() {
    let (fx, expiry) = expiring_fixture().await;
    let (stop, rx) = tokio::sync::watch::channel(false);
    let sweep = control::sweep_expired_grants(Arc::clone(&fx.service), rx);
    tokio::pin!(sweep);
    // Poll the real task into its wait, then freeze monotonic time. Advancing
    // only wall time makes shutdown the only ready select branch, so the test
    // cannot pass through a lucky periodic sweep.
    tokio::time::pause();
    assert!(futures::poll!(&mut sweep).is_pending());
    assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
    while chrono::Utc::now().timestamp_millis() < expiry * 1000 + 100 {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    stop.send(true).unwrap();
    sweep.await;
    assert_eq!(disk_grants(&fx), json!([]), "shutdown wake skipped purge");
    tokio::time::resume();

    // Shutdown removes only expired records; a live tally must survive restart.
    let mut live = fixture().await;
    let token = live.grant(None, GrantTerms::new(10_000)).await;
    assert_eq!(live.compose(&token).await.0, StatusCode::OK);
    let before = disk_grants(&live);
    let (_stop, rx) = tokio::sync::watch::channel(true);
    control::sweep_expired_grants(Arc::clone(&live.service), rx).await;
    assert_eq!(disk_grants(&live), before);
    live.restart();
    assert_eq!(live.used(), 1000);
}

#[tokio::test]
async fn expiry_api_start_purges_before_binding_listener() {
    let (fx, expiry) = expiring_fixture().await;
    wait_for_expiry(expiry).await;
    assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
    // Occupy the address: serve must purge before even attempting its bind.
    // No HTTP server or request can clean the store on this test's behalf.
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_stop, rx) = tokio::sync::watch::channel(false);
    let err = konsensus_api::serve(occupied.local_addr().unwrap(), fx.state.clone(), rx)
        .await
        .unwrap_err();
    assert_eq!(
        err.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::AddrInUse
    );
    assert_eq!(disk_grants(&fx), json!([]), "API startup skipped purge");
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn expiry_api_start_refuses_failed_cleanup_before_binding() {
    let (fx, expiry) = expiring_fixture().await;
    let blocker = fx.tmp.path().join("pairing/clients.json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    wait_for_expiry(expiry).await;
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (_stop, rx) = tokio::sync::watch::channel(false);
    let err = konsensus_api::serve(occupied.local_addr().unwrap(), fx.state.clone(), rx)
        .await
        .unwrap_err();
    assert!(
        err.downcast_ref::<pairing::PairingError>().is_some(),
        "API attempted bind before refusing failed cleanup: {err}"
    );
    assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
    std::fs::remove_dir(blocker).unwrap();
    fx.service.prune_expired_grants().unwrap();
    assert_eq!(disk_grants(&fx), json!([]));
}

#[tokio::test]
async fn expiry_offline_restart_purges_before_any_api_access() {
    let (mut fx, expiry) = expiring_fixture().await;
    let stale = fx.token().await;
    wait_for_expiry(expiry).await;
    assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
    fx.restart();
    // Assert durable removal before even constructing an HTTP request.
    assert_eq!(disk_grants(&fx), json!([]));
    assert_eq!(
        fx.call("GET", "/api/v1/pair/grant", None, Some(&stale))
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(fx.compose(&stale).await.0, StatusCode::UNAUTHORIZED);
    let read = fx.token().await;
    let (status, body) = fx
        .call("GET", "/api/v1/pair/grant", None, Some(&read))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({"grant": null}));
    assert_eq!(fx.compose(&read).await.0, StatusCode::FORBIDDEN);
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn failed_revocation_paths_stay_inert_and_retry_durable_deletion() {
    for operation in ["grant", "all", "epoch", "pairing", "rotation", "identity"] {
        let fx = fixture().await;
        let token = fx.grant(None, GrantTerms::new(10_000)).await;
        let epoch = fx.service.snapshot().clients[0].epoch;
        let blocker = fx.tmp.path().join("pairing/clients.json.tmp");
        std::fs::create_dir(&blocker).unwrap();
        let result = match operation {
            "grant" => fx.service.revoke_grants(Some(&fx.client_id)).map(|_| ()),
            "all" => fx.service.revoke_grants(None).map(|_| ()),
            "epoch" => fx.service.bump_epoch(&fx.client_id).map(|_| ()),
            "pairing" => fx.service.revoke(&fx.client_id),
            "rotation" => {
                let new_key = SigningKey::from_bytes(&[9u8; 32]);
                let new_pub = hex::encode(new_key.verifying_key().to_bytes());
                let msg = format!("bitsov-pair-rotate-v1:{}:{new_pub}", fx.client_id);
                let sig = hex::encode(fx.key.sign(msg.as_bytes()).to_bytes());
                fx.service
                    .rotate_client_key(&fx.client_id, &new_pub, &sig)
                    .map(|_| ())
            }
            "identity" => fx.service.rebind_to_identity("replacement-identity"),
            _ => unreachable!(),
        };
        assert!(result.is_err(), "{operation}: write fault must fire");
        assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
        assert!(fx.service.grant_view_for(&fx.client_id).is_none());
        assert_eq!(fx.compose(&token).await.0, StatusCode::UNAUTHORIZED);
        assert_eq!(
            fx.service.reserve_spend(
                &fx.client_id,
                epoch,
                vec![Charge {
                    recipient: fx.peer.to_hex(),
                    amount_msat: 1000
                }],
            ),
            Err(BudgetRefusal::NoGrant),
            "{operation}: failed deletion must never restore spend authority"
        );
        assert!(
            fx.service.prune_expired_grants().is_err(),
            "{operation}: cleanup forgot a deletion that is still blocked"
        );
        std::fs::remove_dir(&blocker).unwrap();
        assert_eq!(fx.service.prune_expired_grants().unwrap(), 1, "{operation}");
        assert_eq!(
            disk_grants(&fx),
            json!([]),
            "{operation}: deletion was lost"
        );
        assert_eq!(fx.service.prune_expired_grants().unwrap(), 0);
        assert_eq!(fx.wallet.money(), 0);
    }
}

#[tokio::test]
async fn failed_revoke_is_purged_after_expiry_by_sweep() {
    let (fx, expiry) = expiring_fixture().await;
    let blocker = fx.tmp.path().join("pairing/clients.json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    assert!(fx.service.revoke_grants(Some(&fx.client_id)).is_err());
    std::fs::remove_dir(&blocker).unwrap();
    wait_for_expiry(expiry).await;
    assert_eq!(disk_grants(&fx).as_array().unwrap().len(), 1);
    assert_eq!(fx.service.prune_expired_grants().unwrap(), 1);
    assert_eq!(disk_grants(&fx), json!([]));
}

#[tokio::test]
async fn failed_revoke_is_retried_at_shutdown_without_waiting_for_expiry() {
    let fx = fixture().await;
    fx.grant(None, GrantTerms::new(10_000)).await;
    let blocker = fx.tmp.path().join("pairing/clients.json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    assert!(fx.service.revoke_grants(Some(&fx.client_id)).is_err());
    std::fs::remove_dir(&blocker).unwrap();
    let (_stop, rx) = tokio::sync::watch::channel(true);
    control::sweep_expired_grants(Arc::clone(&fx.service), rx).await;
    assert_eq!(disk_grants(&fx), json!([]), "shutdown forgot failed revoke");
}

#[tokio::test]
async fn failed_revoke_expired_disk_record_is_purged_at_startup() {
    let (mut fx, expiry) = expiring_fixture().await;
    let blocker = fx.tmp.path().join("pairing/clients.json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    assert!(fx.service.revoke_grants(Some(&fx.client_id)).is_err());
    wait_for_expiry(expiry).await;
    assert!(PairingService::open(fx.tmp.path(), fx.service.bound_fingerprint(), true).is_err());
    std::fs::remove_dir(&blocker).unwrap();
    fx.restart();
    assert_eq!(
        disk_grants(&fx),
        json!([]),
        "startup must purge before API access"
    );
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn failed_revoke_remains_retryable_if_replacement_write_also_fails() {
    let fx = fixture().await;
    fx.grant(None, GrantTerms::new(10_000)).await;
    let old_id = disk_grants(&fx)[0]["op_id"].clone();
    let request = fx
        .service
        .create_elevation_request(&fx.client_id, vec![Scope::Spend])
        .unwrap();
    let confirmation = fx
        .console
        .confirmation(&pairing::grant_confirmation_phrase(&request));
    let blocker = fx.tmp.path().join("pairing/clients.json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    assert!(fx.service.revoke_grants(Some(&fx.client_id)).is_err());
    assert!(fx
        .service
        .grant_elevation(&request.op_id, &confirmation, GrantTerms::new(5000))
        .is_err());
    assert_eq!(disk_grants(&fx)[0]["op_id"], old_id);
    std::fs::remove_dir(&blocker).unwrap();
    // The pending replacement must not erase the old deletion obligation.
    fx.service.prune_expired_grants().unwrap();
    let grants = disk_grants(&fx);
    assert!(grants
        .as_array()
        .unwrap()
        .iter()
        .all(|g| g["op_id"] != old_id));
    assert_eq!(fx.wallet.money(), 0);
}
