mod common;

use konsensus_api::calls::devices::Devices;
use konsensus_core::{
    payloads::call::{Phase, TOMBSTONE_MS},
    NodeId, PaymentProof, Recipient, UkmEnvelope, UkmEnvelopeBuilder,
};
use konsensus_storage::{SqliteStorage, Storage};

const CALL: &str = "0123456789abcdef0123456789abcdef";

fn own() -> NodeId {
    NodeId::from_bytes([201; 32])
}
fn invite(seed: u8) -> (UkmEnvelope, String) {
    (
        UkmEnvelopeBuilder::new(
            400,
            NodeId::from_bytes([202; 32]),
            Recipient::Node(own()),
            vec![seed],
            PaymentProof::new([seed; 32], [seed; 32], 10_000),
        )
        .build(),
        format!(r#"{{"v":1,"call_id":"{CALL}","media":"audio","sdp":"v=0"}}"#),
    )
}

#[tokio::test]
async fn no_device_is_refused_at_fifteen_seconds_and_withdrawn() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (env, text) = invite(1);
    db.accept_paid_envelope(&env).await.unwrap();
    devices
        .admit(&db, &own(), &env, Some(&text), 1_000, || 1_000)
        .await
        .unwrap();
    assert!(devices.sweep(&db, 15_999).await.unwrap().is_empty());
    let notices = devices.sweep(&db, 16_000).await.unwrap();
    assert!(
        matches!(&notices[..], [(peer, konsensus_message::Frame::MessageReject { id, reason })] if *peer == env.sender && *id == env.id && reason == "call_not_reachable")
    );
    let row = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
    assert_eq!(
        (row.phase, row.deadline_ms),
        (Phase::Ended, 16_000 + TOMBSTONE_MS)
    );
    assert!(db.get_message(&env.id).await.unwrap().is_none());
    assert!(!db.is_paid_envelope_accepted(&env).await.unwrap());
    assert!(devices.sweep(&db, 16_001).await.unwrap().is_empty());
}

#[tokio::test]
async fn device_delivery_starts_once_and_historical_fetch_cannot_ring_a_new_call() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (old, text) = invite(2);
    // The receive gate has accepted each paid invite before admission.
    db.accept_paid_envelope(&old).await.unwrap();
    devices
        .admit(&db, &own(), &old, Some(&text), 1_000, || 1_000)
        .await
        .unwrap();
    devices.fetched(&db, &old, || 11_000).await.unwrap();
    devices.fetched(&db, &old, || 14_000).await.unwrap();
    let row = db.call_get(&old.sender, CALL).await.unwrap().unwrap();
    assert_eq!((row.phase, row.deadline_ms), (Phase::Ringing, 71_000));
    assert!(
        matches!(&devices.sweep(&db, 16_000).await.unwrap()[..], [(_, konsensus_message::Frame::MessageAck { id, duplicate: false, paid_until_ms: None })] if *id == old.id)
    );
    assert!(devices.sweep(&db, 16_100).await.unwrap().is_empty());
    assert_eq!(row.at(71_000).unwrap().phase, Phase::Ended);
    let (new, text) = invite(3);
    db.accept_paid_envelope(&new).await.unwrap();
    devices
        .admit(
            &db,
            &own(),
            &new,
            Some(&text),
            71_000 + TOMBSTONE_MS + 1,
            || 71_000 + TOMBSTONE_MS + 1,
        )
        .await
        .unwrap();
    assert!(!devices
        .deliverable(&db, &old, Some(&text), || 71_000 + TOMBSTONE_MS + 2)
        .await
        .unwrap());
    devices
        .fetched(&db, &old, || 71_000 + TOMBSTONE_MS + 2)
        .await
        .unwrap();
    assert_eq!(
        db.call_get(&new.sender, CALL).await.unwrap().unwrap().phase,
        Phase::AwaitingDevice
    );
}

#[tokio::test]
async fn late_fetch_and_resend_cannot_revive_an_expired_awaiting_row() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (env, text) = invite(4);
    db.accept_paid_envelope(&env).await.unwrap();
    devices
        .admit(&db, &own(), &env, Some(&text), 1_000, || 1_000)
        .await
        .unwrap();
    devices.fetched(&db, &env, || 16_000).await.unwrap();
    assert!(!devices
        .deliverable(&db, &env, Some(&text), || 16_000)
        .await
        .unwrap());
    assert!(!devices
        .deliverable(&db, &env, Some(&text), || 16_000 + TOMBSTONE_MS + 1)
        .await
        .unwrap());
    assert_eq!(devices.sweep(&db, 16_000).await.unwrap().len(), 1);
}

#[tokio::test]
async fn restart_ends_awaiting_rows_and_sweep_removes_them() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("node.sqlite");
    let (env, text) = invite(5);
    {
        let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
        db.accept_paid_envelope(&env).await.unwrap();
        Devices::default()
            .admit(&db, &own(), &env, Some(&text), 1_000, || 1_000)
            .await
            .unwrap();
        db.pool().close().await;
    }
    let db = SqliteStorage::open(path.to_str().unwrap()).await.unwrap();
    konsensus_api::calls::recover(&db).await.unwrap();
    let row = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
    assert_eq!(row.phase, Phase::Ended);
    assert!(db.get_message(&env.id).await.unwrap().is_none());
    assert_eq!(
        db.call_invite_outcome(&env).await.unwrap(),
        Some(konsensus_storage::CallInviteOutcome::NotReachable)
    );
    db.call_sweep(row.deadline_ms, 10_000).await.unwrap();
    assert!(db.call_get(&env.sender, CALL).await.unwrap().is_none());
}

async fn paired_state() -> (
    tempfile::TempDir,
    std::sync::Arc<konsensus_api::AppState>,
    std::sync::Arc<SqliteStorage>,
    String,
) {
    use konsensus_api::{
        auth::{create_paired_token, Scope},
        pairing::{self, PairingService},
    };
    let dir = tempfile::tempdir().unwrap();
    let db = std::sync::Arc::new(SqliteStorage::in_memory().await.unwrap());
    let base = common::test_state_with_storage(db.clone());
    let service = std::sync::Arc::new(
        PairingService::open(
            dir.path(),
            pairing::identity_fingerprint(&base.identity.node_id().to_hex()),
            false,
        )
        .unwrap()
        .without_stdout_code(),
    );
    service.open_pairing_window(std::time::Duration::from_secs(60));
    let key = ed25519_dalek::SigningKey::from_bytes(&[77; 32]);
    let client = service
        .create_verified_remote_pairing(
            "app",
            &hex::encode(key.verifying_key().to_bytes()),
            &[77; 32],
        )
        .unwrap();
    let token = create_paired_token(
        &base.identity.node_id().to_hex(),
        &base.jwt_secret,
        vec![Scope::Read, Scope::Receive],
        &client.client_id,
        client.epoch,
        &service.bound_fingerprint(),
    )
    .unwrap();
    let state = std::sync::Arc::new(konsensus_api::AppState {
        pairing: Some(service),
        plaintext_cipher: Some(std::sync::Arc::new(
            konsensus_crypto::PlaintextCacheCipher::new(&[88; 32]),
        )),
        ..(*base).clone()
    });
    (dir, state, db, token)
}

async fn stored_invite(
    state: &konsensus_api::AppState,
    db: &SqliteStorage,
) -> (UkmEnvelope, String) {
    let (mut env, text) = invite(6);
    env.recipient = Recipient::Node(*state.identity.node_id());
    db.accept_paid_envelope(&env).await.unwrap();
    db.store_message_plaintext(
        &env.id,
        &state
            .plaintext_cipher
            .as_ref()
            .unwrap()
            .encrypt(text.as_bytes())
            .unwrap(),
    )
    .await
    .unwrap();
    state
        .call_devices
        .admit(
            db,
            state.identity.node_id(),
            &env,
            Some(&text),
            konsensus_api::calls::now_ms(),
            konsensus_api::calls::now_ms,
        )
        .await
        .unwrap();
    (env, text)
}

#[tokio::test]
async fn paired_message_fetch_starts_ringing_but_owner_inspection_does_not() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    for path in ["", "/plaintext", "list"] {
        let (_dir, state, db, token) = paired_state().await;
        let (env, _) = stored_invite(&state, &db).await;
        let uri = if path == "list" {
            "/api/v1/messages".to_string()
        } else {
            format!("/api/v1/messages/{}{path}", env.id.to_hex())
        };
        let req = |authorization: String| {
            Request::builder()
                .uri(&uri)
                .header("authorization", authorization)
                .body(Body::empty())
                .unwrap()
        };
        let reply = common::test_router(state.clone())
            .oneshot(req(common::auth_header(&state)))
            .await
            .unwrap();
        assert!(reply.status().is_success());
        assert_eq!(
            db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase,
            Phase::AwaitingDevice
        );
        let before = konsensus_api::calls::now_ms();
        let reply = common::test_router(state.clone())
            .oneshot(req(format!("Bearer {token}")))
            .await
            .unwrap();
        assert!(reply.status().is_success(), "{path}: {}", reply.status());
        let row = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
        assert_eq!(row.phase, Phase::Ringing, "{path}");
        assert!(
            (before + 60_000..=konsensus_api::calls::now_ms() + 60_000).contains(&row.deadline_ms)
        );
    }
}

#[tokio::test]
async fn internal_subscriber_and_resync_enqueue_do_not_start_ringing() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let (_dir, state, db, _) = paired_state().await;
    let (env, _) = stored_invite(&state, &db).await;
    let mut internal = state.ws_broadcast.subscribe();
    let request = Request::builder().method("POST").uri("/api/v1/messages/resync")
        .header("authorization", common::auth_header(&state)).header("content-type", "application/json")
        .body(Body::from(serde_json::json!({"phase":"fulfill", "peer_id":env.sender.to_hex(), "message_ids":[env.id.to_hex()]}).to_string())).unwrap();
    let reply = common::test_router(state.clone())
        .oneshot(request)
        .await
        .unwrap();
    assert!(reply.status().is_success());
    assert!(internal.try_recv().is_ok());
    assert_eq!(
        db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase,
        Phase::AwaitingDevice
    );
}

async fn ws_connect(
    addr: std::net::SocketAddr,
    token: &str,
    subprotocol: bool,
) -> (u16, tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (query, header) = if subprotocol {
        (
            String::new(),
            format!("Sec-WebSocket-Protocol: bitsov.v1, bitsov.jwt.{token}\r\n"),
        )
    } else {
        (format!("?token={token}"), String::new())
    };
    stream.write_all(format!("GET /api/v1/ws{query} HTTP/1.1\r\nHost: {addr}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n{header}\r\n").as_bytes()).await.unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !response.ends_with(b"\r\n\r\n") {
            response.push(stream.read_u8().await.unwrap());
            assert!(response.len() < 8192);
        }
    })
    .await
    .unwrap();
    let status = std::str::from_utf8(&response)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    (status, stream)
}

async fn read_ws_text(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        assert_eq!(stream.read_u8().await.unwrap(), 0x81);
        let size = stream.read_u8().await.unwrap();
        assert!(size <= 126, "unmasked, bounded fixture frame");
        let size = if size == 126 {
            stream.read_u16().await.unwrap() as usize
        } else {
            size as usize
        };
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).await.unwrap();
        String::from_utf8(bytes).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn successful_paired_websocket_write_starts_ringing() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_dir, state, db, token) = paired_state().await;
    let (env, text) = stored_invite(&state, &db).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = konsensus_api::build_router_for_addr(state.clone(), addr);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let (status, mut socket) = ws_connect(addr, &token, true).await;
    assert_eq!(status, 101);
    socket.write_all(&[0x89, 0x80, 0, 0, 0, 0]).await.unwrap();
    assert_eq!(socket.read_u8().await.unwrap(), 0x8a);
    assert_eq!(socket.read_u8().await.unwrap(), 0);
    let before = konsensus_api::calls::now_ms();
    state
        .ws_broadcast
        .send(std::sync::Arc::new(konsensus_api::state::WsMessage {
            envelope: env.clone(),
            plaintext: Some(text),
        }))
        .unwrap();
    let received: serde_json::Value =
        serde_json::from_str(&read_ws_text(&mut socket).await).unwrap();
    assert_eq!(received["id"], env.id.to_hex());
    let result = tokio::time::timeout(std::time::Duration::from_millis(500), async {
        loop {
            let row = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
            if row.phase == Phase::Ringing {
                break row;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    let row = result.expect("successful device write must start ringing");
    assert!((before + 60_000..=konsensus_api::calls::now_ms() + 60_000).contains(&row.deadline_ms));
    let outgoing = UkmEnvelopeBuilder::new(
        400,
        *state.identity.node_id(),
        Recipient::Node(env.sender),
        vec![99],
        env.payment_proof.clone(),
    )
    .build();
    state
        .ws_broadcast
        .send(std::sync::Arc::new(konsensus_api::state::WsMessage {
            envelope: outgoing.clone(),
            plaintext: Some("outgoing invite".into()),
        }))
        .unwrap();
    let received: serde_json::Value =
        serde_json::from_str(&read_ws_text(&mut socket).await).unwrap();
    assert_eq!(
        received["id"],
        outgoing.id.to_hex(),
        "callee filtering must preserve outgoing invite notifications"
    );
    server.abort();
}

#[tokio::test]
async fn failed_expiry_cleanup_retries_without_losing_other_refusals() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let mut envs = Vec::new();
    for seed in [10, 11] {
        let (env, text) = invite(seed);
        let text = text.replace(CALL, &format!("{seed:032x}"));
        db.accept_paid_envelope(&env).await.unwrap();
        devices
            .admit(&db, &own(), &env, Some(&text), 1_000, || 1_000)
            .await
            .unwrap();
        envs.push(env);
    }
    sqlx::query(&format!("CREATE TRIGGER fail_one_withdraw BEFORE DELETE ON messages WHEN OLD.id = '{}' BEGIN SELECT RAISE(FAIL, 'temporary failure'); END", envs[0].id.to_hex())).execute(db.pool()).await.unwrap();
    let first = devices.sweep(&db, 16_000).await.unwrap();
    assert_eq!(
        first.len(),
        2,
        "a durable hold allows refusal even if physical deletion fails"
    );
    assert!(db.call_admission_held(&envs[0].id).await.unwrap());
    assert!(
        db.get_message(&envs[0].id).await.unwrap().is_none(),
        "expired invite must stay invisible while cleanup retries"
    );
    assert_eq!(
        db.call_get(&envs[0].sender, &format!("{:032x}", 10))
            .await
            .unwrap()
            .unwrap()
            .phase,
        Phase::Ended
    );
    db.call_sweep(16_000 + TOMBSTONE_MS + 1, 10_000)
        .await
        .unwrap();
    sqlx::query("DROP TRIGGER fail_one_withdraw")
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(
        konsensus_api::calls::withdraw_held(&db, false)
            .await
            .unwrap(),
        1
    );
    assert!(!db.call_admission_held(&envs[0].id).await.unwrap());
    assert!(!db.is_paid_envelope_accepted(&envs[0]).await.unwrap());
    assert!(
        devices
            .sweep(&db, 16_000 + TOMBSTONE_MS + 2)
            .await
            .unwrap()
            .is_empty(),
        "refusal is emitted once"
    );
}

#[tokio::test]
async fn slow_admission_keeps_arrival_deadline_and_ages_other_signals_before_classification() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (env, text) = invite(12);
    devices
        .admit(&db, &own(), &env, Some(&text), 1_000, || 15_000)
        .await
        .unwrap();
    assert_eq!(
        db.call_get(&env.sender, CALL)
            .await
            .unwrap()
            .unwrap()
            .deadline_ms,
        16_000
    );
    devices.fetched(&db, &env, || 16_000).await.unwrap();
    assert_eq!(
        db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase,
        Phase::AwaitingDevice
    );
    let ice = UkmEnvelopeBuilder::new(
        402,
        env.sender,
        Recipient::Node(own()),
        vec![],
        PaymentProof::new([13; 32], [13; 32], 1_000),
    )
    .build();
    let text = format!(r#"{{"v":1,"call_id":"{CALL}","candidate":"ice"}}"#);
    assert!(
        devices
            .admit(&db, &own(), &ice, Some(&text), 15_999, || 16_000)
            .await
            .is_err(),
        "processing after expiry cannot admit a signal that arrived just before expiry"
    );
}

#[tokio::test]
async fn encrypted_storage_restart_ends_an_awaiting_invite() {
    let db = konsensus_storage::EncryptedStorage::new(
        SqliteStorage::in_memory().await.unwrap(),
        &[7; 32],
    );
    let (env, text) = invite(14);
    db.accept_paid_envelope(&env).await.unwrap();
    Devices::default()
        .admit(&db, &own(), &env, Some(&text), 1_000, || 1_000)
        .await
        .unwrap();
    konsensus_api::calls::recover(&db).await.unwrap();
    assert_eq!(
        db.call_invite_outcome(&env).await.unwrap(),
        Some(konsensus_storage::CallInviteOutcome::NotReachable)
    );
    assert!(db.get_message(&env.id).await.unwrap().is_none());
    assert_eq!(
        db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase,
        Phase::Ended
    );
}

#[tokio::test]
async fn encrypted_storage_expires_and_withdraws_an_unfetched_invite() {
    let db = konsensus_storage::EncryptedStorage::new(
        SqliteStorage::in_memory().await.unwrap(),
        &[7; 32],
    );
    let devices = Devices::default();
    let (env, text) = invite(15);
    db.accept_paid_envelope(&env).await.unwrap();
    devices
        .admit(&db, &own(), &env, Some(&text), 1_000, || 1_000)
        .await
        .unwrap();
    assert_eq!(devices.sweep(&db, 16_000).await.unwrap().len(), 1);
    assert_eq!(
        db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase,
        Phase::Ended
    );
    assert!(db.get_message(&env.id).await.unwrap().is_none());
    assert!(!db.is_paid_envelope_accepted(&env).await.unwrap());
}

#[tokio::test]
async fn failed_rehold_cannot_be_lost_when_a_call_id_becomes_reusable() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (old, text) = invite(16);
    db.accept_paid_envelope(&old).await.unwrap();
    devices
        .admit(&db, &own(), &old, Some(&text), 1_000, || 1_000)
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER fail_rehold BEFORE INSERT ON call_admission_hold BEGIN SELECT RAISE(FAIL, 'temporary hold failure'); END").execute(db.pool()).await.unwrap();
    assert!(devices.sweep(&db, 16_000).await.unwrap().is_empty());
    let after_gc = 16_000 + TOMBSTONE_MS + 1;
    db.call_sweep(after_gc, 10_000).await.unwrap();
    let (new, text) = invite(17);
    devices
        .admit(&db, &own(), &new, Some(&text), after_gc, || after_gc)
        .await
        .unwrap();
    let newer = db.call_get(&new.sender, CALL).await.unwrap().unwrap();
    assert_eq!(newer.phase, Phase::AwaitingDevice);
    sqlx::query("DROP TRIGGER fail_rehold")
        .execute(db.pool())
        .await
        .unwrap();
    assert_eq!(devices.sweep(&db, after_gc + 1).await.unwrap().len(), 1);
    assert!(db.get_message(&old.id).await.unwrap().is_none());
    assert_eq!(
        db.call_get(&new.sender, CALL).await.unwrap().unwrap(),
        newer,
        "cleaning up an old envelope cannot end or restart the new call"
    );
}

#[tokio::test]
async fn old_wait_cannot_borrow_device_delivery_from_a_reused_call_id() {
    use konsensus_storage::CallInviteOutcome;
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (old, text) = invite(18);
    db.accept_paid_envelope(&old).await.unwrap();
    devices
        .admit(&db, &own(), &old, Some(&text), 1_000, || 1_000)
        .await
        .unwrap();
    sqlx::query("CREATE TRIGGER fail_old_rehold BEFORE INSERT ON call_admission_hold BEGIN SELECT RAISE(FAIL, 'temporary hold failure'); END").execute(db.pool()).await.unwrap();
    assert!(devices.sweep(&db, 16_000).await.unwrap().is_empty());
    let after_gc = 16_000 + TOMBSTONE_MS + 1;
    db.call_sweep(after_gc, 10_000).await.unwrap();
    let (new, text) = invite(19);
    db.accept_paid_envelope(&new).await.unwrap();
    devices
        .admit(&db, &own(), &new, Some(&text), after_gc, || after_gc)
        .await
        .unwrap();
    devices.fetched(&db, &new, || after_gc + 1).await.unwrap();
    let newer = db.call_get(&new.sender, CALL).await.unwrap().unwrap();
    devices.fetched(&db, &old, || after_gc + 2).await.unwrap();
    assert_eq!(
        db.call_invite_outcome(&old).await.unwrap(),
        Some(CallInviteOutcome::Pending),
        "a historical fetch cannot borrow the newer call's ringing state"
    );
    sqlx::query("DROP TRIGGER fail_old_rehold")
        .execute(db.pool())
        .await
        .unwrap();
    let notices = devices.sweep(&db, after_gc + 3).await.unwrap();
    assert!(notices.iter().any(|(_, frame)| matches!(frame, konsensus_message::Frame::MessageReject { id, reason } if *id == old.id && reason == "call_not_reachable")));
    assert_eq!(
        db.call_get(&new.sender, CALL).await.unwrap().unwrap(),
        newer
    );
    assert!(db.get_message(&old.id).await.unwrap().is_none());
}

#[tokio::test]
async fn pending_device_receipts_are_withdrawn_before_outbound_recovery_can_fail() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let (env, text) = invite(20);
    db.accept_paid_envelope(&env).await.unwrap();
    Devices::default()
        .admit(&db, &own(), &env, Some(&text), 1_000, || 1_000)
        .await
        .unwrap();
    sqlx::query("DROP TABLE call_state")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        konsensus_api::calls::recover(&db).await.is_err(),
        "startup must propagate unavailable call state"
    );
    assert!(
        db.get_message(&env.id).await.unwrap().is_none(),
        "an outbound recovery error must not leave orphaned device waits visible"
    );
    assert_eq!(
        db.call_invite_outcome(&env).await.unwrap(),
        Some(konsensus_storage::CallInviteOutcome::NotReachable)
    );
}

#[tokio::test]
async fn device_sweep_leaves_live_expiry_and_its_unpaid_notice_to_expire_calls() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (env, text) = invite(9);
    db.accept_paid_envelope(&env).await.unwrap();
    devices
        .admit(&db, &own(), &env, Some(&text), 1_000, || 1_000)
        .await
        .unwrap();
    devices.fetched(&db, &env, || 11_000).await.unwrap();
    assert_eq!(devices.sweep(&db, 11_100).await.unwrap().len(), 1, "ringing ack");
    // Answered and paid until 40 s; its grace ends at 50 s.
    let ringing = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
    let live = konsensus_core::payloads::call::CallEntry {
        phase: Phase::Live,
        deadline_ms: 50_000,
        paid_until_ms: Some(40_000),
        next_block_seq: 1,
        ..ringing
    };
    db.call_put(&env.sender, CALL, &live).await.unwrap();
    // Past the paid deadline and the old ring deadline: the device sweep must
    // not end the row, or the callee would never send its Unpaid hangup.
    assert!(devices.sweep(&db, 71_000).await.unwrap().is_empty());
    assert_eq!(db.call_get(&env.sender, CALL).await.unwrap().unwrap(), live);
    assert_eq!(
        konsensus_api::calls::expire_calls(&db, 71_000).await.unwrap(),
        vec![(env.sender, CALL.to_owned())]
    );
}

/// Codex FAIL on #472: a device fetch whose receipt write fails must not later
/// produce a ringing ACK; the invite stays awaiting and ends not-reachable.
#[tokio::test]
async fn failed_fetch_receipt_write_never_rings() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (env, text) = invite(11);
    db.accept_paid_envelope(&env).await.unwrap();
    devices.admit(&db, &own(), &env, Some(&text), 1_000, || 1_000).await.unwrap();
    sqlx::raw_sql("CREATE TRIGGER fail_fetch BEFORE UPDATE OF accepted ON payment_receipts WHEN NEW.accepted = 1 BEGIN SELECT RAISE(ABORT, 'injected'); END;")
        .execute(db.pool()).await.unwrap();
    assert!(devices.fetched(&db, &env, || 11_000).await.is_err());
    let row = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
    assert_eq!(row.phase, Phase::AwaitingDevice);
    assert!(devices.sweep(&db, 11_100).await.unwrap().is_empty(), "rang without a fetch");
    sqlx::raw_sql("DROP TRIGGER fail_fetch").execute(db.pool()).await.unwrap();
    let notices = devices.sweep(&db, 16_000).await.unwrap();
    assert!(matches!(&notices[..], [(_, konsensus_message::Frame::MessageReject { reason, .. })] if reason == "call_not_reachable"));
}

/// An interrupted transition (receipt written, ringing row not) reverts the
/// receipt, so neither a duplicate nor a restart can report a delivery.
#[tokio::test]
async fn interrupted_fetch_transition_reverts_its_receipt() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (env, text) = invite(12);
    db.accept_paid_envelope(&env).await.unwrap();
    devices.admit(&db, &own(), &env, Some(&text), 1_000, || 1_000).await.unwrap();
    sqlx::raw_sql("CREATE TRIGGER fail_ring BEFORE UPDATE ON call_state WHEN NEW.phase = 'ringing' BEGIN SELECT RAISE(ABORT, 'injected'); END;")
        .execute(db.pool()).await.unwrap();
    assert!(devices.fetched(&db, &env, || 11_000).await.is_err());
    assert_eq!(db.call_invite_outcome(&env).await.unwrap(), Some(konsensus_storage::CallInviteOutcome::Pending));
    assert_eq!(db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase, Phase::AwaitingDevice);
    assert!(devices.sweep(&db, 11_100).await.unwrap().is_empty());
    // A later fetch, once storage works again, rings normally.
    sqlx::raw_sql("DROP TRIGGER fail_ring").execute(db.pool()).await.unwrap();
    devices.fetched(&db, &env, || 12_000).await.unwrap();
    assert_eq!(db.call_invite_outcome(&env).await.unwrap(), Some(konsensus_storage::CallInviteOutcome::Fetched));
    assert!(matches!(&devices.sweep(&db, 12_100).await.unwrap()[..], [(_, konsensus_message::Frame::MessageAck { .. })]));
}

/// A listing whose delivery write fails withholds that invite: the device is
/// never handed a call it cannot answer, and the next listing delivers it.
#[tokio::test]
async fn listing_withholds_an_invite_whose_delivery_did_not_commit() {
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;
    let (_dir, state, db, token) = paired_state().await;
    let (env, _) = stored_invite(&state, &db).await;
    let list = || async {
        let reply = common::test_router(state.clone())
            .oneshot(Request::builder().uri("/api/v1/messages")
                .header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(reply.status().is_success(), "{}", reply.status());
        let body = axum::body::to_bytes(reply.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()
    };
    let listed = |page: &serde_json::Value| {
        page.as_array().unwrap().iter().any(|m| m["id"].as_str() == Some(env.id.to_hex().as_str()))
    };
    sqlx::raw_sql("CREATE TRIGGER fail_fetch BEFORE UPDATE OF accepted ON payment_receipts WHEN NEW.accepted = 1 BEGIN SELECT RAISE(ABORT, 'injected'); END;")
        .execute(db.pool()).await.unwrap();
    assert!(!listed(&list().await), "unanswerable invite returned");
    assert_eq!(db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase, Phase::AwaitingDevice);
    sqlx::raw_sql("DROP TRIGGER fail_fetch").execute(db.pool()).await.unwrap();
    assert!(listed(&list().await));
    assert_eq!(db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase, Phase::Ringing);
}

/// The delivery transaction commits but its request is cancelled before the
/// registry hears of it. Durable evidence wins: a retry adopts the ringing
/// state, and the original deadline sweep acknowledges instead of refusing.
#[tokio::test]
async fn delivery_committed_by_a_cancelled_request_is_acknowledged_not_refused() {
    for (seed, retry, answered) in [(13, false, false), (14, true, false), (15, false, true)] {
        let db = SqliteStorage::in_memory().await.unwrap();
        let devices = Devices::default();
        let (env, text) = invite(seed);
        db.accept_paid_envelope(&env).await.unwrap();
        devices.admit(&db, &own(), &env, Some(&text), 1_000, || 1_000).await.unwrap();
        let row = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
        // The commit lands; the cancelled future never updates the registry.
        db.call_invite_deliver(&env.id, &env.sender, CALL, &row.device_fetched(11_000).unwrap())
            .await
            .unwrap();
        if retry {
            devices.fetched(&db, &env, || 12_000).await.unwrap();
            assert!(matches!(&devices.sweep(&db, 12_100).await.unwrap()[..],
                [(_, konsensus_message::Frame::MessageAck { .. })]));
        }
        if answered {
            // The device got the invite through the committed delivery and answered.
            let ringing = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
            db.call_put(&env.sender, CALL, &konsensus_core::payloads::call::CallEntry { phase: Phase::Live, ..ringing })
                .await
                .unwrap();
        }
        let notices = devices.sweep(&db, 16_000).await.unwrap();
        assert!(notices.iter().all(|(_, f)| !matches!(f, konsensus_message::Frame::MessageReject { .. })), "seed {seed}");
        assert_eq!(notices.len(), usize::from(!retry), "seed {seed}: {notices:?}");
        assert_eq!(db.call_invite_outcome(&env).await.unwrap(), Some(konsensus_storage::CallInviteOutcome::Fetched));
        let phase = db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase;
        assert_eq!(phase, if answered { Phase::Live } else { Phase::Ringing }, "seed {seed}");
    }
}

/// Delivery and expiry are each one transaction decided on the invite's
/// receipt, so in either commit order exactly one wins and the loser writes
/// nothing: no committed delivery is refused, no expired wait rings, and a
/// stale second delivery never moves the first one's ring deadline.
#[tokio::test]
async fn delivery_and_expiry_are_mutually_exclusive_in_either_order() {
    use konsensus_storage::CallInviteOutcome::{Fetched, NotReachable};
    for (seed, delivery_first) in [(16, true), (17, false)] {
        let db = SqliteStorage::in_memory().await.unwrap();
        let devices = Devices::default();
        let (env, text) = invite(seed);
        db.accept_paid_envelope(&env).await.unwrap();
        devices.admit(&db, &own(), &env, Some(&text), 1_000, || 1_000).await.unwrap();
        let awaiting = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
        let ringing = awaiting.clone().device_fetched(11_000).unwrap();
        if delivery_first {
            assert!(db.call_invite_deliver(&env.id, &env.sender, CALL, &ringing).await.unwrap());
            assert!(!db.call_invite_expire(&env.id, &env.sender, CALL, awaiting.deadline_ms).await.unwrap());
            // A stale snapshot's second delivery adopts, never overwrites.
            let later = awaiting.clone().device_fetched(12_000).unwrap();
            assert!(!db.call_invite_deliver(&env.id, &env.sender, CALL, &later).await.unwrap());
            let row = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
            assert_eq!((row.phase, row.deadline_ms), (Phase::Ringing, ringing.deadline_ms));
            assert_eq!(db.call_invite_outcome(&env).await.unwrap(), Some(Fetched));
            assert!(!db.call_admission_held(&env.id).await.unwrap());
        } else {
            assert!(db.call_invite_expire(&env.id, &env.sender, CALL, awaiting.deadline_ms).await.unwrap());
            assert!(db.call_invite_deliver(&env.id, &env.sender, CALL, &ringing).await.is_err());
            assert_eq!(db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase, Phase::Ended);
            assert_eq!(db.call_invite_outcome(&env).await.unwrap(), Some(NotReachable));
            assert!(db.call_admission_held(&env.id).await.unwrap());
            // A retried expiry (e.g. after a failed withdrawal) still proceeds.
            assert!(db.call_invite_expire(&env.id, &env.sender, CALL, awaiting.deadline_ms).await.unwrap());
        }
    }
}

/// A stream write in flight holds off expiry: the sweep at the deadline
/// waits for it, and a completed write rings from its own time even when it
/// finished after the deadline and storage failed to record it at once.
#[tokio::test]
async fn in_flight_stream_write_cannot_lose_to_expiry() {
    let db = SqliteStorage::in_memory().await.unwrap();
    let devices = Devices::default();
    let (env, text) = invite(18);
    db.accept_paid_envelope(&env).await.unwrap();
    devices.admit(&db, &own(), &env, Some(&text), 1_000, || 1_000).await.unwrap();
    let mut ticket = devices.stream(&db, &env, Some(&text), || 15_900).await.unwrap().expect("deliverable");
    assert!(devices.sweep(&db, 16_100).await.unwrap().is_empty(), "expired under an in-flight write");
    assert_eq!(db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase, Phase::AwaitingDevice);
    ticket.written(15_950);
    drop(ticket);
    let notices = devices.sweep(&db, 16_200).await.unwrap();
    assert!(matches!(&notices[..], [(_, konsensus_message::Frame::MessageAck { .. })]), "{notices:?}");
    let row = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
    assert_eq!((row.phase, row.deadline_ms), (Phase::Ringing, 15_950 + konsensus_core::payloads::call::RING_TIMEOUT_MS));
    // An interrupted write leaves no evidence: the next wait expires normally.
    let (env, text) = invite(19);
    let devices = Devices::default();
    let db = SqliteStorage::in_memory().await.unwrap();
    db.accept_paid_envelope(&env).await.unwrap();
    devices.admit(&db, &own(), &env, Some(&text), 1_000, || 1_000).await.unwrap();
    drop(devices.stream(&db, &env, Some(&text), || 15_900).await.unwrap());
    let notices = devices.sweep(&db, 16_100).await.unwrap();
    assert!(matches!(&notices[..], [(_, konsensus_message::Frame::MessageReject { reason, .. })] if reason == "call_not_reachable"));
}

/// Through the real WebSocket handler: the device receives the invite but
/// recording the delivery fails. The sweep past the device deadline refuses
/// nothing; a later paired fetch after storage recovers rings from the first
/// write, not from itself, and the caller is acknowledged.
#[tokio::test]
async fn websocket_delivery_survives_a_failed_record_and_anchors_the_ring_clock() {
    use axum::{body::Body, http::Request};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tower::ServiceExt;
    let (_dir, state, db, token) = paired_state().await;
    let (env, text) = stored_invite(&state, &db).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = konsensus_api::build_router_for_addr(state.clone(), addr);
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await.unwrap();
    });
    let (status, mut socket) = ws_connect(addr, &token, true).await;
    assert_eq!(status, 101);
    socket.write_all(&[0x89, 0x80, 0, 0, 0, 0]).await.unwrap();
    assert_eq!(socket.read_u8().await.unwrap(), 0x8a);
    assert_eq!(socket.read_u8().await.unwrap(), 0);
    sqlx::raw_sql("CREATE TRIGGER fail_fetch BEFORE UPDATE OF accepted ON payment_receipts WHEN NEW.accepted = 1 BEGIN SELECT RAISE(ABORT, 'injected'); END;")
        .execute(db.pool()).await.unwrap();
    let before = konsensus_api::calls::now_ms();
    state.ws_broadcast.send(std::sync::Arc::new(konsensus_api::state::WsMessage { envelope: env.clone(), plaintext: Some(text) })).unwrap();
    let received: serde_json::Value = serde_json::from_str(&read_ws_text(&mut socket).await).unwrap();
    assert_eq!(received["id"], env.id.to_hex());
    let written = konsensus_api::calls::now_ms();
    // The handler gives up on the connection once recording fails.
    let mut rest = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), socket.read_to_end(&mut rest)).await.unwrap().ok();
    assert_eq!(db.call_get(&env.sender, CALL).await.unwrap().unwrap().phase, Phase::AwaitingDevice);
    let notices = state.call_devices.sweep(db.as_ref(), written + 16_000).await.unwrap();
    assert!(notices.is_empty(), "delivered invite refused: {notices:?}");
    sqlx::raw_sql("DROP TRIGGER fail_fetch").execute(db.pool()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let reply = common::test_router(state.clone())
        .oneshot(Request::builder().uri("/api/v1/messages").header("authorization", format!("Bearer {token}")).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert!(reply.status().is_success());
    let row = db.call_get(&env.sender, CALL).await.unwrap().unwrap();
    assert_eq!(row.phase, Phase::Ringing);
    let ring = konsensus_core::payloads::call::RING_TIMEOUT_MS;
    assert!((before + ring..=written + ring).contains(&row.deadline_ms), "ring clock moved to the later fetch");
    let notices = state.call_devices.sweep(db.as_ref(), konsensus_api::calls::now_ms()).await.unwrap();
    assert!(matches!(&notices[..], [(_, konsensus_message::Frame::MessageAck { .. })]), "{notices:?}");
    server.abort();
}
