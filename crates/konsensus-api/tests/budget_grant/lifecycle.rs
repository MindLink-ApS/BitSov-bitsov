//! Grant lifecycle regressions: mocks and disposable data only.

use super::*;
#[derive(Clone, Copy)]
enum Invalidation {
    Revoke,
    Rotate,
    Expire,
    Replace,
}

fn shorten_grant(fx: &mut Fx) {
    let path = fx.tmp.path().join("pairing/clients.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let now = chrono::Utc::now().timestamp();
    file["grants"][0]["granted_at"] = json!(now - 100);
    file["grants"][0]["expires_at"] = json!(now + 3);
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    fx.restart();
}

async fn invalidate(fx: &Fx, how: Invalidation) {
    match how {
        Invalidation::Revoke => {
            fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
        }
        Invalidation::Rotate => {
            let new_key = SigningKey::from_bytes(&[9u8; 32]);
            let new_pub = hex::encode(new_key.verifying_key().to_bytes());
            let msg = format!("bitsov-pair-rotate-v1:{}:{new_pub}", fx.client_id);
            let sig = hex::encode(fx.key.sign(msg.as_bytes()).to_bytes());
            fx.service
                .rotate_client_key(&fx.client_id, &new_pub, &sig)
                .unwrap();
        }
        Invalidation::Expire => {
            let expires = fx.service.snapshot().grants[0].expires_at;
            while chrono::Utc::now().timestamp() < expires {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            // Deliberately do not sweep: dispatch must check the deadline itself.
            assert!(fx.service.grant_view_for(&fx.client_id).is_none());
        }
        Invalidation::Replace => {
            fx.grant(None, GrantTerms::new(5000)).await;
        }
    }
}

async fn pending_invoice_authority_probe(how: Invalidation, file: bool) {
    let mut fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    let route = if file {
        upload_probe_file(&fx, &token).await
    } else {
        "/api/v1/messages/compose".into()
    };
    if matches!(how, Invalidation::Expire) {
        shorten_grant(&mut fx);
    }
    fx.state.peer_ln_pubkeys.lock().await.clear();
    let state = Arc::clone(&fx.state);
    let peer = fx.peer;
    let task = tokio::spawn(async move {
        let body = if file {
            json!({"recipient":peer.to_hex()})
        } else {
            json!({"recipient": peer.to_hex(), "kind": 100, "plaintext": "pending invoice"})
        };
        call(&state, "POST", &route, Some(body), Some(&token)).await
    });
    // Hold the peer response until after authority is invalidated. The normal
    // ConnectedStubTransport has no responder, so no timing-sensitive sleep.
    let response_tx = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            {
                let mut pending = fx.state.invoice_requests.lock().await;
                if let Some(id) = pending.keys().next().cloned() {
                    break pending.remove(&id).unwrap();
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("compose never requested an invoice");
    assert_eq!(fx.used(), 1_000, "reservation must precede invoice request");
    assert_eq!(fx.wallet.money(), 0, "no payment was dispatched yet");
    invalidate(&fx, how).await;
    response_tx
        .send(konsensus_api::state::InvoiceResponseData {
            recipient: fx.peer,
            bolt11: create_test_bolt11(1_000),
            payment_hash: "00".repeat(32),
        })
        .unwrap();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .expect("compose did not finish")
        .unwrap();
    assert_eq!(
        fx.wallet.money(),
        0,
        "new invoice payment dispatched after grant invalidation; response={response:?}"
    );
    if matches!(how, Invalidation::Replace) {
        assert_eq!(
            fx.used(),
            0,
            "old reservation must not debit or release the replacement grant"
        );
    }
}

#[tokio::test]
async fn revoke_prevents_pending_invoice_dispatch() {
    pending_invoice_authority_probe(Invalidation::Revoke, false).await;
}

#[tokio::test]
async fn rotation_prevents_pending_invoice_dispatch() {
    pending_invoice_authority_probe(Invalidation::Rotate, false).await;
}

#[tokio::test]
async fn budget_refusal_preserves_ratchet() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000).per_call(999)).await;
    let before = fx
        .state
        .session_manager
        .encrypt(&fx.peer, b"counter probe before")
        .await
        .unwrap()
        .header
        .message_number;
    let (status, body) = fx.compose(&token).await;
    assert_budget_exceeded(status, &body, "per_call");
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!(fx.used(), 0);
    let after = fx
        .state
        .session_manager
        .encrypt(&fx.peer, b"counter probe after")
        .await
        .unwrap()
        .header
        .message_number;
    assert_eq!(
        after,
        before + 1,
        "budget-refused compose advanced the sender ratchet without delivering a message"
    );
}

#[tokio::test]
async fn max_total_and_grant_both_enforced() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(1_500)).await;
    let req = |cap| {
        json!({"recipient": fx.peer.to_hex(), "kind": 100,
        "plaintext": "cap and grant", "max_total_msat": cap})
    };
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/messages/compose",
            Some(req(999)),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body:?}");
    assert_eq!(body["code"], "price_cap_exceeded");
    assert_eq!(fx.used(), 0);
    assert_eq!(fx.wallet.money(), 0);
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/messages/compose",
            Some(req(1000)),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body:?}");
    assert_eq!(fx.used(), 1000);
    assert_eq!(fx.wallet.money(), 1);
    let (status, body) = fx
        .call(
            "POST",
            "/api/v1/messages/compose",
            Some(req(1000)),
            Some(&token),
        )
        .await;
    assert_budget_exceeded(status, &body, "total");
    assert_eq!(fx.used(), 1000);
    assert_eq!(fx.wallet.money(), 1);
}

/// Independent review probe: a transient cleanup write failure must not make
/// future sweeps silently skip the expired grant still stored on disk.
#[tokio::test]
async fn expiry_cleanup_retries_after_transient_write_failure() {
    let fx = fixture().await;
    let _token = fx.grant(None, GrantTerms::new(10_000)).await;
    let path = fx.tmp.path().join("pairing").join("clients.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let now = chrono::Utc::now().timestamp();
    let expires_at = now + 2;
    file["grants"][0]["granted_at"] = json!(now - 100);
    file["grants"][0]["expires_at"] = json!(expires_at);
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
    let service = open_owner_service(fx.tmp.path(), &fx.service.bound_fingerprint(), &fx.console);
    assert_eq!(
        service.snapshot().grants.len(),
        1,
        "probe must open a live grant"
    );

    // Block only the next atomic temporary-file write in this disposable
    // fixture; neither node startup nor a real Lightning provider is involved.
    let blocker = path.with_extension("json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    while chrono::Utc::now().timestamp() < expires_at {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let first = service.prune_expired_grants();
    assert!(
        first.is_err(),
        "the injected temporary-file write failure must fire"
    );
    let after_failure: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(after_failure["grants"].as_array().unwrap().len(), 1);
    assert_eq!(
        service.snapshot().grants.len(),
        0,
        "failed durable deletion must never expose an expired grant"
    );

    // The filesystem has recovered, so the next sweep should remove the
    // expired durable record even if the first attempt changed memory.
    std::fs::remove_dir(&blocker).unwrap();
    assert_eq!(service.prune_expired_grants().unwrap(), 1);
    let after_retry: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(fx.wallet.money(), 0, "probe must never dispatch a payment");
    assert_eq!(
        after_retry["grants"],
        json!([]),
        "a recovered expiry sweep must retry the earlier failed durable deletion"
    );
}

async fn wait_for_dispatches(wallet: &Wallet, count: usize) {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while wallet.waiting.load(Ordering::SeqCst) < count {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("payment future never reached the dispatch barrier");
}

async fn paused_dispatch_is_invalidated(route: &str, how: Invalidation) {
    let mut fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    if matches!(how, Invalidation::Expire) {
        shorten_grant(&mut fx);
    }
    fx.wallet.pause_dispatch.store(true, Ordering::SeqCst);
    let body = match route {
        "/api/v1/payments/pay" => json!({"bolt11": create_test_bolt11(1000)}),
        "/api/v1/payments/keysend" => json!({"dest_pubkey": OTHER_LN, "amount_msat": 1000}),
        _ => json!({"recipient": fx.peer.to_hex(), "kind": 100, "plaintext": "paused"}),
    };
    let route = route.to_string();
    let state = Arc::clone(&fx.state);
    let task =
        tokio::spawn(async move { call(&state, "POST", &route, Some(body), Some(&token)).await });
    wait_for_dispatches(&fx.wallet, 1).await;
    assert_eq!(fx.used(), 1000);
    assert_eq!(fx.wallet.money(), 0);
    invalidate(&fx, how).await;
    fx.wallet.resume.notify_waiters();
    let response = task.await.unwrap();
    assert_eq!(
        fx.wallet.money(),
        0,
        "revoked operation dispatched: {response:?}"
    );
}

#[tokio::test]
async fn suspended_direct_invoice_stops_on_revoke() {
    paused_dispatch_is_invalidated("/api/v1/payments/pay", Invalidation::Revoke).await;
}

#[tokio::test]
async fn suspended_direct_keysend_stops_on_revoke() {
    paused_dispatch_is_invalidated("/api/v1/payments/keysend", Invalidation::Revoke).await;
}

#[tokio::test]
async fn suspended_compose_keysend_stops_on_revoke() {
    paused_dispatch_is_invalidated("/api/v1/messages/compose", Invalidation::Revoke).await;
}

#[tokio::test]
async fn queued_room_members_stop_on_revoke() {
    let mut fx = fixture().await;
    let mut members = Vec::new();
    for n in 0..10 {
        let identity = konsensus_core::NodeIdentity::from_mnemonic(
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            &format!("room-peer-{n}"),
        )
        .unwrap();
        let peer = *identity.node_id();
        let peer_sm = konsensus_crypto::SessionManager::new(Arc::new(identity));
        fx.state
            .session_manager
            .initiate_session(&peer, &peer_sm.prekey_bundle().await)
            .await
            .unwrap();
        fx.state
            .peer_ln_pubkeys
            .lock()
            .await
            .insert(peer, PEER_LN.into());
        members.push(peer);
    }
    fx.state = Arc::new(AppState {
        transport: Arc::new(ConnectedStubTransport::new(
            members.clone(),
            fx.state.invoice_requests.clone(),
        )),
        ..(*fx.state).clone()
    });
    let owner = auth_header(&fx.state);
    let owner = owner.trim_start_matches("Bearer ");
    let (status, room) = fx
        .call(
            "POST",
            "/api/v1/rooms",
            Some(json!({"name":"revoked fanout"})),
            Some(owner),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let id = room["id"].as_str().unwrap();
    for peer in members {
        assert_eq!(
            fx.call(
                "POST",
                &format!("/api/v1/rooms/{id}/members"),
                Some(json!({"node_id":peer.to_hex()})),
                Some(owner)
            )
            .await
            .0,
            StatusCode::OK
        );
    }
    let body = json!({"recipient": id, "is_room": true, "kind": 100, "plaintext": "queued", "max_total_msat": 10_000});
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    fx.wallet.pause_dispatch.store(true, Ordering::SeqCst);
    let state = Arc::clone(&fx.state);
    let task = tokio::spawn(async move {
        call(
            &state,
            "POST",
            "/api/v1/messages/compose",
            Some(body),
            Some(&token),
        )
        .await
    });
    wait_for_dispatches(&fx.wallet, 8).await;
    assert_eq!(
        fx.used(),
        10_000,
        "entire fanout must be reserved before the first dispatch"
    );
    fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
    fx.wallet.pause_dispatch.store(false, Ordering::SeqCst);
    fx.wallet.resume.notify_waiters();
    let (status, receipt) = task.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["member_outcomes"].as_array().unwrap().len(), 10);
    assert_eq!(
        fx.wallet.money(),
        0,
        "queued or suspended members dispatched after revoke"
    );
}

/// F1 staging belongs to the uploader: the paired client stages its own file
/// under its live grant (the owner's staged file is not sendable by a grant).
async fn upload_probe_file(fx: &Fx, token: &str) -> String {
    let (status, file) = fx
        .call(
            "POST",
            "/api/v1/files",
            Some(json!({"filename":"grant.txt","mime_type":"text/plain","data_b64":"aGk="})),
            Some(token),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{file}");
    format!("/api/v1/files/{}/send", file["file_id"].as_str().unwrap())
}

#[tokio::test]
async fn file_budget_and_cap_refusals_preserve_ratchet() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000).per_call(999)).await;
    let path = upload_probe_file(&fx, &token).await;
    for cap in [999, 1000] {
        let before = fx
            .state
            .session_manager
            .encrypt(&fx.peer, b"before")
            .await
            .unwrap()
            .header
            .message_number;
        let (status, body) = fx
            .call(
                "POST",
                &path,
                Some(json!({"recipient":fx.peer.to_hex(),"max_total_msat":cap})),
                Some(&token),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        assert_eq!(
            body["code"],
            if cap == 999 {
                "price_cap_exceeded"
            } else {
                "budget_exceeded"
            }
        );
        let after = fx
            .state
            .session_manager
            .encrypt(&fx.peer, b"after")
            .await
            .unwrap()
            .header
            .message_number;
        assert_eq!(after, before + 1, "refused file advanced ratchet");
    }
    assert_eq!(fx.wallet.money(), 0);
    assert_eq!(fx.used(), 0);
}

#[tokio::test]
async fn suspended_file_keysend_stops_on_revoke() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(10_000)).await;
    let path = upload_probe_file(&fx, &token).await;
    fx.wallet.pause_dispatch.store(true, Ordering::SeqCst);
    let body = json!({"recipient":fx.peer.to_hex()});
    let state = Arc::clone(&fx.state);
    let task =
        tokio::spawn(async move { call(&state, "POST", &path, Some(body), Some(&token)).await });
    wait_for_dispatches(&fx.wallet, 1).await;
    fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
    fx.wallet.resume.notify_waiters();
    let _ = task.await.unwrap();
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn expiry_prevents_pending_invoice_dispatch() {
    pending_invoice_authority_probe(Invalidation::Expire, false).await;
}

#[tokio::test]
async fn replacement_prevents_old_pending_invoice_dispatch() {
    pending_invoice_authority_probe(Invalidation::Replace, false).await;
}

#[tokio::test]
async fn file_invoice_fallback_stops_on_revoke() {
    pending_invoice_authority_probe(Invalidation::Revoke, true).await;
}

#[tokio::test]
async fn file_invoice_fallback_stops_on_expiry() {
    pending_invoice_authority_probe(Invalidation::Expire, true).await;
}

#[tokio::test]
async fn suspended_direct_keysend_stops_on_expiry() {
    paused_dispatch_is_invalidated("/api/v1/payments/keysend", Invalidation::Expire).await;
}

#[tokio::test]
async fn suspended_direct_invoice_stops_on_rotation() {
    paused_dispatch_is_invalidated("/api/v1/payments/pay", Invalidation::Rotate).await;
}

#[tokio::test]
async fn peer_cap_refusal_preserves_ratchet() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(1000)).await;
    let before = fx
        .state
        .session_manager
        .encrypt(&fx.peer, b"before")
        .await
        .unwrap()
        .header
        .message_number;
    let (status, body) = fx.call("POST", "/api/v1/messages/compose",
        Some(json!({"recipient":fx.peer.to_hex(),"kind":100,"plaintext":"cap","max_total_msat":999})),
        Some(&token)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], "price_cap_exceeded");
    let after = fx
        .state
        .session_manager
        .encrypt(&fx.peer, b"after")
        .await
        .unwrap()
        .header
        .message_number;
    assert_eq!(after, before + 1);
    assert_eq!(fx.used(), 0);
    assert_eq!(fx.wallet.money(), 0);
}

#[tokio::test]
async fn file_encryption_failure_releases_reservation() {
    let fx = fixture().await;
    let token = fx.grant(None, GrantTerms::new(1000)).await;
    let path = upload_probe_file(&fx, &token).await;
    let (status, _) = fx
        .call(
            "POST",
            &path,
            Some(json!({"recipient":"ee".repeat(32)})),
            Some(&token),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(fx.used(), 0);
    assert_eq!(fx.wallet.money(), 0);
}

/// Models a Noise frame whose header/nonce is committed before socket
/// backpressure. Revocation must not cancel its remaining ciphertext write.
struct PartialFrameTransport {
    inner: ConnectedStubTransport,
    started: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    completed: AtomicBool,
}

#[async_trait]
impl konsensus_core::traits::transport::MessageTransport for PartialFrameTransport {
    async fn send(
        &self,
        peer: &NodeId,
        envelope: &konsensus_core::UkmEnvelope,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.send(peer, envelope).await
    }
    async fn recv(
        &self,
    ) -> Result<konsensus_core::UkmEnvelope, konsensus_core::traits::transport::TransportError>
    {
        self.inner.recv().await
    }
    async fn connect(
        &self,
        peer: &NodeId,
        addr: &str,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.connect(peer, addr).await
    }
    async fn disconnect(
        &self,
        peer: &NodeId,
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.inner.disconnect(peer).await
    }
    async fn is_connected(&self, peer: &NodeId) -> bool {
        self.inner.is_connected(peer).await
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        self.inner.connected_peers().await
    }
    async fn send_raw_frame(
        &self,
        peer: &NodeId,
        bytes: &[u8],
    ) -> Result<(), konsensus_core::traits::transport::TransportError> {
        self.started.notify_one();
        self.resume.notified().await;
        self.completed.store(true, Ordering::SeqCst);
        self.inner.send_raw_frame(peer, bytes).await
    }
}

#[tokio::test]
async fn revoke_finishes_started_invoice_frame_but_never_pays() {
    let mut fx = fixture().await;
    let transport = Arc::new(PartialFrameTransport {
        inner: ConnectedStubTransport::new(vec![fx.peer], fx.state.invoice_requests.clone()),
        started: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
        completed: AtomicBool::new(false),
    });
    fx.state = Arc::new(AppState {
        transport: transport.clone(),
        ..(*fx.state).clone()
    });
    fx.state.peer_ln_pubkeys.lock().await.clear();
    let token = fx.grant(None, GrantTerms::new(1000)).await;
    let state = fx.state.clone();
    let body = json!({"recipient":fx.peer.to_hex(),"kind":100,"plaintext":"partial frame"});
    let task = tokio::spawn(async move {
        call(
            &state,
            "POST",
            "/api/v1/messages/compose",
            Some(body),
            Some(&token),
        )
        .await
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        transport.started.notified(),
    )
    .await
    .unwrap();
    fx.service.revoke_grants(Some(&fx.client_id)).unwrap();
    let response_tx = {
        let mut pending = fx.state.invoice_requests.lock().await;
        let id = pending.keys().next().unwrap().clone();
        pending.remove(&id).unwrap()
    };
    response_tx
        .send(konsensus_api::state::InvoiceResponseData {
            recipient: fx.peer,
            bolt11: create_test_bolt11(1000),
            payment_hash: "00".repeat(32),
        })
        .unwrap();
    transport.resume.notify_one();
    let response = tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fx.wallet.money(), 0, "revoked request paid: {response:?}");
    assert!(
        transport.completed.load(Ordering::SeqCst),
        "revocation truncated a started Noise frame"
    );
}
