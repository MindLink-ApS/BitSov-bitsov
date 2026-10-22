use super::*;
use async_trait::async_trait;
use konsensus_core::traits::lightning::*;
use konsensus_storage::{InviteIssuedRecord, InviteState, SqliteStorage};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

struct Backend {
    db: Arc<dyn Storage>,
    calls: AtomicUsize,
    channels: Mutex<Vec<ChannelInfo>>,
    outcome: u8,
    connected: std::sync::atomic::AtomicBool,
    fail_channel_read: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl LightningProvider for Backend {
    async fn sign_message(&self, message: &[u8]) -> Result<String, LightningError> {
        Ok(String::from_utf8_lossy(message).into())
    }
    async fn get_node_pubkey(&self) -> Option<String> {
        Some("02".repeat(33))
    }
    async fn connect_peer(&self, _: &str, _: &str, _: bool) -> Result<(), LightningError> {
        Ok(())
    }

    async fn create_invoice(&self, _: u64, _: &str, _: u32) -> Result<Invoice, LightningError> {
        unimplemented!()
    }
    async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        unimplemented!()
    }
    async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
        unimplemented!()
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        Ok(0)
    }
    async fn is_available(&self) -> bool {
        true
    }
    fn starter_network(&self) -> Option<String> {
        Some("regtest".into())
    }
    async fn verify_message(
        &self,
        message: &[u8],
        sig: &str,
        _: &str,
    ) -> Result<bool, LightningError> {
        Ok(sig == String::from_utf8_lossy(message))
    }
    async fn list_peers(&self) -> Result<Vec<LightningPeer>, LightningError> {
        Ok(vec![LightningPeer {
            pubkey: "02".repeat(33),
            address: "192.0.2.4:9735".into(),
            connected: self.connected.load(Ordering::SeqCst),
        }])
    }
    async fn suppress_peer_address(&self, _: &str) -> Result<(), LightningError> {
        Ok(())
    }
    async fn get_balance_breakdown(&self) -> Result<WalletBalanceBreakdown, LightningError> {
        Ok(WalletBalanceBreakdown {
            onchain_spendable_sats: Some(1_000_000),
            ..Default::default()
        })
    }
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        if self.fail_channel_read.swap(false, Ordering::SeqCst) {
            return Err(LightningError::Backend("channel read failed".into()));
        }
        Ok(self.channels.lock().unwrap().clone())
    }
    async fn channel_is_ready(&self, _: &str) -> Result<bool, LightningError> {
        Ok(true)
    }
    async fn open_channel_with_funding(
        &self,
        peer: &str,
        _: &str,
        amount: u64,
        announce: bool,
        options: FundingOptions,
        push: Option<u64>,
    ) -> Result<ChannelOpenResult, LightningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let grants = self.db.starter_grants().await.unwrap();
        let g = grants
            .iter()
            .find(|g| g.ln_pubkey == peer && g.state == "opening")
            .expect("persisted grant before dispatch");
        assert!(self
            .db
            .get_channel_open_operation(&g.request_id)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            (amount, announce, push, options.max_funding_fee_sats),
            (100_000, false, Some(10_000_000), Some(2_000))
        );
        match self.outcome {
            1 => Err(LightningError::PaymentNotDispatched(
                FUNDING_FEE_CAP_EXCEEDED.into(),
            )),
            2 => Err(LightningError::PaymentNotDispatched("preflight".into())),
            3 => Ok(ChannelOpenResult {
                channel_id: "ab".repeat(32),
                user_channel_id: Some("1".into()),
                funding_txo: Some(format!("{}:0", "cd".repeat(32))),
                funding_txid: Some("cd".repeat(32)),
                funding_fee: None,
                status: ChannelOpenStatus::Opening,
            }),
            _ => Err(LightningError::Backend("ambiguous".into())),
        }
    }
}
async fn setup(outcome: u8) -> (StarterHub, Arc<Backend>, NodeId) {
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let peer = NodeId::from_bytes([7; 32]);
    db.add_invite_issued(&InviteIssuedRecord {
        id: uuid::Uuid::new_v4(),
        invitee_pubkey: *peer.as_bytes(),
        expiry_unix: 100_000,
        channel_size_hint_sats: Some(1),
        addr: String::new(),
        max_fee_rate_sat_per_vb: Some(1),
        channel_open_intent_expiry_unix: Some(100_000),
        nonce: [1; 16],
        state: InviteState::Pending,
        created_at: 1,
        accepted_at: None,
        revoked_at: None,
    })
    .await
    .unwrap();
    let backend = Arc::new(Backend {
        db: db.clone(),
        calls: AtomicUsize::new(0),
        channels: Mutex::new(vec![]),
        outcome,
        connected: std::sync::atomic::AtomicBool::new(true),
        fail_channel_read: std::sync::atomic::AtomicBool::new(false),
    });
    let hub = StarterHub {
        config: StarterHubConfig {
            enabled: true,
            ..Default::default()
        },
        storage: db,
        lightning: backend.clone(),
        hub_id: NodeId::from_bytes([8; 32]),
        network: "regtest".into(),
    };
    (hub, backend, peer)
}
fn request(hub: &StarterHub, peer: NodeId, id: uuid::Uuid) -> Frame {
    let key = "02".repeat(33);
    let signature = canonical("regtest", &hub.hub_id, &peer, id, &key);
    Frame::StarterRequest {
        v: 1,
        request_id: id,
        network: "regtest".into(),
        ln_pubkey: key,
        ln_sig: signature,
    }
}
#[tokio::test]
async fn open_uses_persisted_config_sizes_and_never_retries_ambiguous_dispatch() {
    let (hub, backend, peer) = setup(0).await;
    let id = uuid::Uuid::new_v4();
    assert!(
        matches!(hub.handle(peer,request(&hub,peer,id),Some(10)).await.unwrap(),Frame::StarterStatus{state,..} if state=="received")
    );
    hub.tick(Some(10)).await.unwrap();
    hub.tick(Some(700)).await.unwrap();
    hub.tick(Some(800)).await.unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    let c = hub.storage.starter_counters().await.unwrap();
    assert_eq!((c.inflight_count, c.committed_sats), (1, 100_000));
    assert_eq!(
        hub.storage
            .get_channel_open_operation(&id.to_string())
            .await
            .unwrap()
            .unwrap()
            .state,
        "uncertain"
    );
}
#[tokio::test]
async fn fee_cap_proof_refunds_but_other_non_dispatch_retries_only_three_times() {
    for outcome in [1, 2] {
        let (hub, backend, peer) = setup(outcome).await;
        let id = uuid::Uuid::new_v4();
        hub.handle(peer, request(&hub, peer, id), Some(10))
            .await
            .unwrap();
        for now in [10, 30, 50, 70] {
            hub.tick(Some(now)).await.unwrap();
        }
        assert_eq!(
            backend.calls.load(Ordering::SeqCst),
            if outcome == 1 { 1 } else { 3 }
        );
        let g = hub.storage.starter_grants().await.unwrap().remove(0);
        assert_eq!(g.state, "refused");
        assert_eq!(
            g.reason.as_deref(),
            Some(if outcome == 1 {
                "fee_too_high"
            } else {
                "open_failed"
            })
        );
        assert_eq!(
            hub.storage.starter_counters().await.unwrap().committed_sats,
            0
        );
    }
}
#[tokio::test]
async fn consumed_channel_ready_is_recovered_even_when_operation_already_opened() {
    for op_state in ["pending", "opened", "uncertain"] {
        let (hub, backend, peer) = setup(0).await;
        let id = uuid::Uuid::new_v4();
        hub.handle(peer, request(&hub, peer, id), Some(10))
            .await
            .unwrap();
        hub.tick(Some(10)).await.unwrap();
        if op_state != "pending" {
            hub.storage
                .resolve_channel_open_operation(&id.to_string(), op_state, None, None)
                .await
                .unwrap();
        }
        backend.channels.lock().unwrap().push(ChannelInfo {
            is_outbound: None,
            is_announced: None,
            is_channel_ready: None,
            local_reserve_msat: None,
            initial_push_msat: None,
            channel_id: "funded".into(),
            user_channel_id: Some("42".into()),
            funding_txo: Some("tx:0".into()),
            peer_pubkey: "02".repeat(33),
            capacity_msat: 100_000_000,
            local_balance_msat: 90_000_000,
            remote_balance_msat: 10_000_000,
            active: false,
            short_channel_id: None,
        });
        // No ChannelReady event exists: it was consumed just before the crash.
        hub.tick(Some(700)).await.unwrap();
        assert_eq!(
            hub.storage.starter_grants().await.unwrap()[0].state,
            "ready"
        );
        assert_eq!(
            hub.storage.starter_counters().await.unwrap().inflight_count,
            0
        );
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }
}
#[tokio::test]
async fn wrong_network_signature_and_uuid_never_reserve_or_open() {
    let (hub, backend, peer) = setup(0).await;
    for mut frame in [
        request(&hub, peer, uuid::Uuid::new_v4()),
        request(&hub, peer, uuid::Uuid::nil()),
    ] {
        if let Frame::StarterRequest { network, .. } = &mut frame {
            *network = "bitcoin".into();
        }
        assert!(
            matches!(hub.handle(peer,frame,Some(10)).await.unwrap(),Frame::StarterStatus{state,..} if state=="refused")
        );
    }
    let mut frame = request(&hub, peer, uuid::Uuid::new_v4());
    if let Frame::StarterRequest { ln_sig, .. } = &mut frame {
        *ln_sig = "invalid".into();
    }
    hub.handle(peer, frame, Some(10)).await.unwrap();
    hub.tick(Some(10)).await.unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        hub.storage.starter_counters().await.unwrap().committed_sats,
        0
    );
}
#[test]
fn startup_mainnet_unknown_backend_and_lockable_hub_are_refused() {
    let mut c = StarterHubConfig::default();
    assert!(!c.enabled);
    c.enabled = true;
    for network in [None, Some("bitcoin"), Some("testnet")] {
        assert!(c.validate(network, Some(200_000), false).is_err());
    }
    assert!(c.validate(Some("signet"), Some(200_000), false).is_ok());
    assert!(c.validate(Some("regtest"), Some(200_000), true).is_err());
    c.allow_mainnet = true;
    assert!(c.validate(Some("signet"), Some(200_000), false).is_err());
}

#[tokio::test]
async fn vanished_opened_channel_becomes_operator_resolvable_without_refund() {
    let (hub, backend, peer) = setup(0).await;
    let id = uuid::Uuid::new_v4();
    hub.handle(peer, request(&hub, peer, id), Some(10))
        .await
        .unwrap();
    hub.tick(Some(10)).await.unwrap();
    hub.storage
        .resolve_channel_open_operation(&id.to_string(), "opened", None, None)
        .await
        .unwrap();
    hub.tick(Some(1000)).await.unwrap();
    hub.storage
        .starter_update(
            StarterUpdate::ResolveUncertain { id: id.to_string() },
            Some(1000),
        )
        .await
        .unwrap();
    assert_eq!(
        hub.storage.starter_grants().await.unwrap()[0].state,
        "resolved"
    );
    assert_eq!(
        hub.storage.starter_counters().await.unwrap().inflight_count,
        0
    );
    assert_eq!(
        hub.storage.starter_counters().await.unwrap().committed_sats,
        100_000
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn disconnected_admission_with_expired_or_revoked_invite_releases_proven_unspent_cap() {
    for revoke in [false, true] {
        let (hub, backend, peer) = setup(0).await;
        let id = uuid::Uuid::new_v4();
        hub.handle(peer, request(&hub, peer, id), Some(10))
            .await
            .unwrap();
        backend.connected.store(false, Ordering::SeqCst);
        if revoke {
            let invite = hub.storage.list_invites_issued().await.unwrap()[0].id;
            hub.storage.revoke_invite(&invite, 20).await.unwrap();
        }
        hub.tick(Some(if revoke { 30 } else { 100_001 }))
            .await
            .unwrap();
        assert_eq!(
            hub.storage.starter_grants().await.unwrap()[0].state,
            "refused"
        );
        let c = hub.storage.starter_counters().await.unwrap();
        assert_eq!((c.inflight_count, c.committed_sats), (0, 0));
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn one_grants_recovery_error_does_not_starve_later_grants() {
    let (hub, backend, peer) = setup(0).await;
    let id = uuid::Uuid::new_v4();
    hub.handle(peer, request(&hub, peer, id), Some(10))
        .await
        .unwrap();
    hub.tick(Some(10)).await.unwrap();
    let orphan = StarterGrant::new(
        "later".into(),
        "other-node".into(),
        "other-key".into(),
        "regtest".into(),
        uuid::Uuid::new_v4().to_string(),
        100_000,
        10_000,
        20,
    );
    hub.storage
        .starter_update(
            StarterUpdate::Admit {
                grant: orphan,
                limits: hub.config.limits(),
            },
            Some(20),
        )
        .await
        .unwrap();
    backend.fail_channel_read.store(true, Ordering::SeqCst);
    hub.tick(Some(30)).await.unwrap();
    let grants = hub.storage.starter_grants().await.unwrap();
    assert_eq!(
        grants
            .iter()
            .find(|g| g.request_id == "later")
            .unwrap()
            .state,
        "refused"
    );
    assert_eq!(
        hub.storage.starter_counters().await.unwrap().committed_sats,
        100_000
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refused_request_flood_keeps_only_one_row_and_does_not_extend_throttle() {
    let (hub, backend, peer) = setup(0).await;
    backend.connected.store(false, Ordering::SeqCst);
    for now in 10..110 {
        let id = Uuid::new_v4();
        let frame = hub
            .handle(peer, request(&hub, peer, id), Some(now))
            .await
            .unwrap();
        assert!(matches!(
            frame,
            Frame::StarterStatus {
                retry_after_unix: Some(610),
                ..
            }
        ));
        assert!(
            matches!(frame, Frame::StarterStatus { reason: Some(ref reason), .. }
            if reason == if now == 10 { "ln_peer_not_connected" } else { "rate_limited" })
        );
    }
    assert_eq!(hub.storage.starter_grants().await.unwrap().len(), 1);
    // A new refusal after the throttle replaces the old refusal, rather than
    // growing history; reconnecting after that throttle still permits admission.
    let id = Uuid::new_v4();
    hub.handle(peer, request(&hub, peer, id), Some(610))
        .await
        .unwrap();
    assert_eq!(hub.storage.starter_grants().await.unwrap().len(), 1);
    backend.connected.store(true, Ordering::SeqCst);
    let id = Uuid::new_v4();
    assert!(
        matches!(hub.handle(peer, request(&hub, peer, id), Some(1210)).await.unwrap(),
        Frame::StarterStatus { state, .. } if state == "received")
    );
    assert_eq!(hub.storage.starter_grants().await.unwrap().len(), 1);
}

#[tokio::test]
async fn newcomer_replays_timeout_without_duplicate_hub_open_and_waits_for_push() {
    use crate::onboarding::starter_newcomer::StarterNewcomer;
    use konsensus_api::handlers::starter_channel::{StarterConfig, StarterSettings};
    use konsensus_storage::starter_request::StarterRequest;
    let (hub, backend, peer) = setup(3).await;
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let client_backend = Arc::new(Backend {
        db: db.clone(),
        calls: AtomicUsize::new(0),
        channels: Mutex::new(vec![]),
        outcome: 0,
        connected: std::sync::atomic::AtomicBool::new(true),
        fail_channel_read: std::sync::atomic::AtomicBool::new(false),
    });
    let newcomer = StarterNewcomer {
        storage: db.clone(),
        lightning: client_backend.clone(),
        node_id: peer,
        settings: StarterSettings {
            config: StarterConfig {
                enabled: true,
                hub_node_id: hub.hub_id.to_hex(),
                allow_mainnet: false,
            },
            network: "regtest".into(),
            hub_ln_pubkey: "03".repeat(33),
            hub_ln_address: "127.0.0.1:9735".into(),
            hub_whitelisted: true,
            trust_no_reserve: true,
        },
    };
    let id = Uuid::new_v4();
    db.starter_request_create(&StarterRequest::new(
        id.to_string(),
        hub.hub_id.to_hex(),
        "03".repeat(33),
        "regtest".into(),
        100,
    ))
    .await
    .unwrap();
    let first = newcomer.poll(100, true).await.unwrap().unwrap();
    let _lost_reply = hub.handle(peer, first, Some(100)).await.unwrap();
    hub.tick(Some(100)).await.unwrap();
    assert!(newcomer.poll(114, true).await.unwrap().is_none());
    let replay = newcomer.poll(115, true).await.unwrap().unwrap();
    assert!(matches!(replay,Frame::StarterRequest{request_id,..} if request_id==id));
    let status = hub.handle(peer, replay, Some(115)).await.unwrap();
    hub.tick(Some(115)).await.unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    newcomer.handle(hub.hub_id, status, 115).await.unwrap();
    let mut channel = ChannelInfo {
        channel_id: "ab".repeat(32),
        user_channel_id: Some("1".into()),
        funding_txo: None,
        peer_pubkey: "03".repeat(33),
        capacity_msat: 100_000_000,
        local_balance_msat: 0,
        remote_balance_msat: 100_000_000,
        active: true,
        short_channel_id: None,
        is_outbound: Some(false),
        is_announced: Some(false),
        is_channel_ready: Some(true),
        local_reserve_msat: Some(0),
        initial_push_msat: None,
    };
    // Use the actual hub operation identifiers, never a channel for another grant.
    let grant = hub
        .storage
        .starter_query(StarterQuery::Request(id.to_string()))
        .await
        .unwrap()
        .remove(0);
    channel.channel_id = grant.channel_id.unwrap();
    channel.funding_txo = grant.funding_txid.map(|t| format!("{t}:0"));
    client_backend
        .channels
        .lock()
        .unwrap()
        .push(channel.clone());
    newcomer.poll(116, true).await.unwrap();
    assert_eq!(
        db.starter_request_get(&id.to_string())
            .await
            .unwrap()
            .unwrap()
            .state,
        "opening"
    );
    channel.initial_push_msat = Some(10_000_000);
    channel.is_channel_ready = Some(false);
    *client_backend.channels.lock().unwrap() = vec![channel.clone()];
    newcomer.poll(117, true).await.unwrap();
    assert_ne!(
        db.starter_request_get(&id.to_string())
            .await
            .unwrap()
            .unwrap()
            .state,
        "ready"
    );
    channel.is_channel_ready = Some(true); // Balance can already be spent: durable evidence remains.
    *client_backend.channels.lock().unwrap() = vec![channel];
    newcomer.poll(118, true).await.unwrap();
    let ready = db
        .starter_request_get(&id.to_string())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ready.state, "ready");
    assert!(ready.verified_at.is_some());
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}

async fn newcomer_fixture(
    hub: &StarterHub,
    peer: NodeId,
) -> (
    super::super::starter_newcomer::StarterNewcomer,
    Arc<SqliteStorage>,
    Arc<Backend>,
) {
    use konsensus_api::handlers::starter_channel::{StarterConfig, StarterSettings};
    let db = Arc::new(SqliteStorage::in_memory().await.unwrap());
    let backend = Arc::new(Backend {
        db: db.clone(),
        calls: AtomicUsize::new(0),
        channels: Mutex::new(vec![]),
        outcome: 0,
        connected: std::sync::atomic::AtomicBool::new(true),
        fail_channel_read: std::sync::atomic::AtomicBool::new(false),
    });
    let client = super::super::starter_newcomer::StarterNewcomer {
        storage: db.clone(),
        lightning: backend.clone(),
        node_id: peer,
        settings: StarterSettings {
            config: StarterConfig {
                enabled: true,
                hub_node_id: hub.hub_id.to_hex(),
                allow_mainnet: false,
            },
            network: "regtest".into(),
            hub_ln_pubkey: "03".repeat(33),
            hub_ln_address: "127.0.0.1:9735".into(),
            hub_whitelisted: true,
            trust_no_reserve: true,
        },
    };
    (client, db, backend)
}
#[tokio::test]
async fn newcomer_refusal_retries_once_after_backoff_and_late_status_cannot_regress_it() {
    use konsensus_storage::starter_request::StarterRequest;
    let (hub, backend, peer) = setup(3).await;
    let (client, db, _) = newcomer_fixture(&hub, peer).await;
    let id = Uuid::new_v4();
    db.starter_request_create(&StarterRequest::new(
        id.to_string(),
        hub.hub_id.to_hex(),
        "03".repeat(33),
        "regtest".into(),
        100,
    ))
    .await
    .unwrap();
    backend.connected.store(false, Ordering::SeqCst);
    let frame = client.poll(100, true).await.unwrap().unwrap();
    let refused = hub.handle(peer, frame, Some(100)).await.unwrap();
    client
        .handle(NodeId::from_bytes([99; 32]), refused.clone(), 100)
        .await
        .unwrap();
    assert_eq!(
        db.starter_request_current().await.unwrap().unwrap().state,
        "requested"
    );
    client
        .handle(hub.hub_id, refused.clone(), 100)
        .await
        .unwrap();
    assert_eq!(
        db.starter_request_current().await.unwrap().unwrap().state,
        "refused"
    );
    assert!(client.poll(699, true).await.unwrap().is_none());
    backend.connected.store(true, Ordering::SeqCst);
    let retry = client.poll(700, true).await.unwrap().unwrap();
    let Frame::StarterRequest {
        request_id: child, ..
    } = retry
    else {
        panic!("request")
    };
    assert_ne!(child, id);
    let accepted = hub.handle(peer, retry.clone(), Some(700)).await.unwrap();
    client.handle(hub.hub_id, accepted, 700).await.unwrap();
    client.handle(hub.hub_id, refused, 701).await.unwrap();
    assert_eq!(
        db.starter_request_current()
            .await
            .unwrap()
            .unwrap()
            .request_id,
        child.to_string()
    );
    hub.tick(Some(700)).await.unwrap();
    hub.handle(peer, retry, Some(715)).await.unwrap();
    hub.tick(Some(715)).await.unwrap();
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        hub.storage
            .get_channel_open_operation(&child.to_string())
            .await
            .unwrap()
            .unwrap()
            .operation_id,
        child.to_string()
    );
}
#[tokio::test]
async fn newcomer_delivery_is_bounded_and_reconnect_reuses_operation_after_24h() {
    use konsensus_storage::starter_request::StarterRequest;
    let (hub, _, peer) = setup(3).await;
    let (client, db, _) = newcomer_fixture(&hub, peer).await;
    let id = Uuid::new_v4();
    db.starter_request_create(&StarterRequest::new(
        id.to_string(),
        hub.hub_id.to_hex(),
        "03".repeat(33),
        "regtest".into(),
        100,
    ))
    .await
    .unwrap();
    for now in [100, 115, 145, 205, 325, 625, 925, 1225] {
        assert!(
            matches!(client.poll(now,true).await.unwrap(),Some(Frame::StarterRequest{request_id,..}) if request_id==id)
        );
    }
    assert!(client.poll(100_000, true).await.unwrap().is_none());
    assert!(client.poll(100_001, false).await.unwrap().is_none());
    let row = db.starter_request_current().await.unwrap().unwrap();
    assert_eq!(row.state, "requested");
    assert_eq!(row.detail.as_deref(), Some("hub_silent_24h"));
    db.starter_request_rearm(&row.request_id).await.unwrap();
    assert!(
        matches!(client.poll(100_002,true).await.unwrap(),Some(Frame::StarterRequest{request_id,..}) if request_id==id)
    );
    assert_eq!(
        db.starter_request_current()
            .await
            .unwrap()
            .unwrap()
            .original_request_id,
        None
    );
}
#[tokio::test]
async fn newcomer_adopts_an_original_that_was_previously_refused() {
    use konsensus_storage::starter_request::StarterRequest;
    let (hub, backend, peer) = setup(3).await;
    let (client, db, client_backend) = newcomer_fixture(&hub, peer).await;
    let id = Uuid::new_v4();
    db.starter_request_create(&StarterRequest::new(
        id.to_string(),
        hub.hub_id.to_hex(),
        "03".repeat(33),
        "regtest".into(),
        100,
    ))
    .await
    .unwrap();
    backend.connected.store(false, Ordering::SeqCst);
    let first = client.poll(100, true).await.unwrap().unwrap();
    let refused = hub.handle(peer, first.clone(), Some(100)).await.unwrap();
    client.handle(hub.hub_id, refused, 100).await.unwrap();
    let child = client.poll(700, true).await.unwrap().unwrap();
    // Hub prunes A's refusal when B is evaluated. B's refusal response is lost.
    let _lost = hub.handle(peer, child.clone(), Some(700)).await.unwrap();
    backend.connected.store(true, Ordering::SeqCst);
    // A delayed duplicate A can now be admitted, since PR-1 pruned its refusal.
    hub.handle(peer, first, Some(1300)).await.unwrap();
    hub.tick(Some(1300)).await.unwrap();
    let served = hub.handle(peer, child, Some(1301)).await.unwrap();
    client.handle(hub.hub_id, served, 1301).await.unwrap();
    let adopted = db.starter_request_current().await.unwrap().unwrap();
    assert_eq!(adopted.request_id, id.to_string());
    assert_eq!(adopted.state, "requested");
    let replay = client.poll(1302, true).await.unwrap().unwrap();
    assert!(matches!(replay,Frame::StarterRequest{request_id,..} if request_id==id));
    let status = hub.handle(peer, replay, Some(1302)).await.unwrap();
    client.handle(hub.hub_id, status, 1302).await.unwrap();
    client_backend.channels.lock().unwrap().push(ChannelInfo {
        channel_id: "ab".repeat(32),
        user_channel_id: Some("1".into()),
        funding_txo: Some(format!("{}:0", "cd".repeat(32))),
        peer_pubkey: "03".repeat(33),
        capacity_msat: 100_000_000,
        local_balance_msat: 10_000_000,
        remote_balance_msat: 90_000_000,
        active: true,
        short_channel_id: None,
        is_outbound: Some(false),
        is_announced: Some(false),
        is_channel_ready: Some(true),
        local_reserve_msat: Some(0),
        initial_push_msat: Some(10_000_000),
    });
    client.poll(1303, true).await.unwrap();
    assert_eq!(
        db.starter_request_current().await.unwrap().unwrap().state,
        "ready"
    );
    assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
}
