//! Offline port of LDK do_test_forming_justice_tx_from_monitor_updates.
use super::*;
use lightning::ln::functional_test_utils::*;
use lightning::sign::SignerProvider;
use lightning::util::test_utils::TestPersister;
use lightning_persister::fs_store::FilesystemStore;

fn hook(path: &std::path::Path, script: ScriptBuf) -> TowerPersister<TestPersister> {
    TowerPersister::new(
        TestPersister::new(),
        Some(Arc::new(TowerClient::new(Arc::new(FilesystemStore::new(
            path.into(),
        ))))),
        Arc::new(|| 1000),
        Arc::new(move || Ok(script.clone())),
    )
}

// Swap the entire decorator/client at a crash boundary while the in-memory peer harness lives on.
struct Restartable(Mutex<TowerPersister<TestPersister>>);
impl<S: EcdsaChannelSigner> Persist<S> for Restartable {
    fn persist_new_channel(
        &self,
        n: MonitorName,
        m: &ChannelMonitor<S>,
    ) -> ChannelMonitorUpdateStatus {
        self.0.lock().unwrap().persist_new_channel(n, m)
    }
    fn update_persisted_channel(
        &self,
        n: MonitorName,
        u: Option<&ChannelMonitorUpdate>,
        m: &ChannelMonitor<S>,
    ) -> ChannelMonitorUpdateStatus {
        self.0.lock().unwrap().update_persisted_channel(n, u, m)
    }
    fn archive_persisted_channel(&self, n: MonitorName) {
        <TowerPersister<TestPersister> as Persist<S>>::archive_persisted_channel(
            &self.0.lock().unwrap(),
            n,
        );
    }
}
impl Restartable {
    fn candidates(&self, id: ChannelId) -> Vec<JusticeCandidate> {
        self.0
            .lock()
            .unwrap()
            .client
            .as_ref()
            .unwrap()
            .pending_candidates(id)
            .unwrap()
    }
}

fn forming_justice(initial: bool, restart: bool, anchors: bool) {
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let cfg = create_chanmon_cfgs(2);
    let scripts: Vec<_> = cfg
        .iter()
        .map(|c| c.keys_manager.get_destination_script([0; 32]).unwrap())
        .collect();
    let persisters = [
        Restartable(Mutex::new(hook(dirs[0].path(), scripts[0].clone()))),
        Restartable(Mutex::new(hook(dirs[1].path(), scripts[1].clone()))),
    ];
    let configs = create_node_cfgs_with_persisters(2, &cfg, persisters.iter().collect());
    let mut config = test_default_channel_config();
    config.manually_accept_inbound_channels = anchors;
    config
        .channel_handshake_config
        .negotiate_anchors_zero_fee_htlc_tx = anchors;
    let managers = create_node_chanmgrs(2, &configs, &[Some(config.clone()), Some(config)]);
    let nodes = create_network(2, &configs, &managers);
    let (_, _, channel_id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
    let initial_other =
        lightning::get_local_commitment_txn!(nodes[1], channel_id)[0].compute_txid();
    if !initial {
        send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
    }
    let revoked = lightning::get_local_commitment_txn!(nodes[0], channel_id).remove(0);
    assert!(persisters[1]
        .candidates(channel_id)
        .iter()
        .all(|c| c.ladder[0].input[0].previous_output.txid != revoked.compute_txid()));
    if restart {
        let restored = hook(dirs[1].path(), ScriptBuf::new());
        let bytes = restored
            .client
            .as_ref()
            .unwrap()
            .store
            .read("tower", "pending", &channel_id.to_string())
            .unwrap();
        let state: PendingChannel = decode(&bytes).unwrap();
        assert!(
            state
                .pending
                .iter()
                .any(|c| c.candidate.ladder[0].input[0].previous_output.txid
                    == revoked.compute_txid())
        );
        *persisters[1].0.lock().unwrap() = restored;
        // Match builder startup: persist the reloaded monitor before later revocations arrive.
        let monitor = nodes[1]
            .chain_monitor
            .chain_monitor
            .get_monitor(channel_id)
            .unwrap();
        assert_eq!(
            persisters[1].persist_new_channel(monitor.persistence_key(), &monitor),
            ChannelMonitorUpdateStatus::Completed
        );
    }
    send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
    let candidates = persisters[1].candidates(channel_id);
    let candidate = candidates
        .iter()
        .find(|c| c.ladder[0].input[0].previous_output.txid == revoked.compute_txid())
        .unwrap();
    assert_eq!(candidate.channel_id, channel_id);
    assert_eq!(candidate.ladder.len(), 3);
    let mut prev_fee = 0;
    for tx in &candidate.ladder {
        lightning::check_spends!(tx, revoked);
        assert_eq!(tx.output[0].script_pubkey, scripts[1]);
        let fee = candidate.value - tx.output[0].value.to_sat();
        assert!(fee > prev_fee && fee <= candidate.value / 2);
        prev_fee = fee;
    }
    // The unfunded peer's initial to_local was dust: no justice candidate for it.
    assert!(persisters[0]
        .candidates(channel_id)
        .iter()
        .all(|c| c.ladder[0].input[0].previous_output.txid != initial_other));
    // Re-open all queue state from disk, independent of the original client.
    let restored = hook(dirs[1].path(), ScriptBuf::new());
    assert_eq!(
        restored
            .client
            .as_ref()
            .unwrap()
            .pending_candidates(channel_id)
            .unwrap(),
        candidates
    );
    // Complete the upstream functional-test port using only simulated blocks.
    if !anchors {
        let justice = &candidate.ladder[0];
        mine_transactions(&nodes[1], &[&revoked, justice]);
        mine_transactions(&nodes[0], &[&revoked, justice]);
        get_announce_close_broadcast_events(&nodes, 1, 0);
        for (index, peer) in [(1, 0), (0, 1)] {
            check_added_monitors(&nodes[index], 1);
            check_closed_event(
                &nodes[index],
                1,
                lightning::events::ClosureReason::CommitmentTxConfirmed,
                false,
                &[nodes[peer].node.get_our_node_id()],
                100_000,
            );
        }
        let monitor = nodes[1]
            .chain_monitor
            .chain_monitor
            .get_monitor(channel_id)
            .unwrap();
        let total: u64 = monitor
            .get_claimable_balances()
            .iter()
            .map(|balance| match balance {
                lightning::chain::channelmonitor::Balance::ClaimableAwaitingConfirmations {
                    amount_satoshis,
                    ..
                } => *amount_satoshis,
                _ => panic!("unexpected claim balance"),
            })
            .sum();
        let original_balance = if initial {
            0
        } else {
            revoked.output[0].value.to_sat()
        };
        assert_eq!(total, original_balance + justice.output[0].value.to_sat());
    }
}

#[test]
fn initial_commitment_justice_and_below_dust() {
    forming_justice(true, false, false);
}
#[test]
fn later_commitment_justice_and_below_dust() {
    forming_justice(false, false, false);
}

#[test]
fn restart_mid_queue_keeps_initial_pending() {
    forming_justice(true, true, false);
}
#[test]
fn restart_mid_queue_keeps_later_pending_with_anchors() {
    forming_justice(false, true, true);
}

#[test]
fn inbound_splice_does_not_block_later_justice() {
    use lightning::chain::channelmonitor::ANTI_REORG_DELAY;
    use lightning::ln::funding::SpliceContribution;
    use lightning::ln::splicing_tests::{lock_splice_after_blocks, splice_channel};

    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let cfg = create_chanmon_cfgs(2);
    let script = cfg[1].keys_manager.get_destination_script([0; 32]).unwrap();
    let persisters = [
        Restartable(Mutex::new(hook(dirs[0].path(), script.clone()))),
        Restartable(Mutex::new(hook(dirs[1].path(), script))),
    ];
    let configs = create_node_cfgs_with_persisters(2, &cfg, persisters.iter().collect());
    let managers = create_node_chanmgrs(2, &configs, &[None, None]);
    let nodes = create_network(2, &configs, &managers);
    let (_, _, id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
    let before = lightning::get_local_commitment_txn!(nodes[0], id).remove(0);
    let splice = splice_channel(
        &nodes[0],
        &nodes[1],
        id,
        SpliceContribution::SpliceOut {
            outputs: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: cfg[0].keys_manager.get_destination_script([0; 32]).unwrap(),
            }],
        },
    );
    mine_transaction(&nodes[0], &splice);
    mine_transaction(&nodes[1], &splice);
    lock_splice_after_blocks(&nodes[0], &nodes[1], ANTI_REORG_DELAY - 1);
    // The acceptor now cannot sign the old funding scope, even after its secret arrives.
    let client = persisters[1]
        .0
        .lock()
        .unwrap()
        .client
        .as_ref()
        .unwrap()
        .clone();
    let state: PendingChannel = decode(
        &client
            .store
            .read("tower", "pending", &id.to_string())
            .unwrap(),
    )
    .unwrap();
    assert!(state
        .pending
        .iter()
        .any(|p| candidate_key(&p.candidate) == before.compute_txid().to_string()));
    let after = lightning::get_local_commitment_txn!(nodes[0], id).remove(0);
    assert_ne!(
        before.input[0].previous_output,
        after.input[0].previous_output
    );
    send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
    let candidates = client.pending_candidates(id).unwrap();
    let candidate = candidates
        .iter()
        .find(|c| candidate_key(c) == after.compute_txid().to_string())
        .expect("pre-splice head must not block post-splice justice");
    for tx in &candidate.ladder {
        lightning::check_spends!(tx, after);
    }
    // A fresh client must also skip the persisted head on startup and sign subsequent states.
    let restored = hook(dirs[1].path(), ScriptBuf::new());
    {
        let monitor = nodes[1]
            .chain_monitor
            .chain_monitor
            .get_monitor(id)
            .unwrap();
        assert_eq!(
            restored.persist_new_channel(monitor.persistence_key(), &monitor),
            ChannelMonitorUpdateStatus::Completed
        );
    }
    *persisters[1].0.lock().unwrap() = restored;
    let later = lightning::get_local_commitment_txn!(nodes[0], id).remove(0);
    send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
    let candidates = persisters[1].candidates(id);
    let candidate = candidates
        .iter()
        .find(|c| candidate_key(c) == later.compute_txid().to_string())
        .unwrap();
    for tx in &candidate.ladder {
        lightning::check_spends!(tx, later);
    }
}

type PersistedCall = (String, Vec<u8>, Option<Vec<u8>>);

#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<PersistedCall>>,
    status: Mutex<Option<ChannelMonitorUpdateStatus>>,
}
impl<S: EcdsaChannelSigner> Persist<S> for Recorder {
    fn persist_new_channel(
        &self,
        name: MonitorName,
        m: &ChannelMonitor<S>,
    ) -> ChannelMonitorUpdateStatus {
        self.calls
            .lock()
            .unwrap()
            .push((name.to_string(), m.encode(), None));
        self.status
            .lock()
            .unwrap()
            .take()
            .unwrap_or(ChannelMonitorUpdateStatus::Completed)
    }
    fn update_persisted_channel(
        &self,
        name: MonitorName,
        u: Option<&ChannelMonitorUpdate>,
        m: &ChannelMonitor<S>,
    ) -> ChannelMonitorUpdateStatus {
        self.calls
            .lock()
            .unwrap()
            .push((name.to_string(), m.encode(), u.map(Writeable::encode)));
        self.status
            .lock()
            .unwrap()
            .take()
            .unwrap_or(ChannelMonitorUpdateStatus::Completed)
    }
    fn archive_persisted_channel(&self, name: MonitorName) {
        self.calls
            .lock()
            .unwrap()
            .push((name.to_string(), Vec::new(), None));
    }
    fn get_and_clear_completed_updates(&self) -> Vec<(ChannelId, u64)> {
        vec![(ChannelId([42; 32]), 7)]
    }
}

struct FailStore {
    store: FilesystemStore,
    writes_until_failure: std::sync::atomic::AtomicUsize,
}
impl KVStoreSync for FailStore {
    fn read(&self, p: &str, s: &str, k: &str) -> Result<Vec<u8>, lightning::io::Error> {
        KVStoreSync::read(&self.store, p, s, k)
    }
    fn write(&self, p: &str, s: &str, k: &str, bytes: Vec<u8>) -> Result<(), lightning::io::Error> {
        use std::sync::atomic::Ordering;
        if self.writes_until_failure.fetch_sub(1, Ordering::SeqCst) == 1 {
            return Err(io::Error::other("injected disk failure").into());
        }
        KVStoreSync::write(&self.store, p, s, k, bytes)
    }
    fn remove(&self, p: &str, s: &str, k: &str, lazy: bool) -> Result<(), lightning::io::Error> {
        KVStoreSync::remove(&self.store, p, s, k, lazy)
    }
    fn list(&self, p: &str, s: &str) -> Result<Vec<String>, lightning::io::Error> {
        KVStoreSync::list(&self.store, p, s)
    }
}

#[test]
fn storage_failure_does_not_advance_monitor_and_restart_retries() {
    let cfg = create_chanmon_cfgs(2);
    let configs = create_node_cfgs(2, &cfg);
    let managers = create_node_chanmgrs(2, &configs, &[None, None]);
    let nodes = create_network(2, &configs, &managers);
    let (_, _, id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
    let script = cfg[1].keys_manager.get_destination_script([0; 32]).unwrap();
    let dirs: Vec<_> = (0..3).map(|_| tempfile::tempdir().unwrap()).collect();
    let mut hooks = Vec::new();
    for dir in &dirs {
        let store = Arc::new(FailStore {
            store: FilesystemStore::new(dir.path().into()),
            writes_until_failure: usize::MAX.into(),
        });
        let destination = script.clone();
        let hook = TowerPersister::new(
            Recorder::default(),
            Some(Arc::new(TowerClient::new(store.clone()))),
            Arc::new(|| 1000),
            Arc::new(move || Ok(destination.clone())),
        );
        let monitor = nodes[1]
            .chain_monitor
            .chain_monitor
            .get_monitor(id)
            .unwrap();
        assert_eq!(
            hook.persist_new_channel(monitor.persistence_key(), &monitor),
            ChannelMonitorUpdateStatus::Completed
        );
        hooks.push((hook, store));
    }
    let revoked = lightning::get_local_commitment_txn!(nodes[0], id).remove(0);
    send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
    for (index, (hook, store)) in hooks.into_iter().enumerate() {
        store
            .writes_until_failure
            .store(index + 1, std::sync::atomic::Ordering::SeqCst);
        let monitor = nodes[1]
            .chain_monitor
            .chain_monitor
            .get_monitor(id)
            .unwrap();
        assert_eq!(
            hook.update_persisted_channel(monitor.persistence_key(), None, &monitor),
            ChannelMonitorUpdateStatus::UnrecoverableError
        );
        assert_eq!(
            hook.inner.calls.lock().unwrap().len(),
            1,
            "failed staging must not advance durable monitor"
        );
        drop(hook);
        // A brand-new client and decorator read only disk. Startup can finish signing/dequeue.
        let restored = super::tests::hook(dirs[index].path(), ScriptBuf::new());
        assert_eq!(
            restored.persist_new_channel(monitor.persistence_key(), &monitor),
            ChannelMonitorUpdateStatus::Completed
        );
        let candidates = restored
            .client
            .as_ref()
            .unwrap()
            .pending_candidates(id)
            .unwrap();
        assert_eq!(candidates.len(), 1);
        for tx in &candidates[0].ladder {
            lightning::check_spends!(tx, revoked);
        }
        assert_eq!(
            restored.update_persisted_channel(monitor.persistence_key(), None, &monitor),
            ChannelMonitorUpdateStatus::Completed
        );
        assert_eq!(
            restored
                .client
                .as_ref()
                .unwrap()
                .pending_candidates(id)
                .unwrap(),
            candidates
        );
    }
}

#[test]
fn disabled_delegates_bytes_status_completion_and_archive() {
    let cfg = create_chanmon_cfgs(2);
    let configs = create_node_cfgs(2, &cfg);
    let managers = create_node_chanmgrs(2, &configs, &[None, None]);
    let nodes = create_network(2, &configs, &managers);
    let (_, _, id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
    send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
    let updates = nodes[1].chain_monitor.monitor_updates.lock().unwrap();
    let update = updates.get(&id).unwrap().last().unwrap();
    let monitor = nodes[1]
        .chain_monitor
        .chain_monitor
        .get_monitor(id)
        .unwrap();
    let hook = TowerPersister::new(
        Recorder::default(),
        None,
        Arc::new(|| 1000),
        Arc::new(|| panic!("disabled allocated a wallet address")),
    );
    let direct = Recorder::default();
    for status in [
        ChannelMonitorUpdateStatus::Completed,
        ChannelMonitorUpdateStatus::InProgress,
        ChannelMonitorUpdateStatus::UnrecoverableError,
    ] {
        *hook.inner.status.lock().unwrap() = Some(status);
        *direct.status.lock().unwrap() = Some(status);
        assert_eq!(
            hook.persist_new_channel(monitor.persistence_key(), &monitor),
            direct.persist_new_channel(monitor.persistence_key(), &monitor)
        );
        *hook.inner.status.lock().unwrap() = Some(status);
        *direct.status.lock().unwrap() = Some(status);
        assert_eq!(
            hook.update_persisted_channel(monitor.persistence_key(), None, &monitor),
            direct.update_persisted_channel(monitor.persistence_key(), None, &monitor)
        );
    }
    assert_eq!(
        hook.update_persisted_channel(monitor.persistence_key(), Some(update), &monitor),
        direct.update_persisted_channel(monitor.persistence_key(), Some(update), &monitor)
    );
    type Signer = lightning::util::test_channel_signer::TestChannelSigner;
    assert_eq!(
        <TowerPersister<Recorder> as Persist<Signer>>::get_and_clear_completed_updates(&hook),
        <Recorder as Persist<Signer>>::get_and_clear_completed_updates(&direct)
    );
    <TowerPersister<Recorder> as Persist<Signer>>::archive_persisted_channel(
        &hook,
        monitor.persistence_key(),
    );
    <Recorder as Persist<Signer>>::archive_persisted_channel(&direct, monitor.persistence_key());
    assert_eq!(
        *hook.inner.calls.lock().unwrap(),
        *direct.calls.lock().unwrap()
    );
}

#[test]
fn fee_ladder_caps_floor_dust_and_overflow() {
    let cfg = create_chanmon_cfgs(2);
    let configs = create_node_cfgs(2, &cfg);
    let managers = create_node_chanmgrs(2, &configs, &[None, None]);
    let nodes = create_network(2, &configs, &managers);
    let (_, _, id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
    let monitor = nodes[1]
        .chain_monitor
        .chain_monitor
        .get_monitor(id)
        .unwrap();
    let commitment = monitor.initial_counterparty_commitment_tx().unwrap();
    let script = cfg[1].keys_manager.get_destination_script([0; 32]).unwrap();
    assert_eq!(
        form_candidate(id, &commitment, &script, 0),
        form_candidate(id, &commitment, &script, 253)
    );
    assert_eq!(
        form_candidate(id, &commitment, &script, 100_000)
            .unwrap()
            .ladder
            .len(),
        1
    );
    assert!(form_candidate(id, &commitment, &script, 1_000_000).is_none());
    assert!(
        form_candidate(id, &commitment, &script, 1 << 30).is_none(),
        "multipliers must not wrap to zero fees"
    );
    let dust_monitor = nodes[0]
        .chain_monitor
        .chain_monitor
        .get_monitor(id)
        .unwrap();
    assert!(form_candidate(
        id,
        &dust_monitor.initial_counterparty_commitment_tx().unwrap(),
        &script,
        253
    )
    .is_none());
}

#[test]
fn crash_with_tower_ahead_of_durable_monitor_does_not_block_new_states() {
    use lightning::ln::channelmanager::{PaymentId, RecipientOnionFields};
    use lightning::ln::msgs::BaseMessageHandler;
    use lightning::util::test_utils::TestChainMonitor;
    let dirs = [tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap()];
    let cfg = create_chanmon_cfgs(2);
    let script = cfg[1].keys_manager.get_destination_script([0; 32]).unwrap();
    let persisters = [
        hook(dirs[0].path(), script.clone()),
        hook(dirs[1].path(), script.clone()),
    ];
    let (restored, chain_monitor);
    let configs = create_node_cfgs_with_persisters(2, &cfg, persisters.iter().collect());
    let manager;
    let managers = create_node_chanmgrs(2, &configs, &[None, None]);
    let mut nodes = create_network(2, &configs, &managers);
    let (_, _, id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
    send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
    let manager_bytes = nodes[1].node.encode();
    let monitor_bytes = nodes[1]
        .chain_monitor
        .chain_monitor
        .get_monitor(id)
        .unwrap()
        .encode();
    let before: PendingChannel = decode(
        &persisters[1]
            .client
            .as_ref()
            .unwrap()
            .store
            .read("tower", "pending", &id.to_string())
            .unwrap(),
    )
    .unwrap();
    // TestPersister does not write monitors. Keep only the old durable snapshot and discard
    // outbound messages, simulating the crash after staging and before monitor fsync. No message
    // reaches the peer. Restore the LAST durable manager/monitor, not these advanced objects.
    let (route, hash, _, secret) =
        lightning::get_route_and_payment_hash!(nodes[1], nodes[0], 2_000_000);
    nodes[1]
        .node
        .send_payment_with_route(
            route,
            hash,
            RecipientOnionFields::secret_only(secret),
            PaymentId(hash.0),
        )
        .unwrap();
    check_added_monitors(&nodes[1], 1);
    assert!(!nodes[1].node.get_and_clear_pending_msg_events().is_empty()); // discard, never delivered
    let ahead: PendingChannel = decode(
        &persisters[1]
            .client
            .as_ref()
            .unwrap()
            .store
            .read("tower", "pending", &id.to_string())
            .unwrap(),
    )
    .unwrap();
    assert!(ahead.pending.len() > before.pending.len());

    restored = hook(dirs[1].path(), ScriptBuf::new());
    chain_monitor = TestChainMonitor::new(
        Some(nodes[1].chain_source),
        nodes[1].tx_broadcaster,
        nodes[1].logger,
        nodes[1].fee_estimator,
        &restored,
        nodes[1].keys_manager,
    );
    nodes[1].chain_monitor = &chain_monitor;
    manager = _reload_node(
        &nodes[1],
        test_default_channel_config(),
        &manager_bytes,
        &[&monitor_bytes],
    );
    nodes[1].node = &manager;
    nodes[1].onion_messenger.set_offers_handler(&manager);
    nodes[1]
        .onion_messenger
        .set_async_payments_handler(&manager);
    {
        let monitor = nodes[1]
            .chain_monitor
            .chain_monitor
            .get_monitor(id)
            .unwrap();
        assert_eq!(
            restored.persist_new_channel(monitor.persistence_key(), &monitor),
            ChannelMonitorUpdateStatus::Completed
        );
    }
    let recovered: PendingChannel = decode(
        &restored
            .client
            .as_ref()
            .unwrap()
            .store
            .read("tower", "pending", &id.to_string())
            .unwrap(),
    )
    .unwrap();
    assert_eq!(
        recovered.pending.len(),
        before.pending.len(),
        "unacknowledged future queue entries must roll back with the monitor"
    );
    nodes[1].node.get_and_clear_pending_events(); // finish startup completion actions
    nodes[0]
        .node
        .peer_disconnected(nodes[1].node.get_our_node_id());
    reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
    send_payment(&nodes[1], &[&nodes[0]], 1_000_000);
    let revoked = lightning::get_local_commitment_txn!(nodes[0], id).remove(0);
    send_payment(&nodes[1], &[&nodes[0]], 1_000_000);
    let candidates = restored
        .client
        .as_ref()
        .unwrap()
        .pending_candidates(id)
        .unwrap();
    let candidate = candidates
        .iter()
        .find(|c| c.ladder[0].input[0].previous_output.txid == revoked.compute_txid())
        .unwrap();
    for tx in &candidate.ladder {
        lightning::check_spends!(tx, revoked);
    }
}

#[test]
fn production_tower_fee_uses_unadjusted_one_block_estimate() {
    use crate::fee_estimator::{apply_post_estimation_adjustments, OnchainFeeEstimator};
    let estimator = OnchainFeeEstimator::new(60);
    let target = lightning::chain::chaininterface::ConfirmationTarget::MaximumFeeEstimate.into();
    for raw in [253, 254, 1000, 8000, 1 << 30, u32::MAX] {
        let padded = apply_post_estimation_adjustments(
            target,
            bitcoin::FeeRate::from_sat_per_kwu(raw as u64),
        );
        estimator.set_test_fee_rate_cache([(target, padded)].into_iter().collect());
        assert_eq!(estimator.tower_justice_rate(), raw);
    }
}

#[test]
fn malformed_candidate_records_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = create_chanmon_cfgs(2);
    let configs = create_node_cfgs(2, &cfg);
    let managers = create_node_chanmgrs(2, &configs, &[None, None]);
    let nodes = create_network(2, &configs, &managers);
    let (_, _, id, _) = create_announced_chan_between_nodes(&nodes, 0, 1);
    let script = cfg[1].keys_manager.get_destination_script([0; 32]).unwrap();
    let hook = hook(dir.path(), script);
    {
        let monitor = nodes[1]
            .chain_monitor
            .chain_monitor
            .get_monitor(id)
            .unwrap();
        assert_eq!(
            hook.persist_new_channel(monitor.persistence_key(), &monitor),
            ChannelMonitorUpdateStatus::Completed
        );
    }
    send_payment(&nodes[0], &[&nodes[1]], 5_000_000);
    let monitor = nodes[1]
        .chain_monitor
        .chain_monitor
        .get_monitor(id)
        .unwrap();
    assert_eq!(
        hook.update_persisted_channel(monitor.persistence_key(), None, &monitor),
        ChannelMonitorUpdateStatus::Completed
    );
    let client = hook.client.as_ref().unwrap();
    let original = client.pending_candidates(id).unwrap().remove(0);
    let key = candidate_key(&original);
    for mutation in 0..4 {
        let mut bad = original.clone();
        match mutation {
            0 => bad.ladder.clear(),
            1 => bad.channel_id = ChannelId([42; 32]),
            2 => bad.ladder[0].input.clear(),
            3 => bad.ladder[0].input[0].witness.clear(),
            _ => unreachable!(),
        }
        client
            .store
            .write("tower_candidates", &id.to_string(), &key, bad.encode())
            .unwrap();
        assert!(
            client.pending_candidates(id).is_err(),
            "malformed signed record {mutation} accepted"
        );
    }
    client
        .store
        .write("tower_candidates", &id.to_string(), &key, original.encode())
        .unwrap();
    let wrong_key = "00".repeat(32);
    client
        .store
        .write(
            "tower_candidates",
            &id.to_string(),
            &wrong_key,
            original.encode(),
        )
        .unwrap();
    assert!(
        client.pending_candidates(id).is_err(),
        "record txid must match key"
    );
    client
        .store
        .remove("tower_candidates", &id.to_string(), &wrong_key, false)
        .unwrap();
    let mut state: PendingChannel = decode(
        &client
            .store
            .read("tower", "pending", &id.to_string())
            .unwrap(),
    )
    .unwrap();
    let mut bad = original;
    bad.ladder.clear();
    state.pending.push(PendingCandidate {
        candidate: bad,
        funding_outpoint: None,
        observed_update_id: monitor.get_latest_update_id(),
    });
    client
        .store
        .write("tower", "pending", &id.to_string(), state.encode())
        .unwrap();
    assert_eq!(
        hook.persist_new_channel(monitor.persistence_key(), &monitor),
        ChannelMonitorUpdateStatus::UnrecoverableError
    );
}
