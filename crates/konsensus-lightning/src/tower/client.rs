//! Local W1 -> encrypted outbox pump. No sessions, sockets or payments.
use super::{
    outbox::{candidate_key, Outbox, MAX_PENDING_PER_CHANNEL},
    TowerConfig,
};
use konsensus_core::tower::TowerStatus;
use ldk_node::{io::sqlite_store::SqliteStore, tower_hook::TowerClient};
use std::{
    collections::HashMap,
    io,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
};

pub struct ClientCore {
    pub candidates: Arc<TowerClient>,
    pub outbox: Outbox,
    towers: Vec<String>,
    cursors: Mutex<HashMap<String, String>>,
    status: RwLock<TowerStatus>,
}

impl ClientCore {
    /// Empty configuration performs no filesystem work and never enables W1.
    pub fn open(config: &TowerConfig, directory: &Path) -> io::Result<Option<Arc<Self>>> {
        config.validate()?;
        if config.clients.is_empty() {
            return Ok(None);
        }
        std::fs::create_dir_all(directory)?;
        let store = SqliteStore::new(directory.into(), None, None).map_err(io::Error::from)?;
        let towers: Vec<String> = config
            .clients
            .values()
            .map(|c| {
                c.node_id
                    .parse::<bitcoin::secp256k1::PublicKey>()
                    .unwrap()
                    .to_string()
            })
            .collect();
        let outbox = Outbox::open(&directory.join("outbox.sqlite"))?;
        outbox.retain_towers(&towers)?;
        Ok(Some(Arc::new(Self {
            candidates: Arc::new(TowerClient::new_bounded(
                Arc::new(store),
                MAX_PENDING_PER_CHANNEL,
            )),
            outbox,
            towers,
            cursors: Mutex::new(HashMap::new()),
            status: RwLock::new(TowerStatus {
                enabled: true,
                ..Default::default()
            }),
        })))
    }

    pub fn status(&self) -> TowerStatus {
        self.status.read().unwrap().clone()
    }

    /// One bounded page/channel; crash recovery replays both enqueue and ack cleanup.
    pub fn reconcile(&self) -> io::Result<()> {
        let result = self.reconcile_inner();
        if let Err(error) = &result {
            let mut status = self.status.write().unwrap();
            status.available = false;
            status.error = Some(error.to_string());
        }
        result
    }

    fn reconcile_inner(&self) -> io::Result<()> {
        for channel in self.candidates.archived_channels()? {
            self.outbox.prune_closed_channel(&channel.to_string())?;
            self.candidates.prune_archived_channel(channel)?;
            self.cursors.lock().unwrap().remove(&channel.to_string());
        }
        let mut status = TowerStatus {
            enabled: true,
            available: true,
            ..Default::default()
        };
        for (channel, peer) in self.candidates.channels()? {
            let id = channel.to_string();
            let cursor = self.cursors.lock().unwrap().get(&id).cloned();
            let page = self
                .candidates
                .candidate_page(channel, cursor.as_deref(), 128)?;
            let mut at_capacity = false;
            for candidate in &page {
                let key = candidate_key(candidate)?;
                if let Err(error) = self
                    .outbox
                    .enqueue(candidate, &peer.to_string(), &self.towers)
                {
                    match error.kind() {
                        io::ErrorKind::WouldBlock => at_capacity = true,
                        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => {
                            status.available = false;
                            status.error = Some(format!("channel {id}: {error}"));
                        }
                        _ => return Err(error),
                    }
                    tracing::warn!(target: "konsensus_lightning::tower", channel = %id, %error, "tower channel enqueue failed; continuing reconciliation");
                    continue;
                }
                if self.outbox.fully_acked(&id, &key)? {
                    self.candidates.acknowledge_candidate(channel, &key)?;
                }
            }
            let mut cursors = self.cursors.lock().unwrap();
            if page.len() < 128 {
                cursors.remove(&id);
            } else {
                cursors.insert(id.clone(), candidate_key(page.last().unwrap())?);
            }
            drop(cursors);
            let diagnostics = self.candidates.diagnostics(channel)?;
            let mut view = self.outbox.channel_status(&id)?;
            let mut unimported = 0;
            for key in self.candidates.candidate_keys(channel)? {
                if !self.outbox.contains(&id, &key)? {
                    unimported += 1;
                }
            }
            view.total_states += unimported + diagnostics.deferred_signed;
            view.unguarded_states += unimported + diagnostics.deferred_signed;
            view.signed_candidates = diagnostics.signed_candidates;
            view.unsigned_pending = diagnostics.unsigned_pending;
            view.deferred_signed = diagnostics.deferred_signed;
            view.quarantined_pending = diagnostics.quarantined_pending;
            view.quarantined_candidates = diagnostics.quarantined_candidates;
            view.retired_records = diagnostics.retired;
            view.at_capacity = at_capacity
                || diagnostics.at_capacity
                || self.outbox.pending_count(&id)? >= MAX_PENDING_PER_CHANNEL;
            view.coverage_gap = diagnostics.quarantined_pending
                + diagnostics.quarantined_candidates
                + diagnostics.retired
                > 0;
            view.skipped_counterparty_towers = self
                .towers
                .iter()
                .filter(|t| **t == peer.to_string())
                .count();
            status.channels.push(view);
        }
        *self.status.write().unwrap() = status;
        Ok(())
    }

    pub fn spawn(self: &Arc<Self>, shutdown: Arc<AtomicBool>) {
        let core = self.clone();
        tokio::spawn(async move {
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let task = core.clone();
                let result = tokio::task::spawn_blocking(move || task.reconcile()).await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(target: "konsensus_lightning::tower", %error, "tower outbox reconciliation failed")
                    }
                    Err(error) => {
                        let mut status = core.status.write().unwrap();
                        status.available = false;
                        status.error = Some(error.to_string());
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ldk_node::lightning::util::{persist::KVStoreSync, ser::Writeable};

    fn fixture(directory: &Path) -> (TowerConfig, String, ldk_node::tower_hook::JusticeCandidate) {
        let peer = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let tower = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
        let config = TowerConfig {
            clients: [(
                "friend".into(),
                super::super::TowerEndpoint {
                    node_id: tower.into(),
                    endpoint: "guard.example:9736".into(),
                },
            )]
            .into(),
        };
        let candidate = super::super::outbox::tests::candidate(2);
        let store = SqliteStore::new(directory.into(), None, None).unwrap();
        store
            .write(
                "tower_peers",
                "",
                &candidate.channel_id.to_string(),
                peer.parse::<bitcoin::secp256k1::PublicKey>()
                    .unwrap()
                    .encode(),
            )
            .unwrap();
        store
            .write(
                "tower_candidates",
                &candidate.channel_id.to_string(),
                &candidate_key(&candidate).unwrap(),
                candidate.encode(),
            )
            .unwrap();
        (config, tower.into(), candidate)
    }

    #[test]
    fn tower_handoff_restart_ack_cleanup_and_durable_diagnostics() {
        let dir = tempfile::tempdir().unwrap();
        let (config, tower, candidate) = fixture(dir.path());
        let id = candidate.channel_id;
        let channel = id.to_string();
        let key = candidate_key(&candidate).unwrap();
        let core = ClientCore::open(&config, dir.path()).unwrap().unwrap();
        core.reconcile().unwrap();
        let first = core.status();
        assert_eq!(
            (
                first.channels[0].total_states,
                first.channels[0].unguarded_states
            ),
            (1, 1)
        );
        assert_eq!(
            core.candidates.candidate_keys(id).unwrap(),
            vec![key.clone()]
        );
        core.outbox.mark_sent(&channel, &key, &tower).unwrap();
        core.reconcile().unwrap();
        assert_eq!(core.status().channels[0].unguarded_states, 1);
        // Crash after durable ACK but before W1 removal.
        core.outbox.ack(&channel, &key, &tower).unwrap();
        drop(core);
        let core = ClientCore::open(&config, dir.path()).unwrap().unwrap();
        core.reconcile().unwrap();
        assert!(core.candidates.candidate_keys(id).unwrap().is_empty());
        assert_eq!(core.status().channels[0].guarded_states, 1);
        assert_eq!(core.status().channels[0].unguarded_states, 0);
        core.outbox.expire_tower(&tower).unwrap();
        core.reconcile().unwrap();
        assert_eq!(core.status().channels[0].guarded_states, 0);
        assert_eq!(core.status().channels[0].unguarded_states, 1);
        // Persisted quarantine and retirement counters survive process restart.
        let store = SqliteStore::new(dir.path().into(), None, None).unwrap();
        store
            .write("tower_quarantine_pending", &channel, "fixture", vec![0])
            .unwrap();
        store
            .write("tower_retired", &channel, "fixture", vec![0])
            .unwrap();
        drop(core);
        let core = ClientCore::open(&config, dir.path()).unwrap().unwrap();
        core.reconcile().unwrap();
        assert!(core.status().channels[0].coverage_gap);
        assert_eq!(core.status().channels[0].quarantined_pending, 1);
        assert_eq!(core.status().channels[0].retired_records, 1);
        store.write("tower_closed", "", &channel, vec![1]).unwrap();
        core.reconcile().unwrap();
        assert!(core.status().channels.is_empty());
        assert_eq!(
            core.outbox.channel_status(&channel).unwrap().total_states,
            0
        );
        assert!(core.candidates.archived_channels().unwrap().is_empty());
    }

    #[test]
    fn tower_handoff_counterparty_only_stays_unguarded_and_corruption_is_visible() {
        let dir = tempfile::tempdir().unwrap();
        let (mut config, _, candidate) = fixture(dir.path());
        config.clients.get_mut("friend").unwrap().node_id =
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into();
        let store = SqliteStore::new(dir.path().into(), None, None).unwrap();
        store
            .write(
                "tower_candidates",
                &candidate.channel_id.to_string(),
                "corrupt",
                vec![0],
            )
            .unwrap();
        let core = ClientCore::open(&config, dir.path()).unwrap().unwrap();
        core.reconcile().unwrap();
        let channel = &core.status().channels[0];
        assert_eq!(channel.skipped_counterparty_towers, 1);
        assert_eq!(channel.unguarded_states, 1);
        assert_eq!(channel.guarded_states, 0);
        assert_eq!(channel.quarantined_candidates, 1);
        assert!(channel.coverage_gap);
    }

    #[test]
    fn tower_handoff_continues_past_channel_at_outbox_capacity() {
        handoff_continues_past_channel_enqueue_error(true);
    }

    #[test]
    fn tower_handoff_continues_past_channel_with_oversized_blob() {
        handoff_continues_past_channel_enqueue_error(false);
    }

    fn handoff_continues_past_channel_enqueue_error(at_capacity: bool) {
        let dir = tempfile::tempdir().unwrap();
        let (config, tower, candidate) = fixture(dir.path());
        let store = SqliteStore::new(dir.path().into(), None, None).unwrap();
        let mut second = candidate.clone();
        second.channel_id = ldk_node::lightning::ln::types::ChannelId([3; 32]);
        store
            .write(
                "tower_peers",
                "",
                &second.channel_id.to_string(),
                store
                    .read("tower_peers", "", &candidate.channel_id.to_string())
                    .unwrap(),
            )
            .unwrap();
        let key = candidate_key(&second).unwrap();
        store
            .write(
                "tower_candidates",
                &second.channel_id.to_string(),
                &key,
                second.encode(),
            )
            .unwrap();
        let core = ClientCore::open(&config, dir.path()).unwrap().unwrap();
        // Use the store's enumeration order so the failing channel is visited first.
        let channels = core.candidates.channels().unwrap();
        assert_eq!(channels.len(), 2);
        let capped = channels[0].0.to_string();
        let later = channels[1].0.to_string();
        let total_states = if at_capacity {
            let db = rusqlite::Connection::open(dir.path().join("outbox.sqlite")).unwrap();
            db.execute(
                "WITH RECURSIVE fixtures(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM fixtures WHERE n<?2)
             INSERT INTO states(channel, txid, blob, pending)
             SELECT ?1, 'fixture-' || n, NULL, 1 FROM fixtures",
                rusqlite::params![capped, MAX_PENDING_PER_CHANNEL],
            )
            .unwrap();
            assert_eq!(
                core.outbox.pending_count(&capped).unwrap(),
                MAX_PENDING_PER_CHANNEL
            );
            MAX_PENDING_PER_CHANNEL + 1
        } else {
            let mut oversized = candidate.clone();
            oversized.channel_id = channels[0].0;
            oversized.ladder[0].input[0]
                .witness
                .push(vec![0; super::super::blob::MAX_BLOB_BYTES]);
            store
                .write("tower_candidates", &capped, &key, oversized.encode())
                .unwrap();
            1
        };

        core.reconcile().unwrap();
        let status = core.status();
        assert_eq!(status.available, at_capacity);
        if at_capacity {
            assert!(status.error.is_none());
        } else {
            assert!(status.error.as_ref().unwrap().contains(&capped));
        }
        assert_eq!(status.channels.len(), 2);
        let full = status
            .channels
            .iter()
            .find(|c| c.channel_id == capped)
            .unwrap();
        assert_eq!(full.at_capacity, at_capacity);
        assert_eq!(full.total_states, total_states);
        assert_eq!(full.unguarded_states, total_states);
        assert_eq!(
            core.candidates.candidate_keys(channels[0].0).unwrap(),
            vec![key.clone()]
        );
        assert!(!core.outbox.contains(&capped, &key).unwrap());
        assert!(core.outbox.contains(&later, &key).unwrap());
        let healthy = status
            .channels
            .iter()
            .find(|c| c.channel_id == later)
            .unwrap();
        assert!(!healthy.at_capacity);
        assert_eq!(healthy.total_states, 1);

        core.outbox.mark_sent(&later, &key, &tower).unwrap();
        core.outbox.ack(&later, &key, &tower).unwrap();
        core.reconcile().unwrap();
        assert!(core
            .candidates
            .candidate_keys(channels[1].0)
            .unwrap()
            .is_empty());
        let status = core.status();
        let healthy = status
            .channels
            .iter()
            .find(|c| c.channel_id == later)
            .unwrap();
        assert_eq!(healthy.guarded_states, 1);
        assert_eq!(healthy.unguarded_states, 0);
    }

    #[test]
    fn tower_handoff_storage_failure_remains_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let (config, _, _) = fixture(dir.path());
        let core = ClientCore::open(&config, dir.path()).unwrap().unwrap();
        let db = rusqlite::Connection::open(dir.path().join("outbox.sqlite")).unwrap();
        db.execute("DROP TABLE deliveries", []).unwrap();

        assert!(core.reconcile().is_err());
        let status = core.status();
        assert!(!status.available);
        assert!(status.error.is_some());
    }

    #[test]
    fn tower_empty_config_does_not_create_storage_or_enable_hook() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        assert!(ClientCore::open(&TowerConfig::default(), &missing)
            .unwrap()
            .is_none());
        assert!(!missing.exists());
    }
}
