//! W2 handoff. One index rebuild per channel/client lifetime; no list per write.
use super::*;
use bitcoin::hex::FromHex;
use std::collections::{BTreeSet, HashMap};

pub(super) type CandidateIndex = Mutex<HashMap<ChannelId, BTreeSet<String>>>;

/// Persisted W1 diagnostics. Counts are records, not a claim of complete coverage.
#[derive(Default, Debug)]
pub struct TowerDiagnostics {
    /// Signed states still awaiting durable tower acknowledgement.
    pub signed_candidates: usize,
    /// Unsigned states, including overflow retained for retry.
    pub unsigned_pending: usize,
    /// Revoked states whose signing was deferred because the hard cap was full.
    pub deferred_signed: usize,
    /// Quarantined unsigned journals; each can represent multiple missing states.
    pub quarantined_pending: usize,
    /// Quarantined signed records.
    pub quarantined_candidates: usize,
    /// Archived unsigned splice records.
    pub retired: usize,
    /// The signed staging store is at its hard bound.
    pub at_capacity: bool,
}

impl TowerClient {
    /// W2 uses a hard cap. At capacity unsigned data is retained for retry, never
    /// discarded and never converted into an LDK UnrecoverableError solely for quota.
    pub fn new_bounded(store: Arc<dyn KVStoreSync + Send + Sync>, limit: usize) -> Self {
        assert!((1..=10_000).contains(&limit));
        Self {
            store,
            gate: Mutex::new(()),
            limit: Some(limit),
            index: Mutex::new(HashMap::new()),
        }
    }

    fn ensure_index(&self, id: ChannelId) -> io::Result<()> {
        if !self.index.lock().unwrap().contains_key(&id) {
            let keys = self
                .read_candidates(id)?
                .into_iter()
                .map(|(k, _)| k)
                .collect();
            self.index.lock().unwrap().insert(id, keys);
        }
        Ok(())
    }

    pub(super) fn room_for(&self, id: ChannelId, key: &str) -> io::Result<bool> {
        let Some(limit) = self.limit else {
            return Ok(true);
        };
        self.ensure_index(id)?;
        let index = self.index.lock().unwrap();
        let keys = &index[&id];
        Ok(keys.contains(key) || keys.len() < limit)
    }

    pub(super) fn overflowed(&self, id: ChannelId, key: &str) -> io::Result<bool> {
        match self.store.read("tower_overflow", &id.to_string(), key) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    pub(super) fn delivered(&self, id: ChannelId, key: &str) -> io::Result<bool> {
        match self.store.read("tower_delivered", &id.to_string(), key) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// In-memory keys for reconciling owner counts without decoding/listing records.
    pub fn candidate_keys(&self, id: ChannelId) -> io::Result<Vec<String>> {
        let _guard = self.gate.lock().unwrap();
        self.ensure_index(id)?;
        Ok(self.index.lock().unwrap()[&id].iter().cloned().collect())
    }

    /// Bounded, lexicographically paged handoff. Reading does not drain candidates.
    pub fn candidate_page(
        &self,
        id: ChannelId,
        after: Option<&str>,
        limit: usize,
    ) -> io::Result<Vec<JusticeCandidate>> {
        let _guard = self.gate.lock().unwrap();
        self.ensure_index(id)?;
        let keys: Vec<_> = self.index.lock().unwrap()[&id]
            .iter()
            .filter(|k| after.is_none_or(|a| k.as_str() > a))
            .take(limit)
            .cloned()
            .collect();
        let mut result = Vec::new();
        for key in keys {
            if let Some(candidate) = self.read_candidate(id, &key)? {
                result.push(candidate.into_candidate());
            } else {
                self.index
                    .lock()
                    .unwrap()
                    .get_mut(&id)
                    .unwrap()
                    .remove(&key);
            }
        }
        Ok(result)
    }

    /// Call ONLY after the outbox has durably recorded acknowledgements from all
    /// of this candidate's eligible towers. Tombstone before removal is crash-safe
    /// and prevents a replayed monitor update recreating an already delivered state.
    pub fn acknowledge_candidate(&self, id: ChannelId, key: &str) -> io::Result<()> {
        let _guard = self.gate.lock().unwrap();
        self.store
            .write("tower_delivered", &id.to_string(), key, vec![1])?;
        self.store
            .remove("tower_candidates", &id.to_string(), key, false)?;
        if let Some(keys) = self.index.lock().unwrap().get_mut(&id) {
            keys.remove(key);
        }
        Ok(())
    }

    /// Known channels and counterparties, including force-closing monitors.
    pub fn channels(&self) -> io::Result<Vec<(ChannelId, bitcoin::secp256k1::PublicKey)>> {
        let _guard = self.gate.lock().unwrap();
        self.store
            .list("tower_peers", "")?
            .into_iter()
            .map(|key| {
                let id = <[u8; 32]>::from_hex(&key).map(ChannelId).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid tower channel")
                })?;
                let peer = decode(&self.store.read("tower_peers", "", &key)?)?;
                Ok((id, peer))
            })
            .collect()
    }

    /// Read persistent coverage-gap counts for an owner status snapshot.
    pub fn diagnostics(&self, id: ChannelId) -> io::Result<TowerDiagnostics> {
        let _guard = self.gate.lock().unwrap();
        self.ensure_index(id)?;
        let channel = id.to_string();
        let unsigned_pending = match self.store.read("tower", "pending", &channel) {
            Ok(bytes) => decode::<PendingChannel>(&bytes)?.pending.len(),
            Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        let signed_candidates = self.index.lock().unwrap()[&id].len();
        Ok(TowerDiagnostics {
            signed_candidates,
            unsigned_pending,
            deferred_signed: self.store.list("tower_overflow", &channel)?.len(),
            quarantined_pending: self.store.list("tower_quarantine_pending", &channel)?.len(),
            quarantined_candidates: self
                .store
                .list("tower_quarantine_candidates", &channel)?
                .len(),
            retired: self.store.list("tower_retired", &channel)?.len(),
            at_capacity: self.limit.is_some_and(|n| signed_candidates >= n),
        })
    }

    /// LDK archival is deliberately later than ChannelClosed (which can be
    /// emitted before a funding spend confirms). Never prune on that event alone.
    pub fn archived_channels(&self) -> io::Result<Vec<ChannelId>> {
        self.store
            .list("tower_closed", "")?
            .iter()
            .map(|s| {
                <[u8; 32]>::from_hex(s).map(ChannelId).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid closed channel")
                })
            })
            .collect()
    }

    /// Delete tower state only after LDK archived the resolved channel and after
    /// the outbox has been pruned. The durable marker survives partial failures.
    pub fn prune_archived_channel(&self, id: ChannelId) -> io::Result<()> {
        let _guard = self.gate.lock().unwrap();
        self.store.read("tower_closed", "", &id.to_string())?;
        for namespace in [
            "tower_candidates",
            "tower_delivered",
            "tower_retired",
            "tower_quarantine_pending",
            "tower_quarantine_candidates",
            "tower_overflow",
        ] {
            for key in self.store.list(namespace, &id.to_string())? {
                self.store.remove(namespace, &id.to_string(), &key, false)?;
            }
        }
        self.store
            .remove("tower", "pending", &id.to_string(), false)?;
        self.store
            .remove("tower_peers", "", &id.to_string(), false)?;
        for name in self.store.list("tower_monitor_channels", "")? {
            let mapped: ChannelId =
                decode(&self.store.read("tower_monitor_channels", "", &name)?)?;
            if mapped == id {
                self.store
                    .remove("tower_monitor_channels", "", &name, false)?;
            }
        }
        self.index.lock().unwrap().remove(&id);
        self.store
            .remove("tower_closed", "", &id.to_string(), false)?;
        Ok(())
    }
}
