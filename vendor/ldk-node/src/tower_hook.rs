//! Local, durable watchtower staging. W1 only: no encryption, transport or tower acknowledgement.
use bitcoin::{ScriptBuf, Transaction};
use lightning::chain::chainmonitor::Persist;
use lightning::chain::channelmonitor::{ChannelMonitor, ChannelMonitorUpdate};
use lightning::chain::ChannelMonitorUpdateStatus;
use lightning::impl_writeable_tlv_based;
use lightning::ln::chan_utils::CommitmentTransaction;
use lightning::ln::types::ChannelId;
use lightning::sign::ecdsa::EcdsaChannelSigner;
use lightning::util::persist::{KVStoreSync, MonitorName};
use lightning::util::ser::{Readable, Writeable};
use std::io;
use std::sync::{Arc, Mutex};

const SIGNED_CANDIDATE_TARGET: usize = 10_000;

/// A revoked commitment's signed, lowest-fee-first justice transaction ladder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JusticeCandidate {
    /// Channel whose counterparty revoked this state.
    pub channel_id: ChannelId,
    /// LDK's backwards-counting commitment number.
    pub commitment_number: u64,
    /// Signed alternatives spending the same revoked to_local output.
    pub ladder: Vec<Transaction>,
    /// Value of the protected output, in satoshis (before justice fees).
    pub value: u64,
}

/// Durable local inbox for a configured tower client. Does not contact a tower.
/// Keep this store across restarts; W2 will consume the signed candidates.
pub struct TowerClient {
    store: Arc<dyn KVStoreSync + Send + Sync>,
    gate: Mutex<()>,
}
impl std::fmt::Debug for TowerClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TowerClient").finish_non_exhaustive()
    }
}
impl TowerClient {
    /// Uses a durable node-local store, normally the same store passed to the node builder.
    pub fn new(store: Arc<dyn KVStoreSync + Send + Sync>) -> Self {
        Self {
            store,
            gate: Mutex::new(()),
        }
    }
    /// Returns valid signed candidates without acknowledging or removing them.
    /// Corrupt records are quarantined and logged; storage failures are returned.
    pub fn pending_candidates(&self, channel_id: ChannelId) -> io::Result<Vec<JusticeCandidate>> {
        let _guard = self.gate.lock().unwrap();
        Ok(self
            .read_candidates(channel_id)?
            .into_iter()
            .map(|(_, c)| c.into_candidate())
            .collect())
    }

    // All private storage helpers run under gate. Copy before remove: a failed write
    // must leave the source intact and propagate to the persister, never Completed.
    fn quarantine(
        &self,
        primary: &str,
        secondary: &str,
        key: &str,
        channel: &str,
        bytes: Vec<u8>,
        reason: &io::Error,
    ) -> io::Result<()> {
        use bitcoin::hashes::{sha256, Hash, HashEngine};
        let namespace = if primary == "tower" {
            "tower_quarantine_pending"
        } else {
            "tower_quarantine_candidates"
        };
        let mut hash = sha256::Hash::engine();
        hash.input(key.as_bytes());
        hash.input(&bytes);
        let saved_key = sha256::Hash::from_engine(hash).to_string();
        // Content-addressing makes retries after a crash between copy/remove idempotent,
        // while preserving different corrupt versions of the same source key.
        self.store.write(namespace, channel, &saved_key, bytes)?;
        self.store.remove(primary, secondary, key, false)?;
        log::error!(
            "Quarantined corrupt watchtower record {}/{}/{} at {}/{}/{}: {}",
            primary,
            secondary,
            key,
            namespace,
            channel,
            saved_key,
            reason
        );
        Ok(())
    }

    fn read_candidate(&self, id: ChannelId, key: &str) -> io::Result<Option<StoredCandidate>> {
        let channel = id.to_string();
        let bytes = match self.store.read("tower_candidates", &channel, key) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let decoded = decode::<StoredCandidate>(&bytes).and_then(|record| {
            validate_candidate(&record.clone().into_candidate(), id, Some(key), true)?;
            Ok(record)
        });
        match decoded {
            Ok(record) => Ok(Some(record)),
            Err(error) => {
                self.quarantine("tower_candidates", &channel, key, &channel, bytes, &error)?;
                Ok(None)
            }
        }
    }

    fn read_candidates(&self, id: ChannelId) -> io::Result<Vec<(String, StoredCandidate)>> {
        let mut candidates = Vec::new();
        for key in self.store.list("tower_candidates", &id.to_string())? {
            if let Some(candidate) = self.read_candidate(id, &key)? {
                candidates.push((key, candidate));
            }
        }
        Ok(candidates)
    }

    fn read_retired(&self, id: ChannelId, key: &str) -> io::Result<Option<RetiredCandidate>> {
        let bytes = match self.store.read("tower_retired", &id.to_string(), key) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let retired = decode::<RetiredCandidate>(&bytes)?;
        validate_candidate(&retired.pending.candidate, id, Some(key), false)?;
        Ok(Some(retired))
    }

    fn is_retired(
        &self,
        id: ChannelId,
        key: &str,
        retired_funding: &[bitcoin::OutPoint],
    ) -> io::Result<bool> {
        // An archive is not fresh retirement proof. Rollback/same-ID transitions
        // clear the journal's proof and must allow redelivery of restored scopes.
        Ok(self
            .read_retired(id, key)?
            .and_then(|retired| retired.pending.funding_outpoint)
            .is_some_and(|funding| retired_funding.contains(&funding)))
    }

    fn restore_retired(
        &self,
        id: ChannelId,
        state: &mut PendingChannel,
        update_id: u64,
    ) -> io::Result<()> {
        for key in self.store.list("tower_retired", &id.to_string())? {
            let Some(retired) = self.read_retired(id, &key)? else {
                continue;
            };
            let pending = retired.pending;
            if pending.observed_update_id > update_id
                || pending
                    .funding_outpoint
                    .is_some_and(|funding| state.retired_funding.contains(&funding))
                || state
                    .pending
                    .iter()
                    .any(|p| candidate_key(&p.candidate) == key)
                || self.read_candidate(id, &key)?.is_some()
            {
                continue;
            }
            if pending.candidate.ladder[0].output[0].script_pubkey != state.destination {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Tower destination mismatch",
                ));
            }
            state.pending.push(pending);
        }
        Ok(())
    }

    fn prune_candidates(
        &self,
        id: ChannelId,
        retired_funding: &[bitcoin::OutPoint],
        active_funding: bitcoin::OutPoint,
    ) -> io::Result<()> {
        let channel = id.to_string();
        if self.store.list("tower_candidates", &channel)?.len() <= SIGNED_CANDIDATE_TARGET {
            return Ok(());
        }
        let mut candidates = self.read_candidates(id)?;
        let mut newest = std::collections::HashMap::new();
        for (_, candidate) in &candidates {
            if let Some(age) = candidate.observed_update_id {
                let latest = newest.entry(candidate.commitment_number).or_insert(age);
                *latest = (*latest).max(age);
            }
        }
        let mut excess = candidates.len().saturating_sub(SIGNED_CANDIDATE_TARGET);
        candidates.sort_by_key(|(key, c)| (c.observed_update_id, key.clone()));
        for (key, candidate) in candidates {
            if excess == 0 {
                break;
            }
            // Age alone is NOT proof of supersession: an unconfirmed splice has two
            // broadcastable funding scopes at the same commitment number. Require an
            // observed LDK retirement of the old scope as well as a newer alternative.
            // Unknown legacy metadata and all still-live scopes remain protected.
            if candidate
                .observed_update_id
                .is_some_and(|age| newest[&candidate.commitment_number] > age)
                && candidate.funding_outpoint.is_some_and(|funding| {
                    funding != active_funding && retired_funding.contains(&funding)
                })
            {
                self.store
                    .remove("tower_candidates", &channel, &key, false)?;
                log::warn!("Pruned superseded watchtower candidate {} for channel {}, commitment {}, observation {:?}", key, channel, candidate.commitment_number, candidate.observed_update_id);
                excess -= 1;
            }
        }
        if excess != 0 {
            log::warn!("Watchtower channel {} exceeds candidate target by {}: retaining distinct commitments and alternatives without proven funding retirement and a strictly newer observation", channel, excess);
        }
        Ok(())
    }
}

// Same TLVs as JusticeCandidate, plus optional age metadata. W1 records remain readable,
// and W1 readers ignore the new odd field. The public candidate API stays unchanged.
#[derive(Clone)]
struct StoredCandidate {
    channel_id: ChannelId,
    commitment_number: u64,
    ladder: Vec<Transaction>,
    value: u64,
    observed_update_id: Option<u64>,
    funding_outpoint: Option<bitcoin::OutPoint>,
}
impl StoredCandidate {
    fn new(
        candidate: JusticeCandidate,
        observed_update_id: u64,
        funding_outpoint: Option<bitcoin::OutPoint>,
    ) -> Self {
        let JusticeCandidate {
            channel_id,
            commitment_number,
            ladder,
            value,
        } = candidate;
        Self {
            channel_id,
            commitment_number,
            ladder,
            value,
            observed_update_id: Some(observed_update_id),
            funding_outpoint,
        }
    }
    fn into_candidate(self) -> JusticeCandidate {
        JusticeCandidate {
            channel_id: self.channel_id,
            commitment_number: self.commitment_number,
            ladder: self.ladder,
            value: self.value,
        }
    }
}

#[derive(Clone)]
struct PendingCandidate {
    candidate: JusticeCandidate,
    observed_update_id: u64,
    // Optional for journals written by W1. This is the commitment's funding input,
    // not the monitor's active input (a pending splice may use a different one).
    funding_outpoint: Option<bitcoin::OutPoint>,
}

struct RetiredCandidate {
    pending: PendingCandidate,
    reason: String,
}

struct PendingChannel {
    destination: ScriptBuf,
    pending: Vec<PendingCandidate>,
    // Active funding at the last journal write, paired with its monitor observation ID.
    funding: Option<(bitcoin::OutPoint, u64)>,
    retired_funding: Vec<bitcoin::OutPoint>,
}
impl PendingChannel {
    fn reconcile_funding(&mut self, active: bitcoin::OutPoint, update_id: u64) -> bool {
        let mut invalidated = false;
        if let Some((previous, observed)) = self.funding {
            if observed > update_id || (previous != active && observed == update_id) {
                // Write-ahead rollback or a same-ID chain transition: do not mistake a
                // restored older monitor for proof that its newer funding was retired.
                invalidated = true;
                self.retired_funding.clear();
            } else if previous != active && !self.retired_funding.contains(&previous) {
                // Follow LDK's scope-retirement policy (including configured splice depth),
                // not a stronger assertion that the funding spend can never be reorged.
                self.retired_funding.push(previous);
            }
        } else {
            invalidated = !self.retired_funding.is_empty();
            self.retired_funding.clear();
        }
        invalidated |= self.retired_funding.contains(&active);
        self.retired_funding.retain(|funding| *funding != active);
        self.funding = Some((active, update_id));
        invalidated
    }
}

// LDK TLV readers deliberately drop a borrow-tracking reader before checking length.
#[allow(clippy::drop_non_drop)]
mod encoding {
    use super::*;
    impl_writeable_tlv_based!(JusticeCandidate, {
        (0, channel_id, required),
        (2, commitment_number, required),
        (4, ladder, required_vec),
        (6, value, required),
    });
    impl_writeable_tlv_based!(StoredCandidate, {
        (0, channel_id, required),
        (2, commitment_number, required),
        (4, ladder, required_vec),
        (6, value, required),
        (9, observed_update_id, option),
        (11, funding_outpoint, option),
    });
    impl_writeable_tlv_based!(PendingCandidate, {
        (0, candidate, required),
        (2, observed_update_id, required),
        (3, funding_outpoint, option),
    });
    impl_writeable_tlv_based!(RetiredCandidate, {
        (0, pending, required),
        (2, reason, required),
    });
    impl_writeable_tlv_based!(PendingChannel, {
        (0, destination, required),
        (2, pending, required_vec),
        (3, funding, option),
        (5, retired_funding, optional_vec),
    });
}

fn decode<T: Readable>(bytes: &[u8]) -> io::Result<T> {
    let mut reader = io::Cursor::new(bytes);
    let value = T::read(&mut reader)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid tower record"))?;
    if reader.position() != bytes.len() as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Trailing tower record data",
        ));
    }
    Ok(value)
}

fn validate_candidate(
    candidate: &JusticeCandidate,
    channel_id: ChannelId,
    key: Option<&str>,
    signed: bool,
) -> io::Result<()> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "Invalid tower candidate");
    if candidate.channel_id != channel_id
        || candidate.commitment_number >= (1 << 48)
        || !(1..=3).contains(&candidate.ladder.len())
    {
        return Err(invalid());
    }
    for tx in &candidate.ladder {
        if tx.input.len() != 1
            || tx.output.len() != 1
            || tx.input[0].sequence != bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME
            || (signed && tx.input[0].witness.is_empty())
            || (!signed && !tx.input[0].witness.is_empty())
            || tx.output[0].value < tx.output[0].script_pubkey.minimal_non_dust()
            || candidate
                .value
                .checked_sub(tx.output[0].value.to_sat())
                .is_none_or(|fee| fee > candidate.value / 2)
        {
            return Err(invalid());
        }
    }
    let first = &candidate.ladder[0];
    if key.is_some_and(|key| key != first.input[0].previous_output.txid.to_string())
        || candidate.ladder.iter().any(|tx| {
            tx.input[0].previous_output != first.input[0].previous_output
                || tx.output[0].script_pubkey != first.output[0].script_pubkey
        })
        || candidate
            .ladder
            .windows(2)
            .any(|tiers| tiers[0].output[0].value <= tiers[1].output[0].value)
    {
        return Err(invalid());
    }
    Ok(())
}

fn candidate_key(candidate: &JusticeCandidate) -> String {
    candidate.ladder[0].input[0]
        .previous_output
        .txid
        .to_string()
}

fn form_candidate(
    channel_id: ChannelId,
    commitment: &CommitmentTransaction,
    destination: &ScriptBuf,
    feerate: u32,
) -> Option<JusticeCandidate> {
    let trusted = commitment.trust();
    let index = trusted.revokeable_output_index()?;
    let value = trusted.built_transaction().transaction.output[index]
        .value
        .to_sat();
    let base = feerate.max(253);
    let ladder: Vec<_> = [1, 4, 16]
        .into_iter()
        .filter_map(|multiplier| {
            // LDK accepts u64 but internally casts the rate to u32. Never wrap a tier.
            let rate = u64::from(base.checked_mul(multiplier)?);
            let tx = trusted
                .build_to_local_justice_tx(rate, destination.clone())
                .ok()?;
            let output = &tx.output[0];
            (value - output.value.to_sat() <= value / 2
                && output.value >= destination.minimal_non_dust())
            .then_some(tx)
        })
        .collect();
    if ladder.is_empty() {
        return None;
    }
    Some(JusticeCandidate {
        channel_id,
        commitment_number: commitment.commitment_number(),
        ladder,
        value,
    })
}

type Destination = Arc<dyn Fn() -> io::Result<ScriptBuf> + Send + Sync>;
pub(crate) struct TowerPersister<P> {
    inner: P,
    client: Option<Arc<TowerClient>>,
    fees: Arc<dyn Fn() -> u32 + Send + Sync>,
    destination: Destination,
}
impl<P> TowerPersister<P> {
    pub(crate) fn new(
        inner: P,
        client: Option<Arc<TowerClient>>,
        fees: Arc<dyn Fn() -> u32 + Send + Sync>,
        destination: Destination,
    ) -> Self {
        Self {
            inner,
            client,
            fees,
            destination,
        }
    }

    fn stage<S: EcdsaChannelSigner>(
        &self,
        monitor: &ChannelMonitor<S>,
        update: Option<&ChannelMonitorUpdate>,
    ) -> io::Result<()> {
        let Some(client) = &self.client else {
            return Ok(());
        };
        let _guard = client.gate.lock().unwrap();
        let id = monitor.channel_id();
        let channel = id.to_string();
        // Startup also checks signed records which no pending entry currently references.
        if update.is_none() {
            client.read_candidates(id)?;
        }
        let loaded = match client.store.read("tower", "pending", &channel) {
            Ok(bytes) => {
                let decoded = decode::<PendingChannel>(&bytes).and_then(|state| {
                    for pending in &state.pending {
                        validate_candidate(&pending.candidate, id, None, false)?;
                        if pending.candidate.ladder[0].output[0].script_pubkey != state.destination
                        {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "Tower destination mismatch",
                            ));
                        }
                    }
                    Ok(state)
                });
                match decoded {
                    Ok(state) => Some(state),
                    Err(error) => {
                        client.quarantine("tower", "pending", &channel, &channel, bytes, &error)?;
                        None
                    }
                }
            }
            Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.into()),
        };
        let (mut state, fresh) = match loaded {
            Some(state) => (state, false),
            None => (
                PendingChannel {
                    destination: (self.destination)()?,
                    pending: Vec::new(),
                    funding: None,
                    retired_funding: Vec::new(),
                },
                true,
            ),
        };
        let active_funding = monitor.get_funding_txo().into_bitcoin_outpoint();
        let retirement_invalidated =
            state.reconcile_funding(active_funding, monitor.get_latest_update_id());
        // A crash can leave the tower write-ahead record newer than the durable monitor.
        // Those unsigned commitments were never acknowledged, so the manager can choose
        // different transactions at the same commitment number on restart. Drop only entries
        // beyond the restored monitor; they are not acknowledged states of its channel history.
        state
            .pending
            .retain(|p| p.observed_update_id <= monitor.get_latest_update_id());
        if retirement_invalidated {
            // Retirement/dequeue can precede the durable monitor write. Recover live
            // heads from the archive if that write rolled back. Ordinary persists do
            // not scan retired records; the proof and restored queue are written together.
            client.restore_retired(id, &mut state, monitor.get_latest_update_id())?;
        }
        let mut commitments = Vec::new();
        if fresh {
            commitments.extend(
                monitor
                    .initial_counterparty_commitment_tx()
                    .map(|tx| (tx, 0)),
            );
        }
        if let Some(update) = update {
            commitments.extend(
                monitor
                    .counterparty_commitment_txs_from_update(update)
                    .into_iter()
                    .map(|tx| (tx, update.update_id)),
            );
        }
        let rate = (self.fees)();
        for (commitment, observed_update_id) in commitments {
            if let Some(candidate) = form_candidate(id, &commitment, &state.destination, rate) {
                let key = candidate_key(&candidate);
                if state
                    .pending
                    .iter()
                    .any(|c| candidate_key(&c.candidate) == key)
                {
                    continue;
                }
                if client.read_candidate(id, &key)?.is_none()
                    && !client.is_retired(id, &key, &state.retired_funding)?
                {
                    state.pending.push(PendingCandidate {
                        candidate,
                        // Redelivery to a newer monitor must not refresh an old alternative's age.
                        observed_update_id,
                        funding_outpoint: Some(
                            commitment.trust().built_transaction().transaction.input[0]
                                .previous_output,
                        ),
                    });
                }
            }
        }
        // Write ahead of the monitor: a later revocation must never overtake its unsigned data.
        client
            .store
            .write("tower", "pending", &channel, state.encode())?;
        let mut index = 0;
        while let Some(pending) = state.pending.get(index) {
            let candidate = &pending.candidate;
            if pending.funding_outpoint.is_some_and(|funding| {
                funding != active_funding && state.retired_funding.contains(&funding)
            }) {
                let key = candidate_key(candidate);
                let retired = RetiredCandidate {
                    pending: pending.clone(),
                    reason: "funding retired by splice".to_string(),
                };
                // Copy BEFORE dequeue, just like signed candidates. Retrying either
                // write after a crash is idempotent, and retired heads are never signed.
                client
                    .store
                    .write("tower_retired", &channel, &key, retired.encode())?;
                state.pending.remove(index);
                client
                    .store
                    .write("tower", "pending", &channel, state.encode())?;
                log::warn!(
                    "Retired unsigned watchtower candidate {} for channel {}: {}",
                    key,
                    channel,
                    retired.reason
                );
                continue;
            }
            let mut signed = candidate.clone();
            let ladder = candidate
                .ladder
                .iter()
                .map(|tx| {
                    monitor.sign_to_local_justice_tx(
                        tx.clone(),
                        0,
                        candidate.value,
                        candidate.commitment_number,
                    )
                })
                .collect::<Result<Vec<_>, _>>();
            // Without retirement proof, retain every failure for retry and continue
            // the queue (including legacy entries with no funding metadata). A differing
            // input can be a pending splice; Err alone cannot prove funding retirement.
            let Ok(ladder) = ladder else {
                let active_funding = monitor.get_funding_txo().into_bitcoin_outpoint();
                if let Some(funding) = pending.funding_outpoint.filter(|f| *f != active_funding) {
                    log::warn!("Watchtower skipping unsigned candidate {} for channel {}: funding outpoint {} differs from active {}; retaining for retry", candidate_key(candidate), channel, funding, active_funding);
                } else {
                    log::debug!("Watchtower deferring unsigned candidate {} for channel {}: secret or signer unavailable (funding {:?}); continuing queue", candidate_key(candidate), channel, pending.funding_outpoint);
                }
                index += 1;
                continue;
            };
            signed.ladder = ladder;
            let key = candidate_key(&signed);
            // Idempotent write BEFORE dequeue. A crash at either write cannot lose the state.
            client.store.write(
                "tower_candidates",
                &channel,
                &key,
                StoredCandidate::new(signed, pending.observed_update_id, pending.funding_outpoint)
                    .encode(),
            )?;
            // Persist the replacement before pruning any older alternative. The target is
            // soft when every retained commitment is distinct; age alone never loses one.
            client.prune_candidates(id, &state.retired_funding, active_funding)?;
            state.pending.remove(index);
            client
                .store
                .write("tower", "pending", &channel, state.encode())?;
        }
        Ok(())
    }
}
impl<S: EcdsaChannelSigner, P: Persist<S>> Persist<S> for TowerPersister<P> {
    fn persist_new_channel(
        &self,
        name: MonitorName,
        monitor: &ChannelMonitor<S>,
    ) -> ChannelMonitorUpdateStatus {
        if let Err(error) = self.stage(monitor, None) {
            log::error!("Watchtower candidate persistence failed: {}", error);
            return ChannelMonitorUpdateStatus::UnrecoverableError;
        }
        self.inner.persist_new_channel(name, monitor)
    }
    fn update_persisted_channel(
        &self,
        name: MonitorName,
        update: Option<&ChannelMonitorUpdate>,
        monitor: &ChannelMonitor<S>,
    ) -> ChannelMonitorUpdateStatus {
        if let Err(error) = self.stage(monitor, update) {
            log::error!("Watchtower candidate persistence failed: {}", error);
            return ChannelMonitorUpdateStatus::UnrecoverableError;
        }
        self.inner.update_persisted_channel(name, update, monitor)
    }
    fn archive_persisted_channel(&self, name: MonitorName) {
        self.inner.archive_persisted_channel(name);
    }
    fn get_and_clear_completed_updates(&self) -> Vec<(ChannelId, u64)> {
        self.inner.get_and_clear_completed_updates()
    }
}

#[cfg(test)]
mod tests;
