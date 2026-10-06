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
    /// Returns signed candidates without removing them. Reading is not acknowledgement.
    pub fn pending_candidates(&self, channel_id: ChannelId) -> io::Result<Vec<JusticeCandidate>> {
        let _guard = self.gate.lock().unwrap();
        let channel = channel_id.to_string();
        self.store
            .list("tower_candidates", &channel)?
            .into_iter()
            .map(|key| {
                let bytes = self.store.read("tower_candidates", &channel, &key)?;
                let candidate = decode(&bytes)?;
                validate_candidate(&candidate, channel_id, Some(&key), true)?;
                Ok(candidate)
            })
            .collect()
    }
}

struct PendingCandidate {
    candidate: JusticeCandidate,
    observed_update_id: u64,
    // Optional for journals written by W1. This is the commitment's funding input,
    // not the monitor's active input (a pending splice may use a different one).
    funding_outpoint: Option<bitcoin::OutPoint>,
}

struct PendingChannel {
    destination: ScriptBuf,
    pending: Vec<PendingCandidate>,
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
    impl_writeable_tlv_based!(PendingCandidate, {
        (0, candidate, required),
        (2, observed_update_id, required),
        (3, funding_outpoint, option),
    });
    impl_writeable_tlv_based!(PendingChannel, {
        (0, destination, required),
        (2, pending, required_vec),
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
        let (mut state, fresh) = match client.store.read("tower", "pending", &channel) {
            Ok(bytes) => (decode::<PendingChannel>(&bytes)?, false),
            Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => (
                PendingChannel {
                    destination: (self.destination)()?,
                    pending: Vec::new(),
                },
                true,
            ),
            Err(e) => return Err(e.into()),
        };
        // A crash can leave the tower write-ahead record newer than the durable monitor.
        // Those unsigned commitments were never acknowledged, so the manager can choose
        // different transactions at the same commitment number on restart. Drop only entries
        // beyond the restored monitor; otherwise an unknown txid could block the queue forever.
        state
            .pending
            .retain(|p| p.observed_update_id <= monitor.get_latest_update_id());
        for pending in &state.pending {
            validate_candidate(&pending.candidate, id, None, false)?;
            if pending.candidate.ladder[0].output[0].script_pubkey != state.destination {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Tower destination mismatch",
                ));
            }
        }
        let mut commitments = Vec::new();
        if fresh {
            commitments.extend(monitor.initial_counterparty_commitment_tx());
        }
        if let Some(update) = update {
            commitments.extend(monitor.counterparty_commitment_txs_from_update(update));
        }
        let rate = (self.fees)();
        for commitment in commitments {
            if let Some(candidate) = form_candidate(id, &commitment, &state.destination, rate) {
                let key = candidate_key(&candidate);
                if state
                    .pending
                    .iter()
                    .any(|c| candidate_key(&c.candidate) == key)
                {
                    continue;
                }
                match client.store.read("tower_candidates", &channel, &key) {
                    Ok(bytes) => {
                        let existing: JusticeCandidate = decode(&bytes)?;
                        validate_candidate(&existing, id, Some(&key), true)?;
                    }
                    Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => {
                        state.pending.push(PendingCandidate {
                            candidate,
                            observed_update_id: monitor.get_latest_update_id(),
                            funding_outpoint: Some(
                                commitment.trust().built_transaction().transaction.input[0]
                                    .previous_output,
                            ),
                        })
                    }
                    Err(e) => return Err(e.into()),
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
            // A locked splice removes the old funding scope from LDK's signer. Never let
            // that entry (including legacy entries with no funding metadata) block later
            // states. Retain failures for retry: a differing input can also be a pending
            // splice, and Err alone does not distinguish a missing secret/signer outage.
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
            let keys = client.store.list("tower_candidates", &channel)?;
            if keys.len() >= 10_000 && !keys.contains(&key) {
                return Err(io::Error::other("Tower candidate queue is full"));
            }
            // Idempotent write BEFORE dequeue. A crash at either write cannot lose the state.
            client
                .store
                .write("tower_candidates", &channel, &key, signed.encode())?;
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
