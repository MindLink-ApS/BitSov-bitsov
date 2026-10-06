//! Local, durable watchtower staging. W1 only: no encryption, transport or tower acknowledgement.
use bitcoin::{ScriptBuf, Transaction};
use lightning::chain::chaininterface::{ConfirmationTarget, FeeEstimator};
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
                decode(&bytes)
            })
            .collect()
    }
}

impl_writeable_tlv_based!(JusticeCandidate, {
    (0, channel_id, required),
    (2, commitment_number, required),
    (4, ladder, required_vec),
    (6, value, required),
});

struct PendingChannel {
    destination: ScriptBuf,
    pending: Vec<JusticeCandidate>,
}
impl_writeable_tlv_based!(PendingChannel, {
    (0, destination, required),
    (2, pending, required_vec),
});

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
    let value = trusted.built_transaction().transaction.output[index as usize]
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
    fees: Arc<dyn FeeEstimator + Send + Sync>,
    destination: Destination,
}
impl<P> TowerPersister<P> {
    pub(crate) fn new(
        inner: P,
        client: Option<Arc<TowerClient>>,
        fees: Arc<dyn FeeEstimator + Send + Sync>,
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
        let mut commitments = Vec::new();
        if fresh {
            commitments.extend(monitor.initial_counterparty_commitment_tx());
        }
        if let Some(update) = update {
            commitments.extend(monitor.counterparty_commitment_txs_from_update(update));
        }
        let rate = self
            .fees
            .get_est_sat_per_1000_weight(ConfirmationTarget::MaximumFeeEstimate);
        for commitment in commitments {
            if let Some(candidate) = form_candidate(id, &commitment, &state.destination, rate) {
                let key = candidate_key(&candidate);
                if state.pending.iter().any(|c| candidate_key(c) == key) {
                    continue;
                }
                match client.store.read("tower_candidates", &channel, &key) {
                    Ok(bytes) => {
                        let _: JusticeCandidate = decode(&bytes)?;
                    }
                    Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => {
                        state.pending.push(candidate)
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        }
        // Write ahead of the monitor: a later revocation must never overtake its unsigned data.
        client
            .store
            .write("tower", "pending", &channel, state.encode())?;
        while let Some(candidate) = state.pending.first() {
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
            // Secret not yet known (or a superseded splice): retain and retry later.
            let Ok(ladder) = ladder else {
                break;
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
            state.pending.remove(0);
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
