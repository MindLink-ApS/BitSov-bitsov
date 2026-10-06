//! Owner-console migration of a CURRENT live LDK store. Never accepts a backup.
//!
//! The caller must hold the node's process lease for the entire job and must
//! obtain console consent before begin/approve_force/approve_sweep. This module
//! is deliberately absent from LightningProvider and every device/API route.
mod ldk;
use bitcoin::{address::NetworkUnchecked, Address, Network, Transaction};
pub use ldk::LdkBackend;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const JOURNAL_FILE: &str = "move-home.json";
pub const FINAL_CONFIRMATIONS: u32 = 6;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub node_id: String,
    pub network: String,
    pub destination: String,
    pub fee_rate_sat_vb: u64,
}
impl Plan {
    pub fn new(
        node_id: String,
        network: &str,
        destination: &str,
        fee_rate_sat_vb: u64,
    ) -> Result<Self> {
        let plan = Self {
            node_id,
            network: network.into(),
            destination: destination.into(),
            fee_rate_sat_vb,
        };
        plan.validate()?;
        Ok(plan)
    }
    pub fn address(&self) -> Result<Address> {
        Ok(Address::<NetworkUnchecked>::from_str(&self.destination)?
            .require_network(Network::from_str(&self.network)?)?)
    }
    fn validate(&self) -> Result<()> {
        self.address()?;
        if !(1..=10_000).contains(&self.fee_rate_sat_vb) || self.node_id.is_empty() {
            return Err("invalid move-home node or fee rate (must be 1..=10000 sat/vB)".into());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct Channel {
    pub id: String,
    pub peer: String,
    pub connected: bool,
    pub shutting_down: bool,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct Snapshot {
    pub channels: Vec<Channel>,
    pub onchain_sats: u64,
    pub spendable_sats: u64,
    pub lightning_sats: u64,
    pub lightning_claims: usize,
    pub pending_monitor_events: usize,
    pub pending_sweeps: usize,
    pub anchor_reserve_sats: u64,
    pub claim_details: Vec<String>,
    pub unresolved_local_spends: usize,
    pub unreadable_local_spends: u64,
    /// Illustrative fee range for our outbound channels at 200 vB per close,
    /// using LDK's current close rates and each channel's avoidance allowance.
    pub estimated_close_fee_min_sats: u64,
    pub estimated_close_fee_max_sats: u64,
}
impl Snapshot {
    pub fn waiting_for_channels(&self) -> bool {
        !self.channels.is_empty()
            || self.lightning_claims != 0
            || self.pending_monitor_events != 0
            || self.pending_sweeps != 0
            || self.anchor_reserve_sats != 0
            || self.unresolved_local_spends != 0
            || self.unreadable_local_spends != 0
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sweep {
    pub transaction: String,
    pub fee_sats: u64,
}
impl Sweep {
    pub fn tx(&self) -> Result<Transaction> {
        Ok(bitcoin::consensus::deserialize(&hex::decode(
            &self.transaction,
        )?)?)
    }
    pub fn validate(&self, plan: &Plan) -> Result<u64> {
        let tx = self.tx()?;
        if tx.output.len() != 1
            || tx.output[0].script_pubkey != plan.address()?.script_pubkey()
            || tx.output[0].value.to_sat() == 0
        {
            return Err("move-home sweep must pay only the owner's destination".into());
        }
        Ok(tx.output[0].value.to_sat())
    }
    pub fn txid(&self) -> Result<String> {
        Ok(self.tx()?.compute_txid().to_string())
    }
}

pub trait Backend {
    fn snapshot(&self) -> Result<Snapshot>;
    fn close(&self, channel: &Channel, force: bool) -> Result<()>;
    /// Sign without reserving inputs, persisting or broadcasting. Caller owns the exclusive lease.
    fn prepare_sweep(&self, plan: &Plan) -> Result<Sweep>;
    /// Record and enqueue EXACTLY this previously approved transaction, idempotently.
    fn broadcast(&mut self, sweep: &Sweep, plan: &Plan) -> Result<()>;
    fn confirmations(&self, sweep: &Sweep) -> Result<u32>;
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    plan: Plan,
    cooperative_attempted: BTreeSet<String>,
    force_approved: BTreeSet<String>,
    sweeps: Vec<Sweep>,
}
pub struct Job {
    path: PathBuf,
    state: State,
    poisoned: bool,
}
#[derive(Debug)]
pub enum Progress {
    Waiting {
        snapshot: Snapshot,
        close_errors: Vec<String>,
    },
    SweepPreview(Sweep),
    Confirming {
        txid: String,
        confirmations: u32,
    },
    Complete,
}
impl Job {
    pub fn begin(path: &Path, plan: Plan) -> Result<Self> {
        plan.validate()?;
        if path.try_exists()? {
            return Err("migration journal already exists; resume it".into());
        }
        let mut job = Self {
            path: path.into(),
            state: State {
                version: 1,
                plan,
                cooperative_attempted: BTreeSet::new(),
                force_approved: BTreeSet::new(),
                sweeps: vec![],
            },
            poisoned: false,
        };
        job.persist(job.state.clone())?;
        Ok(job)
    }
    pub fn load(path: &Path, plan: &Plan) -> Result<Option<Self>> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let state: State = serde_json::from_slice(&bytes)?;
        state.plan.validate()?;
        if state.version != 1 || state.plan != *plan {
            return Err("move-home journal does not match node, network, destination or fee rate; refusing to change the approved plan".into());
        }
        for sweep in &state.sweeps {
            sweep.validate(plan)?;
        }
        // Also repair durability after a prior interrupted/failed directory sync.
        File::open(path)?.sync_all()?;
        File::open(path.parent().ok_or("journal has no parent")?)?.sync_all()?;
        Ok(Some(Self {
            path: path.into(),
            state,
            poisoned: false,
        }))
    }
    pub fn plan(&self) -> &Plan {
        &self.state.plan
    }
    /// Read-only status; never rebroadcasts or requests closes.
    pub fn sweep_status(&self, backend: &impl Backend) -> Result<Vec<(String, u32)>> {
        self.state
            .sweeps
            .iter()
            .map(|sweep| Ok((sweep.txid()?, backend.confirmations(sweep)?)))
            .collect()
    }
    fn persist(&mut self, next: State) -> Result<()> {
        if self.poisoned {
            return Err("journal write failed; restart before continuing".into());
        }
        let result = persist(&self.path, &next);
        if result.is_err() {
            self.poisoned = true;
        }
        result?;
        self.state = next;
        Ok(())
    }
    pub fn approve_force(
        &mut self,
        selected: &BTreeSet<String>,
        backend: &impl Backend,
    ) -> Result<()> {
        let snapshot = backend.snapshot()?;
        for id in selected {
            if !snapshot.channels.iter().any(|ch| &ch.id == id) {
                return Err(format!("force-close {id} requires a named live channel").into());
            }
        }
        let mut next = self.state.clone();
        next.force_approved.extend(selected.iter().cloned());
        self.persist(next)
    }
    pub fn approve_sweep(&mut self, sweep: &Sweep, backend: &impl Backend) -> Result<()> {
        sweep.validate(&self.state.plan)?;
        if backend.snapshot()?.waiting_for_channels() {
            return Err("channel claims or reserves still pending".into());
        }
        if let Some(previous) = self.state.sweeps.last() {
            if backend.confirmations(previous)? < FINAL_CONFIRMATIONS {
                return Err("previous sweep is not final".into());
            }
        }
        // Rebuild before accepting consent: changed inputs/amounts require another preview.
        if backend.prepare_sweep(&self.state.plan)? != *sweep {
            return Err("wallet changed since preview; preview and confirm again".into());
        }
        let mut next = self.state.clone();
        next.sweeps.push(sweep.clone());
        self.persist(next) // No broadcast until the signed bytes and consent are durable.
    }
    pub fn advance(&mut self, backend: &mut impl Backend) -> Result<Progress> {
        if self.poisoned {
            return Err("journal write failed; restart before continuing".into());
        }
        // Replay a durable send before selecting any new inputs. A lost response,
        // restart or absent mempool transaction NEVER means a new send is safe.
        for sweep in &self.state.sweeps {
            let confirmations = backend.confirmations(sweep)?;
            if confirmations < FINAL_CONFIRMATIONS {
                if confirmations == 0 {
                    backend.broadcast(sweep, &self.state.plan)?;
                }
                return Ok(Progress::Confirming {
                    txid: sweep.txid()?,
                    confirmations,
                });
            }
        }
        let snapshot = backend.snapshot()?;
        let mut close_errors = vec![];
        for channel in &snapshot.channels {
            let force = self.state.force_approved.contains(&channel.id);
            // Read live LDK shutdown state, including after a crash between
            // dispatch and journal persistence. Old journals may have recorded
            // failed attempts, so the journal alone cannot suppress a retry.
            if !force && channel.shutting_down {
                continue;
            }
            match backend.close(channel, force) {
                Err(error) => close_errors.push(format!("{}: {error}", channel.id)),
                Ok(()) if !force && !self.state.cooperative_attempted.contains(&channel.id) => {
                    let mut next = self.state.clone();
                    next.cooperative_attempted.insert(channel.id.clone());
                    self.persist(next)?;
                }
                Ok(()) => {}
            }
        }
        if snapshot.waiting_for_channels() {
            return Ok(Progress::Waiting {
                snapshot,
                close_errors,
            });
        }
        if snapshot.onchain_sats == 0 {
            return Ok(Progress::Complete);
        }
        let sweep = backend.prepare_sweep(&self.state.plan)?;
        sweep.validate(&self.state.plan)?;
        Ok(Progress::SweepPreview(sweep))
    }
}
fn persist(path: &Path, state: &State) -> Result<()> {
    let temp = path.with_extension(format!("{}.tmp", rand::random::<u128>()));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp)?;
        file.write_all(&serde_json::to_vec_pretty(state)?)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(path.parent().ok_or("journal has no parent")?)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Mirrors the pinned LDK builder's master-key derivation without opening state.
pub fn node_id_from_seed(seed: &[u8; 64]) -> Result<String> {
    use ldk_node::lightning::sign::{KeysManager, NodeSigner, Recipient};
    // Network only changes extended-key serialization, not the private key.
    let master = bitcoin::bip32::Xpriv::new_master(Network::Bitcoin, seed)?;
    let key = zeroize::Zeroizing::new(master.private_key.secret_bytes());
    let keys = KeysManager::new(&key, 0, 0, true);
    Ok(keys
        .get_node_id(Recipient::Node)
        .map_err(|_| "could not derive LDK node id")?
        .to_string())
}
