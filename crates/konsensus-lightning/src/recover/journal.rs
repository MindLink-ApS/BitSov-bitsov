use super::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const JOURNAL_FILE: &str = "recover.json";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub node_id: String,
    pub closing_txids: Vec<String>,
    pub sweep_txids: Vec<String>,
    pub recovered_sats: u64,
    pub self_test: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SavedSweep {
    pub sweep: Sweep,
    pub inputs: Vec<FoundOutput>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recovery {
    plan: Plan,
    funding: Vec<OutPoint>,
    closes: Vec<(OutPoint, bitcoin::Txid)>,
    sweeps: Vec<SavedSweep>,
    report: Option<Report>,
    #[serde(default)]
    verification: Option<Verification>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    recovery: Option<Recovery>,
}

fn read(path: &Path) -> Result<Option<Journal>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !meta.is_file() || meta.len() > 16 * 1024 * 1024 {
        return Err("invalid recovery journal file".into());
    }
    let journal: Journal = serde_json::from_slice(&fs::read(path)?)?;
    if journal.version != 1 || !matches!(journal.state.as_str(), "open" | "done") {
        return Err("unsupported recovery journal".into());
    }
    Ok(Some(journal))
}
/// Sanitized diagnostics only: never serialize journal contents or parser/I/O errors.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Absent,
    Open,
    Done,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Status {
    pub state: JournalState,
}

/// Read the same versioned journal used by the startup fence, without changing it.
/// Completion mirrors that fence, including its legacy `done` skeleton support.
pub fn status(storage: &Path) -> Status {
    let state = match read(&storage.join(JOURNAL_FILE)) {
        Ok(None) => JournalState::Absent,
        Ok(Some(journal)) if journal.state == "open" => JournalState::Open,
        Ok(Some(journal)) if journal.recovery.as_ref().is_none_or(|r| r.report.is_some()) => {
            JournalState::Done
        }
        Ok(Some(_)) | Err(_) => JournalState::Unavailable,
    };
    Status { state }
}

fn persist(path: &Path, state: &Journal) -> Result<()> {
    let parent = path.parent().ok_or("journal has no parent")?;
    let temp = parent.join(format!(".recover-{:016x}", rand::random::<u64>()));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut f = options.open(&temp)?;
        serde_json::to_writer(&mut f, state)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
/// Caller holds the process lease. The fence is written before restored state/config.
pub fn initialize(storage: &Path) -> Result<()> {
    ensure_fresh_root(storage)?;
    fs::create_dir_all(storage)?;
    let path = storage.join(JOURNAL_FILE);
    if read(&path)?.is_some() {
        return Err("recovery journal already exists".into());
    }
    persist(
        &path,
        &Journal {
            version: 1,
            state: "open".into(),
            recovery: None,
        },
    )?;
    File::open(storage.parent().ok_or("storage has no parent")?)?.sync_all()?;
    Ok(())
}
pub fn ensure_normal_start(storage: &Path) -> Result<()> {
    if let Some(journal) = read(&storage.join(JOURNAL_FILE))? {
        if journal.state != "done"
            || journal
                .recovery
                .as_ref()
                .is_some_and(|r| r.report.is_none())
        {
            return Err(
                "recover.json is open; resume konsensus recover on the owner console".into(),
            );
        }
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub store_id: String,
    pub hub: String,
    pub invoice: Option<String>,
    #[serde(default)]
    pub previous_invoices: Vec<String>,
    pub payment_id: Option<String>,
    #[serde(default)]
    pub payment_attempt: u32,
}

/// Accept only the brand-new canonical store designated by this recovery job.
/// A full pre-loss snapshot contains neither this random marker nor its journal.
pub fn ensure_recovery_root(storage: &Path) -> Result<()> {
    if let Some(journal) = read(&storage.join(JOURNAL_FILE))? {
        if let Some(verification) = journal.recovery.and_then(|r| r.verification) {
            return ensure_verification_store(storage, &verification.store_id);
        }
    }
    ensure_fresh_root(storage)
}
pub fn ensure_verification_store(storage: &Path, store_id: &str) -> Result<()> {
    let marker = storage.join("RECOVERY_STORE");
    if marker.exists() {
        if !fs::symlink_metadata(&marker)?.is_file() || fs::read_to_string(marker)? != store_id {
            return Err("recovery verification store marker mismatch".into());
        }
        let db = storage.join("ldk_node_data.sqlite");
        if db.exists() && !fs::symlink_metadata(db)?.is_file() {
            return Err("recovery verification database is not a regular file".into());
        }
        Ok(())
    } else {
        // Crash after journaling verification, before creating its store marker.
        ensure_fresh_root(storage)
    }
}

pub struct Job {
    path: PathBuf,
    journal: Journal,
    poisoned: bool,
}
impl Job {
    pub fn load_or_begin(storage: &Path, plan: Plan, funding: Vec<OutPoint>) -> Result<Self> {
        ensure_recovery_root(storage)?;
        let path = storage.join(JOURNAL_FILE);
        let mut journal = read(&path)?.ok_or("restore the seed into a fresh directory first")?;
        if let Some(r) = &journal.recovery {
            if r.plan != plan || r.funding != funding {
                return Err(
                    "recovery plan changed; use the original node/network/destination/fee/backup"
                        .into(),
                );
            }
            for s in &r.sweeps {
                s.sweep.validate(&plan)?;
            }
        } else {
            if journal.state != "open" {
                return Err("recovery already done".into());
            }
            journal.recovery = Some(Recovery {
                plan,
                funding,
                closes: vec![],
                sweeps: vec![],
                report: None,
                verification: None,
            });
        }
        persist(&path, &journal)?;
        Ok(Self {
            path,
            journal,
            poisoned: false,
        })
    }
    pub fn verification(&self) -> Option<&Verification> {
        self.recovery().verification.as_ref()
    }
    pub fn begin_verification(&mut self, hub: String) -> Result<()> {
        if let Some(v) = self.verification() {
            if v.hub != hub {
                return Err("verification hub changed".into());
            }
        } else {
            ensure_fresh_root(self.path.parent().ok_or("journal has no parent")?)?;
            let mut next = self.journal.clone();
            next.recovery
                .as_mut()
                .ok_or("missing recovery")?
                .verification = Some(Verification {
                store_id: hex::encode(rand::random::<[u8; 32]>()),
                hub,
                invoice: None,
                previous_invoices: vec![],
                payment_id: None,
                payment_attempt: 0,
            });
            self.save(next)?;
        }
        let storage = self.path.parent().ok_or("journal has no parent")?;
        let id = &self.verification().ok_or("missing verification")?.store_id;
        ensure_verification_store(storage, id)?;
        let marker = storage.join("RECOVERY_STORE");
        if !marker.exists() {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let temporary = storage.join(format!(".recover-store-{:016x}", rand::random::<u64>()));
            let mut file = options.open(&temporary)?;
            file.write_all(id.as_bytes())?;
            file.sync_all()?;
            fs::rename(&temporary, &marker)?;
        }
        File::open(&marker)?.sync_all()?;
        File::open(storage)?.sync_all()?;
        Ok(())
    }
    pub fn save_verification(&mut self, verification: Verification) -> Result<()> {
        let current = self.verification().ok_or("verification not begun")?;
        if current.store_id != verification.store_id || current.hub != verification.hub {
            return Err("verification identity changed".into());
        }
        let mut next = self.journal.clone();
        next.recovery
            .as_mut()
            .ok_or("missing recovery")?
            .verification = Some(verification);
        self.save(next)
    }
    fn recovery(&self) -> &Recovery {
        self.journal
            .recovery
            .as_ref()
            .expect("constructed recovery")
    }
    pub fn plan(&self) -> &Plan {
        &self.recovery().plan
    }
    pub fn done(&self) -> bool {
        self.journal.state == "done"
    }
    pub(super) fn sweeps(&self) -> &[SavedSweep] {
        &self.recovery().sweeps
    }
    pub(super) fn funding(&self) -> &[OutPoint] {
        &self.recovery().funding
    }
    pub(super) fn check(&self) -> Result<()> {
        if self.poisoned {
            Err("journal write failed; restart recovery".into())
        } else {
            Ok(())
        }
    }
    fn save(&mut self, next: Journal) -> Result<()> {
        self.check()?;
        self.poisoned = true;
        persist(&self.path, &next)?;
        self.journal = next;
        self.poisoned = false;
        Ok(())
    }
    pub(super) fn save_sweep(&mut self, sweep: Sweep, inputs: Vec<FoundOutput>) -> Result<()> {
        let mut next = self.journal.clone();
        let r = next.recovery.as_mut().ok_or("missing recovery")?;
        r.sweeps.push(SavedSweep { sweep, inputs });
        self.save(next)
    }
    /// Keep authenticated close identifiers across long pauses, including zero-value
    /// channels, but recheck their actual funding inputs and depth on every use.
    pub(super) async fn confirmed_closes(
        &mut self,
        chain: &dyn RecoveryChain,
    ) -> Result<Option<Vec<bitcoin::Txid>>> {
        let mut ids = Vec::new();
        for funding in self.funding().to_vec() {
            let saved = self
                .recovery()
                .closes
                .iter()
                .find(|(o, _)| *o == funding)
                .map(|(_, id)| *id);
            let close = match saved {
                Some(id) => chain.transaction(id).await?,
                None => chain.funding_spend(funding).await?,
            };
            let Some(close) = close else {
                return Ok(None);
            };
            if !close
                .transaction
                .input
                .iter()
                .any(|i| i.previous_output == funding)
            {
                return Err(
                    "closing transaction does not spend the indexed funding outpoint".into(),
                );
            }
            if close.confirmations < FINAL_CONFIRMATIONS {
                return Ok(None);
            }
            let id = close.transaction.compute_txid();
            if saved.is_some_and(|saved| saved != id) {
                return Err("closing transaction identity changed".into());
            }
            if saved.is_none() {
                let mut next = self.journal.clone();
                next.recovery
                    .as_mut()
                    .ok_or("missing recovery")?
                    .closes
                    .push((funding, id));
                self.save(next)?;
            }
            ids.push(id);
        }
        Ok(Some(ids))
    }
    /// Recheck all six-confirmation receipts after the self-test, before unlocking start.
    pub async fn finish(&mut self, chain: &dyn RecoveryChain, self_test: String) -> Result<Report> {
        self.check()?;
        if (self.sweeps().is_empty() && self.funding().is_empty()) || self_test.is_empty() {
            return Err("recovery/self-test incomplete".into());
        }
        let mut report = Report {
            node_id: self.plan().node_id.clone(),
            closing_txids: vec![],
            sweep_txids: vec![],
            recovered_sats: 0,
            self_test,
        };
        report.closing_txids = self
            .confirmed_closes(chain)
            .await?
            .ok_or("funding close reorged, unknown or immature")?
            .into_iter()
            .map(|id| id.to_string())
            .collect();
        for saved in self.sweeps() {
            let tx = saved.sweep.tx()?;
            let current = chain
                .transaction(tx.compute_txid())
                .await?
                .ok_or("sweep missing")?;
            if current.transaction != tx || current.confirmations < FINAL_CONFIRMATIONS {
                return Err("sweep reorged; recovery remains open".into());
            }
            report.sweep_txids.push(tx.compute_txid().to_string());
            report.recovered_sats += saved.sweep.validate(self.plan())?;
            report
                .closing_txids
                .extend(saved.inputs.iter().map(|o| o.outpoint.txid.to_string()));
        }
        report.closing_txids.sort();
        report.closing_txids.dedup();
        let mut next = self.journal.clone();
        next.state = "done".into();
        next.recovery.as_mut().ok_or("missing recovery")?.report = Some(report.clone());
        self.save(next)?;
        Ok(report)
    }
}
