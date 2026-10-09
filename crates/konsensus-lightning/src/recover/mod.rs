//! Seed-only owner-console recovery. Backups are immutable public indexes only.
mod journal;
use crate::move_home::{Plan, Result, Sweep, FINAL_CONFIRMATIONS};
use bitcoin::{FeeRate, OutPoint};
pub use journal::{
    ensure_normal_start, ensure_recovery_root, ensure_verification_store, initialize, status, Job,
    JournalState, Report, Status, Verification,
};
use konsensus_chain::recovery::RecoveryChain;
use konsensus_recovery::{BackupIndex, FoundOutput, RecoveryKeys, RecoveryScript};

#[derive(Debug)]
pub enum Progress {
    WaitingForHub,
    SweepPreview {
        sweep: Sweep,
        inputs: Vec<FoundOutput>,
    },
    Confirming {
        txid: String,
        confirmations: u32,
    },
    SelfTest,
    Complete,
}

/// Metadata only. A stale snapshot cannot provide a transaction or a signer.
pub fn scripts(keys: &RecoveryKeys, index: Option<&BackupIndex>) -> Vec<RecoveryScript> {
    match index {
        None => keys.scripts().to_vec(),
        Some(index) => {
            let mut scripts: Vec<_> = index
                .channels()
                .iter()
                .filter(|c| !c.archived)
                .map(|c| c.to_remote.clone())
                .collect();
            scripts.sort_by_key(|s| (s.key_index, s.script_pubkey.clone()));
            scripts.dedup();
            scripts
        }
    }
}

/// Reject a copied live store *before* any LDK builder, including preview/resume.
/// The close/sweep phase uses a new private child directory on every invocation.
/// After sweeping, a journal-designated canonical store retains the self-test
/// channel and wallet for normal startup.
pub fn ensure_fresh_root(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("invalid recovery directory entry")?;
        if name != "INSTANCE"
            && name != "recover.json"
            && !name.starts_with("recover-session-")
            && !name.starts_with(".recover-")
        {
            return Err("recovery requires a fresh data directory; never start or recover in a snapshot/live LDK store".into());
        }
        if entry.file_type()?.is_symlink() {
            return Err("symlink in recovery directory".into());
        }
    }
    Ok(())
}

impl Job {
    pub async fn advance(
        &mut self,
        chain: &dyn RecoveryChain,
        keys: &RecoveryKeys,
        scripts: &[RecoveryScript],
    ) -> Result<Progress> {
        self.check()?;
        if self.done() {
            return Ok(Progress::Complete);
        }
        if let Some(progress) = self.resume_sweeps(chain).await? {
            return Ok(progress);
        }
        let outputs = chain.scan(scripts).await?;
        if outputs.iter().any(|o| o.confirmations == 0) {
            return Ok(Progress::WaitingForHub);
        }
        if !outputs.is_empty() {
            self.authenticate_closes(chain, &outputs).await?;
            let signed = keys.build_sweep(
                &outputs,
                self.plan().address()?.script_pubkey(),
                FeeRate::from_sat_per_vb(self.plan().fee_rate_sat_vb).ok_or("invalid fee rate")?,
            )?;
            let sweep = Sweep {
                transaction: bitcoin::consensus::encode::serialize_hex(&signed.transaction),
                fee_sats: signed.fee.to_sat(),
            };
            sweep.validate(self.plan())?;
            return Ok(Progress::SweepPreview {
                sweep,
                inputs: outputs,
            });
        }
        if self.sweeps().is_empty() && self.funding().is_empty() {
            return Ok(Progress::WaitingForHub);
        }
        if self.confirmed_closes(chain).await?.is_none() {
            return Ok(Progress::WaitingForHub);
        }
        Ok(Progress::SelfTest)
    }

    /// Resume previously authorized sweeps without opening/replacing any LDK
    /// store. Also used during the canonical Lightning verification phase.
    pub async fn resume_sweeps(&self, chain: &dyn RecoveryChain) -> Result<Option<Progress>> {
        self.check()?;
        // Every saved transaction is rechecked on the current chain after restart.
        for saved in self.sweeps() {
            let tx = saved.sweep.tx()?;
            if chain.recheck(&saved.inputs).await? {
                chain.broadcast(&tx).await?;
                return Ok(Some(Progress::Confirming {
                    txid: tx.compute_txid().to_string(),
                    confirmations: 0,
                }));
            } else if let Some(current) = chain.transaction(tx.compute_txid()).await? {
                if current.transaction != tx {
                    return Err("chain transaction differs from approved sweep".into());
                }
                if current.confirmations < FINAL_CONFIRMATIONS {
                    return Ok(Some(Progress::Confirming {
                        txid: tx.compute_txid().to_string(),
                        confirmations: current.confirmations,
                    }));
                }
            } else {
                return Err(
                    "approved inputs are spent but sweep is unknown; journal remains open".into(),
                );
            }
        }
        Ok(None)
    }

    async fn authenticate_closes(
        &self,
        chain: &dyn RecoveryChain,
        outputs: &[FoundOutput],
    ) -> Result<()> {
        for output in outputs {
            let close = chain
                .transaction(output.outpoint.txid)
                .await?
                .ok_or("closing transaction unavailable")?;
            if close.confirmations == 0
                || close.transaction.output.get(output.outpoint.vout as usize)
                    != Some(&output.txout)
            {
                return Err("closing output is not confirmed/authenticated".into());
            }
            if !self.funding().is_empty()
                && !close
                    .transaction
                    .input
                    .iter()
                    .any(|i| self.funding().contains(&i.previous_output))
            {
                return Err("backup-index output does not spend a known funding outpoint".into());
            }
        }
        Ok(())
    }

    /// Caller must display/confirm this exact transaction through /dev/tty first.
    pub async fn approve(
        &mut self,
        chain: &dyn RecoveryChain,
        sweep: Sweep,
        inputs: Vec<FoundOutput>,
    ) -> Result<()> {
        self.check()?;
        sweep.validate(self.plan())?;
        let tx = sweep.tx()?;
        if self.sweeps().iter().any(|saved| {
            saved
                .inputs
                .iter()
                .any(|old| inputs.iter().any(|new| old.outpoint == new.outpoint))
        }) {
            return Err("sweep input already authorized; resume the saved transaction".into());
        }
        if inputs.is_empty()
            || tx.input.len() != inputs.len()
            || tx
                .input
                .iter()
                .zip(&inputs)
                .any(|(i, o)| i.previous_output != o.outpoint)
        {
            return Err("sweep inputs differ from preview".into());
        }
        let total = inputs
            .iter()
            .try_fold(0u64, |n, o| n.checked_add(o.txout.value.to_sat()))
            .ok_or("input overflow")?;
        if tx.output[0].value.to_sat().checked_add(sweep.fee_sats) != Some(total) {
            return Err("sweep fee differs from preview".into());
        }
        if !chain.recheck(&inputs).await? {
            return Err("inputs changed during consent; preview again".into());
        }
        self.authenticate_closes(chain, &inputs).await?;
        // Persist before the first possible broadcast, including an interrupted command.
        self.save_sweep(sweep, inputs)?;
        Ok(())
    }
}

/// First external BIP84 address, matching the pinned ldk-node/BDK descriptors.
/// No wallet, storage, network, or channel state is opened.
pub fn wallet_address(seed: &[u8; 64], network: bitcoin::Network) -> Result<bitcoin::Address> {
    use bitcoin::bip32::{ChildNumber, Xpriv};
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut master = Xpriv::new_master(network, seed)?;
    let mut child = master.derive_priv(
        &secp,
        &[
            ChildNumber::from_hardened_idx(84)?,
            ChildNumber::from_hardened_idx(if network == bitcoin::Network::Bitcoin {
                0
            } else {
                1
            })?,
            ChildNumber::from_hardened_idx(0)?,
            ChildNumber::from_normal_idx(0)?,
            ChildNumber::from_normal_idx(0)?,
        ],
    )?;
    let public = bitcoin::CompressedPublicKey(bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &child.private_key,
    ));
    master.private_key.non_secure_erase();
    child.private_key.non_secure_erase();
    Ok(bitcoin::Address::p2wpkh(&public, network))
}

/// On-chain continuity test while APIs/liquidity/channel acceptance remain disabled.
/// This deliberately reports only checks actually performed, not Lightning readiness.
pub async fn self_test(
    provider: &crate::LdkProvider,
    job: &Job,
    own_wallet: bool,
) -> Result<String> {
    use konsensus_core::traits::lightning::LightningProvider;
    let node = provider.node();
    tokio::task::block_in_place(|| node.sync_wallets())?;
    if node.node_id().to_string() != job.plan().node_id || !node.list_channels().is_empty() {
        return Err("self-test identity/channel isolation failed".into());
    }
    if !provider.money_ready().await {
        return Err("self-test chain synchronization incomplete".into());
    }
    if own_wallet {
        let expected: u64 = job
            .sweeps()
            .iter()
            .map(|s| s.sweep.validate(job.plan()))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .sum();
        if node.list_balances().total_onchain_balance_sats < expected {
            return Err("self-test recovered wallet balance not yet synchronized".into());
        }
    }
    Ok(format!("identity and empty channel store verified; money_ready=true; own_wallet_balance_verified={own_wallet}; Lightning payment not tested"))
}

impl crate::LdkProvider {
    /// Console recovery's idempotent 1-sat direct-hub test, with zero routing-fee budget.
    pub fn send_recovery_self_test(&self, hub: &str, preimage: [u8; 32]) -> Result<()> {
        use ldk_node::lightning::{
            routing::router::RouteParametersConfig, types::payment::PaymentPreimage,
        };
        self.node().spontaneous_payment().send_with_preimage(
            1000,
            hub.parse()?,
            PaymentPreimage(preimage),
            Some(RouteParametersConfig {
                max_total_routing_fee_msat: Some(0),
                ..Default::default()
            }),
        )?;
        Ok(())
    }
}
