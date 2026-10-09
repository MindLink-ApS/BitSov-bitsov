use bitcoin::{absolute, transaction, Amount, OutPoint, Transaction, TxIn, TxOut};
use konsensus_chain::recovery::{ChainTransaction, RecoveryChain};
use konsensus_core::traits::chain::ChainError;
use konsensus_lightning::{
    move_home::Plan,
    recover::{self, Job, Progress},
};
use konsensus_recovery::{FoundOutput, RecoveryKeys, RecoveryScript, Scanner};
use std::sync::Mutex;

struct Chain {
    discovery_unavailable: std::sync::atomic::AtomicBool,
    outputs: Mutex<Vec<FoundOutput>>,
    transactions: Mutex<Vec<ChainTransaction>>,
    sent: Mutex<Vec<Transaction>>,
}
#[async_trait::async_trait]
impl Scanner for Chain {
    type Error = ChainError;
    async fn scan(&self, _: &[RecoveryScript]) -> Result<Vec<FoundOutput>, ChainError> {
        Ok(self.outputs.lock().unwrap().clone())
    }
}
#[async_trait::async_trait]
impl RecoveryChain for Chain {
    async fn funding_spend(
        &self,
        outpoint: OutPoint,
    ) -> Result<Option<ChainTransaction>, ChainError> {
        if self
            .discovery_unavailable
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(ChainError::NotAvailable(
                "outside recent discovery window".into(),
            ));
        }
        Ok(self
            .transactions
            .lock()
            .unwrap()
            .iter()
            .find(|t| {
                t.confirmations > 0
                    && t.transaction
                        .input
                        .iter()
                        .any(|i| i.previous_output == outpoint)
            })
            .cloned())
    }
    async fn transaction(
        &self,
        txid: bitcoin::Txid,
    ) -> Result<Option<ChainTransaction>, ChainError> {
        Ok(self
            .transactions
            .lock()
            .unwrap()
            .iter()
            .find(|t| t.transaction.compute_txid() == txid)
            .cloned())
    }
    async fn recheck(&self, outputs: &[FoundOutput]) -> Result<bool, ChainError> {
        Ok(outputs.iter().all(|o| {
            self.outputs
                .lock()
                .unwrap()
                .iter()
                .any(|v| v.outpoint == o.outpoint && v.txout == o.txout && v.confirmations > 0)
        }))
    }
    async fn broadcast(&self, tx: &Transaction) -> Result<(), ChainError> {
        self.sent.lock().unwrap().push(tx.clone());
        self.outputs
            .lock()
            .unwrap()
            .retain(|o| !tx.input.iter().any(|i| i.previous_output == o.outpoint));
        self.transactions.lock().unwrap().push(ChainTransaction {
            transaction: tx.clone(),
            confirmations: 0,
        });
        Ok(())
    }
}
fn fixture() -> (tempfile::TempDir, RecoveryKeys, Chain, Plan) {
    let dir = tempfile::tempdir().unwrap();
    recover::initialize(dir.path()).unwrap();
    let keys = RecoveryKeys::from_ldk_seed(&[9; 32]).unwrap();
    let close = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(90_000),
            script_pubkey: keys.scripts()[1].script_pubkey.clone(),
        }],
    };
    let output = FoundOutput {
        outpoint: OutPoint {
            txid: close.compute_txid(),
            vout: 0,
        },
        txout: close.output[0].clone(),
        confirmations: 1,
    };
    let chain = Chain {
        discovery_unavailable: std::sync::atomic::AtomicBool::new(false),
        outputs: Mutex::new(vec![output]),
        transactions: Mutex::new(vec![ChainTransaction {
            transaction: close,
            confirmations: 1,
        }]),
        sent: Mutex::new(vec![]),
    };
    let plan = Plan::new(
        "node".into(),
        "regtest",
        "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        2,
    )
    .unwrap();
    (dir, keys, chain, plan)
}
#[tokio::test]
async fn consent_is_durable_and_six_confirmations_plus_self_test_gate_completion() {
    let (dir, keys, chain, plan) = fixture();
    let mut job = Job::load_or_begin(dir.path(), plan.clone(), vec![]).unwrap();
    let Progress::SweepPreview { sweep, inputs } =
        job.advance(&chain, &keys, keys.scripts()).await.unwrap()
    else {
        panic!("preview");
    };
    assert!(chain.sent.lock().unwrap().is_empty());
    assert!(recover::ensure_normal_start(dir.path()).is_err());
    assert!(job.finish(&chain, "test".into()).await.is_err());
    job.approve(&chain, sweep, inputs).await.unwrap();
    drop(job);
    let mut job = Job::load_or_begin(dir.path(), plan, vec![]).unwrap();
    assert!(matches!(
        job.advance(&chain, &keys, keys.scripts()).await.unwrap(),
        Progress::Confirming {
            confirmations: 0,
            ..
        }
    ));
    assert_eq!(chain.sent.lock().unwrap().len(), 1);
    for confirmations in 0..6 {
        chain
            .transactions
            .lock()
            .unwrap()
            .last_mut()
            .unwrap()
            .confirmations = confirmations;
        assert!(matches!(
            job.advance(&chain, &keys, keys.scripts()).await.unwrap(),
            Progress::Confirming { .. }
        ));
        assert!(job.finish(&chain, "test".into()).await.is_err());
    }
    chain
        .transactions
        .lock()
        .unwrap()
        .last_mut()
        .unwrap()
        .confirmations = 6;
    assert!(matches!(
        job.advance(&chain, &keys, keys.scripts()).await.unwrap(),
        Progress::SelfTest
    ));
    assert!(job.finish(&chain, String::new()).await.is_err());
    // Reorg between self-test and completion must not clear the fence.
    chain
        .transactions
        .lock()
        .unwrap()
        .last_mut()
        .unwrap()
        .confirmations = 5;
    assert!(job.finish(&chain, "test".into()).await.is_err());
    assert!(recover::ensure_normal_start(dir.path()).is_err());
    chain
        .transactions
        .lock()
        .unwrap()
        .last_mut()
        .unwrap()
        .confirmations = 6;
    job.finish(&chain, "tested".into()).await.unwrap();
    recover::ensure_normal_start(dir.path()).unwrap();
}
#[tokio::test]
async fn verification_keeps_its_live_store_while_rebroadcasting_an_evicted_sweep() {
    let (dir, keys, chain, plan) = fixture();
    let mut job = Job::load_or_begin(dir.path(), plan.clone(), vec![]).unwrap();
    let Progress::SweepPreview { sweep, inputs } =
        job.advance(&chain, &keys, keys.scripts()).await.unwrap()
    else {
        panic!("preview")
    };
    let originals = inputs.clone();
    let approved = sweep.tx().unwrap();
    job.approve(&chain, sweep, inputs).await.unwrap();
    job.resume_sweeps(&chain).await.unwrap();
    chain
        .transactions
        .lock()
        .unwrap()
        .last_mut()
        .unwrap()
        .confirmations = 6;
    job.begin_verification("hub".into()).unwrap();
    std::fs::write(dir.path().join("ldk_node_data.sqlite"), b"new live channel").unwrap();
    let mut verification = job.verification().unwrap().clone();
    verification
        .previous_invoices
        .push("expired pending invoice".into());
    verification.invoice = Some("current invoice".into());
    job.save_verification(verification).unwrap();
    // An offline reorg evicts the sweep and restores its original confirmed inputs.
    chain.transactions.lock().unwrap().pop();
    *chain.outputs.lock().unwrap() = originals;
    drop(job);
    let job = Job::load_or_begin(dir.path(), plan, vec![]).unwrap();
    assert_eq!(
        job.verification().unwrap().previous_invoices,
        vec!["expired pending invoice"]
    );
    assert!(matches!(
        job.resume_sweeps(&chain).await.unwrap(),
        Some(Progress::Confirming {
            confirmations: 0,
            ..
        })
    ));
    assert_eq!(
        chain.sent.lock().unwrap().as_slice(),
        &[approved.clone(), approved]
    );
    assert_eq!(
        std::fs::read(dir.path().join("ldk_node_data.sqlite")).unwrap(),
        b"new live channel"
    );
    assert!(recover::ensure_normal_start(dir.path()).is_err());
}

#[tokio::test]
async fn maturity_input_changes_and_unknown_spends_fail_closed() {
    let (dir, keys, chain, plan) = fixture();
    let mut job = Job::load_or_begin(dir.path(), plan, vec![]).unwrap();
    chain.outputs.lock().unwrap()[0].confirmations = 0;
    assert!(matches!(
        job.advance(&chain, &keys, keys.scripts()).await.unwrap(),
        Progress::WaitingForHub
    ));
    chain.outputs.lock().unwrap()[0].confirmations = 1;
    let Progress::SweepPreview { sweep, inputs } =
        job.advance(&chain, &keys, keys.scripts()).await.unwrap()
    else {
        panic!("preview");
    };
    chain.outputs.lock().unwrap().clear();
    assert!(job
        .approve(&chain, sweep.clone(), inputs.clone())
        .await
        .is_err());
    *chain.outputs.lock().unwrap() = inputs.clone();
    job.approve(&chain, sweep, inputs).await.unwrap();
    chain.outputs.lock().unwrap().clear();
    assert!(job.advance(&chain, &keys, keys.scripts()).await.is_err());
    assert!(chain.sent.lock().unwrap().is_empty());
}
#[tokio::test]
async fn duplicate_sweep_consent_is_rejected() {
    let (dir, keys, chain, plan) = fixture();
    let mut job = Job::load_or_begin(dir.path(), plan, vec![]).unwrap();
    let Progress::SweepPreview { sweep, inputs } =
        job.advance(&chain, &keys, keys.scripts()).await.unwrap()
    else {
        panic!("preview");
    };
    job.approve(&chain, sweep.clone(), inputs.clone())
        .await
        .unwrap();
    assert!(job.approve(&chain, sweep, inputs).await.is_err());
}
#[test]
fn changed_plan_corrupt_journal_and_live_stores_are_refused() {
    let (dir, _, _, mut plan) = fixture();
    Job::load_or_begin(dir.path(), plan.clone(), vec![]).unwrap();
    plan.fee_rate_sat_vb += 1;
    assert!(Job::load_or_begin(dir.path(), plan.clone(), vec![]).is_err());
    std::fs::write(dir.path().join("recover.json"), b"{broken").unwrap();
    assert!(recover::ensure_normal_start(dir.path()).is_err());
    assert!(Job::load_or_begin(dir.path(), plan, vec![]).is_err());
    std::fs::write(dir.path().join("ldk_node_data.sqlite"), b"stale").unwrap();
    assert!(recover::ensure_fresh_root(dir.path()).is_err());
    assert!(recover::initialize(dir.path()).is_err());
}

#[tokio::test]
async fn confirmed_zero_claim_channel_does_not_strand_other_recovered_funds() {
    let (dir, keys, chain, plan) = fixture();
    let other = OutPoint {
        txid: "ab".repeat(32).parse().unwrap(),
        vout: 1,
    };
    let close = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: other,
            ..Default::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: plan.address().unwrap().script_pubkey(),
        }],
    };
    chain.transactions.lock().unwrap().push(ChainTransaction {
        transaction: close,
        confirmations: 6,
    });
    chain.transactions.lock().unwrap()[0].confirmations = 6;
    let mut job =
        Job::load_or_begin(dir.path(), plan.clone(), vec![OutPoint::null(), other]).unwrap();
    let Progress::SweepPreview { sweep, inputs } =
        job.advance(&chain, &keys, keys.scripts()).await.unwrap()
    else {
        panic!("preview");
    };
    job.approve(&chain, sweep, inputs).await.unwrap();
    job.advance(&chain, &keys, keys.scripts()).await.unwrap();
    chain
        .transactions
        .lock()
        .unwrap()
        .last_mut()
        .unwrap()
        .confirmations = 6;
    assert!(matches!(
        job.advance(&chain, &keys, keys.scripts()).await.unwrap(),
        Progress::SelfTest
    ));
    // A long console pause must revalidate saved close txids, not rediscover
    // funding spends in the chain source's bounded recent-block window.
    chain
        .discovery_unavailable
        .store(true, std::sync::atomic::Ordering::Relaxed);
    drop(job);
    let mut job = Job::load_or_begin(dir.path(), plan, vec![OutPoint::null(), other]).unwrap();
    let report = job.finish(&chain, "tested".into()).await.unwrap();
    assert_eq!(report.closing_txids.len(), 2);
}

#[test]
fn verification_resumes_only_its_designated_new_store() {
    let (dir, _, _, plan) = fixture();
    let mut job = Job::load_or_begin(dir.path(), plan.clone(), vec![]).unwrap();
    job.begin_verification("hub".into()).unwrap();
    let id = job.verification().unwrap().store_id.clone();
    // A crash leaves only an unpublished temporary marker/journal. It must
    // neither masquerade as live state nor strand the untouched fresh store.
    std::fs::remove_file(dir.path().join("RECOVERY_STORE")).unwrap();
    std::fs::write(dir.path().join(".recover-store-interrupted"), b"partial").unwrap();
    std::fs::write(dir.path().join(".recover-interrupted"), b"{partial").unwrap();
    drop(job);
    let mut job = Job::load_or_begin(dir.path(), plan.clone(), vec![]).unwrap();
    job.begin_verification("hub".into()).unwrap();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("RECOVERY_STORE")).unwrap(),
        id
    );
    std::fs::write(
        dir.path().join("ldk_node_data.sqlite"),
        b"new verification store",
    )
    .unwrap();
    assert!(recover::ensure_normal_start(dir.path()).is_err());
    let mut resumed = Job::load_or_begin(dir.path(), plan.clone(), vec![]).unwrap();
    resumed.begin_verification("hub".into()).unwrap();
    assert_eq!(resumed.verification().unwrap().store_id, id);
    assert!(resumed.begin_verification("another hub".into()).is_err());
    std::fs::remove_file(dir.path().join("RECOVERY_STORE")).unwrap();
    assert!(Job::load_or_begin(dir.path(), plan, vec![]).is_err());
}
