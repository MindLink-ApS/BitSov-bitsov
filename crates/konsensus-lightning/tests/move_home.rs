use bitcoin::{absolute, transaction, Amount, Transaction, TxOut};
use konsensus_lightning::move_home::*;
use std::collections::BTreeSet;

const DEST: &str = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";

#[derive(Default)]
struct Fake {
    snapshot: Snapshot,
    closes: std::cell::RefCell<Vec<(String, bool)>>,
    sent: Vec<Sweep>,
    confirmations: u32,
}
impl Backend for Fake {
    fn snapshot(&self) -> Result<Snapshot> {
        Ok(self.snapshot.clone())
    }
    fn close(&self, channel: &Channel, force: bool) -> Result<()> {
        self.closes.borrow_mut().push((channel.id.clone(), force));
        Ok(())
    }
    fn prepare_sweep(&self, plan: &Plan) -> Result<Sweep> {
        let address = plan.address()?;
        let tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default()],
            output: vec![TxOut {
                value: Amount::from_sat(9000),
                script_pubkey: address.script_pubkey(),
            }],
        };
        Ok(Sweep {
            transaction: bitcoin::consensus::encode::serialize_hex(&tx),
            fee_sats: 1000,
        })
    }
    fn broadcast(&mut self, sweep: &Sweep, _: &Plan) -> Result<()> {
        self.sent.push(sweep.clone());
        Ok(())
    }
    fn confirmations(&self, _: &Sweep) -> Result<u32> {
        Ok(self.confirmations)
    }
}
fn plan() -> Plan {
    Plan::new("node".into(), "regtest", DEST, 2).unwrap()
}

#[test]
fn invalid_network_and_fee_policy_rejected() {
    assert!(Plan::new("n".into(), "bitcoin", DEST, 2).is_err());
    assert!(Plan::new("n".into(), "regtest", DEST, 0).is_err());
    assert!(Plan::new("n".into(), "regtest", DEST, 10001).is_err());
}
#[test]
fn restart_replays_same_transaction_and_never_redirects() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(JOURNAL_FILE);
    let mut job = Job::begin(&path, plan()).unwrap();
    let mut backend = Fake::default();
    backend.snapshot.onchain_sats = 10000;
    let Progress::SweepPreview(sweep) = job.advance(&mut backend).unwrap() else {
        panic!()
    };
    job.approve_sweep(&sweep, &backend).unwrap();
    drop(job); // Crash before broadcast.
    let mut job = Job::load(&path, &plan()).unwrap().unwrap();
    assert!(matches!(
        job.advance(&mut backend).unwrap(),
        Progress::Confirming { .. }
    ));
    assert_eq!(backend.sent[0], sweep);
    assert!(matches!(
        job.advance(&mut backend).unwrap(),
        Progress::Confirming { .. }
    ));
    assert_eq!(backend.sent[1], sweep);
    backend.confirmations = 6;
    backend.snapshot.onchain_sats = 0;
    assert!(matches!(
        job.advance(&mut backend).unwrap(),
        Progress::Complete
    ));
    assert_eq!(backend.sent.len(), 2);
    let mut other = plan();
    other.node_id = "other".into();
    assert!(Job::load(&path, &other).is_err());
}
#[test]
fn pending_claims_and_reserves_prevent_sweep() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = Job::begin(&tmp.path().join(JOURNAL_FILE), plan()).unwrap();
    for snapshot in [
        Snapshot {
            lightning_claims: 1,
            ..Default::default()
        },
        Snapshot {
            pending_sweeps: 1,
            ..Default::default()
        },
        Snapshot {
            pending_monitor_events: 1,
            ..Default::default()
        },
        Snapshot {
            anchor_reserve_sats: 25000,
            ..Default::default()
        },
        Snapshot {
            unresolved_local_spends: 1,
            ..Default::default()
        },
        Snapshot {
            unreadable_local_spends: 1,
            ..Default::default()
        },
    ] {
        let mut backend = Fake {
            snapshot,
            ..Default::default()
        };
        assert!(matches!(
            job.advance(&mut backend).unwrap(),
            Progress::Waiting { .. }
        ));
        assert!(backend.sent.is_empty());
    }
}
#[test]
fn force_requires_previous_cooperative_attempt_and_disconnected_named_channel() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = Job::begin(&tmp.path().join(JOURNAL_FILE), plan()).unwrap();
    let channel = Channel {
        id: "1".into(),
        peer: "p".into(),
        connected: false,
    };
    let mut backend = Fake::default();
    backend.snapshot.channels.push(channel);
    let selected = BTreeSet::from(["1".to_owned()]);
    assert!(job.approve_force(&selected, &backend).is_err());
    job.advance(&mut backend).unwrap();
    backend.snapshot.channels[0].connected = true;
    assert!(job.approve_force(&selected, &backend).is_err());
    backend.snapshot.channels[0].connected = false;
    assert!(job
        .approve_force(&BTreeSet::from(["unknown".into()]), &backend)
        .is_err());
    job.approve_force(&selected, &backend).unwrap();
    job.advance(&mut backend).unwrap();
    assert_eq!(
        *backend.closes.borrow(),
        vec![("1".into(), false), ("1".into(), true)]
    );
}
#[test]
fn corrupt_journal_never_becomes_fresh_job() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(JOURNAL_FILE);
    std::fs::write(&path, b"{").unwrap();
    assert!(Job::load(&path, &plan()).is_err());
    assert!(Job::begin(&path, plan()).is_err());
}

#[test]
fn destination_and_network_are_immutable_after_consent() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join(JOURNAL_FILE);
    Job::begin(&path, plan()).unwrap();
    for changed in [
        Plan {
            destination: "n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi".into(),
            ..plan()
        },
        Plan {
            network: "testnet".into(),
            ..plan()
        },
        Plan {
            fee_rate_sat_vb: 3,
            ..plan()
        },
    ] {
        assert!(Job::load(&path, &changed).is_err());
    }
}
#[test]
fn changed_sweep_or_extra_output_cannot_be_approved() {
    let tmp = tempfile::tempdir().unwrap();
    let mut job = Job::begin(&tmp.path().join(JOURNAL_FILE), plan()).unwrap();
    let backend = Fake::default();
    let sweep = backend.prepare_sweep(&plan()).unwrap();
    let mut changed = sweep.clone();
    changed.fee_sats += 1;
    assert!(job.approve_sweep(&changed, &backend).is_err());
    let mut tx = sweep.tx().unwrap();
    tx.output.push(tx.output[0].clone());
    changed.transaction = bitcoin::consensus::encode::serialize_hex(&tx);
    assert!(job.approve_sweep(&changed, &backend).is_err());
    let redirect = Plan {
        destination: "n2eMqTT929pb1RDNuqEnxdaLau1rxy3efi".into(),
        ..plan()
    };
    assert!(sweep.validate(&redirect).is_err());
}
#[test]
fn failed_journal_write_never_broadcasts_and_poisoned_job_requires_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("job");
    std::fs::create_dir(&path).unwrap();
    let mut job = Job::begin(&path.join(JOURNAL_FILE), plan()).unwrap();
    let mut backend = Fake::default();
    let sweep = backend.prepare_sweep(&plan()).unwrap();
    std::fs::remove_dir_all(&path).unwrap();
    assert!(job.approve_sweep(&sweep, &backend).is_err());
    assert!(job.advance(&mut backend).is_err());
    assert!(backend.sent.is_empty());
}
#[test]
fn normal_startup_refuses_even_malformed_migration_journal() {
    let tmp = tempfile::tempdir().unwrap();
    konsensus_lightning::ldk::ensure_no_move_home(tmp.path()).unwrap();
    std::fs::write(tmp.path().join(JOURNAL_FILE), b"corrupt").unwrap();
    assert!(konsensus_lightning::ldk::ensure_no_move_home(tmp.path()).is_err());
}
