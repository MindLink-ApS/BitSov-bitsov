//! Broadcast eligibility uses only explicit funding evidence, never lookup failure.
use bitcoin::{OutPoint, Transaction, Txid};
use std::collections::HashSet;
use std::future::Future;

pub(super) async fn eligible_package<F, Fut>(
    package: Vec<Transaction>,
    closed_funding: &HashSet<OutPoint>,
    mut present: F,
) -> Vec<Transaction>
where
    F: FnMut(Txid) -> Fut,
    Fut: Future<Output = Result<bool, crate::Error>>,
{
    let supplied: HashSet<_> = package.iter().map(Transaction::compute_txid).collect();
    let mut absent = HashSet::new();
    let mut checked = HashSet::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    'funding: for tx in &package {
        for input in &tx.input {
            if tokio::time::Instant::now() >= deadline {
                break 'funding;
            }
            let funding = input.previous_output;
            if closed_funding.contains(&funding)
                && !supplied.contains(&funding.txid)
                && checked.insert(funding)
                && matches!(
                    tokio::time::timeout_at(deadline, present(funding.txid)).await,
                    Ok(Ok(false))
                )
            {
                absent.insert(funding);
            }
        }
    }
    let mut suppressed = HashSet::new();
    // Packages need not be topologically sorted. Propagate suppression to all
    // descendants, including fee-bump children, without touching LDK state.
    loop {
        let before = suppressed.len();
        for tx in &package {
            if tx.input.iter().any(|input| {
                absent.contains(&input.previous_output)
                    || suppressed.contains(&input.previous_output.txid)
            }) {
                suppressed.insert(tx.compute_txid());
            }
        }
        if suppressed.len() == before {
            break;
        }
    }
    package
        .into_iter()
        .filter(|tx| !suppressed.contains(&tx.compute_txid()))
        .collect()
}

#[cfg(test)]
mod bitsov_ghost_tests {
    use super::*;
    use bitcoin::hashes::Hash;
    fn spending(outpoint: OutPoint) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: outpoint,
                ..Default::default()
            }],
            output: vec![],
        }
    }
    #[tokio::test]
    async fn only_proven_absent_closed_funding_suppresses_commitment_and_children() {
        let funding = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        };
        let commitment = spending(funding);
        let child = spending(OutPoint {
            txid: commitment.compute_txid(),
            vout: 0,
        });
        let closed = HashSet::from([funding]);
        for evidence in [
            Ok(false),
            Ok(true),
            Err(crate::Error::ChainRateLimited),
            Err(crate::Error::TxSyncFailed),
            Err(crate::Error::TxSyncTimeout),
        ] {
            let package = vec![commitment.clone(), child.clone()];
            let result = eligible_package(package, &closed, |_| async { evidence }).await;
            assert_eq!(result.len(), if evidence == Ok(false) { 0 } else { 2 });
        }
        let result = eligible_package(vec![commitment], &HashSet::new(), |_| async {
            panic!("ordinary/open funding must not be queried")
        })
        .await;
        assert_eq!(result.len(), 1);
    }
    #[tokio::test]
    async fn funding_in_same_package_and_later_funding_presence_preserve_recovery() {
        let parent = spending(OutPoint::null());
        let funding = OutPoint {
            txid: parent.compute_txid(),
            vout: 0,
        };
        let commitment = spending(funding);
        let closed = HashSet::from([funding]);
        assert_eq!(
            eligible_package(vec![parent, commitment.clone()], &closed, |_| async {
                panic!("parent supplied locally")
            })
            .await
            .len(),
            2
        );
        assert!(
            eligible_package(vec![commitment.clone()], &closed, |_| async { Ok(false) })
                .await
                .is_empty()
        );
        assert_eq!(
            eligible_package(vec![commitment], &closed, |_| async { Ok(true) })
                .await
                .len(),
            1
        );
    }
    #[tokio::test(start_paused = true)]
    async fn later_inconclusive_lookup_does_not_erase_proven_absence() {
        let absent = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        };
        let unknown = OutPoint {
            txid: Txid::from_byte_array([2; 32]),
            vout: 0,
        };
        let result = eligible_package(
            vec![spending(absent), spending(unknown)],
            &HashSet::from([absent, unknown]),
            |txid| async move {
                if txid == absent.txid {
                    Ok(false)
                } else {
                    std::future::pending().await
                }
            },
        )
        .await;
        assert_eq!(result, vec![spending(unknown)]);
    }
}
