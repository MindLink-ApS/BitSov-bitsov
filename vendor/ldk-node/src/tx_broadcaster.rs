// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::ops::Deref;

use bitcoin::{Transaction, Txid};
use lightning::chain::chaininterface::BroadcasterInterface;
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, MutexGuard};
use tokio::time::Instant;

use crate::logger::{log_error, LdkLogger};

const BCAST_PACKAGE_QUEUE_SIZE: usize = 50;

pub(crate) struct TransactionBroadcaster<L: Deref>
where
    L::Target: LdkLogger,
{
    queue_sender: mpsc::Sender<Vec<Transaction>>,
    queue_receiver: Mutex<mpsc::Receiver<Vec<Transaction>>>,
    logger: L,
    attempts: std::sync::Mutex<HashMap<Txid, (Instant, u64)>>,
    pending: std::sync::Mutex<HashMap<Txid, usize>>,
    in_flight: std::sync::Mutex<HashMap<Vec<Txid>, Vec<Transaction>>>,
}

impl<L: Deref> TransactionBroadcaster<L>
where
    L::Target: LdkLogger,
{
    pub(crate) fn new(logger: L) -> Self {
        let (queue_sender, queue_receiver) = mpsc::channel(BCAST_PACKAGE_QUEUE_SIZE);
        Self {
            queue_sender,
            queue_receiver: Mutex::new(queue_receiver),
            logger,
            attempts: std::sync::Mutex::new(HashMap::new()),
            pending: std::sync::Mutex::new(HashMap::new()),
            in_flight: std::sync::Mutex::new(HashMap::new()),
        }
    }

    // Save before the first await. A dropped/aborted worker leaves this package
    // available for the next worker on the same Node, even if the queue is full.
    pub(crate) fn begin_broadcast(&self, package: &[Transaction]) {
        let txids = package.iter().map(Transaction::compute_txid).collect();
        self.in_flight.lock().unwrap().insert(txids, package.to_vec());
    }
    pub(crate) fn interrupted_broadcasts(&self) -> Vec<Vec<Transaction>> {
        self.in_flight.lock().unwrap().values().cloned().collect()
    }

    pub(crate) fn broadcast_completed(&self, txids: &[Txid]) {
        self.in_flight.lock().unwrap().remove(txids);
        let mut pending = self.pending.lock().unwrap();
        for txid in txids {
            if let Some(count) = pending.get_mut(txid) {
                *count -= 1;
                if *count == 0 {
                    pending.remove(txid);
                }
            }
        }
    }

    pub(crate) async fn get_broadcast_queue(
        &self,
    ) -> MutexGuard<'_, mpsc::Receiver<Vec<Transaction>>> {
        self.queue_receiver.lock().await
    }
}

impl<L: Deref> BroadcasterInterface for TransactionBroadcaster<L>
where
    L::Target: LdkLogger,
{
    fn broadcast_transactions(&self, txs: &[&Transaction]) {
        let now = Instant::now();
        let mut attempts = self.attempts.lock().unwrap();
        let mut pending = self.pending.lock().unwrap();
        if txs
            .iter()
            .all(|tx| pending.contains_key(&tx.compute_txid()))
        {
            return;
        }
        // Bound history after transactions stop being offered by LDK. Never evict
        // a pending cooldown; expiry only makes a later broadcast more conservative.
        attempts.retain(|_, (next, _)| {
            now.saturating_duration_since(*next) < Duration::from_secs(86400)
        });
        if txs.iter().all(|tx| {
            attempts
                .get(&tx.compute_txid())
                .is_some_and(|(next, _)| now < *next)
        }) {
            return;
        }
        // Keep the whole package if it contains a new/due child: its parent may
        // be required for package relay. Repeated identical packages back off.
        let package = txs.iter().map(|&t| t.clone()).collect::<Vec<Transaction>>();
        match self.queue_sender.try_send(package) {
            Ok(()) => {
                for tx in txs {
                    *pending.entry(tx.compute_txid()).or_default() += 1;
                    let delay = attempts
                        .get(&tx.compute_txid())
                        .map_or(30, |(_, delay)| (delay * 2).min(300));
                    attempts.insert(tx.compute_txid(), (now + Duration::from_secs(delay), delay));
                }
            }
            Err(e) => log_error!(self.logger, "Failed to broadcast transactions: {}", e),
        }
    }
}

#[cfg(test)]
mod bitsov_rebroadcast_tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn repeated_pending_transaction_is_backed_off_but_not_lost() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = crate::Builder::new();
        builder.set_storage_dir_path(dir.path().to_str().unwrap().to_owned());
        let node = builder.build().unwrap();
        let broadcaster = &node.tx_broadcaster;
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let mut queue = broadcaster.get_broadcast_queue().await;
        broadcaster.broadcast_transactions(&[&tx]);
        assert!(queue.try_recv().is_ok());
        broadcaster.broadcast_completed(&[tx.compute_txid()]);
        broadcaster.broadcast_transactions(&[&tx]);
        assert!(
            queue.try_recv().is_err(),
            "duplicate must not consume backend quota"
        );
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        broadcaster.broadcast_transactions(&[&tx]);
        assert!(queue.try_recv().is_ok());
        broadcaster.broadcast_completed(&[tx.compute_txid()]);
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        broadcaster.broadcast_transactions(&[&tx]);
        assert!(queue.try_recv().is_err(), "second retry waits 60 seconds");
        tokio::time::advance(std::time::Duration::from_secs(30)).await;
        broadcaster.broadcast_transactions(&[&tx]);
        assert!(queue.try_recv().is_ok());
        broadcaster.broadcast_completed(&[tx.compute_txid()]);
    }
    #[tokio::test(start_paused = true)]
    async fn queued_transaction_does_not_accumulate_duplicates_during_long_cooldown() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = crate::Builder::new();
        builder.set_storage_dir_path(dir.path().to_str().unwrap().to_owned());
        let node = builder.build().unwrap();
        let broadcaster = &node.tx_broadcaster;
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        let mut queue = broadcaster.get_broadcast_queue().await;
        broadcaster.broadcast_transactions(&[&tx]);
        assert!(queue.try_recv().is_ok());
        for _ in 0..20 {
            tokio::time::advance(Duration::from_secs(300)).await;
            broadcaster.broadcast_transactions(&[&tx]);
            assert!(
                queue.try_recv().is_err(),
                "cooldown must not build a recovery burst"
            );
        }
        broadcaster.broadcast_completed(&[tx.compute_txid()]);
        broadcaster.broadcast_transactions(&[&tx]);
        assert!(queue.try_recv().is_ok());
    }
    #[tokio::test(start_paused = true)]
    async fn abort_preserves_dequeued_package_for_restart_without_duplicate_burst() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = crate::Builder::new();
        builder.set_storage_dir_path(dir.path().to_str().unwrap().to_owned());
        let node = builder.build().unwrap();
        let broadcaster = node.tx_broadcaster.clone();
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };
        broadcaster.broadcast_transactions(&[&tx]);
        let worker_broadcaster = broadcaster.clone();
        let worker = tokio::spawn(async move {
            let mut queue = worker_broadcaster.get_broadcast_queue().await;
            let package = queue.recv().await.unwrap();
            worker_broadcaster.begin_broadcast(&package);
            std::future::pending::<()>().await;
            worker_broadcaster.broadcast_completed(&[package[0].compute_txid()]);
        });
        tokio::task::yield_now().await;
        worker.abort();
        let _ = worker.await;
        let interrupted = broadcaster
            .interrupted_broadcasts().pop()
            .expect("aborted package must survive for restart");
        assert_eq!(interrupted, vec![tx.clone()]);
        let mut queue = broadcaster.get_broadcast_queue().await;
        tokio::time::advance(Duration::from_secs(300)).await;
        broadcaster.broadcast_transactions(&[&tx]);
        assert!(
            queue.try_recv().is_err(),
            "restarted worker owns interrupted package"
        );
        broadcaster.broadcast_completed(&[tx.compute_txid()]);
        assert!(broadcaster.interrupted_broadcasts().is_empty());
        broadcaster.broadcast_transactions(&[&tx]);
        assert!(queue.try_recv().is_ok());
    }
    #[tokio::test]
    async fn completing_one_package_retains_other_interrupted_packages() {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = crate::Builder::new();
        builder.set_storage_dir_path(dir.path().to_str().unwrap().to_owned());
        let node = builder.build().unwrap();
        let broadcaster = &node.tx_broadcaster;
        let first = Transaction { version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO, input: vec![], output: vec![] };
        let mut second = first.clone();
        second.lock_time = bitcoin::absolute::LockTime::from_consensus(1);
        let mut queue = broadcaster.get_broadcast_queue().await;
        broadcaster.broadcast_transactions(&[&first]);
        broadcaster.broadcast_transactions(&[&second]);
        broadcaster.begin_broadcast(&queue.recv().await.unwrap());
        broadcaster.begin_broadcast(&queue.recv().await.unwrap());
        assert_eq!(broadcaster.interrupted_broadcasts().len(), 2);
        broadcaster.broadcast_completed(&[second.compute_txid()]);
        assert_eq!(broadcaster.interrupted_broadcasts(), vec![vec![first.clone()]]);
        broadcaster.broadcast_transactions(&[&first]);
        assert!(queue.try_recv().is_err(), "incomplete package must remain coalesced");
    }

}
