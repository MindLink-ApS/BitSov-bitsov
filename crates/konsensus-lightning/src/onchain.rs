//! Serializes owner-initiated on-chain operations through their asynchronous outcome.

use std::{future::Future, sync::Arc, time::Duration};

use konsensus_core::traits::lightning::{ChannelOpenResult, ChannelOpenStatus, LightningError};
use tokio::sync::Mutex;

const POLL_INTERVAL: Duration = Duration::from_millis(250);
const FUNDING_TIMEOUT: Duration = Duration::from_secs(60);
const BROADCAST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
pub(crate) struct OnchainOperations {
    lock: Arc<Mutex<()>>,
}

impl OnchainOperations {
    pub(crate) fn new(lock: Arc<Mutex<()>>) -> Self {
        Self { lock }
    }

    pub(crate) async fn run<T, F>(&self, operation: F) -> Result<T, LightningError>
    where
        T: Send + 'static,
        F: Future<Output = Result<T, LightningError>> + Send + 'static,
    {
        // Cancellation while queued is harmless. Once dispatched, the worker owns
        // the lock until verification finishes even if the HTTP caller goes away.
        let guard = self.lock.clone().lock_owned().await;
        tokio::spawn(async move {
            let _guard = guard;
            let result = operation.await;
            if let Err(error) = &result {
                tracing::warn!(%error, "on-chain operation did not complete successfully");
            }
            result
        })
        .await
        .map_err(|e| LightningError::Backend(format!("on-chain operation worker failed: {e}")))?
    }
}

#[derive(Clone)]
pub(crate) struct ChainVisibility {
    pub(crate) node: Arc<ldk_node::Node>,
    pub(crate) bitcoind: Option<Arc<konsensus_chain::BitcoindProvider>>,
    pub(crate) electrum: Option<Arc<konsensus_chain::ElectrumProvider>>,
}

impl ChainVisibility {
    pub(crate) async fn tx_visible(&self, txid: String) -> Result<bool, String> {
        if let Some(rpc) = &self.bitcoind {
            rpc.tx_visible(&txid).await.map_err(|e| e.to_string())
        } else if let Some(server) = &self.electrum {
            server.tx_visible(&txid).await.map_err(|e| e.to_string())
        } else {
            let txid = txid.parse().map_err(|_| "invalid transaction id".to_owned())?;
            self.node.funding_present(txid).await.map_err(|e| e.to_string())
        }
    }
}

/// The same reconciliation runs at startup and periodically. An affirmative
/// not-found result is required; transport/index lookup errors retain ownership.
pub(crate) async fn reconcile_local_spends(
    node: &Arc<ldk_node::Node>,
    chain: &ChainVisibility,
    resume_after: &mut Option<ldk_node::bitcoin::Txid>,
) {
    reconcile_local_spends_with(node, |id| chain.tx_visible(id), resume_after).await;
}

async fn reconcile_local_spends_with<F, Fut>(
    node: &Arc<ldk_node::Node>,
    mut visible: F,
    resume_after: &mut Option<ldk_node::bitcoin::Txid>,
) where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<bool, String>>,
{
    // One total budget, including gate acquisition, bounds startup/recovery.
    // Yield the gate between rows so an owner release or urgent bump can run.
    let mut reservations = node.local_spend_reservations();
    reservations.sort_by_key(|r| r.txid);
    if let Some(last) = resume_after {
        let next = reservations.partition_point(|r| r.txid <= *last);
        reservations.rotate_left(next);
    }
    let pass = async {
        for reservation in reservations {
            let _guard = node.onchain_operation_lock().lock_owned().await;
            let txid = reservation.txid;
            // Advance before querying: one hung source lookup cannot starve
            // every later reservation across all subsequent bounded passes.
            *resume_after = Some(txid);
            match visible(txid.to_string()).await {
                Ok(visible) => {
                    if let Err(error) = node.reconcile_local_spend(txid, visible) {
                        tracing::warn!(%txid, %error, "local spend reconciliation persistence failed");
                    }
                }
                Err(_) => {
                    tracing::warn!(%txid, "local spend lookup unavailable; reservation retained")
                }
            }
        }
    };
    if tokio::time::timeout(BROADCAST_TIMEOUT, pass).await.is_err() {
        tracing::warn!(
            "local spend reconciliation budget exhausted; remaining reservations retained"
        );
    }
}

/// Caller holds the operation gate across the lookup and durable release.
/// Only the configured source's definitive not-found result permits release.
pub(crate) async fn release_local_spend_with<F, Fut>(
    node: Arc<ldk_node::Node>,
    txid: ldk_node::bitcoin::Txid,
    visible: F,
) -> Result<(), LightningError>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<bool, String>>,
{
    match tokio::time::timeout(BROADCAST_TIMEOUT, visible(txid.to_string())).await {
        Ok(Ok(false)) => {}
        Ok(Ok(true)) => return Err(LightningError::Backend(format!(
            "cannot release {txid}: transaction is visible to the chain source; reservation retained"
        ))),
        Ok(Err(_)) => return Err(LightningError::Backend(format!(
            "cannot release {txid}: chain-source lookup is inconclusive; reservation retained"
        ))),
        Err(_) => return Err(LightningError::Backend(format!(
            "cannot release {txid}: chain-source lookup timed out; reservation retained"
        ))),
    }
    tokio::task::spawn_blocking(move || node.release_local_spend(txid))
        .await
        .map_err(|e| LightningError::Backend(e.to_string()))?
        .map_err(|e| LightningError::Backend(e.to_string()))
}

pub(crate) async fn verify_broadcast<F, Fut>(
    txid: &str,
    mut visible: F,
) -> Result<(), LightningError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<bool, String>>,
{
    let result = tokio::time::timeout(BROADCAST_TIMEOUT, async {
        loop {
            if matches!(visible(txid.to_owned()).await, Ok(true)) {
                return Ok::<(), String>(());
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await;
    match result {
        Ok(Ok(())) => Ok(()),
        _ => Err(LightningError::BroadcastUnconfirmed {
            txid: txid.to_owned(),
        }),
    }
}

pub(crate) async fn finish_channel_open<F, V, Fut>(
    channel_id: String,
    mut funding_txid: F,
    visible: V,
) -> Result<ChannelOpenResult, LightningError>
where
    F: FnMut() -> Result<Option<String>, LightningError>,
    V: FnMut(String) -> Fut,
    Fut: Future<Output = Result<bool, String>>,
{
    let txid = tokio::time::timeout(FUNDING_TIMEOUT, async {
        loop {
            if let Some(txid) = funding_txid()? {
                return Ok::<_, LightningError>(txid);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }).await.map_err(|_| LightningError::Backend(format!(
        "channel {channel_id}: funding transaction unavailable after 60s; outcome uncertain; inspect channel before retrying"
    )))??;
    let status = match verify_broadcast(&txid, visible).await {
        Ok(()) => ChannelOpenStatus::Opening,
        Err(_) => ChannelOpenStatus::PendingVisibility,
    };
    Ok(ChannelOpenResult {
            funding_fee: None,
        channel_id,
        funding_txid: Some(txid),
        status,
    })
}

/// Cooperative close negotiates asynchronously; hold the shared gate until LDK
/// removes the channel, or report uncertainty on timeout. This never force-closes.
pub(crate) async fn finish_channel_close(
    channel_id: &str,
    mut still_open: impl FnMut() -> bool,
) -> Result<Option<String>, LightningError> {
    tokio::time::timeout(FUNDING_TIMEOUT, async {
        while still_open() {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| {
        LightningError::Backend(format!(
            "channel {channel_id}: close not completed after 60s; inspect channel before retrying"
        ))
    })?;
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::Notify;

    #[tokio::test]
    async fn gate_remains_owned_after_caller_cancellation() {
        let gate = Arc::new(OnchainOperations::default());
        let entered = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let first = {
            let (gate, entered, finish) = (gate.clone(), entered.clone(), finish.clone());
            tokio::spawn(async move {
                gate.run(async move {
                    entered.notify_one();
                    finish.notified().await;
                    Ok(())
                })
                .await
            })
        };
        entered.notified().await;
        first.abort();
        let _ = first.await;
        let second_entered = Arc::new(AtomicBool::new(false));
        let second = {
            let (gate, flag) = (gate.clone(), second_entered.clone());
            tokio::spawn(async move {
                gate.run(async move {
                    flag.store(true, Ordering::SeqCst);
                    Ok(())
                })
                .await
            })
        };
        // Let the second caller try to enter; the cancelled first still owns the gate.
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(!second_entered.load(Ordering::SeqCst));
        finish.notify_one();
        second.await.unwrap().unwrap();
        assert!(second_entered.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn separate_nodes_are_not_serialized_together() {
        let first = OnchainOperations::default();
        let second = OnchainOperations::default();
        let entered = Arc::new(Notify::new());
        let finish = Arc::new(Notify::new());
        let pending = {
            let (entered, finish) = (entered.clone(), finish.clone());
            tokio::spawn(async move {
                first
                    .run(async move {
                        entered.notify_one();
                        finish.notified().await;
                        Ok(())
                    })
                    .await
            })
        };
        entered.notified().await;
        second.run(async { Ok(()) }).await.unwrap();
        finish.notify_one();
        pending.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn slow_or_unavailable_visibility_returns_pending_with_channel_and_txid() {
        for visible in [Ok(false), Err("lookup unavailable".to_string())] {
            let result = finish_channel_open(
                "UserChannelId(7)".into(),
                || Ok(Some("funding-tx".into())),
                |_| std::future::ready(visible.clone()),
            )
            .await
            .unwrap();
            assert_eq!(result.channel_id, "UserChannelId(7)");
            assert_eq!(result.funding_txid.as_deref(), Some("funding-tx"));
            assert_eq!(result.status, ChannelOpenStatus::PendingVisibility);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn lookup_error_is_retried_until_visible() {
        let mut attempts = 0;
        verify_broadcast("funding-tx", |_| {
            attempts += 1;
            std::future::ready(if attempts == 1 {
                Err("temporary lookup failure".into())
            } else {
                Ok(true)
            })
        })
        .await
        .unwrap();
        assert_eq!(attempts, 2);
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_funding_handshake_is_bounded() {
        let error = finish_channel_open(
            "UserChannelId(9)".into(),
            || Ok(None),
            |_| std::future::ready(Ok(true)),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("UserChannelId(9)"));
    }

    #[tokio::test(start_paused = true)]
    async fn normal_single_open_waits_for_funding_and_acceptance() {
        let mut funding_polls = 0;
        let mut visibility_polls = 0;
        let result = finish_channel_open(
            "UserChannelId(7)".into(),
            || {
                funding_polls += 1;
                Ok((funding_polls > 1).then(|| "funding-tx".into()))
            },
            |txid| {
                assert_eq!(txid, "funding-tx");
                visibility_polls += 1;
                std::future::ready(Ok(visibility_polls > 1))
            },
        )
        .await
        .unwrap();
        assert_eq!(result.channel_id, "UserChannelId(7)");
        assert_eq!(result.status, ChannelOpenStatus::Opening);
        assert_eq!(funding_polls, 2);
        assert_eq!(visibility_polls, 2);
    }
    fn restarted_reservations() -> (tempfile::TempDir, Arc<ldk_node::Node>) {
        use bitcoin::{
            absolute::LockTime, transaction::Version, Amount, ScriptBuf, Transaction, TxIn, TxOut,
        };
        let dir = tempfile::tempdir().unwrap();
        let mut builder = ldk_node::Builder::new();
        builder.set_network(bitcoin::Network::Regtest);
        builder.set_entropy_seed_bytes([73; 64]);
        builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
        drop(builder.build_with_fs_store().unwrap());
        let rows = dir.path().join("fs_store/bitsov_local_spends");
        std::fs::create_dir_all(&rows).unwrap();
        for amount in [100, 200, 300] {
            let tx = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn::default()],
                output: vec![TxOut {
                    value: Amount::from_sat(amount),
                    script_pubkey: ScriptBuf::new(),
                }],
            };
            let mut row = vec![2, 0, 0];
            row.extend(1_u64.to_le_bytes());
            row.extend(0_u64.to_le_bytes());
            row.extend(bitcoin::consensus::serialize(&tx));
            std::fs::write(rows.join(tx.compute_txid().to_string()), row).unwrap();
        }
        std::fs::write(rows.join("malformed"), [9]).unwrap();
        (dir, Arc::new(builder.build_with_fs_store().unwrap()))
    }

    #[tokio::test(start_paused = true)]
    async fn owner_release_requires_definitive_absence() {
        for (visibility, refused) in [
            (Ok(true), true),
            (Err("lookup failed".into()), true),
            (Ok(false), false),
        ] {
            let (dir, node) = restarted_reservations();
            let txid = node.local_spend_reservations()[0].txid;
            let gate = OnchainOperations::new(node.onchain_operation_lock());
            let worker_node = node.clone();
            let result = gate
                .run(async move {
                    release_local_spend_with(worker_node, txid, |id| {
                        assert_eq!(id, txid.to_string());
                        std::future::ready(visibility)
                    })
                    .await
                })
                .await;
            assert_eq!(result.is_err(), refused);
            if let Err(error) = result {
                assert!(error.to_string().contains("reservation retained"));
            }
            assert_eq!(
                node.local_spend_reservations().len(),
                if refused { 3 } else { 2 }
            );
            assert_eq!(
                dir.path()
                    .join("fs_store/bitsov_local_spends")
                    .join(txid.to_string())
                    .exists(),
                refused
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn owner_release_retains_reservation_on_lookup_timeout() {
        let (_dir, node) = restarted_reservations();
        let txid = node.local_spend_reservations()[0].txid;
        let gate = OnchainOperations::new(node.onchain_operation_lock());
        let worker_node = node.clone();
        let result = gate
            .run(async move {
                release_local_spend_with(worker_node, txid, |_| {
                    std::future::pending::<Result<bool, String>>()
                })
                .await
            })
            .await;
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("reservation retained"));
        assert_eq!(node.local_spend_reservations().len(), 3);
        assert!(node.onchain_operation_lock().try_lock().is_ok());
    }

    #[tokio::test]
    async fn owner_release_without_chain_source_is_inconclusive() {
        use konsensus_core::traits::lightning::LightningProvider;
        let (_dir, node) = restarted_reservations();
        let provider = crate::ldk::LdkProvider::from_node(node.clone());
        let txid = node.local_spend_reservations()[0].txid;
        assert!(provider
            .release_local_spend(&txid.to_string())
            .await
            .is_err());
        assert_eq!(node.local_spend_reservations().len(), 3);
    }

    #[tokio::test]
    async fn reconciliation_without_chain_source_keeps_reservations() {
        let (_dir, node) = restarted_reservations();
        let chain = ChainVisibility { node: node.clone(), bitcoind: None, electrum: None };
        let mut cursor = None;
        reconcile_local_spends(&node, &chain, &mut cursor).await;
        assert_eq!(node.local_spend_reservations().len(), 3);
        assert!(node.local_spend_reservations().iter().all(|row| row.last_seen_at.is_none()));
    }

    #[tokio::test(start_paused = true)]
    async fn startup_reconciliation_retains_on_lookup_error_then_releases_absent_rows() {
        let (_dir, node) = restarted_reservations();
        let provider = crate::ldk::LdkProvider::from_node(node.clone());
        use konsensus_core::traits::lightning::LightningProvider;
        assert_eq!(provider.local_spend_diagnostics().unreadable_rows, 1);
        let mut cursor = None;
        reconcile_local_spends_with(
            &node,
            |_| std::future::ready(Err("lookup failed".into())),
            &mut cursor,
        )
        .await;
        assert_eq!(node.local_spend_reservations().len(), 3);
        reconcile_local_spends_with(&node, |_| std::future::ready(Ok(false)), &mut cursor).await;
        assert!(node.local_spend_reservations().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn reconciliation_has_total_budget_releases_gate_and_resumes_after_hung_row() {
        let (_dir, node) = restarted_reservations();
        let mut cursor = None;
        let started = tokio::time::Instant::now();
        reconcile_local_spends_with(
            &node,
            |_| std::future::pending::<Result<bool, String>>(),
            &mut cursor,
        )
        .await;
        assert_eq!(started.elapsed(), Duration::from_secs(10));
        assert!(node.onchain_operation_lock().try_lock().is_ok());
        assert_eq!(node.local_spend_reservations().len(), 3);
        let hung = cursor.unwrap();
        let mut first_lookup = None;
        reconcile_local_spends_with(
            &node,
            |id| {
                first_lookup.get_or_insert(id);
                std::future::ready(Ok(false))
            },
            &mut cursor,
        )
        .await;
        assert_ne!(first_lookup.unwrap(), hung.to_string());
        assert!(node.local_spend_reservations().is_empty());
    }
}
