//! Serializes owner-initiated on-chain operations through their asynchronous outcome.

use std::{future::Future, sync::Arc, time::Duration};

use konsensus_core::traits::lightning::LightningError;
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
    pub(crate) esplora_url: String,
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
            crate::ldk::esplora_tx_visible(&self.esplora_url, &txid).await
        }
    }
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
            if visible(txid.to_owned()).await? {
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
) -> Result<String, LightningError>
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
    verify_broadcast(&txid, visible).await.map_err(|_| LightningError::Backend(format!(
        "channel {channel_id}: funding transaction {txid} not verified by chain source within 10s; may propagate later; inspect channel before retrying"
    )))?;
    Ok(channel_id)
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
    async fn failed_broadcast_surfaces_error_with_channel_and_txid() {
        for visible in [Ok(false), Err("broadcast rejected".to_string())] {
            let error = finish_channel_open(
                "UserChannelId(7)".into(),
                || Ok(Some("funding-tx".into())),
                |_| std::future::ready(visible.clone()),
            )
            .await
            .unwrap_err();
            let message = error.to_string();
            assert!(message.contains("UserChannelId(7)"));
            assert!(message.contains("funding-tx"));
            assert!(
                !matches!(error, LightningError::PaymentNotDispatched(_)),
                "an unseen transaction may propagate later; do not authorize retry/refund"
            );
        }
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
        assert_eq!(result, "UserChannelId(7)");
        assert_eq!(funding_polls, 2);
        assert_eq!(visibility_polls, 2);
    }
}
