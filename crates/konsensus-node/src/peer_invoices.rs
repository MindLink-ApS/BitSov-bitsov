//! Bounds on service invoices issued to an already admitted peer.
//!
//! Each request can create a wallet invoice. This book caps how often one peer
//! may ask, how many unpaid invoices that peer may hold, and how many the node
//! holds in total. Expired rows stop counting and are deleted from the wallet
//! when the backend still has them as pending.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use konsensus_core::traits::lightning::{LightningProvider, PaymentStatus};
use konsensus_core::types::NodeId;

use konsensus_api::invoice_refusal::INVOICE_LIMITED;

/// Unpaid service invoices one peer may have open at once.
pub(crate) const PEER_OUTSTANDING_CAP: usize = 4;
/// Unpaid service invoices the node holds for every peer together.
pub(crate) const GLOBAL_OUTSTANDING_CAP: usize = 32;
/// Requests one peer may make during [`RATE_WINDOW`], including attempts that
/// fail after the cap check.
pub(crate) const PEER_RATE_BURST: usize = 8;
pub(crate) const RATE_WINDOW: Duration = Duration::from_secs(10);
/// Wallet expiry for a service invoice requested by a peer.
pub(crate) const INVOICE_EXPIRY_SECS: u32 = 120;
pub(crate) const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) const RECONCILIATION_BUDGET: Duration = Duration::from_secs(2);
const STATUS_BUDGET: Duration = Duration::from_millis(100);

const MAX_RATE_PEERS: usize = 1024;
const MAX_FORGET_RETRIES: usize = 64;

/// Why a service invoice was refused. Callers answer with [`INVOICE_LIMITED`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvoiceLimit {
    Recovering,
    Rate,
    PeerOutstanding,
    Global,
}

impl InvoiceLimit {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Recovering | Self::Rate | Self::PeerOutstanding | Self::Global => INVOICE_LIMITED,
        }
    }
}

#[derive(Debug, Clone)]
struct Row {
    /// `None` is an invoice restored after restart. It counts toward the global
    /// cap only; this process no longer knows which peer asked for it.
    peer: Option<NodeId>,
    hash: String,
    expires_at: u64,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PeerInvoiceBook {
    reconciled: bool,
    rates: HashMap<NodeId, (Instant, usize)>,
    rows: Vec<Row>,
}

impl PeerInvoiceBook {
    /// Reserve a slot for a new service invoice. Expired rows do not count.
    /// The rate counter advances only when both outstanding caps allow it.
    pub(crate) fn try_issue(
        &mut self,
        peer: &NodeId,
        now: Instant,
        now_unix: u64,
    ) -> Result<(), InvoiceLimit> {
        if !self.reconciled {
            return Err(InvoiceLimit::Recovering);
        }
        self.rates
            .retain(|_, (start, _)| now.saturating_duration_since(*start) < RATE_WINDOW);
        if self.outstanding(Some(peer), now_unix) >= PEER_OUTSTANDING_CAP {
            return Err(InvoiceLimit::PeerOutstanding);
        }
        if self.outstanding(None, now_unix) >= GLOBAL_OUTSTANDING_CAP {
            return Err(InvoiceLimit::Global);
        }
        if !self.rates.contains_key(peer) && self.rates.len() >= MAX_RATE_PEERS {
            return Err(InvoiceLimit::Rate);
        }
        let entry = self.rates.entry(*peer).or_insert((now, 0));
        if now.saturating_duration_since(entry.0) >= RATE_WINDOW {
            *entry = (now, 0);
        }
        if entry.1 >= PEER_RATE_BURST {
            return Err(InvoiceLimit::Rate);
        }
        entry.1 += 1;
        Ok(())
    }

    /// Undo a rate-slot reservation when invoice creation never commits a row.
    pub(crate) fn rollback_issue(&mut self, peer: &NodeId) {
        if let Some((_, count)) = self.rates.get_mut(peer) {
            if *count > 0 {
                *count -= 1;
            }
        }
    }

    pub(crate) fn commit(&mut self, peer: NodeId, hash: String, expires_at: u64) {
        self.rows.push(Row {
            peer: Some(peer),
            hash,
            expires_at,
        });
    }

    /// Count a still-pending invoice whose peer was not kept across restart.
    pub(crate) fn note_unattributed(&mut self, hash: String, expires_at: u64) {
        if self.rows.iter().any(|row| row.hash == hash) {
            return;
        }
        self.rows.push(Row {
            peer: None,
            hash,
            expires_at,
        });
    }

    /// Merge only observations from the snapshot. Requests may have committed
    /// new invoices while the worker was running; never replace the live book.
    pub(crate) fn apply_reconciliation(&mut self, result: Reconciliation) {
        self.reconciled = result.ready;
        self.rows.retain(|row| !result.removed.contains(&row.hash));
        for (hash, expires_at) in result.imported {
            if !result.removed.contains(&hash) {
                self.note_unattributed(hash, expires_at);
            }
        }
    }

    fn outstanding(&self, peer: Option<&NodeId>, now_unix: u64) -> usize {
        self.rows
            .iter()
            .filter(|row| now_unix < row.expires_at && peer.is_none_or(|id| row.peer == Some(*id)))
            .count()
    }
}

pub(crate) struct Reconciliation {
    ready: bool,
    imported: Vec<(String, u64)>,
    removed: HashSet<String>,
}

/// One worker owns a snapshot, with a total budget independent of backend RPC
/// timeouts. Cancellation conservatively retains any unconfirmed cap slots.
/// Run in a separate task so no wallet lookup can stall control dispatch.
pub(crate) async fn reconcile(
    mut snapshot: PeerInvoiceBook,
    lightning: Arc<dyn LightningProvider>,
    now_unix: u64,
) -> Reconciliation {
    let mut result = Reconciliation {
        ready: false,
        imported: Vec::new(),
        removed: HashSet::new(),
    };
    let mut before: HashSet<_> = snapshot.rows.iter().map(|row| row.hash.clone()).collect();
    let _ = tokio::time::timeout(RECONCILIATION_BUDGET, async {
        if !lightning.receive_invoice_capable().await {
            return;
        }
        let Ok(imported) = lightning.pending_invoice_expiries().await else {
            return;
        };
        for (hash, expires_at) in &imported {
            before.insert(hash.clone());
            snapshot.note_unattributed(hash.clone(), *expires_at);
        }
        result.imported = imported;
        result.ready = true;
        purge_expired_peer_invoices(&mut snapshot, lightning.as_ref(), now_unix).await;
    })
    .await;
    // Completed observations survive cancellation of the remaining sweep.
    let after: HashSet<_> = snapshot.rows.iter().map(|row| row.hash.clone()).collect();
    result.removed = before.difference(&after).cloned().collect();
    result
}

/// Drop rows that are no longer an unpaid hold, then delete expired pending
/// invoices from the wallet. A settled invoice stays in the wallet and stops
/// occupying a cap slot. A failed delete stays in the book, without counting
/// toward the caps, until a later sweep.
pub(crate) async fn purge_expired_peer_invoices(
    book: &mut PeerInvoiceBook,
    lightning: &dyn LightningProvider,
    now_unix: u64,
) {
    release_closed_rows(book, lightning).await;
    let expired: Vec<String> = book
        .rows
        .iter()
        .filter(|row| now_unix >= row.expires_at)
        .map(|row| row.hash.clone())
        .collect();
    use futures::{stream, StreamExt};
    let mut deletions = stream::iter(expired.into_iter().map(|hash| async move {
        let forgotten = matches!(
            tokio::time::timeout(STATUS_BUDGET, lightning.forget_pending_invoice(&hash)).await,
            Ok(Ok(true))
        );
        (hash, forgotten)
    }))
    .buffer_unordered(8);
    while let Some((hash, forgotten)) = deletions.next().await {
        if forgotten {
            book.rows.retain(|row| row.hash != hash);
        }
    }
    let mut failed = 0usize;
    book.rows.retain(|row| {
        if now_unix < row.expires_at {
            return true;
        }
        failed += 1;
        failed <= MAX_FORGET_RETRIES
    });
    if let Ok(Err(error)) = tokio::time::timeout(
        STATUS_BUDGET,
        lightning.purge_expired_pending_invoices(now_unix),
    )
    .await
    {
        tracing::debug!(error = %error, "backend invoice expiry sweep failed");
    }
}

/// A paid, failed, or missing invoice no longer holds a cap slot. The wallet
/// record is left untouched here; expiry deletion is a separate step.
async fn release_closed_rows(book: &mut PeerInvoiceBook, lightning: &dyn LightningProvider) {
    use futures::{stream, StreamExt};
    let mut statuses = stream::iter(
        book.rows
            .iter()
            .map(|row| row.hash.clone())
            .collect::<Vec<_>>()
            .into_iter()
            .map(|hash| async move {
                let status =
                    tokio::time::timeout(STATUS_BUDGET, lightning.get_payment_status(&hash)).await;
                let closed = matches!(
                    status,
                    Ok(Ok(ref details))
                        if matches!(
                            details.status,
                            PaymentStatus::Settled | PaymentStatus::Failed | PaymentStatus::Expired
                        )
                );
                (hash, closed)
            }),
    )
    .buffer_unordered(8);
    while let Some((hash, is_closed)) = statuses.next().await {
        if is_closed {
            let _ =
                tokio::time::timeout(STATUS_BUDGET, lightning.forget_pending_invoice(&hash)).await;
            book.rows.retain(|row| row.hash != hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; 32])
    }

    #[test]
    fn outstanding_caps_hold_for_one_peer_and_for_the_node() {
        let mut book = PeerInvoiceBook {
            reconciled: true,
            ..Default::default()
        };
        let now = Instant::now();
        let unix = 1_000_000u64;
        let first = peer(1);
        for i in 0..PEER_OUTSTANDING_CAP {
            book.try_issue(&first, now, unix).unwrap();
            book.commit(first, format!("a{i}"), unix + 120);
        }
        assert_eq!(
            book.try_issue(&first, now, unix),
            Err(InvoiceLimit::PeerOutstanding)
        );
        let mut issued = PEER_OUTSTANDING_CAP;
        let mut id = 2u8;
        while issued < GLOBAL_OUTSTANDING_CAP {
            let peer = peer(id);
            book.try_issue(&peer, now, unix).unwrap();
            book.commit(peer, format!("g{id}"), unix + 120);
            issued += 1;
            id = id.checked_add(1).unwrap();
        }
        assert_eq!(
            book.try_issue(&peer(id), now, unix),
            Err(InvoiceLimit::Global)
        );
        assert_eq!(book.outstanding(None, unix), GLOBAL_OUTSTANDING_CAP);
    }

    #[test]
    fn rate_limit_holds_after_outstanding_rows_expire() {
        let mut book = PeerInvoiceBook {
            reconciled: true,
            ..Default::default()
        };
        let peer = peer(7);
        let now = Instant::now();
        let unix = 5_000u64;
        for i in 0..PEER_RATE_BURST {
            book.try_issue(&peer, now, unix).unwrap();
            book.commit(peer, format!("r{i}"), unix);
        }
        assert_eq!(book.outstanding(Some(&peer), unix), 0);
        assert_eq!(book.try_issue(&peer, now, unix), Err(InvoiceLimit::Rate));
        assert_eq!(book.try_issue(&peer, now + RATE_WINDOW, unix), Ok(()));
    }

    #[test]
    fn expired_rows_stop_counting_before_they_are_forgotten() {
        let mut book = PeerInvoiceBook {
            reconciled: true,
            ..Default::default()
        };
        let peer = peer(3);
        let now = Instant::now();
        book.try_issue(&peer, now, 10).unwrap();
        book.commit(peer, "old".into(), 20);
        assert_eq!(book.outstanding(Some(&peer), 20), 0);
        assert!(book.try_issue(&peer, now, 20).is_ok());
    }

    #[test]
    fn failed_rate_reservation_rolls_back_on_refusal_paths() {
        let mut book = PeerInvoiceBook {
            reconciled: true,
            ..Default::default()
        };
        let peer = peer(4);
        let now = Instant::now();
        let unix = 1_000u64;
        for _ in 0..PEER_RATE_BURST {
            book.try_issue(&peer, now, unix).unwrap();
            book.rollback_issue(&peer);
        }
        assert!(book.try_issue(&peer, now, unix).is_ok());
    }

    #[tokio::test]
    async fn inconclusive_status_lookup_keeps_the_cap_slot() {
        use async_trait::async_trait;
        use konsensus_core::traits::lightning::{
            Invoice, LightningError, LightningProvider as LP, PaymentDetails,
        };
        use std::sync::Arc;

        struct LookupFails {
            inventory: Vec<(String, u64)>,
        }

        #[async_trait]
        impl LP for LookupFails {
            async fn receive_invoice_capable(&self) -> bool {
                true
            }
            async fn pending_invoice_expiries(&self) -> Result<Vec<(String, u64)>, LightningError> {
                Ok(self.inventory.clone())
            }
            async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
                Err(LightningError::PaymentNotFound("missing".into()))
            }
            async fn create_invoice(
                &self,
                _: u64,
                _: &str,
                _: u32,
            ) -> Result<Invoice, LightningError> {
                Err(LightningError::Backend("unused".into()))
            }
            async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
                Err(LightningError::Backend("unused".into()))
            }
            async fn get_balance_msat(&self) -> Result<u64, LightningError> {
                Ok(0)
            }
            async fn is_available(&self) -> bool {
                true
            }
        }

        let lightning: Arc<dyn LightningProvider> = Arc::new(LookupFails {
            inventory: vec![("aa".repeat(32), 9_999)],
        });
        let mut book = PeerInvoiceBook::default();
        for n in 0..PEER_OUTSTANDING_CAP {
            book.commit(peer(1), format!("open-{n}"), 120);
        }
        let result = reconcile(book.clone(), lightning, 0).await;
        book.apply_reconciliation(result);
        assert!(book.try_issue(&peer(2), Instant::now(), 0).is_ok());
        assert_eq!(
            book.rows
                .iter()
                .filter(|row| row.peer == Some(peer(1)))
                .count(),
            PEER_OUTSTANDING_CAP
        );
        assert_eq!(
            book.try_issue(&peer(1), Instant::now(), 0),
            Err(InvoiceLimit::PeerOutstanding)
        );
    }

    #[tokio::test]
    async fn receive_capable_backends_reconcile_without_money_ready() {
        use async_trait::async_trait;
        use konsensus_core::traits::lightning::{
            Invoice, LightningError, LightningProvider as LP, PaymentDetails,
        };
        use std::sync::Arc;

        struct ReceiveOnly;

        #[async_trait]
        impl LP for ReceiveOnly {
            async fn money_ready(&self) -> bool {
                false
            }
            async fn receive_invoice_capable(&self) -> bool {
                true
            }
            async fn pending_invoice_expiries(&self) -> Result<Vec<(String, u64)>, LightningError> {
                Ok(vec![("bb".repeat(32), 500)])
            }
            async fn create_invoice(
                &self,
                _: u64,
                _: &str,
                _: u32,
            ) -> Result<Invoice, LightningError> {
                Err(LightningError::Backend("unused".into()))
            }
            async fn pay_invoice(&self, _: &str) -> Result<PaymentDetails, LightningError> {
                Err(LightningError::Backend("unused".into()))
            }
            async fn get_payment_status(&self, _: &str) -> Result<PaymentDetails, LightningError> {
                Err(LightningError::PaymentNotFound("missing".into()))
            }
            async fn get_balance_msat(&self) -> Result<u64, LightningError> {
                Ok(0)
            }
            async fn is_available(&self) -> bool {
                true
            }
        }

        let lightning: Arc<dyn LightningProvider> = Arc::new(ReceiveOnly);
        let mut book = PeerInvoiceBook::default();
        let result = reconcile(book.clone(), lightning, 0).await;
        book.apply_reconciliation(result);
        assert!(book.try_issue(&peer(1), Instant::now(), 0).is_ok());
        assert!(book.rows.iter().any(|row| row.hash == "bb".repeat(32)));
    }

    #[test]
    fn restored_invoices_count_toward_the_global_cap_only() {
        let mut book = PeerInvoiceBook {
            reconciled: true,
            ..Default::default()
        };
        let now = Instant::now();
        let unix = 1_000u64;
        for i in 0..GLOBAL_OUTSTANDING_CAP {
            book.note_unattributed(format!("u{i}"), unix + 120);
        }
        let peer = peer(9);
        assert_eq!(book.outstanding(Some(&peer), unix), 0);
        assert_eq!(book.try_issue(&peer, now, unix), Err(InvoiceLimit::Global));
    }
}
