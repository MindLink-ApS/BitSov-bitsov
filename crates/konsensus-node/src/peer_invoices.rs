//! Bounds on service invoices issued to an already admitted peer.
//!
//! Each request can create a wallet invoice. This book caps how often one peer
//! may ask, how many unpaid invoices that peer may hold, and how many the node
//! holds in total. Expired rows stop counting and are deleted from the wallet
//! when the backend still has them as pending.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use konsensus_core::traits::lightning::{LightningError, LightningProvider, PaymentStatus};
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

const MAX_RATE_PEERS: usize = 1024;
const MAX_FORGET_RETRIES: usize = 64;

/// Why a service invoice was refused. Callers answer with [`INVOICE_LIMITED`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvoiceLimit {
    Rate,
    PeerOutstanding,
    Global,
}

impl InvoiceLimit {
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::Rate | Self::PeerOutstanding | Self::Global => INVOICE_LIMITED,
        }
    }
}

#[derive(Debug)]
struct Row {
    /// `None` is an invoice restored after restart. It counts toward the global
    /// cap only; this process no longer knows which peer asked for it.
    peer: Option<NodeId>,
    hash: String,
    expires_at: u64,
}

#[derive(Debug, Default)]
pub(crate) struct PeerInvoiceBook {
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

    pub(crate) fn commit(&mut self, peer: NodeId, hash: String, expires_at: u64) {
        self.rows.push(Row {
            peer: Some(peer),
            hash,
            expires_at,
        });
    }

    /// Count a still-pending invoice whose peer was not kept across restart.
    pub(crate) fn note_unattributed(&mut self, hash: String, expires_at: u64) {
        self.rows.push(Row {
            peer: None,
            hash,
            expires_at,
        });
    }

    fn outstanding(&self, peer: Option<&NodeId>, now_unix: u64) -> usize {
        self.rows
            .iter()
            .filter(|row| now_unix < row.expires_at && peer.is_none_or(|id| row.peer == Some(*id)))
            .count()
    }
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
    let mut forgotten = HashSet::new();
    for hash in &expired {
        match lightning.forget_pending_invoice(hash).await {
            Ok(_) => {
                forgotten.insert(hash.clone());
            }
            Err(error) => {
                tracing::debug!(error = %error, "pending invoice cleanup will retry");
            }
        }
    }
    let mut failed = 0usize;
    book.rows.retain(|row| {
        if now_unix < row.expires_at {
            return true;
        }
        if forgotten.contains(&row.hash) {
            return false;
        }
        failed += 1;
        failed <= MAX_FORGET_RETRIES
    });
    if let Err(error) = lightning.purge_expired_pending_invoices(now_unix).await {
        tracing::debug!(error = %error, "backend invoice expiry sweep failed");
    }
}

/// A paid, failed, or missing invoice no longer holds a cap slot. The wallet
/// record is left untouched here; expiry deletion is a separate step.
async fn release_closed_rows(book: &mut PeerInvoiceBook, lightning: &dyn LightningProvider) {
    let mut closed = HashSet::new();
    for row in &book.rows {
        match lightning.get_payment_status(&row.hash).await {
            Ok(details) => match details.status {
                PaymentStatus::Pending | PaymentStatus::InFlight => {}
                PaymentStatus::Settled | PaymentStatus::Failed | PaymentStatus::Expired => {
                    closed.insert(row.hash.clone());
                }
            },
            Err(LightningError::PaymentNotFound(_)) => {
                closed.insert(row.hash.clone());
            }
            Err(error) => {
                tracing::debug!(error = %error, "leaving peer invoice slot until status is known");
            }
        }
    }
    if !closed.is_empty() {
        book.rows.retain(|row| !closed.contains(&row.hash));
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
        let mut book = PeerInvoiceBook::default();
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
        let mut book = PeerInvoiceBook::default();
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
        let mut book = PeerInvoiceBook::default();
        let peer = peer(3);
        let now = Instant::now();
        book.try_issue(&peer, now, 10).unwrap();
        book.commit(peer, "old".into(), 20);
        assert_eq!(book.outstanding(Some(&peer), 20), 0);
        assert!(book.try_issue(&peer, now, 20).is_ok());
    }

    #[test]
    fn restored_invoices_count_toward_the_global_cap_only() {
        let mut book = PeerInvoiceBook::default();
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
