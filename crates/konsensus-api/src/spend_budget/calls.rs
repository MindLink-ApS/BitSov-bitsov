//! Durable accounting for one call and its recoverable block payments.
use super::*;
/// Maintenance never pays more than this for a closing signal, with no fee.
pub(crate) const CALL_CLOSING_MSAT: u64 = 1_000;
// Missing on pre-cap holds: preserve their original four-hour reservation.
fn legacy_max_call_minutes() -> u16 { 240 }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CallSpendTerms {
    pub peer: String,
    pub call_id: String,
    pub per_block_msat: u64,
    pub per_block_fee_msat: u64,
    #[serde(default = "legacy_max_call_minutes")]
    pub max_call_minutes: u16,
    pub reserved_msat: u64,
    /// The zero per-block fee was pinned for a direct channel to the payee:
    /// each block is paid only while that channel still carries it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub direct: bool,
}

impl CallSpendTerms {
    /// Keep the closing signal in the same budget/liquidity reservation as
    /// the blocks. Owner calls do not create this grant reservation.
    pub(crate) fn with_closing_signal(mut self) -> Result<Self, BudgetRefusal> {
        self.reserved_msat = self.reserved_msat.checked_add(CALL_CLOSING_MSAT)
            .ok_or_else(|| BudgetRefusal::Unpriced("call reservation overflow".into()))?;
        Ok(self)
    }

    pub fn new(peer: &str, call_id: &str, price: u64, fee: u64, max_call_minutes: u16) -> Result<Self, BudgetRefusal> {
        if !(1..=240).contains(&max_call_minutes) {
            return Err(BudgetRefusal::Unpriced("call duration must be between 1 and 240 minutes".into()));
        }
        let reserved_msat = price
            .checked_add(fee)
            .and_then(|amount| amount.checked_mul(u64::from(max_call_minutes)))
            .ok_or_else(|| BudgetRefusal::Unpriced("call reservation overflow".into()))?;
        Ok(Self {
            peer: peer.into(),
            call_id: call_id.into(),
            per_block_msat: price,
            per_block_fee_msat: fee,
            max_call_minutes,
            reserved_msat,
            direct: false,
        })
    }

    /// Mark the zero per-block fee as pinned for a direct channel.
    pub fn over_direct_channel(mut self, direct: bool) -> Self {
        self.direct = direct;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CallSpend {
    pub terms: CallSpendTerms,
    pub spent_msat: u64,
    pub released_msat: u64,
    pub closed: bool,
    pub(crate) outcome_recorded: bool,
    #[serde(default)]
    pub(crate) payment_failed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) finished_at: Option<i64>,
    /// Child reservation ID -> block sequence (u32::MAX for closure); each
    /// child also has an outbox link.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) draws: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub(crate) paid_sequences: BTreeSet<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallSpendStatus {
    pub max_call_minutes: u16,
    pub reserved_msat: u64,
    pub spent_msat: u64,
    /// Still held, including unresolved payments. Released funds are excluded.
    pub remaining_msat: u64,
    pub per_block_msat: u64,
    pub per_block_fee_msat: u64,
    pub released_msat: u64,
    pub closed: bool,
    /// Blocks are paid only over the direct channel their zero fee relies on.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub direct: bool,
}

impl CallSpend {
    pub(crate) fn new(terms: CallSpendTerms) -> Self {
        Self {
            terms,
            spent_msat: 0,
            released_msat: 0,
            closed: false,
            outcome_recorded: false,
            payment_failed: false,
            finished_at: None,
            draws: BTreeMap::new(),
            paid_sequences: BTreeSet::new(),
        }
    }

    pub fn status(&self) -> CallSpendStatus {
        CallSpendStatus {
            max_call_minutes: self.terms.max_call_minutes,
            reserved_msat: self.terms.reserved_msat,
            spent_msat: self.spent_msat,
            remaining_msat: self
                .terms
                .reserved_msat
                .saturating_sub(self.spent_msat)
                .saturating_sub(self.released_msat),
            per_block_msat: self.terms.per_block_msat,
            per_block_fee_msat: self.terms.per_block_fee_msat,
            released_msat: self.released_msat,
            closed: self.closed,
            direct: self.terms.direct,
        }
    }
}

impl GrantBudget {
    /// The most one call payment to `peer` may carry under this grant now,
    /// msat: the signed per-payment value, or on a relation grant the peer's
    /// envelope per-act maximum (none: nothing).
    pub(crate) fn call_payment_limit(&self, peer: &str) -> u64 {
        if self.recipients_only {
            self.per_act_max_by_recipient.get(peer).copied().unwrap_or(0)
        } else {
            self.per_call_max_msat
        }
    }

    /// Every draw from a hold (a block, its retry or its recovery) is bounded
    /// by the grant as it is now: the hold's pinned per-block ceiling must fit
    /// [`Self::call_payment_limit`]. A hold persisted under an earlier rule
    /// can exceed it; such a hold never pays again.
    pub(crate) fn check_call_hold(&self, terms: &CallSpendTerms) -> Result<(), BudgetRefusal> {
        let max_msat = self.call_payment_limit(&terms.peer);
        if terms.per_block_msat.saturating_add(terms.per_block_fee_msat) > max_msat {
            return Err(BudgetRefusal::PerCall { max_msat });
        }
        Ok(())
    }

    /// Close each open hold that fails [`Self::check_call_hold`], releasing
    /// what it has not paid. With `only`, just that call (peer, call id).
    /// Returns the refusal for the last hold closed, if any.
    pub(crate) fn close_holds_over_limit(&mut self, only: Option<(&str, &str)>) -> Option<BudgetRefusal> {
        let over: Vec<(String, BudgetRefusal)> = self
            .call_reservations
            .iter()
            .filter(|(_, call)| !call.closed)
            .filter(|(_, call)| only.is_none_or(|(peer, id)| call.terms.peer == peer && call.terms.call_id == id))
            .filter_map(|(id, call)| self.check_call_hold(&call.terms).err().map(|refusal| (id.clone(), refusal)))
            .collect();
        let mut refused = None;
        for (id, refusal) in over {
            self.close_call(&id);
            refused = Some(refusal);
        }
        refused
    }

    /// Keep only small, recent finished receipts. Open holds and unresolved
    /// children are never evicted, even under count pressure.
    pub(crate) fn prune_call_tombstones(&mut self, now: i64) {
        const RETAIN_SECS: i64 = 24 * 60 * 60;
        const MAX_TOMBSTONES: usize = 256;
        let mut finished = Vec::new();
        for (id, call) in &mut self.call_reservations {
            if call.closed && call.draws.is_empty() && call.outcome_recorded {
                // Upgrade receipts written before compaction existed.
                call.paid_sequences.clear();
                let at = *call.finished_at.get_or_insert(now);
                finished.push((at, id.clone()));
            }
        }
        finished.sort();
        let excess = finished.len().saturating_sub(MAX_TOMBSTONES);
        for (index, (at, id)) in finished.into_iter().enumerate() {
            if index < excess || now.saturating_sub(at) >= RETAIN_SECS {
                self.call_reservations.remove(&id);
            }
        }
    }

    /// A child was consumed by try_resolve_spend. Return unused funds to an
    /// open hold; after close, return them to the grant. Never count a block
    /// as another breaker payment/outcome.
    pub(crate) fn resolve_call_draw(
        &mut self,
        id: &str,
        peer: &str,
        reserved: u64,
        actual: u64,
        payment_failed: bool,
    ) -> bool {
        let Some(parent) = self
            .call_reservations
            .iter()
            .find(|(_, call)| call.terms.peer == peer && call.draws.contains_key(id))
            .map(|(id, _)| id.clone())
        else {
            return false;
        };
        let call = self
            .call_reservations
            .get_mut(&parent)
            .expect("located call");
        let seq = call.draws.remove(id).expect("located draw");
        call.payment_failed |= payment_failed && actual == 0;
        if actual > 0 {
            call.paid_sequences.insert(seq);
        }
        call.spent_msat = call.spent_msat.saturating_add(actual);
        let closed = call.closed;
        let unused = reserved.saturating_sub(actual);
        if closed {
            call.released_msat = call.released_msat.saturating_add(unused);
            self.resolve(peer, reserved, actual);
        } else {
            // Never recreate a missing parent: keep its liability held if the
            // ledger is inconsistent, rather than making funds spendable twice.
            if let Some(remaining) = self.pending.get_mut(&parent).and_then(|r| r.get_mut(peer)) {
                *remaining = remaining.saturating_add(unused);
            }
            if actual > reserved {
                self.resolve(peer, 0, actual - reserved);
            }
        }
        self.record_call_outcome(&parent);
        true
    }

    pub(crate) fn close_call(&mut self, id: &str) {
        let Some(call) = self.call_reservations.get_mut(id) else {
            return;
        };
        if call.closed {
            return;
        }
        call.closed = true;
        let peer = call.terms.peer.clone();
        let unused = self
            .pending
            .remove(id)
            .and_then(|r| r.get(&peer).copied())
            .unwrap_or(0);
        call.released_msat = call.released_msat.saturating_add(unused);
        self.resolve(&peer, unused, 0);
        self.record_call_outcome(id);
    }

    fn record_call_outcome(&mut self, id: &str) {
        let call = self.call_reservations.get_mut(id).expect("located call");
        if call.closed && call.draws.is_empty() && !call.outcome_recorded {
            call.outcome_recorded = true;
            call.finished_at = Some(chrono::Utc::now().timestamp());
            call.paid_sequences.clear();
            let (reserved, spent, failed) = (call.terms.reserved_msat, call.spent_msat, call.payment_failed);
            // A declined/unanswered call did not fail a payment.
            if spent > 0 || failed {
                self.record_outcome(reserved, spent, chrono::Utc::now().timestamp());
            }
            self.prune_call_tombstones(chrono::Utc::now().timestamp());
        }
    }
}
