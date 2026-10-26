//! Durable accounting for one call and its recoverable block payments.
use super::*;
use konsensus_core::payloads::call::{CALL_BLOCK_MS, MAX_CALL_MS};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CallSpendTerms {
    pub peer: String,
    pub call_id: String,
    pub per_block_msat: u64,
    pub per_block_fee_msat: u64,
    pub reserved_msat: u64,
}

impl CallSpendTerms {
    pub fn new(peer: &str, call_id: &str, price: u64, fee: u64) -> Result<Self, BudgetRefusal> {
        let reserved_msat = price
            .checked_add(fee)
            .and_then(|amount| amount.checked_mul(MAX_CALL_MS / CALL_BLOCK_MS))
            .ok_or_else(|| BudgetRefusal::Unpriced("call reservation overflow".into()))?;
        Ok(Self {
            peer: peer.into(),
            call_id: call_id.into(),
            per_block_msat: price,
            per_block_fee_msat: fee,
            reserved_msat,
        })
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
    /// Child reservation ID -> block sequence; each child also has an outbox link.
    pub(crate) draws: BTreeMap<String, u32>,
    pub(crate) paid_sequences: BTreeSet<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CallSpendStatus {
    pub reserved_msat: u64,
    pub spent_msat: u64,
    /// Still held, including unresolved payments. Released funds are excluded.
    pub remaining_msat: u64,
    pub per_block_msat: u64,
    pub per_block_fee_msat: u64,
    pub released_msat: u64,
    pub closed: bool,
}

impl CallSpend {
    pub(crate) fn new(terms: CallSpendTerms) -> Self {
        Self {
            terms,
            spent_msat: 0,
            released_msat: 0,
            closed: false,
            outcome_recorded: false,
            draws: BTreeMap::new(),
            paid_sequences: BTreeSet::new(),
        }
    }

    pub fn status(&self) -> CallSpendStatus {
        CallSpendStatus {
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
        }
    }
}

impl GrantBudget {
    /// A child was consumed by try_resolve_spend. Return unused funds to an
    /// open hold; after close, return them to the grant. Never count a block
    /// as another breaker payment/outcome.
    pub(crate) fn resolve_call_draw(
        &mut self,
        id: &str,
        peer: &str,
        reserved: u64,
        actual: u64,
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
            *self
                .pending
                .entry(parent.clone())
                .or_default()
                .entry(peer.into())
                .or_default() += unused;
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
            let (reserved, spent) = (call.terms.reserved_msat, call.spent_msat);
            self.record_outcome(reserved, spent, chrono::Utc::now().timestamp());
        }
    }
}
