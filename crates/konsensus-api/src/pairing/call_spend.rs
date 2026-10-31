//! Call holds share the pairing ledger's mutex, atomic publication and grant checks.
use super::*;
use crate::spend_budget::{CallSpendStatus, CallSpendTerms, OperationReservationLink};

impl PairingService {
    pub(crate) fn prune_call_spend(&self, now: i64) -> Result<(), PairingError> {
        let mut inner = self.lock();
        let before = inner.file.clone();
        for budget in inner.file.grants.iter_mut().filter_map(|g| g.budget.as_mut()) {
            budget.prune_call_tombstones(now);
        }
        if inner.file.grants.iter().zip(&before.grants).any(|(a, b)| a.budget != b.budget) {
            if let Err(error) = self.persist(&mut inner.file) {
                inner.file = before;
                return Err(error);
            }
        }
        Ok(())
    }

    fn call_grant_index(
        &self,
        inner: &Inner,
        client: &str,
        epoch: u64,
    ) -> Result<usize, BudgetRefusal> {
        let now = chrono::Utc::now().timestamp();
        if !inner.file.clients.iter().any(|c| {
            c.client_id == client
                && c.epoch == epoch
                && c.identity_fingerprint == inner.identity_fingerprint
        }) {
            return Err(BudgetRefusal::NoGrant);
        }
        inner
            .file
            .grants
            .iter()
            .position(|g| {
                g.client_id == client
                    && g.epoch == epoch
                    && g.identity_fingerprint == inner.identity_fingerprint
                    && g.is_live(now)
                    && g.scopes.contains(&Scope::Spend)
                    && self.permits_spend_grant(g)
            })
            .ok_or(BudgetRefusal::NoGrant)
    }

    /// The capacity is an observed outbound channel bound. Subtract all holds
    /// under the same lock as the grant debit so concurrent calls cannot both
    /// promise the same funds. This is deliberately conservative across routes.
    pub(crate) fn reserve_call_spend(
        &self,
        client: &str,
        epoch: u64,
        terms: CallSpendTerms,
        capacity_msat: u64,
    ) -> Result<Reservation, BudgetRefusal> {
        self.prune_call_spend(chrono::Utc::now().timestamp())
            .map_err(|e| BudgetRefusal::Ledger(e.to_string()))?;
        let mut inner = self.lock();
        let idx = self.call_grant_index(&inner, client, epoch)?;
        for (grant_idx, grant) in inner.file.grants.iter().enumerate() {
            if let Some(budget) = &grant.budget {
                for (id, call) in &budget.call_reservations {
                    if call.terms.peer == terms.peer && call.terms.call_id == terms.call_id {
                        if grant_idx != idx || call.closed || call.terms != terms {
                            return Err(BudgetRefusal::Unpriced(
                                "call already reserved with different authority or terms".into(),
                            ));
                        }
                        return Ok(call_reference(grant, id, &call.terms));
                    }
                }
            }
        }
        let held = inner
            .file
            .grants
            .iter()
            .filter_map(|g| g.budget.as_ref())
            .flat_map(|b| b.call_reservations.values())
            .fold(0u64, |sum, call| {
                sum.saturating_add(call.status().remaining_msat)
            });
        let available_msat = capacity_msat.saturating_sub(held);
        if terms.reserved_msat > available_msat {
            return Err(BudgetRefusal::CallLiquidity {
                required_msat: terms.reserved_msat,
                available_msat,
            });
        }
        if inner.file.grants[idx]
            .budget
            .as_ref()
            .is_some_and(|b| b.call_reservations.values().filter(|c| !c.closed || !c.draws.is_empty()).count() >= 1024)
        {
            return Err(BudgetRefusal::Ledger(
                "call reservation ledger is full; ask the owner for a new grant".into(),
            ));
        }
        self.reserve_spend_locked(
            &mut inner,
            client,
            epoch,
            vec![Charge {
                recipient: terms.peer.clone(),
                amount_msat: terms.reserved_msat,
            }],
            ReservationAuthority {
                call: Some(terms),
                ..Default::default()
            },
            || chrono::Utc::now().timestamp(),
        )
    }

    /// Reserve a call offer under the call's existing hold: its per-payment
    /// bound is the hold's pinned per-block ceiling (`GrantBudget::reserve_call_at`).
    pub(crate) fn reserve_call_offer_spend(
        &self,
        client: &str,
        epoch: u64,
        charges: Vec<Charge>,
        call_id: &str,
        link: OperationReservationLink,
    ) -> Result<Reservation, BudgetRefusal> {
        let mut inner = self.lock();
        self.reserve_spend_locked(
            &mut inner,
            client,
            epoch,
            charges,
            ReservationAuthority {
                operation: Some(link),
                call_offer: Some(call_id),
                ..Default::default()
            },
            || chrono::Utc::now().timestamp(),
        )
    }

    /// Transfer a bounded part of a hold to an ordinary recoverable operation.
    /// No reserve_at here: neither budget nor breakers are charged again.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn draw_call_spend(
        &self,
        client: &str,
        epoch: u64,
        peer: &str,
        call_id: &str,
        seq: u32,
        price: u64,
        fee: u64,
        link: OperationReservationLink,
    ) -> Result<Reservation, BudgetRefusal> {
        let mut inner = self.lock();
        let idx = self.call_grant_index(&inner, client, epoch)?;
        let before = inner.file.clone();
        let grant = &mut inner.file.grants[idx];
        let budget = grant.budget.as_mut().ok_or(BudgetRefusal::NoGrant)?;
        if budget.is_paused() {
            return Err(BudgetRefusal::GrantPaused);
        }
        if !budget.envelopes_live(
            std::iter::once(&peer.to_owned()),
            chrono::Utc::now().timestamp(),
        ) {
            return Err(BudgetRefusal::NoGrant);
        }
        let (parent, call) = budget
            .call_reservations
            .iter_mut()
            .find(|(_, call)| call.terms.peer == peer && call.terms.call_id == call_id)
            .ok_or_else(|| BudgetRefusal::Unpriced("call has no spend reservation".into()))?;
        if call.closed
            || seq >= u32::from(call.terms.max_call_minutes)
        {
            return Err(BudgetRefusal::Unpriced(
                "call reservation is closed or duration cap reached".into(),
            ));
        }
        if price > call.terms.per_block_msat || fee > call.terms.per_block_fee_msat {
            return Err(BudgetRefusal::CallPriceChanged);
        }
        if call.paid_sequences.contains(&seq) || call.draws.values().any(|s| *s == seq) {
            return Err(BudgetRefusal::DuplicatePayment);
        }
        let amount = price
            .checked_add(fee)
            .ok_or(BudgetRefusal::CallPriceChanged)?;
        let remaining = budget
            .pending
            .get_mut(parent)
            .and_then(|r| r.get_mut(peer))
            .ok_or_else(|| BudgetRefusal::Unpriced("call reservation is not available".into()))?;
        if amount > *remaining {
            return Err(BudgetRefusal::Total {
                remaining_msat: *remaining,
            });
        }
        let id = uuid::Uuid::new_v4().to_string();
        *remaining -= amount;
        call.draws.insert(id.clone(), seq);
        budget
            .pending
            .insert(id.clone(), BTreeMap::from([(peer.into(), amount)]));
        budget.operation_links.insert(id.clone(), link);
        let reservation = Reservation {
            id,
            client_id: client.into(),
            op_id: grant.op_id.clone(),
            charges: vec![Charge {
                recipient: peer.into(),
                amount_msat: amount,
            }],
        };
        if let Err(error) = self.persist(&mut inner.file) {
            inner.file = before;
            return Err(BudgetRefusal::Ledger(error.to_string()));
        }
        Ok(reservation)
    }

    pub(crate) fn close_call_spend(&self, reservation: &Reservation) -> Result<(), PairingError> {
        let mut inner = self.lock();
        let before = inner.file.clone();
        let Some(budget) = inner
            .file
            .grants
            .iter_mut()
            .find(|g| g.op_id == reservation.op_id && g.client_id == reservation.client_id)
            .and_then(|g| g.budget.as_mut())
        else {
            return Ok(());
        };
        if budget
            .call_reservations
            .get(&reservation.id)
            .is_none_or(|call| call.closed)
        {
            return Ok(());
        }
        budget.close_call(&reservation.id);
        if let Err(error) = self.persist(&mut inner.file) {
            inner.file = before;
            return Err(error);
        }
        Ok(())
    }

    /// Reconciliation references only. No method here restores spend authority.
    pub(crate) fn call_spend_holds(&self) -> Vec<(Reservation, CallSpendTerms)> {
        let inner = self.lock();
        inner
            .file
            .grants
            .iter()
            .flat_map(|grant| {
                grant.budget.iter().flat_map(move |budget| {
                    budget
                        .call_reservations
                        .iter()
                        .filter(|(_, call)| !call.closed)
                        .map(move |(id, call)| {
                            (call_reference(grant, id, &call.terms), call.terms.clone())
                        })
                })
            })
            .collect()
    }

    pub fn call_spend_status(&self, peer: &str, call_id: &str) -> Option<CallSpendStatus> {
        self.lock()
            .file
            .grants
            .iter()
            .filter_map(|g| g.budget.as_ref())
            .flat_map(|b| b.call_reservations.values())
            .find(|call| call.terms.peer == peer && call.terms.call_id == call_id)
            .map(|call| call.status())
    }

    pub(crate) fn owns_call_spend(&self, client: &str, peer: &str, call_id: &str) -> bool {
        self.lock()
            .file
            .grants
            .iter()
            .filter(|g| g.client_id == client)
            .filter_map(|g| g.budget.as_ref())
            .flat_map(|b| b.call_reservations.values())
            .any(|call| call.terms.peer == peer && call.terms.call_id == call_id)
    }
}

fn call_reference(grant: &SpendGrant, id: &str, terms: &CallSpendTerms) -> Reservation {
    Reservation {
        id: id.into(),
        client_id: grant.client_id.clone(),
        op_id: grant.op_id.clone(),
        charges: vec![Charge {
            recipient: terms.peer.clone(),
            amount_msat: terms.reserved_msat,
        }],
    }
}
