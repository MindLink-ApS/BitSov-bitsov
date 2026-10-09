fn unchecked(budget: &mut GrantBudget, service: &PairingService) {
    // ruleid: bitsov-grant-reserve-must-check-breakers
    budget.reserve(&charges);
    // ruleid: bitsov-grant-breakers-owner-reset-only
    service.reset_grant_breakers(client, grant);
    // ruleid: bitsov-grant-breakers-owner-reset-only
    budget.reset_breakers();
    // ruleid: bitsov-grant-breakers-owner-reset-only
    budget.breaker_state = Default::default();
    // ruleid: bitsov-grant-breakers-owner-reset-only
    budget.breakers = limits;
    // ruleid: bitsov-grant-breaker-refusal-must-propagate
    let _ = budget.reserve_at(&charges, now);
    // ruleid: bitsov-grant-breaker-refusal-must-propagate
    budget.reserve_at(&charges, now).ok();
    // ok: bitsov-grant-breaker-refusal-must-propagate
    budget.reserve_at(&charges, now)?;
}
