//! Budget-scoped, short-lived spend grants (G1).
//!
//! # Why a grant carries a budget and a clock, not just a scope
//!
//! A grant that says only "this client may spend for 30 days" is a durable
//! admission object: something that can be seized, sold or administered, and
//! whose worth grows with the wallet behind it. Doctrine says there is no such
//! object. So a spend grant is now a **metered allowance**:
//!
//! - an absolute expiry the owner chose, never more than
//!   [`MAX_SPEND_GRANT_TTL_SECS`] (24 hours) after it was written;
//! - a total budget in millisatoshis;
//! - optional per-recipient budgets;
//! - a per-call maximum.
//!
//! The node debits the budget **before** it creates or pays any invoice, under
//! the same mutex that guards the pairing store, so two concurrent calls can
//! never both spend the last sats. A refusal is `budget_exceeded` and nothing
//! was dispatched.
//!
//! # Reserve, then resolve (the #80 rule)
//!
//! A debit is a reservation of the full amount the call may pay. It resolves
//! only when the outcome is known:
//!
//! - **settled** — the reservation shrinks (or grows) to the amount the
//!   provider reported;
//! - **refused before dispatch, or confirmed failed** — released;
//! - **unknown** (transport loss, in-flight at timeout, a crash in between) —
//!   kept. The tally can over-count, never under-count.
//!
//! # Persistence without extension
//!
//! Budget numbers live in the pairing store so a restart cannot reset the
//! tally. The expiry is absolute Unix time, so a restart cannot extend it
//! either, and an expired grant is removed on every write and by a periodic
//! sweep rather than lingering on disk.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Capability advertised on `/api/v1/status` once this node meters grants.
pub const CAPABILITY: &str = "spend_budget_grant_v1";

/// `GET /api/v1/status` advertises this when a paired client can pay a first
/// contact through a one-time first-contact grant (see [`FirstContactGrant`]).
pub const FIRST_CONTACT_CAPABILITY: &str = "first_contact_grant_v1";

/// How long the owner's one-time first-contact confirmation stays usable.
/// Long enough to send right after confirming, short enough that an
/// unused confirmation does not linger as standing authority.
pub const FIRST_CONTACT_GRANT_TTL_SECS: i64 = 120;

/// Largest first contact (admission + first message) a grant may cover:
/// F1's aggregate safety ceiling for first contact, 100 sats.
pub const FIRST_CONTACT_MAX_MSAT: u64 = 100_000;

/// The owner's one-time OK to pay a first contact to exactly one recipient,
/// for at most `max_total_msat` (admission plus the first message).
///
/// First contact is never paid from a budget on its own: every new contact
/// needs one of these, issued only while the client holds a live budget grant
/// and only within that budget. It is single-use, expires after
/// [`FIRST_CONTACT_GRANT_TTL_SECS`] (or with the budget grant, if sooner),
/// lives in memory only and is never persisted, so a restart drops it.
/// Paying it still debits the budget grant, once, for what actually settled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FirstContactGrant {
    /// Canonical recipient key (lowercase hex node id).
    pub recipient: String,
    /// Admission plus first message, msat.
    pub max_total_msat: u64,
    /// Absolute expiry, unix seconds.
    pub expires_at: i64,
}

/// Longest a spend grant may live: 24 hours. Also the default.
pub const MAX_SPEND_GRANT_TTL_SECS: i64 = 24 * 3600;

/// Shortest a spend grant may live. Below a minute the owner's command would
/// race the grant's own expiry.
pub const MIN_SPEND_GRANT_TTL_SECS: i64 = 60;

/// Sanity ceiling on a budget: 1 BTC, the same bound keysend applies.
pub const MAX_GRANT_BUDGET_MSAT: u64 = 100_000_000_000;

/// Most per-recipient budgets one grant may carry.
pub const MAX_RECIPIENT_BUDGETS: usize = 256;

/// What the owner approves: the numbers that bound one budget window.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantTerms {
    /// Explicit authority for LSP deductions, charged to this SAME budget.
    /// Ordinary message grants never imply liquidity-purchase authority.
    #[serde(default)]
    pub allow_liquidity_fees: bool,
    /// Total the client may spend inside the window, in millisatoshis.
    pub budget_msat: u64,
    /// Most one API call may reserve, in millisatoshis. A room message is one
    /// call, so this bounds the whole fan-out, not each member.
    pub per_call_max_msat: u64,
    /// Optional per-recipient budgets, keyed by lowercase hex: a node id for
    /// messages and files, a Lightning pubkey for pay and keysend. A recipient
    /// without an entry is bounded by the total only.
    #[serde(default)]
    pub per_recipient_msat: BTreeMap<String, u64>,
    /// Lifetime in seconds, counted from the moment the owner grants it.
    pub ttl_secs: i64,
}

impl GrantTerms {
    /// A budget for the default (and maximum) window: 24 hours, per-call max
    /// equal to the whole budget, no per-recipient budgets.
    pub fn new(budget_msat: u64) -> Self {
        Self {
            allow_liquidity_fees: false,
            budget_msat,
            per_call_max_msat: budget_msat,
            per_recipient_msat: BTreeMap::new(),
            ttl_secs: MAX_SPEND_GRANT_TTL_SECS,
        }
    }

    /// Narrow the window.
    pub fn for_secs(mut self, ttl_secs: i64) -> Self {
        self.ttl_secs = ttl_secs;
        self
    }

    /// Narrow the per-call maximum.
    pub fn per_call(mut self, max_msat: u64) -> Self {
        self.per_call_max_msat = max_msat;
        self
    }

    /// Add a per-recipient budget.
    pub fn recipient(mut self, key: &str, budget_msat: u64) -> Self {
        self.per_recipient_msat.insert(key.to_string(), budget_msat);
        self
    }

    /// Check every bound and canonicalise recipient keys. A term the node
    /// cannot enforce as written is refused, never silently widened.
    pub fn normalized(self) -> Result<Self, String> {
        if self.budget_msat == 0 {
            return Err("the budget must be greater than zero".into());
        }
        if self.budget_msat > MAX_GRANT_BUDGET_MSAT {
            return Err(format!(
                "the budget exceeds the {MAX_GRANT_BUDGET_MSAT} msat ceiling"
            ));
        }
        if !(MIN_SPEND_GRANT_TTL_SECS..=MAX_SPEND_GRANT_TTL_SECS).contains(&self.ttl_secs) {
            return Err(format!(
                "a spend grant lasts between {MIN_SPEND_GRANT_TTL_SECS} s and \
                 {MAX_SPEND_GRANT_TTL_SECS} s (24 h)"
            ));
        }
        if self.per_call_max_msat == 0 || self.per_call_max_msat > self.budget_msat {
            return Err("the per-call maximum must be between 1 msat and the budget".into());
        }
        if self.per_recipient_msat.len() > MAX_RECIPIENT_BUDGETS {
            return Err(format!(
                "at most {MAX_RECIPIENT_BUDGETS} per-recipient budgets"
            ));
        }
        let mut per_recipient = BTreeMap::new();
        for (key, cap) in self.per_recipient_msat {
            let key = canonical_recipient(&key)
                .ok_or_else(|| format!("recipient {key:?} is not a node id or Lightning pubkey"))?;
            if cap == 0 || cap > self.budget_msat {
                return Err(format!(
                    "the budget for {key} must be between 1 msat and the total budget"
                ));
            }
            if per_recipient.insert(key.clone(), cap).is_some() {
                return Err(format!("recipient {key} is listed twice"));
            }
        }
        Ok(Self {
            per_recipient_msat: per_recipient,
            ..self
        })
    }
}

/// A recipient key as the ledger stores it: lowercase hex of a 32-byte node id
/// or a 33-byte compressed Lightning pubkey.
pub fn canonical_recipient(key: &str) -> Option<String> {
    let key = key.trim().to_ascii_lowercase();
    let ok = matches!(key.len(), 64 | 66) && key.bytes().all(|b| b.is_ascii_hexdigit());
    ok.then_some(key)
}

/// The live meter on a grant: its terms plus what has been reserved or spent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrantBudget {
    #[serde(default)]
    pub allow_liquidity_fees: bool,
    /// Total budget, msat.
    pub budget_msat: u64,
    /// Per-call maximum, msat.
    pub per_call_max_msat: u64,
    /// Per-recipient budgets, msat.
    #[serde(default)]
    pub per_recipient_msat: BTreeMap<String, u64>,
    /// Settled plus still-reserved (including unknown outcomes), msat.
    pub used_msat: u64,
    /// The same, per recipient.
    #[serde(default)]
    pub used_by_recipient: BTreeMap<String, u64>,
    /// Outstanding reservations; terminal resolution consumes each recipient once.
    #[serde(default)]
    pub pending: BTreeMap<String, BTreeMap<String, u64>>,
}

impl GrantBudget {
    /// A fresh meter for approved terms.
    pub fn from_terms(terms: &GrantTerms) -> Self {
        Self {
            allow_liquidity_fees: terms.allow_liquidity_fees,
            budget_msat: terms.budget_msat,
            per_call_max_msat: terms.per_call_max_msat,
            per_recipient_msat: terms.per_recipient_msat.clone(),
            used_msat: 0,
            used_by_recipient: BTreeMap::new(),
            pending: BTreeMap::new(),
        }
    }

    /// Budget left, msat.
    pub fn remaining_msat(&self) -> u64 {
        self.budget_msat.saturating_sub(self.used_msat)
    }

    /// Check a call's charges against every bound and, only if all pass,
    /// reserve them. Either every charge is reserved or none is.
    pub fn reserve(&mut self, charges: &[Charge]) -> Result<(), BudgetRefusal> {
        let mut call_total: u64 = 0;
        let mut per_recipient: BTreeMap<&str, u64> = BTreeMap::new();
        for charge in charges {
            call_total =
                call_total
                    .checked_add(charge.amount_msat)
                    .ok_or(BudgetRefusal::PerCall {
                        max_msat: self.per_call_max_msat,
                    })?;
            let entry = per_recipient.entry(charge.recipient.as_str()).or_insert(0);
            *entry = entry
                .checked_add(charge.amount_msat)
                .ok_or(BudgetRefusal::PerCall {
                    max_msat: self.per_call_max_msat,
                })?;
        }
        if call_total > self.per_call_max_msat {
            return Err(BudgetRefusal::PerCall {
                max_msat: self.per_call_max_msat,
            });
        }
        if call_total > self.remaining_msat() {
            return Err(BudgetRefusal::Total {
                remaining_msat: self.remaining_msat(),
            });
        }
        for (recipient, amount) in &per_recipient {
            if let Some(cap) = self.per_recipient_msat.get(*recipient) {
                let used = self.used_by_recipient.get(*recipient).copied().unwrap_or(0);
                let left = cap.saturating_sub(used);
                if *amount > left {
                    return Err(BudgetRefusal::Recipient {
                        recipient: recipient.to_string(),
                        remaining_msat: left,
                    });
                }
            }
        }
        self.used_msat += call_total;
        for (recipient, amount) in per_recipient {
            if amount > 0 {
                *self
                    .used_by_recipient
                    .entry(recipient.to_string())
                    .or_insert(0) += amount;
            }
        }
        Ok(())
    }

    /// Move one reserved charge to its known outcome: `actual_msat` is what
    /// was paid (zero for a refusal before dispatch or a confirmed failure).
    pub fn resolve(&mut self, recipient: &str, reserved_msat: u64, actual_msat: u64) {
        if actual_msat == reserved_msat {
            return;
        }
        let used = self
            .used_by_recipient
            .entry(recipient.to_string())
            .or_insert(0);
        if actual_msat < reserved_msat {
            let released = reserved_msat - actual_msat;
            self.used_msat = self.used_msat.saturating_sub(released);
            *used = used.saturating_sub(released);
        } else {
            // The provider reported more than was reserved. Record it: the
            // tally must never under-count what actually left the wallet.
            let extra = actual_msat - reserved_msat;
            self.used_msat = self.used_msat.saturating_add(extra);
            *used = used.saturating_add(extra);
        }
        if *used == 0 {
            self.used_by_recipient.remove(recipient);
        }
    }
}

/// One payment a call intends to make.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Charge {
    /// Canonical recipient key (see [`canonical_recipient`]).
    pub recipient: String,
    /// Principal, msat. Routing fees are provider-controlled and, as in the
    /// #80 caps, not part of the principal.
    pub amount_msat: u64,
}

/// Charges reserved against one grant. Carries no authority: resolving it
/// against a grant that has since been revoked or replaced does nothing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reservation {
    /// Unique durable reservation, distinct from the grant id.
    pub id: String,
    /// Client the grant belongs to.
    pub client_id: String,
    /// The grant's operation id — identifies which grant was debited.
    pub op_id: String,
    /// What was reserved.
    pub charges: Vec<Charge>,
}

impl Reservation {
    /// Amount reserved for `recipient` in this call.
    pub fn reserved_for(&self, recipient: &str) -> u64 {
        self.charges
            .iter()
            .filter(|c| c.recipient == recipient)
            .map(|c| c.amount_msat)
            .sum()
    }
}

/// Why a debit was refused. Nothing was reserved and nothing was dispatched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BudgetRefusal {
    /// No live, metered grant for this client (expired, revoked, rotated).
    #[error("no live spend grant for this client — ask the owner for a new budget")]
    NoGrant,
    /// The call is larger than the per-call maximum.
    #[error("this call exceeds the grant's per-call maximum of {max_msat} msat")]
    PerCall {
        /// The per-call maximum.
        max_msat: u64,
    },
    /// Not enough budget left.
    #[error("the grant's budget has {remaining_msat} msat left")]
    Total {
        /// What is left.
        remaining_msat: u64,
    },
    /// Not enough left for one recipient.
    #[error("the grant's budget for {recipient} has {remaining_msat} msat left")]
    Recipient {
        /// The recipient.
        recipient: String,
        /// What is left for them.
        remaining_msat: u64,
    },
    /// The amount cannot be known before paying, so it cannot be debited.
    #[error("{0}")]
    Unpriced(String),
    /// The ledger could not be written; refusing is the only safe answer.
    #[error("the spend ledger could not be written: {0}")]
    Ledger(String),
    /// A first contact without the owner's one-time confirmation for this
    /// recipient (no live, matching first-contact grant).
    #[error("{0}")]
    FirstContact(String),
}

impl BudgetRefusal {
    /// Stable machine-readable reason, returned alongside `budget_exceeded`.
    pub fn reason(&self) -> &'static str {
        match self {
            BudgetRefusal::NoGrant => "no_grant",
            BudgetRefusal::PerCall { .. } => "per_call",
            BudgetRefusal::Total { .. } => "total",
            BudgetRefusal::Recipient { .. } => "recipient",
            BudgetRefusal::Unpriced(_) => "unpriced",
            BudgetRefusal::Ledger(_) => "ledger",
            BudgetRefusal::FirstContact(_) => "first_contact",
        }
    }
}

/// A grant as reported to the client that holds it and to the owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrantView {
    #[serde(default)]
    pub allow_liquidity_fees: bool,
    /// The grant's operation id.
    pub op_id: String,
    /// Client it belongs to.
    pub client_id: String,
    /// Unix seconds it was written.
    pub granted_at: i64,
    /// Unix seconds it stops working.
    pub expires_at: i64,
    /// Total budget, msat.
    pub budget_msat: u64,
    /// Reserved or spent, msat.
    pub used_msat: u64,
    /// Left, msat.
    pub remaining_msat: u64,
    /// Per-call maximum, msat.
    pub per_call_max_msat: u64,
    /// Per-recipient budgets, msat.
    pub per_recipient_msat: BTreeMap<String, u64>,
    /// Per-recipient usage, msat.
    pub used_by_recipient: BTreeMap<String, u64>,
}

/// Render terms for a human before they approve them.
pub fn describe_terms(terms: &GrantTerms) -> String {
    let mut out = format!(
        "  budget:        {} sats in total\n  per call:      at most {} sats\n  window:        {}",
        sats(terms.budget_msat),
        sats(terms.per_call_max_msat),
        human_duration(terms.ttl_secs)
    );
    out.push_str(if terms.allow_liquidity_fees { "\n  LSP fees:      allowed, within this same budget" } else { "\n  LSP fees:      not authorized" });
    if terms.per_recipient_msat.is_empty() {
        out.push_str("\n  recipients:    any, within the total");
    } else {
        for (key, cap) in &terms.per_recipient_msat {
            out.push_str(&format!(
                "\n  recipient:     {key} — at most {} sats",
                sats(*cap)
            ));
        }
        out.push_str("\n  others:        any, within the total");
    }
    out
}

/// Millisatoshis as sats for display, keeping a fraction only when present.
pub fn sats(msat: u64) -> String {
    if msat.is_multiple_of(1000) {
        format!("{}", msat / 1000)
    } else {
        format!("{}.{:03}", msat / 1000, msat % 1000)
    }
}

/// `3600` → `1 h`, `5400` → `1 h 30 min`, `90` → `1 min 30 s`.
pub fn human_duration(secs: i64) -> String {
    let (h, m, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let mut parts = Vec::new();
    if h > 0 {
        parts.push(format!("{h} h"));
    }
    if m > 0 {
        parts.push(format!("{m} min"));
    }
    if s > 0 || parts.is_empty() {
        parts.push(format!("{s} s"));
    }
    parts.join(" ")
}

/// Parse `24h`, `90m`, `3600s`, `1h30m` or a bare number of seconds.
pub fn parse_duration(input: &str) -> Result<i64, String> {
    let input = input.trim().to_ascii_lowercase();
    if input.is_empty() {
        return Err("empty duration".into());
    }
    if let Ok(secs) = input.parse::<i64>() {
        return Ok(secs);
    }
    let mut total: i64 = 0;
    let mut digits = String::new();
    for c in input.chars() {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = match c {
            'h' => 3600,
            'm' => 60,
            's' => 1,
            _ => return Err(format!("unknown duration unit {c:?} in {input:?}")),
        };
        let n: i64 = digits
            .parse()
            .map_err(|_| format!("malformed duration {input:?}"))?;
        total = n
            .checked_mul(unit)
            .and_then(|v| total.checked_add(v))
            .ok_or_else(|| format!("duration {input:?} is too long"))?;
        digits.clear();
    }
    if !digits.is_empty() {
        return Err(format!("duration {input:?} ends without a unit"));
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn charge(r: &str, amount_msat: u64) -> Charge {
        Charge {
            recipient: r.repeat(32),
            amount_msat,
        }
    }

    #[test]
    fn terms_refuse_what_cannot_be_enforced() {
        assert!(GrantTerms::new(0).normalized().is_err());
        assert!(GrantTerms::new(MAX_GRANT_BUDGET_MSAT + 1)
            .normalized()
            .is_err());
        assert!(GrantTerms::new(1000)
            .for_secs(MAX_SPEND_GRANT_TTL_SECS + 1)
            .normalized()
            .is_err());
        assert!(GrantTerms::new(1000).for_secs(30).normalized().is_err());
        assert!(GrantTerms::new(1000).per_call(1001).normalized().is_err());
        assert!(GrantTerms::new(1000)
            .recipient("zz", 10)
            .normalized()
            .is_err());
        assert!(GrantTerms::new(1000)
            .recipient(&"aa".repeat(32), 1001)
            .normalized()
            .is_err());
        let ok = GrantTerms::new(1000)
            .recipient(&"AA".repeat(32), 500)
            .normalized()
            .unwrap();
        assert!(ok.per_recipient_msat.contains_key(&"aa".repeat(32)));
    }

    #[test]
    fn reserve_is_all_or_nothing_across_every_bound() {
        let terms = GrantTerms::new(10_000)
            .per_call(4_000)
            .recipient(&"aa".repeat(32), 3_000)
            .normalized()
            .unwrap();
        let mut b = GrantBudget::from_terms(&terms);
        assert_eq!(
            b.reserve(&[charge("bb", 4_001)]),
            Err(BudgetRefusal::PerCall { max_msat: 4_000 })
        );
        assert!(matches!(
            b.reserve(&[charge("aa", 2_000), charge("aa", 1_001)]),
            Err(BudgetRefusal::Recipient { .. })
        ));
        assert_eq!(b.used_msat, 0, "a refused call reserves nothing");
        b.reserve(&[charge("aa", 3_000)]).unwrap();
        b.reserve(&[charge("bb", 4_000)]).unwrap();
        assert!(matches!(
            b.reserve(&[charge("aa", 1)]),
            Err(BudgetRefusal::Recipient {
                remaining_msat: 0,
                ..
            })
        ));
        assert_eq!(
            b.reserve(&[charge("cc", 3_001)]),
            Err(BudgetRefusal::Total {
                remaining_msat: 3_000
            })
        );
        b.reserve(&[charge("cc", 3_000)]).unwrap();
        assert_eq!(b.remaining_msat(), 0);
    }

    #[test]
    fn resolve_releases_settles_or_records_more() {
        let mut b = GrantBudget::from_terms(&GrantTerms::new(10_000).normalized().unwrap());
        let r = "aa".repeat(32);
        b.reserve(&[charge("aa", 5_000)]).unwrap();
        b.resolve(&r, 5_000, 4_000);
        assert_eq!(b.used_msat, 4_000);
        b.resolve(&r, 4_000, 0);
        assert_eq!(b.used_msat, 0);
        assert!(b.used_by_recipient.is_empty());
        b.reserve(&[charge("aa", 1_000)]).unwrap();
        b.resolve(&r, 1_000, 1_500);
        assert_eq!(b.used_msat, 1_500, "never under-count what left the wallet");
    }

    #[test]
    fn durations_parse_and_render() {
        assert_eq!(parse_duration("24h"), Ok(86_400));
        assert_eq!(parse_duration("1h30m"), Ok(5_400));
        assert_eq!(parse_duration("90"), Ok(90));
        assert!(parse_duration("2d").is_err());
        assert!(parse_duration("5").is_ok());
        assert!(parse_duration("1h5").is_err());
        assert_eq!(human_duration(5_400), "1 h 30 min");
        assert_eq!(sats(1_500), "1.500");
    }
}
