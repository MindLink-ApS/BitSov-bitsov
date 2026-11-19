//! Standing allowance: owner-set terms, attached to one pairing, inside which
//! the node opens that pairing's spend windows by itself.
//!
//! A spend grant is a short window (at most 24 h) the owner approves one at a
//! time. A standing allowance is the owner's approval of a *series* of such
//! windows, bounded by:
//!
//! - a daily cap, counted over any rolling 24 hours, never per window or per
//!   calendar day, so back-to-back windows cannot add up to more than the cap;
//! - a per-call cap;
//! - an end date (`until`), after which no new window opens;
//! - circuit breakers, which carry over from one window to the next.
//!
//! Only an owner channel writes an allowance, never a client request body.
//! Today that channel is `konsensus pair-ticket --allow` on an owner-run node:
//! the terms are bound node-side to that one ticket and copied onto the
//! pairing it creates. The allowance records who set it and a receipt.
//!
//! The whole feature sits behind `[pairing] standing_allowance_v1`, off by
//! default. With it off, an allowance is never written, never opens a window,
//! and a window opened earlier authorizes nothing.
//!
//! # The rolling ledger
//!
//! Every window the allowance opens is recorded with the most it could spend:
//! its whole budget while it can still spend, and what it actually used
//! (settled, reserved or of unknown outcome) once it has ended. An ended
//! window keeps counting until 24 hours after the last moment it could have
//! spent, plus the longest call, because a call admitted before the end may
//! still pay its minutes. A new window opens only if its budget fits what is
//! left. Counting this way is conservative: it may hold back sats that were
//! not spent, never let more than the cap be spent in any 24 hours.
//!
//! The ledger is stored with the pairing, so a restart cannot reset it. A
//! clock moving backward only keeps entries counting longer, and the highest
//! time the allowance has seen is what `until` is compared against, so a
//! clock moving backward cannot reopen an allowance that ended.
//!
//! Lowering the cap applies from the moment it is written: spending already
//! recorded stays counted against the new, lower cap, and is never undone.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::spend_budget::{
    BreakerLimits, BreakerState, DeviceBreakerReset, GrantBudget, GrantTerms, MAX_GRANT_BUDGET_MSAT,
    MAX_SPEND_GRANT_TTL_SECS, MIN_SPEND_GRANT_TTL_SECS,
};

/// Advertised on `/api/v1/status` while `[pairing] standing_allowance_v1` is on.
pub const STANDING_ALLOWANCE_CAPABILITY: &str = "standing_allowance_v1";

/// `granted_by` on a spend window the node opened from an allowance.
pub const ALLOWANCE_GRANTED_BY: &str = "allowance";

/// `set_by` of an allowance written by `konsensus pair-ticket --allow`.
pub const SET_BY_CLI: &str = "cli";

/// Daily cap when the owner names none: 2,500 sats.
pub const DEFAULT_DAILY_SATS: u64 = 2_500;
/// Per-call cap when the owner names none: 700 sats.
pub const DEFAULT_PER_CALL_SATS: u64 = 700;
/// Lifetime when the owner names none: 30 days.
pub const DEFAULT_DAYS: u32 = 30;
/// Longest allowance the node accepts.
pub const MAX_DAYS: u32 = 365;
/// Longest a pairing ticket carrying an allowance may stay usable. The link is
/// a bearer secret, and with an allowance attached it is worth up to the daily
/// cap, so it must be used soon.
pub const MAX_TICKET_TTL_SECS: u64 = 3600;

/// The window over which the daily cap is counted.
pub const ROLLING_SECS: i64 = 24 * 3600;

/// How long after its window ends a call admitted inside it may still pay:
/// the longest call, plus a minute.
pub const CALL_TAIL_SECS: i64 = 240 * 60 + 60;

/// Most windows the ledger keeps per pairing. Windows age out after at most
/// two days; reaching this means windows are being opened far faster than any
/// app needs, and the node stops opening more until older ones age out.
pub const MAX_LEDGER_WINDOWS: usize = 512;

/// File, next to the pairing link, that binds owner terms to one ticket.
const TICKET_ALLOWANCE_FILE: &str = "remote-access-allowance";

/// The numbers the owner approves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowanceTerms {
    /// Most all windows together may spend in any rolling 24 hours, msat.
    pub daily_msat: u64,
    /// Most one call may reserve in a window the allowance opens, msat.
    pub per_call_max_msat: u64,
    /// Unix seconds after which no new window opens.
    pub until: i64,
    /// Breakers for every window the allowance opens.
    #[serde(default)]
    pub breakers: BreakerLimits,
}

impl AllowanceTerms {
    /// Terms in sats and days, from `now`. Refuses what the node cannot
    /// enforce as written.
    pub fn from_sats(daily_sats: u64, per_call_sats: u64, days: u32, now: i64) -> Result<Self, String> {
        if !(1..=MAX_DAYS).contains(&days) {
            return Err(format!("an allowance lasts between 1 and {MAX_DAYS} days"));
        }
        let daily_msat = daily_sats
            .checked_mul(1000)
            .ok_or_else(|| "the daily cap is too large".to_string())?;
        let per_call_max_msat = per_call_sats
            .checked_mul(1000)
            .ok_or_else(|| "the per-call cap is too large".to_string())?;
        let terms = Self {
            daily_msat,
            per_call_max_msat,
            until: now.saturating_add(i64::from(days) * 86_400),
            breakers: BreakerLimits::default(),
        };
        terms.validate(now)?;
        Ok(terms)
    }

    /// The owner-approved defaults: 2,500 sats a day, 700 sats a call, 30 days.
    pub fn owner_defaults(now: i64) -> Self {
        Self::from_sats(DEFAULT_DAILY_SATS, DEFAULT_PER_CALL_SATS, DEFAULT_DAYS, now)
            .expect("default allowance terms are valid")
    }

    /// Every bound, checked.
    pub fn validate(&self, now: i64) -> Result<(), String> {
        if self.daily_msat == 0 || self.daily_msat > MAX_GRANT_BUDGET_MSAT {
            return Err(format!(
                "the daily cap must be between 1 msat and {MAX_GRANT_BUDGET_MSAT} msat"
            ));
        }
        if self.per_call_max_msat == 0 || self.per_call_max_msat > self.daily_msat {
            return Err("the per-call cap must be between 1 msat and the daily cap".into());
        }
        if self.until <= now || self.until > now.saturating_add(i64::from(MAX_DAYS) * 86_400) {
            return Err(format!("an allowance ends between now and {MAX_DAYS} days from now"));
        }
        if !self.breakers.valid() {
            return Err("all circuit breaker limits must be greater than zero".into());
        }
        Ok(())
    }
}

/// One window the allowance opened, as the rolling ledger counts it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AllowanceWindow {
    /// The spend grant's operation id.
    pub op_id: String,
    /// Unix seconds when it opened.
    pub opened_at: i64,
    /// Most it can still have spent: the whole budget while it can spend,
    /// what it used once it has ended.
    pub committed_msat: u64,
    /// Unix seconds when it stopped being able to open new spending; absent
    /// while it still can.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
}

impl AllowanceWindow {
    /// Whether this window still counts against the daily cap at `now`.
    pub fn counts(&self, now: i64) -> bool {
        match self.ended_at {
            None => true,
            Some(end) => now < end.saturating_add(CALL_TAIL_SECS).saturating_add(ROLLING_SECS),
        }
    }
}

/// Breaker history carried from one window to the next, so a new window
/// never starts from a clean slate the owner did not approve.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CarriedBreakers {
    #[serde(default)]
    pub(crate) state: BreakerState,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) device_resets: Vec<DeviceBreakerReset>,
    #[serde(default)]
    pub(crate) reset_generation: u64,
}

impl CarriedBreakers {
    fn from_budget(budget: &GrantBudget) -> Self {
        Self {
            state: budget.breaker_state.clone(),
            device_resets: budget.device_breaker_resets.clone(),
            reset_generation: budget.breaker_reset_generation,
        }
    }

    fn apply_to(&self, budget: &mut GrantBudget) {
        budget.breaker_state = self.state.clone();
        budget.device_breaker_resets = self.device_resets.clone();
        budget.breaker_reset_generation = self.reset_generation;
    }
}

/// An owner-set allowance on one pairing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StandingAllowance {
    pub terms: AllowanceTerms,
    /// Which owner channel wrote it (see [`SET_BY_CLI`]).
    pub set_by: String,
    /// Evidence of that channel, where it has one: for a pairing ticket, the
    /// ticket's hash. Never the ticket itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    /// Unix seconds when it was written.
    pub set_at: i64,
    /// The pairing epoch it was written against; a bump removes it.
    pub epoch: u64,
    /// The node identity it was written against.
    pub identity_fingerprint: String,
    /// The rolling ledger.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub windows: Vec<AllowanceWindow>,
    /// Highest wall-clock time the allowance has seen, unix seconds.
    #[serde(default)]
    pub observed_at: i64,
    /// Breaker history of the last window that ended.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub carried_breakers: Option<CarriedBreakers>,
}

/// Why an allowance did not open a window. The request then takes the usual
/// owner path, unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoWindow {
    /// The node does not run with the switch on.
    Off,
    /// The pairing has no allowance.
    None,
    /// The allowance was written by a channel this start does not honour, or
    /// for another epoch or identity.
    Provenance,
    /// Its end date has passed.
    Ended,
    /// The request is outside the allowance's terms.
    OutsideTerms(&'static str),
    /// The rolling 24-hour cap has no room for this budget.
    OverDailyCap { remaining_msat: u64 },
}

impl StandingAllowance {
    /// A fresh allowance written by `set_by` at `now`.
    pub fn new(
        terms: AllowanceTerms,
        set_by: &str,
        receipt: Option<String>,
        epoch: u64,
        identity_fingerprint: &str,
        now: i64,
    ) -> Self {
        Self {
            terms,
            set_by: set_by.to_string(),
            receipt,
            set_at: now,
            epoch,
            identity_fingerprint: identity_fingerprint.to_string(),
            windows: Vec::new(),
            observed_at: now,
            carried_breakers: None,
        }
    }

    /// New terms from the owner on a pairing that already has an allowance.
    /// The ledger and breaker history stay: a lower cap applies from now and
    /// counts what was already spent, and nothing restarts from zero.
    pub fn replace_terms(&mut self, next: StandingAllowance) {
        let windows = std::mem::take(&mut self.windows);
        let carried = self.carried_breakers.take();
        let observed = self.observed_at;
        *self = next;
        self.windows = windows;
        self.carried_breakers = carried;
        self.observed_at = self.observed_at.max(observed);
    }

    /// The time `until` is compared against: never earlier than a time the
    /// allowance has already seen.
    pub fn effective_now(&self, now: i64) -> i64 {
        now.max(self.observed_at)
    }

    /// Whether the allowance can still open windows at `now`.
    pub fn is_live(&self, now: i64) -> bool {
        self.effective_now(now) < self.terms.until
    }

    /// What all counted windows may have spent, msat.
    pub fn committed_msat(&self, now: i64) -> u64 {
        self.windows
            .iter()
            .filter(|w| w.counts(now))
            .fold(0u64, |sum, w| sum.saturating_add(w.committed_msat))
    }

    /// Room left under the daily cap at `now`, msat.
    pub fn remaining_msat(&self, now: i64) -> u64 {
        self.terms.daily_msat.saturating_sub(self.committed_msat(now))
    }

    /// Drop windows that no longer count.
    pub fn forget_old_windows(&mut self, now: i64) {
        self.windows.retain(|w| w.counts(now));
    }

    /// Check a proposal against the terms, at `now`, given that the window
    /// with `replacing` op id (if any) is about to end having used
    /// `replacing_used_msat`. Returns the window length to grant.
    pub fn admit(
        &self,
        terms: &GrantTerms,
        replacing: Option<(&str, u64)>,
        now: i64,
    ) -> Result<i64, NoWindow> {
        let effective = self.effective_now(now);
        if effective >= self.terms.until {
            return Err(NoWindow::Ended);
        }
        if terms.allow_liquidity_fees {
            return Err(NoWindow::OutsideTerms("liquidity fees need the owner"));
        }
        if terms.per_call_max_msat > self.terms.per_call_max_msat {
            return Err(NoWindow::OutsideTerms("per-call amount above the allowance"));
        }
        if terms.budget_msat > self.terms.daily_msat {
            return Err(NoWindow::OutsideTerms("budget above the daily cap"));
        }
        let ttl = terms.ttl_secs.min(self.terms.until - effective);
        if !(MIN_SPEND_GRANT_TTL_SECS..=MAX_SPEND_GRANT_TTL_SECS).contains(&ttl) {
            return Err(NoWindow::Ended);
        }
        let live_windows = self.windows.iter().filter(|w| w.counts(now)).count();
        if live_windows >= MAX_LEDGER_WINDOWS {
            return Err(NoWindow::OutsideTerms("too many windows in the last day"));
        }
        let committed = self.windows.iter().filter(|w| w.counts(now)).fold(0u64, |sum, w| {
            let counted = match replacing {
                Some((op, used)) if w.op_id == op && w.ended_at.is_none() => used,
                _ => w.committed_msat,
            };
            sum.saturating_add(counted)
        });
        let remaining = self.terms.daily_msat.saturating_sub(committed);
        if terms.budget_msat > remaining {
            return Err(NoWindow::OverDailyCap { remaining_msat: remaining });
        }
        Ok(ttl)
    }

    /// Record that the open window `op_id` has ended at `ended_at` having
    /// used `used_msat`, if `budget` is known; with no budget (the grant was
    /// revoked or replaced elsewhere) the whole window stays counted.
    pub(crate) fn end_window(&mut self, op_id: &str, ended_at: i64, budget: Option<&GrantBudget>) {
        let Some(window) = self
            .windows
            .iter_mut()
            .find(|w| w.op_id == op_id && w.ended_at.is_none())
        else {
            return;
        };
        window.ended_at = Some(ended_at);
        if let Some(budget) = budget {
            window.committed_msat = window.committed_msat.min(budget.used_msat);
            self.carried_breakers = Some(CarriedBreakers::from_budget(budget));
        }
    }

    /// A fresh meter for a new window: the proposal's numbers with the
    /// allowance's breakers and the breaker history carried forward.
    pub(crate) fn window_budget(&self, terms: &GrantTerms, previous: Option<&GrantBudget>) -> GrantBudget {
        let mut terms = terms.clone();
        terms.breakers = self.terms.breakers.clone();
        let mut budget = GrantBudget::from_terms(&terms);
        match previous {
            Some(previous) => CarriedBreakers::from_budget(previous).apply_to(&mut budget),
            None => {
                if let Some(carried) = &self.carried_breakers {
                    carried.apply_to(&mut budget);
                }
            }
        }
        budget
    }

    /// Record a window that just opened.
    pub(crate) fn open_window(&mut self, op_id: &str, budget_msat: u64, now: i64) {
        self.observed_at = self.observed_at.max(now);
        self.windows.push(AllowanceWindow {
            op_id: op_id.to_string(),
            opened_at: now,
            committed_msat: budget_msat,
            ended_at: None,
        });
    }
}

/// What the owner and the app may read about an allowance. Terms and
/// provenance only, never the receipt.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AllowanceView {
    pub daily_msat: u64,
    pub per_call_max_msat: u64,
    pub until: i64,
    pub set_by: String,
    pub set_at: i64,
    pub remaining_msat: u64,
}

impl AllowanceView {
    pub(crate) fn of(allowance: &StandingAllowance, now: i64) -> Self {
        Self {
            daily_msat: allowance.terms.daily_msat,
            per_call_max_msat: allowance.terms.per_call_max_msat,
            until: allowance.terms.until,
            set_by: allowance.set_by.clone(),
            set_at: allowance.set_at,
            remaining_msat: allowance.remaining_msat(now),
        }
    }
}

/// Owner terms bound to one pairing ticket, kept in a protected file next to
/// the ticket and never in the link itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct TicketAllowance {
    /// Hash of the ticket code these terms belong to.
    ticket_hash: String,
    terms: AllowanceTerms,
}

/// Hash that binds terms to one ticket code.
pub fn ticket_hash(code: &str) -> String {
    blake3::hash(code.as_bytes()).to_hex().to_string()
}

/// Bind `terms` to the ticket whose code is `code`. Owner CLI only; written
/// before the ticket itself, so a node never sees the ticket without them.
pub fn write_ticket_allowance(
    pairing_dir: &Path,
    code: &str,
    terms: &AllowanceTerms,
) -> std::io::Result<()> {
    let record = TicketAllowance {
        ticket_hash: ticket_hash(code),
        terms: terms.clone(),
    };
    let bytes = serde_json::to_vec(&record).map_err(std::io::Error::other)?;
    let path = pairing_dir.join(TICKET_ALLOWANCE_FILE);
    let temporary = pairing_dir.join(format!(".remote-access-allowance-{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        super::write_protected(&temporary, &bytes)?;
        std::fs::rename(&temporary, &path)?;
        super::fsync_dir_strict(pairing_dir)
    })();
    let _ = std::fs::remove_file(temporary);
    result
}

/// Remove any terms bound to a ticket.
pub fn remove_ticket_allowance(pairing_dir: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(pairing_dir.join(TICKET_ALLOWANCE_FILE)) {
        Ok(()) => super::fsync_dir_strict(pairing_dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// The terms bound to exactly this ticket code, if any. Terms bound to
/// another code, an unreadable file or invalid terms all read as none.
pub fn read_ticket_allowance(pairing_dir: &Path, code: &str, now: i64) -> Option<AllowanceTerms> {
    let path = pairing_dir.join(TICKET_ALLOWANCE_FILE);
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return None;
    }
    let record: TicketAllowance = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
    let expected = ticket_hash(code);
    let matches: bool = record.ticket_hash.len() == expected.len()
        && record
            .ticket_hash
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    (matches && record.terms.validate(now).is_ok()).then_some(record.terms)
}

impl super::PairingFile {
    fn has_open_window(
        allowances: &std::collections::BTreeMap<String, StandingAllowance>,
        grant: &super::SpendGrant,
    ) -> bool {
        allowances.get(&grant.client_id).is_some_and(|a| {
            a.epoch == grant.epoch
                && a.windows.iter().any(|w| w.op_id == grant.op_id && w.ended_at.is_none())
        })
    }

    /// A window opened from an allowance that no longer has it on record.
    pub(super) fn has_orphan_allowance_window(&self) -> bool {
        self.grants.iter().any(|g| {
            g.granted_by == ALLOWANCE_GRANTED_BY
                && g.budget.is_some()
                && !Self::has_open_window(&self.allowances, g)
        })
    }

    /// Bring every allowance's ledger up to date with its grants: an open
    /// window whose grant expired is ended at its expiry with what it used;
    /// one whose grant was revoked, replaced elsewhere or is gone stays
    /// counted in full. Windows past counting are dropped.
    pub(super) fn settle_allowance_windows(&mut self, now: i64) {
        // A window whose allowance is gone (revoked, or dropped by a node
        // that did not know it) authorizes nothing more.
        for grant in &mut self.grants {
            if grant.granted_by == ALLOWANCE_GRANTED_BY
                && grant.budget.is_some()
                && !Self::has_open_window(&self.allowances, grant)
            {
                grant.budget = None;
            }
        }
        let Self { allowances, grants, .. } = self;
        for allowance in allowances.values_mut() {
            let open: Vec<String> = allowance
                .windows
                .iter()
                .filter(|w| w.ended_at.is_none())
                .map(|w| w.op_id.clone())
                .collect();
            for op_id in open {
                match grants.iter().find(|g| g.op_id == op_id) {
                    Some(grant) if grant.budget.is_some() && grant.is_live(now) => {}
                    Some(grant) if grant.budget.is_some() => {
                        allowance.end_window(&op_id, grant.expires_at.min(now), grant.budget.as_ref())
                    }
                    _ => allowance.end_window(&op_id, now, None),
                }
            }
            allowance.forget_old_windows(now);
        }
    }
}

impl super::PairingService {
    /// Turn `[pairing] standing_allowance_v1` on. Off by default.
    pub fn with_standing_allowance(mut self, enabled: bool) -> Self {
        self.standing_allowance = enabled;
        self
    }

    /// Whether standing allowances are on (and advertised).
    pub fn standing_allowance_enabled(&self) -> bool {
        self.standing_allowance
    }

    /// Whether this start honours an allowance written by `set_by`. The only
    /// writer so far is the owner's `pair-ticket` command, which is owner
    /// provenance only on a node the owner runs with its control socket.
    fn allowance_set_by_honoured(&self, set_by: &str) -> bool {
        self.standing_allowance && set_by == SET_BY_CLI && self.owner_control_enabled
    }

    /// Whether windows opened from an allowance authorize anything on this
    /// start. Every allowance writer this start honours is checked again
    /// when a window opens; this is the gate for windows already open.
    pub(super) fn allowance_windows_honoured(&self) -> bool {
        self.allowance_set_by_honoured(SET_BY_CLI)
    }

    /// The allowance on a pairing, as the owner set it.
    pub fn allowance_view(&self, client_id: &str) -> Option<AllowanceView> {
        let now = chrono::Utc::now().timestamp();
        let inner = self.lock();
        let client = inner.file.clients.iter().find(|c| c.client_id == client_id)?;
        let allowance = inner.file.allowances.get(client_id)?;
        (allowance.epoch == client.epoch).then(|| AllowanceView::of(allowance, now))
    }

    /// Open a spend window from the client's allowance, if the request fits
    /// it. `Ok(Err(_))` means it does not fit and nothing was written.
    pub(super) fn open_allowance_window(
        &self,
        inner: &mut super::Inner,
        client: &super::PairedClient,
        scopes: &[crate::auth::Scope],
        terms: &GrantTerms,
        now: i64,
    ) -> Result<Result<super::PendingElevation, NoWindow>, super::PairingError> {
        use rand::Rng;
        if !self.standing_allowance {
            return Ok(Err(NoWindow::Off));
        }
        if scopes != [crate::auth::Scope::Spend] {
            return Ok(Err(NoWindow::OutsideTerms("only spend opens from an allowance")));
        }
        let Some(allowance) = inner.file.allowances.get(&client.client_id) else {
            return Ok(Err(NoWindow::None));
        };
        if !self.allowance_set_by_honoured(&allowance.set_by)
            || allowance.epoch != client.epoch
            || allowance.identity_fingerprint != inner.identity_fingerprint
            || client.identity_fingerprint != inner.identity_fingerprint
        {
            return Ok(Err(NoWindow::Provenance));
        }
        let previous = inner
            .file
            .grants
            .iter()
            .filter(|g| {
                g.client_id == client.client_id
                    && g.granted_by == ALLOWANCE_GRANTED_BY
                    && g.is_live(now)
            })
            .max_by_key(|g| g.granted_at);
        let replacing = previous.and_then(|g| Some((g.op_id.as_str(), g.budget.as_ref()?.used_msat)));
        let ttl = match allowance.admit(terms, replacing, now) {
            Ok(ttl) => ttl,
            Err(why) => return Ok(Err(why)),
        };
        let budget = allowance.window_budget(terms, previous.and_then(|g| g.budget.as_ref()));
        let mut op_bytes = [0u8; 12];
        rand::rng().fill_bytes(&mut op_bytes);
        let op_id = hex::encode(op_bytes);
        let grant = super::SpendGrant {
            op_id: op_id.clone(),
            client_id: client.client_id.clone(),
            scopes: vec![crate::auth::Scope::Spend],
            granted_at: now,
            expires_at: now + ttl,
            identity_fingerprint: inner.identity_fingerprint.clone(),
            epoch: client.epoch,
            granted_by: ALLOWANCE_GRANTED_BY.to_string(),
            budget: Some(budget),
            owner_approval: None,
        };
        let before = inner.file.clone();
        let file = &mut inner.file;
        let allowance = file
            .allowances
            .get_mut(&client.client_id)
            .expect("checked above under the same lock");
        // A new window replaces the client's old one, as every budget window
        // does. The allowance's own window ends now with what it used.
        for old in &mut file.grants {
            if old.client_id == client.client_id {
                if old.granted_by == ALLOWANCE_GRANTED_BY && old.budget.is_some() {
                    allowance.end_window(&old.op_id, old.expires_at.min(now), old.budget.as_ref());
                }
                old.budget = None;
            }
        }
        allowance.open_window(&op_id, terms.budget_msat, now);
        file.grants.push(grant);
        if let Err(error) = self.persist(&mut inner.file) {
            inner.file = before;
            return Err(error);
        }
        Ok(Ok(super::PendingElevation {
            op_id,
            client_id: client.client_id.clone(),
            client_name: client.name.clone(),
            scopes: vec![crate::auth::Scope::Spend],
            created_at: now,
            expires_at: now + super::ELEVATION_TTL_SECS,
            proposed_terms: Some(terms.clone()),
        }))
    }

    /// Pair through a consumed pairing ticket, attaching the owner's terms
    /// bound to that ticket. The terms attach only to a pairing this ticket
    /// creates, only with the switch on and only on a start that honours the
    /// owner's command; otherwise the pairing is made without them.
    pub fn create_ticket_remote_pairing_with_allowance(
        &self,
        name: &str,
        client_pubkey_hex: &str,
        remote_transport_pubkey: &[u8; 32],
        code: &str,
        terms: Option<&AllowanceTerms>,
    ) -> Result<super::PairedClient, super::PairingError> {
        let mut inner = self.lock();
        let client_id = super::client_id_from_pubkey(&client_pubkey_hex.to_ascii_lowercase());
        let existed = inner.file.clients.iter().any(|c| c.client_id == client_id);
        let record = self.create_remote_pairing_locked(
            &mut inner,
            name,
            client_pubkey_hex,
            remote_transport_pubkey,
            false,
        )?;
        let Some(terms) = terms else {
            return Ok(record);
        };
        let now = chrono::Utc::now().timestamp();
        if existed || !self.allowance_set_by_honoured(SET_BY_CLI) || terms.validate(now).is_err() {
            tracing::warn!("pairing ticket carried allowance terms this node does not honour; paired without them");
            return Ok(record);
        }
        let before = inner.file.clone();
        let allowance = StandingAllowance::new(
            terms.clone(),
            SET_BY_CLI,
            Some(format!("ticket:{}", ticket_hash(code))),
            record.epoch,
            &record.identity_fingerprint,
            now,
        );
        inner.file.allowances.insert(record.client_id.clone(), allowance);
        if let Err(error) = self.persist(&mut inner.file) {
            inner.file = before;
            tracing::warn!(%error, "could not store the allowance from a pairing ticket; paired without it");
        }
        Ok(record)
    }
}
