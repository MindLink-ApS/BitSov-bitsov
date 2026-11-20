//! Standing allowance cases. Every fixture runs with the switch off as well
//! as on: off must be exactly today's behaviour.
use super::allowance::*;
use super::*;

const DAILY: u64 = 2_500_000;
const PER_CALL: u64 = 700_000;

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn terms() -> AllowanceTerms {
    AllowanceTerms::owner_defaults(now())
}

struct Fixture {
    _dir: tempfile::TempDir,
    svc: PairingService,
    client: String,
}

/// A node (owner-run or not, switch on or off) with one app paired through a
/// ticket that carries `ticket_terms`.
fn fixture(owner_control: bool, switch: bool, ticket_terms: Option<AllowanceTerms>) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let svc = PairingService::open(dir.path(), "identity".into(), owner_control)
        .unwrap()
        .with_standing_allowance(switch);
    let key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
    let client = svc
        .create_ticket_remote_pairing_with_allowance(
            "app",
            &hex::encode(key.verifying_key().to_bytes()),
            &[22; 32],
            "ticket-code",
            ticket_terms.as_ref(),
        )
        .unwrap()
        .client_id;
    Fixture { _dir: dir, svc, client }
}

fn reopen(f: Fixture, owner_control: bool, switch: bool) -> Fixture {
    let Fixture { _dir, svc, client } = f;
    drop(svc);
    let svc = PairingService::open(_dir.path(), "identity".into(), owner_control)
        .unwrap()
        .with_standing_allowance(switch);
    Fixture { _dir, svc, client }
}

fn proposal(budget_msat: u64, per_call_msat: u64) -> GrantTerms {
    GrantTerms::new(budget_msat).per_call(per_call_msat).for_secs(MAX_SPEND_GRANT_TTL_SECS)
}

/// What a request led to.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The node opened a window from the allowance, and the app reads it as granted.
    Window,
    /// A pending request for the owner, as today.
    Owner,
}

fn ask(f: &Fixture, terms: GrantTerms) -> Result<(String, Outcome), PairingError> {
    let op = f
        .svc
        .create_budget_elevation_request(&f.client, vec![Scope::Spend], Some(terms))?;
    let status = f.svc.elevation_status(&f.client, &op.op_id)?;
    let window = allowance_grants(f).iter().any(|g| g.op_id == op.op_id);
    let pending = f.svc.snapshot().pending_elevations.iter().any(|e| e.op_id == op.op_id);
    let outcome = match (window, pending) {
        (true, false) => {
            assert_eq!(status, ElevationStatus::Granted, "an opened window reads as granted");
            Outcome::Window
        }
        (false, true) => Outcome::Owner,
        other => panic!("request {} ended as {other:?}", op.op_id),
    };
    Ok((op.op_id, outcome))
}

fn allowance_grants(f: &Fixture) -> Vec<SpendGrant> {
    f.svc
        .lock()
        .file
        .grants
        .iter()
        .filter(|g| g.granted_by == ALLOWANCE_GRANTED_BY && g.budget.is_some())
        .cloned()
        .collect()
}

fn spend_scope(f: &Fixture) -> bool {
    let inner = f.svc.lock();
    let record = inner.file.clients.iter().find(|c| c.client_id == f.client).unwrap().clone();
    f.svc.effective_scopes(&inner, &record, now()).contains(&Scope::Spend)
}

/// Reserve a call hold of `minutes * 2,500 msat` under the live window.
fn hold(f: &Fixture, call: &str, minutes: u16) -> u64 {
    let peer = "aa".repeat(32);
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, call, 2_000, 500, minutes).unwrap();
    let reserved = terms.reserved_msat;
    f.svc.reserve_call_spend(&f.client, 1, terms, u64::MAX / 4).unwrap();
    reserved
}

fn ledger(f: &Fixture) -> StandingAllowance {
    f.svc.lock().file.allowances.get(&f.client).cloned().unwrap()
}

// ── N2-T1 / P08: only an owner channel writes an allowance ───────────────

#[test]
fn ticket_terms_become_an_owner_allowance_with_provenance() {
    let f = fixture(true, true, Some(terms()));
    let view = f.svc.allowance_view(&f.client).expect("the ticket's terms are on the pairing");
    assert_eq!((view.daily_msat, view.per_call_max_msat, view.set_by.as_str()), (DAILY, PER_CALL, SET_BY_CLI));
    assert!(view.until > now() + 29 * 86_400 && view.until <= now() + 30 * 86_400);
    let stored = ledger(&f);
    let receipt = stored.receipt.expect("a ticket allowance keeps a receipt");
    assert_eq!(receipt, format!("ticket:{}", ticket_hash("ticket-code")));
    assert!(!serde_json::to_string(&f.svc.reload_from_disk().unwrap()).unwrap().contains("ticket-code"));
}

#[test]
fn a_client_cannot_set_or_raise_an_allowance() {
    // No ticket terms: the first paired app gets nothing for arriving first.
    let f = fixture(true, true, None);
    assert!(f.svc.allowance_view(&f.client).is_none());
    let (op, outcome) = ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
    assert_eq!(outcome, Outcome::Owner);
    assert_eq!(f.svc.elevation_status(&f.client, &op).unwrap(), ElevationStatus::Pending);
    assert!(allowance_grants(&f).is_empty());

    // The request body cannot carry allowance fields of any shape.
    for extra in [
        r#""allowance":{"daily_msat":1}"#,
        r#""standing_allowance":true"#,
        r#""set_by":"cli""#,
        r#""daily_msat":99999999"#,
        r#""until":9999999999"#,
    ] {
        let body = format!(r#"{{"scopes":["spend"],"budget":{{"budget_msat":1000}},{extra}}}"#);
        assert!(serde_json::from_str::<crate::handlers::pairing_routes::ElevationRequestBody>(&body).is_err(), "{extra}");
        let nested = format!(r#"{{"scopes":["spend"],"budget":{{"budget_msat":1000,{extra}}}}}"#);
        assert!(serde_json::from_str::<crate::handlers::pairing_routes::ElevationRequestBody>(&nested).is_err(), "{extra}");
    }

    // With an allowance, no number of requests changes its terms.
    let f = fixture(true, true, Some(terms()));
    let before = f.svc.allowance_view(&f.client).unwrap();
    for budget in [1, DAILY, DAILY + 1, u64::MAX / 2] {
        let _ = ask(&f, proposal(budget, 1.max(budget.min(PER_CALL))));
    }
    let after = f.svc.allowance_view(&f.client).unwrap();
    assert_eq!((after.daily_msat, after.per_call_max_msat, after.until), (before.daily_msat, before.per_call_max_msat, before.until));
}

// ── N2-T4 / P08: a ticket's terms are bound node-side, used once ────────

#[test]
fn replayed_expired_or_foreign_ticket_terms_give_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let t = terms();
    write_ticket_allowance(dir.path(), "code-a", &t).unwrap();
    assert_eq!(read_ticket_allowance(dir.path(), "code-a", now()), Some(t.clone()));
    assert_eq!(read_ticket_allowance(dir.path(), "code-b", now()), None, "bound to one code");
    assert_eq!(read_ticket_allowance(dir.path(), "code-a", t.until), None, "ended terms");
    let mut raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.path().join("remote-access-allowance")).unwrap()).unwrap();
    raw["terms"]["daily_msat"] = serde_json::json!(0);
    std::fs::write(dir.path().join("remote-access-allowance"), raw.to_string()).unwrap();
    assert_eq!(read_ticket_allowance(dir.path(), "code-a", now()), None, "invalid terms");
    raw["terms"]["daily_msat"] = serde_json::json!(1_000);
    raw["extra"] = serde_json::json!(true);
    std::fs::write(dir.path().join("remote-access-allowance"), raw.to_string()).unwrap();
    assert_eq!(read_ticket_allowance(dir.path(), "code-a", now()), None, "unknown fields");
    remove_ticket_allowance(dir.path()).unwrap();
    assert_eq!(read_ticket_allowance(dir.path(), "code-a", now()), None);

    // Removing the ticket removes its terms.
    let f = fixture(true, true, None);
    write_ticket_allowance(f.svc.dir(), "code-a", &t).unwrap();
    f.svc.remove_remote_access_link().unwrap();
    assert_eq!(read_ticket_allowance(f.svc.dir(), "code-a", now()), None);

    // A ticket reused for a pairing that already exists attaches nothing.
    let f = fixture(true, true, None);
    let key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
    f.svc
        .create_ticket_remote_pairing_with_allowance(
            "app",
            &hex::encode(key.verifying_key().to_bytes()),
            &[22; 32],
            "second-code",
            Some(&t),
        )
        .unwrap();
    assert!(f.svc.allowance_view(&f.client).is_none());

    // Expired terms carried to consumption attach nothing either.
    let mut ended = terms();
    ended.until = now() - 1;
    let f = fixture(true, true, Some(ended));
    assert!(f.svc.allowance_view(&f.client).is_none());
}

// ── N2-T2 / P10: auto-grant only within the allowance ───────────────────

#[test]
fn a_request_within_the_allowance_opens_a_window_at_once() {
    let f = fixture(true, true, Some(terms()));
    let (op, outcome) = ask(&f, proposal(2_000_000, PER_CALL)).unwrap();
    assert_eq!(outcome, Outcome::Window);
    let grants = allowance_grants(&f);
    assert_eq!(grants.len(), 1);
    let grant = &grants[0];
    assert_eq!(grant.op_id, op);
    assert_eq!(grant.scopes, vec![Scope::Spend]);
    let budget = grant.budget.as_ref().unwrap();
    assert_eq!((budget.budget_msat, budget.per_call_max_msat, budget.used_msat), (2_000_000, PER_CALL, 0));
    assert_eq!(budget.breakers, terms().breakers);
    assert!(grant.expires_at - grant.granted_at <= MAX_SPEND_GRANT_TTL_SECS);
    assert!(spend_scope(&f));
    assert!(f.svc.snapshot().pending_elevations.is_empty(), "no owner request was raised");
    // Exactly the daily cap and exactly the per-call cap also fit.
    assert_eq!(ask(&f, proposal(DAILY, PER_CALL)).unwrap().1, Outcome::Window);
}

#[test]
fn requests_outside_the_allowance_take_the_owner_path_unchanged() {
    let cases: Vec<(&str, Option<GrantTerms>, Vec<Scope>)> = vec![
        ("above the daily cap", Some(proposal(DAILY + 1, PER_CALL)), vec![Scope::Spend]),
        ("above the per-call cap", Some(proposal(1_000_000, PER_CALL + 1)), vec![Scope::Spend]),
        ("liquidity fees", Some(GrantTerms { allow_liquidity_fees: true, ..proposal(1_000, 1_000) }), vec![Scope::Spend]),
        ("no budget", None, vec![Scope::Spend]),
        ("scopes other than spend alone", Some(proposal(1_000, 1_000)), vec![Scope::Spend, Scope::Spend]),
    ];
    for owner_control in [true, false] {
        for (name, proposed, scopes) in &cases {
            let f = fixture(owner_control, true, Some(terms()));
            let result = f.svc.create_budget_elevation_request(&f.client, scopes.clone(), proposed.clone());
            match owner_control {
                true => {
                    let op = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                    assert_eq!(f.svc.elevation_status(&f.client, &op.op_id).unwrap(), ElevationStatus::Pending, "{name}");
                }
                false => assert!(matches!(result, Err(PairingError::OwnerApprovalUnavailable)), "{name}"),
            }
            assert!(allowance_grants(&f).is_empty(), "{name}");
            assert!(f.svc.lock().file.allowances.get(&f.client).is_none_or(|a| a.windows.is_empty()), "{name}");
        }
    }
    // A window just above 24 h, a zero budget and an overflowing one are
    // refused before anything else, as today.
    let f = fixture(true, true, Some(terms()));
    for bad in [proposal(1_000, 1_000).for_secs(MAX_SPEND_GRANT_TTL_SECS + 1), GrantTerms::new(0), proposal(u64::MAX, 1)] {
        assert!(matches!(
            f.svc.create_budget_elevation_request(&f.client, vec![Scope::Spend], Some(bad)),
            Err(PairingError::Malformed(_))
        ));
    }
    assert!(allowance_grants(&f).is_empty());
}

// ── Switch off = today's behaviour, same fixtures both ways ─────────────

#[test]
fn with_the_switch_off_nothing_changes() {
    for owner_control in [true, false] {
        let on = fixture(owner_control, true, Some(terms()));
        let off = fixture(owner_control, false, Some(terms()));
        assert!(on.svc.standing_allowance_enabled() && !off.svc.standing_allowance_enabled());
        assert!(off.svc.allowance_view(&off.client).is_none(), "off writes no allowance");
        let off_result = off.svc.create_budget_elevation_request(&off.client, vec![Scope::Spend], Some(proposal(1_000_000, PER_CALL)));
        if owner_control {
            assert_eq!(on.svc.allowance_view(&on.client).map(|v| v.set_by), Some(SET_BY_CLI.into()));
            assert_eq!(ask(&on, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
            let op = off_result.unwrap();
            assert_eq!(off.svc.elevation_status(&off.client, &op.op_id).unwrap(), ElevationStatus::Pending);
        } else {
            assert!(matches!(off_result, Err(PairingError::OwnerApprovalUnavailable)));
        }
        assert!(allowance_grants(&off).is_empty());
        assert!(!spend_scope(&off));
    }

    // A window opened while on authorizes nothing once the node restarts off.
    let f = fixture(true, true, Some(terms()));
    let (op, _) = ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
    let f = reopen(f, true, false);
    assert!(!spend_scope(&f));
    assert!(f.svc.grant_view_for(&f.client).is_none());
    assert_ne!(f.svc.elevation_status(&f.client, &op).unwrap(), ElevationStatus::Granted);
    let peer = "aa".repeat(32);
    let call = crate::spend_budget::CallSpendTerms::new(&peer, "c", 2_000, 500, 10).unwrap();
    assert!(f.svc.reserve_call_spend(&f.client, 1, call, u64::MAX / 4).is_err());
    // And a new request takes the owner path.
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Owner);
}

// ── N2-T5 / P09: no owner provenance, no window ─────────────────────────

#[test]
fn a_start_without_owner_control_does_not_honour_a_cli_allowance() {
    let f = fixture(true, true, Some(terms()));
    let (op, _) = ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
    assert!(spend_scope(&f));
    let f = reopen(f, false, true);
    assert!(!spend_scope(&f), "the open window stops authorizing");
    assert_ne!(f.svc.elevation_status(&f.client, &op).unwrap(), ElevationStatus::Granted);
    assert!(matches!(
        f.svc.create_budget_elevation_request(&f.client, vec![Scope::Spend], Some(proposal(1_000_000, PER_CALL))),
        Err(PairingError::OwnerApprovalUnavailable)
    ));
    // Nor does a ticket consumed on such a start attach its terms.
    let f = fixture(false, true, Some(terms()));
    assert!(f.svc.allowance_view(&f.client).is_none());
}

// ── N2-T3 / P11 / P12: the rolling cap ──────────────────────────────────

#[test]
fn renewal_counts_what_the_old_window_used() {
    let f = fixture(true, true, Some(terms()));
    assert_eq!(ask(&f, proposal(2_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    let used = hold(&f, "call-1", 240);
    assert_eq!(used, 600_000);
    // The old window's hold stays counted: 2,500,000 - 600,000 is left.
    assert_eq!(ask(&f, proposal(1_900_001, PER_CALL)).unwrap().1, Outcome::Owner);
    assert_eq!(allowance_grants(&f).len(), 1, "a refused renewal leaves the old window alone");
    assert_eq!(ask(&f, proposal(1_900_000, PER_CALL)).unwrap().1, Outcome::Window);
    let book = ledger(&f);
    assert_eq!(book.committed_msat(now()), DAILY);
    assert_eq!(book.remaining_msat(now()), 0);
    // Renewing an unused window gives its budget back, never more.
    assert_eq!(ask(&f, proposal(1_900_000, PER_CALL)).unwrap().1, Outcome::Window);
    assert_eq!(ask(&f, proposal(1_900_001, PER_CALL)).unwrap().1, Outcome::Owner);
    let live: u64 = allowance_grants(&f).iter().map(|g| g.budget.as_ref().unwrap().budget_msat).sum();
    let ended: u64 = ledger(&f).windows.iter().filter(|w| w.ended_at.is_some()).map(|w| w.committed_msat).sum();
    assert!(live + ended <= DAILY, "{live} + {ended}");
}

#[test]
fn concurrent_requests_share_one_balance() {
    let f = fixture(true, true, Some(terms()));
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    hold(&f, "call-1", 240);
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                barrier.wait();
                let _ = f.svc.create_budget_elevation_request(&f.client, vec![Scope::Spend], Some(proposal(1_900_000, PER_CALL)));
                let peer = "aa".repeat(32);
                let call = crate::spend_budget::CallSpendTerms::new(&peer, &format!("call-{}", rand::random::<u32>()), 2_000, 500, 240).unwrap();
                let _ = f.svc.reserve_call_spend(&f.client, 1, call, u64::MAX / 4);
            });
        }
    });
    let book = ledger(&f);
    let live: Vec<_> = allowance_grants(&f);
    assert_eq!(live.len(), 1, "one window at a time");
    let open = book.windows.iter().filter(|w| w.ended_at.is_none()).count();
    assert_eq!(open, 1);
    assert!(book.committed_msat(now()) <= DAILY);
    // What every window could have spent, together, stays under the cap.
    let ended: u64 = book.windows.iter().filter(|w| w.ended_at.is_some()).map(|w| w.committed_msat).sum();
    assert!(ended + live[0].budget.as_ref().unwrap().budget_msat <= DAILY);
}

#[test]
fn the_ledger_survives_restart_and_expiry() {
    let f = fixture(true, true, Some(terms()));
    assert_eq!(ask(&f, proposal(2_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    hold(&f, "call-1", 240);
    let f = reopen(f, true, true);
    assert_eq!(ask(&f, proposal(1_900_001, PER_CALL)).unwrap().1, Outcome::Owner);
    // The window expires (here: its clock runs out) while the node is down.
    {
        let mut inner = f.svc.lock();
        let grant = inner.file.grants.iter_mut().find(|g| g.granted_by == ALLOWANCE_GRANTED_BY).unwrap();
        grant.granted_at -= 2 * MAX_SPEND_GRANT_TTL_SECS;
        grant.expires_at = now() - 1;
        f.svc.persist(&mut inner.file).unwrap();
    }
    let f = reopen(f, true, true);
    assert!(allowance_grants(&f).is_empty(), "the expired window is gone");
    let book = ledger(&f);
    assert_eq!(book.windows.len(), 1);
    assert_eq!(book.windows[0].committed_msat, 600_000, "an ended window counts what it used");
    assert!(book.windows[0].ended_at.is_some());
    assert_eq!(ask(&f, proposal(1_900_001, PER_CALL)).unwrap().1, Outcome::Owner);
    assert_eq!(ask(&f, proposal(1_900_000, PER_CALL)).unwrap().1, Outcome::Window);
}

/// Deterministic schedule of windows, renewals and spends over forty days,
/// with windows opening right before and after midnight and right at the
/// moment an old window stops counting. In no 24 hours does spending exceed
/// the cap, whatever the schedule.
#[test]
fn no_schedule_of_renewals_exceeds_the_cap_in_any_24_hours() {
    let start = 1_767_225_599; // 31 Dec 23:59:59 UTC
    let cap_terms = AllowanceTerms {
        daily_msat: DAILY,
        per_call_max_msat: PER_CALL,
        until: start + 60 * 86_400,
        breakers: Default::default(),
    };
    let mut book = StandingAllowance::new(cap_terms, SET_BY_CLI, None, 1, "identity", start);
    let mut spends: Vec<(i64, u64)> = Vec::new();
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut next = |m: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % m
    };
    let mut t = start;
    let mut open: Option<(String, i64, GrantBudget)> = None;
    let mut granted = 0;
    while t < start + 40 * 86_400 {
        // Spend inside the open window (spending is only possible there).
        if let Some((_, expires, budget)) = open.as_mut() {
            if t < *expires {
                let want = next(PER_CALL) + 1;
                if budget.used_msat + want <= budget.budget_msat {
                    budget.used_msat += want;
                    spends.push((t, want));
                }
            }
        }
        // Renew at random, sometimes with the largest budget that could fit.
        if next(3) == 0 {
            let budget_msat = match next(3) {
                0 => DAILY,
                1 => book.remaining_msat(t).max(1),
                _ => next(DAILY) + 1,
            };
            let ttl = [60, 3_600, MAX_SPEND_GRANT_TTL_SECS][next(3) as usize];
            let proposal = GrantTerms::new(budget_msat).per_call(budget_msat.min(PER_CALL)).for_secs(ttl);
            let replacing = open.as_ref().filter(|(_, e, _)| t < *e).map(|(op, _, b)| (op.as_str(), b.used_msat));
            if let Ok(ttl) = book.admit(&proposal, replacing, t) {
                if let Some((op, _, budget)) = open.take() {
                    book.end_window(&op, t, Some(&budget));
                }
                let op = format!("w{granted}");
                granted += 1;
                book.open_window(&op, budget_msat, t);
                open = Some((op, t + ttl, GrantBudget::from_terms(&proposal)));
            }
        }
        // Expiry, as the store's sweep records it.
        if let Some((op, expires, budget)) = open.as_ref() {
            if t >= *expires {
                book.end_window(op, *expires, Some(budget));
                open = None;
            }
        }
        book.forget_old_windows(t);
        t += [1, 59, 600, 3_599, 86_399][next(5) as usize] as i64;
    }
    assert!(granted > 20, "the schedule must exercise renewals ({granted})");
    for &(at, _) in &spends {
        let in_day: u64 = spends.iter().filter(|(s, _)| *s > at - ROLLING_SECS && *s <= at).map(|(_, m)| m).sum();
        assert!(in_day <= DAILY, "{in_day} msat in the 24 h ending at {at}");
    }
}

#[test]
fn an_ended_window_counts_until_a_day_after_its_last_possible_spend() {
    let w = AllowanceWindow { op_id: "w".into(), opened_at: 100, committed_msat: 5, ended_at: Some(1_000) };
    let edge = 1_000 + CALL_TAIL_SECS + ROLLING_SECS;
    assert!(w.counts(edge - 1));
    assert!(!w.counts(edge));
    assert!(w.counts(50), "a clock before the window still counts it");
    let live = AllowanceWindow { ended_at: None, ..w };
    assert!(live.counts(i64::MAX));
}

// ── P13 / Q5(a): the clock cannot extend `until`; it ends new windows only

#[test]
fn until_ends_new_windows_and_a_clock_rollback_cannot_reopen_it() {
    let t0 = 1_800_000_000;
    let t = AllowanceTerms { until: t0 + 3_600, ..AllowanceTerms::owner_defaults(t0) };
    let mut book = StandingAllowance::new(t, SET_BY_CLI, None, 1, "identity", t0);
    // A window opened near the end lasts until the end, no longer.
    assert_eq!(book.admit(&proposal(1_000, 1_000), None, t0 + 1_800), Ok(1_800));
    book.open_window("w", 1_000, t0 + 1_800);
    assert_eq!(book.admit(&proposal(1_000, 1_000), None, t0 + 3_570), Err(NoWindow::Ended), "under a minute left");
    assert_eq!(book.admit(&proposal(1_000, 1_000), None, t0 + 3_600), Err(NoWindow::Ended));
    // The node saw t0 + 3,600 once, through a refusal; a clock set back an
    // hour changes nothing.
    assert!(!book.is_live(t0));
    assert_eq!(book.admit(&proposal(1_000, 1_000), None, t0), Err(NoWindow::Ended));
}

#[test]
fn a_window_opened_by_a_live_allowance_never_outlives_it() {
    let f = fixture(true, true, Some(AllowanceTerms { until: now() + 600, ..terms() }));
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    let grant = &allowance_grants(&f)[0];
    assert!(grant.expires_at <= now() + 600);
}

// ── P15: breakers carry over; renewal never resets them ─────────────────

#[test]
fn breakers_are_not_reset_by_renewal_or_expiry() {
    let f = fixture(true, true, Some(terms()));
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    hold(&f, "call-1", 10);
    let first = allowance_grants(&f)[0].budget.clone().unwrap();
    assert_eq!(first.breaker_status(now()).payments_last_hour, 1);
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    let second = allowance_grants(&f)[0].budget.clone().unwrap();
    assert_eq!(second.breaker_state, first.breaker_state, "renewal carries the breaker history");
    assert_eq!(second.breaker_status(now()).payments_last_hour, 1);
    // After expiry the history is kept with the allowance for the next one.
    {
        let mut inner = f.svc.lock();
        let grant = inner.file.grants.iter_mut().find(|g| g.granted_by == ALLOWANCE_GRANTED_BY && g.budget.is_some()).unwrap();
        grant.expires_at = now() - 1;
        f.svc.persist(&mut inner.file).unwrap();
    }
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    let third = allowance_grants(&f)[0].budget.clone().unwrap();
    assert_eq!(third.breaker_state, first.breaker_state);
}

// ── P16 / (c): lowering the cap; revoke dominates ───────────────────────

#[test]
fn a_lower_cap_applies_from_now_and_never_undoes_spending() {
    let t0 = 1_800_000_000;
    let mut book = StandingAllowance::new(AllowanceTerms::owner_defaults(t0), SET_BY_CLI, None, 1, "identity", t0);
    book.open_window("w", 2_000_000, t0);
    let mut used = GrantBudget::from_terms(&GrantTerms::new(2_000_000));
    used.used_msat = 1_800_000;
    book.end_window("w", t0 + 60, Some(&used));
    let lower = StandingAllowance::new(
        AllowanceTerms { daily_msat: 1_000_000, ..AllowanceTerms::owner_defaults(t0 + 60) },
        SET_BY_CLI,
        None,
        1,
        "identity",
        t0 + 60,
    );
    book.replace_terms(lower);
    assert_eq!(book.terms.daily_msat, 1_000_000);
    assert_eq!(book.committed_msat(t0 + 120), 1_800_000, "spending already done stays counted");
    assert_eq!(book.remaining_msat(t0 + 120), 0);
    assert!(matches!(book.admit(&proposal(1, 1), None, t0 + 120), Err(NoWindow::OverDailyCap { remaining_msat: 0 })));
    // Once it ages out, the lower cap is what is left.
    let later = t0 + 60 + CALL_TAIL_SECS + ROLLING_SECS;
    assert_eq!(book.remaining_msat(later), 1_000_000);
}

#[test]
fn revocation_removes_the_allowance_and_its_window() {
    type Revoke = fn(&Fixture);
    let revocations: [(&str, Revoke); 3] = [
        ("revoke grants", |f| {
            f.svc.revoke_grants(Some(&f.client)).unwrap();
        }),
        ("epoch bump", |f| {
            f.svc.bump_epoch(&f.client).unwrap();
        }),
        ("all grants", |f| {
            f.svc.revoke_grants(None).unwrap();
        }),
    ];
    for (name, revoke) in revocations {
        let f = fixture(true, true, Some(terms()));
        assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
        revoke(&f);
        assert!(f.svc.allowance_view(&f.client).is_none(), "{name}");
        assert!(f.svc.reload_from_disk().unwrap().allowances.is_empty(), "{name}");
        assert!(allowance_grants(&f).is_empty(), "{name}");
        assert!(!spend_scope(&f), "{name}");
        assert_eq!(ask(&f, proposal(1_000, 1_000)).unwrap().1, Outcome::Owner, "{name}");
    }
    let f = fixture(true, true, Some(terms()));
    f.svc.revoke(&f.client).unwrap();
    assert!(f.svc.reload_from_disk().unwrap().allowances.is_empty(), "pair revoke");
}

// ── P21: the file stays readable both ways ──────────────────────────────

#[test]
fn a_pairing_file_with_allowance_fields_loads_in_code_without_them() {
    let f = fixture(true, true, Some(terms()));
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    let raw = std::fs::read(f.svc.dir().join("clients.json")).unwrap();
    let mut json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(json["version"], serde_json::json!(PAIRING_FILE_VERSION), "no version bump: older nodes keep reading it");
    assert!(json.get("allowances").is_some());
    // Code without the field ignores it: every struct on the path tolerates
    // unknown fields, which is how an older node reads this file.
    json["allowances_from_a_later_version"] = json["allowances"].clone();
    json["clients"][0]["allowance_from_a_later_version"] = serde_json::json!({"daily_msat": 1});
    json["grants"][0]["field_from_a_later_version"] = serde_json::json!(1);
    let parsed: PairingFile = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(parsed.clients.len(), 1);
    // Without the field, nothing is opted in.
    let mut base = json;
    base.as_object_mut().unwrap().remove("allowances");
    let parsed: PairingFile = serde_json::from_value(base.clone()).unwrap();
    assert!(parsed.allowances.is_empty());
    std::fs::write(f.svc.dir().join("clients.json"), serde_json::to_vec(&base).unwrap()).unwrap();
    let f = reopen(f, true, true);
    assert!(f.svc.allowance_view(&f.client).is_none());
    assert!(allowance_grants(&f).is_empty(), "a window without its allowance is dropped");
    assert!(!spend_scope(&f));
    assert_eq!(ask(&f, proposal(1_000, 1_000)).unwrap().1, Outcome::Owner);
    // A file with no allowance written by this code has no new key at all.
    let plain = fixture(true, true, None);
    assert!(!String::from_utf8(std::fs::read(plain.svc.dir().join("clients.json")).unwrap()).unwrap().contains("allowance"));
}

#[test]
fn allowance_terms_refuse_what_cannot_be_enforced() {
    let t0 = 1_800_000_000;
    assert_eq!(AllowanceTerms::owner_defaults(t0).daily_msat, DAILY);
    assert_eq!(AllowanceTerms::owner_defaults(t0).per_call_max_msat, PER_CALL);
    assert_eq!(AllowanceTerms::owner_defaults(t0).until, t0 + 30 * 86_400);
    for (daily, per_call, days) in [(0, 1, 1), (1, 0, 1), (1, 2, 1), (1, 1, 0), (1, 1, 366), (u64::MAX, 1, 1), (100_000_001, 1, 1)] {
        assert!(AllowanceTerms::from_sats(daily, per_call, days, t0).is_err(), "{daily} {per_call} {days}");
    }
    assert!(AllowanceTerms::from_sats(1, 1, 365, t0).is_ok());
}

// ── Review follow-ups: clock monotonicity, ledger retention, status ─────

/// A request refused because the allowance ended records that time, so a
/// clock set back afterwards cannot open a window.
#[test]
fn a_refusal_at_the_end_date_survives_a_clock_set_back() {
    let t0 = 1_800_000_000;
    let terms = AllowanceTerms { until: t0 + 3_600, ..AllowanceTerms::owner_defaults(t0) };
    let mut book = StandingAllowance::new(terms, SET_BY_CLI, None, 1, "identity", t0);
    assert_eq!(book.admit(&proposal(1_000, 1_000), None, t0 + 3_600), Err(NoWindow::Ended));
    assert_eq!(book.admit(&proposal(1_000, 1_000), None, t0 + 60), Err(NoWindow::Ended), "clock set back");
    assert!(!book.is_live(t0));
}

#[test]
fn a_refused_request_persists_the_time_it_saw() {
    let real = now();
    let until = real + 3_600;
    let f = fixture(true, true, Some(AllowanceTerms { until, ..terms() }));
    let open_at = |f: &Fixture, at: i64| {
        let mut inner = f.svc.lock();
        let client = inner.file.clients.iter().find(|c| c.client_id == f.client).unwrap().clone();
        f.svc
            .open_allowance_window(&mut inner, &client, &[Scope::Spend], &proposal(1_000, 1_000), at)
            .unwrap()
            .map(|op| op.op_id)
    };
    assert_eq!(open_at(&f, until), Err(NoWindow::Ended));
    // The node restarts and its clock reads earlier than what it saw.
    let f = reopen(f, true, true);
    assert_eq!(open_at(&f, real + 60), Err(NoWindow::Ended));
    assert!(allowance_grants(&f).is_empty());
    assert!(ledger(&f).observed_at >= until);
}

/// A clock that jumps forward and comes back must not lose ledger entries
/// that count again once it is back.
#[test]
fn a_forward_clock_jump_does_not_forget_spending() {
    let t0 = 1_800_000_000;
    let mut book = StandingAllowance::new(AllowanceTerms::owner_defaults(t0), SET_BY_CLI, None, 1, "identity", t0);
    book.open_window("a", 2_000_000, t0);
    let mut used = GrantBudget::from_terms(&GrantTerms::new(2_000_000));
    used.used_msat = 2_000_000;
    book.end_window("a", t0 + 60, Some(&used));
    // Ten days ahead, the old window no longer counts, and the store tidies up.
    let ahead = t0 + 10 * 86_400;
    assert_eq!(book.remaining_msat(ahead), DAILY);
    book.forget_old_windows(ahead);
    book.open_window("b", 400_000, ahead);
    // Back to the real time: both windows count.
    let back = t0 + 120;
    assert!(book.committed_msat(back) >= 2_400_000, "{}", book.committed_msat(back));
    assert!(book.remaining_msat(back) <= DAILY - 2_400_000);
    assert!(matches!(book.admit(&proposal(200_000, 200_000), None, back), Err(NoWindow::OverDailyCap { .. })));
    // Tidying keeps the ledger small without losing anything that counts.
    for i in 0..100 {
        let op = format!("w{i}");
        book.open_window(&op, 1, ahead + i);
        book.end_window(&op, ahead + i, Some(&GrantBudget::from_terms(&GrantTerms::new(1))));
    }
    book.forget_old_windows(ahead + 30 * 86_400);
    assert!(book.windows.len() <= 3, "{}", book.windows.len());
    assert!(book.committed_msat(back) >= 2_400_000);
}

#[test]
fn an_over_cap_request_stays_pending_while_a_window_is_live() {
    let f = fixture(true, true, Some(terms()));
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    let (op, outcome) = ask(&f, proposal(DAILY + 1, PER_CALL)).unwrap();
    assert_eq!(outcome, Outcome::Owner);
    assert_eq!(f.svc.elevation_status(&f.client, &op).unwrap(), ElevationStatus::Pending);
    assert_eq!(allowance_grants(&f).len(), 1, "the live window is untouched");
}

/// The store's own sweep also records the time, so an allowance whose end the
/// node has seen stays ended even if no request was made at that time.
#[test]
fn the_sweep_latches_the_end_date_without_a_request() {
    let real = now();
    let f = fixture(true, true, Some(terms()));
    let until = real - 1;
    {
        let mut inner = f.svc.lock();
        let allowance = inner.file.allowances.get_mut(&f.client).unwrap();
        allowance.terms.until = until;
        allowance.observed_at = until - 3_600;
        f.svc.persist(&mut inner.file).unwrap();
    }
    let f = reopen(f, true, true);
    assert!(ledger(&f).observed_at >= real, "the write recorded the time it saw");
    let mut inner = f.svc.lock();
    let client = inner.file.clients.iter().find(|c| c.client_id == f.client).unwrap().clone();
    let opened = f
        .svc
        .open_allowance_window(&mut inner, &client, &[Scope::Spend], &proposal(1_000, 1_000), until - 1_800)
        .unwrap()
        .map(|op| op.op_id);
    assert_eq!(opened, Err(NoWindow::Ended));
}

// ── The per-call cap bounds the whole call ──────────────────────────────
// The allowance's per-call cap is what one call may reserve in all: its hold
// (minutes and closing signal) and its offers. A window opened from it
// carries the same number as an ordinary grant's per-payment limit, which
// alone would bound only each block.

fn call_window() -> Fixture {
    let f = fixture(true, true, Some(terms()));
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
    f
}

fn call(id: &str, price: u64, minutes: u16) -> crate::spend_budget::CallSpendTerms {
    crate::spend_budget::CallSpendTerms::new(&"aa".repeat(32), id, price, 500, minutes).unwrap()
}

fn window_used(f: &Fixture) -> u64 {
    allowance_grants(f)[0].budget.as_ref().unwrap().used_msat
}

fn offer_link(id: &str) -> crate::spend_budget::OperationReservationLink {
    crate::spend_budget::OperationReservationLink { operation_id: id.into(), execution_id: "attempt".into(), readmission: false }
}

#[test]
fn a_standing_allowance_accepts_a_call_at_its_whole_call_cap() {
    let f = call_window();
    let at_cap = call("at-cap", 3_000, 200);
    assert_eq!(at_cap.reserved_msat, PER_CALL);
    f.svc.reserve_call_spend(&f.client, 1, at_cap, u64::MAX / 4).unwrap();
    assert_eq!(window_used(&f), PER_CALL);
}

#[test]
fn a_standing_allowance_refuses_a_call_above_its_whole_call_cap() {
    let f = call_window();
    let above = call("above-cap", 3_500, 200);
    assert_eq!(above.reserved_msat, 800_000);
    let result = f.svc.reserve_call_spend(&f.client, 1, above, u64::MAX / 4);
    assert!(matches!(result, Err(BudgetRefusal::PerCall { max_msat: PER_CALL })), "{result:?}");
    assert_eq!(window_used(&f), 0, "a refusal leaves the window untouched");
    assert!(allowance_grants(&f)[0].budget.as_ref().unwrap().call_reservations.is_empty());
}

#[test]
fn the_whole_call_cap_counts_the_closing_signal_and_every_offer() {
    let peer = "aa".repeat(32);
    let offer = |msat| vec![Charge { recipient: peer.clone(), amount_msat: msat }];
    // Closing signal included: 199 minutes plus closing past the cap.
    let f = call_window();
    let closing = call("closing", 3_000, 200).with_closing_signal(1, 0).unwrap();
    assert_eq!(closing.reserved_msat, PER_CALL + 1_000);
    assert!(matches!(
        f.svc.reserve_call_spend(&f.client, 1, closing, u64::MAX / 4),
        Err(BudgetRefusal::PerCall { max_msat: PER_CALL })
    ));
    // Hold plus offer exactly at the cap is accepted ...
    let hold = call("with-offer", 3_000, 199);
    assert_eq!(hold.reserved_msat + 3_500, PER_CALL);
    f.svc
        .reserve_call_with_offer(&f.client, 1, hold, u64::MAX / 4, offer(3_500), None, offer_link("offer-1"))
        .unwrap();
    assert_eq!(window_used(&f), PER_CALL);
    // ... and one more offer for the same call is not.
    let again = f.svc.reserve_call_offer_spend(&f.client, 1, offer(1), "with-offer", None, offer_link("offer-2"));
    assert!(matches!(again, Err(BudgetRefusal::PerCall { max_msat: PER_CALL })), "{again:?}");
    assert_eq!(window_used(&f), PER_CALL, "the refused offer reserved nothing");
    // A hold at the cap with any offer is refused as a whole: no hold kept.
    let f = call_window();
    let full = call("full", 3_000, 200);
    let refused = f.svc.reserve_call_with_offer(&f.client, 1, full, u64::MAX / 4, offer(1), None, offer_link("offer-3"));
    assert!(matches!(refused, Err(BudgetRefusal::PerCall { max_msat: PER_CALL })), "{refused:?}");
    assert_eq!(window_used(&f), 0);
    assert!(allowance_grants(&f)[0].budget.as_ref().unwrap().call_reservations.is_empty());
    // The offer count survives a restart.
    let f = call_window();
    f.svc
        .reserve_call_with_offer(&f.client, 1, call("kept", 3_000, 199), u64::MAX / 4, offer(3_500), None, offer_link("offer-4"))
        .unwrap();
    let f = reopen(f, true, true);
    assert!(f.svc.reserve_call_offer_spend(&f.client, 1, offer(1), "kept", None, offer_link("offer-5")).is_err());
}

#[test]
fn an_owner_window_keeps_its_per_payment_meaning() {
    // The same numbers in an owner-written window: its per-call maximum
    // bounds each payment, as before, so the 800,000-msat hold is accepted.
    let f = fixture(true, true, None);
    {
        let mut inner = f.svc.lock();
        let epoch = inner.file.clients[0].epoch;
        let now = now();
        inner.file.grants.push(SpendGrant {
            owner_approval: None,
            op_id: "owner".into(),
            client_id: f.client.clone(),
            scopes: vec![Scope::Spend],
            granted_at: now,
            expires_at: now + 600,
            identity_fingerprint: "identity".into(),
            epoch,
            granted_by: "cli".into(),
            budget: Some(GrantBudget::from_terms(&proposal(1_000_000, PER_CALL))),
            ended: None,
        });
        f.svc.persist(&mut inner.file).unwrap();
    }
    f.svc.reserve_call_spend(&f.client, 1, call("owner-call", 3_500, 200), u64::MAX / 4).unwrap();
}

// ── With live-call continuity ([calls] call_continuity_v1) ──────────────
// A call admitted inside an allowance window keeps its hold when that window
// expires or the allowance opens the next one; the allowance still counts
// everything the call can pay. Every case also runs with continuity off.

const MINUTE: u64 = 1_000;
const MINUTES: u16 = 5;

fn continuity_fixture(continuity: bool) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let svc = PairingService::open(dir.path(), "identity".into(), true)
        .unwrap()
        .with_standing_allowance(true)
        .with_call_continuity(continuity);
    let key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
    let client = svc
        .create_ticket_remote_pairing_with_allowance(
            "app",
            &hex::encode(key.verifying_key().to_bytes()),
            &[22; 32],
            "ticket-code",
            Some(&terms()),
        )
        .unwrap()
        .client_id;
    Fixture { _dir: dir, svc, client }
}

fn binding(f: &Fixture) -> auth::PairingBinding {
    auth::PairingBinding { client_id: f.client.clone(), epoch: 1, fingerprint: "identity".into() }
}

fn admit_call(f: &Fixture, id: &str) {
    let peer = "aa".repeat(32);
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, id, MINUTE, 0, MINUTES).unwrap();
    f.svc.reserve_call_spend(&f.client, 1, terms, 1_000_000).unwrap();
    let b = binding(f);
    f.svc.remember_call_client(Some(&b), &peer, id, "invite", "request").unwrap();
    f.svc.commit_call_client(None, &peer, id, "invite", "request").unwrap();
    f.svc.finish_call_client(&peer, id, "invite", "request");
}

fn draw_block(f: &Fixture, id: &str, seq: u32) -> Result<Reservation, BudgetRefusal> {
    f.svc.draw_call_spend(&f.client, 1, &"aa".repeat(32), id, seq, MINUTE, 0, offer_link(&format!("{id}-{seq}")))
}

fn pay_block(f: &Fixture, id: &str, seq: u32) {
    let debit = draw_block(f, id, seq).unwrap_or_else(|e| panic!("block {seq}: {e:?}"));
    f.svc.try_resolve_spend(&debit, &"aa".repeat(32), MINUTE).unwrap();
}

fn window_committed(f: &Fixture, op: &str) -> Option<(u64, bool)> {
    ledger(f).windows.iter().find(|w| w.op_id == op).map(|w| (w.committed_msat, w.ended_at.is_some()))
}

#[test]
fn the_next_allowance_window_carries_an_admitted_call_once() {
    for continuity in [true, false] {
        let f = continuity_fixture(continuity);
        let (first, _) = ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
        admit_call(&f, "call");
        pay_block(&f, "call", 0);
        let in_flight = draw_block(&f, "call", 1).unwrap();
        let (second, outcome) = ask(&f, proposal(900_000, PER_CALL)).unwrap();
        assert_eq!(outcome, Outcome::Window);
        // The old window counts what stayed with it: with continuity the
        // minute paid there (the rest of the hold moved on), without it the
        // whole hold (nothing moved).
        let kept = if continuity { MINUTE } else { u64::from(MINUTES) * MINUTE };
        assert_eq!(window_committed(&f, &first), Some((kept, true)), "{continuity}");
        let next = allowance_grants(&f).into_iter().find(|g| g.op_id == second).unwrap();
        let budget = next.budget.unwrap();
        if continuity {
            assert_eq!(budget.call_reservations.len(), 1, "the call moved to the new window");
            assert_eq!(budget.used_msat, u64::from(MINUTES - 1) * MINUTE, "only what the hold still had moved");
            // The block in flight settles once, where the call now lives.
            f.svc.try_resolve_spend(&in_flight, &"aa".repeat(32), MINUTE).unwrap();
            f.svc.try_resolve_spend(&in_flight, &"aa".repeat(32), MINUTE).unwrap();
            let status = f.svc.call_spend_status(&"aa".repeat(32), "call").unwrap();
            assert_eq!(status.spent_msat, 2 * MINUTE);
            pay_block(&f, "call", 2);
            assert!(f.svc.call_hold_live(&binding(&f), &"aa".repeat(32), "call"));
        } else {
            assert!(budget.call_reservations.is_empty(), "as before: a renewal ends the call's hold");
            assert!(draw_block(&f, "call", 2).is_err());
        }
        // Everything the call can pay is in the day's count, once.
        let book = ledger(&f);
        assert_eq!(book.committed_msat(now()), kept + 900_000, "{continuity}");
    }
}

#[test]
fn an_expired_allowance_window_keeps_its_admitted_call_and_counts_it() {
    for continuity in [true, false] {
        let f = continuity_fixture(continuity);
        let (op, _) = ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
        admit_call(&f, "call");
        pay_block(&f, "call", 0);
        {
            let mut inner = f.svc.lock_without_cleanup();
            let grant = inner.file.grants.iter_mut().find(|g| g.op_id == op).unwrap();
            let length = grant.expires_at - grant.granted_at;
            grant.expires_at = now() - 1;
            grant.granted_at = grant.expires_at - length;
        }
        let file = f.svc.reload_from_disk().unwrap();
        let kept = file.grants.iter().find(|g| g.op_id == op);
        if continuity {
            // Kept, with its budget, to finish the call: not an orphan. Its
            // window counts at least the whole hold.
            assert!(kept.is_some_and(|g| g.budget.is_some()), "the call's grant was dropped");
            let (counted, _) = window_committed(&f, &op).unwrap();
            assert!((u64::from(MINUTES) * MINUTE..=1_000_000).contains(&counted), "{counted}");
            pay_block(&f, "call", 1);
            assert!(f.svc.call_hold_live(&binding(&f), &"aa".repeat(32), "call"));
            // No new spending on the ended window.
            let second = crate::spend_budget::CallSpendTerms::new(&"aa".repeat(32), "second", MINUTE, 0, MINUTES).unwrap();
            assert_eq!(f.svc.reserve_call_spend(&f.client, 1, second, 1_000_000), Err(BudgetRefusal::NoGrant));
            // The call ends: the grant goes. Its window ended at the grant's
            // expiry with the whole hold counted; the release afterwards
            // never lowers that, so the day's count stays an upper bound.
            let hold = f.svc.call_spend_holds().into_iter().map(|(r, _)| r).next().unwrap();
            f.svc.close_call_spend(&hold).unwrap();
            let _ = f.svc.reload_from_disk().unwrap();
            assert!(allowance_grants(&f).is_empty());
            assert_eq!(window_committed(&f, &op), Some((u64::from(MINUTES) * MINUTE, true)));
        } else {
            assert!(kept.is_none());
            assert_eq!(window_committed(&f, &op), Some((u64::from(MINUTES) * MINUTE, true)));
            assert!(draw_block(&f, "call", 1).is_err());
            // The next window has room for everything but what was used.
            assert_eq!(ask(&f, proposal(DAILY - u64::from(MINUTES) * MINUTE + 1, PER_CALL)).unwrap().1, Outcome::Owner);
            assert_eq!(ask(&f, proposal(DAILY - u64::from(MINUTES) * MINUTE, PER_CALL)).unwrap().1, Outcome::Window);
        }
    }
}

#[test]
fn a_revocation_ends_a_call_kept_past_its_allowance_window() {
    let f = continuity_fixture(true);
    let (op, _) = ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
    admit_call(&f, "call");
    pay_block(&f, "call", 0);
    {
        let mut inner = f.svc.lock_without_cleanup();
        let grant = inner.file.grants.iter_mut().find(|g| g.op_id == op).unwrap();
        let length = grant.expires_at - grant.granted_at;
        grant.expires_at = now() - 1;
        grant.granted_at = grant.expires_at - length;
    }
    let _ = f.svc.reload_from_disk().unwrap();
    pay_block(&f, "call", 1);
    f.svc.revoke_grants(Some(&f.client)).unwrap();
    assert!(draw_block(&f, "call", 2).is_err());
    assert!(!f.svc.call_hold_live(&binding(&f), &"aa".repeat(32), "call"));
    assert!(f.svc.reload_from_disk().unwrap().allowances.is_empty());
    assert!(allowance_grants(&f).is_empty());
}

#[test]
fn an_epoch_bump_ends_a_carried_call_and_the_allowance() {
    let f = continuity_fixture(true);
    ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
    admit_call(&f, "call");
    pay_block(&f, "call", 0);
    ask(&f, proposal(900_000, PER_CALL)).unwrap();
    f.svc.bump_epoch(&f.client).unwrap();
    assert!(draw_block(&f, "call", 1).is_err());
    assert!(f.svc.reload_from_disk().unwrap().allowances.is_empty());
    assert!(allowance_grants(&f).is_empty());
}

/// A write that fails leaves the window, the call, its offers and the day's
/// count exactly as they were.
#[cfg(unix)]
#[test]
fn a_failed_write_changes_nothing() {
    use std::os::unix::fs::PermissionsExt;
    let f = continuity_fixture(true);
    let (first, _) = ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
    let peer = "aa".repeat(32);
    f.svc
        .reserve_call_with_offer(&f.client, 1, call("call", 3_000, 10), u64::MAX / 4,
            vec![Charge { recipient: peer.clone(), amount_msat: 3_500 }], None, offer_link("offer-1"))
        .unwrap();
    let before = f.svc.lock().file.clone();
    let dir = f.svc.dir().to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let probe = std::fs::write(dir.join("probe"), b"x").is_ok();
    let renew = f.svc.create_budget_elevation_request(&f.client, vec![Scope::Spend], Some(proposal(900_000, PER_CALL)));
    let offer = f.svc.reserve_call_offer_spend(&f.client, 1,
        vec![Charge { recipient: peer.clone(), amount_msat: 1 }], "call", None, offer_link("offer-2"));
    let after = f.svc.lock().file.clone();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    if probe {
        return; // The directory stayed writable (a privileged run); nothing to test.
    }
    assert!(renew.is_err() && offer.is_err(), "{renew:?} {offer:?}");
    assert_eq!(after.allowances, before.allowances, "ledger and offer count unchanged");
    assert_eq!(after.grants, before.grants, "windows and holds unchanged");
    assert_eq!(after.call_spend_grants, before.call_spend_grants);
    assert!(allowance_grants(&f).iter().any(|g| g.op_id == first));
}

// ── Unresolved payments across automatic renewals ───────────────────────
// A payment whose outcome is unknown holds a failure slot of the breaker.
// Opening the next allowance window must not free those slots, and the
// payment's late outcome must still count where its slot now lives.

fn payment(f: &Fixture, n: u32) -> Result<Reservation, BudgetRefusal> {
    f.svc.reserve_operation_spend(&f.client, 1, vec![Charge { recipient: "aa".repeat(32), amount_msat: 10 }],
        offer_link(&format!("payment-{n}")))
}

fn live_breakers(f: &Fixture) -> crate::spend_budget::BreakerStatus {
    allowance_grants(f)
        .into_iter()
        .find(|g| g.is_live(now()))
        .unwrap()
        .budget
        .unwrap()
        .breaker_status(now())
}

/// Five unresolved payments fill the five failure slots of the default breakers.
fn fill_failure_slots(f: &Fixture) -> Vec<Reservation> {
    let slots = terms().breakers.max_consecutive_failures as u32;
    let open: Vec<_> = (0..slots).map(|n| payment(f, n).unwrap()).collect();
    assert_eq!(payment(f, 99), Err(BudgetRefusal::FailuresPending));
    open
}

#[test]
fn a_renewal_does_not_free_the_failure_slots_of_unresolved_payments() {
    for continuity in [false, true] {
        let f = continuity_fixture(continuity);
        ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
        fill_failure_slots(&f);
        assert_eq!(ask(&f, proposal(900_000, PER_CALL)).unwrap().1, Outcome::Window);
        assert_eq!(live_breakers(&f).unresolved_payments, 5, "{continuity}");
        assert_eq!(payment(&f, 100), Err(BudgetRefusal::FailuresPending), "{continuity}");
        // Nor does a second renewal.
        ask(&f, proposal(800_000, PER_CALL)).unwrap();
        assert_eq!(payment(&f, 101), Err(BudgetRefusal::FailuresPending), "{continuity}");
    }
}

#[test]
fn an_old_window_payment_that_fails_after_renewal_counts_and_trips_the_breaker() {
    for continuity in [false, true] {
        let f = continuity_fixture(continuity);
        ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
        let open = fill_failure_slots(&f);
        ask(&f, proposal(900_000, PER_CALL)).unwrap();
        let peer = "aa".repeat(32);
        f.svc.try_resolve_spend(&open[0], &peer, 0).unwrap();
        f.svc.try_resolve_spend(&open[0], &peer, 0).unwrap();
        let status = live_breakers(&f);
        assert_eq!((status.consecutive_failures, status.unresolved_payments), (1, 4), "{continuity}");
        for reservation in &open[1..] {
            f.svc.try_resolve_spend(reservation, &peer, 0).unwrap();
        }
        assert!(live_breakers(&f).paused, "five failures pause the window ({continuity})");
        assert_eq!(payment(&f, 100), Err(BudgetRefusal::GrantPaused));
        // The paused state carries into the next window too.
        ask(&f, proposal(800_000, PER_CALL)).unwrap();
        assert_eq!(payment(&f, 101), Err(BudgetRefusal::GrantPaused), "{continuity}");
    }
}

#[test]
fn an_old_window_payment_that_succeeds_after_renewal_frees_its_slot() {
    for continuity in [false, true] {
        let f = continuity_fixture(continuity);
        ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
        let open = fill_failure_slots(&f);
        ask(&f, proposal(900_000, PER_CALL)).unwrap();
        let peer = "aa".repeat(32);
        f.svc.try_resolve_spend(&open[0], &peer, 0).unwrap();
        f.svc.try_resolve_spend(&open[1], &peer, 10).unwrap();
        let status = live_breakers(&f);
        assert_eq!((status.consecutive_failures, status.unresolved_payments), (0, 3), "a success clears ({continuity})");
        payment(&f, 100).expect("the freed slot can be used");
        let next = allowance_grants(&f).into_iter().find(|g| g.is_live(now())).unwrap().budget.unwrap();
        // The settled payment is paid once, in the window that holds it.
        assert_eq!(next.used_msat, 3 * 10 + 10 + 10, "{continuity}");
    }
}

#[test]
fn a_carried_call_and_carried_payments_are_each_counted_once() {
    let f = continuity_fixture(true);
    ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
    admit_call(&f, "call");
    for n in 0..4 {
        payment(&f, n).unwrap();
    }
    assert_eq!(live_breakers(&f).unresolved_payments, 5);
    ask(&f, proposal(900_000, PER_CALL)).unwrap();
    assert_eq!(live_breakers(&f).unresolved_payments, 5);
    assert_eq!(payment(&f, 100), Err(BudgetRefusal::FailuresPending));
}

// ── Carried calls first, then carried payments ──────────────────────────

#[test]
fn a_live_call_is_carried_before_payments_take_the_next_window() {
    let f = continuity_fixture(true);
    ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
    // A call holding 600,000 msat, and four payments still in flight.
    let peer = "aa".repeat(32);
    let big = crate::spend_budget::CallSpendTerms::new(&peer, "call", 2_000, 500, 240).unwrap();
    assert_eq!(big.reserved_msat, 600_000);
    f.svc.reserve_call_spend(&f.client, 1, big, u64::MAX / 4).unwrap();
    for n in 0..4 {
        payment(&f, n).unwrap();
    }
    // The next window fits the call on its own, not the call plus payments.
    let (next, outcome) = ask(&f, proposal(600_020, 600_020)).unwrap();
    assert_eq!(outcome, Outcome::Window);
    let budget = allowance_grants(&f).into_iter().find(|g| g.op_id == next).unwrap().budget.unwrap();
    assert_eq!(budget.call_reservations.len(), 1, "the admitted call was dropped");
    // The payments moved too, past the budget: they are already sent.
    assert_eq!(budget.used_msat, 600_000 + 40);
    assert_eq!(budget.breaker_status(now()).unresolved_payments, 5);
    assert_eq!(payment(&f, 100), Err(BudgetRefusal::FailuresPending));
    // One payment settles at its amount: its slot frees, the money stays
    // used, and with the window already past its budget a new payment is
    // refused for money, not for slots.
    f.svc.try_resolve_spend(&first_payment(&f), &peer, 10).unwrap();
    let budget = allowance_grants(&f).into_iter().find(|g| g.op_id == next).unwrap().budget.unwrap();
    assert_eq!((budget.used_msat, budget.remaining_msat()), (600_040, 0));
    assert_eq!(budget.breaker_status(now()).unresolved_payments, 4);
    assert_eq!(payment(&f, 101), Err(BudgetRefusal::Total { remaining_msat: 0 }));
    assert_eq!(window_used(&f), 600_040);
}

fn first_payment(f: &Fixture) -> Reservation {
    let grant = allowance_grants(f).into_iter().find(|g| g.is_live(now())).unwrap();
    let budget = grant.budget.unwrap();
    let id = budget
        .pending
        .keys()
        .find(|id| !budget.call_reservations.contains_key(*id))
        .unwrap()
        .clone();
    Reservation { id, client_id: f.client.clone(), op_id: grant.op_id, charges: vec![] }
}

// ── An allowance never replaces an owner-written window ─────────────────

fn push_owner_grant(f: &Fixture, terms: GrantTerms, expires_in: i64) -> SpendGrant {
    let mut inner = f.svc.lock();
    let epoch = inner.file.clients.iter().find(|c| c.client_id == f.client).unwrap().epoch;
    let now = now();
    let grant = SpendGrant {
        owner_approval: None,
        op_id: "owner-window".into(),
        client_id: f.client.clone(),
        scopes: vec![Scope::Spend],
        granted_at: now,
        expires_at: now + expires_in,
        identity_fingerprint: "identity".into(),
        epoch,
        granted_by: "cli".into(),
        budget: Some(GrantBudget::from_terms(&terms)),
        ended: None,
    };
    inner.file.grants.push(grant.clone());
    f.svc.persist(&mut inner.file).unwrap();
    grant
}

#[test]
fn a_live_owner_window_is_never_replaced_by_the_allowance() {
    for continuity in [false, true] {
        let f = continuity_fixture(continuity);
        let mut terms = GrantTerms::new(5_000_000).per_call(PER_CALL);
        terms.allow_liquidity_fees = true;
        let owner = push_owner_grant(&f, terms, 3_600);
        payment(&f, 0).unwrap();
        let before = f.svc.lock().file.grants.iter().find(|g| g.op_id == owner.op_id).cloned().unwrap();
        // The app asks within its allowance: the owner's window governs, and
        // the request takes the owner path.
        let (_, outcome) = ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
        assert_eq!(outcome, Outcome::Owner, "{continuity}");
        let after = f.svc.lock().file.grants.iter().find(|g| g.op_id == owner.op_id).cloned().unwrap();
        assert_eq!(after, before, "the owner's window changed ({continuity})");
        assert!(after.is_live(now()));
        assert!(allowance_grants(&f).is_empty());
        assert!(ledger(&f).windows.is_empty(), "nothing counted against the allowance");
    }
}

#[test]
fn the_allowance_opens_again_once_the_owner_window_is_over() {
    let f = continuity_fixture(false);
    push_owner_grant(&f, GrantTerms::new(5_000_000).per_call(PER_CALL), 3_600);
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Owner);
    f.svc.revoke_grants(Some(&f.client)).ok();
    // Revoking also removed the allowance: re-pairing is the owner's way back.
    assert!(f.svc.allowance_view(&f.client).is_none());
    let f = continuity_fixture(false);
    push_owner_grant(&f, GrantTerms::new(5_000_000).per_call(PER_CALL), 3_600);
    {
        let mut inner = f.svc.lock_without_cleanup();
        let g = inner.file.grants.iter_mut().find(|g| g.op_id == "owner-window").unwrap();
        g.granted_at -= 7_200;
        g.expires_at = now() - 1;
    }
    let _ = f.svc.reload_from_disk().unwrap();
    assert_eq!(ask(&f, proposal(1_000_000, PER_CALL)).unwrap().1, Outcome::Window);
}

// ── Payment identities survive an automatic renewal ─────────────────────

#[test]
fn a_payment_in_flight_cannot_be_paid_again_after_a_renewal() {
    for continuity in [false, true] {
        let f = continuity_fixture(continuity);
        ask(&f, proposal(1_000_000, PER_CALL)).unwrap();
        let pay = |id: &str| f.svc.reserve_payment(&f.client, 1,
            vec![Charge { recipient: "bb".repeat(33), amount_msat: 1_000 }], vec![id.to_string()]);
        pay("payment-x").unwrap();
        assert_eq!(pay("payment-x"), Err(BudgetRefusal::DuplicatePayment));
        ask(&f, proposal(900_000, PER_CALL)).unwrap();
        let used = window_used(&f);
        assert_eq!(pay("payment-x"), Err(BudgetRefusal::DuplicatePayment), "{continuity}");
        assert_eq!(window_used(&f), used, "no second debit ({continuity})");
        // Through a second renewal as well.
        ask(&f, proposal(800_000, PER_CALL)).unwrap();
        assert_eq!(pay("payment-x"), Err(BudgetRefusal::DuplicatePayment), "{continuity}");
        // Another identity still pays.
        pay("payment-y").unwrap();
    }
}

// ── Each transferred liability counts once in the day ───────────────────
// A renewal moves payments in flight and (with continuity) admitted calls to
// the new window. What moved counts on the new window only; what was paid,
// or did not move, stays on the window it was spent in.

const DAY: u64 = 1_000_000;

fn day_terms(daily: u64) -> AllowanceTerms {
    AllowanceTerms {
        daily_msat: daily,
        per_call_max_msat: 700_000,
        breakers: crate::spend_budget::BreakerLimits { max_msat_per_10_minutes: 10_000_000, ..Default::default() },
        ..AllowanceTerms::owner_defaults(now())
    }
}

fn day_fixture(continuity: bool, daily: u64) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let svc = PairingService::open(dir.path(), "identity".into(), true)
        .unwrap()
        .with_standing_allowance(true)
        .with_call_continuity(continuity);
    let key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
    let client = svc
        .create_ticket_remote_pairing_with_allowance(
            "app", &hex::encode(key.verifying_key().to_bytes()), &[22; 32], "ticket-code", Some(&day_terms(daily)),
        )
        .unwrap()
        .client_id;
    Fixture { _dir: dir, svc, client }
}

fn ln_payment(f: &Fixture, id: &str, msat: u64) -> Result<Reservation, BudgetRefusal> {
    f.svc.reserve_payment(&f.client, 1, vec![Charge { recipient: "bb".repeat(33), amount_msat: msat }], vec![id.into()])
}

fn day_total(f: &Fixture) -> u64 {
    ledger(f).committed_msat(now())
}

fn snapshot(f: &Fixture) -> (Vec<SpendGrant>, BTreeMap<String, StandingAllowance>) {
    let inner = f.svc.lock();
    (inner.file.grants.clone(), inner.file.allowances.clone())
}

#[test]
fn a_renewal_counts_moved_payments_once_and_admits_up_to_the_cap() {
    for continuity in [false, true] {
        let f = day_fixture(continuity, DAY);
        let (w1, _) = ask(&f, proposal(400_000, 300_000)).unwrap();
        let paid = ln_payment(&f, "paid", 100_000).unwrap();
        f.svc.try_resolve_spend(&paid, &"bb".repeat(33), 100_000).unwrap();
        ln_payment(&f, "pending", 200_000).unwrap();
        // 100,000 paid stays on the first window; the 200,000 in flight moves.
        let before = snapshot(&f);
        assert_eq!(ask(&f, proposal(900_001, 300_000)).unwrap().1, Outcome::Owner, "{continuity}");
        let after = snapshot(&f);
        assert_eq!(after.0.iter().filter(|g| g.granted_by == ALLOWANCE_GRANTED_BY).cloned().collect::<Vec<_>>(),
            before.0.iter().filter(|g| g.granted_by == ALLOWANCE_GRANTED_BY).cloned().collect::<Vec<_>>(),
            "a refused renewal changes no window ({continuity})");
        assert_eq!(after.1[&f.client].windows, before.1[&f.client].windows, "nor the day's count ({continuity})");
        let (w2, outcome) = ask(&f, proposal(900_000, 300_000)).unwrap();
        assert_eq!(outcome, Outcome::Window, "{continuity}");
        assert_eq!(window_committed(&f, &w1), Some((100_000, true)), "{continuity}");
        assert_eq!(window_committed(&f, &w2), Some((900_000, false)), "{continuity}");
        assert_eq!(day_total(&f), DAY, "{continuity}");
        assert_eq!(window_used(&f), 200_000);
    }
}

/// A call (continuity on) and payments in flight carried through two
/// renewals count once; a third renewal is admitted exactly up to the cap.
#[test]
fn repeated_renewals_count_a_carried_call_and_payments_once() {
    let f = day_fixture(true, DAY);
    let (w1, _) = ask(&f, proposal(400_000, 300_000)).unwrap();
    let peer = "aa".repeat(32);
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, "call", 9_500, 500, 5).unwrap();
    assert_eq!(terms.reserved_msat, 50_000);
    f.svc.reserve_call_spend(&f.client, 1, terms, u64::MAX / 4).unwrap();
    let block = f.svc.draw_call_spend(&f.client, 1, &peer, "call", 0, 9_500, 500, offer_link("block-0")).unwrap();
    f.svc.try_resolve_spend(&block, &peer, 10_000).unwrap();
    let paid = ln_payment(&f, "paid", 100_000).unwrap();
    f.svc.try_resolve_spend(&paid, &"bb".repeat(33), 100_000).unwrap();
    ln_payment(&f, "pending", 100_000).unwrap();
    // First window: a 10,000 minute and the 100,000 payment were paid there.
    let (w2, _) = ask(&f, proposal(400_000, 300_000)).unwrap();
    assert_eq!(window_committed(&f, &w1), Some((110_000, true)));
    assert_eq!(window_committed(&f, &w2), Some((400_000, false)));
    assert_eq!(day_total(&f), 510_000);
    let (w3, _) = ask(&f, proposal(400_000, 300_000)).unwrap();
    assert_eq!(window_committed(&f, &w2), Some((0, true)), "nothing was spent in the second window");
    assert_eq!(window_committed(&f, &w3), Some((400_000, false)));
    assert_eq!(day_total(&f), 510_000);
    let carried = allowance_grants(&f).into_iter().find(|g| g.op_id == w3).unwrap().budget.unwrap();
    assert_eq!((carried.used_msat, carried.call_reservations.len()), (140_000, 1));
    // Exactly up to the cap: 110,000 + 890,000.
    assert_eq!(ask(&f, proposal(890_001, 300_000)).unwrap().1, Outcome::Owner);
    let (w4, outcome) = ask(&f, proposal(890_000, 300_000)).unwrap();
    assert_eq!(outcome, Outcome::Window);
    assert_eq!(window_committed(&f, &w3), Some((0, true)));
    assert_eq!(day_total(&f), DAY);
    assert_eq!(window_committed(&f, &w4), Some((890_000, false)));
}

/// The donor's window had already ended (its grant kept to finish the call)
/// when the call moved on: the moved part is taken off that window once.
#[test]
fn a_call_moved_from_an_ended_window_is_counted_once() {
    let f = day_fixture(true, DAY);
    let (w1, _) = ask(&f, proposal(400_000, 300_000)).unwrap();
    let peer = "aa".repeat(32);
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, "call", 9_500, 500, 5).unwrap();
    f.svc.reserve_call_spend(&f.client, 1, terms, u64::MAX / 4).unwrap();
    let b = binding(&f);
    f.svc.remember_call_client(Some(&b), &peer, "call", "invite", "request").unwrap();
    f.svc.commit_call_client(None, &peer, "call", "invite", "request").unwrap();
    f.svc.finish_call_client(&peer, "call", "invite", "request");
    let block = f.svc.draw_call_spend(&f.client, 1, &peer, "call", 0, 9_500, 500, offer_link("block-0")).unwrap();
    f.svc.try_resolve_spend(&block, &peer, 10_000).unwrap();
    {
        let mut inner = f.svc.lock_without_cleanup();
        let grant = inner.file.grants.iter_mut().find(|g| g.op_id == w1).unwrap();
        let length = grant.expires_at - grant.granted_at;
        grant.expires_at = now() - 1;
        grant.granted_at = grant.expires_at - length;
        f.svc.persist(&mut inner.file).unwrap();
    }
    assert_eq!(window_committed(&f, &w1), Some((50_000, true)));
    let (w2, _) = ask(&f, proposal(400_000, 300_000)).unwrap();
    assert_eq!(window_committed(&f, &w1), Some((10_000, true)));
    assert_eq!(day_total(&f), 410_000);
    let carried = allowance_grants(&f).into_iter().find(|g| g.op_id == w2).unwrap().budget.unwrap();
    assert_eq!(carried.call_reservations.len(), 1);
}

/// What does not move stays counted where it was: a call the next window
/// cannot fund is released, not credited, and with continuity off no call
/// moves at all.
#[test]
fn an_unmoved_call_is_not_credited() {
    for (continuity, next_budget) in [(false, 400_000), (true, 30_000)] {
        let f = day_fixture(continuity, DAY);
        let (w1, _) = ask(&f, proposal(400_000, 300_000)).unwrap();
        let peer = "aa".repeat(32);
        let terms = crate::spend_budget::CallSpendTerms::new(&peer, "call", 9_500, 500, 5).unwrap();
        f.svc.reserve_call_spend(&f.client, 1, terms, u64::MAX / 4).unwrap();
        ln_payment(&f, "pending", 20_000).unwrap();
        let (w2, _) = ask(&f, proposal(next_budget, next_budget)).unwrap();
        let carried = allowance_grants(&f).into_iter().find(|g| g.op_id == w2).unwrap().budget.unwrap();
        assert!(carried.call_reservations.is_empty(), "{continuity}");
        // Only the payment moved: the whole hold stays on the first window.
        assert_eq!(window_committed(&f, &w1), Some((50_000, true)), "{continuity}");
        assert_eq!(day_total(&f), 50_000 + next_budget, "{continuity}");
    }
}

/// A call and payments that together exceed the new budget: the call fits
/// on its own and moves first, the payments move after it past the budget,
/// and the new window counts what it carries.
#[test]
fn the_new_window_counts_what_it_carries_when_that_exceeds_its_budget() {
    let f = day_fixture(true, 2_500_000);
    let (w1, _) = ask(&f, proposal(1_200_000, 700_000)).unwrap();
    let peer = "aa".repeat(32);
    let terms = crate::spend_budget::CallSpendTerms::new(&peer, "call", 2_000, 500, 240).unwrap();
    assert_eq!(terms.reserved_msat, 600_000);
    f.svc.reserve_call_spend(&f.client, 1, terms, u64::MAX / 4).unwrap();
    ln_payment(&f, "pending", 500_000).unwrap();
    let (w2, outcome) = ask(&f, proposal(1_000_000, 700_000)).unwrap();
    assert_eq!(outcome, Outcome::Window);
    let carried = allowance_grants(&f).into_iter().find(|g| g.op_id == w2).unwrap().budget.unwrap();
    assert_eq!((carried.used_msat, carried.remaining_msat()), (1_100_000, 0));
    assert_eq!(window_committed(&f, &w1), Some((0, true)));
    assert_eq!(window_committed(&f, &w2), Some((1_100_000, false)));
    assert_eq!(day_total(&f), 1_100_000);
    assert_eq!(ln_payment(&f, "more", 1), Err(BudgetRefusal::Total { remaining_msat: 0 }));
}

/// A renewal whose write fails credits nothing and moves nothing; after a
/// restart the same renewal credits once.
#[cfg(unix)]
#[test]
fn a_failed_renewal_write_credits_nothing_and_a_retry_credits_once() {
    use std::os::unix::fs::PermissionsExt;
    let f = day_fixture(true, DAY);
    let (w1, _) = ask(&f, proposal(400_000, 300_000)).unwrap();
    ln_payment(&f, "pending", 200_000).unwrap();
    let before = snapshot(&f);
    let dir = f.svc.dir().to_path_buf();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let probe = std::fs::write(dir.join("probe"), b"x").is_ok();
    let renewed = f.svc.create_budget_elevation_request(&f.client, vec![Scope::Spend], Some(proposal(800_000, 300_000)));
    let after = snapshot(&f);
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    if probe {
        return; // A privileged run: the directory stayed writable.
    }
    assert!(renewed.is_err());
    assert_eq!(after, before);
    let f = reopen(f, true, true);
    let f = Fixture { svc: f.svc.with_call_continuity(true), ..f };
    let (w2, outcome) = ask(&f, proposal(800_000, 300_000)).unwrap();
    assert_eq!(outcome, Outcome::Window);
    assert_eq!(window_committed(&f, &w1), Some((0, true)));
    assert_eq!(window_committed(&f, &w2), Some((800_000, false)));
    assert_eq!(day_total(&f), 800_000);
}
