//! Live-call continuity (`[calls] call_continuity_v1`): a call admitted under
//! a live grant keeps its pinned hold when that grant expires or is replaced,
//! and never after a revocation. Every case also runs with the switch off and
//! must then behave exactly as before. Amounts are integer msat; grant windows
//! are moved explicitly instead of waiting on the clock.
use super::*;
use crate::spend_budget::{CallSpendTerms, OperationReservationLink};

/// The owner terminal, captured.
#[derive(Clone, Default)]
struct Console(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl io::Write for Console {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Console {
    fn confirmation(&self, label: &str) -> String {
        let text = String::from_utf8(self.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .rfind(|line| line.starts_with(&format!("{label} CODE ")))
            .expect("owner confirmation")
            .to_owned()
    }
}

const PRICE: u64 = 1_000;
const MINUTES: u16 = 5;
/// `PRICE` per minute for `MINUTES`, no routing fee.
const HELD: u64 = 5_000;

struct Fx {
    _dir: tempfile::TempDir,
    service: PairingService,
    console: Console,
    client: String,
    binding: auth::PairingBinding,
}

fn peer() -> String {
    "aa".repeat(32)
}

fn fixture(continuity: bool) -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let console = Console::default();
    let service = PairingService::open(dir.path(), "identity".into(), true)
        .unwrap()
        .with_owner_console(Box::new(console.clone()))
        .without_stdout_code()
        .with_call_continuity(continuity);
    let key = ed25519_dalek::SigningKey::from_bytes(&[12; 32]);
    let client = service
        .create_verified_remote_pairing("app", &hex::encode(key.verifying_key().to_bytes()), &[13; 32])
        .unwrap();
    let binding = auth::PairingBinding {
        client_id: client.client_id.clone(),
        epoch: client.epoch,
        fingerprint: "identity".into(),
    };
    Fx { _dir: dir, service, console, client: client.client_id, binding }
}

/// The owner writes a spend grant for the app, replacing any earlier one.
fn grant(fx: &Fx, budget_msat: u64) -> SpendGrant {
    let op = fx.service.create_elevation_request(&fx.client, vec![Scope::Spend]).unwrap();
    let phrase = fx.console.confirmation(&grant_confirmation_phrase(&op));
    fx.service.grant_elevation(&op.op_id, &phrase, GrantTerms::new(budget_msat)).unwrap()
}

/// Close every spend window of the app one second ago, keeping its length:
/// the clock ran past the grant.
fn expire(fx: &Fx) {
    let mut inner = fx.service.lock_without_cleanup();
    let now = chrono::Utc::now().timestamp();
    for grant in inner.file.grants.iter_mut() {
        let length = grant.expires_at - grant.granted_at;
        grant.expires_at = now - 1;
        grant.granted_at = grant.expires_at - length;
    }
}

/// A paid invite admitted the call under the live grant: its hold is
/// reserved and the app's binding owns the call's media.
fn admit(fx: &Fx, call: &str) -> Reservation {
    let terms = CallSpendTerms::new(&peer(), call, PRICE, 0, MINUTES).unwrap();
    let hold = fx.service.reserve_call_spend(&fx.client, fx.binding.epoch, terms, 1_000_000).unwrap();
    fx.service.remember_call_client(Some(&fx.binding), &peer(), call, "invite", "request").unwrap();
    fx.service.commit_call_client(None, &peer(), call, "invite", "request").unwrap();
    fx.service.finish_call_client(&peer(), call, "invite", "request");
    hold
}

fn link(id: &str) -> OperationReservationLink {
    OperationReservationLink { operation_id: id.into(), execution_id: "attempt".into(), readmission: false }
}

/// One minute block drawn from the call's hold.
fn draw(fx: &Fx, call: &str, seq: u32) -> Result<Reservation, BudgetRefusal> {
    fx.service.draw_call_spend(&fx.client, fx.binding.epoch, &peer(), call, seq, PRICE, 0, link(&format!("{call}-{seq}")))
}

/// A draw that was dispatched and settled at its full price.
fn pay(fx: &Fx, call: &str, seq: u32) {
    let debit = draw(fx, call, seq).unwrap_or_else(|refusal| panic!("block {seq}: {refusal:?}"));
    fx.service
        .with_call_spend_authority(&debit, Some((&peer(), call)), || ())
        .unwrap_or_else(|refusal| panic!("block {seq} dispatch: {refusal:?}"));
    fx.service.try_resolve_spend(&debit, &peer(), PRICE).unwrap();
}

fn disk_budget(fx: &Fx, op_id: &str) -> Option<GrantBudget> {
    fx.service.reload_from_disk().unwrap().grants.into_iter().find(|g| g.op_id == op_id).and_then(|g| g.budget)
}

fn status(fx: &Fx, call: &str) -> Option<(u64, u64, u64, u64)> {
    fx.service.call_spend_status(&peer(), call)
        .map(|s| (s.reserved_msat, s.spent_msat, s.released_msat, s.remaining_msat))
}

fn new_payment(fx: &Fx) -> Result<Reservation, BudgetRefusal> {
    fx.service.reserve_operation_spend(&fx.client, fx.binding.epoch,
        vec![Charge { recipient: peer(), amount_msat: 10 }], link("message"))
}

#[test]
fn expired_hold_keeps_same_call_media_and_draws_but_not_new_admission() {
    let fx = fixture(true);
    let g = grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    expire(&fx);

    // The admitted call draws on its existing hold, inside the pinned limit.
    let block = draw(&fx, "call", 1);
    assert!(block.is_ok(), "a call admitted before expiry lost its hold: {block:?}");
    let block = block.unwrap();
    fx.service.with_call_spend_authority(&block, Some((&peer(), "call")), || ())
        .expect("the existing hold's block may be dispatched after expiry");
    fx.service.try_resolve_spend(&block, &peer(), PRICE).unwrap();
    assert!(fx.service.call_hold_live(&fx.binding, &peer(), "call"));
    assert!(fx.service.owns_call_media(&fx.binding, &peer(), "call"));
    for seq in 2..u32::from(MINUTES) {
        pay(&fx, "call", seq);
    }
    // The minute limit and the hold stay where admission pinned them.
    assert!(matches!(draw(&fx, "call", u32::from(MINUTES)), Err(BudgetRefusal::Unpriced(_))));
    assert_eq!(status(&fx, "call"), Some((HELD, HELD, 0, 0)));
    let budget = disk_budget(&fx, &g.op_id).expect("the funding grant stays on disk while its call is open");
    assert_eq!(budget.used_msat, HELD, "post-expiry spending stays inside the hold reserved before it");
    assert_eq!(budget.pending.values().flat_map(|r| r.values()).sum::<u64>(), 0);

    // Nothing new: no second call, no ordinary payment, no `spend` scope.
    let second = CallSpendTerms::new(&peer(), "second", PRICE, 0, MINUTES).unwrap();
    assert_eq!(fx.service.reserve_call_spend(&fx.client, 1, second, 1_000_000), Err(BudgetRefusal::NoGrant));
    assert_eq!(new_payment(&fx), Err(BudgetRefusal::NoGrant));
    assert!(fx.service.verify_token_binding(&fx.client, 1, "identity", &[Scope::Spend]).is_err());
    assert!(fx.service.grant_view_for(&fx.client).is_none());
    // Only this pairing, this call.
    assert!(!fx.service.call_hold_live(&fx.binding, &peer(), "second"));
    assert!(!fx.service.call_hold_live(&fx.binding, "bb", "call"));
    assert!(!fx.service.call_hold_live(&auth::PairingBinding { epoch: 2, ..fx.binding.clone() }, &peer(), "call"));
    assert!(!fx.service.call_hold_live(&auth::PairingBinding { client_id: "other".into(), ..fx.binding.clone() },
        &peer(), "call"));

    // The call ends: nothing was left to release, and the grant goes.
    let hold = fx.service.call_spend_holds().into_iter().map(|(r, _)| r).next().unwrap();
    fx.service.close_call_spend(&hold).unwrap();
    assert!(!fx.service.call_hold_live(&fx.binding, &peer(), "call"));
    assert!(fx.service.reload_from_disk().unwrap().grants.is_empty());
}

#[test]
fn expired_hold_with_continuity_off_ends_as_before() {
    let fx = fixture(false);
    let g = grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    expire(&fx);
    assert_eq!(draw(&fx, "call", 1), Err(BudgetRefusal::NoGrant));
    assert!(!fx.service.call_hold_live(&fx.binding, &peer(), "call"));
    assert!(disk_budget(&fx, &g.op_id).is_none());
    assert!(fx.service.reload_from_disk().unwrap().grants.is_empty());
    assert_eq!(status(&fx, "call"), None);
    let second = CallSpendTerms::new(&peer(), "second", PRICE, 0, MINUTES).unwrap();
    assert_eq!(fx.service.reserve_call_spend(&fx.client, 1, second, 1_000_000), Err(BudgetRefusal::NoGrant));
}

#[test]
fn replacement_migrates_hold_once_without_budget_credit() {
    let fx = fixture(true);
    let first = grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    // Block 1 is in flight when the owner renews.
    let in_flight = draw(&fx, "call", 1).unwrap();
    assert_eq!(disk_budget(&fx, &first.op_id).unwrap().used_msat, HELD);

    let second = grant(&fx, 50_000);
    let budget = disk_budget(&fx, &second.op_id).expect("renewed grant");
    assert_eq!(budget.call_reservations.len(), 1, "replacement lost the live call's hold");
    // Only what the hold still had moved: 3 unpaid minutes and the one in
    // flight. The minute paid under the first grant is not charged again.
    assert_eq!(budget.used_msat, HELD - PRICE);
    assert_eq!(budget.remaining_msat(), 50_000 - (HELD - PRICE));
    assert!(disk_budget(&fx, &first.op_id).is_none(), "the replaced grant funds nothing");
    assert_eq!(
        fx.service.reload_from_disk().unwrap().call_spend_grants.get(&format!("{}:call", peer())),
        Some(&second.op_id)
    );
    assert_eq!(status(&fx, "call"), Some((HELD, PRICE, 0, HELD - PRICE)));
    assert!(fx.service.call_hold_live(&fx.binding, &peer(), "call"));
    assert!(fx.service.owns_call_media(&fx.binding, &peer(), "call"));

    // The block in flight settles once, on the hold where it now lives.
    fx.service.with_call_spend_authority(&in_flight, Some((&peer(), "call")), || ())
        .expect("a block in flight at renewal may still be dispatched");
    fx.service.try_resolve_spend(&in_flight, &peer(), PRICE).unwrap();
    fx.service.try_resolve_spend(&in_flight, &peer(), PRICE).unwrap();
    assert_eq!(status(&fx, "call"), Some((HELD, 2 * PRICE, 0, HELD - 2 * PRICE)));

    // Renew again mid-call: still one hold, moved once more.
    pay(&fx, "call", 2);
    let third = grant(&fx, 40_000);
    let budget = disk_budget(&fx, &third.op_id).unwrap();
    assert_eq!(budget.call_reservations.len(), 1);
    assert_eq!(budget.used_msat, HELD - 3 * PRICE);
    assert_eq!(fx.service.reload_from_disk().unwrap().grants.len(), 1);

    pay(&fx, "call", 3);
    // A cheaper minute leaves change that goes back to the hold, not the grant.
    let last = draw(&fx, "call", 4).unwrap();
    fx.service.try_resolve_spend(&last, &peer(), PRICE / 2).unwrap();
    assert!(matches!(draw(&fx, "call", 5), Err(BudgetRefusal::Unpriced(_))));
    let hold = fx.service.call_spend_holds().into_iter().map(|(r, _)| r).next().unwrap();
    assert_eq!(hold.op_id, third.op_id);
    fx.service.close_call_spend(&hold).unwrap();
    fx.service.close_call_spend(&hold).unwrap();
    let spent = HELD - PRICE / 2;
    assert_eq!(status(&fx, "call"), Some((HELD, spent, PRICE / 2, 0)));
    let budget = disk_budget(&fx, &third.op_id).unwrap();
    // The third grant carries exactly what was paid under it; the release
    // returned the unspent half minute once and created nothing.
    assert_eq!(budget.used_msat, 2 * PRICE - PRICE / 2);
    assert_eq!(budget.remaining_msat(), 40_000 - (2 * PRICE - PRICE / 2));
    assert!(budget.pending.is_empty());
}

#[test]
fn replacement_with_continuity_off_drops_the_hold_as_before() {
    let fx = fixture(false);
    grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    let second = grant(&fx, 50_000);
    let budget = disk_budget(&fx, &second.op_id).unwrap();
    assert!(budget.call_reservations.is_empty());
    assert_eq!(budget.used_msat, 0);
    assert_eq!(status(&fx, "call"), None);
    assert!(matches!(draw(&fx, "call", 1), Err(BudgetRefusal::Unpriced(_))));
    assert!(!fx.service.call_hold_live(&fx.binding, &peer(), "call"));
}

#[derive(Debug, Clone, Copy)]
enum End {
    RevokeGrants,
    RemovePairing,
    BumpEpoch,
    NewIdentity,
}

fn end(fx: &Fx, how: End) {
    match how {
        End::RevokeGrants => { fx.service.revoke_grants(Some(&fx.client)).unwrap(); }
        End::RemovePairing => fx.service.revoke(&fx.client).unwrap(),
        End::BumpEpoch => { fx.service.bump_epoch(&fx.client).unwrap(); }
        End::NewIdentity => fx.service.rebind_to_identity("another-identity").unwrap(),
    }
}

#[test]
fn revocation_beats_continuity_and_renewal() {
    for continuity in [true, false] {
        for expired_first in [false, true] {
            for how in [End::RevokeGrants, End::RemovePairing, End::BumpEpoch, End::NewIdentity] {
                let case = format!("continuity={continuity} expired_first={expired_first} {how:?}");
                let fx = fixture(continuity);
                grant(&fx, 100_000);
                admit(&fx, "call");
                pay(&fx, "call", 0);
                let in_flight = draw(&fx, "call", 1).unwrap();
                if expired_first {
                    expire(&fx);
                }
                end(&fx, how);
                assert!(draw(&fx, "call", 2).is_err(), "{case}: drew after revocation");
                assert!(fx.service.with_call_spend_authority(&in_flight, Some((&peer(), "call")), || ()).is_err(),
                    "{case}: dispatched after revocation");
                assert!(!fx.service.call_hold_live(&fx.binding, &peer(), "call"), "{case}");
                assert!(fx.service.verify_token_binding(&fx.client, fx.binding.epoch, "identity", &[]).is_err()
                    || matches!(how, End::RevokeGrants), "{case}");
                assert!(fx.service.verify_token_binding(&fx.client, fx.binding.epoch, "identity", &[Scope::Spend]).is_err(),
                    "{case}");
                assert!(fx.service.reload_from_disk().unwrap().grants.is_empty(), "{case}");
                // A renewal after the revocation never revives the old hold.
                if matches!(how, End::RevokeGrants | End::BumpEpoch) {
                    let renewed = grant(&fx, 50_000);
                    let budget = disk_budget(&fx, &renewed.op_id).unwrap();
                    assert!(budget.call_reservations.is_empty(), "{case}: revived a revoked hold");
                    assert_eq!(budget.used_msat, 0, "{case}");
                    assert_eq!(status(&fx, "call"), None, "{case}");
                    assert!(draw(&fx, "call", 2).is_err(), "{case}");
                    assert!(!fx.service.call_hold_live(&fx.binding, &peer(), "call"), "{case}");
                }
            }
        }
    }
}

#[test]
fn continuity_does_not_outlive_the_longest_call() {
    let fx = fixture(true);
    grant(&fx, 100_000);
    admit(&fx, "call");
    {
        let mut inner = fx.service.lock_without_cleanup();
        let now = chrono::Utc::now().timestamp();
        let grant = &mut inner.file.grants[0];
        let length = grant.expires_at - grant.granted_at;
        // Expired longer ago than any call admitted before it can last.
        grant.expires_at = now - CALL_CONTINUITY_MAX_SECS - 1;
        grant.granted_at = grant.expires_at - length;
    }
    assert_eq!(draw(&fx, "call", 0), Err(BudgetRefusal::NoGrant));
    assert!(!fx.service.call_hold_live(&fx.binding, &peer(), "call"));
    assert!(fx.service.reload_from_disk().unwrap().grants.is_empty());
}

/// The fields of a spend grant as nodes without continuity read it. Serde
/// ignores fields a struct does not name unless it opts out, and none of the
/// durable pairing structs touched here do; this proves it for the new ones.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EarlierSpendGrant {
    op_id: String,
    client_id: String,
    scopes: Vec<Scope>,
    granted_at: i64,
    expires_at: i64,
    identity_fingerprint: String,
    epoch: u64,
    granted_by: String,
    #[serde(default)]
    budget: Option<GrantBudget>,
    #[serde(default)]
    owner_approval: Option<approval::ApprovalReceipt>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct EarlierPairingFile {
    version: u32,
    clients: Vec<PairedClient>,
    grants: Vec<EarlierSpendGrant>,
    #[serde(default)]
    call_spend_grants: BTreeMap<String, String>,
}

#[test]
fn pairing_file_with_an_ended_grant_loads_without_the_new_field() {
    let fx = fixture(true);
    grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    expire(&fx);
    pay(&fx, "call", 1);
    let bytes = std::fs::read(fx.service.dir().join("clients.json")).unwrap();
    let written: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(written["grants"][0]["ended"], "expired", "the retained grant records how it ended");
    assert_eq!(written["version"], PAIRING_FILE_VERSION, "no schema version bump: older nodes still read it");
    let earlier: EarlierPairingFile = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(earlier.grants.len(), 1);
    let budget = earlier.grants[0].budget.as_ref().unwrap();
    assert_eq!(budget.call_reservations.len(), 1);
    // Read the way a node without continuity reads it, the expired grant is
    // simply not live: it is pruned and funds nothing.
    let current: PairingFile = serde_json::from_slice(&bytes).unwrap();
    assert!(!current.grants[0].is_live(chrono::Utc::now().timestamp()));
    assert_eq!(current.grants[0].ended, Some(GrantEnd::Expired));

    // And a file written before the field existed reads as "not ended".
    let mut older = written.clone();
    older["grants"][0].as_object_mut().unwrap().remove("ended");
    let current: PairingFile = serde_json::from_value(older).unwrap();
    assert_eq!(current.grants[0].ended, None);
    for (end, text) in [(GrantEnd::Expired, "expired"), (GrantEnd::Replaced, "replaced"), (GrantEnd::Revoked, "revoked")] {
        assert_eq!(serde_json::to_value(end).unwrap(), text);
    }
}

#[test]
fn a_live_grant_writes_the_same_file_with_continuity_on_or_off() {
    let files = [true, false].map(|continuity| {
        let fx = fixture(continuity);
        grant(&fx, 100_000);
        admit(&fx, "call");
        pay(&fx, "call", 0);
        let mut file = serde_json::to_value(fx.service.reload_from_disk().unwrap()).unwrap();
        // Identifiers and timestamps differ per run; the shape must not.
        normalize(&mut file);
        file
    });
    assert_eq!(files[0], files[1]);
    assert!(files[0]["grants"][0].get("ended").is_none());
}

fn normalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let mut inner = map.remove(&key).unwrap();
                normalize(&mut inner);
                let generated = uuid::Uuid::parse_str(&key).is_ok() || key.len() == 32 || key.parse::<i64>().is_ok();
                let key = if generated { "<id>".to_owned() } else { key };
                map.insert(key, inner);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(normalize),
        serde_json::Value::Number(_) => *value = serde_json::Value::Null,
        serde_json::Value::String(text) => *value = serde_json::Value::String(text.len().to_string()),
        _ => {}
    }
}

#[test]
fn renewal_after_expiry_takes_over_the_open_hold_once() {
    let fx = fixture(true);
    let first = grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    expire(&fx);
    pay(&fx, "call", 1);
    assert_eq!(disk_budget(&fx, &first.op_id).unwrap().used_msat, HELD);
    let renewed = grant(&fx, 30_000);
    let budget = disk_budget(&fx, &renewed.op_id).unwrap();
    assert_eq!(budget.call_reservations.len(), 1);
    assert_eq!(budget.used_msat, HELD - 2 * PRICE);
    assert_eq!(fx.service.reload_from_disk().unwrap().grants.len(), 1);
    assert!(fx.service.verify_token_binding(&fx.client, 1, "identity", &[Scope::Spend]).is_ok());
    pay(&fx, "call", 2);
    assert_eq!(status(&fx, "call"), Some((HELD, 3 * PRICE, 0, HELD - 3 * PRICE)));
    // Only the renewed grant's own budget is new authority.
    assert!(new_payment(&fx).is_ok());
}

fn grant_with_terms(fx: &Fx, terms: GrantTerms) -> SpendGrant {
    let op = fx.service.create_elevation_request(&fx.client, vec![Scope::Spend]).unwrap();
    let phrase = fx.console.confirmation(&grant_confirmation_phrase(&op));
    fx.service.grant_elevation(&op.op_id, &phrase, terms).unwrap()
}

/// Pay whatever blocks the call can still draw and dispatch.
fn pay_what_draws(fx: &Fx) {
    for seq in 1..u32::from(MINUTES) {
        let Ok(block) = draw(fx, "call", seq) else { break };
        if fx.service.with_call_spend_authority(&block, Some((&peer(), "call")), || ()).is_err() {
            fx.service.try_resolve_spend(&block, &peer(), 0).unwrap();
            break;
        }
        fx.service.try_resolve_spend(&block, &peer(), PRICE).unwrap();
    }
}

#[test]
fn renewal_must_honor_the_successor_total() {
    let fx = fixture(true);
    grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    // The renewed grant allows 1 minute; the hold still has 4.
    let next = grant_with_terms(&fx, GrantTerms::new(PRICE));
    pay_what_draws(&fx);
    let budget = disk_budget(&fx, &next.op_id).unwrap();
    assert!(budget.used_msat <= budget.budget_msat,
        "successor authorized {} but migration charged {}", budget.budget_msat, budget.used_msat);
    assert_eq!(budget.used_msat, 0, "a hold that does not fit is not carried");
    assert!(budget.call_reservations.is_empty());
    assert!(!fx.service.call_hold_live(&fx.binding, &peer(), "call"));
}

#[test]
fn renewal_must_honor_the_successor_payee_set_recipient_cap_and_per_payment_limit() {
    let mut payees = GrantTerms::new(50_000);
    payees.payee_allowlist = Some(Default::default());
    let recipient = GrantTerms::new(50_000).recipient(&peer(), PRICE);
    let per_payment = GrantTerms::new(50_000).per_call(PRICE - 1);
    for (name, terms) in [("payees", payees), ("recipient", recipient), ("per-payment", per_payment)] {
        let fx = fixture(true);
        grant(&fx, 100_000);
        admit(&fx, "call");
        pay(&fx, "call", 0);
        let next = grant_with_terms(&fx, terms);
        if let Ok(block) = draw(&fx, "call", 1) {
            assert!(fx.service.with_call_spend_authority(&block, Some((&peer(), "call")), || ()).is_err(),
                "{name}: dispatch authorized a payment the successor grant excludes");
        }
        let budget = disk_budget(&fx, &next.op_id).unwrap();
        assert!(budget.call_reservations.is_empty(), "{name}: an excluded hold was carried");
        assert_eq!(budget.used_msat, 0, "{name}");
    }
}

#[test]
fn an_unfit_renewal_closes_the_hold_and_settles_its_block_in_flight_on_the_old_grant() {
    let fx = fixture(true);
    let first = grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    let in_flight = draw(&fx, "call", 1).unwrap();
    let next = grant_with_terms(&fx, GrantTerms::new(PRICE));
    // Not carried: the successor is untouched and nothing more can be drawn.
    let budget = disk_budget(&fx, &next.op_id).unwrap();
    assert_eq!((budget.used_msat, budget.call_reservations.len()), (0, 0));
    assert!(draw(&fx, "call", 2).is_err());
    // The block in flight is no longer dispatched, and settles once on the
    // grant that reserved it; the rest of the hold was released at once.
    assert!(fx.service.with_call_spend_authority(&in_flight, Some((&peer(), "call")), || ()).is_err());
    let old = disk_budget(&fx, &first.op_id).expect("the old grant stays only to settle its block");
    let kept = fx.service.reload_from_disk().unwrap().grants.into_iter().find(|g| g.op_id == first.op_id).unwrap();
    assert!(!kept.is_live(chrono::Utc::now().timestamp()) && kept.expires_at <= chrono::Utc::now().timestamp(),
        "a settling grant reads as ended even to a node without the end reason");
    assert_eq!(kept.ended, Some(GrantEnd::Replaced));
    assert_eq!(old.used_msat, 2 * PRICE, "one paid minute plus the one in flight");
    fx.service.try_resolve_spend(&in_flight, &peer(), 0).unwrap();
    fx.service.try_resolve_spend(&in_flight, &peer(), 0).unwrap();
    assert!(disk_budget(&fx, &first.op_id).is_none(), "settled, the old grant goes");
    assert_eq!(disk_budget(&fx, &next.op_id).unwrap().used_msat, 0);
    let status = fx.service.call_spend_status(&peer(), "call");
    assert!(status.is_none_or(|s| s.closed));
}

fn relation_fixture() -> (Fx, String, ring::signature::EcdsaKeyPair, ring::rand::SystemRandom) {
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    let mut fx = fixture(true);
    let owner = konsensus_core::OwnerApprovalKey::from_seed(&[31; 64], &[32; 32]).unwrap();
    fx.service = fx.service.with_owner_approval_key(owner.verifying_key());
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(signer.public_key().as_ref());
    let key_id = device::key_id_for(signer.public_key().as_ref());
    let client_pubkey = hex::encode(ed25519_dalek::SigningKey::from_bytes(&[12; 32]).verifying_key().to_bytes());
    {
        let mut inner = fx.service.lock();
        inner.file.device_keys.push(device::DeviceKey {
            key_id: key_id.clone(), client_id: fx.client.clone(), public_key: public.clone(),
            name: "device".into(), registered_at: 0, epoch: fx.binding.epoch,
            client_pubkey: client_pubkey.clone(), enrolled_by: "console".into(),
            owner_approval: hex::encode(owner.sign(device::owner_approval_message(
                "identity", &client_pubkey, fx.binding.epoch, &public).as_bytes()).to_bytes()),
        });
    }
    (fx, key_id, signer, rng)
}

fn relation_intent(fx: &Fx, key_id: &str, signer: &ring::signature::EcdsaKeyPair, rng: &ring::rand::SystemRandom)
    -> Result<device::RelationIntentOutcome, PairingError> {
    let intent = device::RelationIntent {
        device_key_id: key_id.into(), peer: peer(), level: device::LEVEL_CONTACT,
        budget_msat: 50_000, per_act_max_msat: 10_000, window_secs: 3600,
        issued_at: chrono::Utc::now().timestamp(), nonce: "12".repeat(16),
    };
    let message = device::intent_message("identity", &fx.client, fx.binding.epoch, &intent);
    let signature = hex::encode(signer.sign(rng, message.as_bytes()).unwrap().as_ref());
    fx.service.apply_relation_intent(&fx.client, fx.binding.epoch, &intent, &signature)
}

#[test]
fn failed_relation_renewal_must_restore_call_funding() {
    let (fx, key_id, signer, rng) = relation_fixture();
    let original = grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    expire(&fx);
    let before = fx.service.lock().file.clone();
    let blocked = fx.service.file_path.with_extension("json.tmp");
    std::fs::create_dir(&blocked).unwrap();
    let result = relation_intent(&fx, &key_id, &signer, &rng);
    std::fs::remove_dir(&blocked).unwrap();
    assert!(result.is_err(), "expected a storage failure");
    let inner = fx.service.lock_without_cleanup();
    assert!(inner.file.grants.iter().any(|g| g.op_id == original.op_id && g.budget.is_some()));
    assert_eq!(inner.file.call_spend_grants, before.call_spend_grants, "failed renewal changed call funding provenance");
    assert_eq!(inner.file.grants, before.grants, "failed renewal changed the grants");
}

#[test]
fn a_relation_renewal_for_the_called_peer_carries_the_hold() {
    let (fx, key_id, signer, rng) = relation_fixture();
    grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    expire(&fx);
    let outcome = relation_intent(&fx, &key_id, &signer, &rng).unwrap();
    let file = fx.service.reload_from_disk().unwrap();
    let relation = file.grants.iter().find(|g| g.budget.as_ref().is_some_and(|b| b.recipients_only)).unwrap();
    assert_eq!(relation.budget.as_ref().unwrap().used_msat, HELD - PRICE);
    assert_eq!(file.call_spend_grants.get(&format!("{}:call", peer())), Some(&relation.op_id));
    assert_eq!(outcome.grant.op_id, relation.op_id);
    pay(&fx, "call", 1);
}

/// The relation window closes: the grant and every recipient envelope end
/// one second ago, as the clock would close them.
fn expire_relation_window(fx: &Fx) {
    let now = chrono::Utc::now().timestamp();
    let mut inner = fx.service.lock_without_cleanup();
    for grant in &mut inner.file.grants {
        let length = grant.expires_at - grant.granted_at;
        grant.expires_at = now - 1;
        grant.granted_at = grant.expires_at - length;
        if let Some(budget) = grant.budget.as_mut() {
            for at in budget.recipient_expires_at.values_mut() {
                *at = now - 1;
            }
        }
    }
}

#[test]
fn relation_window_expiry_keeps_the_next_minute_of_an_admitted_call() {
    let (fx, key_id, signer, rng) = relation_fixture();
    relation_intent(&fx, &key_id, &signer, &rng).unwrap();
    admit(&fx, "call");
    pay(&fx, "call", 0);
    expire_relation_window(&fx);
    assert!(fx.service.call_hold_live(&fx.binding, &peer(), "call"));
    assert!(fx.service.owns_call_media(&fx.binding, &peer(), "call"));
    // Nothing new on the ended window: no payment, no second call.
    assert!(new_payment(&fx).is_err());
    let second = CallSpendTerms::new(&peer(), "second", PRICE, 0, MINUTES).unwrap();
    assert!(fx.service.reserve_call_spend(&fx.client, 1, second, 1_000_000).is_err());
    // The admitted call keeps drawing on its hold, to its pinned limit.
    let block = draw(&fx, "call", 1);
    assert!(block.is_ok(), "funded admitted relation call cannot draw its next minute after its window: {block:?}");
    let block = block.unwrap();
    fx.service.with_call_spend_authority(&block, Some((&peer(), "call")), || ()).unwrap();
    fx.service.try_resolve_spend(&block, &peer(), PRICE).unwrap();
    for seq in 2..u32::from(MINUTES) {
        pay(&fx, "call", seq);
    }
    assert!(matches!(draw(&fx, "call", u32::from(MINUTES)), Err(BudgetRefusal::Unpriced(_))));
    assert_eq!(status(&fx, "call"), Some((HELD, HELD, 0, 0)));
}

#[test]
fn relation_window_expiry_keeps_a_drawn_minute_dispatchable() {
    let (fx, key_id, signer, rng) = relation_fixture();
    relation_intent(&fx, &key_id, &signer, &rng).unwrap();
    admit(&fx, "call");
    pay(&fx, "call", 0);
    let block = draw(&fx, "call", 1).unwrap();
    fx.service.with_call_spend_authority(&block, Some((&peer(), "call")), || ()).unwrap();
    expire_relation_window(&fx);
    assert!(fx.service.call_hold_live(&fx.binding, &peer(), "call"));
    let dispatch = fx.service.with_call_spend_authority(&block, Some((&peer(), "call")), || ());
    assert!(dispatch.is_ok(), "an existing held relation minute cannot dispatch after its window: {dispatch:?}");
}

#[test]
fn after_a_relation_window_revocation_still_stops_the_call_and_the_switch_off_keeps_the_window() {
    // Revoked after the window closed: no draw, no dispatch, no media.
    let (fx, key_id, signer, rng) = relation_fixture();
    relation_intent(&fx, &key_id, &signer, &rng).unwrap();
    admit(&fx, "call");
    pay(&fx, "call", 0);
    let block = draw(&fx, "call", 1).unwrap();
    expire_relation_window(&fx);
    fx.service.revoke_grants(Some(&fx.client)).unwrap();
    assert!(draw(&fx, "call", 2).is_err());
    assert!(fx.service.with_call_spend_authority(&block, Some((&peer(), "call")), || ()).is_err());
    assert!(!fx.service.call_hold_live(&fx.binding, &peer(), "call"));

    // Switch off: the envelope deadline stops the call as before.
    let (mut fx, key_id, signer, rng) = relation_fixture();
    fx.service = fx.service.with_call_continuity(false);
    relation_intent(&fx, &key_id, &signer, &rng).unwrap();
    admit(&fx, "call");
    pay(&fx, "call", 0);
    let block = draw(&fx, "call", 1).unwrap();
    {
        // Only the peer's envelope ends; the grant stays live on paper.
        let now = chrono::Utc::now().timestamp();
        let mut inner = fx.service.lock_without_cleanup();
        for at in inner.file.grants.iter_mut().filter_map(|g| g.budget.as_mut())
            .flat_map(|b| b.recipient_expires_at.values_mut()) {
            *at = now - 1;
        }
    }
    assert_eq!(draw(&fx, "call", 2), Err(BudgetRefusal::NoGrant));
    assert!(fx.service.with_call_spend_authority(&block, Some((&peer(), "call")), || ()).is_err());
}

/// A console renewal whose write fails leaves the pairing exactly as it was,
/// in memory as on disk: the earlier grant, its call's hold where it was,
/// no successor. Later draws behave as before the attempt.
fn failed_console_renewal_restores_the_file(continuity: bool) {
    let fx = fixture(continuity);
    let first = grant(&fx, 100_000);
    admit(&fx, "call");
    pay(&fx, "call", 0);
    let op = fx.service.create_elevation_request(&fx.client, vec![Scope::Spend]).unwrap();
    let phrase = fx.console.confirmation(&grant_confirmation_phrase(&op));
    let before = fx.service.lock().file.clone();
    let blocked = fx.service.file_path.with_extension("json.tmp");
    std::fs::create_dir(&blocked).unwrap();
    let result = fx.service.grant_elevation(&op.op_id, &phrase, GrantTerms::new(50_000));
    std::fs::remove_dir(&blocked).unwrap();
    assert!(matches!(result, Err(PairingError::Io(_))), "continuity={continuity}: expected a storage failure: {result:?}");
    {
        let inner = fx.service.lock_without_cleanup();
        assert_eq!(inner.file.grants, before.grants, "continuity={continuity}: a failed renewal changed the grants in memory");
        assert_eq!(inner.file.call_spend_grants, before.call_spend_grants, "continuity={continuity}");
        assert_eq!(inner.file, before, "continuity={continuity}: a failed renewal changed the pairing file in memory");
    }
    assert_eq!(fx.service.reload_from_disk().unwrap().grants, before.grants, "continuity={continuity}");
    // The call keeps drawing on its hold under the earlier grant.
    assert_eq!(status(&fx, "call"), Some((HELD, PRICE, 0, HELD - PRICE)));
    pay(&fx, "call", 1);
    assert_eq!(disk_budget(&fx, &first.op_id).unwrap().used_msat, HELD);
    assert_eq!(fx.service.grant_view_for(&fx.client).unwrap().op_id, first.op_id);
}

#[test]
fn a_failed_renewal_write_restores_the_pairing_file_with_continuity_on() {
    failed_console_renewal_restores_the_file(true);
}

#[test]
fn a_failed_renewal_write_restores_the_pairing_file_with_continuity_off() {
    failed_console_renewal_restores_the_file(false);
}

/// A paid invite admitted the call with a `PRICE` closing reserve for its
/// hangup, as a metered offer does.
fn admit_with_closing(fx: &Fx, call: &str) {
    let terms = CallSpendTerms::new(&peer(), call, PRICE, 0, MINUTES).unwrap().with_closing_signal(PRICE, 0).unwrap();
    fx.service.reserve_call_spend(&fx.client, fx.binding.epoch, terms, 1_000_000).unwrap();
    fx.service.remember_call_client(Some(&fx.binding), &peer(), call, "invite", "request").unwrap();
    fx.service.commit_call_client(None, &peer(), call, "invite", "request").unwrap();
    fx.service.finish_call_client(&peer(), call, "invite", "request");
}

/// The app's hangup after expiry, admitted as the compose route admits it
/// without `spend`: its binding still holds and owns the call, and the meter
/// keeps the grant that funds the call.
fn admit_hangup(fx: &Fx, call: &str) -> String {
    assert!(fx.service.call_hold_live(&fx.binding, &peer(), call));
    assert!(fx.service.owns_call_media(&fx.binding, &peer(), call));
    fx.service.call_spend_grant(&peer(), call).expect("the grant that funds the call")
}

/// The hangup's draw on the closing reserve, as `Meter::CallClosing` makes it.
fn closing(fx: &Fx, grant_op_id: &str, call: &str, id: &str) -> Result<Reservation, BudgetRefusal> {
    fx.service.reserve_call_closing_spend(grant_op_id, &peer(), call,
        vec![Charge { recipient: peer(), amount_msat: PRICE }], link(id))
}

/// One dispatch poll of the hangup's payment, as the compose route makes it.
fn dispatch_closing(fx: &Fx, reservation: &Reservation, call: &str, paid: &mut bool) -> Result<(), BudgetRefusal> {
    fx.service.with_call_payment_authority(reservation, Some((&peer(), call)),
        Some(crate::spend_budget::CallPayment::Signal), || *paid = true)
}

/// An expired app's live call, with block 0 paid and its hangup admitted.
fn admitted_hangup() -> (Fx, String) {
    let fx = fixture(true);
    grant(&fx, 100_000);
    admit_with_closing(&fx, "call");
    pay(&fx, "call", 0);
    expire(&fx);
    let grant_op_id = admit_hangup(&fx, "call");
    (fx, grant_op_id)
}

#[test]
fn a_closing_admitted_on_a_binding_is_refused_once_that_binding_is_stale() {
    // Control: with nothing changed the admitted hangup reserves and dispatches.
    let (fx, grant_op_id) = admitted_hangup();
    let reserved = closing(&fx, &grant_op_id, "call", "hangup").expect("the admitted hangup draws its closing reserve");
    let mut paid = false;
    dispatch_closing(&fx, &reserved, "call", &mut paid).expect("and may be dispatched");
    assert!(paid);

    for how in [End::RevokeGrants, End::RemovePairing, End::BumpEpoch, End::NewIdentity] {
        // Admitted, then the binding goes stale before the closing is reserved.
        let (fx, grant_op_id) = admitted_hangup();
        let before = status(&fx, "call");
        end(&fx, how);
        assert_eq!(closing(&fx, &grant_op_id, "call", "hangup"), Err(BudgetRefusal::NoGrant), "{how:?}: reserved");
        assert!(status(&fx, "call").is_none_or(|now| Some(now) == before), "{how:?}: the refusal moved the hold");

        // Admitted and reserved, then the binding goes stale before dispatch.
        let (fx, grant_op_id) = admitted_hangup();
        let reserved = closing(&fx, &grant_op_id, "call", "hangup").unwrap();
        end(&fx, how);
        let mut paid = false;
        assert_eq!(dispatch_closing(&fx, &reserved, "call", &mut paid), Err(BudgetRefusal::NoGrant), "{how:?}: dispatched");
        assert!(!paid, "{how:?}: nothing is dispatched");
    }
}
