//! K1 slice 2: capped sponsor sats in an introduction kit.
//!
//! **Sponsor node** (the inviter): the owner turns sponsoring on in the node
//! config (`[sponsor]`, off by default, clamped to the spec's hard ceilings).
//! `POST /sponsor/offer` signs a fresh introduction card plus an offer of one
//! fixed gift for that card only. The newcomer answers with a signed funding
//! request; `POST /sponsor/candidate` checks it (kit, keys, invoice payee,
//! amount, hash) and freezes it as the kit's one candidate; `POST
//! /sponsor/approve`, with the six-digit code both people compared, reserves
//! gift + fee ceiling against the rolling purse, persists that, and only then
//! pays. Only independent owner credentials can approve; a G1 grant cannot.
//!
//! **Newcomer node:** `POST /sponsor/request` checks the card and offer,
//! creates one fixed invoice to its own wallet, and registers its hash as
//! funding-only in the gate's durable receipt table **before** the invoice
//! leaves the node: an envelope carrying that preimage is refused as a
//! reused payment, even from the sponsor who learns it by paying.
//!
//! Doctrine: the gift is the newcomer's ordinary balance. It buys no
//! admission, no session and no credit; every act after it pays through the
//! gate. Sponsoring grants no authority over the newcomer's wallet.
//!
//! Ledger: `<data_dir>/sponsor/kits.json` (0600, atomic replace). Unknown
//! payment outcomes keep their reservation until reconciled; a consumed
//! introduction id never produces a second gift; clock rollback cannot
//! refresh the purse (a reservation dated in the future still counts).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Path as UrlPath, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use konsensus_core::introduction::Introduction;
use konsensus_core::sponsor::{self as core, FundingRequest, SponsorOffer};
use konsensus_core::traits::lightning::{LightningError, PaymentDetails, PaymentDirection, PaymentStatus};
use konsensus_core::types::{MessageId, NodeId};

use crate::auth::scoped::{Read, Receive, ScopedAuth};
use crate::error::ApiError;
use crate::metered::MeteredSpend;
use crate::spend_budget::{BudgetRefusal, Charge, Reservation};
use crate::state::AppState;

/// Advertised on `/api/v1/status`.
pub const CAPABILITY: &str = "sponsor_kit_v1";
const DAY_SECS: u64 = 86_400;
const LEDGER_VERSION: u32 = 1;

/// The owner's sponsoring policy, from the node config. Off by default.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SponsorPolicy {
    pub enabled: bool,
    /// The fixed gift per kit, msat.
    pub gift_msat: u64,
    /// Route-fee ceiling reserved on top of each gift, msat.
    pub fee_msat: u64,
    /// Rolling 24 h purse, gifts + fees + unresolved reservations, msat.
    pub purse_msat: u64,
    /// Approved kits per rolling 24 h.
    pub kits_per_day: u32,
}

impl SponsorPolicy {
    /// The policy as configured, refused if it exceeds a spec ceiling.
    pub fn new(enabled: bool, gift_msat: u64, fee_msat: u64, purse_msat: u64, kits_per_day: u32) -> Result<Self, String> {
        let p = Self { enabled, gift_msat, fee_msat, purse_msat, kits_per_day };
        if !enabled {
            return Ok(p);
        }
        if gift_msat == 0 || gift_msat.saturating_add(fee_msat) > core::MAX_KIT_MSAT {
            return Err(format!("[sponsor] gift + fee must be 1..={} sats", core::MAX_KIT_MSAT / 1000));
        }
        if fee_msat > core::MAX_FEE_MSAT {
            return Err(format!("[sponsor] fee ceiling above {} sats", core::MAX_FEE_MSAT / 1000));
        }
        if purse_msat > core::MAX_PURSE_MSAT || purse_msat < gift_msat.saturating_add(fee_msat) {
            return Err(format!("[sponsor] purse must cover one kit and stay ≤ {} sats", core::MAX_PURSE_MSAT / 1000));
        }
        if kits_per_day == 0 || kits_per_day > core::MAX_KITS_PER_DAY {
            return Err(format!("[sponsor] kits_per_day must be 1..={}", core::MAX_KITS_PER_DAY));
        }
        Ok(p)
    }

    fn kit_msat(&self) -> u64 {
        self.gift_msat.saturating_add(self.fee_msat)
    }
}

// ---- the ledger ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KitState {
    /// Offer out; no request yet.
    Offered,
    /// One signed request frozen, waiting for the owner's approval.
    Candidate,
    /// Reserved and dispatched; outcome not yet known.
    Paying,
    /// The gift settled.
    Funded,
    /// Definitively not paid. The kit is closed (single use).
    Failed,
    /// The provider could not say. The reservation stays until reconciled.
    Unknown,
    /// The sponsor cancelled before dispatch.
    Cancelled,
    /// Observed past its dispatch deadline; never reopens after clock rollback.
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub newcomer: String,
    pub newcomer_ln: String,
    pub payment_hash: String,
    pub bolt11: String,
    pub code: String,
    /// Legacy candidates without the verified deadline cannot dispatch.
    #[serde(default)]
    pub expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Kit {
    pub intro_id: String,
    pub gift_msat: u64,
    pub fee_msat: u64,
    pub created_at: u64,
    /// Offer and dispatch authority end here.
    pub expires_at: u64,
    pub state: KitState,
    pub candidate: Option<Candidate>,
    /// Set when the owner approved: the daily approval count uses it.
    pub approved_at: Option<u64>,
    /// First authoritative monetary outcome, independent of approval age.
    #[serde(default)]
    pub settled_at: Option<u64>,
    /// Reconciliation only; this does not confer dispatch authority.
    #[serde(default)]
    pub grant_reservation: Option<Reservation>,
    /// A lookup proved the invoice had no prior attempt before dispatch.
    /// Legacy ambiguous operations cannot release holds on failed lookups.
    #[serde(default)]
    pub fresh_payment_hash: bool,
    /// Gift + fee ceiling held from approval until a definitive outcome.
    pub reserved_msat: u64,
    pub paid_msat: u64,
    pub fee_paid_msat: u64,
}

impl Kit {
    fn open(&self, now: u64) -> bool {
        match self.state {
            KitState::Offered | KitState::Candidate => self.expires_at > now,
            KitState::Paying | KitState::Unknown => true,
            KitState::Funded => self.reserved_msat > 0,
            _ => false,
        }
    }

    fn in_day(&self, now: u64) -> bool {
        // A reservation dated after `now` (clock moved back) still counts.
        self.approved_at.is_some_and(|at| at.saturating_add(DAY_SECS) > now)
    }

    /// What this kit holds against the purse.
    fn charge(&self, now: u64) -> u64 {
        match self.state {
            KitState::Paying | KitState::Unknown => self.reserved_msat,
            // An unknown fee keeps the complete approved maximum held until
            // its definitive outcome, regardless of elapsed time.
            KitState::Funded if self.reserved_msat > 0 => self.reserved_msat,
            KitState::Funded if self.settled_at.or(self.approved_at)
                .is_some_and(|at| at.saturating_add(DAY_SECS) > now) =>
                self.paid_msat.saturating_add(self.fee_paid_msat),
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub version: u32,
    /// Highest observed wall time, durably advanced even on refused operations.
    #[serde(default)]
    pub last_observed_time: u64,
    pub kits: Vec<Kit>,
}

impl Ledger {
    fn observe(&mut self, wall_now: u64) -> u64 {
        self.last_observed_time = self.last_observed_time.max(wall_now);
        let now = self.last_observed_time;
        for kit in &mut self.kits {
            let deadline = kit.candidate.as_ref().map_or(kit.expires_at, |c| kit.expires_at.min(c.expires_at));
            if matches!(kit.state, KitState::Offered | KitState::Candidate) && deadline <= now {
                kit.state = KitState::Expired;
            }
        }
        now
    }

    pub fn purse_used(&self, now: u64) -> u64 {
        let now = now.max(self.last_observed_time);
        self.kits.iter().fold(0u64, |used, k| used.saturating_add(k.charge(now)))
    }

    pub fn kits_today(&self, now: u64) -> u32 {
        let now = now.max(self.last_observed_time);
        self.kits.iter().filter(|k| k.in_day(now)).count() as u32
    }

    pub fn active(&self, now: u64) -> u32 {
        let now = now.max(self.last_observed_time);
        self.kits.iter().filter(|k| k.open(now)).count() as u32
    }

    fn kit_mut(&mut self, intro_id: &str) -> Result<&mut Kit, ApiError> {
        self.kits
            .iter_mut()
            .find(|k| k.intro_id == intro_id)
            .ok_or_else(|| ApiError::NotFound("sponsor_kit_unknown: no kit for that introduction".into()))
    }

    /// Before a new offer: sponsoring on, nothing else open, and room left
    /// today for one more approved kit of the configured size.
    fn check_new_kit(&self, policy: &SponsorPolicy, now: u64) -> Result<(), ApiError> {
        if !policy.enabled {
            return Err(ApiError::Conflict("sponsor_disabled: the owner has not turned sponsoring on ([sponsor] in the node config)".into()));
        }
        if self.active(now) >= core::MAX_ACTIVE_KITS {
            return Err(ApiError::Conflict("sponsor_kit_open: finish or cancel the open kit first".into()));
        }
        self.check_room(policy, policy.kit_msat(), now)
    }

    fn check_room(&self, policy: &SponsorPolicy, kit_msat: u64, now: u64) -> Result<(), ApiError> {
        if self.kits_today(now) >= policy.kits_per_day {
            return Err(ApiError::Conflict(format!(
                "sponsor_daily_limit: {} kits in the last 24 hours",
                policy.kits_per_day
            )));
        }
        if self.purse_used(now).saturating_add(kit_msat) > policy.purse_msat {
            return Err(ApiError::Conflict(format!(
                "sponsor_purse_exhausted: {} of {} sats used in the last 24 hours",
                self.purse_used(now) / 1000,
                policy.purse_msat / 1000
            )));
        }
        Ok(())
    }
}

/// Serialises every read-modify-write of the ledger in this process.
static LEDGER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

// A backend lookup cannot adjudicate a call still preparing/dispatching in
// this process: it could describe an earlier failed attempt for the invoice.
// Only the live caller records its result. Cancellation drops this marker,
// leaving the durable unknown reservation available for reconciliation.
static ACTIVE_DISPATCHES: std::sync::Mutex<Vec<(PathBuf, String)>> = std::sync::Mutex::new(Vec::new());

struct ActiveDispatch((PathBuf, String));

impl ActiveDispatch {
    // Called while holding LEDGER_LOCK, before the first backend poll.
    fn start(dir: PathBuf, intro_id: String) -> Self {
        let key = (dir, intro_id);
        ACTIVE_DISPATCHES.lock().unwrap_or_else(|e| e.into_inner()).push(key.clone());
        Self(key)
    }

    fn contains(dir: &Path, intro_id: &str) -> bool {
        ACTIVE_DISPATCHES.lock().unwrap_or_else(|e| e.into_inner()).iter()
            .any(|(d, id)| d == dir && id == intro_id)
    }
}

impl Drop for ActiveDispatch {
    fn drop(&mut self) {
        ACTIVE_DISPATCHES.lock().unwrap_or_else(|e| e.into_inner()).retain(|key| key != &self.0);
    }
}

fn ledger_dir(state: &AppState) -> Result<PathBuf, ApiError> {
    let dir = state
        .data_dir
        .as_ref()
        .ok_or_else(|| ApiError::Conflict("sponsor_unavailable: this node has no data directory".into()))?;
    Ok(dir.join("sponsor"))
}

fn load(dir: &Path) -> Result<Ledger, ApiError> {
    match std::fs::read(dir.join("kits.json")) {
        Ok(bytes) => {
            let mut ledger: Ledger = serde_json::from_slice(&bytes)
                .map_err(|e| ApiError::Internal(format!("sponsor ledger unreadable: {e}")))?;
            if ledger.version != LEDGER_VERSION {
                return Err(ApiError::Internal(format!("sponsor ledger version {} not supported", ledger.version)));
            }
            // Older ledgers used approval time for late settlements and
            // stored an unknown fee as zero. Do not treat those fields as
            // proof that exposure has aged out: reconcile once under the new
            // accounting rules before releasing their approved maximum.
            for kit in &mut ledger.kits {
                if kit.state == KitState::Funded && kit.settled_at.is_none() {
                    kit.reserved_msat = kit.reserved_msat
                        .max(kit.gift_msat.saturating_add(kit.fee_msat))
                        .max(kit.paid_msat.saturating_add(kit.fee_paid_msat));
                }
            }
            Ok(ledger)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger { version: LEDGER_VERSION, ..Ledger::default() }),
        Err(e) => Err(ApiError::Internal(format!("sponsor ledger unreadable: {e}"))),
    }
}

fn save(dir: &Path, ledger: &Ledger) -> Result<(), ApiError> {
    let io = |e: std::io::Error| ApiError::Internal(format!("sponsor ledger not saved: {e}"));
    std::fs::create_dir_all(dir).map_err(io)?;
    crate::pairing::restrict_dir(dir).map_err(io)?;
    let bytes = serde_json::to_vec_pretty(ledger).map_err(|e| ApiError::Internal(e.to_string()))?;
    let tmp = dir.join("kits.json.tmp");
    if let Err(e) = crate::pairing::write_protected(&tmp, &bytes).and_then(|()| std::fs::rename(&tmp, dir.join("kits.json"))) {
        let _ = std::fs::remove_file(&tmp);
        return Err(io(e));
    }
    crate::pairing::fsync_dir(dir).map_err(io)?;
    Ok(())
}

/// Advance time durably before a caller can observe expiry, even if its
/// subsequent operation is refused. Caller must hold LEDGER_LOCK.
fn load_observed(dir: &Path, wall_now: u64) -> Result<Ledger, ApiError> {
    let mut ledger = load(dir)?;
    let before = ledger.clone();
    ledger.observe(wall_now);
    if ledger != before {
        save(dir, &ledger)?;
    }
    Ok(ledger)
}

/// Run `edit` under the lock with durable, nondecreasing effective time.
async fn with_ledger<T>(state: &AppState, edit: impl FnOnce(&mut Ledger, u64) -> Result<T, ApiError>) -> Result<T, ApiError> {
    let _guard = LEDGER_LOCK.lock().await;
    let dir = ledger_dir(state)?;
    let mut ledger = load_observed(&dir, now_unix()?)?;
    let now = ledger.last_observed_time;
    let out = edit(&mut ledger, now)?;
    save(&dir, &ledger)?;
    Ok(out)
}

fn now_unix() -> Result<u64, ApiError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| ApiError::Internal(format!("system clock before UNIX_EPOCH: {e}")))
}

fn network(state: &AppState) -> Result<String, ApiError> {
    state.introduction.network.clone().ok_or_else(|| {
        ApiError::Conflict("sponsor_unavailable: this node's Lightning backend does not state a Bitcoin network".into())
    })
}

fn invoice_currency(network: &str) -> Result<lightning_invoice::Currency, ApiError> {
    use lightning_invoice::Currency;
    match network {
        "bitcoin" => Ok(Currency::Bitcoin),
        "testnet" => Ok(Currency::BitcoinTestnet),
        "signet" => Ok(Currency::Signet),
        "regtest" => Ok(Currency::Regtest),
        _ => Err(invalid("unsupported sponsor network")),
    }
}

fn invalid(e: impl std::fmt::Display) -> ApiError {
    ApiError::BadRequest(format!("sponsor_invalid: {e}"))
}

// ---- sponsor side ------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct OfferResponse {
    pub card: Introduction,
    pub gift_msat: u64,
    pub fee_msat: u64,
    pub expires_at: u64,
    /// `bitsov://introduce#<card>.<offer>`: the QR and the link to share.
    pub link: String,
}

/// `POST /api/v1/sponsor/offer` — a fresh introduction card with a signed
/// offer of this node's configured gift, for that card only. Sharing it
/// moves nothing. Opens the one active kit; refused past the daily count or
/// purse. Spend authority: it is the start of a payment the owner allowed.
async fn create_offer(_auth: MeteredSpend, State(state): State<Arc<AppState>>) -> Result<Json<OfferResponse>, ApiError> {
    let policy = state.sponsor.clone();
    // Check first, so a refused offer signs nothing.
    let now = with_ledger(&state, |l, now| {
        l.check_new_kit(&policy, now)?;
        Ok(now)
    }).await?;
    let card = super::introduction::issue_card(&state).await?;
    let intro_id: [u8; 16] = hex::decode(&card.intro_id).ok().and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::Internal("card id".into()))?;
    let expires_at = card.expires_at.min(now + core::OFFER_LIFETIME_SECS);
    let offer = SponsorOffer::sign(state.identity.ed25519_signing_key(), &card.network, intro_id, policy.gift_msat, expires_at)
        .map_err(|e| ApiError::Internal(format!("offer: {e}")))?;
    with_ledger(&state, |l, now| {
        l.check_new_kit(&policy, now)?;
        if expires_at <= now {
            return Err(ApiError::Conflict("sponsor_kit_expired: introduction has expired".into()));
        }
        l.kits.push(Kit {
            intro_id: card.intro_id.clone(),
            gift_msat: policy.gift_msat,
            fee_msat: policy.fee_msat,
            created_at: now,
            expires_at,
            state: KitState::Offered,
            candidate: None,
            approved_at: None,
            settled_at: None,
            grant_reservation: None,
            fresh_payment_hash: false,
            reserved_msat: 0,
            paid_msat: 0,
            fee_paid_msat: 0,
        });
        Ok(())
    })
    .await?;
    let link = format!("{}{}{}", card.to_link(), core::OFFER_SEPARATOR, offer.encode());
    Ok(Json(OfferResponse { card, gift_msat: policy.gift_msat, fee_msat: policy.fee_msat, expires_at, link }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateRequest {
    /// `bitsov://sponsor-request#…` as shown by the newcomer.
    pub request: String,
}

#[derive(Debug, Serialize)]
pub struct CandidateResponse {
    pub intro_id: String,
    pub newcomer: String,
    pub payment_hash: String,
    pub gift_msat: u64,
    pub fee_max_msat: u64,
    /// The six digits the newcomer's screen shows. Compare them in person.
    pub code: String,
    pub expires_at: u64,
}

/// `POST /api/v1/sponsor/candidate` — check a newcomer's signed request
/// against an open kit and freeze it as that kit's only candidate. Pays
/// nothing. A second, different request for the same kit is refused rather
/// than replacing the first.
async fn add_candidate(
    _auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(body): Json<CandidateRequest>,
) -> Result<Json<CandidateResponse>, ApiError> {
    // Persist observation even when signature/invoice expiry refuses the request.
    let now = with_ledger(&state, |_, now| Ok(now)).await?;
    let req = FundingRequest::parse(&body.request).map_err(invalid)?;
    let net = network(&state)?;
    req.verify(now, &net).map_err(invalid)?;
    if req.sponsor != *state.identity.node_id().as_bytes() {
        return Err(invalid("this request is for another sponsor"));
    }
    // The invoice must be exactly what the newcomer signed: its amount, its
    // hash, and payable to the Lightning key the request binds.
    let invoice = req.bolt11.parse::<lightning_invoice::Bolt11Invoice>().map_err(|e| invalid(format!("invoice: {e}")))?;
    if invoice.currency() != invoice_currency(&net)? {
        return Err(invalid("invoice network differs from this sponsor"));
    }
    let payee = invoice.payee_pub_key().copied().unwrap_or_else(|| invoice.recover_payee_pub_key());
    if payee.serialize() != req.newcomer_ln {
        return Err(invalid("the invoice is not payable to the key the request names"));
    }
    if invoice.amount_milli_satoshis() != Some(req.amount_msat) {
        return Err(invalid("the invoice amount differs from the request"));
    }
    if invoice.payment_hash().as_ref() as &[u8] != req.payment_hash.as_slice() {
        return Err(invalid("the invoice hash differs from the request"));
    }
    if invoice.expires_at().map_or(0, |d| d.as_secs()) <= now {
        return Err(invalid("the invoice has expired"));
    }
    let intro_id = hex::encode(req.intro_id);
    let code = req.comparison_code();
    let candidate = Candidate {
        newcomer: hex::encode(req.newcomer),
        newcomer_ln: hex::encode(req.newcomer_ln),
        payment_hash: hex::encode(req.payment_hash),
        bolt11: req.bolt11.clone(),
        code: code.clone(),
        expires_at: req.expires_at.min(invoice.expires_at().map_or(0, |d| d.as_secs())),
    };
    let (gift_msat, fee_msat, expires_at) = with_ledger(&state, |l, now| {
        req.verify(now, &net).map_err(invalid)?;
        if candidate.expires_at <= now {
            return Err(invalid("the invoice has expired"));
        }
        let kit = l.kit_mut(&intro_id)?;
        if kit.expires_at <= now {
            return Err(ApiError::Conflict("sponsor_kit_expired: make a new offer".into()));
        }
        if req.amount_msat != kit.gift_msat {
            return Err(invalid("the request is not for the offered gift"));
        }
        match (kit.state, &kit.candidate) {
            (KitState::Offered, _) => {}
            // Idempotent for the same request; any other one is refused.
            (KitState::Candidate, Some(c)) if *c == candidate => {}
            (KitState::Candidate, _) => {
                return Err(ApiError::Conflict("sponsor_candidate_exists: this kit already has a candidate; cancel and reissue if it is wrong".into()))
            }
            _ => return Err(ApiError::Conflict("sponsor_kit_closed: this introduction's gift is already used".into())),
        }
        kit.state = KitState::Candidate;
        kit.candidate = Some(candidate.clone());
        Ok((kit.gift_msat, kit.fee_msat, kit.expires_at.min(candidate.expires_at)))
    })
    .await?;
    Ok(Json(CandidateResponse { intro_id, newcomer: candidate.newcomer, payment_hash: candidate.payment_hash, gift_msat, fee_max_msat: fee_msat, code, expires_at }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub intro_id: String,
    /// Exact immutable funding intent the independent owner reviewed.
    pub newcomer: String,
    pub payment_hash: String,
    pub gift_msat: u64,
    pub fee_max_msat: u64,
    /// The code the owner compared with the newcomer's screen.
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct ApproveResponse {
    pub intro_id: String,
    pub state: KitState,
    pub paid_msat: u64,
    pub fee_paid_msat: u64,
    pub payment_hash: String,
}

/// Enforce the owner boundary before parsing an approval body, so paired
/// callers always receive the owner-approval refusal, including old clients.
struct SponsorOwner(MeteredSpend);

#[axum::async_trait]
impl axum::extract::FromRequestParts<Arc<AppState>> for SponsorOwner {
    type Rejection = axum::response::Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        use axum::response::IntoResponse;
        let auth = MeteredSpend::from_request_parts(parts, state).await?;
        // Same authority boundary as first_contact_grant: a delegated budget
        // cannot mint the independent owner's consent.
        if auth.is_metered() {
            return Err(ApiError::Conflict("sponsor_owner_approval_required".into()).into_response());
        }
        Ok(Self(auth))
    }
}

/// `POST /api/v1/sponsor/approve` — the owner's approval of exactly this
/// candidate. Re-checks the daily count and purse, reserves gift + fee
/// ceiling and consumes the intent in the same durable write before dispatch.
/// Paired credentials cannot provide this independent owner approval.
/// Settled → funded; failed → the kit closes;
/// anything else → unknown, reservation kept.
async fn approve(
    SponsorOwner(auth): SponsorOwner,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, ApiError> {
    let (candidate, fee_msat, deadline, debit, _active_dispatch) = {
        // One transaction validates the owner intent and consumes the kit
        // with its purse reservation. No await separates approval and claim.
        let _guard = LEDGER_LOCK.lock().await;
        let dir = ledger_dir(&state)?;
        let mut ledger = load_observed(&dir, now_unix()?)?;
        let now = ledger.last_observed_time;
        let policy = &state.sponsor;
        if !policy.enabled {
            return Err(ApiError::Conflict("sponsor_disabled: the owner has turned sponsoring off".into()));
        }
        let kit = ledger.kit_mut(&body.intro_id)?.clone();
        if kit.state != KitState::Candidate {
            return Err(ApiError::Conflict("sponsor_kit_not_ready: no candidate waiting on this kit".into()));
        }
        if kit.gift_msat > policy.gift_msat || kit.fee_msat > policy.fee_msat {
            return Err(ApiError::Conflict("sponsor_policy_changed: this candidate exceeds the current owner policy; make a new offer".into()));
        }
        if ledger.active(now) > core::MAX_ACTIVE_KITS {
            return Err(ApiError::Conflict("sponsor_kit_open: another kit is active".into()));
        }
        ledger.check_room(policy, kit.gift_msat.saturating_add(kit.fee_msat), now)?;
        let candidate = kit.candidate.clone().ok_or_else(|| ApiError::Internal("candidate".into()))?;
        if body.newcomer != candidate.newcomer || body.payment_hash != candidate.payment_hash
            || body.gift_msat != kit.gift_msat || body.fee_max_msat != kit.fee_msat {
            return Err(invalid("approval differs from the frozen funding intent"));
        }
        let deadline = kit.expires_at.min(candidate.expires_at);
        let invoice = candidate.bolt11.parse::<lightning_invoice::Bolt11Invoice>().map_err(invalid)?;
        if invoice.currency() != invoice_currency(&network(&state)?)? {
            return Err(invalid("invoice network differs from this sponsor"));
        }
        let deadline = deadline.min(invoice.expires_at().map_or(0, |d| d.as_secs()));
        if deadline <= now {
            return Err(ApiError::Conflict("sponsor_kit_expired: the request or invoice dispatch window has passed".into()));
        }
        if body.code.trim() != candidate.code {
            return Err(ApiError::BadRequest("sponsor_code_mismatch: the code does not match this candidate; nothing was paid".into()));
        }
        let (gift_msat, payee) = super::payments::invoice_terms(&candidate.bolt11)?;
        let pending = ledger.kit_mut(&body.intro_id)?;
        pending.state = KitState::Paying;
        pending.approved_at = Some(now);
        pending.reserved_msat = kit.gift_msat.saturating_add(kit.fee_msat);
        let debit = auth.debit_linked(&state, vec![Charge { recipient: payee, amount_msat: gift_msat }], |reservation| {
            ledger.kit_mut(&body.intro_id).map_err(|e| BudgetRefusal::Ledger(e.to_string()))?
                .grant_reservation = reservation.cloned();
            save(&dir, &ledger).map_err(|e| BudgetRefusal::Ledger(e.to_string()))
        });
        let debit = match debit {
            Ok(debit) => debit,
            Err(error) => {
                // No backend was invoked. Restore the candidate; no async gap
                // can leave a second caller dispatching this same kit.
                *ledger.kit_mut(&body.intro_id)? = kit;
                save(&dir, &ledger)?;
                return Err(error);
            }
        };
        let active = ActiveDispatch::start(dir, body.intro_id.clone());
        (candidate, kit.fee_msat, deadline, debit, active)
    };
    // A hash alone cannot distinguish two attempts (nor can second-resolution
    // timestamps). Sponsor gifts only dispatch fresh invoices. Persist the
    // proof before calling the backend so failure reconciliation survives a
    // process restart. Lookup errors other than absence fail before dispatch.
    let preflight = match state.lightning.get_payment_status(&candidate.payment_hash).await {
        Err(LightningError::PaymentNotFound(_)) => {
            with_ledger(&state, |ledger, _now| {
                ledger.kit_mut(&body.intro_id)?.fresh_payment_hash = true;
                Ok(())
            }).await?;
            Ok(())
        }
        Ok(_) => Err(LightningError::PaymentNotDispatched("sponsor invoice already has a payment record; request a fresh invoice".into())),
        Err(e) => Err(LightningError::PaymentNotDispatched(format!("cannot establish a fresh sponsor invoice: {e}"))),
    };
    let result = debit.dispatch(async {
        preflight?;
        let now = with_ledger(&state, |_, now| Ok(now)).await
            .map_err(|e| LightningError::PaymentNotDispatched(e.to_string()))?;
        if now >= deadline {
            return Err(LightningError::PaymentNotDispatched("sponsor request expired before dispatch".into()));
        }
        state.lightning.pay_invoice_with_fee_limit(&candidate.bolt11, fee_msat).await
    }).await;
    let paid = match result {
        Ok(paid) => paid,
        Err(ApiError::BudgetExceeded(e)) => Err(LightningError::PaymentNotDispatched(e.to_string())),
        Err(e) => Err(LightningError::Backend(e.to_string())),
    };
    let outcome = with_ledger(&state, |ledger, now| {
        let kit = ledger.kit_mut(&body.intro_id)?;
        record_outcome(kit, &paid, now, true);
        Ok(kit.clone())
    }).await?;
    resolve_grant(&state, &outcome);
    if outcome.state == KitState::Failed {
        return Err(ApiError::Lightning("the gift was definitively not paid".into()));
    }
    Ok(Json(ApproveResponse {
        intro_id: outcome.intro_id,
        state: outcome.state,
        paid_msat: outcome.paid_msat,
        fee_paid_msat: outcome.fee_paid_msat,
        payment_hash: candidate.payment_hash,
    }))
}

/// Only the outgoing record for the exact approved operation may release a
/// reservation. Terminal outcomes are monotonic across concurrent callers.
fn record_outcome(kit: &mut Kit, result: &Result<PaymentDetails, LightningError>, now: u64, from_dispatch: bool) {
    if matches!(kit.state, KitState::Failed | KitState::Cancelled | KitState::Expired)
        || (kit.state == KitState::Funded && kit.reserved_msat == 0) {
        return;
    }
    let valid = |d: &PaymentDetails| d.direction == PaymentDirection::Outgoing
        && kit.candidate.as_ref().is_some_and(|c| c.payment_hash == d.payment_hash);
    match result {
        Ok(d) if valid(d) && d.status == PaymentStatus::Settled && d.amount_msat == kit.gift_msat => {
            kit.state = KitState::Funded;
            kit.paid_msat = d.amount_msat;
            match d.fee_msat {
                Some(fee) if fee <= kit.fee_msat => {
                    kit.fee_paid_msat = fee;
                    kit.reserved_msat = 0;
                    // Timestamp reconciliation, not initiation: providers often
                    // expose only the latter. This conservatively retains loss.
                    kit.settled_at = Some(now.max(kit.approved_at.unwrap_or(now)));
                }
                _ => {
                    // Missing/invalid fee information cannot free any allowance.
                    kit.reserved_msat = kit.gift_msat.saturating_add(kit.fee_msat)
                        .max(d.amount_msat.saturating_add(d.fee_msat.unwrap_or(0)));
                }
            }
        }
        Ok(d) if valid(d) && matches!(d.status, PaymentStatus::Failed | PaymentStatus::Expired)
            && kit.state != KitState::Funded && (from_dispatch || kit.fresh_payment_hash) => {
                kit.state = KitState::Failed;
                kit.reserved_msat = 0;
            }
        Err(LightningError::PaymentNotDispatched(_)) if kit.state != KitState::Funded => {
            kit.state = KitState::Failed;
            kit.reserved_msat = 0;
        }
        _ if kit.state != KitState::Funded => kit.state = KitState::Unknown,
        _ => {}
    }
}

/// Retain this reference even after resolution. Pairing resolution is durable
/// and idempotent; retrying a terminal kit repairs a failed grant-store write.
fn resolve_grant(state: &AppState, kit: &Kit) {
    let actual = match kit.state {
        KitState::Funded => kit.paid_msat,
        KitState::Failed => 0,
        _ => return,
    };
    if let (Some(service), Some(reservation), Some(candidate)) =
        (&state.pairing, &kit.grant_reservation, &kit.candidate) {
        service.resolve_spend(reservation, &candidate.newcomer_ln, actual);
    }
}

/// `POST /api/v1/sponsor/kits/:intro_id/cancel` — withdraw an offer or a
/// candidate before dispatch. A paid or pending kit cannot be cancelled.
async fn cancel(
    _auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    UrlPath(intro_id): UrlPath<String>,
) -> Result<Json<Kit>, ApiError> {
    with_ledger(&state, |l, _now| {
        let kit = l.kit_mut(&intro_id)?;
        if !matches!(kit.state, KitState::Offered | KitState::Candidate) {
            return Err(ApiError::Conflict("sponsor_kit_dispatched: only an undispatched kit can be cancelled".into()));
        }
        kit.state = KitState::Cancelled;
        Ok(kit.clone())
    })
    .await
    .map(Json)
}

/// `POST /api/v1/sponsor/kits/:intro_id/reconcile` — settle an unknown
/// outcome from the backend's own record of the outgoing payment. This
/// never dispatches, so an expired/revoked spend grant is not a prerequisite.
async fn reconcile(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    UrlPath(intro_id): UrlPath<String>,
) -> Result<Json<Kit>, ApiError> {
    let (snapshot, active) = with_ledger(&state, |ledger, _now| {
        let kit = ledger.kit_mut(&intro_id)?;
        if !matches!(kit.state, KitState::Unknown | KitState::Paying | KitState::Funded | KitState::Failed) {
            return Err(ApiError::Conflict("sponsor_kit_not_dispatched: nothing to reconcile".into()));
        }
        Ok((kit.clone(), ActiveDispatch::contains(&ledger_dir(&state)?, &intro_id)))
    }).await?;
    if active {
        return Ok(Json(snapshot));
    }
    if snapshot.state == KitState::Failed || (snapshot.state == KitState::Funded && snapshot.reserved_msat == 0) {
        resolve_grant(&state, &snapshot);
        return Ok(Json(snapshot));
    }
    let hash = &snapshot.candidate.as_ref().ok_or_else(|| ApiError::Internal("candidate".into()))?.payment_hash;
    // A lookup error says nothing definitive about dispatch, even if a
    // backend happens to reuse a pre-dispatch error variant here.
    let details = state.lightning.get_payment_status(hash).await
        .map_err(|e| LightningError::Backend(e.to_string()));
    // Re-read under lock: another reconciliation or the original approval
    // may have completed while the backend was awaited.
    let outcome = with_ledger(&state, |ledger, now| {
        let kit = ledger.kit_mut(&intro_id)?;
        record_outcome(kit, &details, now, false);
        Ok(kit.clone())
    }).await?;
    resolve_grant(&state, &outcome);
    Ok(Json(outcome))
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub enabled: bool,
    pub gift_msat: u64,
    pub fee_msat: u64,
    pub purse_msat: u64,
    pub purse_used_msat: u64,
    pub kits_per_day: u32,
    pub kits_today: u32,
    pub kits: Vec<Kit>,
}

/// `GET /api/v1/sponsor` — the policy, the rolling purse and the kits
/// (newest first). Bolt11 strings are left out of this read.
async fn status(_auth: ScopedAuth<Read>, State(state): State<Arc<AppState>>) -> Result<Json<StatusResponse>, ApiError> {
    let p = state.sponsor.clone();
    let now = now_unix()?;
    let _guard = LEDGER_LOCK.lock().await;
    let ledger = match ledger_dir(&state) {
        Ok(dir) => load_observed(&dir, now)?,
        Err(_) => Ledger::default(),
    };
    let mut kits: Vec<Kit> = ledger.kits.iter().rev().take(20).cloned().collect();
    for k in &mut kits {
        if let Some(c) = &mut k.candidate {
            c.bolt11.clear();
        }
    }
    Ok(Json(StatusResponse {
        enabled: p.enabled,
        gift_msat: p.gift_msat,
        fee_msat: p.fee_msat,
        purse_msat: p.purse_msat,
        purse_used_msat: ledger.purse_used(now),
        kits_per_day: p.kits_per_day,
        kits_today: ledger.kits_today(now),
        kits,
    }))
}

// ---- newcomer side -----------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FundingAsk {
    /// The introduction link with its offer: `bitsov://introduce#<card>.<offer>`.
    pub link: String,
}

#[derive(Debug, Serialize)]
pub struct FundingAskResponse {
    /// `bitsov://sponsor-request#…`: show it to the sponsor as a QR.
    pub request: String,
    /// The six digits to compare with the sponsor's screen.
    pub code: String,
    pub sponsor: String,
    pub amount_msat: u64,
    pub payment_hash: String,
    pub expires_at: u64,
}

/// `POST /api/v1/sponsor/request` — the newcomer's node asks for the offered
/// gift into one fixed invoice to its own wallet. The invoice's hash is made
/// funding-only (the gate refuses it as a message proof) before the invoice
/// is returned. Receive scope: it creates the means to be paid. Nothing is
/// sent anywhere; the request goes to the sponsor in person.
async fn request_funding(
    _auth: ScopedAuth<Receive>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<FundingAsk>,
) -> Result<Json<FundingAskResponse>, ApiError> {
    let now = now_unix()?;
    let net = network(&state)?;
    let (_, offer_text) = core::split_introduction_link(&body.link);
    let offer_text = offer_text.ok_or_else(|| invalid("this introduction offers no starter bitcoin"))?;
    let card = super::introduction::verified_card(&state, &body.link)?;
    let offer = SponsorOffer::decode(&offer_text).map_err(invalid)?;
    offer.verify(now, &net).map_err(invalid)?;
    if hex::encode(offer.sponsor) != card.node_id || hex::encode(offer.intro_id) != card.intro_id {
        return Err(invalid("the offer does not belong to this introduction"));
    }
    if offer.sponsor == *state.identity.node_id().as_bytes() {
        return Err(invalid("this is your own offer"));
    }
    let expiry = offer.expires_at.saturating_sub(now).clamp(60, core::OFFER_LIFETIME_SECS) as u32;
    let description = format!("bitsov starter bitcoin {}", &card.intro_id[..8]);
    let invoice = state
        .lightning
        .create_invoice(offer.gift_msat, &description, expiry)
        .await
        .map_err(|e| ApiError::Lightning(format!("could not create the funding invoice: {e}")))?;
    let hash: [u8; 32] = hex::decode(&invoice.payment_hash).ok().and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::Internal("invoice hash".into()))?;
    // Funding-only BEFORE the invoice leaves this node: the gate's durable
    // receipt table now holds this hash, so an envelope proving payment with
    // it is refused as a reused payment. Fail closed if it cannot be stored.
    let sentinel = MessageId::from_bytes(*blake3::hash(&[b"bitsov-sponsor-funding/v1".as_slice(), &hash].concat()).as_bytes());
    let own = NodeId::from_bytes(*state.identity.node_id().as_bytes());
    match state.storage.store_payment_receipt(&hash, &own, &sentinel).await {
        Ok(true) => {}
        Ok(false) => return Err(ApiError::Conflict("sponsor_hash_in_use: the invoice hash is already a receipt; nothing was requested".into())),
        Err(e) => return Err(ApiError::Storage(format!("could not mark the funding invoice funding-only; nothing was requested: {e}"))),
    }
    let parsed = invoice.bolt11.parse::<lightning_invoice::Bolt11Invoice>().map_err(|e| ApiError::Internal(format!("own invoice: {e}")))?;
    let payee = parsed.payee_pub_key().copied().unwrap_or_else(|| parsed.recover_payee_pub_key());
    let request = FundingRequest::sign(
        state.identity.ed25519_signing_key(),
        &offer,
        payee.serialize(),
        offer.gift_msat,
        hash,
        now + u64::from(expiry),
        invoice.bolt11,
    )
    .map_err(invalid)?;
    Ok(Json(FundingAskResponse {
        request: request.to_link(),
        code: request.comparison_code(),
        sponsor: card.node_id,
        amount_msat: request.amount_msat,
        payment_hash: invoice.payment_hash,
        expires_at: request.expires_at,
    }))
}

#[derive(Debug, Serialize)]
pub struct FundingStatus {
    pub payment_hash: String,
    /// `waiting` or `received`.
    pub state: &'static str,
    pub amount_msat: u64,
}

/// `GET /api/v1/sponsor/request/:hash` — has the starter bitcoin arrived?
async fn funding_status(
    _auth: ScopedAuth<Read>,
    State(state): State<Arc<AppState>>,
    UrlPath(hash): UrlPath<String>,
) -> Result<Json<FundingStatus>, ApiError> {
    if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("payment hash must be 64 hex"));
    }
    let received = state.lightning.get_payment_status(&hash).await.ok()
        .filter(|d| d.direction == PaymentDirection::Incoming && d.status == PaymentStatus::Settled);
    Ok(Json(FundingStatus {
        payment_hash: hash,
        state: if received.is_some() { "received" } else { "waiting" },
        amount_msat: received.map_or(0, |d| d.amount_msat),
    }))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/sponsor", get(status))
        .route("/api/v1/sponsor/offer", post(create_offer))
        .route("/api/v1/sponsor/candidate", post(add_candidate))
        .route("/api/v1/sponsor/approve", post(approve))
        .route("/api/v1/sponsor/kits/:intro_id/cancel", post(cancel))
        .route("/api/v1/sponsor/kits/:intro_id/reconcile", post(reconcile))
        .route("/api/v1/sponsor/request", post(request_funding))
        .route("/api/v1/sponsor/request/:hash", get(funding_status))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;

    fn kit(state: KitState, approved_at: Option<u64>, reserved: u64, paid: u64) -> Kit {
        Kit {
            intro_id: "00".repeat(16),
            gift_msat: 20_000,
            fee_msat: 1_000,
            created_at: NOW - 100,
            expires_at: NOW + 500,
            state,
            candidate: None,
            approved_at,
            settled_at: None,
            grant_reservation: None,
            fresh_payment_hash: false,
            reserved_msat: reserved,
            paid_msat: paid,
            fee_paid_msat: 0,
        }
    }

    #[test]
    fn unknown_outcomes_keep_their_reservation_in_the_purse() {
        let l = Ledger { version: 1, last_observed_time: 0, kits: vec![kit(KitState::Unknown, Some(NOW - 10), 21_000, 0)] };
        assert_eq!(l.purse_used(NOW), 21_000);
        assert_eq!(l.active(NOW), 1, "an unknown kit blocks a new one until reconciled");
        let failed = Ledger { version: 1, last_observed_time: 0, kits: vec![kit(KitState::Failed, Some(NOW - 10), 0, 0)] };
        assert_eq!(failed.purse_used(NOW), 0);
        assert_eq!(failed.kits_today(NOW), 1, "a failed approval still used a daily kit");
    }

    #[test]
    fn a_clock_moved_back_cannot_refresh_the_purse() {
        // Approved "in the future" relative to a clock that went back: still counts.
        let l = Ledger { version: 1, last_observed_time: 0, kits: vec![kit(KitState::Funded, Some(NOW + 3_600), 0, 20_000)] };
        assert_eq!(l.purse_used(NOW), 20_000);
        assert_eq!(l.kits_today(NOW), 1);
        // A day after approval it leaves the window.
        let old = Ledger { version: 1, last_observed_time: 0, kits: vec![kit(KitState::Funded, Some(NOW - DAY_SECS), 0, 20_000)] };
        assert_eq!(old.purse_used(NOW), 0);
    }

    #[test]
    fn an_expired_offer_no_longer_blocks_a_new_kit() {
        let mut k = kit(KitState::Offered, None, 0, 0);
        k.expires_at = NOW - 1;
        let l = Ledger { version: 1, last_observed_time: 0, kits: vec![k] };
        assert_eq!(l.active(NOW), 0);
        let policy = SponsorPolicy::new(true, 20_000, 1_000, 100_000, 2).unwrap();
        assert!(l.check_new_kit(&policy, NOW).is_ok());
    }

    #[test]
    fn observed_expiry_and_time_floor_survive_reload_and_rollback() {
        let dir = tempfile::tempdir().unwrap();
        let mut a = kit(KitState::Offered, None, 0, 0);
        a.intro_id = "A".into();
        a.created_at = 1000;
        a.expires_at = 1600;
        save(dir.path(), &Ledger { version: 1, kits: vec![a], ..Ledger::default() }).unwrap();
        let mut ledger = load_observed(dir.path(), 1601).unwrap();
        assert_eq!(ledger.active(1601), 0);
        let mut b = kit(KitState::Offered, None, 0, 0);
        b.intro_id = "B".into();
        b.created_at = 1601;
        b.expires_at = 2201;
        ledger.kits.push(b);
        save(dir.path(), &ledger).unwrap();
        drop(ledger);
        let restarted = load_observed(dir.path(), 1599).unwrap();
        assert_eq!(restarted.active(1599), 1, "A must not revive alongside B");
        assert_eq!(restarted.kits[0].state, KitState::Expired);
        assert_eq!(restarted.last_observed_time, 1601);
        assert_eq!(load(dir.path()).unwrap().last_observed_time, 1601);
        let expired = load_observed(dir.path(), 2201).unwrap();
        assert_eq!(expired.active(2201), 0, "expiry is inclusive");
        assert_eq!(load_observed(dir.path(), 1000).unwrap().active(1000), 0);
    }

    #[test]
    fn candidate_deadline_retires_kit_without_releasing_unresolved_payments() {
        let dir = tempfile::tempdir().unwrap();
        let (mut candidate, _) = pending_with_record();
        candidate.state = KitState::Candidate;
        candidate.reserved_msat = 0;
        let (unknown, _) = pending_with_record();
        save(dir.path(), &Ledger { version: 1, kits: vec![candidate, unknown], ..Ledger::default() }).unwrap();
        let ledger = load_observed(dir.path(), NOW + 50).unwrap();
        assert_eq!(ledger.kits[0].state, KitState::Expired);
        assert_eq!(ledger.kits[1].state, KitState::Unknown);
        assert_eq!(ledger.purse_used(NOW + DAY_SECS * 2), 21_000);
    }

    fn pending_with_record() -> (Kit, PaymentDetails) {
        let mut k = kit(KitState::Unknown, Some(NOW - 10), 21_000, 0);
        k.candidate = Some(Candidate {
            newcomer: "11".repeat(32), newcomer_ln: "02".repeat(33),
            payment_hash: "33".repeat(32), bolt11: String::new(),
            code: "123456".into(), expires_at: NOW + 50,
        });
        let d = PaymentDetails {
            payment_hash: "33".repeat(32), preimage: None, amount_msat: 20_000,
            status: PaymentStatus::Settled, direction: PaymentDirection::Outgoing,
            timestamp: NOW - 10, memo: None, fee_msat: Some(100),
        };
        (k, d)
    }

    #[test]
    fn stale_pending_or_failed_results_cannot_undo_a_known_settlement() {
        let (mut k, mut d) = pending_with_record();
        record_outcome(&mut k, &Ok(d.clone()), NOW, true);
        assert_eq!(k.charge(NOW), 20_100);
        for status in [PaymentStatus::InFlight, PaymentStatus::Failed] {
            d.status = status;
            record_outcome(&mut k, &Ok(d.clone()), NOW + 1, true);
            assert_eq!(k.state, KitState::Funded);
            assert_eq!(k.charge(NOW + 1), 20_100);
            assert_eq!(k.settled_at, Some(NOW));
        }
    }

    #[test]
    fn only_the_exact_outgoing_record_can_release_a_reservation() {
        let (mut k, d) = pending_with_record();
        let mut wrong = d.clone();
        wrong.payment_hash = "44".repeat(32);
        wrong.status = PaymentStatus::Failed;
        record_outcome(&mut k, &Ok(wrong), NOW, true);
        assert_eq!(k.charge(NOW), 21_000);
        let mut wrong = d.clone();
        wrong.direction = PaymentDirection::Incoming;
        record_outcome(&mut k, &Ok(wrong), NOW, true);
        assert_eq!(k.charge(NOW), 21_000);
        let mut wrong = d;
        wrong.amount_msat = 1;
        record_outcome(&mut k, &Ok(wrong), NOW, true);
        assert_eq!(k.state, KitState::Unknown);
        assert_eq!(k.charge(NOW), 21_000);
    }
}
