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
//! pays. A metered (paired) caller is also debited against its G1 grant.
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
use konsensus_core::traits::lightning::{LightningError, PaymentDirection, PaymentStatus};
use konsensus_core::types::{MessageId, NodeId};

use crate::auth::scoped::{Read, Receive, ScopedAuth};
use crate::error::ApiError;
use crate::metered::MeteredSpend;
use crate::spend_budget::Charge;
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
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    pub newcomer: String,
    pub newcomer_ln: String,
    pub payment_hash: String,
    pub bolt11: String,
    pub code: String,
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
    /// Set when the owner approved: the purse and daily count use it.
    pub approved_at: Option<u64>,
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
            _ => false,
        }
    }

    fn in_day(&self, now: u64) -> bool {
        // A reservation dated after `now` (clock moved back) still counts.
        self.approved_at.is_some_and(|at| at.saturating_add(DAY_SECS) > now)
    }

    /// What this kit holds against the purse.
    fn charge(&self, now: u64) -> u64 {
        if !self.in_day(now) {
            return 0;
        }
        match self.state {
            KitState::Paying | KitState::Unknown => self.reserved_msat,
            KitState::Funded => self.paid_msat.saturating_add(self.fee_paid_msat),
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub version: u32,
    pub kits: Vec<Kit>,
}

impl Ledger {
    pub fn purse_used(&self, now: u64) -> u64 {
        self.kits.iter().map(|k| k.charge(now)).sum()
    }

    pub fn kits_today(&self, now: u64) -> u32 {
        self.kits.iter().filter(|k| k.in_day(now)).count() as u32
    }

    pub fn active(&self, now: u64) -> u32 {
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
        self.check_room(policy, now)
    }

    fn check_room(&self, policy: &SponsorPolicy, now: u64) -> Result<(), ApiError> {
        if self.kits_today(now) >= policy.kits_per_day {
            return Err(ApiError::Conflict(format!(
                "sponsor_daily_limit: {} kits in the last 24 hours",
                policy.kits_per_day
            )));
        }
        if self.purse_used(now).saturating_add(policy.kit_msat()) > policy.purse_msat {
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
            let ledger: Ledger = serde_json::from_slice(&bytes)
                .map_err(|e| ApiError::Internal(format!("sponsor ledger unreadable: {e}")))?;
            if ledger.version != LEDGER_VERSION {
                return Err(ApiError::Internal(format!("sponsor ledger version {} not supported", ledger.version)));
            }
            Ok(ledger)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ledger { version: LEDGER_VERSION, kits: Vec::new() }),
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
    let _ = crate::pairing::fsync_dir(dir);
    Ok(())
}

/// Run `edit` on the ledger under the lock, saving only if it succeeds.
async fn with_ledger<T>(state: &AppState, edit: impl FnOnce(&mut Ledger) -> Result<T, ApiError>) -> Result<T, ApiError> {
    let _guard = LEDGER_LOCK.lock().await;
    let dir = ledger_dir(state)?;
    let mut ledger = load(&dir)?;
    let out = edit(&mut ledger)?;
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
    let now = now_unix()?;
    // Check first, so a refused offer signs nothing.
    with_ledger(&state, |l| l.check_new_kit(&policy, now)).await?;
    let card = super::introduction::issue_card(&state).await?;
    let intro_id: [u8; 16] = hex::decode(&card.intro_id).ok().and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::Internal("card id".into()))?;
    let expires_at = card.expires_at.min(now + core::OFFER_LIFETIME_SECS);
    let offer = SponsorOffer::sign(state.identity.ed25519_signing_key(), &card.network, intro_id, policy.gift_msat, expires_at)
        .map_err(|e| ApiError::Internal(format!("offer: {e}")))?;
    with_ledger(&state, |l| {
        l.check_new_kit(&policy, now)?;
        l.kits.push(Kit {
            intro_id: card.intro_id.clone(),
            gift_msat: policy.gift_msat,
            fee_msat: policy.fee_msat,
            created_at: now,
            expires_at,
            state: KitState::Offered,
            candidate: None,
            approved_at: None,
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
    let now = now_unix()?;
    let req = FundingRequest::parse(&body.request).map_err(invalid)?;
    req.verify(now, &network(&state)?).map_err(invalid)?;
    if req.sponsor != *state.identity.node_id().as_bytes() {
        return Err(invalid("this request is for another sponsor"));
    }
    // The invoice must be exactly what the newcomer signed: its amount, its
    // hash, and payable to the Lightning key the request binds.
    let invoice = req.bolt11.parse::<lightning_invoice::Bolt11Invoice>().map_err(|e| invalid(format!("invoice: {e}")))?;
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
    if invoice.is_expired() {
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
    };
    let (gift_msat, fee_msat, expires_at) = with_ledger(&state, |l| {
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
        Ok((kit.gift_msat, kit.fee_msat, kit.expires_at))
    })
    .await?;
    Ok(Json(CandidateResponse { intro_id, newcomer: candidate.newcomer, gift_msat, fee_max_msat: fee_msat, code, expires_at }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveRequest {
    pub intro_id: String,
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

/// `POST /api/v1/sponsor/approve` — the owner's approval of exactly this
/// candidate. Re-checks the daily count and purse, reserves gift + fee
/// ceiling and persists that before dispatch; a paired caller is debited
/// against its G1 grant too. Settled → funded; failed → the kit closes;
/// anything else → unknown, reservation kept.
async fn approve(
    auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ApproveRequest>,
) -> Result<Json<ApproveResponse>, ApiError> {
    let policy = state.sponsor.clone();
    let now = now_unix()?;
    let candidate = with_ledger(&state, |l| {
        if !policy.enabled {
            return Err(ApiError::Conflict("sponsor_disabled: the owner has turned sponsoring off".into()));
        }
        l.check_room(&policy, now)?;
        let kit = l.kit_mut(&body.intro_id)?;
        if kit.state != KitState::Candidate {
            return Err(ApiError::Conflict("sponsor_kit_not_ready: no candidate waiting on this kit".into()));
        }
        if kit.expires_at <= now {
            return Err(ApiError::Conflict("sponsor_kit_expired: the ten-minute dispatch window has passed".into()));
        }
        let c = kit.candidate.clone().ok_or_else(|| ApiError::Internal("candidate".into()))?;
        if body.code.trim() != c.code {
            return Err(ApiError::BadRequest("sponsor_code_mismatch: the code does not match this candidate; nothing was paid".into()));
        }
        kit.state = KitState::Paying;
        kit.approved_at = Some(now);
        kit.reserved_msat = kit.gift_msat.saturating_add(kit.fee_msat);
        Ok(c)
    })
    .await?;

    // G1: a paired caller's grant is debited before dispatch as well.
    let (gift_msat, payee) = super::payments::invoice_terms(&candidate.bolt11)?;
    let debit = match auth.debit(&state, vec![Charge { recipient: payee.clone(), amount_msat: gift_msat }]) {
        Ok(d) => d,
        Err(e) => {
            // Nothing dispatched: return the kit to its candidate state.
            with_ledger(&state, |l| {
                let kit = l.kit_mut(&body.intro_id)?;
                kit.state = KitState::Candidate;
                kit.approved_at = None;
                kit.reserved_msat = 0;
                Ok(())
            })
            .await?;
            return Err(e);
        }
    };
    let paid = debit.dispatch(state.lightning.pay_invoice(&candidate.bolt11)).await;
    let paid = match paid {
        Ok(p) => p,
        Err(e) => Err(LightningError::Backend(e.to_string())),
    };
    if debit.is_metered() {
        super::payments::resolve_payment(&debit, &payee, &paid);
    }
    let outcome = with_ledger(&state, |l| {
        let kit = l.kit_mut(&body.intro_id)?;
        match &paid {
            Ok(d) if d.status == PaymentStatus::Settled => {
                kit.state = KitState::Funded;
                kit.paid_msat = d.amount_msat;
                kit.fee_paid_msat = d.fee_msat.unwrap_or(0);
                kit.reserved_msat = 0;
            }
            Ok(d) if matches!(d.status, PaymentStatus::Failed | PaymentStatus::Expired) => {
                kit.state = KitState::Failed;
                kit.reserved_msat = 0;
            }
            Err(LightningError::PaymentNotDispatched(_)) => {
                kit.state = KitState::Failed;
                kit.reserved_msat = 0;
            }
            _ => kit.state = KitState::Unknown,
        }
        Ok(kit.clone())
    })
    .await?;
    if outcome.state == KitState::Failed {
        return Err(ApiError::Lightning(format!(
            "the gift was not paid: {}",
            paid.err().map(|e| e.to_string()).unwrap_or_else(|| "payment failed".into())
        )));
    }
    Ok(Json(ApproveResponse {
        intro_id: outcome.intro_id,
        state: outcome.state,
        paid_msat: outcome.paid_msat,
        fee_paid_msat: outcome.fee_paid_msat,
        payment_hash: candidate.payment_hash,
    }))
}

/// `POST /api/v1/sponsor/kits/:intro_id/cancel` — withdraw an offer or a
/// candidate before dispatch. A paid or pending kit cannot be cancelled.
async fn cancel(
    _auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    UrlPath(intro_id): UrlPath<String>,
) -> Result<Json<Kit>, ApiError> {
    with_ledger(&state, |l| {
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
/// outcome from the backend's own record of the outgoing payment.
async fn reconcile(
    _auth: MeteredSpend,
    State(state): State<Arc<AppState>>,
    UrlPath(intro_id): UrlPath<String>,
) -> Result<Json<Kit>, ApiError> {
    let hash = with_ledger(&state, |l| {
        let kit = l.kit_mut(&intro_id)?;
        if !matches!(kit.state, KitState::Unknown | KitState::Paying) {
            return Err(ApiError::Conflict("sponsor_kit_resolved: nothing to reconcile".into()));
        }
        kit.candidate.as_ref().map(|c| c.payment_hash.clone()).ok_or_else(|| ApiError::Internal("candidate".into()))
    })
    .await?;
    let details = state.lightning.get_payment_status(&hash).await.ok();
    with_ledger(&state, |l| {
        let kit = l.kit_mut(&intro_id)?;
        match details {
            Some(d) if d.direction == PaymentDirection::Outgoing && d.status == PaymentStatus::Settled => {
                kit.state = KitState::Funded;
                kit.paid_msat = d.amount_msat;
                kit.fee_paid_msat = d.fee_msat.unwrap_or(0);
                kit.reserved_msat = 0;
            }
            Some(d) if d.direction == PaymentDirection::Outgoing && matches!(d.status, PaymentStatus::Failed | PaymentStatus::Expired) => {
                kit.state = KitState::Failed;
                kit.reserved_msat = 0;
            }
            // No definitive record: the reservation stays.
            _ => kit.state = KitState::Unknown,
        }
        Ok(kit.clone())
    })
    .await
    .map(Json)
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
        Ok(dir) => load(&dir)?,
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
            reserved_msat: reserved,
            paid_msat: paid,
            fee_paid_msat: 0,
        }
    }

    #[test]
    fn unknown_outcomes_keep_their_reservation_in_the_purse() {
        let l = Ledger { version: 1, kits: vec![kit(KitState::Unknown, Some(NOW - 10), 21_000, 0)] };
        assert_eq!(l.purse_used(NOW), 21_000);
        assert_eq!(l.active(NOW), 1, "an unknown kit blocks a new one until reconciled");
        let failed = Ledger { version: 1, kits: vec![kit(KitState::Failed, Some(NOW - 10), 0, 0)] };
        assert_eq!(failed.purse_used(NOW), 0);
        assert_eq!(failed.kits_today(NOW), 1, "a failed approval still used a daily kit");
    }

    #[test]
    fn a_clock_moved_back_cannot_refresh_the_purse() {
        // Approved "in the future" relative to a clock that went back: still counts.
        let l = Ledger { version: 1, kits: vec![kit(KitState::Funded, Some(NOW + 3_600), 0, 20_000)] };
        assert_eq!(l.purse_used(NOW), 20_000);
        assert_eq!(l.kits_today(NOW), 1);
        // A day after approval it leaves the window.
        let old = Ledger { version: 1, kits: vec![kit(KitState::Funded, Some(NOW - DAY_SECS), 0, 20_000)] };
        assert_eq!(old.purse_used(NOW), 0);
    }

    #[test]
    fn an_expired_offer_no_longer_blocks_a_new_kit() {
        let mut k = kit(KitState::Offered, None, 0, 0);
        k.expires_at = NOW - 1;
        let l = Ledger { version: 1, kits: vec![k] };
        assert_eq!(l.active(NOW), 0);
        let policy = SponsorPolicy::new(true, 20_000, 1_000, 100_000, 2).unwrap();
        assert!(l.check_new_kit(&policy, NOW).is_ok());
    }
}
