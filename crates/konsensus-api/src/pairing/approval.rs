//! Separate-owner-device approvals. Requests and rate counters are process-local;
//! only a verified, consumed spend approval is persisted with its signature.
use super::{device, DeviceKey, Inner, PairingError, PairingService, SpendGrant};
use crate::auth::Scope;
use crate::spend_budget::{BudgetRefusal, GrantBudget, GrantTerms};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Feature detection for the two PR A approval kinds.
pub const CAPABILITY: &str = "owner_device_approval_v1";
const TTL: i64 = 300;
const PER_HOUR: usize = 30;

/// Strict request vocabulary: no caller-supplied identity, nonce or operation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "kind",
    content = "terms",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ApprovalRequest {
    /// A bounded ordinary spend window. Breakers cannot be weakened by the client.
    SpendGrant {
        /// Total budget in millisatoshis.
        budget_msat: u64,
        /// Maximum reservation for one call.
        per_call_max_msat: u64,
        /// Window from approval, bounded by the console's limits.
        window_secs: i64,
        /// Optional exclusive recipient (node id).
        recipient: Option<String>,
    },
    /// A single first-contact payment under the client's current live grant.
    FirstContact {
        /// Node id, canonicalized before rendering.
        recipient: String,
        /// Maximum aggregate first-contact payment.
        max_total_msat: u64,
        /// Optional persistent recipient cap, as on the console path.
        budget_msat: Option<u64>,
    },
}
impl ApprovalRequest {
    /// Stable audit/protocol kind.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::SpendGrant { .. } => "spend_grant",
            Self::FirstContact { .. } => "first_contact",
        }
    }
    fn spend_terms(&self) -> Result<GrantTerms, PairingError> {
        let Self::SpendGrant {
            budget_msat,
            per_call_max_msat,
            window_secs,
            recipient,
        } = self
        else {
            return Err(PairingError::BadProof);
        };
        let mut terms = GrantTerms::new(*budget_msat)
            .per_call(*per_call_max_msat)
            .for_secs(*window_secs);
        if let Some(recipient) = recipient {
            terms = terms.recipient(recipient, *budget_msat);
            terms.payee_allowlist = Some([recipient.clone()].into_iter().collect());
        }
        terms.normalized().map_err(PairingError::Malformed)
    }
    fn normalize(mut self) -> Result<Self, PairingError> {
        let recipient = match &mut self {
            Self::SpendGrant { recipient, .. } => recipient.as_mut(),
            Self::FirstContact { recipient, .. } => Some(recipient),
        };
        if let Some(recipient) = recipient {
            *recipient = crate::spend_budget::canonical_recipient(recipient)
                .filter(|r| r.len() == 64)
                .ok_or_else(|| PairingError::Malformed("recipient must be a node id".into()))?;
        }
        match &self {
            Self::SpendGrant { .. } => {
                self.spend_terms()?;
            }
            Self::FirstContact { max_total_msat, .. }
                if *max_total_msat == 0
                    || *max_total_msat > crate::spend_budget::FIRST_CONTACT_MAX_MSAT =>
            {
                return Err(PairingError::Malformed(
                    "first contact must cover 1..=100000 msat".into(),
                ))
            }
            _ => {}
        }
        Ok(self)
    }
}

/// Public exact terms, all binding fields supplied by the node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalOperation {
    /// Server-issued operation id.
    pub op_id: String,
    /// Node fingerprint at creation.
    pub node: String,
    /// Requesting pairing id.
    pub client_id: String,
    /// Requesting pairing public key.
    pub client_pubkey: String,
    /// Requesting pairing epoch.
    pub epoch: u64,
    /// Live grant snapshot, if any; replacing it invalidates this request.
    pub grant_op: Option<String>,
    /// Canonical bounded terms.
    pub request: ApprovalRequest,
    /// Server-generated 16-byte nonce, hex.
    pub nonce: String,
    /// Absolute approval deadline, included in the signed bytes.
    pub expires_at: i64,
}
impl ApprovalOperation {
    /// UTF-8 protocol bytes, without a trailing newline.
    pub fn message(&self) -> String {
        let (recipient, max, budget, per_call, window) = match &self.request {
            ApprovalRequest::SpendGrant {
                budget_msat,
                per_call_max_msat,
                window_secs,
                recipient,
            } => (
                recipient.as_deref().unwrap_or("-"),
                *budget_msat,
                budget_msat.to_string(),
                per_call_max_msat.to_string(),
                window_secs.to_string(),
            ),
            ApprovalRequest::FirstContact {
                recipient,
                max_total_msat,
                budget_msat,
            } => (
                recipient.as_str(),
                *max_total_msat,
                budget_msat.map_or_else(|| "-".into(), |n| n.to_string()),
                "-".into(),
                "-".into(),
            ),
        };
        format!("bitsov-owner-approval-v1\nnode:{}\nkind:{}\nclient:{}\nclient_pubkey:{}\nepoch:{}\ngrant_op:{}\nrecipient:{}\nmax_total_msat:{}\nbudget_msat:{}\nper_call_max_msat:{}\nwindow_secs:{}\nop_id:{}\nnonce:{}\nexpires_at:{}", self.node, self.request.kind(), self.client_id, self.client_pubkey, self.epoch, self.grant_op.as_deref().unwrap_or("-"), recipient, max, budget, per_call, window, self.op_id, self.nonce, self.expires_at)
    }
}
/// A status read conveys no authority.
#[derive(Debug, Clone, Serialize)]
pub struct ApprovalView {
    /// Node-issued exact terms.
    #[serde(flatten)]
    pub operation: ApprovalOperation,
    /// Exact bytes the owner displays and signs.
    pub approval_message: String,
    /// pending, consumed, or expired.
    pub status: &'static str,
    /// User action; never contains a console code or signature.
    pub owner_action: &'static str,
}
#[derive(Clone)]
struct Pending {
    operation: ApprovalOperation,
    created: Instant,
    consumed: bool,
}
impl Pending {
    fn live(&self, now: i64) -> bool {
        self.operation.expires_at > now && self.created.elapsed().as_secs() < TTL as u64
    }
    fn view(&self) -> ApprovalView {
        ApprovalView {
            operation: self.operation.clone(),
            approval_message: self.operation.message(),
            status: if self.consumed {
                "consumed"
            } else if self.live(chrono::Utc::now().timestamp()) {
                "pending"
            } else {
                "expired"
            },
            owner_action: "Approve these exact terms on a different enrolled owner device",
        }
    }
}
/// Bounded, non-durable state. Restart invalidates every pending approval.
#[derive(Default)]
pub(super) struct OwnerApprovals {
    pending: HashMap<String, Pending>,
    requests: HashMap<String, VecDeque<Instant>>,
    approvals: HashMap<String, VecDeque<Instant>>,
}
fn rate(map: &mut HashMap<String, VecDeque<Instant>>, key: &str) -> Result<(), PairingError> {
    map.retain(|_, times| {
        times.retain(|t| t.elapsed().as_secs() < 3600);
        !times.is_empty()
    });
    let times = map.entry(key.into()).or_default();
    if times.len() >= PER_HOUR {
        return Err(PairingError::TooManyPending);
    }
    times.push_back(Instant::now());
    Ok(())
}
/// An approval can fail the same budget check as the console.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    /// Pairing, signature, expiry or rate refusal.
    #[error(transparent)]
    Pairing(#[from] PairingError),
    /// Existing console budget validation.
    #[error(transparent)]
    Budget(#[from] BudgetRefusal),
}
/// Persisted evidence, not included in audit logs or status responses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalReceipt {
    operation: ApprovalOperation,
    approver: DeviceKey,
    signature: String,
}
impl ApprovalReceipt {
    pub(super) fn verifies(&self, service: &PairingService, grant: &SpendGrant) -> bool {
        let op = &self.operation;
        let key = &self.approver;
        let Some(root) = service.owner_approval_key.as_ref() else {
            return false;
        };
        let valid = || -> Result<(), PairingError> {
            device::verify_owner_approval(
                root,
                &device::owner_approval_message(
                    &op.node,
                    &key.client_pubkey,
                    key.epoch,
                    &key.public_key,
                ),
                &key.owner_approval,
            )?;
            let public = device::parse_public_key(&key.public_key)?;
            if device::key_id_for(&public) != key.key_id
                || super::client_id_from_pubkey(&key.client_pubkey) != key.client_id
                || super::client_id_from_pubkey(&op.client_pubkey) != op.client_id
            {
                return Err(PairingError::BindingMismatch);
            }
            device::verify_p256(&public, op.message().as_bytes(), &self.signature)
        };
        if valid().is_err()
            || op.client_id == key.client_id
            || grant.client_id != op.client_id
            || grant.epoch != op.epoch
            || grant.identity_fingerprint != op.node
            || grant.op_id != op.op_id
            || grant.granted_by != format!("device:{}", key.key_id)
            || grant.scopes != [Scope::Spend]
            || grant.granted_at >= op.expires_at
            || grant.granted_at < op.expires_at - TTL
        {
            return false;
        }
        let Ok(terms) = op.request.spend_terms() else {
            return false;
        };
        let Some(budget) = &grant.budget else {
            return false;
        };
        // First-contact approval can add a narrower cap later.
        let recipient_caps_fit = terms.per_recipient_msat.iter().all(|(r, cap)| {
            budget
                .per_recipient_msat
                .get(r)
                .is_some_and(|actual| actual <= cap)
        });
        grant.granted_at.checked_add(terms.ttl_secs) == Some(grant.expires_at)
            && budget.budget_msat == terms.budget_msat
            && budget.per_call_max_msat == terms.per_call_max_msat
            && budget.breakers == terms.breakers
            && budget.payee_allowlist == terms.payee_allowlist
            && !budget.allow_liquidity_fees
            && !budget.recipients_only
            && recipient_caps_fit
    }
}
impl PairingService {
    fn approval_mode(&self) -> Result<(), PairingError> {
        if !self.owner_control_enabled && !self.local_owner_device {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        Ok(())
    }
    fn approval_client<'a>(
        &self,
        inner: &'a Inner,
        id: &str,
        epoch: u64,
    ) -> Result<&'a super::PairedClient, PairingError> {
        let client = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == id)
            .ok_or(PairingError::UnknownClient)?;
        if client.epoch != epoch {
            return Err(PairingError::BindingMismatch);
        }
        Ok(client)
    }
    fn approval_grant<'a>(
        &self,
        inner: &'a Inner,
        id: &str,
        epoch: u64,
        now: i64,
    ) -> Option<&'a SpendGrant> {
        inner.file.grants.iter().find(|g| {
            g.client_id == id
                && g.epoch == epoch
                && g.identity_fingerprint == inner.identity_fingerprint
                && g.is_live(now)
                && self.permits_spend_grant(g)
        })
    }
    /// Creates a proposal only: never writes a grant or first-contact authority.
    pub fn request_owner_approval(
        &self,
        client_id: &str,
        epoch: u64,
        request: ApprovalRequest,
    ) -> Result<ApprovalView, PairingError> {
        self.approval_mode()?;
        let request = request.normalize()?;
        let mut inner = self.lock();
        let client = self.approval_client(&inner, client_id, epoch)?.clone();
        let now = chrono::Utc::now().timestamp();
        let grant_op = self
            .approval_grant(&inner, client_id, epoch, now)
            .map(|g| g.op_id.clone());
        if matches!(request, ApprovalRequest::FirstContact { .. }) && grant_op.is_none() {
            return Err(PairingError::NotGrantable(
                "first contact requires a live spend grant".into(),
            ));
        }
        inner.owner_approvals.pending.retain(|_, p| p.live(now));
        if inner.owner_approvals.pending.len() >= 1024
            || inner
                .owner_approvals
                .pending
                .values()
                .filter(|p| !p.consumed && p.operation.client_id == client_id)
                .count()
                >= 3
        {
            return Err(PairingError::TooManyPending);
        }
        rate(&mut inner.owner_approvals.requests, client_id)?;
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        let op = ApprovalOperation {
            op_id: uuid::Uuid::new_v4().to_string(),
            node: inner.identity_fingerprint.clone(),
            client_id: client_id.into(),
            client_pubkey: client.client_pubkey,
            epoch,
            grant_op,
            request,
            nonce: hex::encode(nonce),
            expires_at: now + TTL,
        };
        let pending = Pending {
            operation: op,
            created: Instant::now(),
            consumed: false,
        };
        let view = pending.view();
        inner
            .owner_approvals
            .pending
            .insert(view.operation.op_id.clone(), pending);
        Ok(view)
    }
    /// Only the requester may read its operation through the requester route.
    pub fn owner_approval_status(
        &self,
        client_id: &str,
        epoch: u64,
        op_id: &str,
    ) -> Result<ApprovalView, PairingError> {
        let inner = self.lock();
        self.approval_client(&inner, client_id, epoch)?;
        inner
            .owner_approvals
            .pending
            .get(op_id)
            .filter(|p| p.operation.client_id == client_id && p.operation.epoch == epoch)
            .map(Pending::view)
            .ok_or(PairingError::UnknownOperation)
    }
    /// Discovery for an enrolled owner key, excluding requests it cannot approve.
    pub fn owner_pending_approvals(
        &self,
        client_id: &str,
        epoch: u64,
        key_id: &str,
    ) -> Result<Vec<ApprovalView>, PairingError> {
        self.approval_mode()?;
        let inner = self.lock();
        self.intent_key(&inner, client_id, epoch, key_id)?;
        Ok(Self::pending_approval_views(&inner)
            .into_iter()
            .filter(|v| v.operation.client_id != client_id)
            .collect())
    }
    fn pending_approval_views(inner: &Inner) -> Vec<ApprovalView> {
        let now = chrono::Utc::now().timestamp();
        let mut views: Vec<_> = inner
            .owner_approvals
            .pending
            .values()
            .filter(|p| !p.consumed && p.live(now))
            .map(Pending::view)
            .collect();
        views.sort_by(|a, b| a.operation.op_id.cmp(&b.operation.op_id));
        views
    }
    /// Audit metadata only; never expose submitted terms or signatures.
    pub(crate) fn approval_kind_for_audit(&self, op_id: &str) -> Option<&'static str> {
        self.lock()
            .owner_approvals
            .pending
            .get(op_id)
            .map(|p| p.operation.request.kind())
    }
    /// Console status is observational; it never approves a device operation.
    pub fn pending_owner_approvals(&self) -> Vec<ApprovalView> {
        Self::pending_approval_views(&self.lock())
    }
    /// Authenticates, verifies, writes and consumes under one pairing mutex.
    pub fn approve_owner_request(
        &self,
        client_id: &str,
        epoch: u64,
        op_id: &str,
        key_id: &str,
        signature: &str,
    ) -> Result<ApprovalView, ApprovalError> {
        self.approval_mode()?;
        let mut inner = self.lock();
        let approver = self.intent_key(&inner, client_id, epoch, key_id)?;
        // Count attempts, including bad signatures, so an enrolled key cannot flood verification.
        rate(&mut inner.owner_approvals.approvals, key_id)?;
        let pending = inner
            .owner_approvals
            .pending
            .get(op_id)
            .cloned()
            .ok_or(PairingError::UnknownOperation)?;
        let now = chrono::Utc::now().timestamp();
        if !pending.live(now) {
            return Err(PairingError::Expired.into());
        }
        if pending.consumed || pending.operation.client_id == client_id {
            return Err(PairingError::BadProof.into());
        }
        let op = &pending.operation;
        let requester = self.approval_client(&inner, &op.client_id, op.epoch)?;
        if op.node != inner.identity_fingerprint || op.client_pubkey != requester.client_pubkey {
            return Err(PairingError::BindingMismatch.into());
        }
        device::verify_p256(
            &device::parse_public_key(&approver.public_key)?,
            op.message().as_bytes(),
            signature,
        )?;
        let live_op = self
            .approval_grant(&inner, &op.client_id, op.epoch, now)
            .map(|g| g.op_id.clone());
        if live_op != op.grant_op {
            return Err(PairingError::BindingMismatch.into());
        }
        match &op.request {
            ApprovalRequest::SpendGrant { .. } => {
                let terms = op.request.spend_terms()?;
                let grant = SpendGrant {
                    op_id: op.op_id.clone(),
                    client_id: op.client_id.clone(),
                    scopes: vec![Scope::Spend],
                    granted_at: now,
                    expires_at: now + terms.ttl_secs,
                    identity_fingerprint: op.node.clone(),
                    epoch: op.epoch,
                    granted_by: format!("device:{key_id}"),
                    budget: Some(GrantBudget::from_terms(&terms)),
                    owner_approval: Some(ApprovalReceipt {
                        operation: op.clone(),
                        approver,
                        signature: signature.into(),
                    }),
                };
                let before = inner.file.clone();
                for old in &mut inner.file.grants {
                    if old.client_id == op.client_id {
                        old.budget = None;
                    }
                }
                inner.file.grants.push(grant);
                if let Err(e) = self.persist(&mut inner.file) {
                    inner.file = before;
                    return Err(e.into());
                }
            }
            ApprovalRequest::FirstContact {
                recipient,
                max_total_msat,
                budget_msat,
            } => {
                let grant_op = op.grant_op.as_deref().ok_or(BudgetRefusal::NoGrant)?;
                self.grant_first_contact_locked(
                    &mut inner,
                    &op.client_id,
                    grant_op,
                    recipient,
                    *max_total_msat,
                    *budget_msat,
                )?;
                let contact = inner
                    .first_contact
                    .get_mut(&op.client_id)
                    .expect("just issued");
                contact.grant.expires_at = contact.grant.expires_at.min(now + 120);
                contact.grant.granted_by = Some(format!("device:{key_id}"));
                contact.owner_approval = Some(ApprovalReceipt {
                    operation: op.clone(),
                    approver,
                    signature: signature.into(),
                });
            }
        }
        let pending = inner
            .owner_approvals
            .pending
            .get_mut(op_id)
            .expect("locked operation");
        pending.consumed = true;
        Ok(pending.view())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    struct Fixture {
        _dir: tempfile::TempDir,
        svc: PairingService,
        owner: super::super::PairedClient,
        requester: super::super::PairedClient,
        key: EcdsaKeyPair,
        key_id: String,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = konsensus_core::OwnerApprovalKey::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", &[9;32]).unwrap();
            let svc = PairingService::open(dir.path(), "node-test".into(), true)
                .unwrap()
                .with_owner_approval_key(root.verifying_key());
            let owner = svc
                .create_ticket_remote_pairing(
                    "owner",
                    &hex::encode(
                        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                    &[2; 32],
                )
                .unwrap();
            let requester = svc
                .create_ticket_remote_pairing(
                    "AI read/receive",
                    &hex::encode(
                        ed25519_dalek::SigningKey::from_bytes(&[3; 32])
                            .verifying_key()
                            .to_bytes(),
                    ),
                    &[4; 32],
                )
                .unwrap();
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .unwrap();
            let public = hex::encode(key.public_key().as_ref());
            let key_id = device::key_id_for(key.public_key().as_ref());
            // Trusted fixture enrollment; subsequent uses traverse the real intent_key chain.
            svc.lock().file.device_keys.push(DeviceKey {
                key_id: key_id.clone(),
                client_id: owner.client_id.clone(),
                public_key: public.clone(),
                name: "owner".into(),
                registered_at: chrono::Utc::now().timestamp(),
                epoch: owner.epoch,
                client_pubkey: owner.client_pubkey.clone(),
                owner_approval: hex::encode(
                    root.sign(
                        device::owner_approval_message(
                            "node-test",
                            &owner.client_pubkey,
                            owner.epoch,
                            &public,
                        )
                        .as_bytes(),
                    )
                    .to_bytes(),
                ),
                enrolled_by: "console".into(),
            });
            Self {
                _dir: dir,
                svc,
                owner,
                requester,
                key,
                key_id,
            }
        }
        fn request(&self) -> ApprovalView {
            self.svc
                .request_owner_approval(
                    &self.requester.client_id,
                    self.requester.epoch,
                    ApprovalRequest::SpendGrant {
                        budget_msat: 100_000,
                        per_call_max_msat: 10_000,
                        window_secs: 600,
                        recipient: None,
                    },
                )
                .unwrap()
        }
        fn approve(&self, op: &ApprovalView) -> Result<ApprovalView, ApprovalError> {
            let signature = hex::encode(
                self.key
                    .sign(
                        &ring::rand::SystemRandom::new(),
                        op.approval_message.as_bytes(),
                    )
                    .unwrap()
                    .as_ref(),
            );
            self.svc.approve_owner_request(
                &self.owner.client_id,
                self.owner.epoch,
                &op.operation.op_id,
                &self.key_id,
                &signature,
            )
        }
        fn inert(&self) {
            assert!(self.svc.grant_view_for(&self.requester.client_id).is_none());
        }
    }
    #[test]
    fn expired_by_wall_or_monotonic_clock_never_grants() {
        for wall in [true, false] {
            let f = Fixture::new();
            let op = f.request();
            let mut inner = f.svc.lock();
            let pending = inner
                .owner_approvals
                .pending
                .get_mut(&op.operation.op_id)
                .unwrap();
            if wall {
                pending.operation.expires_at = chrono::Utc::now().timestamp();
            } else {
                pending.created = Instant::now() - std::time::Duration::from_secs(301);
            }
            drop(inner);
            assert!(matches!(
                f.approve(&op),
                Err(ApprovalError::Pairing(PairingError::Expired))
            ));
            f.inert();
        }
    }
    #[test]
    fn changed_pending_terms_node_requester_epoch_and_owner_attestation_refused() {
        for change in 0..5 {
            let f = Fixture::new();
            let op = f.request();
            let mut inner = f.svc.lock();
            match change {
                0 => {
                    inner
                        .owner_approvals
                        .pending
                        .get_mut(&op.operation.op_id)
                        .unwrap()
                        .operation
                        .request = ApprovalRequest::SpendGrant {
                        budget_msat: 99999,
                        per_call_max_msat: 10000,
                        window_secs: 600,
                        recipient: None,
                    }
                }
                1 => inner.identity_fingerprint = "other-node".into(),
                2 => {
                    inner
                        .file
                        .clients
                        .iter_mut()
                        .find(|c| c.client_id == f.requester.client_id)
                        .unwrap()
                        .epoch += 1
                }
                3 => inner.file.device_keys[0].owner_approval = "00".repeat(64),
                _ => {
                    inner
                        .file
                        .clients
                        .iter_mut()
                        .find(|c| c.client_id == f.requester.client_id)
                        .unwrap()
                        .client_pubkey = "00".repeat(32)
                }
            }
            drop(inner);
            assert!(f.approve(&op).is_err());
            f.inert();
        }
    }
    #[test]
    fn failed_persistence_rolls_back_and_keeps_request_unconsumed() {
        let f = Fixture::new();
        let op = f.request();
        // persist() uses the service's path; make its parent unwritable by shape, not permissions.
        let parent = f.svc.dir().to_path_buf();
        let backup = parent.with_extension("backup");
        std::fs::rename(&parent, &backup).unwrap();
        std::fs::write(&parent, b"not a directory").unwrap();
        assert!(matches!(
            f.approve(&op),
            Err(ApprovalError::Pairing(PairingError::Io(_)))
        ));
        f.inert();
        assert_eq!(
            f.svc
                .owner_approval_status(
                    &f.requester.client_id,
                    f.requester.epoch,
                    &op.operation.op_id
                )
                .unwrap()
                .status,
            "pending"
        );
        std::fs::remove_file(&parent).unwrap();
        std::fs::rename(&backup, &parent).unwrap();
        f.approve(&op).unwrap();
    }
    #[test]
    fn requests_and_approver_attempts_have_independent_hourly_limits() {
        let f = Fixture::new();
        for _ in 0..30 {
            let op = f.request();
            f.approve(&op).unwrap();
        }
        assert!(matches!(
            f.svc.request_owner_approval(
                &f.requester.client_id,
                f.requester.epoch,
                ApprovalRequest::SpendGrant {
                    budget_msat: 100,
                    per_call_max_msat: 100,
                    window_secs: 60,
                    recipient: None
                }
            ),
            Err(PairingError::TooManyPending)
        ));
        let f = Fixture::new();
        let op = f.request();
        for _ in 0..30 {
            assert!(f
                .svc
                .approve_owner_request(
                    &f.owner.client_id,
                    f.owner.epoch,
                    &op.operation.op_id,
                    &f.key_id,
                    "00"
                )
                .is_err());
        }
        assert!(matches!(
            f.approve(&op),
            Err(ApprovalError::Pairing(PairingError::TooManyPending))
        ));
        f.inert();
    }
    #[test]
    fn first_contact_rechecks_remaining_and_recipient_caps_at_approval() {
        for recipient_cap in [false, true] {
            let f = Fixture::new();
            let spend = f.request();
            f.approve(&spend).unwrap();
            let recipient = "aa".repeat(32);
            let op = f
                .svc
                .request_owner_approval(
                    &f.requester.client_id,
                    f.requester.epoch,
                    ApprovalRequest::FirstContact {
                        recipient: recipient.clone(),
                        max_total_msat: 1000,
                        budget_msat: None,
                    },
                )
                .unwrap();
            let mut inner = f.svc.lock();
            let budget = inner
                .file
                .grants
                .last_mut()
                .unwrap()
                .budget
                .as_mut()
                .unwrap();
            if recipient_cap {
                budget.per_recipient_msat.insert(recipient.clone(), 500);
            } else {
                budget.used_msat = 99_500;
            }
            drop(inner);
            let refusal = f.approve(&op).unwrap_err();
            assert!(if recipient_cap {
                matches!(
                    refusal,
                    ApprovalError::Budget(BudgetRefusal::Recipient {
                        remaining_msat: 500,
                        ..
                    })
                )
            } else {
                matches!(
                    refusal,
                    ApprovalError::Budget(BudgetRefusal::Total {
                        remaining_msat: 500
                    })
                )
            });
            assert!(f
                .svc
                .take_first_contact(&f.requester.client_id, f.requester.epoch, &recipient)
                .is_none());
            assert_eq!(
                f.svc
                    .owner_approval_status(
                        &f.requester.client_id,
                        f.requester.epoch,
                        &op.operation.op_id
                    )
                    .unwrap()
                    .status,
                "pending"
            );
        }
    }
    #[test]
    fn disabled_mode_and_revoked_approver_pairing_cannot_approve() {
        for mode in [false, true] {
            let mut f = Fixture::new();
            let op = f.request();
            if mode {
                f.svc.owner_control_enabled = false;
            } else {
                f.svc.revoke(&f.owner.client_id).unwrap();
            }
            assert!(f.approve(&op).is_err());
            f.inert();
        }
    }
    #[test]
    fn concurrent_approval_consumes_exactly_once() {
        let f = Fixture::new();
        let op = f.request();
        std::thread::scope(|s| {
            let a = s.spawn(|| f.approve(&op));
            let b = s.spawn(|| f.approve(&op));
            assert_eq!(
                usize::from(a.join().unwrap().is_ok()) + usize::from(b.join().unwrap().is_ok()),
                1
            );
        });
        assert_eq!(
            f.svc
                .lock()
                .file
                .grants
                .iter()
                .filter(|g| g.client_id == f.requester.client_id)
                .count(),
            1
        );
    }
    #[test]
    fn receipt_cannot_forge_a_distinct_approver_identity_for_self_approval() {
        let f = Fixture::new();
        let op = f.request();
        f.approve(&op).unwrap();
        let mut grant = f.svc.lock().file.grants.last().unwrap().clone();
        grant.client_id = f.owner.client_id.clone();
        grant.epoch = f.owner.epoch;
        let receipt = grant.owner_approval.as_mut().unwrap();
        receipt.operation.client_id = f.owner.client_id.clone();
        receipt.operation.client_pubkey = f.owner.client_pubkey.clone();
        receipt.operation.epoch = f.owner.epoch;
        receipt.approver.client_id = "forged-other-client".into();
        receipt.signature = hex::encode(
            f.key
                .sign(
                    &ring::rand::SystemRandom::new(),
                    receipt.operation.message().as_bytes(),
                )
                .unwrap()
                .as_ref(),
        );
        assert!(!f.svc.permits_spend_grant(&grant));
    }
    #[test]
    fn signed_spend_receipt_rejects_larger_budget_and_lifetime() {
        let f = Fixture::new();
        let op = f.request();
        f.approve(&op).unwrap();
        let mut grant = f.svc.lock().file.grants.last().unwrap().clone();
        assert!(f.svc.permits_spend_grant(&grant));
        grant.budget.as_mut().unwrap().budget_msat += 1;
        assert!(!f.svc.permits_spend_grant(&grant));
        grant.budget.as_mut().unwrap().budget_msat -= 1;
        grant.expires_at += 1;
        assert!(!f.svc.permits_spend_grant(&grant));
    }
}
