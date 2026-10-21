//! Claimless, owner-approved enrollment. All authority transitions use the pairing lock.
use super::{
    device::{self, DeviceKey, PendingDeviceKey, MAX_DEVICE_KEYS_PER_CLIENT},
    Inner, PairedClient, PairingError, PairingService,
};
use crate::auth::Scope;
use serde::Serialize;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

/// Five-minute SAS lifetime, independent of the v1 elevation lifetime.
pub const SECOND_DEVICE_SAS_TTL_SECS: i64 = 300;
/// Feature detection for owner-approved enrollment.
pub const CAPABILITY: &str = "second_device_enrollment_v1";
/// Strictly one-use console ticket namespace.
pub const SECOND_TICKET_PREFIX: &str = "second_";
const PROVISIONAL_SECS: u64 = 900;

#[derive(Clone)]
pub(super) struct Provisional {
    pub ticket_id: String,
    pub ticket_commitment: [u8; 32],
    pub issuer: String,
    pub deadline: Instant,
    pub expires_at: i64,
    pub failures: u8,
}
#[derive(Clone)]
struct UsedTicket {
    client_id: String,
    epoch: u64,
    public_key: String,
    transport: [u8; 32],
    deadline: Instant,
    contested: bool,
    // Retain only the killed op's id, bounded by this ticket's original deadline.
    contested_op: Option<String>,
}
/// Owner-visible late-rescan alert; contains no ticket or SAS material.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ContestedAlert {
    /// Previously enrolled pairing.
    pub client_id: String,
    /// Approved display name.
    pub name: String,
    /// Audit event identifier.
    pub event: String,
}
#[derive(Clone, Default)]
pub(super) struct State {
    pub provisional: HashMap<String, Provisional>,
    used: HashMap<String, UsedTicket>,
    pub mismatches: Vec<Instant>,
    pub bad_signatures: HashMap<String, Vec<Instant>>,
    alerts: Vec<ContestedAlert>,
    swept_before_audit: Vec<String>,
}

/// Commitment binds SAS to the scanned QR without retaining its secret code.
pub fn ticket_commitment(code: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"bitsov-second-device-ticket-v1");
    h.update(code.as_bytes());
    *h.finalize().as_bytes()
}
/// Public identifier the issuing app compares with its current QR.
pub fn ticket_id(code: &str) -> String {
    let mut h = blake3::Hasher::new();
    h.update(b"bitsov-ticket-id-v1");
    h.update(code.as_bytes());
    hex::encode(&h.finalize().as_bytes()[..16])
}
fn ticket_hash(code: &str) -> String {
    blake3::hash(code.as_bytes()).to_hex().to_string()
}

impl PairingService {
    /// Startup-only rollout flag, off by default.
    pub fn with_second_device_enrollment(mut self, enabled: bool) -> Self {
        self.second_device_enrollment = enabled;
        self
    }
    /// Compatibility switch for claim-bound second-device SAS v1; default true.
    pub fn with_second_device_claim_v1(mut self, enabled: bool) -> Self {
        self.second_device_claim_v1 = enabled;
        self
    }
    /// Attach the node audit sink before publishing the service.
    pub fn with_enrollment_audit(mut self, audit: std::sync::Arc<crate::audit::AuditLog>) -> Self {
        let swept = std::mem::take(
            &mut self
                .inner
                .get_mut()
                .unwrap_or_else(|e| e.into_inner())
                .second_device
                .swept_before_audit,
        );
        for client in swept {
            audit.record(
                "pair.provisional_swept",
                &client,
                Some(serde_json::json!({})),
            );
        }
        self.enrollment_audit = Some(audit);
        self
    }
    /// Route rollout gate (signer availability is checked at request time).
    pub fn second_device_enrollment_enabled(&self) -> bool {
        self.second_device_enrollment && self.local_owner_device
    }
    pub(super) fn second_device_available(&self) -> Result<(), PairingError> {
        if !self.second_device_enrollment_enabled() || self.owner_signing_key.is_none() {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        Ok(())
    }
    pub(super) fn enrollment_event(&self, event: &str, client: &str, detail: serde_json::Value) {
        tracing::info!(event, client_id = client, "second-device enrollment");
        if let Some(audit) = &self.enrollment_audit {
            audit.record(event, client, Some(detail));
        }
    }
    /// Live provisional authority only, never an empty-scope record from a prior process.
    pub fn is_provisional(&self, client: &str) -> bool {
        let inner = self.lock();
        self.provisional_locked(&inner, client).is_ok()
    }
    pub(super) fn provisional_locked<'a>(
        &self,
        inner: &'a Inner,
        client: &str,
    ) -> Result<&'a Provisional, PairingError> {
        self.second_device_available()?;
        let p =
            inner.second_device.provisional.get(client).ok_or_else(|| {
                PairingError::PairingInvalid("provisional pairing required".into())
            })?;
        if p.deadline <= Instant::now() || p.expires_at <= chrono::Utc::now().timestamp() {
            return Err(PairingError::Expired);
        }
        if !inner
            .file
            .clients
            .iter()
            .any(|c| c.client_id == client && c.scopes.is_empty())
        {
            return Err(PairingError::PairingInvalid(
                "provisional pairing required".into(),
            ));
        }
        Ok(p)
    }
    /// Called only after a valid Noise pairing proof and console ticket validation.
    pub fn create_second_device_pairing(
        &self,
        code: &str,
        name: &str,
        public_key: &str,
        transport: &[u8; 32],
        issuer: &str,
    ) -> Result<PairedClient, PairingError> {
        let mut inner = self.lock();
        self.create_second_device_locked(&mut inner, code, name, public_key, transport, issuer)
    }
    pub(super) fn create_second_device_locked(
        &self,
        inner: &mut Inner,
        code: &str,
        name: &str,
        public_key: &str,
        transport: &[u8; 32],
        issuer: &str,
    ) -> Result<PairedClient, PairingError> {
        self.second_device_available()?;
        self.rescan_locked(inner, code, public_key, transport)?;
        if !inner.file.device_keys.iter().any(|k| {
            self.intent_key(inner, &k.client_id, k.epoch, &k.key_id)
                .is_ok()
        }) {
            return Err(PairingError::PairingInvalid("no_owner_device".into()));
        }
        let public_key = public_key.to_ascii_lowercase();
        super::parse_pubkey(&public_key)?;
        let remote = hex::encode(transport);
        if inner.file.clients.iter().any(|c| {
            c.client_pubkey == public_key || c.remote_transport_pubkey.as_deref() == Some(&remote)
        }) {
            return Err(PairingError::PairingInvalid("already_paired".into()));
        }
        if inner
            .second_device
            .provisional
            .values()
            .filter(|p| {
                p.deadline > Instant::now() && p.expires_at > chrono::Utc::now().timestamp()
            })
            .count()
            >= 2
        {
            return Err(PairingError::TooManyPending);
        }
        if inner.pairing_closed || inner.identity_fingerprint.is_empty() {
            return Err(PairingError::Closed);
        }
        let before = inner.file.clone();
        let before_state = inner.second_device.clone();
        let client_id = super::client_id_from_pubkey(&public_key);
        let epoch = inner.file.last_epoch.entry(client_id.clone()).or_default();
        *epoch = epoch.checked_add(1).ok_or(PairingError::Closed)?;
        let now = chrono::Utc::now().timestamp();
        let deadline = Instant::now() + Duration::from_secs(PROVISIONAL_SECS);
        let record = PairedClient {
            client_id: client_id.clone(),
            name: super::sanitize_name(name),
            client_pubkey: public_key.clone(),
            remote_transport_pubkey: Some(remote),
            scopes: vec![],
            epoch: *epoch,
            identity_fingerprint: inner.identity_fingerprint.clone(),
            created_at: now,
            last_seen: None,
        };
        inner.file.clients.push(record.clone());
        inner.second_device.provisional.insert(
            client_id.clone(),
            Provisional {
                ticket_id: ticket_id(code),
                ticket_commitment: ticket_commitment(code),
                issuer: issuer.into(),
                deadline,
                expires_at: now + PROVISIONAL_SECS as i64,
                failures: 0,
            },
        );
        inner.second_device.used.insert(
            ticket_hash(code),
            UsedTicket {
                epoch: record.epoch,
                client_id,
                public_key,
                transport: *transport,
                deadline,
                contested: false,
                contested_op: None,
            },
        );
        if let Err(e) = self.persist(&mut inner.file) {
            inner.file = before;
            inner.second_device = before_state;
            return Err(e);
        }
        self.notify_authority_change();
        Ok(record)
    }
    /// Check used tickets before any legacy retry or file-ticket path. A same-key retry
    /// is refused, but cannot contest itself. Reconnect without the code instead.
    pub fn check_second_device_rescan(
        &self,
        code: &str,
        public_key: &str,
        transport: &[u8; 32],
    ) -> Result<(), PairingError> {
        self.rescan_locked(&mut self.lock(), code, public_key, transport)
    }
    pub(super) fn rescan_locked(
        &self,
        inner: &mut Inner,
        code: &str,
        public_key: &str,
        transport: &[u8; 32],
    ) -> Result<(), PairingError> {
        inner
            .second_device
            .used
            .retain(|_, t| t.deadline > Instant::now());
        let hash = ticket_hash(code);
        let Some(used) = inner.second_device.used.get(&hash).cloned() else {
            return Ok(());
        };
        if used.public_key == public_key && &used.transport == transport {
            return Err(PairingError::BadProof);
        }
        // A client id can be reused after console revocation. An old QR must
        // never retire a later enrollment attempt (or its enrolled device).
        if inner
            .second_device
            .provisional
            .get(&used.client_id)
            .is_some_and(|p| p.ticket_id == ticket_id(code))
            && inner.file.clients.iter().any(|c| {
                c.client_id == used.client_id && c.epoch == used.epoch && c.scopes.is_empty()
            })
        {
            let before = inner.file.clone();
            let state = inner.second_device.clone();
            let cancelled = inner.cancelled_ops.clone();
            let contested_op = inner
                .file
                .pending_device_keys
                .iter()
                .find(|op| op.client_id == used.client_id && op.sas_version == Some(2))
                .map(|op| op.op_id.clone());
            Self::remove_provisional_locked(inner, &used.client_id);
            let tombstone = inner.second_device.used.get_mut(&hash).unwrap();
            tombstone.contested = true;
            tombstone.contested_op = contested_op;
            if let Err(e) = self.persist(&mut inner.file) {
                inner.file = before;
                inner.second_device = state;
                inner.cancelled_ops = cancelled;
                return Err(e);
            }
            Self::commit_enrollment_cleanup(inner);
            self.notify_authority_change();
            self.enrollment_event(
                "pair.second_device_contested",
                &used.client_id,
                serde_json::json!({"epoch": used.epoch}),
            );
        } else if !used.contested {
            if let Some(key) = inner
                .file
                .device_keys
                .iter()
                .find(|k| k.client_id == used.client_id && k.epoch == used.epoch)
            {
                let alert = ContestedAlert {
                    client_id: used.client_id.clone(),
                    name: key.name.clone(),
                    event: "pair.second_device_contested_after_enroll".into(),
                };
                self.enrollment_event(
                    &alert.event,
                    &alert.client_id,
                    serde_json::json!({"name":alert.name}),
                );
                // One alert per used ticket, bounded by the ticket issue window.
                inner.second_device.alerts.push(alert);
                if inner.second_device.alerts.len() > 64 {
                    inner.second_device.alerts.remove(0);
                }
                inner.second_device.used.get_mut(&hash).unwrap().contested = true;
            }
        }
        Err(PairingError::PairingInvalid("contested".into()))
    }
    /// Alerts consumed by owner UI and console status; no secrets.
    pub fn second_device_alerts(&self) -> Vec<ContestedAlert> {
        self.lock().second_device.alerts.clone()
    }
    pub(super) fn remove_provisional_locked(inner: &mut Inner, client: &str) {
        let ops: Vec<_> = inner
            .file
            .pending_device_keys
            .iter()
            .filter(|p| p.client_id == client)
            .map(|p| p.op_id.clone())
            .collect();
        for op in ops {
            Self::drop_second_op(inner, &op);
        }
        inner.file.clients.retain(|c| c.client_id != client);
        inner.second_device.provisional.remove(client);
    }
    pub(super) fn drop_second_op(inner: &mut Inner, op: &str) {
        if let Some(p) = inner
            .file
            .pending_device_keys
            .iter()
            .find(|p| p.op_id == op)
        {
            inner.cancelled_ops.insert(op.into(), p.client_id.clone());
        }
        inner.file.pending_device_keys.retain(|p| p.op_id != op);
    }
    pub(super) fn commit_enrollment_cleanup(inner: &mut Inner) {
        for op in inner.cancelled_ops.keys() {
            inner.owner_confirmations.remove(op);
        }
        inner
            .token_challenges
            .retain(|_, (client, _)| inner.file.clients.iter().any(|c| &c.client_id == client));
    }
    pub(super) fn charge_second_failure(
        &self,
        inner: &mut Inner,
        op: &PendingDeviceKey,
        mismatch: bool,
    ) -> Result<(), PairingError> {
        let before = inner.file.clone();
        let state = inner.second_device.clone();
        let cancelled = inner.cancelled_ops.clone();
        if mismatch {
            inner.second_device.mismatches.push(Instant::now());
        }
        Self::drop_second_op(inner, &op.op_id);
        if let Some(p) = inner.second_device.provisional.get_mut(&op.client_id) {
            p.failures = p.failures.saturating_add(1);
            if p.failures >= 3 {
                Self::remove_provisional_locked(inner, &op.client_id);
            }
        }
        if let Err(e) = self.persist(&mut inner.file) {
            inner.file = before;
            inner.second_device = state;
            inner.cancelled_ops = cancelled;
            return Err(e);
        }
        Self::commit_enrollment_cleanup(inner);
        self.notify_authority_change();
        Ok(())
    }
    pub(super) fn second_request_rate(inner: &mut Inner) -> Result<(), PairingError> {
        inner
            .second_device
            .mismatches
            .retain(|t| t.elapsed() < Duration::from_secs(3600));
        if inner.second_device.mismatches.len() >= 10 {
            Err(PairingError::TooManyPending)
        } else {
            Ok(())
        }
    }
    /// Console reset primitive; CLI wiring belongs to PR B.
    pub fn reset_sas_failures(&self) {
        let mut i = self.lock();
        i.sas_failures = 0;
        i.second_device.mismatches.clear();
    }
    /// Startup and minute sweep. Empty scopes are the durable provisional marker.
    pub fn sweep_provisional_pairings(&self) -> Result<usize, PairingError> {
        let mut inner = self.lock();
        let now = Instant::now();
        let unix = chrono::Utc::now().timestamp();
        let ids: Vec<_> = inner
            .file
            .clients
            .iter()
            .filter(|c| {
                c.scopes.is_empty()
                    && inner
                        .second_device
                        .provisional
                        .get(&c.client_id)
                        .is_none_or(|p| p.deadline <= now || p.expires_at <= unix)
            })
            .map(|c| c.client_id.clone())
            .collect();
        let before = inner.file.clone();
        let state = inner.second_device.clone();
        let cancelled = inner.cancelled_ops.clone();
        for id in &ids {
            Self::remove_provisional_locked(&mut inner, id);
        }
        if !ids.is_empty() {
            if let Err(e) = self.persist(&mut inner.file) {
                inner.file = before;
                inner.second_device = state;
                inner.cancelled_ops = cancelled;
                return Err(e);
            }
            Self::commit_enrollment_cleanup(&mut inner);
            self.notify_authority_change();
        }
        inner.second_device.used.retain(|_, t| t.deadline > now);
        for id in &ids {
            if self.enrollment_audit.is_none() {
                inner.second_device.swept_before_audit.push(id.clone());
            }
            self.enrollment_event("pair.provisional_swept", id, serde_json::json!({}));
        }
        Ok(ids.len())
    }
    pub(super) fn validate_second_op(
        &self,
        inner: &Inner,
        op: &PendingDeviceKey,
    ) -> Result<(), PairingError> {
        if op.sas_version != Some(2) || op.sas.is_none() {
            return Err(PairingError::UnknownOperation);
        }
        if op.expires_at <= chrono::Utc::now().timestamp()
            || op.sas.as_ref().unwrap().created_at.elapsed().as_secs()
                >= SECOND_DEVICE_SAS_TTL_SECS as u64
        {
            return Err(PairingError::Expired);
        }
        op.require_sas_confirmed()?;
        self.provisional_locked(inner, &op.client_id)?;
        if !inner.file.clients.iter().any(|c| {
            c.client_id == op.client_id
                && c.epoch == op.epoch
                && c.client_pubkey == op.client_pubkey
        }) {
            return Err(PairingError::PairingInvalid("pairing changed".into()));
        }
        if device::key_id_for(&device::parse_public_key(&op.public_key)?) != op.key_id
            || inner.file.device_keys.iter().any(|k| k.key_id == op.key_id)
            || inner
                .file
                .device_keys
                .iter()
                .filter(|k| k.client_id == op.client_id && k.epoch == op.epoch)
                .count()
                >= MAX_DEVICE_KEYS_PER_CLIENT
        {
            return Err(PairingError::NotGrantable(
                "device key already enrolled or pairing full".into(),
            ));
        }
        Ok(())
    }
    /// Exact approval/reject bytes, built exclusively from server state.
    pub fn second_device_message(
        &self,
        client: &str,
        epoch: u64,
        key: &str,
        op: &str,
        reject: bool,
    ) -> Result<String, PairingError> {
        let inner = self.lock();
        self.second_device_available()?;
        self.intent_key(&inner, client, epoch, key)?;
        let op = inner
            .file
            .pending_device_keys
            .iter()
            .find(|p| p.op_id == op)
            .ok_or(PairingError::UnknownOperation)?;
        self.validate_second_op(&inner, op)?;
        Self::second_message_locked(&inner, client, epoch, key, op, reject)
    }
    pub(super) fn second_message_locked(
        inner: &Inner,
        client: &str,
        epoch: u64,
        key: &str,
        op: &PendingDeviceKey,
        reject: bool,
    ) -> Result<String, PairingError> {
        let p = inner
            .second_device
            .provisional
            .get(&op.client_id)
            .ok_or(PairingError::UnknownOperation)?;
        let sas = op.sas.as_ref().ok_or(PairingError::UnknownOperation)?;
        let domain = if reject {
            "bitsov-second-device-reject-v1"
        } else {
            "bitsov-second-device-approval-v1"
        };
        Ok(format!("{domain}\nnode:{}\napprover_client:{client}\napprover_epoch:{epoch}\napprover_key:{key}\nop_id:{}\nnonce:{}\nclient_pubkey:{}\nepoch:{}\ndevice_key:{}\ndevice_name:{}\nnoise_handshake_hash:{}\nnoise_client_static:{}\nbox_transport_pubkey:{}\nticket_id:{}\nissuer:{}\nsas_version:2\nsas_digest:{}\nsas_words:{}\nexpires_at:{}",inner.identity_fingerprint,op.op_id,op.delegation_nonce,op.client_pubkey,op.epoch,op.public_key,op.name,hex::encode(sas.binding.handshake_hash),hex::encode(sas.binding.client_static),hex::encode(sas.binding.box_public_key),p.ticket_id,p.issuer,sas.digest.to_hex(),crate::sas::words(&sas.digest).join(" "),op.expires_at))
    }
    /// Enrolled owner approval; the HTTP caller separately binds the token to Noise.
    pub fn approve_second_device(
        &self,
        client: &str,
        epoch: u64,
        op: &str,
        key: &str,
        signature: &str,
    ) -> Result<DeviceKey, PairingError> {
        self.decide_second_device(client, epoch, op, key, signature, false)?
            .ok_or(PairingError::UnknownOperation)
    }
    /// Enrolled owner rejection immediately retires provisional authority.
    pub fn reject_second_device(
        &self,
        client: &str,
        epoch: u64,
        op: &str,
        key: &str,
        signature: &str,
    ) -> Result<(), PairingError> {
        self.decide_second_device(client, epoch, op, key, signature, true)
            .map(|_| ())
    }
    fn decide_second_device(
        &self,
        client: &str,
        epoch: u64,
        op_id: &str,
        key_id: &str,
        signature: &str,
        reject: bool,
    ) -> Result<Option<DeviceKey>, PairingError> {
        let mut inner = self.lock();
        // §5: gates, approver authority, chronology, live op, provisional, key, signature, commit.
        self.second_device_available()?;
        if inner.second_device.provisional.contains_key(client) {
            return Err(PairingError::BadProof);
        }
        let approver = self.intent_key(&inner, client, epoch, key_id)?;
        if inner.second_device.used.values().any(|ticket| {
            ticket.contested_op.as_deref() == Some(op_id) && ticket.deadline > Instant::now()
        }) {
            return Err(PairingError::PairingInvalid("contested".into()));
        }
        let op = inner
            .file
            .pending_device_keys
            .iter()
            .find(|p| p.op_id == op_id)
            .cloned()
            .ok_or(PairingError::UnknownOperation)?;
        if client == op.client_id || approver.registered_at >= op.created_at {
            return Err(PairingError::BadProof);
        }
        self.validate_second_op(&inner, &op)?;
        inner.second_device.bad_signatures.retain(|_, v| {
            v.retain(|t| t.elapsed() < Duration::from_secs(3600));
            !v.is_empty()
        });
        if inner
            .second_device
            .bad_signatures
            .get(key_id)
            .is_some_and(|v| v.len() >= 10)
        {
            return Err(PairingError::TooManyPending);
        }
        let message = Self::second_message_locked(&inner, client, epoch, key_id, &op, reject)?;
        if device::verify_p256(
            &device::parse_public_key(&approver.public_key)?,
            message.as_bytes(),
            signature,
        )
        .is_err()
        {
            inner
                .second_device
                .bad_signatures
                .entry(key_id.into())
                .or_default()
                .push(Instant::now());
            return Err(PairingError::BadProof);
        }
        if reject {
            let before = inner.file.clone();
            let state = inner.second_device.clone();
            let cancelled = inner.cancelled_ops.clone();
            Self::remove_provisional_locked(&mut inner, &op.client_id);
            if let Err(e) = self.persist(&mut inner.file) {
                inner.file = before;
                inner.second_device = state;
                inner.cancelled_ops = cancelled;
                return Err(e);
            }
            Self::commit_enrollment_cleanup(&mut inner);
            self.notify_authority_change();
            self.enrollment_event(
                "pair.second_device_rejected",
                client,
                serde_json::json!({"epoch":epoch,"key_id":key_id,"op_id":op_id}),
            );
            Ok(None)
        } else {
            let signer = self
                .owner_signing_key
                .as_ref()
                .ok_or(PairingError::OwnerChannelUnavailable)?;
            let approval = hex::encode(
                signer
                    .sign(
                        device::owner_approval_message(
                            &inner.identity_fingerprint,
                            &op.client_pubkey,
                            op.epoch,
                            &op.public_key,
                        )
                        .as_bytes(),
                    )
                    .to_bytes(),
            );
            let key = self.complete_second_locked(
                &mut inner,
                &op,
                approval,
                format!("second_device:{key_id}"),
            )?;
            self.enrollment_event(
                "pair.second_device_enrolled",
                client,
                serde_json::json!({"epoch":epoch,"key_id":key_id,"op_id":op_id}),
            );
            Ok(Some(key))
        }
    }
    pub(super) fn complete_second_locked(
        &self,
        inner: &mut Inner,
        op: &PendingDeviceKey,
        owner_approval: String,
        enrolled_by: String,
    ) -> Result<DeviceKey, PairingError> {
        self.validate_second_op(inner, op)?;
        let key = DeviceKey {
            key_id: op.key_id.clone(),
            client_id: op.client_id.clone(),
            public_key: op.public_key.clone(),
            name: op.name.clone(),
            registered_at: chrono::Utc::now().timestamp(),
            epoch: op.epoch,
            client_pubkey: op.client_pubkey.clone(),
            owner_approval,
            enrolled_by,
        };
        let before = inner.file.clone();
        inner
            .file
            .clients
            .iter_mut()
            .find(|c| c.client_id == op.client_id)
            .unwrap()
            .scopes = vec![Scope::Read, Scope::Receive];
        inner.file.device_keys.push(key.clone());
        inner
            .file
            .pending_device_keys
            .retain(|p| p.op_id != op.op_id);
        inner
            .file
            .registered_ops
            .insert(op.op_id.clone(), key.key_id.clone());
        if let Err(e) = self.persist(&mut inner.file) {
            inner.file = before;
            return Err(e);
        }
        inner.second_device.provisional.remove(&op.client_id);
        inner.owner_confirmations.remove(&op.op_id);
        self.notify_authority_change();
        Ok(key)
    }
}
