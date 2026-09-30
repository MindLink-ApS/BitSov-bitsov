//! Paired device keys and signed relation intents (relation ladder, steps 1–2).
//!
//! A paired app generates a P-256 key in the device's secure hardware (on
//! macOS the Secure Enclave, unlocked by Touch ID for each signature). The
//! owner registers its public key with the node **once**, over the owner
//! console (the short code of `konsensus device approve`). After that the app
//! opens a per-peer spend envelope by signing a [`RelationIntent`]; the node
//! verifies the signature against the registered key and enforces the exact
//! terms per recipient. There is no "biometric passed" flag anywhere: the node
//! accepts a signature over exact bytes, or nothing.
//!
//! What the node can and cannot know is stated in `docs/security/device-keys.md`:
//! it verifies possession of a registered key, not that the key lives in
//! hardware (macOS offers no attestation to an app outside the App Store). The
//! owner's one-time console approval is the root of that trust.

use rand::RngCore;
use serde::{Deserialize, Serialize};

use super::{
    Inner, PairingError, PairingService, SpendGrant, ELEVATION_TTL_SECS,
};
use crate::auth::Scope;
use crate::spend_budget::{GrantBudget, GrantView, MAX_SPEND_GRANT_TTL_SECS};

/// Reason code: the node runs from a plaintext recovery phrase.
pub const SEED_NOT_ENCRYPTED: &str = "seed_not_encrypted";
/// Reason code: the encrypted phrase's password came from a flag or file, not
/// typed at start, so a same-user program could have it.
pub const SEED_PASSWORD_NOT_TYPED: &str = "seed_password_not_typed";
/// Reason code: no owner-approval key was configured at start.
pub const OWNER_KEY_UNAVAILABLE: &str = "owner_key_unavailable";

/// What the owner is told for a reason code.
pub fn device_approvals_off_message(reason: &str) -> &'static str {
    match reason {
        SEED_NOT_ENCRYPTED => {
            "Touch ID approvals are off on this node: its recovery phrase is not encrypted. Encrypt \
             your recovery phrase to enable Touch ID approvals (`konsensus seed encrypt`, then \
             restart the node)."
        }
        SEED_PASSWORD_NOT_TYPED => {
            "Touch ID approvals are off on this node: it was started with the recovery-phrase \
             password from a flag or file. Restart it and type the password at start to enable \
             Touch ID approvals."
        }
        _ => "Touch ID approvals are off on this node: it has no owner-approval key.",
    }
}

/// Registered device keys per paired client.
pub const MAX_DEVICE_KEYS_PER_CLIENT: usize = 4;

/// How far a relation intent's `issued_at` may be from the node's clock.
pub const INTENT_MAX_SKEW_SECS: i64 = 300;

/// Shortest and longest envelope window a relation intent may ask for.
pub const RELATION_MIN_WINDOW_SECS: i64 = 60;
/// See [`RELATION_MIN_WINDOW_SECS`]; the 24-hour grant cap.
pub const RELATION_MAX_WINDOW_SECS: i64 = MAX_SPEND_GRANT_TTL_SECS;

/// Most one envelope may hold: 100,000 sats, the app's own daily ceiling.
pub const RELATION_MAX_BUDGET_MSAT: u64 = 100_000_000;

/// Relation intents one client may apply per hour (new or renewed envelopes).
pub const RELATION_INTENTS_PER_HOUR: usize = 30;

/// `level` values. Only Contact is accepted before step 4 (first contact).
pub const LEVEL_CONTACT: u8 = 1;

/// A registered device key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceKey {
    /// `blake3(public key)[..16]`, hex. Names the key in intents.
    pub key_id: String,
    /// Paired client the key belongs to.
    pub client_id: String,
    /// SEC1 uncompressed P-256 public key, hex (65 bytes).
    pub public_key: String,
    /// Device name the client gave, as the owner approved it.
    pub name: String,
    /// Unix seconds the owner approved it.
    pub registered_at: i64,
    /// Pairing epoch at approval: a revocation or rotation retires the key.
    pub epoch: u64,
    /// The pairing's client public key the owner approved this device for.
    #[serde(default)]
    pub client_pubkey: String,
    /// The owner-approval key's Ed25519 signature over
    /// [`owner_approval_message`], hex. Re-verified on every use: a record
    /// written into `data_dir` by anyone but the owner authorizes nothing.
    #[serde(default)]
    pub owner_approval: String,
}

/// A device key awaiting the owner's one-time approval. Durable: a node
/// restart re-prints a fresh code for it instead of losing it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingDeviceKey {
    /// Operation id the owner names.
    pub op_id: String,
    /// Requesting client.
    pub client_id: String,
    /// Requesting client's name.
    pub client_name: String,
    /// Pairing epoch at request time.
    pub epoch: u64,
    /// The pairing's client public key at request time.
    #[serde(default)]
    pub client_pubkey: String,
    /// Key id of the key to register.
    pub key_id: String,
    /// The public key, hex.
    pub public_key: String,
    /// Device name.
    pub name: String,
    /// Unix seconds after which it can no longer be approved.
    pub expires_at: i64,
}

/// Status of a device-key registration, as the requesting client reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKeyStatus {
    /// Awaiting the owner.
    Pending,
    /// The owner approved it; the key is registered.
    Registered,
    /// The window closed.
    Expired,
    /// Cancelled by wrong codes; ask again.
    Lost,
    /// No such operation.
    Absent,
}

/// The terms a device signs to open or renew one peer's envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RelationIntent {
    /// Registered key that signed it.
    pub device_key_id: String,
    /// The peer's node id, 64 hex.
    pub peer: String,
    /// Relation level (1 = Contact).
    pub level: u8,
    /// Budget for this peer in this window, msat.
    pub budget_msat: u64,
    /// Most one act may pay this peer, msat.
    pub per_act_max_msat: u64,
    /// Envelope window, seconds.
    pub window_secs: i64,
    /// Unix seconds the device signed it.
    pub issued_at: i64,
    /// 16 random bytes, hex. Single use.
    pub nonce: String,
}

/// Public label and command for a pending device registration.
pub fn device_confirmation_phrase(op: &PendingDeviceKey) -> String {
    format!("REGISTER DEVICE {} TO {}", op.key_id, op.op_id)
}

/// The key id of a public key: `blake3(pubkey)[..16]`, hex.
pub fn key_id_for(public_key: &[u8]) -> String {
    hex::encode(&blake3::hash(public_key).as_bytes()[..16])
}

/// A short, groupable fingerprint the owner compares with the app's screen.
pub fn key_fingerprint(key_id: &str) -> String {
    key_id
        .as_bytes()
        .chunks(4)
        .take(4)
        .map(|c| String::from_utf8_lossy(c).to_uppercase())
        .collect::<Vec<_>>()
        .join("-")
}

/// Exact bytes the **owner-approval key** signs to register a device key:
/// the pairing's `client_pubkey` and `epoch` (the root of the pairing chain),
/// bound to this node and to the one device key being approved.
pub fn owner_approval_message(node: &str, client_pubkey: &str, epoch: u64, device_public_key: &str) -> String {
    format!(
        "bitsov-owner-approval-v1\npurpose:device-key\nnode:{node}\nclient_pubkey:{client_pubkey}\n\
         epoch:{epoch}\ndevice_key:{device_public_key}"
    )
}

/// Verify an owner-approval signature (Ed25519, hex).
pub fn verify_owner_approval(
    owner: &ed25519_dalek::VerifyingKey,
    message: &str,
    signature_hex: &str,
) -> Result<(), PairingError> {
    let raw = hex::decode(signature_hex).map_err(|_| PairingError::BadProof)?;
    let sig = ed25519_dalek::Signature::from_slice(&raw).map_err(|_| PairingError::BadProof)?;
    owner.verify_strict(message.as_bytes(), &sig).map_err(|_| PairingError::BadProof)
}

/// Exact bytes the device signs to prove possession at registration.
pub fn registration_message(node: &str, client_id: &str, public_key_hex: &str) -> String {
    format!("bitsov-device-register-v1\nnode:{node}\nclient:{client_id}\npublic_key:{public_key_hex}")
}

/// Exact bytes a device signs for a relation intent. `node` and `client_id`
/// come from the node's own state and the caller's token, never the body, so
/// a signature cannot be replayed to another node or pairing.
pub fn intent_message(node: &str, client_id: &str, intent: &RelationIntent) -> String {
    format!(
        "bitsov-relation-intent-v1\nnode:{node}\nclient:{client_id}\ndevice:{}\npeer:{}\nlevel:{}\n\
         budget_msat:{}\nper_act_max_msat:{}\nwindow_secs:{}\nissued_at:{}\nnonce:{}",
        intent.device_key_id,
        intent.peer,
        intent.level,
        intent.budget_msat,
        intent.per_act_max_msat,
        intent.window_secs,
        intent.issued_at,
        intent.nonce
    )
}

fn parse_public_key(public_key_hex: &str) -> Result<Vec<u8>, PairingError> {
    let raw = hex::decode(public_key_hex)
        .map_err(|_| PairingError::Malformed("device key is not hex".into()))?;
    if raw.len() != 65 || raw[0] != 0x04 {
        return Err(PairingError::Malformed(
            "device key must be an uncompressed P-256 point (65 bytes, 0x04…)".into(),
        ));
    }
    Ok(raw)
}

/// ECDSA P-256 / SHA-256, DER signature (what CryptoKit's
/// `derRepresentation` produces). `ring` rejects points off the curve.
fn verify_p256(public_key: &[u8], message: &[u8], signature_hex: &str) -> Result<(), PairingError> {
    let sig = hex::decode(signature_hex).map_err(|_| PairingError::BadProof)?;
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, public_key)
        .verify(message, &sig)
        .map_err(|_| PairingError::BadProof)
}

fn clean_name(name: &str) -> Result<String, PairingError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > 64
        || name.chars().any(|c| c.is_control() || super::invisible_format(c))
    {
        return Err(PairingError::Malformed(
            "device name must be 1–64 visible characters".into(),
        ));
    }
    Ok(name.to_string())
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl PairingService {
    /// A paired client asks the owner to register a device key. Writes **no**
    /// authority. `proof_hex` must be the key's signature over
    /// [`registration_message`], so a client cannot register a key it does
    /// not hold. The owner approves with `konsensus device approve`.
    pub fn request_device_key(
        &self,
        client_id: &str,
        public_key_hex: &str,
        name: &str,
        proof_hex: &str,
    ) -> Result<PendingDeviceKey, PairingError> {
        if !self.owner_control_enabled {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        self.device_authority()?;
        let public_key_hex = public_key_hex.to_ascii_lowercase();
        let raw = parse_public_key(&public_key_hex)?;
        let name = clean_name(name)?;
        let mut op_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut op_bytes);

        // Verify before taking the pairing lock: a flood of bad proofs must not
        // hold up every token check on the node.
        let node = self.bound_fingerprint();
        verify_p256(
            &raw,
            registration_message(&node, client_id, &public_key_hex).as_bytes(),
            proof_hex,
        )?;
        let mut inner = self.lock();
        if inner.identity_fingerprint != node {
            return Err(PairingError::PairingInvalid("the node identity changed; ask again".into()));
        }
        let client = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .cloned()
            .ok_or(PairingError::UnknownClient)?;
        let key_id = key_id_for(&raw);
        let now = chrono::Utc::now().timestamp();
        // At most one new registration request per client every 30 s: each
        // one prints to the owner's terminal and replaces the previous one.
        if inner.file.pending_device_keys.iter().any(|p| {
            p.client_id == client_id && p.expires_at - ELEVATION_TTL_SECS > now - 30
        }) {
            return Err(PairingError::TooManyPending);
        }
        // Keys retired by a rotation or epoch bump no longer block the device.
        let live: Vec<(String, u64)> = inner.file.clients.iter().map(|c| (c.client_id.clone(), c.epoch)).collect();
        inner
            .file
            .device_keys
            .retain(|k| live.iter().any(|(c, e)| *c == k.client_id && *e == k.epoch));
        if inner.file.device_keys.iter().any(|k| k.key_id == key_id) {
            return Err(PairingError::Malformed("this device key is already registered".into()));
        }
        let live = inner
            .file
            .device_keys
            .iter()
            .filter(|k| k.client_id == client_id && k.epoch == client.epoch)
            .count();
        if live >= MAX_DEVICE_KEYS_PER_CLIENT {
            return Err(PairingError::NotGrantable(format!(
                "this pairing already has {MAX_DEVICE_KEYS_PER_CLIENT} device keys; revoke one first"
            )));
        }
        let op = PendingDeviceKey {
            op_id: hex::encode(op_bytes),
            client_id: client_id.to_string(),
            client_name: client.name.clone(),
            epoch: client.epoch,
            client_pubkey: client.client_pubkey.clone(),
            key_id,
            public_key: public_key_hex,
            name,
            expires_at: now + ELEVATION_TTL_SECS,
        };
        self.console_challenge(
            &mut inner,
            &op.op_id,
            &device_confirmation_phrase(&op),
            op.expires_at,
            Some(self.owner_device_command(&op.op_id)),
        )?;
        // One registration in flight per client: a new request replaces it.
        let replaced: Vec<String> = inner
            .file
            .pending_device_keys
            .iter()
            .filter(|p| p.client_id == client_id || p.expires_at <= now)
            .map(|p| p.op_id.clone())
            .collect();
        for id in &replaced {
            inner.owner_confirmations.remove(id);
        }
        inner
            .file
            .pending_device_keys
            .retain(|p| !replaced.contains(&p.op_id));
        let before = inner.file.clone();
        inner.file.pending_device_keys.push(op.clone());
        if let Err(e) = self.persist(&mut inner.file) {
            inner.file = before;
            return Err(e);
        }
        Ok(op)
    }

    /// Read a registration's status. A read, never a consumption.
    pub fn device_key_status(&self, client_id: &str, op_id: &str) -> DeviceKeyStatus {
        let inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        if let Some(p) = inner
            .file
            .pending_device_keys
            .iter()
            .find(|p| p.op_id == op_id && p.client_id == client_id)
        {
            if p.expires_at <= now {
                return DeviceKeyStatus::Expired;
            }
            if !Self::confirmable(&inner, op_id) {
                return DeviceKeyStatus::Lost;
            }
            return DeviceKeyStatus::Pending;
        }
        if inner
            .file
            .registered_ops
            .get(op_id)
            .is_some_and(|key_id| {
                inner
                    .file
                    .device_keys
                    .iter()
                    .any(|k| &k.key_id == key_id && k.client_id == client_id)
            })
        {
            return DeviceKeyStatus::Registered;
        }
        if inner.cancelled_ops.contains(op_id) {
            return DeviceKeyStatus::Lost;
        }
        DeviceKeyStatus::Absent
    }

    /// The pending registration `op_id`, for the owner console.
    pub fn pending_device_key(&self, op_id: &str) -> Option<PendingDeviceKey> {
        self.lock()
            .file
            .pending_device_keys
            .iter()
            .find(|p| p.op_id == op_id)
            .cloned()
    }

    /// **Owner console only.** Register a device key after the owner typed the
    /// code the node printed for this request.
    pub fn approve_device_key(
        &self,
        op_id: &str,
        confirmation: &str,
        owner_signature: &str,
    ) -> Result<DeviceKey, PairingError> {
        if !self.owner_control_enabled {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        let owner = self.device_authority()?;
        let mut inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        let op = inner
            .file
            .pending_device_keys
            .iter()
            .find(|p| p.op_id == op_id)
            .cloned()
            .ok_or(PairingError::UnknownOperation)?;
        if op.expires_at <= now {
            inner.file.pending_device_keys.retain(|p| p.op_id != op_id);
            self.persist(&mut inner.file)?;
            return Err(PairingError::Expired);
        }
        // The owner key signs first: a wrong signature spends no code attempt.
        let client_pubkey = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == op.client_id)
            .map(|c| c.client_pubkey.clone())
            .ok_or(PairingError::UnknownClient)?;
        let node = inner.identity_fingerprint.clone();
        verify_owner_approval(
            &owner,
            &owner_approval_message(&node, &client_pubkey, op.epoch, &op.public_key),
            owner_signature,
        )?;
        self.verify_grant_confirmation(
            &mut inner,
            &device_confirmation_phrase(&op),
            op_id,
            confirmation,
        )?;
        let epoch = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == op.client_id)
            .map(|c| c.epoch)
            .ok_or(PairingError::UnknownClient)?;
        if epoch != op.epoch {
            return Err(PairingError::PairingInvalid(
                "the pairing changed since this key was requested; ask again".into(),
            ));
        }
        let key = DeviceKey {
            key_id: op.key_id.clone(),
            client_id: op.client_id.clone(),
            public_key: op.public_key.clone(),
            name: op.name.clone(),
            registered_at: now,
            epoch,
            client_pubkey,
            owner_approval: owner_signature.to_ascii_lowercase(),
        };
        let before = inner.file.clone();
        inner.file.pending_device_keys.retain(|p| p.op_id != op_id);
        inner.file.device_keys.retain(|k| k.key_id != key.key_id);
        inner.file.device_keys.push(key.clone());
        inner.file.registered_ops.insert(op_id.to_string(), key.key_id.clone());
        if let Err(e) = self.persist(&mut inner.file) {
            inner.file = before;
            return Err(e);
        }
        inner.owner_confirmations.remove(op_id);
        Ok(key)
    }

    /// Registered device keys (all clients), for the owner.
    pub fn device_keys(&self) -> Vec<DeviceKey> {
        self.lock().file.device_keys.clone()
    }

    /// Pending device-key registrations (all clients), for the owner.
    pub fn pending_device_keys(&self) -> Vec<PendingDeviceKey> {
        self.lock().file.pending_device_keys.clone()
    }

    /// This client's usable device keys.
    pub fn device_keys_for(&self, client_id: &str) -> Vec<DeviceKey> {
        let inner = self.lock();
        let epoch = inner.file.clients.iter().find(|c| c.client_id == client_id).map(|c| c.epoch);
        inner
            .file
            .device_keys
            .iter()
            .filter(|k| k.client_id == client_id && Some(k.epoch) == epoch)
            .cloned()
            .collect()
    }

    /// Revoke a device key (owner, or the client revoking its own). The
    /// relation grant it may have opened ends with it: every envelope of that
    /// client stops on its next request.
    pub fn revoke_device_key(&self, key_id: &str, only_client: Option<&str>) -> Result<(), PairingError> {
        let mut inner = self.lock();
        let Some(key) = inner
            .file
            .device_keys
            .iter()
            .find(|k| k.key_id == key_id && only_client.is_none_or(|c| k.client_id == c))
            .cloned()
        else {
            return Err(PairingError::UnknownOperation);
        };
        inner.file.device_keys.retain(|k| k.key_id != key_id);
        inner.file.registered_ops.retain(|_, k| k != key_id);
        Self::end_relation_grants(&mut inner, &key.client_id);
        self.persist(&mut inner.file)?;
        Ok(())
    }

    fn end_relation_grants(inner: &mut Inner, client_id: &str) {
        for grant in &mut inner.file.grants {
            if grant.client_id == client_id
                && grant.budget.as_ref().is_some_and(|b| b.recipients_only)
            {
                grant.budget = None;
            }
        }
    }

    /// A paired client withdraws its own pending request (an elevation or a
    /// device registration). Removes no authority; the owner's code stops
    /// working.
    pub fn cancel_pending(&self, client_id: &str, op_id: &str) -> Result<(), PairingError> {
        let mut inner = self.lock();
        let before = inner.file.pending_elevations.len() + inner.file.pending_device_keys.len();
        inner
            .file
            .pending_elevations
            .retain(|e| !(e.op_id == op_id && e.client_id == client_id));
        inner
            .file
            .pending_device_keys
            .retain(|p| !(p.op_id == op_id && p.client_id == client_id));
        if inner.file.pending_elevations.len() + inner.file.pending_device_keys.len() == before {
            return Err(PairingError::UnknownOperation);
        }
        inner.owner_confirmations.remove(op_id);
        self.persist(&mut inner.file)?;
        Ok(())
    }

    /// Open or renew one peer's spend envelope from a device-signed intent.
    ///
    /// Checked, in order, before anything is written: owner-run node; the key
    /// is registered to this client at its current epoch; the signature is
    /// over [`intent_message`] with this node and this client; `issued_at` is
    /// within [`INTENT_MAX_SKEW_SECS`]; the nonce is unused; the terms are in
    /// bounds; the client is under [`RELATION_INTENTS_PER_HOUR`]. The nonce
    /// is recorded durably with the envelope, so neither a replay nor a
    /// restart can apply it twice.
    pub fn apply_relation_intent(
        &self,
        client_id: &str,
        epoch: u64,
        intent: &RelationIntent,
        signature_hex: &str,
    ) -> Result<GrantView, PairingError> {
        if !self.owner_control_enabled {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        self.device_authority()?;
        let peer = intent.peer.to_ascii_lowercase();
        if !is_hex(&peer, 64) || peer != intent.peer {
            return Err(PairingError::Malformed("peer must be a lowercase 64-hex node id".into()));
        }
        if !is_hex(&intent.nonce, 32) {
            return Err(PairingError::Malformed("nonce must be 16 random bytes, lowercase hex".into()));
        }
        if intent.level != LEVEL_CONTACT {
            return Err(PairingError::NotGrantable(
                "only Contact (level 1) envelopes are signed yet".into(),
            ));
        }
        if !(RELATION_MIN_WINDOW_SECS..=RELATION_MAX_WINDOW_SECS).contains(&intent.window_secs) {
            return Err(PairingError::Malformed("window must be between 1 minute and 24 hours".into()));
        }
        if intent.budget_msat == 0
            || intent.budget_msat > RELATION_MAX_BUDGET_MSAT
            || intent.per_act_max_msat == 0
            || intent.per_act_max_msat > intent.budget_msat
        {
            return Err(PairingError::Malformed(
                "budget must be 1 msat to 100,000 sats, and per act at most the budget".into(),
            ));
        }

        // Phase 1, under the lock: find the key. Phase 2, outside it: the
        // signature check. Phase 3, under the lock again: re-check and write.
        let (node, key) = {
            let inner = self.lock();
            let key = self.intent_key(&inner, client_id, epoch, &intent.device_key_id)?;
            (inner.identity_fingerprint.clone(), key)
        };
        let raw = parse_public_key(&key.public_key)?;
        verify_p256(&raw, intent_message(&node, client_id, intent).as_bytes(), signature_hex)?;

        let mut inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        if (i128::from(now) - i128::from(intent.issued_at)).abs() > i128::from(INTENT_MAX_SKEW_SECS) {
            return Err(PairingError::Expired);
        }
        if inner.identity_fingerprint != node
            || self.intent_key(&inner, client_id, epoch, &intent.device_key_id)? != key
        {
            return Err(PairingError::NotGrantable("the device key changed while checking; sign again".into()));
        }
        let before = (inner.file.grants.clone(), inner.file.intent_nonces.clone());

        let nonce_key = format!("{}:{}", key.key_id, intent.nonce);
        inner
            .file
            .intent_nonces
            .retain(|_, (_, at)| *at > now - 3600 - INTENT_MAX_SKEW_SECS);
        if inner.file.intent_nonces.contains_key(&nonce_key) {
            return Err(PairingError::BadProof);
        }
        let recent = inner
            .file
            .intent_nonces
            .values()
            .filter(|(c, at)| c == client_id && *at > now - 3600)
            .count();
        if recent >= RELATION_INTENTS_PER_HOUR {
            return Err(PairingError::TooManyPending);
        }

        let expires = now + intent.window_secs;
        let live_idx = inner.file.grants.iter().position(|g| {
            g.client_id == client_id
                && g.epoch == epoch
                && g.identity_fingerprint == node
                && g.is_live(now)
                && g.budget.as_ref().is_some_and(|b| b.recipients_only)
        });
        let idx = match live_idx {
            Some(idx) => idx,
            None => {
                // A relation grant replaces a console budget window: one
                // budget per client, and the device is the owner's now.
                for old in &mut inner.file.grants {
                    if old.client_id == client_id {
                        old.budget = None;
                    }
                }
                let mut op = [0u8; 12];
                rand::thread_rng().fill_bytes(&mut op);
                inner.file.grants.push(SpendGrant {
                    op_id: format!("rel-{}", hex::encode(op)),
                    client_id: client_id.to_string(),
                    scopes: vec![Scope::Spend],
                    granted_at: now,
                    expires_at: expires,
                    identity_fingerprint: node.clone(),
                    epoch,
                    granted_by: format!("device:{}", key.key_id),
                    budget: Some(GrantBudget::relations()),
                });
                inner.file.grants.len() - 1
            }
        };
        let grant = &mut inner.file.grants[idx];
        let budget = grant.budget.as_mut().ok_or(PairingError::Io("grant vanished".into()))?;
        budget.open_envelope(&peer, intent.budget_msat, intent.per_act_max_msat, expires);
        // A fresh signature renews the grant: it lives until its last envelope,
        // which is never more than 24 h from now.
        let last = budget
            .recipient_expires_at
            .values()
            .copied()
            .filter(|at| *at > now)
            .max()
            .unwrap_or(expires);
        grant.granted_at = now;
        grant.expires_at = last;
        grant.granted_by = format!("device:{}", key.key_id);
        let view = super::grant_view(grant).ok_or(PairingError::Io("grant vanished".into()))?;
        inner
            .file
            .intent_nonces
            .insert(nonce_key, (client_id.to_string(), intent.issued_at.max(now)));
        if let Err(e) = self.persist(&mut inner.file) {
            // Never leave authority live in memory that the disk did not take.
            (inner.file.grants, inner.file.intent_nonces) = before;
            return Err(e);
        }
        tracing::info!(
            client_id,
            device_key = %key.key_id,
            peer = %peer,
            budget_msat = intent.budget_msat,
            per_act_max_msat = intent.per_act_max_msat,
            window_secs = intent.window_secs,
            "device-signed relation envelope opened"
        );
        Ok(view)
    }

    /// The registered key an intent names, for this client at its current
    /// epoch, or why not.
    /// Fail closed while device authority is off node-wide.
    fn device_authority(&self) -> Result<ed25519_dalek::VerifyingKey, PairingError> {
        if let Some(reason) = self.device_authority_off {
            return Err(PairingError::DeviceApprovalsDisabled(reason));
        }
        self.owner_approval_key
            .ok_or(PairingError::DeviceApprovalsDisabled(OWNER_KEY_UNAVAILABLE))
    }

    fn intent_key(&self, inner: &Inner, client_id: &str, epoch: u64, key_id: &str) -> Result<DeviceKey, PairingError> {
        let client = inner
            .file
            .clients
            .iter()
            .find(|c| c.client_id == client_id)
            .ok_or(PairingError::UnknownClient)?;
        if client.epoch != epoch {
            return Err(PairingError::PairingInvalid("stale token epoch".into()));
        }
        let key = inner
            .file
            .device_keys
            .iter()
            .find(|k| k.key_id == key_id && k.client_id == client_id && k.epoch == epoch)
            .cloned()
            .ok_or_else(|| PairingError::NotGrantable("unknown or revoked device key".into()))?;
        // The root of the chain: the owner-approval key signed exactly this
        // pairing key, epoch and device key for this node.
        let owner = self.device_authority()?;
        let unsigned = || PairingError::NotGrantable("device key has no valid owner approval".into());
        if key.client_pubkey != client.client_pubkey {
            return Err(unsigned());
        }
        verify_owner_approval(
            &owner,
            &owner_approval_message(&inner.identity_fingerprint, &key.client_pubkey, key.epoch, &key.public_key),
            &key.owner_approval,
        )
        .map_err(|_| unsigned())?;
        Ok(key)
    }

    /// Owner-run startup: print a fresh code for every approval that
    /// survived the restart. The records are durable; only the codes were
    /// memory, so a restart renews them instead of killing the request.
    pub fn reissue_owner_challenges(&self) -> Result<usize, PairingError> {
        if !self.owner_control_enabled {
            return Ok(0);
        }
        let mut inner = self.lock();
        let now = chrono::Utc::now().timestamp();
        type Todo = (String, String, i64, Option<String>);
        let mut todo: Vec<Todo> = Vec::new();
        for e in inner.file.pending_elevations.iter().filter(|e| e.expires_at > now) {
            let command = Some(self.owner_grant_command(&e.op_id));
            todo.push((e.op_id.clone(), super::grant_confirmation_phrase(e), e.expires_at, command));
        }
        for p in inner.file.pending_device_keys.iter().filter(|p| p.expires_at > now) {
            let command = Some(self.owner_device_command(&p.op_id));
            todo.push((p.op_id.clone(), device_confirmation_phrase(p), p.expires_at, command));
        }
        for a in inner
            .file
            .replacement_approvals
            .iter()
            .filter(|a| a.expires_at > now && !a.approved)
        {
            todo.push((a.op_id.clone(), super::replacement_confirmation_phrase(a), a.expires_at, None));
        }
        let mut issued = 0;
        for (op_id, label, expires_at, command) in todo {
            if Self::confirmable(&inner, &op_id) {
                continue;
            }
            self.console_challenge(&mut inner, &op_id, &label, expires_at, command)?;
            issued += 1;
        }
        Ok(issued)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spend_budget::{BudgetRefusal, Charge};
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    /// Codex #146 P1: A has a 60 s envelope, B a 3600 s one. A payment to A
    /// reserved inside A's window must not dispatch after it, even though B
    /// keeps the shared grant alive.
    #[test]
    fn an_expired_peer_envelope_cannot_dispatch_on_a_live_peers_time() {
        let tmp = tempfile::tempdir().unwrap();
        let owner = konsensus_core::OwnerApprovalKey::from_seed(&[7u8; 64], &[9u8; 32]).unwrap();
        let service = PairingService::open(tmp.path(), "f".repeat(32), true)
            .unwrap()
            .with_owner_console(Box::new(std::io::sink()))
            .without_stdout_code()
            .with_owner_approval_key(owner.verifying_key());
        // Pair a client.
        let ck = ed25519_dalek::SigningKey::from_bytes(&[3; 32]);
        let cpub = hex::encode(ck.verifying_key().to_bytes());
        let pending = service.request_pairing("app", &cpub).unwrap();
        let challenge = std::fs::read(service.dir().join(format!("challenge-{}", pending.pair_id))).unwrap();
        use ed25519_dalek::Signer;
        let sig = hex::encode(ck.sign(&PairingService::proof_message(&pending.pair_id, &cpub, &challenge)).to_bytes());
        let client = service.confirm_pairing(&pending.pair_id, &sig, super::super::default_pairing_scopes()).unwrap();
        // A registered device key (approval tested elsewhere; the record is the effect).
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let device = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
        let public = device.public_key().as_ref().to_vec();
        let key_id = key_id_for(&public);
        {
            let mut inner = service.lock();
            inner.file.device_keys.push(DeviceKey {
                key_id: key_id.clone(),
                client_id: client.client_id.clone(),
                public_key: hex::encode(&public),
                name: "mac".into(),
                registered_at: 0,
                epoch: client.epoch,
                client_pubkey: cpub.clone(),
                owner_approval: hex::encode(
                    owner
                        .sign(owner_approval_message(&"f".repeat(32), &cpub, client.epoch, &hex::encode(&public)).as_bytes())
                        .to_bytes(),
                ),
            });
        }
        let (a, b) = ("a".repeat(64), "b".repeat(64));
        let now = chrono::Utc::now().timestamp();
        for (peer, window) in [(&a, 60), (&b, 3600)] {
            let mut nonce = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut nonce);
            let intent = RelationIntent {
                device_key_id: key_id.clone(),
                peer: peer.clone(),
                level: LEVEL_CONTACT,
                budget_msat: 10_000,
                per_act_max_msat: 10_000,
                window_secs: window,
                issued_at: now,
                nonce: hex::encode(nonce),
            };
            let msg = intent_message(&"f".repeat(32), &client.client_id, &intent);
            let sig = hex::encode(device.sign(&rng, msg.as_bytes()).unwrap().as_ref());
            service.apply_relation_intent(&client.client_id, client.epoch, &intent, &sig).unwrap();
        }
        // Reserved at second ~0, inside A's window.
        let to_a = service
            .reserve_spend(&client.client_id, client.epoch, vec![Charge { recipient: a.clone(), amount_msat: 1_000 }])
            .unwrap();
        let to_b = service
            .reserve_spend(&client.client_id, client.epoch, vec![Charge { recipient: b.clone(), amount_msat: 1_000 }])
            .unwrap();
        // Second 59: both may dispatch.
        assert!(service.with_spend_authority_at(&to_a, || now + 59, || ()).is_ok());
        // Second 61: A's envelope is over; B's grant time does not carry A.
        assert!(matches!(service.with_spend_authority_at(&to_a, || now + 61, || ()), Err(BudgetRefusal::NoGrant)));
        assert!(service.with_spend_authority_at(&to_b, || now + 61, || ()).is_ok());
        // And past B's deadline, B stops too.
        assert!(matches!(service.with_spend_authority_at(&to_b, || now + 3601, || ()), Err(BudgetRefusal::NoGrant)));
    }
}

#[cfg(test)]
mod clock_tests {
    use super::*;
    use crate::spend_budget::{BudgetRefusal, Charge};

    /// Codex #146 delta: the dispatch deadline is judged at the moment the
    /// lock is held, not when the caller arrived. The clock runs only after
    /// the lock is acquired (it would deadlock re-locking otherwise), and a
    /// clock read then that is past the deadline refuses.
    #[test]
    fn the_dispatch_clock_is_read_under_the_pairing_lock() {
        let tmp = tempfile::tempdir().unwrap();
        let service = PairingService::open(tmp.path(), "f".repeat(32), true)
            .unwrap()
            .with_owner_console(Box::new(std::io::sink()))
            .without_stdout_code();
        let reservation = crate::spend_budget::Reservation {
            id: "r".into(),
            client_id: "c".into(),
            op_id: "op".into(),
            charges: vec![Charge { recipient: "a".repeat(64), amount_msat: 1 }],
        };
        let held = std::cell::Cell::new(false);
        let out = service.with_spend_authority_at(
            &reservation,
            || {
                // The pairing mutex is held while the clock is read.
                held.set(service.inner.try_lock().is_err());
                0
            },
            || (),
        );
        assert!(held.get(), "the clock must be sampled while holding the lock");
        assert!(matches!(out, Err(BudgetRefusal::NoGrant)));
    }
}
