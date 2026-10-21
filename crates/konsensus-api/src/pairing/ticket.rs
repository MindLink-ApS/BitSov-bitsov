//! Owner-device tickets: bounded, memory-only authority, serialized with revocation.
use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;

use super::{device, Inner, PairedClient, PairingError, PairingService};
use crate::remote_access::{self, PairLink};

const TTL: Duration = Duration::from_secs(300);
const ISSUE_WINDOW: Duration = Duration::from_secs(900);
const MAX_ISSUES: usize = 5;
/// Distinguishes strict single-use device tickets from idempotent CLI pairing retries.
pub const OWNER_TICKET_PREFIX: &str = "owner_";

#[derive(Default)]
pub(super) struct OwnerTickets {
    descriptor: Option<PairLink>,
    challenges: HashMap<String, Challenge>,
    tickets: HashMap<String, Ticket>,
    issued: Vec<(String, Instant)>,
    reads: Vec<Instant>,
}
struct Challenge {
    nonce: String,
    key_id: String,
    epoch: u64,
    deadline: Instant,
}
#[derive(Clone)]
struct Ticket {
    client_id: String,
    key_id: String,
    epoch: u64,
    deadline: Instant,
    second_device: bool,
}

fn random_hex() -> String {
    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

impl PairingService {
    /// Live-listener startup only. Public signed descriptor; no ticket is issued here.
    pub fn configure_owner_tickets(
        &self,
        identity: &konsensus_core::NodeIdentity,
        endpoints: Vec<String>,
    ) -> Result<(), PairingError> {
        let node_id = identity.node_id().to_hex();
        let transport_pubkey = hex::encode(identity.x25519_public().as_bytes());
        let box_transport_pubkey = hex::encode(self.box_transport_pubkey());
        let sign =
            |message: String| URL_SAFE_NO_PAD.encode(identity.sign(message.as_bytes()).to_bytes());
        let mut descriptor = PairLink {
            v: remote_access::PAIR_LINK_VERSION,
            endpoint: endpoints.first().cloned().unwrap_or_default(),
            endpoints,
            endpoints_signature: None,
            transport_signature: sign(remote_access::transport_proof_message(
                &node_id,
                &transport_pubkey,
            )),
            box_transport_signature: Some(sign(remote_access::box_transport_proof_message(
                &node_id,
                &box_transport_pubkey,
            ))),
            node_id,
            transport_pubkey,
            box_transport_pubkey,
            code: String::new(),
            expires_at: 0,
            hosted_by: self.hosted_by().map(str::to_owned),
        };
        descriptor.endpoints_signature = Some(sign(descriptor.endpoints_proof_message()));
        descriptor
            .validate_descriptor()
            .map_err(PairingError::Malformed)?;
        let mut inner = self.lock();
        if inner.identity_fingerprint != super::identity_fingerprint(&descriptor.node_id) {
            return Err(PairingError::BadProof);
        }
        inner.owner_tickets.descriptor = Some(descriptor);
        Ok(())
    }

    fn ticket_owner(
        &self,
        inner: &Inner,
        client: &str,
        epoch: u64,
        key: &str,
    ) -> Result<device::DeviceKey, PairingError> {
        if !self.local_owner_device || self.owner_signing_key.is_none() || inner.pairing_closed {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        self.intent_key(inner, client, epoch, key)
    }

    /// Five-minute, server-chosen challenge, bound to the client's current key and epoch.
    pub fn owner_ticket_challenge(
        &self,
        client: &str,
        epoch: u64,
        key: &str,
    ) -> Result<String, PairingError> {
        let mut inner = self.lock();
        self.ticket_owner(&inner, client, epoch, key)?;
        let state = &mut inner.owner_tickets;
        if state.descriptor.is_none() {
            return Err(PairingError::OwnerChannelUnavailable);
        }
        let now = Instant::now();
        state
            .reads
            .retain(|t| now.duration_since(*t) < Duration::from_secs(60));
        if state.reads.len() >= 30 {
            return Err(PairingError::TooManyPending);
        }
        state.reads.push(now);
        state.challenges.retain(|_, c| c.deadline > now);
        if let Some(c) = state
            .challenges
            .get(client)
            .filter(|c| c.epoch == epoch && c.key_id == key)
        {
            return Ok(c.nonce.clone());
        }
        if state.challenges.len() >= 64 {
            return Err(PairingError::TooManyPending);
        }
        let nonce = random_hex();
        state.challenges.insert(
            client.into(),
            Challenge {
                nonce: nonce.clone(),
                key_id: key.into(),
                epoch,
                deadline: now + TTL,
            },
        );
        Ok(nonce)
    }

    /// Verify and consume the server challenge, then mint a five-minute one-use ticket.
    pub fn mint_owner_ticket(
        &self,
        client: &str,
        epoch: u64,
        key: &str,
        nonce: &str,
        signature: &str,
    ) -> Result<PairLink, PairingError> {
        self.mint_owner_ticket_with_purpose(client, epoch, key, nonce, signature, None)
    }

    /// Purpose is covered by the v2 ticket signature; omission retains v1 bytes.
    pub fn mint_owner_ticket_with_purpose(
        &self,
        client: &str,
        epoch: u64,
        key: &str,
        nonce: &str,
        signature: &str,
        purpose: Option<&str>,
    ) -> Result<PairLink, PairingError> {
        if purpose.is_some_and(|p| p != "second_device") {
            return Err(PairingError::BadProof);
        }
        let second_device = purpose.is_some();
        let mut inner = self.lock();
        if second_device {
            self.second_device_available()?;
            if !inner.file.device_keys.iter().any(|k| {
                self.intent_key(&inner, &k.client_id, k.epoch, &k.key_id)
                    .is_ok()
            }) {
                return Err(PairingError::PairingInvalid("no_owner_device".into()));
            }
        }
        let owner = self.ticket_owner(&inner, client, epoch, key)?;
        let now = Instant::now();
        let challenge = inner
            .owner_tickets
            .challenges
            .get(client)
            .ok_or(PairingError::BadProof)?;
        if challenge.deadline <= now
            || challenge.epoch != epoch
            || challenge.key_id != key
            || challenge.nonce != nonce
        {
            return Err(PairingError::BadProof);
        }
        device::verify_p256(
            &device::parse_public_key(&owner.public_key)?,
            if second_device {
                format!(
                    "bitsov-ticket-v2\nnode:{}\nnonce:{nonce}\npurpose:second_device",
                    inner.identity_fingerprint
                )
            } else {
                format!(
                    "bitsov-ticket-v1\nnode:{}\nnonce:{nonce}",
                    inner.identity_fingerprint
                )
            }
            .as_bytes(),
            signature,
        )?;
        let state = &mut inner.owner_tickets;
        // Expired, unconsumed tickets refund their issue slots; consumed ones do not.
        let refunds: Vec<_> = state
            .tickets
            .iter()
            .filter(|(_, t)| t.deadline <= now)
            .map(|(hash, _)| hash.clone())
            .collect();
        state.tickets.retain(|_, t| t.deadline > now);
        state
            .issued
            .retain(|(hash, t)| now.duration_since(*t) < ISSUE_WINDOW && !refunds.contains(hash));
        if state.issued.len() >= MAX_ISSUES {
            return Err(PairingError::TooManyPending);
        }
        let mut link = state
            .descriptor
            .clone()
            .ok_or(PairingError::OwnerChannelUnavailable)?;
        link.code = format!("{OWNER_TICKET_PREFIX}{}", random_hex());
        link.expires_at = chrono::Utc::now().timestamp() + TTL.as_secs() as i64;
        let ticket_hash = blake3::hash(link.code.as_bytes()).to_hex().to_string();
        state.tickets.retain(|_, t| t.deadline > now);
        state.tickets.insert(
            ticket_hash.clone(),
            Ticket {
                client_id: client.into(),
                key_id: key.into(),
                epoch,
                deadline: now + TTL,
                second_device,
            },
        );
        state.challenges.remove(client);
        state.issued.push((ticket_hash, now));
        if second_device {
            self.enrollment_event(
                "pair.second_device_ticket_issued",
                client,
                serde_json::json!({"epoch":epoch,"key_id":key}),
            );
        }
        Ok(link)
    }

    /// Called by the Noise listener after verifying the new client's pairing proof.
    /// Issuer revalidation, single-use consumption and pairing write share one lock.
    pub fn consume_owner_ticket(
        &self,
        code: &str,
        name: &str,
        public_key: &str,
        transport: &[u8; 32],
    ) -> Result<PairedClient, PairingError> {
        let mut inner = self.lock();
        self.rescan_locked(&mut inner, code, public_key, transport)?;
        let hash = blake3::hash(code.as_bytes()).to_hex().to_string();
        let ticket = inner
            .owner_tickets
            .tickets
            .get(&hash)
            .cloned()
            .ok_or(PairingError::BadProof)?;
        // Legacy tickets burn on any consumption attempt, including expiry or
        // stale issuer authority. V2 keeps its eligibility-before-consume order.
        if !ticket.second_device {
            inner.owner_tickets.tickets.remove(&hash);
        }
        if ticket.deadline <= Instant::now() {
            return Err(PairingError::Expired);
        }
        self.ticket_owner(&inner, &ticket.client_id, ticket.epoch, &ticket.key_id)?;
        if ticket.second_device {
            let client = self.create_second_device_locked(
                &mut inner,
                code,
                name,
                public_key,
                transport,
                &ticket.key_id,
            )?;
            inner.owner_tickets.tickets.remove(&hash);
            Ok(client)
        } else {
            self.create_remote_pairing_locked(&mut inner, name, public_key, transport, false)
        }
    }

    /// Only an enrolled owner on its authenticated tunnel may inspect another
    /// client's SAS. Never disclose the claim code or its commitment.
    pub fn owner_pending_device(
        &self,
        client: &str,
        epoch: u64,
        key: &str,
        op_id: &str,
    ) -> Result<serde_json::Value, PairingError> {
        let inner = self.lock();
        self.ticket_owner(&inner, client, epoch, key)?;
        let op = inner
            .file
            .pending_device_keys
            .iter()
            .find(|op| op.op_id == op_id)
            .ok_or(PairingError::UnknownOperation)?;
        self.owner_device_view(&inner, client, epoch, key, op)
    }

    /// Discover live SAS requests without transferring operation ids between devices.
    pub fn owner_pending_devices(
        &self,
        client: &str,
        epoch: u64,
        key: &str,
    ) -> Result<Vec<serde_json::Value>, PairingError> {
        let inner = self.lock();
        self.ticket_owner(&inner, client, epoch, key)?;
        Ok(inner
            .file
            .pending_device_keys
            .iter()
            .filter_map(|op| self.owner_device_view(&inner, client, epoch, key, op).ok())
            .collect())
    }
    fn owner_device_view(
        &self,
        inner: &Inner,
        client: &str,
        epoch: u64,
        key: &str,
        op: &device::PendingDeviceKey,
    ) -> Result<serde_json::Value, PairingError> {
        let mut view = pending_device_view(inner, op)?;
        if op.sas_version == Some(2) {
            let p = self.provisional_locked(inner, &op.client_id)?;
            let sas = op.sas.as_ref().ok_or(PairingError::UnknownOperation)?;
            let object = view.as_object_mut().unwrap();
            object.remove("delegation_message");
            object.extend(serde_json::json!({
                "approval":"owner_device", "issuer":p.issuer, "ticket_id":p.ticket_id,
                "node":inner.identity_fingerprint,"approver_client":client,"approver_epoch":epoch,"approver_key":key,
                "nonce":op.delegation_nonce,"client_pubkey":op.client_pubkey,"epoch":op.epoch,"device_key":op.public_key,"device_name":op.name,
                "noise_handshake_hash":hex::encode(sas.binding.handshake_hash),"noise_client_static":hex::encode(sas.binding.client_static),"box_transport_pubkey":hex::encode(sas.binding.box_public_key),
                "sas_digest":sas.digest.to_hex().to_string(),
                "approval_message":if sas.confirmed {Some(Self::second_message_locked(inner,client,epoch,key,op,false)?)} else {None},
                "reject_message":if sas.confirmed {Some(Self::second_message_locked(inner,client,epoch,key,op,true)?)} else {None}
            }).as_object().unwrap().clone());
        }
        Ok(view)
    }
}

fn pending_device_view(
    inner: &Inner,
    op: &device::PendingDeviceKey,
) -> Result<serde_json::Value, PairingError> {
    let sas = op
        .sas
        .as_ref()
        .filter(|_| matches!(op.sas_version, Some(1) | Some(2)))
        .ok_or(PairingError::BadProof)?;
    if op.expires_at <= chrono::Utc::now().timestamp()
        || sas.created_at.elapsed() >= Duration::from_secs(op.sas_ttl_secs() as u64)
    {
        return Err(PairingError::Expired);
    }
    if !inner.file.clients.iter().any(|c| {
        c.client_id == op.client_id && c.epoch == op.epoch && c.client_pubkey == op.client_pubkey
    }) {
        return Err(PairingError::BadProof);
    }
    Ok(serde_json::json!({
        "op_id": op.op_id, "client_id": op.client_id, "name": op.name,
        "public_key": op.public_key, "expires_at": op.expires_at,
        "sas_version": op.sas_version, "box_nonce": hex::encode(sas.nonce),
        "sas_words": crate::sas::words(&sas.digest),
        "delegation_message": sas.confirmed.then(|| device::delegation_message(&inner.identity_fingerprint, op)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_owner_ticket_is_burned_on_expiry_or_invalid_approver() {
        for expired in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let svc = PairingService::open(dir.path(), "node".into(), false).unwrap();
            let code = "owner_legacy";
            let hash = blake3::hash(code.as_bytes()).to_hex().to_string();
            svc.lock().owner_tickets.tickets.insert(
                hash.clone(),
                Ticket {
                    client_id: "revoked".into(),
                    key_id: "revoked".into(),
                    epoch: 1,
                    deadline: if expired {
                        Instant::now() - TTL
                    } else {
                        Instant::now() + TTL
                    },
                    second_device: false,
                },
            );
            let first = svc.consume_owner_ticket(code, "phone", "", &[2; 32]);
            if expired {
                assert!(matches!(first, Err(PairingError::Expired)));
            } else {
                assert!(first.is_err());
            }
            assert!(!svc.lock().owner_tickets.tickets.contains_key(&hash));
            assert!(matches!(
                svc.consume_owner_ticket(code, "phone", "", &[2; 32]),
                Err(PairingError::BadProof)
            ));
        }
    }

    // Discovery must stop exposing a ceremony when either lifetime expires or
    // the target pairing changes, even if the in-memory SAS survived.
    #[test]
    fn pending_view_filters_expired_and_changed_target() {
        let dir = tempfile::tempdir().unwrap();
        let svc = PairingService::open(dir.path(), "node".into(), false).unwrap();
        let client = svc
            .create_ticket_remote_pairing(
                "phone",
                &hex::encode(
                    ed25519_dalek::SigningKey::from_bytes(&[1; 32])
                        .verifying_key()
                        .to_bytes(),
                ),
                &[2; 32],
            )
            .unwrap();
        let mut op = device::PendingDeviceKey {
            op_id: "op".into(),
            client_id: client.client_id,
            client_name: "phone".into(),
            epoch: client.epoch,
            client_pubkey: client.client_pubkey,
            key_id: "key".into(),
            public_key: "public".into(),
            name: "phone".into(),
            expires_at: chrono::Utc::now().timestamp() + 900,
            created_at: 0,
            delegation_nonce: "nonce".into(),
            sas_version: Some(1),
            sas: Some(device::DeviceSas {
                nonce: [3; 16],
                digest: blake3::hash(b"sas"),
                confirmed: false,
                binding: crate::sas::NoiseBinding {
                    handshake_hash: [4; 32],
                    box_public_key: [5; 32],
                    client_static: [2; 32],
                },
                created_at: std::time::Instant::now(),
            }),
        };
        let inner = svc.lock();
        assert!(pending_device_view(&inner, &op).is_ok());
        op.expires_at = chrono::Utc::now().timestamp();
        assert!(pending_device_view(&inner, &op).is_err());
        op.expires_at += 900;
        op.sas.as_mut().unwrap().created_at -= Duration::from_secs(900);
        assert!(pending_device_view(&inner, &op).is_err());
        op.sas.as_mut().unwrap().created_at = std::time::Instant::now();
        op.epoch += 1;
        assert!(pending_device_view(&inner, &op).is_err());
        op.epoch -= 1;
        assert!(pending_device_view(&inner, &op).is_ok());
    }
}
