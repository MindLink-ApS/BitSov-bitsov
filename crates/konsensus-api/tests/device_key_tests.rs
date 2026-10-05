//! Paired device keys and device-signed relation intents (relation ladder
//! steps 1–2), and approvals that survive a restart (step 3).
//!
//! A `ring` P-256 key stands in for the Secure Enclave key: the node sees the
//! same thing either way, a public key and DER signatures over exact bytes.
//! Every refusal asserts its **effect** (no grant, no key, no debit) and sits
//! beside a positive control.

use std::sync::Arc;

#[path = "common/owner_console.rs"]
mod owner_console;
use owner_console::OwnerConsole;

use ed25519_dalek::{Signer, SigningKey};
use rand::RngCore;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use konsensus_api::auth::Scope;
use konsensus_api::control::{self, ControlContext, ControlRequest, ControlResponse};
use konsensus_api::pairing::device::{self, intent_message, owner_approval_message, registration_message};
use konsensus_api::pairing::PendingDeviceKey;
use konsensus_api::pairing::{
    self, DeviceKeyStatus, PairedClient, PairingError, PairingService, RelationIntent,
};
use konsensus_api::spend_budget::{BudgetRefusal, Charge};
use konsensus_core::OwnerApprovalKey;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PEER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn fingerprint() -> String {
    let id = konsensus_core::NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
    pairing::identity_fingerprint(&id.node_id().to_hex())
}

fn owner_key() -> OwnerApprovalKey {
    OwnerApprovalKey::from_mnemonic(MNEMONIC, "", &[9u8; 32]).unwrap()
}

/// What the owner CLI signs for a pending registration.
fn owner_sig(op: &PendingDeviceKey) -> String {
    let msg = owner_approval_message(&fingerprint(), &op.client_pubkey, op.epoch, &op.public_key);
    hex::encode(owner_key().sign(msg.as_bytes()).to_bytes())
}

fn owner_run(dir: &std::path::Path) -> (Arc<PairingService>, OwnerConsole) {
    let console = OwnerConsole::default();
    let service = Arc::new(
        PairingService::open(dir, fingerprint(), true)
            .unwrap()
            .with_owner_approval_key(owner_key().verifying_key())
            .with_owner_console(Box::new(console.clone()))
            .without_stdout_code(),
    );
    (service, console)
}

fn pair(service: &PairingService, seed: u8) -> (PairedClient, SigningKey) {
    let key = SigningKey::from_bytes(&[seed; 32]);
    let pubkey = hex::encode(key.verifying_key().to_bytes());
    service.open_pairing_window(std::time::Duration::from_secs(60));
    let outcome = service.request_pairing("desktop app", &pubkey).unwrap();
    let challenge =
        std::fs::read(service.dir().join(format!("challenge-{}", outcome.pair_id))).unwrap();
    let msg = PairingService::proof_message(&outcome.pair_id, &pubkey, &challenge);
    let sig = hex::encode(key.sign(&msg).to_bytes());
    let client = service
        .confirm_pairing(&outcome.pair_id, &sig, pairing::default_pairing_scopes())
        .unwrap();
    (client, key)
}

fn ctx(service: &Arc<PairingService>, dir: &std::path::Path) -> ControlContext {
    ControlContext {
        service: Arc::clone(service),
        identity_fingerprint: fingerprint(),
        data_dir: dir.to_path_buf(),
        mnemonic_path: dir.join("mnemonic.txt"),
        replacement_guard: control::ReplacementGuard {
            layout: konsensus_api::bootstrap::DataDirLayout::new(dir),
            uses_identity_derived_keys: false,
            has_identity_passphrase: false,
        },
    }
}

/// The device: a P-256 key that signs exact bytes (the Secure Enclave's role).
struct Device {
    key: EcdsaKeyPair,
}

impl Device {
    fn new() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        Self {
            key: EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                .unwrap(),
        }
    }
    fn public_hex(&self) -> String {
        hex::encode(self.key.public_key().as_ref())
    }
    fn sign(&self, msg: &str) -> String {
        let rng = ring::rand::SystemRandom::new();
        hex::encode(self.key.sign(&rng, msg.as_bytes()).unwrap().as_ref())
    }
    fn proof(&self, client_id: &str) -> String {
        self.sign(&registration_message(&fingerprint(), client_id, &self.public_hex()))
    }
}

fn nonce() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

fn intent(key_id: &str, peer: &str, budget_msat: u64, per_act_max_msat: u64) -> RelationIntent {
    RelationIntent {
        device_key_id: key_id.to_string(),
        peer: peer.to_string(),
        level: device::LEVEL_CONTACT,
        budget_msat,
        per_act_max_msat,
        window_secs: 86_400,
        issued_at: chrono::Utc::now().timestamp(),
        nonce: nonce(),
    }
}

/// Pair, request a device key and have the owner approve it with the code.
fn registered(
    dir: &std::path::Path,
) -> (Arc<PairingService>, OwnerConsole, PairedClient, Device, String) {
    let (service, console) = owner_run(dir);
    let (client, _) = pair(&service, 1);
    let device = Device::new();
    let op = service
        .request_device_key(&client.client_id, &device.public_hex(), "Rasmus's MacBook", &device.proof(&client.client_id))
        .unwrap();
    let key = service
        .approve_device_key(&op.op_id, &console.owner_code(&op.op_id), &owner_sig(&op))
        .unwrap();
    (service, console, client, device, key.key_id)
}

fn charge(recipient: &str, msat: u64) -> Vec<Charge> {
    vec![Charge { recipient: recipient.to_string(), amount_msat: msat }]
}

// ─── Step 1: registration ──────────────────────────────────────────

#[test]
fn a_device_key_is_registered_only_with_proof_and_the_owner_code() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run(tmp.path());
    let (client, _) = pair(&service, 1);
    let device = Device::new();
    let other = Device::new();

    // A key the client does not hold cannot even be requested.
    let err = service
        .request_device_key(&client.client_id, &device.public_hex(), "mac", &other.proof(&client.client_id))
        .unwrap_err();
    assert!(matches!(err, PairingError::BadProof), "{err}");
    // A proof made for another pairing does not transfer.
    let err = service
        .request_device_key(&client.client_id, &device.public_hex(), "mac", &device.proof("someone-else"))
        .unwrap_err();
    assert!(matches!(err, PairingError::BadProof), "{err}");
    assert!(service.pending_device_keys().is_empty());

    let op = service
        .request_device_key(&client.client_id, &device.public_hex(), "mac", &device.proof(&client.client_id))
        .unwrap();
    assert_eq!(service.device_key_status(&client.client_id, &op.op_id), DeviceKeyStatus::Pending);
    // The owner console names the device command and shows the fingerprint.
    let text = console.text();
    assert!(text.contains(&format!("konsensus device approve --op {}", op.op_id)), "{text}");
    assert!(text.contains(&format!("REGISTER DEVICE {} TO {}", op.key_id, op.op_id)), "{text}");

    // Wrong code: nothing registered.
    let err = service.approve_device_key(&op.op_id, "AAAA-AAAA", &owner_sig(&op)).unwrap_err();
    assert!(matches!(err, PairingError::WrongOwnerCode(_)), "{err}");
    assert!(service.device_keys().is_empty());

    // POSITIVE CONTROL: the owner's code registers it, once.
    let key = service
        .approve_device_key(&op.op_id, &console.owner_code(&op.op_id), &owner_sig(&op))
        .unwrap();
    assert_eq!(key.client_id, client.client_id);
    assert_eq!(service.device_key_status(&client.client_id, &op.op_id), DeviceKeyStatus::Registered);
    assert_eq!(service.device_keys_for(&client.client_id).len(), 1);
    // Registering the same key again is refused.
    let err = service
        .request_device_key(&client.client_id, &device.public_hex(), "mac", &device.proof(&client.client_id))
        .unwrap_err();
    assert!(matches!(err, PairingError::Malformed(_)), "{err}");
}

#[test]
fn a_node_without_an_owner_channel_registers_no_device_key() {
    let tmp = tempfile::tempdir().unwrap();
    let service = PairingService::open(tmp.path(), fingerprint(), false)
        .unwrap()
        .without_stdout_code();
    let (client, _) = pair(&service, 1);
    let device = Device::new();
    let err = service
        .request_device_key(&client.client_id, &device.public_hex(), "mac", &device.proof(&client.client_id))
        .unwrap_err();
    assert!(matches!(err, PairingError::OwnerChannelUnavailable), "{err}");
}

#[test]
fn malformed_keys_and_names_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _) = owner_run(tmp.path());
    let (client, _) = pair(&service, 1);
    let device = Device::new();
    let proof = device.proof(&client.client_id);
    for bad in ["04", "zz", &format!("02{}", "11".repeat(32))] {
        let err = service.request_device_key(&client.client_id, bad, "mac", &proof).unwrap_err();
        assert!(matches!(err, PairingError::Malformed(_)), "{bad}: {err}");
    }
    for name in ["", "a\u{202E}b", "line\nbreak", &"x".repeat(65)] {
        let err = service
            .request_device_key(&client.client_id, &device.public_hex(), name, &proof)
            .unwrap_err();
        assert!(matches!(err, PairingError::Malformed(_)), "{name:?}: {err}");
    }
}

// ─── Step 2: signed relation intents ───────────────────────────────

#[test]
fn a_signed_intent_opens_a_recipient_bound_envelope() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, client, device, key_id) = registered(tmp.path());
    let i = intent(&key_id, PEER, 200_000, 20_000);
    let sig = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    let view = service
        .apply_relation_intent(&client.client_id, client.epoch, &i, &sig)
        .unwrap();
    assert!(view.recipients_only);
    assert_eq!(view.per_recipient_msat.get(PEER), Some(&200_000));
    assert_eq!(view.per_act_max_by_recipient.get(PEER), Some(&20_000));

    // The pairing's token now carries spend.
    let key = SigningKey::from_bytes(&[1; 32]);
    let challenge = service.issue_token_challenge(&client.client_id).unwrap();
    let sig_tok = hex::encode(key.sign(challenge.as_bytes()).to_bytes());
    let issued = service
        .issue_token("node", "test-secret-at-least-32-bytes-long!", &client.client_id, &challenge, &sig_tok)
        .unwrap();
    assert!(issued.scopes.contains(&Scope::Spend));

    // Within the envelope: paid. Above the per-act max, another peer, or
    // past the budget: refused before anything is debited.
    service.reserve_spend(&client.client_id, client.epoch, charge(PEER, 20_000)).unwrap();
    let per_act = service.reserve_spend(&client.client_id, client.epoch, charge(PEER, 20_001)).unwrap_err();
    assert!(matches!(per_act, BudgetRefusal::PerCall { max_msat: 20_000 }), "{per_act:?}");
    let other = service.reserve_spend(&client.client_id, client.epoch, charge(OTHER, 1)).unwrap_err();
    assert!(matches!(other, BudgetRefusal::Recipient { .. }), "{other:?}");
    for _ in 0..9 {
        service.reserve_spend(&client.client_id, client.epoch, charge(PEER, 20_000)).unwrap();
    }
    let spent = service.reserve_spend(&client.client_id, client.epoch, charge(PEER, 1)).unwrap_err();
    assert!(matches!(spent, BudgetRefusal::Recipient { .. } | BudgetRefusal::Total { .. }), "{spent:?}");
    let used = service.grant_view_for(&client.client_id).unwrap().used_by_recipient[PEER];
    assert_eq!(used, 200_000, "exactly the envelope, never more");

    // A new tap renews the envelope on top of what was used.
    let again = intent(&key_id, PEER, 50_000, 20_000);
    let sig = device.sign(&intent_message(&fingerprint(), &client.client_id, &again));
    service.apply_relation_intent(&client.client_id, client.epoch, &again, &sig).unwrap();
    service.reserve_spend(&client.client_id, client.epoch, charge(PEER, 20_000)).unwrap();
}

#[test]
fn a_second_peer_gets_its_own_envelope_without_touching_the_first() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, client, device, key_id) = registered(tmp.path());
    for (peer, budget) in [(PEER, 100_000), (OTHER, 30_000)] {
        let i = intent(&key_id, peer, budget, 10_000);
        let sig = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
        service.apply_relation_intent(&client.client_id, client.epoch, &i, &sig).unwrap();
    }
    let view = service.grant_view_for(&client.client_id).unwrap();
    assert_eq!(view.budget_msat, 130_000);
    assert_eq!(view.per_recipient_msat[PEER], 100_000);
    assert_eq!(view.per_recipient_msat[OTHER], 30_000);
    // A room act paying both, each within its own per-act max, is one call.
    service
        .reserve_spend(&client.client_id, client.epoch, vec![
            Charge { recipient: PEER.into(), amount_msat: 10_000 },
            Charge { recipient: OTHER.into(), amount_msat: 10_000 },
        ])
        .unwrap();
}

#[test]
fn a_tampered_replayed_stale_or_misbound_intent_writes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, client, device, key_id) = registered(tmp.path());
    let fp = fingerprint();
    let no_grant = |service: &PairingService| assert!(service.grant_view_for(&client.client_id).is_none());

    // Tampered terms: signed 1,000, sent 100,000.
    let signed = intent(&key_id, PEER, 1_000, 1_000);
    let sig = device.sign(&intent_message(&fp, &client.client_id, &signed));
    let tampered = RelationIntent { budget_msat: 100_000, per_act_max_msat: 100_000, ..signed.clone() };
    let err = service.apply_relation_intent(&client.client_id, client.epoch, &tampered, &sig).unwrap_err();
    assert!(matches!(err, PairingError::BadProof), "{err}");
    // Another peer under the same signature.
    let moved = RelationIntent { peer: OTHER.into(), ..signed.clone() };
    assert!(matches!(
        service.apply_relation_intent(&client.client_id, client.epoch, &moved, &sig).unwrap_err(),
        PairingError::BadProof
    ));
    // Signed for another node or another pairing.
    for (node, cid) in [("0".repeat(64), client.client_id.clone()), (fp.clone(), "other-client".into())] {
        let s = device.sign(&intent_message(&node, &cid, &signed));
        assert!(matches!(
            service.apply_relation_intent(&client.client_id, client.epoch, &signed, &s).unwrap_err(),
            PairingError::BadProof
        ));
    }
    // A key that is not registered, even with a valid signature of its own.
    let stranger = Device::new();
    let foreign = RelationIntent { device_key_id: device::key_id_for(&hex::decode(stranger.public_hex()).unwrap()), ..signed.clone() };
    let s = stranger.sign(&intent_message(&fp, &client.client_id, &foreign));
    assert!(matches!(
        service.apply_relation_intent(&client.client_id, client.epoch, &foreign, &s).unwrap_err(),
        PairingError::NotGrantable(_)
    ));
    // Too old, or from the future.
    for skew in [-(device::INTENT_MAX_SKEW_SECS + 5), device::INTENT_MAX_SKEW_SECS + 5] {
        let stale = RelationIntent { issued_at: chrono::Utc::now().timestamp() + skew, nonce: nonce(), ..signed.clone() };
        let s = device.sign(&intent_message(&fp, &client.client_id, &stale));
        assert!(matches!(
            service.apply_relation_intent(&client.client_id, client.epoch, &stale, &s).unwrap_err(),
            PairingError::Expired
        ));
    }
    // Out of bounds, even when signed.
    for bad in [
        RelationIntent { level: 0, ..signed.clone() },
        RelationIntent { level: 2, ..signed.clone() },
        RelationIntent { window_secs: 86_401, ..signed.clone() },
        RelationIntent { window_secs: 59, ..signed.clone() },
        RelationIntent { budget_msat: device::RELATION_MAX_BUDGET_MSAT + 1, ..signed.clone() },
        RelationIntent { per_act_max_msat: 1_001, ..signed.clone() },
        RelationIntent { budget_msat: 0, ..signed.clone() },
        RelationIntent { peer: PEER.to_uppercase(), ..signed.clone() },
        RelationIntent { nonce: "short".into(), ..signed.clone() },
    ] {
        let s = device.sign(&intent_message(&fp, &client.client_id, &bad));
        let err = service.apply_relation_intent(&client.client_id, client.epoch, &bad, &s).unwrap_err();
        assert!(matches!(err, PairingError::Malformed(_) | PairingError::NotGrantable(_)), "{bad:?}: {err}");
    }
    // A stale token epoch.
    assert!(matches!(
        service.apply_relation_intent(&client.client_id, client.epoch + 1, &signed, &sig).unwrap_err(),
        PairingError::PairingInvalid(_)
    ));
    no_grant(&service);

    // POSITIVE CONTROL, then a replay of the same signed intent.
    service.apply_relation_intent(&client.client_id, client.epoch, &signed, &sig).unwrap();
    let err = service.apply_relation_intent(&client.client_id, client.epoch, &signed, &sig).unwrap_err();
    assert!(matches!(err, PairingError::BadProof), "a replay must not renew the envelope: {err}");
    assert_eq!(service.grant_view_for(&client.client_id).unwrap().budget_msat, 1_000);

    // The replay record is durable: a restart does not forget it.
    drop(service);
    let (service, _) = owner_run(tmp.path());
    let err = service.apply_relation_intent(&client.client_id, client.epoch, &signed, &sig).unwrap_err();
    assert!(matches!(err, PairingError::BadProof), "{err}");
}

#[test]
fn intents_are_rate_limited_per_client() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, client, device, key_id) = registered(tmp.path());
    for _ in 0..device::RELATION_INTENTS_PER_HOUR {
        let i = intent(&key_id, PEER, 1_000, 1_000);
        let s = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
        service.apply_relation_intent(&client.client_id, client.epoch, &i, &s).unwrap();
    }
    let i = intent(&key_id, PEER, 1_000, 1_000);
    let s = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    let err = service.apply_relation_intent(&client.client_id, client.epoch, &i, &s).unwrap_err();
    assert!(matches!(err, PairingError::TooManyPending), "{err}");
}

#[test]
fn revoking_the_key_or_the_pairing_ends_the_envelopes() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, client, device, key_id) = registered(tmp.path());
    let open = |service: &PairingService| {
        let i = intent(&key_id, PEER, 10_000, 10_000);
        let s = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
        service.apply_relation_intent(&client.client_id, client.epoch, &i, &s)
    };
    open(&service).unwrap();
    service.revoke_device_key(&key_id, Some("someone-else")).unwrap_err();
    service.revoke_device_key(&key_id, Some(&client.client_id)).unwrap();
    assert!(matches!(
        service.reserve_spend(&client.client_id, client.epoch, charge(PEER, 1)).unwrap_err(),
        BudgetRefusal::NoGrant
    ));
    assert!(matches!(open(&service).unwrap_err(), PairingError::NotGrantable(_)));

    // An epoch bump retires every key of the pairing.
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, client, device, key_id) = registered(tmp.path());
    service.bump_epoch(&client.client_id).unwrap();
    let i = intent(&key_id, PEER, 10_000, 10_000);
    let s = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    let err = service.apply_relation_intent(&client.client_id, client.epoch + 1, &i, &s).unwrap_err();
    assert!(matches!(err, PairingError::NotGrantable(_)), "{err}");
    assert!(service.device_keys_for(&client.client_id).is_empty());
}

#[test]
fn a_relation_grant_replaces_a_console_budget_window() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console, client, device, key_id) = registered(tmp.path());
    let op = service.create_elevation_request(&client.client_id, vec![Scope::Spend]).unwrap();
    service
        .grant_elevation(&op.op_id, &console.owner_code(&op.op_id), konsensus_api::spend_budget::GrantTerms::new(1_000_000))
        .unwrap();
    // The console grant pays anyone within its total...
    service.reserve_spend(&client.client_id, client.epoch, charge(OTHER, 1_000)).unwrap();
    // ...until the device opens an envelope: one budget per client, recipient-bound.
    let i = intent(&key_id, PEER, 10_000, 10_000);
    let s = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    service.apply_relation_intent(&client.client_id, client.epoch, &i, &s).unwrap();
    assert!(service.reserve_spend(&client.client_id, client.epoch, charge(OTHER, 1_000)).is_err());
    service.reserve_spend(&client.client_id, client.epoch, charge(PEER, 1_000)).unwrap();
}

#[test]
fn http_cannot_reach_the_owner_approval_and_the_signature_is_the_only_way_in() {
    // Structural: see handlers/device_routes.rs tests. Here: the control
    // socket is where a device key is approved.
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run(tmp.path());
    let (client, _) = pair(&service, 1);
    let device = Device::new();
    let op = service
        .request_device_key(&client.client_id, &device.public_hex(), "mac", &device.proof(&client.client_id))
        .unwrap();
    let ctx = ctx(&service, tmp.path());
    match control::handle(&ctx, ControlRequest::Describe { op_id: op.op_id.clone() }) {
        ControlResponse::Describe { summary, .. } => {
            assert!(summary.contains(&device::key_fingerprint(&op.key_id)), "{summary}");
            assert!(!summary.contains(&console.owner_code(&op.op_id)));
        }
        other => panic!("{other:?}"),
    }
    let reply = control::handle(
        &ctx,
        ControlRequest::ApproveDeviceKey { op_id: op.op_id.clone(), confirmation: console.owner_code(&op.op_id), owner_signature: owner_sig(&op) },
    );
    assert!(matches!(reply, ControlResponse::Ok { .. }), "{reply:?}");
    match control::handle(&ctx, ControlRequest::Status) {
        ControlResponse::Status { device_keys, .. } => assert_eq!(device_keys.len(), 1),
        other => panic!("{other:?}"),
    }
}

// ─── Step 3: approvals survive a restart; the client can cancel ────

#[test]
fn a_restart_reissues_codes_instead_of_losing_the_approval() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run(tmp.path());
    let (client, _) = pair(&service, 1);
    let device = Device::new();
    let reg = service
        .request_device_key(&client.client_id, &device.public_hex(), "mac", &device.proof(&client.client_id))
        .unwrap();
    let grant = service.create_elevation_request(&client.client_id, vec![Scope::Spend]).unwrap();
    let old_reg_code = console.owner_code(&reg.op_id);
    let old_grant_code = console.owner_code(&grant.op_id);
    drop(service);

    let (service, console) = owner_run(tmp.path());
    // Before re-issue the codes are gone: the client would see "lost".
    assert_eq!(service.device_key_status(&client.client_id, &reg.op_id), DeviceKeyStatus::Lost);
    assert_eq!(service.reissue_owner_challenges().unwrap(), 2);
    assert_eq!(service.device_key_status(&client.client_id, &reg.op_id), DeviceKeyStatus::Pending);
    assert_eq!(service.elevation_status(&client.client_id, &grant.op_id).unwrap(), pairing::ElevationStatus::Pending);

    // The old codes do not carry over; the new ones approve.
    assert!(service.approve_device_key(&reg.op_id, &old_reg_code, &owner_sig(&reg)).is_err());
    service.approve_device_key(&reg.op_id, &console.owner_code(&reg.op_id), &owner_sig(&reg)).unwrap();
    assert!(service
        .grant_elevation(&grant.op_id, &old_grant_code, konsensus_api::spend_budget::GrantTerms::new(1_000))
        .is_err());
    service
        .grant_elevation(&grant.op_id, &console.owner_code(&grant.op_id), konsensus_api::spend_budget::GrantTerms::new(1_000))
        .unwrap();
    // Re-issuing twice prints nothing new for a live code.
    assert_eq!(service.reissue_owner_challenges().unwrap(), 0);
}

#[test]
fn a_client_cancels_only_its_own_pending_request() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run(tmp.path());
    let (a, _) = pair(&service, 1);
    let (b, _) = pair(&service, 2);
    let op = service.create_elevation_request(&a.client_id, vec![Scope::Spend]).unwrap();
    let code = console.owner_code(&op.op_id);
    assert!(matches!(service.cancel_pending(&b.client_id, &op.op_id), Err(PairingError::UnknownOperation)));
    service.cancel_pending(&a.client_id, &op.op_id).unwrap();
    assert!(matches!(service.elevation_status(&a.client_id, &op.op_id), Err(PairingError::UnknownOperation)));
    assert!(service
        .grant_elevation(&op.op_id, &code, konsensus_api::spend_budget::GrantTerms::new(1_000))
        .is_err());
    assert!(service.reload_from_disk().unwrap().grants.is_empty());
}

#[test]
fn a_rotated_pairing_can_register_the_same_device_again() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console, client, device, _) = registered(tmp.path());
    let old_key = SigningKey::from_bytes(&[1; 32]);
    let new_key = SigningKey::from_bytes(&[7; 32]);
    let new_pub = hex::encode(new_key.verifying_key().to_bytes());
    let msg = format!("bitsov-pair-rotate-v1:{}:{new_pub}", client.client_id);
    let sig = hex::encode(old_key.sign(msg.as_bytes()).to_bytes());
    let rotated = service.rotate_client_key(&client.client_id, &new_pub, &sig).unwrap();
    assert!(service.device_keys().is_empty(), "keys of the old pairing id are retired");
    let op = service
        .request_device_key(&rotated.client_id, &device.public_hex(), "mac", &device.proof(&rotated.client_id))
        .unwrap();
    service.approve_device_key(&op.op_id, &console.owner_code(&op.op_id), &owner_sig(&op)).unwrap();
}

#[test]
fn registration_requests_are_rate_limited_per_client() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _) = owner_run(tmp.path());
    let (client, _) = pair(&service, 1);
    let (a, b) = (Device::new(), Device::new());
    service.request_device_key(&client.client_id, &a.public_hex(), "mac", &a.proof(&client.client_id)).unwrap();
    let err = service
        .request_device_key(&client.client_id, &b.public_hex(), "mac", &b.proof(&client.client_id))
        .unwrap_err();
    assert!(matches!(err, PairingError::TooManyPending), "{err}");
}

#[test]
fn an_absurd_issued_at_is_refused_not_a_panic() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, client, device, key_id) = registered(tmp.path());
    let i = RelationIntent { issued_at: i64::MIN, ..intent(&key_id, PEER, 1_000, 1_000) };
    let s = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    assert!(matches!(service.apply_relation_intent(&client.client_id, client.epoch, &i, &s), Err(PairingError::Expired)));
}

// ─── The owner-approval key (identity model v2) ────────────────────

#[test]
fn registration_needs_the_owner_key_signature_over_this_exact_tuple() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, console) = owner_run(tmp.path());
    let (client, _) = pair(&service, 1);
    let device = Device::new();
    let op = service
        .request_device_key(&client.client_id, &device.public_hex(), "mac", &device.proof(&client.client_id))
        .unwrap();
    let code = console.owner_code(&op.op_id);
    let sign = |key: &OwnerApprovalKey, msg: String| hex::encode(key.sign(msg.as_bytes()).to_bytes());
    let other_owner = OwnerApprovalKey::from_mnemonic(MNEMONIC, "", &[1u8; 32]).unwrap();
    let other_device = Device::new();
    for bad in [
        String::new(),
        "zz".into(),
        // Another seed's owner key.
        sign(&other_owner, owner_approval_message(&fingerprint(), &op.client_pubkey, op.epoch, &op.public_key)),
        // The right key over a different device, epoch, pairing or node.
        sign(&owner_key(), owner_approval_message(&fingerprint(), &op.client_pubkey, op.epoch, &other_device.public_hex())),
        sign(&owner_key(), owner_approval_message(&fingerprint(), &op.client_pubkey, op.epoch + 1, &op.public_key)),
        sign(&owner_key(), owner_approval_message(&fingerprint(), &"11".repeat(32), op.epoch, &op.public_key)),
        sign(&owner_key(), owner_approval_message(&"0".repeat(32), &op.client_pubkey, op.epoch, &op.public_key)),
    ] {
        let err = service.approve_device_key(&op.op_id, &code, &bad).unwrap_err();
        assert!(matches!(err, PairingError::BadProof), "{err}");
    }
    assert!(service.device_keys().is_empty());
    // A bad signature spends none of the owner's code attempts.
    service.approve_device_key(&op.op_id, &code, &owner_sig(&op)).unwrap();
    assert_eq!(service.device_keys()[0].owner_approval, owner_sig(&op));
}

#[test]
fn a_device_key_written_into_data_dir_authorizes_nothing() {
    // Write access to data_dir is no longer the root of the chain: a record
    // added to the pairing store without the owner key's signature (or with
    // a signature for another key) is refused on every use.
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, client, device, key_id) = registered(tmp.path());
    let attacker = Device::new();
    let attacker_id = device::key_id_for(&hex::decode(attacker.public_hex()).unwrap());
    drop(service);
    let path = tmp.path().join("pairing").join("clients.json");
    let mut file: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let genuine = file["device_keys"][0].clone();
    for approval in [String::new(), genuine["owner_approval"].as_str().unwrap().to_string()] {
        let mut forged = genuine.clone();
        forged["key_id"] = attacker_id.clone().into();
        forged["public_key"] = attacker.public_hex().into();
        forged["owner_approval"] = approval.into();
        file["device_keys"].as_array_mut().unwrap().push(forged);
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&file).unwrap()).unwrap();
    let (service, _) = owner_run(tmp.path());
    let i = intent(&attacker_id, PEER, 10_000, 10_000);
    let s = attacker.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    let err = service.apply_relation_intent(&client.client_id, client.epoch, &i, &s).unwrap_err();
    assert!(matches!(err, PairingError::NotGrantable(_)), "{err}");
    assert!(service.grant_view_for(&client.client_id).is_none());

    // POSITIVE CONTROL: the owner-approved key still works after the reload.
    let i = intent(&key_id, PEER, 10_000, 10_000);
    let s = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    service.apply_relation_intent(&client.client_id, client.epoch, &i, &s).unwrap();
}

#[test]
fn a_node_started_without_an_owner_key_honours_no_device_key() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, _, client, device, key_id) = registered(tmp.path());
    // Same data_dir, but the node was not given the owner-approval public key.
    let service = PairingService::open(tmp.path(), fingerprint(), true).unwrap().without_stdout_code();
    let i = intent(&key_id, PEER, 10_000, 10_000);
    let s = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    assert!(matches!(
        service.apply_relation_intent(&client.client_id, client.epoch, &i, &s).unwrap_err(),
        PairingError::DeviceApprovalsDisabled(device::OWNER_KEY_UNAVAILABLE)
    ));
}

#[test]
fn a_node_running_from_a_plaintext_seed_disables_device_authority_node_wide() {
    // Codex #147 delta repro: a same-user process reads the plaintext seed,
    // derives an owner key and writes a correctly signed device record. With
    // the node started from a plaintext seed, nothing device-signed works.
    let tmp = tempfile::tempdir().unwrap();
    let (_, _, client, device, key_id) = registered(tmp.path());
    let service = PairingService::open(tmp.path(), fingerprint(), true)
        .unwrap()
        .without_stdout_code()
        .with_owner_approval_key(owner_key().verifying_key())
        .with_device_authority_disabled(device::SEED_NOT_ENCRYPTED);
    assert_eq!(service.device_authority_off(), Some(device::SEED_NOT_ENCRYPTED));
    let i = intent(&key_id, PEER, 10_000, 10_000);
    let s = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    let err = service.apply_relation_intent(&client.client_id, client.epoch, &i, &s).unwrap_err();
    assert!(matches!(err, PairingError::DeviceApprovalsDisabled(device::SEED_NOT_ENCRYPTED)), "{err}");
    assert!(err.to_string().contains("Encrypt your recovery phrase to enable Touch ID approvals"), "{err}");
    assert!(service.grant_view_for(&client.client_id).is_none());
    // Registration is off too, before any proof is even checked.
    let other = Device::new();
    let err = service
        .request_device_key(&client.client_id, &other.public_hex(), "mac", &other.proof(&client.client_id))
        .unwrap_err();
    assert!(matches!(err, PairingError::DeviceApprovalsDisabled(device::SEED_NOT_ENCRYPTED)), "{err}");
    // POSITIVE CONTROL: the same state with the node started from the encrypted seed.
    let (service, _) = owner_run(tmp.path());
    service
        .apply_relation_intent(&client.client_id, client.epoch, &i, &s)
        .unwrap();
}

fn local_run(dir: &std::path::Path) -> PairingService {
    PairingService::open(dir, fingerprint(), false)
        .unwrap()
        .with_local_owner_device()
        .with_owner_approval_key(owner_key().verifying_key())
        .without_stdout_code()
}

fn token_scopes(service: &PairingService, client: &PairedClient) -> Vec<Scope> {
    let challenge = service.issue_token_challenge(&client.client_id).unwrap();
    let signature = hex::encode(
        SigningKey::from_bytes(&[1; 32])
            .sign(challenge.as_bytes())
            .to_bytes(),
    );
    service
        .issue_token(
            "node",
            "test-secret-at-least-32-bytes-long!",
            &client.client_id,
            &challenge,
            &signature,
        )
        .unwrap()
        .scopes
}

#[test]
fn local_owner_without_verifier_cannot_spend_stored_device_grants() {
    let tmp = tempfile::tempdir().unwrap();
    let (console, _, client, device, key_id) = registered(tmp.path());
    drop(console);
    let local = local_run(tmp.path());
    let i = intent(&key_id, PEER, 10_000, 1_000);
    let sig = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    local
        .apply_relation_intent(&client.client_id, client.epoch, &i, &sig)
        .unwrap();
    assert!(token_scopes(&local, &client).contains(&Scope::Spend));
    drop(local);

    // Exercise both a missing verifier and one explicitly disabled after installation.
    for disabled in [false, true] {
        let service = PairingService::open(tmp.path(), fingerprint(), false)
            .unwrap()
            .with_local_owner_device()
            .without_stdout_code();
        let service = if disabled {
            service
                .with_owner_approval_key(owner_key().verifying_key())
                .with_device_authority_disabled(device::OWNER_KEY_UNAVAILABLE)
        } else {
            service
        };
        let reservation = service.reserve_spend(&client.client_id, client.epoch, charge(PEER, 1));
        let scopes = token_scopes(&service, &client);
        assert!(
            matches!(reservation, Err(BudgetRefusal::NoGrant)) && !scopes.contains(&Scope::Spend),
            "unavailable verifier must block reservation and spend scope: {reservation:?}, {scopes:?}"
        );
    }
}

#[test]
fn local_owner_accepts_console_enrolled_key_but_restart_without_flag_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let (console, _, client, device, key_id) = registered(tmp.path());
    assert_eq!(console.device_keys()[0].enrolled_by, "console");
    drop(console);
    let local = local_run(tmp.path());
    assert!(!local.owner_control_enabled());
    let i = intent(&key_id, PEER, 10_000, 1_000);
    let sig = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
    local
        .apply_relation_intent(&client.client_id, client.epoch, &i, &sig)
        .unwrap();
    assert!(token_scopes(&local, &client).contains(&Scope::Spend));
    local
        .reserve_spend(&client.client_id, client.epoch, charge(PEER, 1_000))
        .unwrap();
    assert!(matches!(
        local.reserve_spend(&client.client_id, client.epoch, charge(OTHER, 1)),
        Err(BudgetRefusal::Recipient { .. })
    ));
    drop(local);
    let local = local_run(tmp.path());
    assert!(
        local
            .apply_relation_intent(&client.client_id, client.epoch, &i, &sig)
            .is_err(),
        "nonce survives restart"
    );
    drop(local);
    let restarted = PairingService::open(tmp.path(), fingerprint(), false)
        .unwrap()
        .with_device_authority_disabled(device::SEED_PASSWORD_NOT_TYPED)
        .without_stdout_code();
    assert_eq!(
        restarted.device_authority_off(),
        Some(device::SEED_PASSWORD_NOT_TYPED)
    );
    assert!(matches!(
        restarted.apply_relation_intent(&client.client_id, client.epoch, &i, &sig),
        Err(PairingError::OwnerChannelUnavailable)
    ));
    assert!(!token_scopes(&restarted, &client).contains(&Scope::Spend));
    assert!(matches!(
        restarted.reserve_spend(&client.client_id, client.epoch, charge(PEER, 1)),
        Err(BudgetRefusal::NoGrant)
    ));
}

#[test]
fn local_owner_reverifies_approval_client_epoch_and_revocation() {
    for mutation in [
        "owner_approval",
        "client_pubkey",
        "epoch",
        "revoked",
        "legacy",
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (service, _, client, device, key_id) = registered(tmp.path());
        drop(service);
        let path = tmp.path().join("pairing/clients.json");
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        match mutation {
            "owner_approval" => file["device_keys"][0][mutation] = "00".repeat(64).into(),
            "client_pubkey" => file["device_keys"][0][mutation] = "ff".repeat(32).into(),
            "epoch" => file["device_keys"][0][mutation] = (client.epoch + 1).into(),
            "revoked" => file["device_keys"] = serde_json::json!([]),
            "legacy" => {
                file["device_keys"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("enrolled_by");
            }
            _ => unreachable!(),
        }
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        let local = local_run(tmp.path());
        let i = intent(&key_id, PEER, 10_000, 1_000);
        let sig = device.sign(&intent_message(&fingerprint(), &client.client_id, &i));
        let result = local.apply_relation_intent(&client.client_id, client.epoch, &i, &sig);
        if mutation == "legacy" {
            result.unwrap();
            assert_eq!(local.device_keys()[0].enrolled_by, "console");
        } else {
            assert!(
                matches!(result, Err(PairingError::NotGrantable(_))),
                "{mutation}: {result:?}"
            );
            assert!(local.grant_view_for(&client.client_id).is_none());
            assert!(matches!(
                local.reserve_spend(&client.client_id, client.epoch, charge(PEER, 1)),
                Err(BudgetRefusal::NoGrant)
            ));
        }
    }
}

#[test]
fn local_owner_honours_only_recipient_bound_device_grants_from_disk() {
    for (granted_by, recipients_only, allowed) in [
        ("cli", true, false),
        ("device:test", false, false),
        ("device:test", true, true),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let (service, _, client, device, key_id) = registered(tmp.path());
        let i = intent(&key_id, PEER, 10_000, 1_000);
        service
            .apply_relation_intent(
                &client.client_id,
                client.epoch,
                &i,
                &device.sign(&intent_message(&fingerprint(), &client.client_id, &i)),
            )
            .unwrap();
        drop(service);
        let path = tmp.path().join("pairing/clients.json");
        let mut file: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        file["grants"][0]["granted_by"] = granted_by.into();
        file["grants"][0]["budget"]["recipients_only"] = recipients_only.into();
        file["grants"][0]["scopes"] = serde_json::json!(["spend", "front_door"]);
        file["clients"][0]["scopes"] =
            serde_json::json!(["read", "receive", "spend", "front_door"]);
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        let local = local_run(tmp.path());
        let scopes = token_scopes(&local, &client);
        assert_eq!(scopes.contains(&Scope::Spend), allowed);
        assert!(!scopes.contains(&Scope::FrontDoor));
        let result = local.reserve_spend(&client.client_id, client.epoch, charge(PEER, 1));
        if allowed {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(BudgetRefusal::NoGrant)));
        }
        assert_eq!(local.grant_view_for(&client.client_id).is_some(), allowed);
        let disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(disk["grants"][0]["budget"]["used_msat"], u64::from(allowed));
    }
}

#[test]
fn local_owner_cannot_use_console_only_authority() {
    let tmp = tempfile::tempdir().unwrap();
    let (service, _, client, device, _) = registered(tmp.path());
    drop(service);
    let local = local_run(tmp.path());
    assert!(matches!(
        local.request_device_key(
            &client.client_id,
            &device.public_hex(),
            "mac",
            &device.proof(&client.client_id)
        ),
        Err(PairingError::OwnerChannelUnavailable)
    ));
    assert!(matches!(
        local.approve_device_key("op", "code", "sig"),
        Err(PairingError::OwnerChannelUnavailable)
    ));
    assert!(matches!(
        local.create_elevation_request(&client.client_id, vec![Scope::Spend]),
        Err(PairingError::OwnerApprovalUnavailable)
    ));
    assert!(matches!(
        local.grant_elevation(
            "op",
            "code",
            konsensus_api::spend_budget::GrantTerms::new(1000)
        ),
        Err(PairingError::OwnerChannelUnavailable)
    ));
    assert!(matches!(
        local.grant_front_door("op", "code", 60),
        Err(PairingError::OwnerChannelUnavailable)
    ));
    assert!(matches!(
        local.approve_replacement("op", "code"),
        Err(PairingError::OwnerChannelUnavailable)
    ));
    assert!(matches!(
        local.grant_first_contact(&client.client_id, "op", PEER, 1, None),
        Err(BudgetRefusal::NoGrant)
    ));
    assert_eq!(local.reissue_owner_challenges().unwrap(), 0);
    assert!(local.pending_device_keys().is_empty());
    assert!(local.grant_view_for(&client.client_id).is_none());
}
