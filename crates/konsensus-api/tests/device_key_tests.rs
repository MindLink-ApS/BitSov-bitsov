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
use konsensus_api::pairing::device::{self, intent_message, registration_message};
use konsensus_api::pairing::{
    self, DeviceKeyStatus, PairedClient, PairingError, PairingService, RelationIntent,
};
use konsensus_api::spend_budget::{BudgetRefusal, Charge};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const PEER: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn fingerprint() -> String {
    let id = konsensus_core::NodeIdentity::from_mnemonic(MNEMONIC, "").unwrap();
    pairing::identity_fingerprint(&id.node_id().to_hex())
}

fn owner_run(dir: &std::path::Path) -> (Arc<PairingService>, OwnerConsole) {
    let console = OwnerConsole::default();
    let service = Arc::new(
        PairingService::open(dir, fingerprint(), true)
            .unwrap()
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
        .approve_device_key(&op.op_id, &console.owner_code(&op.op_id))
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
    let err = service.approve_device_key(&op.op_id, "AAAA-AAAA").unwrap_err();
    assert!(matches!(err, PairingError::WrongOwnerCode(_)), "{err}");
    assert!(service.device_keys().is_empty());

    // POSITIVE CONTROL: the owner's code registers it, once.
    let key = service
        .approve_device_key(&op.op_id, &console.owner_code(&op.op_id))
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
        ControlRequest::ApproveDeviceKey { op_id: op.op_id.clone(), confirmation: console.owner_code(&op.op_id) },
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
    assert_eq!(service.elevation_status(&grant.op_id), pairing::ElevationStatus::Pending);

    // The old codes do not carry over; the new ones approve.
    assert!(service.approve_device_key(&reg.op_id, &old_reg_code).is_err());
    service.approve_device_key(&reg.op_id, &console.owner_code(&reg.op_id)).unwrap();
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
    assert_eq!(service.elevation_status(&op.op_id), pairing::ElevationStatus::Absent);
    assert!(service
        .grant_elevation(&op.op_id, &code, konsensus_api::spend_budget::GrantTerms::new(1_000))
        .is_err());
    assert!(service.reload_from_disk().unwrap().grants.is_empty());
}
