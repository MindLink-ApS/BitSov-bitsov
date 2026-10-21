//! N-2DEV contract tests. Real P-256 signatures and durable pairing state.
use super::*;
#[path = "../../tests/common/owner_console.rs"]
mod owner_console;
use super::device::{
    key_id_for, owner_approval_message, registration_message, sas_registration_message,
};
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

fn key() -> EcdsaKeyPair {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap()
}
fn sign(k: &EcdsaKeyPair, message: &str) -> String {
    hex::encode(
        k.sign(&ring::rand::SystemRandom::new(), message.as_bytes())
            .unwrap()
            .as_ref(),
    )
}
pub(super) struct Fixture {
    dir: tempfile::TempDir,
    svc: PairingService,
    owner: PairedClient,
    key: EcdsaKeyPair,
    key_id: String,
    console: owner_console::OwnerConsole,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let console = owner_console::OwnerConsole::default();
        let signer = konsensus_core::OwnerApprovalKey::from_seed(&[7; 64], &[9; 32]).unwrap();
        let identity=konsensus_core::NodeIdentity::from_mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "").unwrap();
        let svc = PairingService::open(
            dir.path(),
            identity_fingerprint(&identity.node_id().to_hex()),
            true,
        )
        .unwrap()
        .with_owner_console(Box::new(console.clone()))
        .without_stdout_code()
        .with_local_owner_device()
        .with_second_device_enrollment(true);
        let owner = svc
            .create_ticket_remote_pairing("Mac", &pubkey(1), &[1; 32])
            .unwrap();
        let key = key();
        let public = hex::encode(key.public_key().as_ref());
        let key_id = key_id_for(key.public_key().as_ref());
        let fingerprint = svc.bound_fingerprint();
        svc.lock().file.device_keys.push(DeviceKey {
            key_id: key_id.clone(),
            client_id: owner.client_id.clone(),
            public_key: public.clone(),
            name: "Mac".into(),
            registered_at: 1,
            epoch: owner.epoch,
            client_pubkey: owner.client_pubkey.clone(),
            enrolled_by: "console".into(),
            owner_approval: hex::encode(
                signer
                    .sign(
                        owner_approval_message(
                            &fingerprint,
                            &owner.client_pubkey,
                            owner.epoch,
                            &public,
                        )
                        .as_bytes(),
                    )
                    .to_bytes(),
            ),
        });
        let svc = svc.with_owner_signing_key(signer);
        svc.configure_owner_tickets(&identity, vec!["127.0.0.1:9737".into()])
            .unwrap();
        Self {
            dir,
            svc,
            owner,
            key,
            key_id,
            console,
        }
    }
    fn provisional(&self, n: u8) -> PairedClient {
        self.svc
            .create_second_device_pairing(
                &format!("second_{n}"),
                "iPhone",
                &pubkey(n),
                &[n; 32],
                "console",
            )
            .unwrap()
    }
    fn request(
        &self,
        client: &PairedClient,
        k: &EcdsaKeyPair,
    ) -> Result<PendingDeviceKey, PairingError> {
        let public = hex::encode(k.public_key().as_ref());
        self.svc.request_device_key_versioned(
            &client.client_id,
            &public,
            "iPhone",
            &sign(
                k,
                &registration_message(&self.svc.bound_fingerprint(), &client.client_id, &public),
            ),
            Some(2),
            Some(binding(&self.svc, client)),
        )
    }
    fn confirmed(&self, n: u8) -> (PairedClient, PendingDeviceKey) {
        let c = self.provisional(n);
        let k = key();
        let op = self.request(&c, &k).unwrap();
        let digest = op.sas.as_ref().unwrap().digest;
        self.svc
            .confirm_device_sas(
                &c.client_id,
                &op.op_id,
                &binding(&self.svc, &c),
                &digest.to_hex(),
                &sign(
                    &k,
                    &sas_registration_message(
                        &self.svc.bound_fingerprint(),
                        &c.client_id,
                        &op.public_key,
                        &digest,
                    ),
                ),
            )
            .unwrap();
        (c, self.svc.pending_device_key(&op.op_id).unwrap())
    }
    fn message(&self, op: &PendingDeviceKey, reject: bool) -> String {
        self.svc
            .second_device_message(
                &self.owner.client_id,
                self.owner.epoch,
                &self.key_id,
                &op.op_id,
                reject,
            )
            .unwrap()
    }
    fn approve(&self, op: &PendingDeviceKey, sig: &str) -> Result<DeviceKey, PairingError> {
        self.svc.approve_second_device(
            &self.owner.client_id,
            self.owner.epoch,
            &op.op_id,
            &self.key_id,
            sig,
        )
    }
}
fn pubkey(n: u8) -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[n; 32])
            .verifying_key()
            .to_bytes(),
    )
}
fn binding(svc: &PairingService, c: &PairedClient) -> crate::sas::NoiseBinding {
    crate::sas::NoiseBinding {
        handshake_hash: [42; 32],
        box_public_key: svc.box_transport_pubkey(),
        client_static: hex::decode(c.remote_transport_pubkey.as_ref().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    }
}
#[test]
fn t3_approve_completes_provisional_and_t5_replay_fails() {
    let f = Fixture::new();
    let (c, op) = f.confirmed(2);
    let sig = sign(&f.key, &f.message(&op, false));
    let enrolled = f.approve(&op, &sig).unwrap();
    assert_eq!(enrolled.enrolled_by, format!("second_device:{}", f.key_id));
    assert_eq!(
        f.svc.device_key_status(&c.client_id, &op.op_id),
        DeviceKeyStatus::Registered
    );
    assert_eq!(
        f.svc.validate_remote_transport(&[2; 32]).unwrap().scopes,
        vec![Scope::Read, Scope::Receive]
    );
    f.svc.sweep_provisional_pairings().unwrap();
    assert!(f.svc.validate_remote_transport(&[2; 32]).is_ok());
    assert!(matches!(
        f.approve(&op, &sig),
        Err(PairingError::UnknownOperation)
    ));
}
#[test]
fn t4_t22_every_signed_field_mutation_refused_without_consuming() {
    let f = Fixture::new();
    let (_, op) = f.confirmed(2);
    let message = f.message(&op, false);
    assert!(message.contains("\nissuer:console\n"));
    assert!(message.contains("\ndevice_name:iPhone\n"));
    for i in 0..message.lines().count() {
        let mut lines: Vec<_> = message.lines().map(str::to_owned).collect();
        lines[i].push('x');
        assert!(matches!(
            f.approve(&op, &sign(&f.key, &lines.join("\n"))),
            Err(PairingError::BadProof)
        ));
        // Isolate each mutation from the independent bad-signature limit.
        f.svc.lock().second_device.bad_signatures.clear();
        assert!(f.svc.pending_device_key(&op.op_id).is_some());
    }
    f.approve(&op, &sign(&f.key, &message)).unwrap();
}
#[test]
fn t6_delegate_refuses_v2_even_without_require_sas() {
    let f = Fixture::new();
    let (_, op) = f.confirmed(2);
    let sig = sign(
        &f.key,
        &device::delegation_message(&f.svc.bound_fingerprint(), &op),
    );
    assert!(matches!(
        f.svc.delegate_device_key(
            &f.owner.client_id,
            f.owner.epoch,
            &op.op_id,
            &f.key_id,
            &sig
        ),
        Err(PairingError::BadProof)
    ));
    assert!(matches!(
        f.svc.delegate_device_key_over_tunnel(
            &f.owner.client_id,
            f.owner.epoch,
            &op.op_id,
            &f.key_id,
            &sig
        ),
        Err(PairingError::BadProof)
    ));
    let approval = sign(&f.key, &f.message(&op, false));
    // The converse domain/version boundary: v2 signatures cannot enroll v1 ops.
    f.svc.lock().file.pending_device_keys[0].sas_version = Some(1);
    assert!(matches!(
        f.approve(&op, &approval),
        Err(PairingError::UnknownOperation)
    ));
    assert!(f.svc.pending_device_key(&op.op_id).is_some());
}
#[test]
fn t8_reject_revokes_and_reports_lost() {
    let f = Fixture::new();
    let (c, op) = f.confirmed(2);
    f.svc
        .reject_second_device(
            &f.owner.client_id,
            f.owner.epoch,
            &op.op_id,
            &f.key_id,
            &sign(&f.key, &f.message(&op, true)),
        )
        .unwrap();
    assert!(f.svc.validate_remote_transport(&[2; 32]).is_err());
    assert_eq!(
        f.svc.device_key_status(&c.client_id, &op.op_id),
        DeviceKeyStatus::Lost
    );
    assert_eq!(f.svc.lock().sas_failures, 0);
}
#[test]
fn t13_contested_before_and_after_enrollment() {
    for enrolled in [false, true] {
        let f = Fixture::new();
        let (_, op) = f.confirmed(2);
        if enrolled {
            f.approve(&op, &sign(&f.key, &f.message(&op, false)))
                .unwrap();
        }
        assert!(f
            .svc
            .check_second_device_rescan("second_2", &pubkey(3), &[3; 32])
            .is_err());
        assert_eq!(f.svc.validate_remote_transport(&[2; 32]).is_ok(), enrolled);
        assert!(f.svc.pending_device_key(&op.op_id).is_none());
        assert_eq!(!f.svc.second_device_alerts().is_empty(), enrolled);
    }
}
#[test]
fn contested_approval_retains_reason_and_audits_once() {
    let mut f = Fixture::new();
    let path = f.dir.path().join("audit.jsonl");
    f.svc = f.svc.with_enrollment_audit(std::sync::Arc::new(
        crate::audit::AuditLog::open(&path).unwrap(),
    ));
    let (client, op) = f.confirmed(2);
    let signature = sign(&f.key, &f.message(&op, false));
    // A failed durable kill must retain the op and produce no contest audit.
    let blocker = f.svc.file_path.with_extension("json.tmp");
    std::fs::create_dir(&blocker).unwrap();
    assert!(matches!(
        f.svc.check_second_device_rescan("second_2", &pubkey(3), &[3; 32]),
        Err(PairingError::Io(_))
    ));
    assert!(f.svc.is_provisional(&client.client_id));
    assert!(f.svc.pending_device_key(&op.op_id).is_some());
    f.message(&op, false);
    std::fs::remove_dir(&blocker).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            f.svc.check_second_device_rescan("second_2", &pubkey(3), &[3; 32]),
            Err(PairingError::PairingInvalid(reason)) if reason == "contested"
        ));
        assert!(matches!(
            f.approve(&op, &signature),
            Err(PairingError::PairingInvalid(reason)) if reason == "contested"
        ));
    }
    assert!(f.svc.pending_device_key(&op.op_id).is_none());
    assert!(f.svc.validate_remote_transport(&[2; 32]).is_err());
    let events: Vec<serde_json::Value> = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .filter(|event: &serde_json::Value| event["event"] == "pair.second_device_contested")
        .collect();
    assert_eq!(events.len(), 1);
    assert!(events[0].to_string().contains(&client.client_id));
    assert!(!events[0].to_string().contains("second_2"));
}

#[test]
fn v1_failure_gate_precedes_unknown_op_but_does_not_block_v2() {
    let f = Fixture::new();
    f.svc.lock().sas_failures = 3;
    assert!(matches!(
        f.svc.confirm_device_sas(
            &f.owner.client_id,
            "unknown",
            &binding(&f.svc, &f.owner),
            "",
            ""
        ),
        Err(PairingError::Closed)
    ));
    // Both request and finalize for v2 ignore the v1 counter.
    f.confirmed(2);
    assert_eq!(f.svc.lock().sas_failures, 3);
}

#[test]
fn t10_restart_sweeps_zero_scope_pairing() {
    let f = Fixture::new();
    f.provisional(2);
    let durable: PairingFile =
        serde_json::from_slice(&std::fs::read(f.svc.dir().join("clients.json")).unwrap()).unwrap();
    assert_eq!(durable.version, 8);
    let stored = durable
        .clients
        .iter()
        .find(|c| c.remote_transport_pubkey.as_deref() == Some(&hex::encode([2; 32])))
        .unwrap();
    assert!(
        stored.scopes.is_empty(),
        "the existing pairing-file reader sees no authority"
    );
    let reopened = PairingService::open(f.dir.path(), f.svc.bound_fingerprint(), true).unwrap();
    assert!(reopened.validate_remote_transport(&[2; 32]).is_err());
    assert!(reopened.validate_remote_transport(&[1; 32]).is_ok());
}
#[test]
fn t19_version_matrix_and_t20_rotate_provisional() {
    let f = Fixture::new();
    let c = f.provisional(2);
    let k = key();
    let public = hex::encode(k.public_key().as_ref());
    let sig = sign(
        &k,
        &registration_message(&f.svc.bound_fingerprint(), &c.client_id, &public),
    );
    assert!(f
        .svc
        .request_device_key(&c.client_id, &public, "iPhone", &sig)
        .is_err());
    assert!(f
        .svc
        .request_device_key_with_sas(
            &c.client_id,
            &public,
            "iPhone",
            &sig,
            Some(binding(&f.svc, &c))
        )
        .is_err());
    assert!(f.request(&f.owner, &k).is_err());
    assert!(f
        .svc
        .create_second_device_pairing("second_other", "phone", &pubkey(2), &[3; 32], "console")
        .is_err());
    use ed25519_dalek::Signer;
    let msg = format!("bitsov-pair-rotate-v1:{}:{}", c.client_id, pubkey(4));
    assert!(f
        .svc
        .rotate_client_key(
            &c.client_id,
            &pubkey(4),
            &hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[2; 32])
                    .sign(msg.as_bytes())
                    .to_bytes()
            )
        )
        .is_err());
}

#[test]
fn t2_claim_file_is_never_read_by_v2() {
    for state in ["absent", "unreadable", "symlink"] {
        let f = Fixture::new();
        let path = f.dir.path().join("claim-code");
        match state {
            "unreadable" => {
                std::fs::write(&path, b"not a valid claim").unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o0)).unwrap();
                }
            }
            "symlink" => {
                #[cfg(unix)]
                std::os::unix::fs::symlink("missing-claim", &path).unwrap();
            }
            _ => {}
        }
        let c = f.provisional(2);
        assert!(f.request(&c, &key()).is_ok(), "{state}");
    }
}
#[test]
fn t7_failure_counts_are_per_pairing_and_v1_closure_does_not_block() {
    for mismatch in [false, true] {
        let f = Fixture::new();
        let c = f.provisional(2);
        f.svc.lock().sas_failures = 3;
        for attempt in 1..=3 {
            let op = f.request(&c, &key()).unwrap();
            if mismatch {
                assert!(matches!(
                    f.svc.confirm_device_sas(
                        &c.client_id,
                        &op.op_id,
                        &binding(&f.svc, &c),
                        &"00".repeat(32),
                        ""
                    ),
                    Err(PairingError::BadProof)
                ));
            } else {
                f.svc.cancel_pending(&c.client_id, &op.op_id).unwrap();
            }
            assert_eq!(
                f.svc.validate_remote_transport(&[2; 32]).is_ok(),
                attempt < 3
            );
            assert_eq!(f.svc.lock().sas_failures, 3);
        }
        let fresh = f.provisional(3);
        assert!(f.request(&fresh, &key()).is_ok());
        assert_eq!(
            f.svc.lock().second_device.mismatches.len(),
            if mismatch { 3 } else { 0 }
        );
    }
}
#[test]
fn t7_node_window_decays_and_reset_clears_both_counters() {
    let f = Fixture::new();
    for n in 2..=5 {
        let c = f.provisional(n);
        for _ in 0..if n == 5 { 1 } else { 3 } {
            let op = f.request(&c, &key()).unwrap();
            assert!(f
                .svc
                .confirm_device_sas(
                    &c.client_id,
                    &op.op_id,
                    &binding(&f.svc, &c),
                    &"00".repeat(32),
                    ""
                )
                .is_err());
        }
    }
    let c = f.svc.validate_remote_transport(&[5; 32]).unwrap();
    assert!(matches!(
        f.request(&c, &key()),
        Err(PairingError::TooManyPending)
    ));
    for t in &mut f.svc.lock().second_device.mismatches {
        *t -= std::time::Duration::from_secs(3600);
    }
    let op = f.request(&c, &key()).unwrap();
    f.svc.cancel_pending(&c.client_id, &op.op_id).unwrap();
    f.svc.lock().sas_failures = 3;
    f.svc
        .lock()
        .second_device
        .mismatches
        .push(std::time::Instant::now());
    f.svc.reset_sas_failures();
    assert_eq!(f.svc.lock().sas_failures, 0);
    assert!(f.svc.lock().second_device.mismatches.is_empty());
}
#[test]
fn t7_v1_takeover_never_charges_v1_and_confirmed_slot_is_preserved() {
    for state in ["unconfirmed", "confirmed", "lost"] {
        let confirmed = state == "confirmed";
        let f = Fixture::new();
        crate::sas::initialize(f.dir.path()).unwrap();
        let k = key();
        let public = hex::encode(k.public_key().as_ref());
        let old = f
            .svc
            .request_device_key_with_sas(
                &f.owner.client_id,
                &public,
                "legacy",
                &sign(
                    &k,
                    &registration_message(&f.svc.bound_fingerprint(), &f.owner.client_id, &public),
                ),
                Some(binding(&f.svc, &f.owner)),
            )
            .unwrap();
        if confirmed {
            f.svc.lock().file.pending_device_keys[0]
                .sas
                .as_mut()
                .unwrap()
                .confirmed = true;
        }
        if state == "lost" {
            f.svc.lock().file.pending_device_keys[0].sas = None;
        }
        let c = f.provisional(2);
        let result = f.request(&c, &key());
        assert_eq!(result.is_ok(), !confirmed);
        assert_eq!(
            f.svc.lock().sas_failures,
            0,
            "pre-emption must not call cancel_pending"
        );
        assert_eq!(f.svc.pending_device_key(&old.op_id).is_some(), confirmed);
        if !confirmed {
            assert_eq!(
                f.svc.device_key_status(&f.owner.client_id, &old.op_id),
                DeviceKeyStatus::Lost
            );
        }
    }
}
#[test]
fn t11_all_v2_expiry_checks_and_created_at_rate_limit() {
    for monotonic in [false, true] {
        let f = Fixture::new();
        let (c, op) = f.confirmed(2);
        assert_eq!(op.expires_at - op.created_at, 300);
        let message = f.message(&op, false);
        {
            let mut i = f.svc.lock();
            let p = i
                .file
                .pending_device_keys
                .iter_mut()
                .find(|p| p.op_id == op.op_id)
                .unwrap();
            if monotonic {
                p.sas.as_mut().unwrap().created_at -= std::time::Duration::from_secs(300);
            } else {
                p.expires_at = chrono::Utc::now().timestamp();
            }
        }
        let expired = f.svc.pending_device_key(&op.op_id).unwrap();
        if monotonic {
            assert!(expired.require_sas_confirmed().is_err());
        }
        assert!(matches!(
            f.svc.confirm_device_sas(
                &c.client_id,
                &op.op_id,
                &binding(&f.svc, &c),
                &op.sas.as_ref().unwrap().digest.to_hex(),
                ""
            ),
            Err(PairingError::Expired)
        ));
        assert!(f
            .svc
            .owner_pending_device(&f.owner.client_id, f.owner.epoch, &f.key_id, &op.op_id)
            .is_err());
        assert!(matches!(
            f.approve(&op, &sign(&f.key, &message)),
            Err(PairingError::Expired)
        ));
    }
    // Expired slot cannot bypass the per-client request interval; legacy zero never blocks.
    for version in [None, Some(1), Some(2)] {
        let f = Fixture::new();
        crate::sas::initialize(f.dir.path()).unwrap();
        if version.is_none() {
            std::fs::remove_file(f.dir.path().join("claim-code")).unwrap();
        }
        let c = if version == Some(2) {
            f.provisional(2)
        } else {
            f.owner.clone()
        };
        let k = key();
        let public = hex::encode(k.public_key().as_ref());
        let proof = sign(
            &k,
            &registration_message(&f.svc.bound_fingerprint(), &c.client_id, &public),
        );
        let request = || {
            f.svc.request_device_key_versioned(
                &c.client_id,
                &public,
                "phone",
                &proof,
                version,
                version.map(|_| binding(&f.svc, &c)),
            )
        };
        let op = request().unwrap();
        assert_eq!(
            op.expires_at - op.created_at,
            if version == Some(2) { 300 } else { 900 }
        );
        f.svc.lock().file.pending_device_keys[0].expires_at = 0;
        assert!(matches!(request(), Err(PairingError::TooManyPending)));
        f.svc.lock().file.pending_device_keys[0].created_at = 0;
        assert!(request().is_ok());
    }
}
#[test]
fn t12_concurrent_approval_consumes_exactly_once() {
    let f = Fixture::new();
    let (_, op) = f.confirmed(2);
    let sig = sign(&f.key, &f.message(&op, false));
    std::thread::scope(|scope| {
        let jobs: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| f.approve(&op, &sig)))
            .collect();
        assert_eq!(
            jobs.into_iter()
                .map(|j| j.join().unwrap())
                .filter(Result::is_ok)
                .count(),
            1
        );
    });
}
#[test]
fn t15_provisional_sas_and_signature_limits() {
    let f = Fixture::new();
    let (_, op) = f.confirmed(2);
    let other = f.provisional(3);
    assert!(matches!(
        f.provisional_result(4),
        Err(PairingError::TooManyPending)
    ));
    assert!(matches!(
        f.request(&other, &key()),
        Err(PairingError::TooManyPending)
    ));
    for _ in 0..10 {
        assert!(matches!(f.approve(&op, "00"), Err(PairingError::BadProof)));
    }
    let sig = sign(&f.key, &f.message(&op, false));
    assert!(matches!(
        f.approve(&op, &sig),
        Err(PairingError::TooManyPending)
    ));
    for times in f.svc.lock().second_device.bad_signatures.values_mut() {
        for t in times {
            *t -= std::time::Duration::from_secs(3600);
        }
    }
    assert!(f.approve(&op, &sig).is_ok());
}
impl Fixture {
    fn provisional_result(&self, n: u8) -> Result<PairedClient, PairingError> {
        self.svc.create_second_device_pairing(
            &format!("second_{n}"),
            "phone",
            &pubkey(n),
            &[n; 32],
            "console",
        )
    }
}
#[test]
fn t5_approver_epoch_revocation_chronology_and_node_binding() {
    for mutation in ["epoch", "revoke", "after", "self", "node"] {
        let f = Fixture::new();
        let (c, op) = f.confirmed(2);
        let message = f.message(&op, false);
        let sig = sign(&f.key, &message);
        match mutation {
            "epoch" => {
                f.svc
                    .lock()
                    .file
                    .clients
                    .iter_mut()
                    .find(|c| c.client_id == f.owner.client_id)
                    .unwrap()
                    .epoch += 1
            }
            "revoke" => f.svc.revoke_device_key(&f.key_id, None).unwrap(),
            "after" => f.svc.lock().file.device_keys[0].registered_at = op.created_at,
            "node" => f.svc.lock().identity_fingerprint = "e".repeat(32),
            "self" => {
                f.svc.lock().file.pending_device_keys[0].client_id = f.owner.client_id.clone()
            }
            _ => unreachable!(),
        }
        assert!(f.approve(&op, &sig).is_err(), "{mutation}");
        assert!(f.svc.pending_device_key(&op.op_id).is_some());
        assert!(f.svc.device_keys_for(&c.client_id).is_empty());
    }
}
#[test]
fn d2_console_v2_completion_survives_sweep() {
    let mut f = Fixture::new();
    let audit_path = f.dir.path().join("console-audit.jsonl");
    f.svc = f.svc.with_enrollment_audit(std::sync::Arc::new(
        crate::audit::AuditLog::open(&audit_path).unwrap(),
    ));
    let (_, op) = f.confirmed(2);
    let signer = konsensus_core::OwnerApprovalKey::from_seed(&[7; 64], &[9; 32]).unwrap();
    let approval = hex::encode(
        signer
            .sign(
                owner_approval_message(
                    &f.svc.bound_fingerprint(),
                    &op.client_pubkey,
                    op.epoch,
                    &op.public_key,
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    f.svc
        .approve_device_key(&op.op_id, &f.console.owner_code(&op.op_id), &approval)
        .unwrap();
    assert!(std::fs::read_to_string(audit_path)
        .unwrap()
        .contains("pair.second_device_enrolled"));
    f.svc.sweep_provisional_pairings().unwrap();
    assert_eq!(
        f.svc.validate_remote_transport(&[2; 32]).unwrap().scopes,
        vec![Scope::Read, Scope::Receive]
    );
    assert!(!f
        .svc
        .lock()
        .second_device
        .provisional
        .contains_key(&op.client_id));
}
#[test]
fn t10_t20_deadline_sweep_uses_client_id() {
    let f = Fixture::new();
    let c = f.provisional(2);
    f.svc
        .lock()
        .second_device
        .provisional
        .get_mut(&c.client_id)
        .unwrap()
        .deadline -= std::time::Duration::from_secs(900);
    assert!(f.svc.validate_remote_transport(&[2; 32]).is_err());
    assert_eq!(f.svc.sweep_provisional_pairings().unwrap(), 1);
    assert!(!f
        .svc
        .lock()
        .file
        .clients
        .iter()
        .any(|p| p.client_id == c.client_id));
}

impl Fixture {
    fn ticket(&self) -> Result<crate::remote_access::PairLink, PairingError> {
        let nonce = self.svc.owner_ticket_challenge(
            &self.owner.client_id,
            self.owner.epoch,
            &self.key_id,
        )?;
        self.svc.mint_owner_ticket_with_purpose(
            &self.owner.client_id,
            self.owner.epoch,
            &self.key_id,
            &nonce,
            &sign(
                &self.key,
                &format!(
                    "bitsov-ticket-v2\nnode:{}\nnonce:{nonce}\npurpose:second_device",
                    self.svc.bound_fingerprint()
                ),
            ),
            Some("second_device"),
        )
    }
}
#[tokio::test(start_paused = true)]
async fn t21_unconsumed_ticket_refund_and_consumed_slot_retained() {
    let f = Fixture::new();
    for _ in 0..5 {
        f.ticket().unwrap();
    }
    assert!(matches!(f.ticket(), Err(PairingError::TooManyPending)));
    tokio::time::advance(std::time::Duration::from_secs(300)).await;
    for n in 2..=6 {
        let ticket = f.ticket().unwrap();
        let c = f
            .svc
            .consume_owner_ticket(&ticket.code, "phone", &pubkey(n), &[n; 32])
            .unwrap();
        {
            let mut i = f.svc.lock();
            PairingService::remove_provisional_locked(&mut i, &c.client_id);
        }
    }
    tokio::time::advance(std::time::Duration::from_secs(300)).await;
    assert!(
        matches!(f.ticket(), Err(PairingError::TooManyPending)),
        "consumed slots must not be refunded"
    );
}
#[test]
fn t19_existing_scanner_does_not_consume_owner_ticket_and_issuer_is_exposed() {
    let f = Fixture::new();
    let ticket = f.ticket().unwrap();
    assert!(
        matches!(f.svc.consume_owner_ticket(&ticket.code,"Mac",&f.owner.client_pubkey,&[9;32]),Err(PairingError::PairingInvalid(s)) if s=="already_paired")
    );
    assert!(
        matches!(f.svc.consume_owner_ticket(&ticket.code,"Mac",&pubkey(9),&[1;32]),Err(PairingError::PairingInvalid(s)) if s=="already_paired")
    );
    let c = f
        .svc
        .consume_owner_ticket(&ticket.code, "phone", &pubkey(2), &[2; 32])
        .unwrap();
    let op = f.request(&c, &key()).unwrap();
    let view = f
        .svc
        .owner_pending_device(&f.owner.client_id, f.owner.epoch, &f.key_id, &op.op_id)
        .unwrap();
    assert_eq!(view["issuer"], f.key_id);
    assert!(view["approval_message"].is_null());
    assert!(!view.to_string().contains(&ticket.code));
}
#[test]
fn t14_gates_and_t3_atomic_persistence_rollback() {
    for gate in ["flag", "mode", "signer", "no_owner"] {
        let mut f = Fixture::new();
        match gate {
            "flag" => f.svc.second_device_enrollment = false,
            "mode" => f.svc.local_owner_device = false,
            "signer" => f.svc.owner_signing_key = None,
            _ => f.svc.lock().file.device_keys.clear(),
        }
        assert!(f.provisional_result(2).is_err(), "{gate}");
        assert!(f.svc.lock().second_device.provisional.is_empty());
    }
    let f = Fixture::new();
    let (c, op) = f.confirmed(2);
    let sig = sign(&f.key, &f.message(&op, false));
    let path = f.svc.file_path.with_extension("json.tmp");
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(f.approve(&op, &sig), Err(PairingError::Io(_))));
    assert!(f.svc.is_provisional(&c.client_id));
    assert!(f.svc.device_keys_for(&c.client_id).is_empty());
    assert!(f.svc.pending_device_key(&op.op_id).is_some());
    std::fs::remove_dir(&path).unwrap();
    f.approve(&op, &sig).unwrap();
}

#[test]
fn rollback_keeps_console_confirmation_and_token_challenge() {
    let f = Fixture::new();
    let (c, op) = f.confirmed(2);
    let challenge = f.svc.issue_token_challenge(&c.client_id).unwrap();
    let code = f.console.owner_code(&op.op_id);
    let fail = f.svc.file_path.with_extension("json.tmp");
    std::fs::create_dir(&fail).unwrap();
    assert!(f.svc.cancel_pending(&c.client_id, &op.op_id).is_err());
    assert!(f.svc.lock().owner_confirmations.contains_key(&op.op_id));
    // A rejected operation must be wholly rolled back too, including token challenges.
    assert!(f
        .svc
        .reject_second_device(
            &f.owner.client_id,
            f.owner.epoch,
            &op.op_id,
            &f.key_id,
            &sign(&f.key, &f.message(&op, true))
        )
        .is_err());
    assert!(f.svc.lock().token_challenges.contains_key(&challenge));
    std::fs::remove_dir(fail).unwrap();
    let signer = konsensus_core::OwnerApprovalKey::from_seed(&[7; 64], &[9; 32]).unwrap();
    let approval = hex::encode(
        signer
            .sign(
                owner_approval_message(
                    &f.svc.bound_fingerprint(),
                    &op.client_pubkey,
                    op.epoch,
                    &op.public_key,
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    f.svc
        .approve_device_key(&op.op_id, &code, &approval)
        .unwrap();
}

#[test]
fn t10_startup_sweep_is_audited_when_sink_is_attached() {
    let f = Fixture::new();
    let c = f.provisional(2);
    let path = f.dir.path().join("audit.jsonl");
    let audit = std::sync::Arc::new(crate::audit::AuditLog::open(&path).unwrap());
    let _reopened = PairingService::open(f.dir.path(), f.svc.bound_fingerprint(), false)
        .unwrap()
        .with_enrollment_audit(audit);
    let log = std::fs::read_to_string(path).unwrap();
    assert!(log.contains("pair.provisional_swept"));
    assert!(log.contains(&c.client_id));
}

#[test]
fn t15_expired_provisional_does_not_hold_capacity() {
    let f = Fixture::new();
    let first = f.provisional(2);
    f.provisional(3);
    f.svc
        .lock()
        .second_device
        .provisional
        .get_mut(&first.client_id)
        .unwrap()
        .deadline -= std::time::Duration::from_secs(900);
    assert!(f.provisional_result(4).is_ok());
}

#[test]
fn t14_no_owner_ticket_refusal_does_not_consume_challenge() {
    let f = Fixture::new();
    let nonce = f
        .svc
        .owner_ticket_challenge(&f.owner.client_id, f.owner.epoch, &f.key_id)
        .unwrap();
    let keys = std::mem::take(&mut f.svc.lock().file.device_keys);
    let signature = sign(
        &f.key,
        &format!(
            "bitsov-ticket-v2\nnode:{}\nnonce:{nonce}\npurpose:second_device",
            f.svc.bound_fingerprint()
        ),
    );
    let mint = || {
        f.svc.mint_owner_ticket_with_purpose(
            &f.owner.client_id,
            f.owner.epoch,
            &f.key_id,
            &nonce,
            &signature,
            Some("second_device"),
        )
    };
    assert!(matches!(mint(),Err(PairingError::PairingInvalid(s)) if s=="no_owner_device"));
    f.svc.lock().file.device_keys = keys;
    assert!(mint().is_ok());
}

#[test]
fn t13_old_ticket_cannot_contest_a_later_pairing_of_the_same_keys() {
    let f = Fixture::new();
    let c = f.provisional(2);
    f.svc.revoke(&c.client_id).unwrap();
    let replacement = f
        .svc
        .create_second_device_pairing(
            "second_replacement",
            "replacement",
            &pubkey(2),
            &[9; 32],
            "console",
        )
        .unwrap();
    assert!(f
        .svc
        .check_second_device_rescan("second_2", &pubkey(3), &[3; 32])
        .is_err());
    assert!(f.svc.is_provisional(&replacement.client_id));
    assert!(f.svc.validate_remote_transport(&[9; 32]).is_ok());
}
#[test]
fn t15_console_revoke_releases_provisional_capacity() {
    let f = Fixture::new();
    let first = f.provisional(2);
    f.provisional(3);
    f.svc.revoke(&first.client_id).unwrap();
    assert!(f.provisional_result(4).is_ok());
}

#[tokio::test(start_paused = true)]
async fn t21_mixed_expiry_never_refunds_a_consumed_ticket() {
    let f = Fixture::new();
    let used = f.ticket().unwrap();
    let c = f
        .svc
        .consume_owner_ticket(&used.code, "phone", &pubkey(2), &[2; 32])
        .unwrap();
    f.svc.revoke(&c.client_id).unwrap();
    for _ in 0..4 {
        f.ticket().unwrap();
    }
    tokio::time::advance(std::time::Duration::from_secs(300)).await;
    for _ in 0..4 {
        f.ticket().unwrap();
    }
    assert!(
        matches!(f.ticket(), Err(PairingError::TooManyPending)),
        "only the four unconsumed tickets refund slots, even with equal issue times"
    );
}
