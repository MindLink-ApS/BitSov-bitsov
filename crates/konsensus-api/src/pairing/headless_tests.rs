use super::*;

struct NoTerminal;
impl io::Write for NoTerminal {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(6))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn service(dir: &Path) -> PairingService {
    PairingService::open(dir, "identity".into(), true)
        .unwrap()
        .with_owner_console(Box::new(NoTerminal))
        .without_stdout_code()
}

fn pending(service: &PairingService) -> PendingElevation {
    let key = ed25519_dalek::SigningKey::from_bytes(&[95; 32]);
    let client = service
        .create_verified_remote_pairing(
            "test",
            &hex::encode(key.verifying_key().to_bytes()),
            &[96; 32],
        )
        .unwrap();
    service
        .create_elevation_request(&client.client_id, vec![Scope::Spend])
        .unwrap()
}

#[test]
fn headless_file_expires_during_sweep_without_an_http_read() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let op = pending(&service);
    let path = service.dir().join(format!("owner-approval-{}", op.op_id));
    assert!(path.exists());
    // Age the private deadline; cleanup must run even without a new request.
    service
        .lock_without_cleanup()
        .owner_confirmations
        .get_mut(&op.op_id)
        .unwrap()
        .expires_at = 0;
    service.prune_expired_grants().unwrap();
    assert!(!path.exists());
    assert!(!service.elevation_confirmable(&op.op_id));
}

#[test]
fn headless_file_removed_on_cancel_wrong_codes_and_shutdown() {
    for action in ["cancel", "wrong", "shutdown"] {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let op = pending(&service);
        let path = service.dir().join(format!("owner-approval-{}", op.op_id));
        assert!(path.exists());
        match action {
            "cancel" => service.cancel_pending(&op.client_id, &op.op_id).unwrap(),
            "wrong" => {
                for _ in 0..OWNER_CODE_ATTEMPTS {
                    assert!(service
                        .grant_elevation(&op.op_id, "wrong", GrantTerms::new(1000))
                        .is_err());
                }
            }
            _ => drop(service),
        }
        assert!(!path.exists(), "{action}");
    }
}

#[test]
fn headless_restart_rotates_codes_and_removes_crash_files() {
    let dir = tempfile::tempdir().unwrap();
    let old = service(dir.path());
    let op = pending(&old);
    let path = old.dir().join(format!("owner-approval-{}", op.op_id));
    let old_text = std::fs::read_to_string(&path).unwrap();
    drop(old);
    // Recreate what an unclean shutdown leaves behind.
    write_protected(&path, old_text.as_bytes()).unwrap();
    let new = service(dir.path());
    assert!(!path.exists());
    assert_eq!(new.reissue_owner_challenges().unwrap(), 1);
    let new_text = std::fs::read_to_string(&path).unwrap();
    assert_ne!(old_text, new_text);
    let old_phrase = old_text
        .lines()
        .find(|line| line.starts_with("GRANT "))
        .unwrap();
    assert!(new
        .grant_elevation(&op.op_id, old_phrase, GrantTerms::new(1000))
        .is_err());
    let phrase = new_text
        .lines()
        .find(|line| line.starts_with("GRANT "))
        .unwrap();
    new.grant_elevation(&op.op_id, phrase, GrantTerms::new(1000))
        .unwrap();
    assert!(!path.exists());
}

#[test]
fn headless_failed_persistence_leaves_no_operation_or_code_file() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let key = ed25519_dalek::SigningKey::from_bytes(&[95; 32]);
    let client = service
        .create_verified_remote_pairing(
            "test",
            &hex::encode(key.verifying_key().to_bytes()),
            &[96; 32],
        )
        .unwrap();
    std::fs::create_dir(service.dir().join("clients.json.tmp")).unwrap();
    assert!(service
        .create_elevation_request(&client.client_id, vec![Scope::Spend])
        .is_err());
    assert!(service.snapshot().pending_elevations.is_empty());
    assert!(std::fs::read_dir(service.dir()).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("owner-approval-")));
}

#[test]
fn headless_file_never_overwrites_an_existing_file_or_symlink() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let target = dir.path().join("existing");
    std::fs::write(&target, "untouched").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link = service.dir().join("owner-approval-op");
    symlink(&target, &link).unwrap();
    assert!(matches!(
        service.write_owner_approval_file("op", i64::MAX, "secret"),
        Err(PairingError::OwnerApprovalUnavailable)
    ));
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "untouched");
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o644
    );
    assert!(std::fs::symlink_metadata(link)
        .unwrap()
        .file_type()
        .is_symlink());
}

fn device_request(service: &PairingService) -> Result<PendingDeviceKey, PairingError> {
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    let client = service
        .create_verified_remote_pairing(
            "device",
            &hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[95; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            &[96; 32],
        )
        .unwrap();
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let proof = hex::encode(
        key.sign(
            &rng,
            device::registration_message("identity", &client.client_id, &public).as_bytes(),
        )
        .unwrap()
        .as_ref(),
    );
    service.request_device_key(&client.client_id, &public, "device", &proof)
}

#[test]
fn headless_device_file_survives_reads_and_is_consumed_on_approval() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let owner = konsensus_core::OwnerApprovalKey::from_seed(&[7; 64], &[9; 32]).unwrap();
    let service = service(dir.path()).with_owner_approval_key(owner.verifying_key());
    let op = device_request(&service).unwrap();
    let path = service.dir().join(format!("owner-approval-{}", op.op_id));
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let text = std::fs::read_to_string(&path).unwrap();
    let code = text
        .lines()
        .find_map(|l| {
            l.split_once("type this code when it asks: ")
                .map(|(_, c)| c)
        })
        .unwrap();
    assert_eq!(
        service.device_key_status(&op.client_id, &op.op_id),
        DeviceKeyStatus::Pending
    );
    assert!(path.exists());
    let signature = hex::encode(
        owner
            .sign(
                device::owner_approval_message(
                    "identity",
                    &op.client_pubkey,
                    op.epoch,
                    &op.public_key,
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    service
        .approve_device_key(&op.op_id, code, &signature)
        .unwrap();
    assert_eq!(
        service.device_key_status(&op.client_id, &op.op_id),
        DeviceKeyStatus::Registered
    );
    assert!(!path.exists());
}

#[test]
fn headless_device_failed_persistence_removes_file_and_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let owner = konsensus_core::OwnerApprovalKey::from_seed(&[7; 64], &[9; 32]).unwrap();
    let service = service(dir.path()).with_owner_approval_key(owner.verifying_key());
    // Pairing creation persists first; block only the device request's write.
    let client = service
        .create_verified_remote_pairing(
            "device",
            &hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[95; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            &[96; 32],
        )
        .unwrap();
    std::fs::create_dir(service.dir().join("clients.json.tmp")).unwrap();
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
    let key =
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng).unwrap();
    let public = hex::encode(key.public_key().as_ref());
    let proof = hex::encode(
        key.sign(
            &rng,
            device::registration_message("identity", &client.client_id, &public).as_bytes(),
        )
        .unwrap()
        .as_ref(),
    );
    assert!(matches!(
        service.request_device_key(&client.client_id, &public, "device", &proof),
        Err(PairingError::Io(_))
    ));
    assert!(service
        .lock_without_cleanup()
        .owner_confirmations
        .is_empty());
    assert!(service.pending_device_keys().is_empty());
    assert!(std::fs::read_dir(service.dir()).unwrap().all(|e| !e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with("owner-approval-")));
}

#[test]
fn headless_restart_skips_unavailable_terminal_item_and_continues() {
    struct RecoveringTerminal(bool);
    impl io::Write for RecoveringTerminal {
        fn write(&mut self, text: &[u8]) -> io::Result<usize> {
            if std::mem::replace(&mut self.0, false) {
                Err(io::Error::from_raw_os_error(6))
            } else {
                Ok(text.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let original = service(dir.path()).with_owner_console(Box::new(io::sink()));
    let client = original
        .create_verified_remote_pairing(
            "test",
            &hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[95; 32])
                    .verifying_key()
                    .to_bytes(),
            ),
            &[96; 32],
        )
        .unwrap();
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let first = original
        .create_replacement_request(&client.client_id, "identity", mnemonic)
        .unwrap();
    let second = original
        .create_replacement_request(&client.client_id, "identity", mnemonic)
        .unwrap();
    drop(original);
    let headless = service(dir.path());
    assert_eq!(headless.reissue_owner_challenges().unwrap(), 0);
    let recovering = headless.with_owner_console(Box::new(RecoveringTerminal(true)));
    assert_eq!(recovering.reissue_owner_challenges().unwrap(), 1);
    let inner = recovering.lock();
    assert!(!PairingService::confirmable(&inner, &first.op_id));
    assert!(PairingService::confirmable(&inner, &second.op_id));
}

#[test]
fn headless_open_skips_non_files_and_removes_stale_regular_files() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let pairing = dir.path().join("pairing");
    std::fs::create_dir_all(pairing.join("owner-approval-directory")).unwrap();
    let target = dir.path().join("untouched");
    std::fs::write(&target, "keep").unwrap();
    symlink(&target, pairing.join("owner-approval-link")).unwrap();
    std::fs::write(pairing.join("owner-approval-stale"), "old code").unwrap();
    let _service = service(dir.path());
    assert!(pairing.join("owner-approval-directory").is_dir());
    assert!(
        std::fs::symlink_metadata(pairing.join("owner-approval-link"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read_to_string(target).unwrap(), "keep");
    assert!(!pairing.join("owner-approval-stale").exists());
}

#[test]
fn headless_device_restart_reissues_and_rejects_old_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let owner = konsensus_core::OwnerApprovalKey::from_seed(&[7; 64], &[9; 32]).unwrap();
    let original = service(dir.path()).with_owner_approval_key(owner.verifying_key());
    let op = device_request(&original).unwrap();
    let path = original.dir().join(format!("owner-approval-{}", op.op_id));
    let old_text = std::fs::read_to_string(&path).unwrap();
    drop(original);
    write_protected(&path, old_text.as_bytes()).unwrap();
    let restarted = service(dir.path()).with_owner_approval_key(owner.verifying_key());
    assert!(!path.exists());
    assert_eq!(restarted.reissue_owner_challenges().unwrap(), 1);
    let new_text = std::fs::read_to_string(&path).unwrap();
    let old_phrase = old_text
        .lines()
        .find(|line| line.contains(" CODE "))
        .unwrap();
    let new_phrase = new_text
        .lines()
        .find(|line| line.contains(" CODE "))
        .unwrap();
    assert_ne!(old_phrase, new_phrase);
    let signature = hex::encode(
        owner
            .sign(
                device::owner_approval_message(
                    "identity",
                    &op.client_pubkey,
                    op.epoch,
                    &op.public_key,
                )
                .as_bytes(),
            )
            .to_bytes(),
    );
    assert!(matches!(
        restarted.approve_device_key(&op.op_id, old_phrase, &signature),
        Err(PairingError::WrongOwnerCode(2))
    ));
    assert!(path.exists());
    restarted
        .approve_device_key(&op.op_id, new_phrase, &signature)
        .unwrap();
    assert!(!path.exists());
    assert_eq!(
        restarted.device_key_status(&op.client_id, &op.op_id),
        DeviceKeyStatus::Registered
    );
}
