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
