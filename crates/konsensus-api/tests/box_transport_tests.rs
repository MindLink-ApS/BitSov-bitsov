//! The box transport secret is independent of seed/identity and never rotated
//! implicitly, including when its on-disk representation is damaged.
use konsensus_api::pairing::PairingService;

#[test]
fn box_transport_key_is_private_and_stable_across_identity_changes() {
    let dir = tempfile::tempdir().unwrap();
    let first = PairingService::open(dir.path(), "first identity".into(), false).unwrap();
    let path = dir.path().join("pairing/box-transport.key");
    let key = std::fs::read(&path).expect("open must create the box transport key");
    assert_eq!(key.len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    drop(first);
    let _restarted = PairingService::open(dir.path(), "different identity".into(), false).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), key);
    let other = tempfile::tempdir().unwrap();
    let _other = PairingService::open(other.path(), "first identity".into(), false).unwrap();
    assert_ne!(
        std::fs::read(other.path().join("pairing/box-transport.key")).unwrap(),
        key
    );
}

#[test]
fn malformed_box_transport_key_is_not_replaced() {
    for size in [0, 31, 33] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("pairing")).unwrap();
        let path = dir.path().join("pairing/box-transport.key");
        let damaged = vec![0x42; size];
        std::fs::write(&path, &damaged).unwrap();
        assert!(PairingService::open(dir.path(), "identity".into(), false).is_err());
        assert_eq!(std::fs::read(path).unwrap(), damaged);
    }
}

#[cfg(unix)]
#[test]
fn box_transport_key_rejects_symlinks_and_repairs_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("pairing")).unwrap();
    let path = dir.path().join("pairing/box-transport.key");
    let target = dir.path().join("other-key");
    std::fs::write(&target, [0x42; 32]).unwrap();
    symlink(&target, &path).unwrap();
    assert!(PairingService::open(dir.path(), "identity".into(), false).is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, [0x42; 32]).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _service = PairingService::open(dir.path(), "identity".into(), false).unwrap();
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn box_transport_accessors_supply_a_noise_responder_static() {
    use konsensus_crypto::noise::NoiseSession;
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), String::new(), false).unwrap();
    let mut client = NoiseSession::initiator(&[0x53; 32]).unwrap();
    let mut server = NoiseSession::responder(service.box_transport_secret_bytes()).unwrap();
    server
        .read_handshake(&client.write_handshake(&[]).unwrap())
        .unwrap();
    client
        .read_handshake(&server.write_handshake(&[]).unwrap())
        .unwrap();
    assert_eq!(
        client.remote_static_key().unwrap(),
        &service.box_transport_pubkey()
    );
    server
        .read_handshake(&client.write_handshake(&[]).unwrap())
        .unwrap();
    client.try_finish_handshake().unwrap();
    server.try_finish_handshake().unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("pairing/box-transport.key")).unwrap(),
        service.box_transport_secret_bytes()
    );
}

#[test]
fn concurrent_opens_publish_one_complete_box_transport_key() {
    let dir = tempfile::tempdir().unwrap();
    let barrier = std::sync::Barrier::new(16);
    let keys = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..16)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    let service = PairingService::open(dir.path(), String::new(), false).unwrap();
                    service.box_transport_pubkey()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(keys.iter().all(|key| key == &keys[0]));
    assert!(std::fs::read_dir(dir.path().join("pairing"))
        .unwrap()
        .all(|entry| { entry.unwrap().file_name() == "box-transport.key" }));
}

#[cfg(unix)]
#[test]
fn failed_initial_write_does_not_publish_a_partial_key() {
    const CHILD_DIR: &str = "BITSOV_BOX_KEY_WRITE_FAILURE_DIR";
    if let Some(dir) = std::env::var_os(CHILD_DIR) {
        let dir = std::path::PathBuf::from(dir);
        assert!(PairingService::open(&dir, String::new(), false).is_err());
        assert!(
            !dir.join("pairing/box-transport.key").exists(),
            "failed write published a partial key"
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // Limit only a child test process: the OS refuses the actual key write.
    // Ignoring SIGXFSZ makes that refusal an I/O error we can inspect.
    let child = std::process::Command::new("sh")
        .args(["-c", "ulimit -f 0; trap '' XFSZ; exec \"$@\"", "sh"])
        .arg(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "failed_initial_write_does_not_publish_a_partial_key",
            "--nocapture",
        ])
        .env(CHILD_DIR, dir.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    let _service = PairingService::open(dir.path(), String::new(), false).unwrap();
    assert_eq!(
        std::fs::read(dir.path().join("pairing/box-transport.key"))
            .unwrap()
            .len(),
        32
    );
}
