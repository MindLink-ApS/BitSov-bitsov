use super::*;

fn service(dir: &Path) -> PairingService {
    PairingService::open(dir, String::new(), false)
        .unwrap()
        .without_stdout_code()
}

fn public_key() -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[1; 32])
            .verifying_key()
            .to_bytes(),
    )
}

#[test]
fn challenge_publication_cannot_race_pending_removal() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let outcome = service
        .request_pairing_with_writer("client", &public_key(), |path, bytes| {
            // Model confirmation/expiry winning the lock before file creation.
            // Publication must prevent that interleaving, or it leaves an orphan.
            if let Ok(mut inner) = service.inner.try_lock() {
                inner.pending.clear();
                let _ = std::fs::remove_file(path);
            }
            write_protected(path, bytes)
        })
        .unwrap();
    assert!(service.lock().pending.contains_key(&outcome.pair_id));
    assert_eq!(
        std::fs::read(service.challenge_path(&outcome.pair_id))
            .unwrap()
            .len(),
        CHALLENGE_LEN
    );
}

#[test]
fn failed_challenge_write_removes_partial_file_and_releases_slot() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let public = public_key();
    for _ in 0..MAX_PENDING_PAIRINGS_PER_SOURCE {
        let result = service.request_pairing_with_writer("client", &public, |path, bytes| {
            std::fs::write(path, &bytes[..1])?;
            Err(io::Error::other(
                "injected write failure after file creation",
            ))
        });
        assert!(matches!(result, Err(PairingError::Io(_))));
        assert!(service.lock().pending.is_empty());
        assert!(!std::fs::read_dir(service.dir()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("challenge-")
        }));
    }
    for _ in 0..MAX_PENDING_PAIRINGS_PER_SOURCE {
        service.request_pairing("client", &public).unwrap();
    }
}

#[test]
fn expired_pairing_removes_challenge_and_releases_source_slot() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let public = public_key();
    let requests: Vec<_> = (0..MAX_PENDING_PAIRINGS_PER_SOURCE)
        .map(|_| service.request_pairing("client", &public).unwrap())
        .collect();
    for pending in service.lock().pending.values_mut() {
        pending.expires_at = Instant::now() - Duration::from_secs(1);
    }
    let fresh = service.request_pairing("client", &public).unwrap();
    assert_eq!(service.lock().pending.len(), 1);
    assert!(service.challenge_path(&fresh.pair_id).exists());
    for request in requests {
        assert!(!service.challenge_path(&request.pair_id).exists());
    }
}

#[test]
fn failed_challenge_cleanup_keeps_reservation_until_removal_can_retry() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let public = public_key();
    let mut failed_path = PathBuf::new();
    let result = service.request_pairing_with_writer("client", &public, |path, _| {
        // An unlink failure must leave a tracked cleanup obligation.
        std::fs::create_dir(path)?;
        failed_path = path.to_owned();
        Err(io::Error::other("injected write and cleanup failure"))
    });
    assert!(matches!(result, Err(PairingError::Io(_))));
    assert_eq!(service.lock().pending.len(), 1);
    for pending in service.lock().pending.values_mut() {
        pending.expires_at = Instant::now() - Duration::from_secs(1);
    }
    // The stuck cleanup stays reserved but no longer blocks other requests.
    service.request_pairing("client", &public).unwrap();
    assert_eq!(service.lock().pending.len(), 2);
    std::fs::remove_dir(failed_path).unwrap();
    // The next sweep retries and removes it.
    service.request_pairing("client", &public).unwrap();
    assert_eq!(service.lock().pending.len(), 2);
    assert!(service.lock().pending.values().all(|p| p.expires_at > Instant::now()));
}

#[test]
fn identity_rebind_removes_pending_challenge_files() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let request = service.request_pairing("client", &public_key()).unwrap();
    service.rebind_to_identity("identity").unwrap();
    assert!(service.lock().pending.is_empty());
    assert!(!service.challenge_path(&request.pair_id).exists());
}

#[test]
fn identity_rebind_retains_failed_cleanup_as_an_expired_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let request = service.request_pairing("client", &public_key()).unwrap();
    let path = service.challenge_path(&request.pair_id);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    service.rebind_to_identity("identity").unwrap();
    {
        let inner = service.lock();
        let retained = inner
            .pending
            .get(&request.pair_id)
            .expect("cleanup must stay tracked");
        assert!(
            retained.expires_at <= Instant::now(),
            "rebind must still cancel authority"
        );
    }
    std::fs::remove_dir(path).unwrap();
    assert!(matches!(
        service.confirm_pairing(&request.pair_id, &"00".repeat(64), default_pairing_scopes()),
        Err(PairingError::UnknownPending)
    ));
    assert!(service.lock().pending.is_empty());
}

#[test]
fn confirmation_unlink_failure_burns_authority_but_retains_cleanup() {
    let dir = tempfile::tempdir().unwrap();
    let service = service(dir.path());
    let request = service.request_pairing("client", &public_key()).unwrap();
    let path = service.challenge_path(&request.pair_id);
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
        service.confirm_pairing(&request.pair_id, &"00".repeat(64), default_pairing_scopes()),
        Err(PairingError::Io(_))
    ));
    {
        let inner = service.lock();
        let retained = inner
            .pending
            .get(&request.pair_id)
            .expect("cleanup must stay tracked");
        assert!(
            retained.expires_at <= Instant::now(),
            "a failed attempt must stay single-use"
        );
    }
    std::fs::remove_dir(path).unwrap();
    assert!(matches!(
        service.confirm_pairing(&request.pair_id, &"00".repeat(64), default_pairing_scopes()),
        Err(PairingError::UnknownPending)
    ));
    assert!(service.lock().pending.is_empty());
}

/// A live owner window over fixed clock values: the exact boundary of each
/// term, with no wall clock involved.
#[test]
fn owner_window_covers_each_term_up_to_its_exact_bound() {
    const CREATED_AT: i64 = 1_700_000_000;
    const TTL: i64 = 600;
    let window = |expires_at: i64| SpendGrant {
        owner_approval: None,
        op_id: "grant".into(),
        client_id: "client".into(),
        scopes: vec![Scope::Spend],
        granted_at: CREATED_AT - 60,
        expires_at,
        identity_fingerprint: "identity".into(),
        epoch: 1,
        granted_by: "cli".into(),
        budget: Some(GrantBudget::from_terms(&GrantTerms::new(300_000).per_call(200_000))),
        ended: None,
    };
    let request = |terms: GrantTerms| PendingElevation {
        op_id: "request".into(),
        client_id: "client".into(),
        client_name: "app".into(),
        scopes: vec![Scope::Spend],
        created_at: CREATED_AT,
        expires_at: CREATED_AT + ELEVATION_TTL_SECS,
        proposed_terms: Some(terms),
    };
    let asked = |budget: u64, per_call: u64| GrantTerms::new(budget).per_call(per_call).for_secs(TTL);

    // Duration: a request ending with the window is covered; a window that
    // ends one second before the request would is not.
    let fits = asked(100_000, 1_000);
    assert!(owner_window_covers(&window(CREATED_AT + TTL), &request(fits.clone())));
    assert!(!owner_window_covers(&window(CREATED_AT + TTL - 1), &request(fits)));

    // Budget and per-call limit: equal is covered, one msat more is not.
    let live = window(CREATED_AT + 1_800);
    assert!(owner_window_covers(&live, &request(asked(300_000, 1_000))));
    assert!(!owner_window_covers(&live, &request(asked(300_001, 1_000))));
    assert!(owner_window_covers(&live, &request(asked(250_000, 200_000))));
    assert!(!owner_window_covers(&live, &request(asked(250_000, 200_001))));
}
