use super::*;

#[test]
fn token_challenges_expiry_releases_client_and_global_capacity() {
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), "identity".into(), false).unwrap();
    service.open_pairing_window(Duration::from_secs(60));
    let clients: Vec<_> = (1..=17)
        .map(|seed| {
            let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
            service
                .create_verified_remote_pairing(
                    &format!("client-{seed}"),
                    &hex::encode(key.verifying_key().to_bytes()),
                    &[seed; 32],
                )
                .unwrap()
                .client_id
        })
        .collect();
    for client in &clients[..16] {
        for _ in 0..8 {
            service.issue_token_challenge(client).unwrap();
        }
    }
    assert!(matches!(
        service.issue_token_challenge(&clients[16]),
        Err(PairingError::TooManyPending)
    ));

    // Age A's actual entries rather than sleeping through the 120-second TTL.
    // The next issuance must prune them before either capacity check.
    {
        let mut inner = service.lock();
        for (owner, expires) in inner.token_challenges.values_mut() {
            if owner == &clients[0] {
                *expires = Instant::now() - Duration::from_secs(1);
            }
        }
    }
    service.issue_token_challenge(&clients[0]).unwrap();
    for _ in 0..7 {
        service.issue_token_challenge(&clients[16]).unwrap();
    }
    assert!(matches!(
        service.issue_token_challenge(&clients[16]),
        Err(PairingError::TooManyPending)
    ));
    // Other clients' live entries still occupy their slots.
    assert!(matches!(
        service.issue_token_challenge(&clients[1]),
        Err(PairingError::TooManyPending)
    ));
}
