use super::*;
use ed25519_dalek::Signer;

fn local_client(service: &PairingService, seed: u8) -> (PairedClient, ed25519_dalek::SigningKey) {
    service.open_pairing_window(Duration::from_secs(60));
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let client = service
        .create_verified_remote_pairing(
            "client",
            &hex::encode(key.verifying_key().to_bytes()),
            &[seed; 32],
        )
        .unwrap();
    (client, key)
}

fn local_signature(
    client: &PairedClient,
    key: &ed25519_dalek::SigningKey,
    timestamp: i64,
) -> [u8; 64] {
    key.sign(format!("bitsov-pair-challenge-v1:{}:{timestamp}", client.client_id).as_bytes())
        .to_bytes()
}

#[test]
fn token_challenges_replay_flood_preserves_fresh_request_and_slots() {
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), "identity".into(), false).unwrap();
    let (client, key) = local_client(&service, 1);
    let now = chrono::Utc::now().timestamp();
    let signature = hex::encode(local_signature(&client, &key, now));
    let challenge = service
        .issue_local_token_challenge(&client.client_id, now, &signature)
        .unwrap();
    for _ in 0..128 {
        assert!(matches!(
            service.issue_local_token_challenge(&client.client_id, now, &signature),
            Err(PairingError::BadProof)
        ));
        assert!(matches!(
            service.issue_local_token_challenge(&client.client_id, now, &"ff".repeat(64)),
            Err(PairingError::BadProof)
        ));
    }
    {
        let inner = service.lock();
        assert_eq!(inner.local_challenge_proofs.len(), 1);
        assert_eq!(inner.token_challenges.len(), 1);
        assert!(inner.token_challenges.contains_key(&challenge));
    }
    service
        .issue_local_token_challenge(
            &client.client_id,
            now + 1,
            &hex::encode(local_signature(&client, &key, now + 1)),
        )
        .unwrap();
}

#[test]
fn token_challenges_one_client_cannot_fill_the_replay_memo() {
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), "identity".into(), false).unwrap();
    let (client, key) = local_client(&service, 1);
    let (other, other_key) = local_client(&service, 2);
    let now = chrono::Utc::now().timestamp();
    let signature = local_signature(&client, &key, now);
    service
        .issue_local_token_challenge(&client.client_id, now, &hex::encode(signature))
        .unwrap();
    // Distinct synthetic post-verification inputs model a signer choosing
    // different signing nonces, not just deterministic signatures each second.
    for index in 1..128u64 {
        let mut proof = [0; 64];
        proof[..8].copy_from_slice(&index.to_le_bytes());
        service
            .issue_verified_local_token_challenge(&client, now, proof)
            .unwrap();
    }
    let challenges = service.lock().token_challenges.clone();
    assert!(matches!(
        service.issue_local_token_challenge(
            &client.client_id,
            now + 1,
            &hex::encode(local_signature(&client, &key, now + 1)),
        ),
        Err(PairingError::TooManyPending)
    ));
    assert!(matches!(
        service.issue_local_token_challenge(&client.client_id, now, &hex::encode(signature)),
        Err(PairingError::BadProof)
    ));
    assert_eq!(service.lock().token_challenges, challenges);
    assert_eq!(service.lock().local_challenge_proofs.len(), 128);
    service
        .issue_local_token_challenge(
            &other.client_id,
            now,
            &hex::encode(local_signature(&other, &other_key, now)),
        )
        .unwrap();
    assert_eq!(service.lock().local_challenge_proofs.len(), 129);
}

#[test]
fn token_challenges_memo_saturation_keeps_live_proofs_and_prunes_expired() {
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), "identity".into(), false).unwrap();
    let (client, key) = local_client(&service, 1);
    let now = chrono::Utc::now().timestamp();
    let signature = local_signature(&client, &key, now + 20);
    service
        .issue_local_token_challenge(&client.client_id, now + 20, &hex::encode(signature))
        .unwrap();
    // Flood the post-verification admission path, independently of Ed25519's
    // cost. Its input contract is a verified snapshot and decoded signature;
    // distinct synthetic signatures model many valid proofs at one timestamp.
    for seed in 1..=32 {
        let (holder, _) = local_client(&service, seed);
        let start = if seed == 1 { 1 } else { 0 };
        for index in start..128u64 {
            let mut proof = [0; 64];
            proof[..8].copy_from_slice(&index.to_le_bytes());
            service
                .issue_verified_local_token_challenge(&holder, now + 20, proof)
                .unwrap();
            let inner = service.lock();
            assert!(inner.local_challenge_proofs.len() <= MAX_LOCAL_CHALLENGE_PROOFS);
            assert!(inner.token_challenges.len() <= 16);
        }
        if seed != 1 {
            // Free challenge capacity without forgetting live replay entries.
            service.revoke(&holder.client_id).unwrap();
        }
    }
    let (overflow, overflow_key) = local_client(&service, 33);
    for index in 0..MAX_LOCAL_CHALLENGE_PROOFS {
        let mut proof = [0; 64];
        proof[..8].copy_from_slice(&(index as u64).to_le_bytes());
        assert!(matches!(
            service.issue_verified_local_token_challenge(&overflow, now + 20, proof),
            Err(PairingError::TooManyPending)
        ));
    }
    assert_eq!(
        service.lock().local_challenge_proofs.len(),
        MAX_LOCAL_CHALLENGE_PROOFS
    );
    // Even at saturation, a captured proof is 401, not 429, and cannot evict
    // the newest challenges. A refused fresh proof has no side effects.
    let challenges = service.lock().token_challenges.clone();
    assert!(matches!(
        service.issue_local_token_challenge(&client.client_id, now + 20, &hex::encode(signature)),
        Err(PairingError::BadProof)
    ));
    let fresh = hex::encode(local_signature(&client, &key, now + 21));
    assert!(matches!(
        service.issue_local_token_challenge(&client.client_id, now + 21, &fresh),
        Err(PairingError::TooManyPending)
    ));
    assert!(matches!(
        service.issue_local_token_challenge(
            &overflow.client_id,
            now + 20,
            &hex::encode(local_signature(&overflow, &overflow_key, now + 20))
        ),
        Err(PairingError::TooManyPending)
    ));
    assert_eq!(service.lock().token_challenges, challenges);
    // Age synthetic rows, retaining the real future-dated proof. Admission
    // must prune these before checking capacity, without forgetting that proof.
    {
        let mut inner = service.lock();
        inner.local_challenge_proofs = inner
            .local_challenge_proofs
            .drain()
            .map(|(id, ts, sig)| (id, if sig == signature { ts } else { now - 31 }, sig))
            .collect();
    }
    service
        .issue_local_token_challenge(&client.client_id, now + 21, &fresh)
        .unwrap();
    assert_eq!(service.lock().local_challenge_proofs.len(), 2);
    assert!(matches!(
        service.issue_local_token_challenge(&client.client_id, now + 20, &hex::encode(signature)),
        Err(PairingError::BadProof)
    ));
}

#[test]
fn token_challenges_verification_snapshot_rechecks_authority() {
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), "identity".into(), false).unwrap();
    let (client, key) = local_client(&service, 1);
    let now = chrono::Utc::now().timestamp();
    let signature = local_signature(&client, &key, now);
    // Deterministically place authority changes between verification and
    // admission, using the same snapshot the public method takes.
    service.revoke(&client.client_id).unwrap();
    assert!(matches!(
        service.issue_verified_local_token_challenge(&client, now, signature),
        Err(PairingError::BadProof)
    ));
    let (repaired, _) = local_client(&service, 1);
    assert_ne!(client.epoch, repaired.epoch);
    assert!(matches!(
        service.issue_verified_local_token_challenge(&client, now, signature),
        Err(PairingError::BadProof)
    ));
    service.rebind_to_identity("new-identity").unwrap();
    assert!(matches!(
        service.issue_verified_local_token_challenge(&repaired, now, signature),
        Err(PairingError::BadProof)
    ));
    assert!(service.lock().token_challenges.is_empty());
    assert!(service.lock().local_challenge_proofs.is_empty());
    service
        .issue_local_token_challenge(&client.client_id, now, &hex::encode(signature))
        .unwrap();
    service.revoke(&client.client_id).unwrap();
    local_client(&service, 1);
    // Revocation does not erase an accepted proof, even if the key re-pairs.
    assert!(matches!(
        service.issue_local_token_challenge(&client.client_id, now, &hex::encode(signature)),
        Err(PairingError::BadProof)
    ));
}

#[test]
fn token_challenges_concurrent_local_replay_allocates_once() {
    let dir = tempfile::tempdir().unwrap();
    let service = PairingService::open(dir.path(), "identity".into(), false).unwrap();
    service.open_pairing_window(Duration::from_secs(60));
    let key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
    let client = service
        .create_verified_remote_pairing(
            "client",
            &hex::encode(key.verifying_key().to_bytes()),
            &[1; 32],
        )
        .unwrap();
    let timestamp = chrono::Utc::now().timestamp();
    let message = format!("bitsov-pair-challenge-v1:{}:{timestamp}", client.client_id);
    let signature = hex::encode(key.sign(message.as_bytes()).to_bytes());
    let barrier = std::sync::Barrier::new(8);
    let results = std::thread::scope(|scope| {
        let threads: Vec<_> = (0..8)
            .map(|_| {
                scope.spawn(|| {
                    barrier.wait();
                    service.issue_local_token_challenge(&client.client_id, timestamp, &signature)
                })
            })
            .collect();
        threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(PairingError::BadProof)))
            .count(),
        7
    );
    assert_eq!(service.lock().token_challenges.len(), 1);
}

#[test]
fn token_challenges_self_eviction_keeps_newest_eight_and_other_clients() {
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
    let others: HashMap<_, _> = service
        .lock()
        .token_challenges
        .iter()
        .filter(|(_, (owner, _))| owner != &clients[0])
        .map(|(challenge, entry)| (challenge.clone(), entry.clone()))
        .collect();
    let newest: Vec<_> = (0..16)
        .map(|_| service.issue_token_challenge(&clients[0]).unwrap())
        .collect();
    let inner = service.lock();
    assert_eq!(inner.token_challenges.len(), 128);
    for challenge in &newest[..8] {
        assert!(!inner.token_challenges.contains_key(challenge));
    }
    for challenge in &newest[8..] {
        assert!(inner.token_challenges.contains_key(challenge));
    }
    for (challenge, entry) in others {
        assert_eq!(inner.token_challenges.get(&challenge), Some(&entry));
    }
    drop(inner);
    assert!(matches!(
        service.issue_token_challenge(&clients[16]),
        Err(PairingError::TooManyPending)
    ));
}

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
    // A full client may replace its own oldest even when the pool is full.
    service.issue_token_challenge(&clients[1]).unwrap();
    assert_eq!(service.lock().token_challenges.len(), 128);
}
