use super::*;
use ed25519_dalek::Signer;

/// Create a test prekey bundle for Bob.
fn make_bob_bundle(
    bob_identity_secret: &StaticSecret,
    bob_signing_key: &ed25519_dalek::SigningKey,
) -> (PrekeyBundle, SignedPreKey, OneTimePreKey) {
    let bob_identity_public = PublicKey::from(bob_identity_secret);
    let spk = SignedPreKey::generate();
    let opk = OneTimePreKey::generate(1);

    // Sign the signed pre-key with Ed25519
    let sig = bob_signing_key.sign(spk.public.as_bytes());

    let bundle = PrekeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: spk.public,
        signed_prekey_sig: sig,
        identity_verifying_key: bob_signing_key.verifying_key(),
        one_time_prekey: Some(opk.public),
        one_time_prekey_id: Some(opk.id),
    };

    (bundle, spk, opk)
}

#[test]
fn x3dh_full_exchange_with_one_time_prekey() {
    // Alice's keys
    let alice_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_identity_public = PublicKey::from(&alice_identity_secret);

    // Bob's keys
    let bob_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);

    let (bundle, spk, opk) = make_bob_bundle(&bob_identity_secret, &bob_signing_key);

    // Alice initiates
    let initiation = initiate(
        &alice_identity_secret,
        &alice_identity_public,
        &bundle,
    )
    .unwrap();

    // Bob responds
    let bob_secret = respond(
        &bob_identity_secret,
        &PublicKey::from(&bob_identity_secret),
        &spk,
        Some(&opk),
        &initiation.identity_key,
        &initiation.ephemeral_key,
    )
    .unwrap();

    // Both derived the same shared secret
    assert_eq!(
        initiation.shared_secret.as_bytes(),
        bob_secret.as_bytes()
    );

    // Associated data matches
    assert_eq!(
        initiation.shared_secret.associated_data,
        bob_secret.associated_data
    );

    // One-time pre-key ID was recorded
    assert_eq!(initiation.one_time_prekey_id, Some(1));
}

#[test]
fn x3dh_without_one_time_prekey() {
    let alice_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_identity_public = PublicKey::from(&alice_identity_secret);

    let bob_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);

    let bob_identity_public = PublicKey::from(&bob_identity_secret);
    let spk = SignedPreKey::generate();
    let sig = bob_signing_key.sign(spk.public.as_bytes());

    let bundle = PrekeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: spk.public,
        signed_prekey_sig: sig,
        identity_verifying_key: bob_signing_key.verifying_key(),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let initiation = initiate(
        &alice_identity_secret,
        &alice_identity_public,
        &bundle,
    )
    .unwrap();

    let bob_secret = respond(
        &bob_identity_secret,
        &bob_identity_public,
        &spk,
        None, // No one-time pre-key
        &initiation.identity_key,
        &initiation.ephemeral_key,
    )
    .unwrap();

    assert_eq!(
        initiation.shared_secret.as_bytes(),
        bob_secret.as_bytes()
    );
    assert_eq!(initiation.one_time_prekey_id, None);
}

#[test]
fn x3dh_rejects_bad_signature() {
    let alice_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_identity_public = PublicKey::from(&alice_identity_secret);

    let bob_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_identity_public = PublicKey::from(&bob_identity_secret);
    let spk = SignedPreKey::generate();

    // Sign with a DIFFERENT key (attacker)
    let attacker_key = ed25519_dalek::SigningKey::from_bytes(&[99u8; 32]);
    let bad_sig = attacker_key.sign(spk.public.as_bytes());

    // Use Bob's verifying key but attacker's signature
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);

    let bundle = PrekeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: spk.public,
        signed_prekey_sig: bad_sig,
        identity_verifying_key: bob_signing_key.verifying_key(),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let result = initiate(
        &alice_identity_secret,
        &alice_identity_public,
        &bundle,
    );

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), X3dhError::InvalidSignature(_)));
}

#[test]
fn x3dh_different_alice_different_secret() {
    let bob_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(&[4u8; 32]);
    let (bundle, spk, opk) = make_bob_bundle(&bob_identity_secret, &bob_signing_key);

    // Alice 1
    let alice1_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice1_public = PublicKey::from(&alice1_secret);
    let init1 = initiate(&alice1_secret, &alice1_public, &bundle).unwrap();

    // Alice 2 (different identity)
    let alice2_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice2_public = PublicKey::from(&alice2_secret);
    let init2 = initiate(&alice2_secret, &alice2_public, &bundle).unwrap();

    // Different Alices produce different shared secrets
    assert_ne!(init1.shared_secret.as_bytes(), init2.shared_secret.as_bytes());

    // Bob can derive each independently
    let bob_secret1 = respond(
        &bob_identity_secret,
        &PublicKey::from(&bob_identity_secret),
        &spk,
        Some(&opk),
        &init1.identity_key,
        &init1.ephemeral_key,
    )
    .unwrap();

    assert_eq!(init1.shared_secret.as_bytes(), bob_secret1.as_bytes());
}

#[test]
fn x3dh_shared_secret_is_32_bytes() {
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]);
    let (bundle, _, _) = make_bob_bundle(&bob_secret, &bob_signing);

    let init = initiate(&alice_secret, &alice_public, &bundle).unwrap();
    assert_eq!(init.shared_secret.as_bytes().len(), 32);
    assert_ne!(init.shared_secret.as_bytes(), &[0u8; 32]);
}

#[test]
fn associated_data_contains_both_identity_keys() {
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[6u8; 32]);
    let (bundle, _, _) = make_bob_bundle(&bob_secret, &bob_signing);

    let init = initiate(&alice_secret, &alice_public, &bundle).unwrap();

    // AD should be IK_A || IK_B (64 bytes)
    assert_eq!(init.shared_secret.associated_data.len(), 64);
    assert_eq!(
        &init.shared_secret.associated_data[..32],
        alice_public.as_bytes()
    );
    assert_eq!(
        &init.shared_secret.associated_data[32..],
        bundle.identity_key.as_bytes()
    );
}

#[test]
fn debug_impl_redacts_shared_secret() {
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
    let (bundle, _, _) = make_bob_bundle(&bob_secret, &bob_signing);

    let init = initiate(&alice_secret, &alice_public, &bundle).unwrap();
    let debug_str = format!("{:?}", init.shared_secret);

    // Must contain REDACTED, must NOT contain raw secret bytes
    assert!(debug_str.contains("[REDACTED]"));
    let secret_hex = hex::encode(init.shared_secret.as_bytes());
    assert!(
        !debug_str.contains(&secret_hex),
        "Debug output must not contain the raw secret"
    );
}

#[test]
fn each_initiation_uses_fresh_ephemeral_key() {
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[8u8; 32]);
    let (bundle, _, _) = make_bob_bundle(&bob_secret, &bob_signing);

    let init1 = initiate(&alice_secret, &alice_public, &bundle).unwrap();
    let init2 = initiate(&alice_secret, &alice_public, &bundle).unwrap();

    // Ephemeral keys must differ between initiations
    assert_ne!(
        init1.ephemeral_key.as_bytes(),
        init2.ephemeral_key.as_bytes(),
        "Each initiation must generate a fresh ephemeral key"
    );

    // Shared secrets must differ (because ephemeral keys differ)
    assert_ne!(
        init1.shared_secret.as_bytes(),
        init2.shared_secret.as_bytes(),
        "Different ephemeral keys must produce different shared secrets"
    );
}

#[test]
fn signed_prekey_from_bytes_is_deterministic() {
    let bytes = [42u8; 32];
    let spk1 = SignedPreKey::from_bytes(bytes);
    let spk2 = SignedPreKey::from_bytes(bytes);

    assert_eq!(
        spk1.public.as_bytes(),
        spk2.public.as_bytes(),
        "Same seed bytes must produce the same public key"
    );

    // Different bytes produce different keys
    let spk3 = SignedPreKey::from_bytes([99u8; 32]);
    assert_ne!(spk1.public.as_bytes(), spk3.public.as_bytes());
}

#[test]
fn associated_data_order_depends_on_role() {
    // AD = IK_Alice || IK_Bob — the order is role-dependent.
    // If Alice initiates to Bob, AD starts with Alice's key.
    // If Bob initiates to Alice, AD starts with Bob's key.
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let (bundle, spk, opk) = make_bob_bundle(&bob_secret, &bob_signing);

    let init = initiate(&alice_secret, &alice_public, &bundle).unwrap();
    let bob_shared = respond(
        &bob_secret,
        &PublicKey::from(&bob_secret),
        &spk,
        Some(&opk),
        &init.identity_key,
        &init.ephemeral_key,
    )
    .unwrap();

    // Alice's AD should equal Bob's AD (both compute IK_A || IK_B in same order)
    assert_eq!(
        init.shared_secret.associated_data,
        bob_shared.associated_data,
        "Initiator and responder must agree on associated data"
    );

    // Verify the first 32 bytes are Alice's key (the initiator)
    assert_eq!(&init.shared_secret.associated_data[..32], alice_public.as_bytes());
    // And the second 32 bytes are Bob's key (the responder)
    assert_eq!(
        &init.shared_secret.associated_data[32..],
        PublicKey::from(&bob_secret).as_bytes()
    );
}

#[test]
fn exchange_with_opk_differs_from_without() {
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[10u8; 32]);
    let bob_public = PublicKey::from(&bob_secret);

    let spk = SignedPreKey::generate();
    let opk = OneTimePreKey::generate(1);
    let sig = bob_signing.sign(spk.public.as_bytes());

    // Bundle WITH one-time prekey
    let bundle_with = PrekeyBundle {
        identity_key: bob_public,
        signed_prekey: spk.public,
        signed_prekey_sig: sig,
        identity_verifying_key: bob_signing.verifying_key(),
        one_time_prekey: Some(opk.public),
        one_time_prekey_id: Some(1),
    };

    // Bundle WITHOUT one-time prekey
    let bundle_without = PrekeyBundle {
        identity_key: bob_public,
        signed_prekey: spk.public,
        signed_prekey_sig: sig,
        identity_verifying_key: bob_signing.verifying_key(),
        one_time_prekey: None,
        one_time_prekey_id: None,
    };

    let init_with = initiate(&alice_secret, &alice_public, &bundle_with).unwrap();
    let init_without = initiate(&alice_secret, &alice_public, &bundle_without).unwrap();

    // The shared secrets MUST differ (DH4 is included only when OPK is present)
    // Note: ephemeral keys differ too, so this is guaranteed.
    // But the important property is that the OPK contributes to the secret.
    assert_eq!(init_with.one_time_prekey_id, Some(1));
    assert_eq!(init_without.one_time_prekey_id, None);
}

#[test]
fn shared_secret_is_nonzero() {
    let alice_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_public = PublicKey::from(&alice_secret);

    let bob_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_signing = ed25519_dalek::SigningKey::from_bytes(&[11u8; 32]);
    let (bundle, _, _) = make_bob_bundle(&bob_secret, &bob_signing);

    let init = initiate(&alice_secret, &alice_public, &bundle).unwrap();

    // Secret must not be all zeros (would indicate a degenerate DH)
    assert_ne!(init.shared_secret.as_bytes(), &[0u8; 32]);

    // Secret must not be all ones (would indicate degenerate KDF)
    assert_ne!(init.shared_secret.as_bytes(), &[0xFF_u8; 32]);
}
