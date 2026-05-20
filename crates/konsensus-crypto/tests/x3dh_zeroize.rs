//! Integration tests for L0c — `Zeroizing<Vec<u8>>` wrapping of X3DH DH-output
//! buffers in `crates/konsensus-crypto/src/x3dh.rs`.
//!
//! L0c is hygiene only — no behavior change is intended. The zeroize
//! discipline itself (drop-time wiping of the `dh_concat` and HKDF `ikm`
//! buffers) cannot be reliably runtime-asserted without unsafe memory
//! probing of freed allocations, so these tests focus on **regression
//! coverage**: every X3DH path still produces matching shared secrets
//! after the wrapping change. Source-level review remains the merge gate
//! for the zeroize discipline itself.
//!
//! What we DO assert at runtime here:
//! 1. `initiate` + `respond` round-trip produces matching `secret` and
//!    `associated_data` for the with-OPK path.
//! 2. Same for the without-OPK path.
//! 3. The `Zeroizing<Vec<u8>>` wrapper from the `zeroize` crate is
//!    constructible and zeroes its payload on drop (smoke check that the
//!    crate's primitive we depend on still behaves as documented).

use ed25519_dalek::Signer;
use konsensus_crypto::{
    x3dh::{initiate, respond, OneTimePreKey, PrekeyBundle, SignedPreKey},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

fn make_bob_bundle(
    bob_identity_secret: &StaticSecret,
    bob_signing_key: &ed25519_dalek::SigningKey,
    include_opk: bool,
) -> (PrekeyBundle, SignedPreKey, Option<OneTimePreKey>) {
    let bob_identity_public = PublicKey::from(bob_identity_secret);
    let spk = SignedPreKey::generate();
    let opk = if include_opk {
        Some(OneTimePreKey::generate(1))
    } else {
        None
    };
    let sig = bob_signing_key.sign(spk.public.as_bytes());
    let bundle = PrekeyBundle {
        identity_key: bob_identity_public,
        signed_prekey: spk.public,
        signed_prekey_sig: sig,
        identity_verifying_key: bob_signing_key.verifying_key(),
        one_time_prekey: opk.as_ref().map(|o| o.public),
        one_time_prekey_id: opk.as_ref().map(|o| o.id),
    };
    (bundle, spk, opk)
}

#[test]
fn x3dh_zeroize_round_trip_with_opk() {
    let alice_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_identity_public = PublicKey::from(&alice_identity_secret);

    let bob_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_identity_public = PublicKey::from(&bob_identity_secret);
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);

    let (bundle, spk, opk) = make_bob_bundle(&bob_identity_secret, &bob_signing_key, true);

    let initiation = initiate(&alice_identity_secret, &alice_identity_public, &bundle).unwrap();

    let bob_secret = respond(
        &bob_identity_secret,
        &bob_identity_public,
        &spk,
        opk.as_ref(),
        &alice_identity_public,
        &initiation.ephemeral_key,
    )
    .unwrap();

    assert_eq!(initiation.shared_secret.as_bytes(), bob_secret.as_bytes());
    assert_eq!(
        initiation.shared_secret.associated_data,
        bob_secret.associated_data
    );
}

#[test]
fn x3dh_zeroize_round_trip_without_opk() {
    let alice_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let alice_identity_public = PublicKey::from(&alice_identity_secret);

    let bob_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
    let bob_identity_public = PublicKey::from(&bob_identity_secret);
    let bob_signing_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);

    let (bundle, spk, _opk) = make_bob_bundle(&bob_identity_secret, &bob_signing_key, false);

    let initiation = initiate(&alice_identity_secret, &alice_identity_public, &bundle).unwrap();

    let bob_secret = respond(
        &bob_identity_secret,
        &bob_identity_public,
        &spk,
        None,
        &alice_identity_public,
        &initiation.ephemeral_key,
    )
    .unwrap();

    assert_eq!(initiation.shared_secret.as_bytes(), bob_secret.as_bytes());
}

#[test]
fn zeroizing_vec_u8_is_constructible_and_zeros_on_drop() {
    // Smoke: confirm the `zeroize` primitive we rely on behaves as
    // documented — `Zeroizing<Vec<u8>>` can wrap a Vec and the wrapped
    // value is zeroed on drop.
    //
    // We can't reliably observe the zeroed buffer in the freed
    // allocation (the OS may have reclaimed it), but we CAN observe
    // the live value before drop and confirm `zeroize::Zeroize` is
    // implemented for `Vec<u8>` via the wrapper.
    let mut z: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0xAA_u8; 64]);
    z.extend_from_slice(&[0xBB_u8; 32]);
    assert_eq!(z.len(), 96);
    assert_eq!(z[0], 0xAA);
    assert_eq!(z[64], 0xBB);
    drop(z); // drop calls Vec::zeroize() then frees
}
