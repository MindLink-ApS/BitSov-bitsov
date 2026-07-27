//! Benchmarks for cryptographic operations — the per-message cost of E2EE.
//!
//! Every message in the mesh passes through these operations:
//! 1. Double Ratchet encrypt/decrypt (session layer)
//! 2. Noise encrypt/decrypt (transport layer)
//! 3. X3DH key agreement (one-time per session)

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::Signer;
use konsensus_crypto::noise::NoiseSession;
use konsensus_crypto::x3dh::{self, OneTimePreKey, SignedPreKey};
use x25519_dalek::{PublicKey, StaticSecret};

/// Complete a Noise_XX handshake between two sessions, returning transport-ready sessions.
fn make_noise_pair() -> (NoiseSession, NoiseSession) {
    let key_a: [u8; 32] = rand::random();
    let key_b: [u8; 32] = rand::random();

    let mut initiator = NoiseSession::initiator(&key_a).expect("init");
    let mut responder = NoiseSession::responder(&key_b).expect("resp");

    // XX handshake: 3 messages
    let msg1 = initiator.write_handshake(&[]).expect("hs1");
    responder.read_handshake(&msg1).expect("hs1r");

    let msg2 = responder.write_handshake(&[]).expect("hs2");
    initiator.read_handshake(&msg2).expect("hs2r");

    let msg3 = initiator.write_handshake(&[]).expect("hs3");
    responder.read_handshake(&msg3).expect("hs3r");

    initiator.try_finish_handshake().expect("fin");
    responder.try_finish_handshake().expect("fin");

    (initiator, responder)
}

fn bench_noise_handshake(c: &mut Criterion) {
    c.bench_function("Noise_XX handshake (full 3-message)", |b| {
        b.iter(|| {
            black_box(make_noise_pair());
        });
    });
}

fn bench_noise_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("Noise::encrypt");

    for size in [64, 256, 1024, 4096, 65000] {
        let (mut enc, _dec) = make_noise_pair();
        let plaintext = vec![0xAB; size];

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size}B")),
            &plaintext,
            |b, pt| {
                b.iter(|| {
                    black_box(enc.encrypt(black_box(pt)).expect("encrypt"));
                });
            },
        );
    }
    group.finish();
}

fn bench_noise_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("Noise::decrypt");

    for size in [64, 256, 1024, 4096, 65000] {
        let (mut enc, mut dec) = make_noise_pair();
        let plaintext = vec![0xAB; size];
        let ciphertext = enc.encrypt(&plaintext).expect("encrypt");

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{size}B")),
            &ciphertext,
            |b, ct| {
                b.iter(|| {
                    black_box(dec.decrypt(black_box(ct)).expect("decrypt"));
                });
            },
        );
    }
    group.finish();
}

fn bench_noise_encrypt_large_chunked(c: &mut Criterion) {
    let (mut enc, _dec) = make_noise_pair();
    let plaintext = vec![0xAB; 256 * 1024]; // 256KB — triggers chunking

    c.bench_function("Noise::encrypt (256KB, chunked)", |b| {
        b.iter(|| {
            black_box(enc.encrypt(black_box(&plaintext)).expect("encrypt"));
        });
    });
}

fn bench_noise_roundtrip(c: &mut Criterion) {
    let (mut enc, mut dec) = make_noise_pair();
    let plaintext = vec![0xAB; 256]; // Typical chat message

    c.bench_function("Noise::encrypt+decrypt roundtrip (256B)", |b| {
        b.iter(|| {
            let ct = enc.encrypt(black_box(&plaintext)).expect("encrypt");
            black_box(dec.decrypt(&ct).expect("decrypt"));
        });
    });
}

fn bench_x3dh_key_agreement(c: &mut Criterion) {
    c.bench_function("X3DH key agreement (initiate + respond)", |b| {
        b.iter(|| {
            let alice_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
            let alice_identity_public = PublicKey::from(&alice_identity_secret);
            let bob_identity_secret = StaticSecret::random_from_rng(rand::thread_rng());
            let bob_identity_public = PublicKey::from(&bob_identity_secret);
            let bob_signing_key = ed25519_dalek::SigningKey::generate(&mut rand::thread_rng());
            let bob_spk = SignedPreKey::generate();
            let bob_opk = OneTimePreKey::generate(2);

            let signed_prekey_sig = bob_signing_key.sign(bob_spk.public.as_bytes());
            let bob_bundle = x3dh::PrekeyBundle {
                identity_key: bob_identity_public,
                signed_prekey: bob_spk.public,
                signed_prekey_sig,
                identity_verifying_key: bob_signing_key.verifying_key(),
                one_time_prekey: Some(bob_opk.public),
                one_time_prekey_id: Some(bob_opk.id),
            };

            let initiation =
                x3dh::initiate(&alice_identity_secret, &alice_identity_public, &bob_bundle)
                    .expect("initiate");
            let response = x3dh::respond(
                &bob_identity_secret,
                &bob_identity_public,
                &bob_spk,
                Some(&bob_opk),
                &initiation.identity_key,
                &initiation.ephemeral_key,
            )
            .expect("respond");
            black_box((initiation.shared_secret, response));
        });
    });
}

fn bench_x3dh_key_generation(c: &mut Criterion) {
    c.bench_function("X3DH::StaticSecret::random_from_rng", |b| {
        b.iter(|| {
            black_box(StaticSecret::random_from_rng(rand::thread_rng()));
        });
    });
}

criterion_group!(
    benches,
    bench_noise_handshake,
    bench_noise_encrypt,
    bench_noise_decrypt,
    bench_noise_encrypt_large_chunked,
    bench_noise_roundtrip,
    bench_x3dh_key_agreement,
    bench_x3dh_key_generation,
);
criterion_main!(benches);
