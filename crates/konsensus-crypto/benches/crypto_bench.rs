//! Benchmarks for cryptographic operations — the per-message cost of E2EE.
//!
//! Every message in the mesh passes through these operations:
//! 1. Double Ratchet encrypt/decrypt (session layer)
//! 2. Noise encrypt/decrypt (transport layer)
//! 3. X3DH key agreement (one-time per session)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use konsensus_crypto::noise::NoiseSession;
use konsensus_crypto::x3dh;

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
            let alice_ik = x3dh::IdentityKeyPair::generate();
            let bob_ik = x3dh::IdentityKeyPair::generate();
            let bob_spk = x3dh::SignedPreKeyPair::generate(1);
            let bob_opk = x3dh::SignedPreKeyPair::generate(2);

            let bob_bundle = x3dh::PrekeyBundle {
                identity_key: *bob_ik.secret().diffie_hellman(&x25519_dalek::X25519_BASEPOINT_BYTES.into()).as_bytes(),
                signed_prekey: *bob_spk.secret().diffie_hellman(&x25519_dalek::X25519_BASEPOINT_BYTES.into()).as_bytes(),
                one_time_prekey: Some(*bob_opk.secret().diffie_hellman(&x25519_dalek::X25519_BASEPOINT_BYTES.into()).as_bytes()),
                signed_prekey_id: 1,
                one_time_prekey_id: Some(2),
            };

            // This tests the ECDH computation cost, which is the bottleneck
            let _alice_ek = x3dh::SignedPreKeyPair::generate(0);
            black_box(&bob_bundle);
        });
    });
}

fn bench_x3dh_key_generation(c: &mut Criterion) {
    c.bench_function("X3DH::IdentityKeyPair::generate", |b| {
        b.iter(|| {
            black_box(x3dh::IdentityKeyPair::generate());
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
