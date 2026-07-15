//! Benchmarks for UKM envelope operations — serialization, signing, verification, gate.
//!
//! These are the hot-path operations for every message in the mesh.
//! Target: <1ms per message at scale on commodity hardware.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use ed25519_dalek::Verifier;
use konsensus_core::{
    NodeId, NodeIdentity, Nonce, PaymentProof, Recipient, Signature, UkmEnvelope,
    UkmEnvelopeBuilder,
};
use sha2::{Digest, Sha256};

fn make_test_identity() -> NodeIdentity {
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    NodeIdentity::from_mnemonic(mnemonic, "").expect("valid mnemonic")
}

fn make_valid_proof(amount_msat: u64) -> PaymentProof {
    let preimage: [u8; 32] = rand::random();
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    PaymentProof {
        payment_hash,
        preimage,
        amount_msat,
    }
}

fn make_test_envelope(identity: &NodeIdentity) -> UkmEnvelope {
    let ciphertext = vec![0xAB; 256]; // Typical chat message size
    let proof = make_valid_proof(25);
    let mut envelope = UkmEnvelopeBuilder::new(
        100, // KIND_CHAT
        *identity.node_id(),
        Recipient::Node(NodeId::from_bytes([0x01; 32])),
        ciphertext,
        proof,
    )
    .build();
    let sig = identity.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);
    envelope
}

fn bench_envelope_sign(c: &mut Criterion) {
    let identity = make_test_identity();
    let proof = make_valid_proof(25);
    let ciphertext = vec![0xAB; 256];

    c.bench_function("UkmEnvelope::sign (256B payload)", |b| {
        b.iter(|| {
            let mut envelope = UkmEnvelopeBuilder::new(
                100,
                *identity.node_id(),
                Recipient::Node(NodeId::from_bytes([0x01; 32])),
                ciphertext.clone(),
                proof.clone(),
            )
            .build();
            let sig = identity.sign(&envelope.signable_bytes());
            envelope.signature = Signature::from_ed25519(&sig);
            black_box(envelope);
        });
    });
}

fn bench_envelope_verify(c: &mut Criterion) {
    let identity = make_test_identity();
    let envelope = make_test_envelope(&identity);

    c.bench_function("UkmEnvelope::verify_signature", |b| {
        b.iter(|| {
            let signable = envelope.signable_bytes();
            let sig = envelope.signature.to_ed25519();
            black_box(
                envelope
                    .sender
                    .to_verifying_key()
                    .expect("valid node id")
                    .verify(&signable, &sig),
            )
            .expect("verify");
        });
    });
}

fn bench_envelope_serialize(c: &mut Criterion) {
    let identity = make_test_identity();
    let envelope = make_test_envelope(&identity);

    c.bench_function("UkmEnvelope::serialize (JSON)", |b| {
        b.iter(|| {
            black_box(serde_json::to_vec(&envelope).expect("serialize"));
        });
    });
}

fn bench_envelope_deserialize(c: &mut Criterion) {
    let identity = make_test_identity();
    let envelope = make_test_envelope(&identity);
    let json = serde_json::to_vec(&envelope).expect("serialize");

    c.bench_function("UkmEnvelope::deserialize (JSON)", |b| {
        b.iter(|| {
            black_box(serde_json::from_slice::<UkmEnvelope>(&json).expect("deserialize"));
        });
    });
}

fn bench_envelope_signable_bytes(c: &mut Criterion) {
    let identity = make_test_identity();
    let envelope = make_test_envelope(&identity);

    c.bench_function("UkmEnvelope::signable_bytes", |b| {
        b.iter(|| {
            black_box(envelope.signable_bytes());
        });
    });
}

fn bench_envelope_serialize_large(c: &mut Criterion) {
    let identity = make_test_identity();
    let proof = make_valid_proof(100);
    let ciphertext = vec![0xAB; 4096]; // 4KB payload (file transfer)
    let mut envelope = UkmEnvelopeBuilder::new(
        200, // KIND_FILE_REF
        *identity.node_id(),
        Recipient::Node(NodeId::from_bytes([0x01; 32])),
        ciphertext,
        proof,
    )
    .build();
    let sig = identity.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);

    c.bench_function("UkmEnvelope::serialize (4KB payload)", |b| {
        b.iter(|| {
            black_box(serde_json::to_vec(&envelope).expect("serialize"));
        });
    });
}

fn bench_payment_proof_verify(c: &mut Criterion) {
    let proof = make_valid_proof(25);

    c.bench_function("PaymentProof::verify (SHA256 preimage check)", |b| {
        b.iter(|| {
            let hash: [u8; 32] = Sha256::digest(black_box(&proof.preimage)).into();
            black_box(hash == proof.payment_hash);
        });
    });
}

fn bench_identity_creation(c: &mut Criterion) {
    c.bench_function("NodeIdentity::from_mnemonic", |b| {
        b.iter(|| {
            let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
            black_box(NodeIdentity::from_mnemonic(mnemonic, "").expect("valid"));
        });
    });
}

fn bench_nonce_generation(c: &mut Criterion) {
    c.bench_function("Nonce::generate", |b| {
        b.iter(|| {
            black_box(Nonce::generate());
        });
    });
}

criterion_group!(
    benches,
    bench_envelope_sign,
    bench_envelope_verify,
    bench_envelope_serialize,
    bench_envelope_deserialize,
    bench_envelope_signable_bytes,
    bench_envelope_serialize_large,
    bench_payment_proof_verify,
    bench_identity_creation,
    bench_nonce_generation,
);
criterion_main!(benches);
