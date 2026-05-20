//! Hardening tests for konsensus-core — wire protocol framing edge cases,
//! envelope validation boundaries, kind taxonomy coverage, federation signing
//! edge cases, and type serialization robustness.

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::error::CoreError;
use konsensus_core::federation::SignedMessage;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::kind::*;
use konsensus_core::types::*;
use konsensus_core::UkmEnvelopeBuilder;
use sha2::{Digest, Sha256};

const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

// ═══════════════════════════════════════════════════════════════════════════════
// ENVELOPE VALIDATION
// ═══════════════════════════════════════════════════════════════════════════════

fn make_valid_proof() -> (PaymentProof, [u8; 32]) {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    (PaymentProof::new(hash, preimage, 100), preimage)
}

fn make_valid_envelope() -> UkmEnvelope {
    let (proof, _) = make_valid_proof();
    UkmEnvelopeBuilder::new(
        KIND_CHAT,
        NodeId::from_bytes([1u8; 32]),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        b"encrypted content".to_vec(),
        proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build()
}

#[test]
fn envelope_validate_passes_for_valid_envelope() {
    let env = make_valid_envelope();
    env.validate().expect("valid envelope must pass validation");
    // Verify computed message ID matches expected blake3(ciphertext || nonce)
    assert_eq!(env.id, MessageId::compute(&env.ciphertext, &env.nonce));
    assert!(!env.ciphertext.is_empty());
}

#[test]
fn envelope_validate_rejects_empty_ciphertext() {
    let (proof, _) = make_valid_proof();
    let env = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        NodeId::from_bytes([1u8; 32]),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        Vec::new(), // Empty ciphertext
        proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build();

    let err = env.validate().unwrap_err();
    assert!(matches!(err, CoreError::EnvelopeValidation(_)));
}

#[test]
fn envelope_validate_rejects_wrong_preimage() {
    let preimage = [42u8; 32];
    let wrong_preimage = [99u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    // Hash from preimage A but preimage from B
    let bad_proof = PaymentProof::new(hash, wrong_preimage, 100);

    let env = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        NodeId::from_bytes([1u8; 32]),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        b"content".to_vec(),
        bad_proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build();

    let err = env.validate().unwrap_err();
    assert!(matches!(err, CoreError::InvalidPaymentProof(_)));
}

#[test]
fn envelope_validate_rejects_tampered_id() {
    let mut env = make_valid_envelope();
    // Tamper with the ID — should fail because id != blake3(ciphertext || nonce)
    env.id = MessageId::from_bytes([0xFF; 32]);
    let err = env.validate().unwrap_err();
    assert!(matches!(err, CoreError::EnvelopeValidation(_)));
}

#[test]
fn envelope_signable_bytes_deterministic() {
    let env = make_valid_envelope();
    let sb1 = env.signable_bytes();
    let sb2 = env.signable_bytes();
    assert_eq!(sb1, sb2, "signable_bytes must be deterministic");
}

#[test]
fn envelope_signable_bytes_differ_by_kind() {
    let (proof, _) = make_valid_proof();
    let env1 = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        NodeId::from_bytes([1u8; 32]),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        b"same content".to_vec(),
        proof.clone(),
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build();

    let env2 = UkmEnvelopeBuilder::new(
        KIND_LONGFORM, // Different kind
        NodeId::from_bytes([1u8; 32]),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        b"same content".to_vec(),
        proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build();

    assert_ne!(
        env1.signable_bytes(),
        env2.signable_bytes(),
        "different kinds must produce different signable bytes"
    );
}

#[test]
fn envelope_signable_bytes_differ_by_recipient_type() {
    let (proof, _) = make_valid_proof();

    let node_recipient = Recipient::Node(NodeId::from_bytes([2u8; 32]));
    let room_recipient = Recipient::Room(RoomId::new());

    let env1 = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        NodeId::from_bytes([1u8; 32]),
        node_recipient,
        b"content".to_vec(),
        proof.clone(),
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build();

    let env2 = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        NodeId::from_bytes([1u8; 32]),
        room_recipient,
        b"content".to_vec(),
        proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build();

    assert_ne!(
        env1.signable_bytes(),
        env2.signable_bytes(),
        "node vs room recipient must produce different signable bytes"
    );
}

#[test]
fn envelope_large_ciphertext_validates() {
    let (proof, _) = make_valid_proof();
    let large_ct = vec![0xAB; 1024 * 1024]; // 1 MiB
    let env = UkmEnvelopeBuilder::new(
        KIND_FILE_REF,
        NodeId::from_bytes([1u8; 32]),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        large_ct,
        proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .build();

    env.validate().expect("large ciphertext envelope must pass validation");
    assert_eq!(env.ciphertext.len(), 1024 * 1024);
    assert_eq!(env.kind, KIND_FILE_REF);
}

#[test]
fn envelope_serde_roundtrip() {
    let env = make_valid_envelope();
    let json = serde_json::to_string(&env).unwrap();
    let decoded: UkmEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(env, decoded);
}

#[test]
fn envelope_serde_with_references() {
    let (proof, _) = make_valid_proof();
    let ref_id = MessageId::from_bytes([0xAA; 32]);
    let env = UkmEnvelopeBuilder::new(
        KIND_REPLY,
        NodeId::from_bytes([1u8; 32]),
        Recipient::Node(NodeId::from_bytes([2u8; 32])),
        b"reply".to_vec(),
        proof,
    )
    .timestamp(1_700_000_000_000)
    .signature(Signature::from_bytes([0u8; 64]))
    .nonce(Nonce::from_bytes([5u8; 24]))
    .references(vec![ref_id])
    .build();

    let json = serde_json::to_string(&env).unwrap();
    let decoded: UkmEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.references.len(), 1);
    assert_eq!(decoded.references[0], ref_id);
}

// ═══════════════════════════════════════════════════════════════════════════════
// KIND TAXONOMY — FULL RANGE COVERAGE
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn kind_category_boundary_values() {
    // Communication boundaries
    assert_eq!(KindCategory::from_kind(0), KindCategory::Communication);
    assert_eq!(KindCategory::from_kind(99), KindCategory::Communication);

    // StructuredData boundaries
    assert_eq!(KindCategory::from_kind(100), KindCategory::StructuredData);
    assert_eq!(KindCategory::from_kind(199), KindCategory::StructuredData);

    // FilesMedia boundaries
    assert_eq!(KindCategory::from_kind(200), KindCategory::FilesMedia);
    assert_eq!(KindCategory::from_kind(299), KindCategory::FilesMedia);

    // Collaboration boundaries
    assert_eq!(KindCategory::from_kind(300), KindCategory::Collaboration);
    assert_eq!(KindCategory::from_kind(399), KindCategory::Collaboration);

    // RealTimeSignaling boundaries
    assert_eq!(KindCategory::from_kind(400), KindCategory::RealTimeSignaling);
    assert_eq!(KindCategory::from_kind(499), KindCategory::RealTimeSignaling);

    // WebContent boundaries
    assert_eq!(KindCategory::from_kind(500), KindCategory::WebContent);
    assert_eq!(KindCategory::from_kind(599), KindCategory::WebContent);

    // Control boundaries
    assert_eq!(KindCategory::from_kind(900), KindCategory::Control);
    assert_eq!(KindCategory::from_kind(999), KindCategory::Control);

    // AppExtension boundaries
    assert_eq!(KindCategory::from_kind(1000), KindCategory::AppExtension);
    assert_eq!(KindCategory::from_kind(u16::MAX), KindCategory::AppExtension);
}

#[test]
fn kind_category_gap_ranges_are_unknown() {
    // 600-899 are unassigned — should be Unknown
    for kind in [600, 700, 800, 899] {
        assert_eq!(
            KindCategory::from_kind(kind),
            KindCategory::Unknown,
            "kind {kind} should be Unknown"
        );
    }
}

#[test]
fn kind_constants_are_in_correct_category() {
    // Communication
    assert_eq!(KindCategory::from_kind(KIND_CHAT), KindCategory::Communication);
    assert_eq!(KindCategory::from_kind(KIND_LONGFORM), KindCategory::Communication);
    assert_eq!(KindCategory::from_kind(KIND_REPLY), KindCategory::Communication);
    assert_eq!(KindCategory::from_kind(KIND_REACTION), KindCategory::Communication);
    assert_eq!(KindCategory::from_kind(KIND_EDIT), KindCategory::Communication);
    assert_eq!(KindCategory::from_kind(KIND_DELETE), KindCategory::Communication);
    assert_eq!(KindCategory::from_kind(KIND_FORWARD), KindCategory::Communication);

    // Structured data
    assert_eq!(KindCategory::from_kind(KIND_CALENDAR_EVENT), KindCategory::StructuredData);
    assert_eq!(KindCategory::from_kind(KIND_RSVP), KindCategory::StructuredData);
    assert_eq!(KindCategory::from_kind(KIND_CONTACT), KindCategory::StructuredData);
    assert_eq!(KindCategory::from_kind(KIND_PROFILE), KindCategory::StructuredData);
    assert_eq!(KindCategory::from_kind(KIND_CALENDAR_UPDATE), KindCategory::StructuredData);

    // Files
    assert_eq!(KindCategory::from_kind(KIND_FILE_REF), KindCategory::FilesMedia);
    assert_eq!(KindCategory::from_kind(KIND_INLINE_IMAGE), KindCategory::FilesMedia);
    assert_eq!(KindCategory::from_kind(KIND_VOICE_MEMO), KindCategory::FilesMedia);

    // Collaboration
    assert_eq!(KindCategory::from_kind(KIND_CRDT_OP), KindCategory::Collaboration);
    assert_eq!(KindCategory::from_kind(KIND_DOC_SNAPSHOT), KindCategory::Collaboration);

    // Web content
    assert_eq!(KindCategory::from_kind(KIND_PAGE_REQUEST), KindCategory::WebContent);
    assert_eq!(KindCategory::from_kind(KIND_PAGE_RESPONSE), KindCategory::WebContent);
    assert_eq!(KindCategory::from_kind(KIND_WEB_MANIFEST), KindCategory::WebContent);

    // Control
    assert_eq!(KindCategory::from_kind(KIND_TYPING), KindCategory::Control);
    assert_eq!(KindCategory::from_kind(KIND_READ_RECEIPT), KindCategory::Control);
    assert_eq!(KindCategory::from_kind(KIND_PRESENCE), KindCategory::Control);
    assert_eq!(KindCategory::from_kind(KIND_ROOM_CREATE), KindCategory::Control);
    assert_eq!(KindCategory::from_kind(KIND_KEY_EXCHANGE), KindCategory::Control);
    assert_eq!(KindCategory::from_kind(KIND_MLS_WELCOME), KindCategory::Control);
}

// ═══════════════════════════════════════════════════════════════════════════════
// TYPE SYSTEM HARDENING
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn node_id_from_hex_rejects_short_input() {
    assert!(NodeId::from_hex("abcdef").is_err());
}

#[test]
fn node_id_from_hex_rejects_odd_length() {
    let err = NodeId::from_hex(&"a".repeat(63)).unwrap_err();
    assert!(matches!(err, CoreError::HexDecode(_)));
}

#[test]
fn node_id_from_hex_rejects_invalid_chars() {
    // 64 chars but contains non-hex 'g'
    let mut bad = "a".repeat(63);
    bad.push('g');
    let err = NodeId::from_hex(&bad).unwrap_err();
    assert!(matches!(err, CoreError::HexDecode(_)));
}

#[test]
fn node_id_from_hex_accepts_valid_64char_hex() {
    let hex = "ab".repeat(32);
    let node_id = NodeId::from_hex(&hex).unwrap();
    assert_eq!(node_id, NodeId::from_bytes([0xAB; 32]));
}

#[test]
fn node_id_hex_roundtrip() {
    let original = NodeId::from_bytes([0xAB; 32]);
    let hex = original.to_hex();
    let decoded = NodeId::from_hex(&hex).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn node_id_display_is_hex() {
    let id = NodeId::from_bytes([0x00; 32]);
    let display = format!("{id}");
    assert_eq!(display.len(), 64);
    assert!(display.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn message_id_compute_is_deterministic() {
    let ct = b"test ciphertext";
    let nonce = Nonce::from_bytes([1u8; 24]);
    let id1 = MessageId::compute(ct, &nonce);
    let id2 = MessageId::compute(ct, &nonce);
    assert_eq!(id1, id2);
}

#[test]
fn message_id_differs_with_different_nonce() {
    let ct = b"test ciphertext";
    let n1 = Nonce::from_bytes([1u8; 24]);
    let n2 = Nonce::from_bytes([2u8; 24]);
    assert_ne!(MessageId::compute(ct, &n1), MessageId::compute(ct, &n2));
}

#[test]
fn message_id_differs_with_different_ciphertext() {
    let nonce = Nonce::from_bytes([1u8; 24]);
    assert_ne!(
        MessageId::compute(b"aaa", &nonce),
        MessageId::compute(b"bbb", &nonce)
    );
}

#[test]
fn message_id_hex_roundtrip() {
    let nonce = Nonce::from_bytes([7u8; 24]);
    let id = MessageId::compute(b"test", &nonce);
    let hex = id.to_hex();
    let decoded = MessageId::from_hex(&hex).unwrap();
    assert_eq!(id, decoded);
}

#[test]
fn nonce_generate_unique() {
    let n1 = Nonce::generate();
    let n2 = Nonce::generate();
    assert_ne!(n1, n2, "sequential nonces should be unique");
}

#[test]
fn nonce_serde_roundtrip() {
    let nonce = Nonce::from_bytes([42u8; 24]);
    let json = serde_json::to_string(&nonce).unwrap();
    let decoded: Nonce = serde_json::from_str(&json).unwrap();
    assert_eq!(nonce, decoded);
}

#[test]
fn payment_proof_verify_correct_preimage() {
    let preimage = [0x55u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 100);
    proof.verify_preimage().expect("valid preimage must pass verification");
}

#[test]
fn payment_proof_verify_wrong_preimage() {
    let preimage = [0x55u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let wrong = [0xAAu8; 32];
    let proof = PaymentProof::new(hash, wrong, 100);
    let err = proof.verify_preimage().unwrap_err();
    assert!(matches!(err, CoreError::InvalidPaymentProof(_)));
}

#[test]
fn payment_proof_zero_amount_valid_if_preimage_matches() {
    let preimage = [0x11u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 0);
    // Zero amount is structurally valid — price enforcement is gate's job
    proof.verify_preimage().expect("zero-amount proof with valid preimage must pass");
    assert_eq!(proof.amount_msat, 0);
}

#[test]
fn room_id_generate_unique() {
    let r1 = RoomId::new();
    let r2 = RoomId::new();
    assert_ne!(r1, r2);
}

#[test]
fn room_id_serde_roundtrip() {
    let id = RoomId::new();
    let json = serde_json::to_string(&id).unwrap();
    let decoded: RoomId = serde_json::from_str(&json).unwrap();
    assert_eq!(id, decoded);
}

#[test]
fn recipient_node_serde_roundtrip() {
    let r = Recipient::Node(NodeId::from_bytes([3u8; 32]));
    let json = serde_json::to_string(&r).unwrap();
    let decoded: Recipient = serde_json::from_str(&json).unwrap();
    assert_eq!(r, decoded);
}

#[test]
fn recipient_room_serde_roundtrip() {
    let r = Recipient::Room(RoomId::new());
    let json = serde_json::to_string(&r).unwrap();
    let decoded: Recipient = serde_json::from_str(&json).unwrap();
    assert_eq!(r, decoded);
}

#[test]
fn signature_serde_roundtrip() {
    let sig = Signature::from_bytes([0xAB; 64]);
    let json = serde_json::to_string(&sig).unwrap();
    let decoded: Signature = serde_json::from_str(&json).unwrap();
    assert_eq!(sig.as_bytes(), decoded.as_bytes());
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEDERATION SIGNING — EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn federation_empty_payload_signs_and_verifies() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let signed = SignedMessage::sign(&identity, Vec::new(), 1_700_000_000_000);
    signed.verify_signature().expect("empty payload must sign and verify");
}

#[test]
fn federation_large_payload_signs_and_verifies() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let payload = vec![0xFFu8; 100_000]; // 100 KB
    let signed = SignedMessage::sign(&identity, payload, 1_700_000_000_000);
    signed.verify_signature().expect("large payload must sign and verify");
}

#[test]
fn federation_tampered_nonce_fails_verification() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let mut signed = SignedMessage::sign(&identity, b"hello".to_vec(), 1_700_000_000_000);
    signed.nonce = Nonce::generate(); // Replace with a different nonce
    let err = signed.verify_signature().unwrap_err();
    assert!(matches!(err, CoreError::InvalidSignature(_)));
}

#[test]
fn federation_tampered_timestamp_fails_verification() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let mut signed = SignedMessage::sign(&identity, b"hello".to_vec(), 1_700_000_000_000);
    signed.timestamp += 1; // Off by one
    let err = signed.verify_signature().unwrap_err();
    assert!(matches!(err, CoreError::InvalidSignature(_)));
}

#[test]
fn federation_timestamp_exactly_at_max_age_boundary() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let msg_time = 1_700_000_000_000u64;
    let max_age = 60_000u64;
    let signed = SignedMessage::sign(&identity, b"hello".to_vec(), msg_time);

    // Exactly at boundary: msg_time + max_age == now → should pass
    assert!(signed
        .verify_with_timestamp(msg_time + max_age, max_age)
        .is_ok());

    // One ms past boundary: should fail (message too old)
    let err = signed
        .verify_with_timestamp(msg_time + max_age + 1, max_age)
        .unwrap_err();
    assert!(matches!(err, CoreError::EnvelopeValidation(_)));
}

#[test]
fn federation_timestamp_within_future_tolerance() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let now = 1_700_000_000_000u64;
    // Message 15 seconds in the future (within 30s tolerance)
    let signed = SignedMessage::sign(&identity, b"hello".to_vec(), now + 15_000);
    signed.verify_with_timestamp(now, 60_000).expect("within future tolerance must pass");
}

#[test]
fn federation_timestamp_beyond_future_tolerance() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let now = 1_700_000_000_000u64;
    // Message 60 seconds in the future (beyond 30s tolerance)
    let signed = SignedMessage::sign(&identity, b"hello".to_vec(), now + 60_000);
    let err = signed.verify_with_timestamp(now, 120_000).unwrap_err();
    assert!(matches!(err, CoreError::EnvelopeValidation(_)));
}

#[test]
fn federation_different_passphrases_produce_different_identities() {
    let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alpha").unwrap();
    let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "beta").unwrap();
    assert_ne!(id1.node_id(), id2.node_id());

    // Message signed by alpha cannot verify as beta
    let signed = SignedMessage::sign(&id1, b"test".to_vec(), 1_700_000_000_000);
    assert_eq!(*id1.node_id(), signed.sender);
    assert!(signed.verify_signature().is_ok());

    let mut tampered = signed;
    tampered.sender = *id2.node_id();
    let err = tampered.verify_signature().unwrap_err();
    assert!(matches!(err, CoreError::InvalidSignature(_)));
}

#[test]
fn federation_serde_roundtrip() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let signed = SignedMessage::sign(&identity, b"roundtrip test".to_vec(), 1_700_000_000_000);

    let json = serde_json::to_string(&signed).unwrap();
    let decoded: SignedMessage = serde_json::from_str(&json).unwrap();

    assert_eq!(decoded.payload, signed.payload);
    assert_eq!(decoded.sender, signed.sender);
    assert_eq!(decoded.nonce, signed.nonce);
    assert_eq!(decoded.timestamp, signed.timestamp);
    assert!(decoded.verify_signature().is_ok());
}

// ═══════════════════════════════════════════════════════════════════════════════
// IDENTITY — EDGE CASES
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn identity_from_mnemonic_empty_passphrase() {
    let id = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    assert!(!id.node_id().as_bytes().iter().all(|&b| b == 0));
}

#[test]
fn identity_from_mnemonic_deterministic() {
    let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "test").unwrap();
    let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "test").unwrap();
    assert_eq!(id1.node_id(), id2.node_id());
}

#[test]
fn identity_invalid_mnemonic_rejected() {
    let result = NodeIdentity::from_mnemonic("not a valid mnemonic", "");
    assert!(result.is_err());
}

#[test]
fn identity_sign_and_verify() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let message = b"test message for signing";
    let sig = identity.sign(message);

    let vk = identity.node_id().to_verifying_key().unwrap();
    assert!(vk.verify_strict(message, &sig).is_ok());
}

#[test]
fn identity_sign_different_messages_different_sigs() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    let sig1 = identity.sign(b"message A");
    let sig2 = identity.sign(b"message B");
    assert_ne!(sig1.to_bytes(), sig2.to_bytes());
}

#[test]
fn identity_aes_key_is_32_bytes() {
    let identity = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "").unwrap();
    assert_eq!(identity.aes_key().len(), 32);
}

#[test]
fn identity_aes_key_deterministic() {
    let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "same").unwrap();
    let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "same").unwrap();
    assert_eq!(id1.aes_key(), id2.aes_key());
}

#[test]
fn identity_different_passphrase_different_aes_key() {
    let id1 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "alpha").unwrap();
    let id2 = NodeIdentity::from_mnemonic(TEST_MNEMONIC, "beta").unwrap();
    assert_ne!(id1.aes_key(), id2.aes_key());
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFETY NUMBER & FINGERPRINTS
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn node_id_safety_number_deterministic() {
    let id_a = NodeId::from_bytes([0xAB; 32]);
    let id_b = NodeId::from_bytes([0xCD; 32]);
    let sn1 = id_a.safety_number(&id_b);
    let sn2 = id_a.safety_number(&id_b);
    assert_eq!(sn1, sn2);
}

#[test]
fn node_id_safety_number_symmetric() {
    let id_a = NodeId::from_bytes([1u8; 32]);
    let id_b = NodeId::from_bytes([2u8; 32]);
    // Both sides should compute the same safety number
    assert_eq!(id_a.safety_number(&id_b), id_b.safety_number(&id_a));
}

#[test]
fn node_id_safety_number_differs_for_different_peers() {
    let me = NodeId::from_bytes([1u8; 32]);
    let peer_a = NodeId::from_bytes([2u8; 32]);
    let peer_b = NodeId::from_bytes([3u8; 32]);
    assert_ne!(me.safety_number(&peer_a), me.safety_number(&peer_b));
}

#[test]
fn node_id_safety_number_format() {
    let id_a = NodeId::from_bytes([0xAB; 32]);
    let id_b = NodeId::from_bytes([0xCD; 32]);
    let sn = id_a.safety_number(&id_b);
    // Should be 12 groups of 5 digits separated by spaces
    let groups: Vec<&str> = sn.split(' ').collect();
    assert_eq!(groups.len(), 12, "expected 12 groups, got: {sn}");
    for group in &groups {
        assert_eq!(group.len(), 5, "each group should be 5 digits: {group}");
        assert!(group.chars().all(|c| c.is_ascii_digit()));
    }
}

#[test]
fn node_id_short_fingerprint_is_short() {
    let id = NodeId::from_bytes([0xAB; 32]);
    let fp = id.short_fingerprint();
    // Should be a concise representation (typically 8-12 chars)
    assert!(!fp.is_empty());
    assert!(fp.len() <= 16, "fingerprint too long: {fp}");
}
