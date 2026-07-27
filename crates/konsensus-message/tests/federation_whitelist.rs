//! Closed-mesh whitelist enforcement tests.
//!
//! Covers three security scenarios for Principle 3 (Closed Mesh):
//!
//! 1. **Non-whitelisted connection** — a peer not in the responder's whitelist
//!    completes Noise_XX but is rejected at the federation handshake layer.
//!    The responder sends a Disconnect frame BEFORE HelloAck (no identity leak).
//!
//! 2. **Self-removal and reconnect** — a node removes a peer from its own whitelist
//!    then disconnects. Subsequent connection attempts are rejected immediately at
//!    the initiator-side whitelist check. A send attempt returns NotConnected since
//!    no active session exists and reconnect is blocked.
//!
//! 3. **Forged federation handshake** — an attacker claiming a different node_id
//!    is rejected by Ed25519 identity binding and by the transport integration
//!    check that compares the bound Noise identity to the responder whitelist.

use std::sync::Arc;

use konsensus_core::UkmEnvelopeBuilder;
use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::transport::{MessageTransport, TransportError};
use konsensus_core::types::{NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_message::wire::{Capability, SovereigntyTier};
use konsensus_message::{ReachabilityMode, NoiseTransport, TransportConfig};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Deterministic test identities -- one mnemonic, passphrase differentiates.
// ---------------------------------------------------------------------------

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

fn make_identity(passphrase: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(MNEMONIC, passphrase).unwrap())
}

fn make_config(whitelist: Vec<NodeId>) -> TransportConfig {
    TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        tier: SovereigntyTier::T1,
        capabilities: vec![Capability::X3dh],
        whitelist,
        version: 2,
        admission_mode: ReachabilityMode::Whitelist,
        cookie_mode: Default::default(),
    }
}

fn make_test_envelope(
    sender: &NodeIdentity,
    recipient: &NodeId,
) -> konsensus_core::envelope::UkmEnvelope {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 10);

    let nonce = Nonce::generate();
    let ciphertext = b"encrypted test content".to_vec();

    let mut envelope = UkmEnvelopeBuilder::new(
        0,
        *sender.node_id(),
        Recipient::Node(*recipient),
        ciphertext,
        proof,
    )
    .nonce(nonce)
    .timestamp(1_700_000_000_000)
    .build();

    let sig = sender.sign(&envelope.signable_bytes());
    envelope.signature = Signature::from_ed25519(&sig);
    envelope
}

// =============================================================================
// TEST 1 -- Non-whitelisted peer rejected by responder
// =============================================================================

/// A peer not in the responder's whitelist is rejected during federation handshake.
///
/// Alice (initiator) passes her own whitelist check (she has Bob whitelisted) and
/// completes the Noise_XX handshake. Bob (responder) receives Alice's Hello frame,
/// checks his whitelist -- Alice is absent -- and sends a Disconnect before HelloAck.
///
/// Security: Principle 3 (Closed Mesh). Empty whitelist OR missing entry = reject.
/// The whitelist check fires before HelloAck, preventing any identity acknowledgement
/// to unauthorized peers (no identity leak on rejection).
#[tokio::test]
async fn non_whitelisted_peer_rejected_by_responder() {
    let alice = make_identity("alice");
    let bob = make_identity("bob");

    let alice_id = *alice.node_id();
    let bob_id = *bob.node_id();

    // Bob's whitelist contains an unrelated node -- NOT Alice.
    let config_bob = make_config(vec![NodeId::from_bytes([0xFF; 32])]);
    // Alice whitelists Bob so her initiator-side check passes (reaching Bob's responder).
    let config_alice = make_config(vec![bob_id]);

    let transport_bob = Arc::new(NoiseTransport::new(Arc::clone(&bob), config_bob));
    transport_bob
        .start_listener()
        .await
        .expect("Bob listener failed to bind");

    let bob_addr = transport_bob
        .listen_addr()
        .expect("Bob listen addr not set");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let transport_alice = NoiseTransport::new(Arc::clone(&alice), config_alice);

    // Alice's connect: initiator whitelist check PASSES, Noise handshake completes,
    // but Bob's federation handshake responder rejects Alice (not in Bob's whitelist).
    let result = transport_alice
        .connect(&bob_id, &bob_addr.to_string())
        .await;

    assert!(
        result.is_err(),
        "non-whitelisted connection must be rejected"
    );
    match result.unwrap_err() {
        TransportError::Rejected(msg) => {
            assert!(
                msg.contains("whitelist") || msg.contains("not in whitelist"),
                "rejection must cite whitelist enforcement, got: {msg}"
            );
        }
        e => panic!("expected Rejected, got: {e:?}"),
    }

    // Alice must not appear in Bob's peer table -- the connection was rejected.
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert!(
        !transport_bob.is_connected(&alice_id).await,
        "Bob must not register a non-whitelisted peer as connected"
    );

    transport_bob.shutdown();
}

// =============================================================================
// TEST 2 -- Self-removal: removed peer cannot reconnect or send
// =============================================================================

/// After self-removing a peer from the whitelist and disconnecting, reconnection
/// is rejected at the initiator-side whitelist check; a send attempt returns
/// NotConnected since no active session exists.
///
/// Security: whitelist revocation takes effect immediately. Once a node removes
/// a peer entry, that peer can no longer be reached via this node -- even if the
/// peer's address is still known.
#[tokio::test]
async fn self_removal_reconnect_and_send_rejected() {
    let alice = make_identity("alice");
    let bob = make_identity("bob");

    let alice_id = *alice.node_id();
    let bob_id = *bob.node_id();

    // Both nodes start with each other whitelisted.
    let config_bob = make_config(vec![alice_id]);
    let config_alice = make_config(vec![bob_id]);

    let transport_bob = Arc::new(NoiseTransport::new(Arc::clone(&bob), config_bob));
    transport_bob
        .start_listener()
        .await
        .expect("Bob listener failed to bind");
    let bob_addr = transport_bob
        .listen_addr()
        .expect("Bob listen addr not set");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let transport_alice = Arc::new(NoiseTransport::new(Arc::clone(&alice), config_alice));

    // Step 1: Initial connection succeeds (mutual whitelist).
    transport_alice
        .connect(&bob_id, &bob_addr.to_string())
        .await
        .expect("initial connection must succeed -- both nodes are whitelisted");

    assert!(
        transport_alice.is_connected(&bob_id).await,
        "Alice must be connected to Bob after handshake"
    );

    // Step 2: Alice removes Bob from her whitelist (self-revocation).
    transport_alice.remove_from_whitelist(&bob_id).await;

    // Step 3: Alice disconnects from Bob.
    transport_alice
        .disconnect(&bob_id)
        .await
        .expect("disconnect must not fail");
    assert!(
        !transport_alice.is_connected(&bob_id).await,
        "Alice must be disconnected from Bob"
    );

    // Step 4: Alice tries to reconnect -- initiator whitelist check fires BEFORE TCP connect.
    // Rejected immediately: not whitelisted (Rejected containing "whitelist").
    let reconnect_result = transport_alice
        .connect(&bob_id, &bob_addr.to_string())
        .await;

    assert!(
        reconnect_result.is_err(),
        "reconnect after whitelist removal must be rejected"
    );
    match reconnect_result.unwrap_err() {
        TransportError::Rejected(msg) => {
            assert!(
                msg.contains("whitelist"),
                "rejection must cite whitelist, got: {msg}"
            );
        }
        e => panic!("expected Rejected(whitelist), got: {e:?}"),
    }

    // Step 5: Alice tries to send -- no active connection exists, returns NotConnected.
    // (Reconnect is blocked by whitelist removal, so there is no path to Bob.)
    let envelope = make_test_envelope(&alice, &bob_id);
    let send_result = transport_alice.send(&bob_id, &envelope).await;

    assert!(
        send_result.is_err(),
        "send after disconnect + whitelist removal must fail"
    );
    assert!(
        matches!(send_result.unwrap_err(), TransportError::NotConnected(_)),
        "send must fail with NotConnected (no active session after whitelist removal)"
    );

    transport_bob.shutdown();
}

// =============================================================================
// TEST 3a -- Forged identity binding: crypto primitive layer
// =============================================================================

/// An attacker cannot forge the Ed25519 identity binding in a Hello frame.
///
/// The Hello frame's x25519_sig is `Ed25519_sign(node_privkey, x25519_public)`.
/// The responder verifies this signature against the claimed node_id (public key).
/// An attacker who does not possess the victim's private key cannot produce a
/// valid signature -- they can only sign with their own key, which fails
/// verification against the claimed (victim's) public key.
///
/// This test exercises the same crypto path as `verify_identity_binding()` in
/// the handshake module, using the public `NodeIdentity::sign/verify` API.
#[test]
fn forged_hello_identity_binding_rejected() {
    let alice = NodeIdentity::from_mnemonic(MNEMONIC, "alice").unwrap();
    let attacker = NodeIdentity::from_mnemonic(MNEMONIC, "attacker").unwrap();

    // Attacker's real X25519 key (what Noise actually authenticated).
    let attacker_x25519 = attacker.x25519_public().as_bytes().to_vec();

    // Attacker signs their X25519 key with their OWN Ed25519 key.
    let attacker_sig = attacker.sign(&attacker_x25519);

    // Responder check: verify attacker's sig against claimed node_id = Alice's pubkey.
    // alice.verify() uses Alice's Ed25519 verifying key -- attacker's sig is invalid.
    let binding_check = alice.verify(&attacker_x25519, &attacker_sig);
    assert!(
        binding_check.is_err(),
        "attacker's Ed25519 sig must not verify against Alice's public key (forged node_id)"
    );

    // Sanity: Alice's own signature over her X25519 key is valid.
    let alice_x25519 = alice.x25519_public().as_bytes().to_vec();
    let alice_sig = alice.sign(&alice_x25519);
    assert!(
        alice.verify(&alice_x25519, &alice_sig).is_ok(),
        "Alice's own identity binding must verify (sanity)"
    );

    // Defense depth: attacker also cannot sign Alice's X25519 public key (copied from
    // her published node manifest). Their signature over it still fails against Alice's key.
    let attacker_sig_over_alice_x25519 = attacker.sign(&alice_x25519);
    assert!(
        alice
            .verify(&alice_x25519, &attacker_sig_over_alice_x25519)
            .is_err(),
        "attacker's signature over Alice's X25519 pubkey must not verify against Alice's key"
    );
}

// =============================================================================
// TEST 3b -- Forged handshake claiming victim's node_id: transport layer
// =============================================================================

/// An attacker node with a legitimate Noise session but a different Ed25519 identity
/// cannot impersonate a whitelisted peer at the transport layer.
///
/// The attacker's node_id is cryptographically bound to their Noise static key via
/// the federation Hello frame's identity binding signature. Since node_id = Ed25519
/// public key and the Ed25519 private key is required to produce a valid binding
/// signature, the attacker's true node_id is always revealed. If that node_id is not
/// in the responder's whitelist, the connection is rejected before HelloAck.
///
/// This test shows that even a well-behaved protocol participant (valid Noise_XX,
/// valid identity binding for their OWN identity) is rejected if they are not
/// in the whitelist -- the whitelist is the final gate regardless of protocol conformance.
#[tokio::test]
async fn attacker_node_rejected_whitelist_is_final_gate() {
    let alice = make_identity("alice");
    let bob = make_identity("bob");
    let attacker = make_identity("attacker");

    let alice_id = *alice.node_id();
    let bob_id = *bob.node_id();
    let attacker_id = *attacker.node_id();

    // Bob whitelists Alice only. Attacker is not listed.
    let config_bob = make_config(vec![alice_id]);
    // Attacker whitelists Bob so their initiator-side check passes and TCP connect happens.
    let config_attacker = make_config(vec![bob_id]);

    let transport_bob = Arc::new(NoiseTransport::new(Arc::clone(&bob), config_bob));
    transport_bob
        .start_listener()
        .await
        .expect("Bob listener failed to bind");
    let bob_addr = transport_bob
        .listen_addr()
        .expect("Bob listen addr not set");
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let transport_attacker = NoiseTransport::new(Arc::clone(&attacker), config_attacker);

    // Attacker completes a valid Noise_XX session with Bob using their real Ed25519/X25519 keys.
    // Their federation Hello carries attacker_id (bound to their Noise static key -- unforgeable).
    // Bob's whitelist does not contain attacker_id -> rejected before HelloAck.
    let result = transport_attacker
        .connect(&bob_id, &bob_addr.to_string())
        .await;

    assert!(
        result.is_err(),
        "attacker with a valid Noise session must still be rejected if not whitelisted"
    );
    match result.unwrap_err() {
        TransportError::Rejected(msg) => {
            assert!(
                msg.contains("whitelist") || msg.contains("not in whitelist"),
                "rejection must cite whitelist, got: {msg}"
            );
        }
        e => panic!("expected Rejected, got: {e:?}"),
    }

    // Attacker must not appear in Bob's peer table.
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    assert!(
        !transport_bob.is_connected(&attacker_id).await,
        "attacker must not be registered as connected on Bob's node"
    );

    // Confirm: Alice (the legitimate whitelisted peer) CAN connect.
    let config_alice = make_config(vec![bob_id]);
    let transport_alice = NoiseTransport::new(Arc::clone(&alice), config_alice);
    let alice_result = transport_alice
        .connect(&bob_id, &bob_addr.to_string())
        .await;
    assert!(
        alice_result.is_ok(),
        "Alice (whitelisted) must connect successfully to Bob"
    );

    transport_bob.shutdown();
}
