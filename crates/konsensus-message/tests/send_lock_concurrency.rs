//! Integration test for L0d — `NoiseTransport::send` and `peer_info` no
//! longer hold `peers.read()` across `conn.lock().await` and network IO.
//!
//! Pre-fix scenario: with `peers.read()` held across the whole send, any
//! concurrent peer registration / disconnect / handshake (which needs
//! `peers.write()`) was blocked for as long as ANY send was in flight.
//! Under sustained outbound traffic, registry mutations were starved.
//!
//! What this test asserts (post-fix):
//! 1. Many concurrent `send` calls to the same peer all complete cleanly.
//! 2. `is_connected` and `connected_peers` queries (which take the same
//!    `peers` RwLock) interleave freely with sends.
//! 3. A read of `peer_info` returns promptly under send pressure (the
//!    same scoped-clone pattern was applied there too).
//!
//! What this test does NOT do: prove starvation timing on pre-fix code.
//! That would require a slow-mock writer to extend send latency past
//! loopback's near-zero floor. The fix's correctness is verified at the
//! source level (codex review per L0 freeze policy); this test is the
//! happy-path regression that the pattern doesn't break working code.

use std::sync::Arc;
use std::time::Duration;

use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::{NodeId, Nonce, PaymentProof, Recipient, Signature};
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_message::wire::{Capability, SovereigntyTier};
use konsensus_message::{ReachabilityMode, NoiseTransport, TransportConfig};
use sha2::{Digest, Sha256};

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon \
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

fn make_envelope(
    sender: &NodeIdentity,
    recipient: &NodeId,
    body_seed: u8,
) -> konsensus_core::envelope::UkmEnvelope {
    let preimage = [body_seed; 32];
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(hash, preimage, 10);
    let nonce = Nonce::generate();
    let ciphertext = vec![body_seed; 32];

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

/// Stand up Alice + Bob on loopback with mutual whitelist, then run a
/// stress phase: many concurrent sends from Alice to Bob interleaved
/// with `is_connected` / `connected_peers` / `peer_info` reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn send_lock_concurrency_does_not_starve_registry_reads() {
    let alice = make_identity("alice-l0d");
    let bob = make_identity("bob-l0d");
    let alice_id = *alice.node_id();
    let bob_id = *bob.node_id();

    let transport_bob = Arc::new(NoiseTransport::new(
        Arc::clone(&bob),
        make_config(vec![alice_id]),
    ));
    transport_bob
        .start_listener()
        .await
        .expect("Bob listener bind");
    let bob_addr = transport_bob.listen_addr().expect("Bob listen addr");
    tokio::time::sleep(Duration::from_millis(50)).await;

    let transport_alice = Arc::new(NoiseTransport::new(
        Arc::clone(&alice),
        make_config(vec![bob_id]),
    ));
    transport_alice
        .connect(&bob_id, &bob_addr.to_string())
        .await
        .expect("Alice→Bob connect");

    // Run the stress phase under a wall-clock deadline so a deadlock would
    // surface as a timeout rather than a hang.
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        // 30 concurrent sends from Alice to Bob.
        let mut send_handles = Vec::with_capacity(30);
        for i in 0..30u8 {
            let t = Arc::clone(&transport_alice);
            let env = make_envelope(&alice, &bob_id, i.wrapping_add(1));
            send_handles.push(tokio::spawn(async move {
                t.send(&bob_id, &env).await
            }));
        }

        // 60 concurrent registry-read calls (is_connected, connected_peers,
        // peer_info) interleaved with the sends. With the L0d fix, sends
        // do NOT hold `peers.read()` across network IO, so these reads
        // never queue behind in-flight sends.
        let mut read_handles = Vec::with_capacity(60);
        for i in 0..60u32 {
            let t = Arc::clone(&transport_alice);
            read_handles.push(tokio::spawn(async move {
                if i % 3 == 0 {
                    let _ = t.is_connected(&bob_id).await;
                } else if i % 3 == 1 {
                    let _ = t.connected_peers().await;
                } else {
                    let _ = t.peer_info(&bob_id).await;
                }
            }));
        }

        for h in send_handles {
            h.await
                .expect("send task join")
                .expect("send returned error");
        }
        for h in read_handles {
            h.await.expect("read task join");
        }
    })
    .await;

    transport_bob.shutdown();

    assert!(
        result.is_ok(),
        "L0d regression: stress phase did not complete within 15s — \
         a starvation/deadlock between send and the peers RwLock is suspected"
    );

    // Final sanity: registry still consistent with reality after the storm.
    assert!(transport_alice.is_connected(&bob_id).await);
    assert!(transport_alice
        .peer_info(&bob_id)
        .await
        .is_some());
}
