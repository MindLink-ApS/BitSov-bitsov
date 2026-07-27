//! Profile outgoing sender — sends our `NodeProfile` to a peer after the
//! Noise handshake completes.
//!
//! # Wire format
//! Sends a `KIND_PROFILE` (103) `UkmEnvelope` with:
//! - AES-256-GCM encrypted `NodeProfile` JSON (key derived from both node IDs)
//! - 25 msat mock payment proof (replace with real LN invoice in production)
//! - Ed25519 signature over `signable_bytes()`
//!
//! # Key derivation
//! `key = SHA-256(DOMAIN || sender_id_bytes || recipient_id_bytes)`
//! Both parties can independently compute the same key from public node IDs.
//! Confidentiality in transit is provided by the Noise transport layer;
//! the AEAD tag binds the payload to this specific sender/recipient pair.
//!
//! # Auto-trigger
//! Called by `session_handler::handle_peer_connected` immediately after the
//! peer is connected so they can display our identity in their contact book.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce as AesGcmNonce,
};
use konsensus_core::{
    identity::NodeIdentity,
    profile::{NodeProfile, KIND_PROFILE},
    traits::transport::MessageTransport,
    types::{NodeId, Nonce, PaymentProof, Recipient, Signature},
    UkmEnvelopeBuilder,
};
use konsensus_message::NoiseTransport;
use sha2::{Digest, Sha256};
use tracing::{info, warn};

/// Payment amount for outgoing profile envelopes (25 msat mock proof).
const PROFILE_PAYMENT_MSAT: u64 = 25;

/// Domain-separation tag for AES-256-GCM key derivation.
/// Must match the constant in `konsensus-message::profile_handler`.
const PROFILE_KEY_DOMAIN: &[u8] = b"konsensus-v2 profile-key v1\0";

/// Send our `KIND_PROFILE` (103) envelope to `peer_id`.
///
/// Errors are logged as warnings; this is a best-effort exchange that should
/// not block or crash the connection flow.
pub(crate) async fn send_profile_to(
    identity: &NodeIdentity,
    transport: &NoiseTransport,
    peer_id: &NodeId,
) {
    if let Err(e) = try_send_profile(identity, transport, peer_id).await {
        warn!(peer = %peer_id, error = %e, "failed to send KIND_PROFILE to peer");
    }
}

async fn try_send_profile(
    identity: &NodeIdentity,
    transport: &NoiseTransport,
    peer_id: &NodeId,
) -> anyhow::Result<()> {
    let sender = *identity.node_id();
    let now_secs = chrono::Utc::now().timestamp();

    // Display name: first 8 hex chars of our node ID (placeholder until the
    // settings layer exposes a user-configured name).
    let my_hex = sender.to_hex();
    let mut profile = NodeProfile {
        display_name: my_hex[..8].to_string(),
        bio: String::new(),
        avatar: None,
        verified_identities: vec![],
        timestamp: now_secs,
    };
    profile
        .validate()
        .map_err(|e| anyhow::anyhow!("profile validation failed: {e}"))?;

    // Serialize and AES-256-GCM encrypt the profile payload.
    let plaintext = serde_json::to_vec(&profile)?;
    let nonce = Nonce::generate();
    let key_bytes = derive_key(&sender, peer_id);
    let ciphertext = aes_encrypt(&plaintext, &key_bytes, &nonce)?;

    // Mock payment proof: preimage = SHA-256(nonce || sender_id).
    // Replace with a real Lightning invoice flow in production.
    let preimage = mock_preimage(&nonce, &sender);
    let payment_hash: [u8; 32] = Sha256::digest(preimage).into();
    let proof = PaymentProof::new(payment_hash, preimage, PROFILE_PAYMENT_MSAT);

    let recipient = Recipient::Node(*peer_id);
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);

    // Two-pass build: first pass gets signable bytes, second attaches real signature.
    let tmp = UkmEnvelopeBuilder::new(
        KIND_PROFILE,
        sender,
        recipient,
        ciphertext.clone(),
        proof.clone(),
    )
    .nonce(nonce)
    .timestamp(now_ms)
    .build();

    let raw_sig = identity.sign(&tmp.signable_bytes());
    let sig = Signature::from_bytes(raw_sig.to_bytes());

    let envelope = UkmEnvelopeBuilder::new(KIND_PROFILE, sender, recipient, ciphertext, proof)
        .nonce(nonce)
        .timestamp(now_ms)
        .signature(sig)
        .build();

    transport.send(peer_id, &envelope).await?;
    info!(
        peer = %&peer_id.to_hex()[..8],
        "sent KIND_PROFILE envelope (25 msat mock)"
    );
    Ok(())
}

/// Derive the AES-256-GCM key for a sender↔recipient pair.
///
/// `key = SHA-256(DOMAIN || sender_id_bytes || recipient_id_bytes)`
fn derive_key(sender_id: &NodeId, recipient_id: &NodeId) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PROFILE_KEY_DOMAIN);
    h.update(sender_id.as_bytes());
    h.update(recipient_id.as_bytes());
    h.finalize().into()
}

/// AES-256-GCM encrypt `plaintext` using the first 12 bytes of the envelope nonce.
fn aes_encrypt(
    plaintext: &[u8],
    key_bytes: &[u8; 32],
    nonce: &Nonce,
) -> anyhow::Result<Vec<u8>> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    // AES-GCM uses a 12-byte nonce; take the first 12 of the 24-byte envelope nonce.
    let aes_nonce = AesGcmNonce::from_slice(&nonce.as_bytes()[..12]);
    cipher
        .encrypt(aes_nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {e}"))
}

/// Derive a deterministic mock payment preimage for non-LN flows.
///
/// `preimage = SHA-256(nonce_bytes || sender_id_bytes)`
///
/// Must match the derivation in `konsensus-message::profile_handler::ProfileHandler::mock_preimage`
/// so that the receiver's `verify_preimage()` check passes.
fn mock_preimage(nonce: &Nonce, sender_id: &NodeId) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(nonce.as_bytes());
    h.update(sender_id.as_bytes());
    h.finalize().into()
}
