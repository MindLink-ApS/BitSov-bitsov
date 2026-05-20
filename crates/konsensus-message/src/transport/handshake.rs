//! Noise_XX + federation handshake functions.
//!
//! These are pure free functions — they own their arguments and return the
//! upgraded state.  No `NoiseTransport` methods live here.

use std::net::SocketAddr;

use konsensus_core::identity::NodeIdentity;
use konsensus_crypto::noise::NoiseSession;
use tokio::net::TcpStream;
use tracing::{info, warn};

use konsensus_core::traits::transport::TransportError;
use konsensus_core::types::NodeId;

use crate::wire::{Capability, Frame, SovereigntyTier};

use super::{
    write_noise_message, read_noise_message,
    TransportConfig, SharedWhitelist,
    HANDSHAKE_TIMEOUT,
};

// ─── Noise_XX handshake ─────────────────────────────────────────────────────

/// Perform Noise_XX handshake as initiator (owns the NoiseSession).
pub(super) async fn noise_handshake_initiator(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    mut noise: NoiseSession,
) -> Result<
    (
        tokio::io::ReadHalf<TcpStream>,
        tokio::io::WriteHalf<TcpStream>,
        NoiseSession,
    ),
    TransportError,
> {
    // Message 1: → e
    let msg1 = noise
        .write_handshake(&[])
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;
    write_noise_message(&mut writer, &msg1)
        .await
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    // Message 2: ← e, ee, s, es
    let msg2 = read_noise_message(&mut reader)
        .await
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;
    noise
        .read_handshake(&msg2)
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    // Message 3: → s, se
    let msg3 = noise
        .write_handshake(&[])
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;
    write_noise_message(&mut writer, &msg3)
        .await
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    // Transition to transport mode
    noise
        .try_finish_handshake()
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    Ok((reader, writer, noise))
}

/// Perform Noise_XX handshake as responder (owns the NoiseSession).
pub(super) async fn noise_handshake_responder(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    mut noise: NoiseSession,
) -> Result<
    (
        tokio::io::ReadHalf<TcpStream>,
        tokio::io::WriteHalf<TcpStream>,
        NoiseSession,
    ),
    TransportError,
> {
    // Message 1: ← e
    let msg1 = read_noise_message(&mut reader)
        .await
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;
    noise
        .read_handshake(&msg1)
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    // Message 2: → e, ee, s, es
    let msg2 = noise
        .write_handshake(&[])
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;
    write_noise_message(&mut writer, &msg2)
        .await
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    // Message 3: ← s, se
    let msg3 = read_noise_message(&mut reader)
        .await
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;
    noise
        .read_handshake(&msg3)
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    // Transition to transport mode
    noise
        .try_finish_handshake()
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    Ok((reader, writer, noise))
}

// ─── Frame-level helpers ────────────────────────────────────────────────────

/// Build a Hello frame for the federation handshake.
pub(super) fn build_hello_frame(
    identity: &NodeIdentity,
    config: &TransportConfig,
    noise: &NoiseSession,
) -> Frame {
    // Get the X25519 public key that was used in the Noise handshake
    let x25519_public = identity.x25519_public().as_bytes().to_vec();

    // Sign the X25519 public key with Ed25519 to prove we own both keys
    let sig = identity.sign(&x25519_public);

    let _ = noise; // noise session reference reserved for future extensions

    Frame::Hello {
        version: config.version,
        node_id: *identity.node_id(),
        x25519_sig: sig.to_bytes().to_vec(),
        x25519_public,
        tier: config.tier,
        capabilities: config.capabilities.clone(),
    }
}

/// Build a HelloAck frame for the federation handshake.
pub(super) fn build_hello_ack_frame(
    identity: &NodeIdentity,
    config: &TransportConfig,
    noise: &NoiseSession,
) -> Frame {
    let x25519_public = identity.x25519_public().as_bytes().to_vec();
    let sig = identity.sign(&x25519_public);

    let _ = noise;

    Frame::HelloAck {
        version: config.version,
        node_id: *identity.node_id(),
        x25519_sig: sig.to_bytes().to_vec(),
        x25519_public,
        tier: config.tier,
        capabilities: config.capabilities.clone(),
    }
}

/// Verify a Hello or HelloAck frame's identity binding.
///
/// Checks that the Ed25519 signature over the X25519 public key is valid,
/// proving the sender owns both keys.
pub(crate) fn verify_identity_binding(
    node_id: &NodeId,
    x25519_public: &[u8],
    x25519_sig: &[u8],
) -> Result<(), TransportError> {
    let verifying_key = node_id
        .to_verifying_key()
        .map_err(|e| TransportError::Rejected(format!("invalid node ID: {e}")))?;

    let sig = ed25519_dalek::Signature::from_slice(x25519_sig)
        .map_err(|e| TransportError::Rejected(format!("invalid signature: {e}")))?;

    ed25519_dalek::Verifier::verify(&verifying_key, x25519_public, &sig)
        .map_err(|e| TransportError::Rejected(format!("identity binding failed: {e}")))?;

    Ok(())
}

/// Send an encrypted frame over a Noise session (used during handshake only).
pub(super) async fn send_encrypted_frame(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    noise: &mut NoiseSession,
    frame: &Frame,
) -> Result<(), TransportError> {
    let frame_bytes = frame
        .to_bytes()
        .map_err(|e| TransportError::WireProtocol(e.to_string()))?;
    let encrypted = noise
        .encrypt(&frame_bytes)
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;
    write_noise_message(writer, &encrypted)
        .await
        .map_err(|e| TransportError::Other(e.to_string()))?;
    Ok(())
}

/// Receive and decrypt a frame over a Noise session (used during handshake only).
pub(super) async fn recv_encrypted_frame(
    reader: &mut tokio::io::ReadHalf<TcpStream>,
    noise: &mut NoiseSession,
) -> Result<Frame, TransportError> {
    let encrypted = read_noise_message(reader)
        .await
        .map_err(|e| TransportError::Other(e.to_string()))?;
    let decrypted = noise
        .decrypt(&encrypted)
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;
    Frame::from_bytes(&decrypted).map_err(|e| TransportError::WireProtocol(e.to_string()))
}

// ─── Federation handshake ───────────────────────────────────────────────────

/// Perform federation handshake as initiator.
///
/// After the Noise_XX handshake, exchange Hello/HelloAck to bind Ed25519
/// identities to the X25519 keys used in Noise, and negotiate capabilities.
pub(super) async fn perform_federation_handshake_initiator(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    mut noise: NoiseSession,
    identity: &NodeIdentity,
    config: &TransportConfig,
) -> Result<
    (
        NodeId,
        SovereigntyTier,
        Vec<Capability>,
        tokio::io::ReadHalf<TcpStream>,
        tokio::io::WriteHalf<TcpStream>,
        NoiseSession,
    ),
    TransportError,
> {
    // Send Hello
    let hello = build_hello_frame(identity, config, &noise);
    send_encrypted_frame(&mut writer, &mut noise, &hello).await?;

    // Receive HelloAck
    let frame = recv_encrypted_frame(&mut reader, &mut noise).await?;
    match frame {
        Frame::HelloAck {
            version,
            node_id,
            x25519_sig,
            x25519_public,
            tier,
            capabilities,
        } => {
            // Verify protocol version
            if version != config.version {
                let disconnect = Frame::Disconnect {
                    reason: format!("version mismatch: expected {}, got {version}", config.version),
                };
                if let Err(e) = send_encrypted_frame(&mut writer, &mut noise, &disconnect).await {
                    warn!(error = %e, "failed to send disconnect frame on version mismatch");
                }
                return Err(TransportError::Rejected(format!(
                    "protocol version mismatch: local={}, remote={version}",
                    config.version
                )));
            }

            // Verify identity binding (Ed25519 sig over X25519 public key)
            verify_identity_binding(&node_id, &x25519_public, &x25519_sig)?;

            // Verify the claimed X25519 key matches the Noise session's remote
            // static key — prevents MITM forwarding a stolen HelloAck.
            if let Some(noise_remote) = noise.remote_static_key() {
                if x25519_public.as_slice() != noise_remote.as_slice() {
                    return Err(TransportError::Rejected(
                        "HelloAck x25519_public does not match Noise remote static key".into(),
                    ));
                }
            } else {
                return Err(TransportError::NoiseError(
                    "remote static key not available after handshake".into(),
                ));
            }

            info!(peer = %node_id, tier = ?tier, "federation handshake complete (initiator)");
            Ok((node_id, tier, capabilities, reader, writer, noise))
        }
        Frame::Disconnect { reason } => {
            Err(TransportError::Rejected(format!("peer disconnected: {reason}")))
        }
        other => Err(TransportError::WireProtocol(format!(
            "expected HelloAck, got {:?}",
            std::mem::discriminant(&other)
        ))),
    }
}

/// Perform federation handshake as responder.
pub(super) async fn perform_federation_handshake_responder(
    mut reader: tokio::io::ReadHalf<TcpStream>,
    mut writer: tokio::io::WriteHalf<TcpStream>,
    mut noise: NoiseSession,
    identity: &NodeIdentity,
    config: &TransportConfig,
    whitelist: &SharedWhitelist,
) -> Result<
    (
        NodeId,
        SovereigntyTier,
        Vec<Capability>,
        tokio::io::ReadHalf<TcpStream>,
        tokio::io::WriteHalf<TcpStream>,
        NoiseSession,
    ),
    TransportError,
> {
    // Receive Hello
    let frame = recv_encrypted_frame(&mut reader, &mut noise).await?;
    match frame {
        Frame::Hello {
            version,
            node_id,
            x25519_sig,
            x25519_public,
            tier,
            capabilities,
        } => {
            // Verify protocol version
            if version != config.version {
                let disconnect = Frame::Disconnect {
                    reason: format!("version mismatch: {version}"),
                };
                if let Err(e) = send_encrypted_frame(&mut writer, &mut noise, &disconnect).await {
                    warn!(error = %e, "failed to send disconnect frame on version mismatch");
                }
                return Err(TransportError::Rejected(format!(
                    "protocol version mismatch: local={}, remote={version}",
                    config.version
                )));
            }

            // Verify identity binding (Ed25519 signed X25519 key)
            verify_identity_binding(&node_id, &x25519_public, &x25519_sig)?;

            // Verify the claimed X25519 key matches the Noise session's remote
            // static key. Without this check, a MITM who completes a Noise
            // handshake with their own key could forward someone else's Hello.
            if let Some(noise_remote) = noise.remote_static_key() {
                if x25519_public.as_slice() != noise_remote.as_slice() {
                    return Err(TransportError::Rejected(
                        "Hello x25519_public does not match Noise remote static key".into(),
                    ));
                }
            } else {
                return Err(TransportError::NoiseError(
                    "remote static key not available after handshake".into(),
                ));
            }

            // Whitelist check BEFORE sending HelloAck (QA-M5: prevents identity leak
            // to unauthorized peers). Empty whitelist = reject all (Principle 3).
            let wl = whitelist.read().await;
            let whitelisted = !wl.is_empty() && wl.contains(&node_id);
            drop(wl);
            if !whitelisted {
                let disconnect = Frame::Disconnect {
                    reason: "not in whitelist".to_string(),
                };
                if let Err(e) = send_encrypted_frame(&mut writer, &mut noise, &disconnect).await {
                    warn!(error = %e, "failed to send disconnect frame on whitelist rejection");
                }
                return Err(TransportError::Rejected(format!(
                    "peer {} not in whitelist (checked before HelloAck)",
                    node_id.to_hex()
                )));
            }

            // Send HelloAck
            let ack = build_hello_ack_frame(identity, config, &noise);
            send_encrypted_frame(&mut writer, &mut noise, &ack).await?;

            info!(peer = %node_id, tier = ?tier, "federation handshake complete (responder)");
            Ok((node_id, tier, capabilities, reader, writer, noise))
        }
        Frame::Disconnect { reason } => {
            Err(TransportError::Rejected(format!("peer disconnected: {reason}")))
        }
        other => Err(TransportError::WireProtocol(format!(
            "expected Hello, got {:?}",
            std::mem::discriminant(&other)
        ))),
    }
}

// ─── connect_to_peer ────────────────────────────────────────────────────────

/// Connect to a peer (used by both `MessageTransport::connect` and supervisor).
///
/// Performs TCP connect → Noise handshake → federation handshake → registration.
pub(super) async fn connect_to_peer(
    peer: &NodeId,
    addr: &SocketAddr,
    ctx: &super::TransportCtx,
) -> Result<(), TransportError> {
    use std::sync::Arc;
    use std::time::Instant;
    use tokio::sync::Mutex;

    use super::{PeerConnection, spawn_reader_task};
    use super::ControlEvent;
    use konsensus_crypto::noise::NoiseSession;

    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| TransportError::ConnectionFailed(e.to_string()))?;

    info!(%addr, "TCP connected, starting Noise handshake");

    let (reader, writer) = tokio::io::split(stream);
    let noise = NoiseSession::initiator(ctx.identity.x25519_secret_bytes())
        .map_err(|e| TransportError::NoiseError(e.to_string()))?;

    let (reader, writer, noise) = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        noise_handshake_initiator(reader, writer, noise),
    )
    .await
    .map_err(|_| {
        TransportError::NoiseError(format!(
            "initiator Noise handshake timed out after {}s to {addr}",
            HANDSHAKE_TIMEOUT.as_secs()
        ))
    })??;

    let (peer_node_id, tier, capabilities, reader, mut writer, mut noise) =
        tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            perform_federation_handshake_initiator(
                reader, writer, noise, &ctx.identity, &ctx.config,
            ),
        )
        .await
        .map_err(|_| {
            TransportError::NoiseError(format!(
                "initiator federation handshake timed out after {}s to {addr}",
                HANDSHAKE_TIMEOUT.as_secs()
            ))
        })??;

    // Verify the peer is who we expect
    if &peer_node_id != peer {
        let disconnect = Frame::Disconnect {
            reason: "node ID mismatch".into(),
        };
        if let Ok(bytes) = disconnect.to_bytes() {
            if let Ok(encrypted) = noise.encrypt(&bytes) {
                if let Err(e) = write_noise_message(&mut writer, &encrypted).await {
                    warn!(error = %e, "failed to send disconnect frame on node ID mismatch");
                }
            }
        }
        return Err(TransportError::Rejected(format!(
            "expected peer {}, got {}",
            peer.to_hex(),
            peer_node_id.to_hex()
        )));
    }

    let now = Instant::now();
    let conn = Arc::new(Mutex::new(PeerConnection {
        noise,
        writer,
        tier,
        capabilities,
        last_recv: now,
        pending_ping: None,
        invalid_frame_count: 0,
        invalid_frame_window_start: now,
        bytes_received: 0,
        memory_budget_window_start: now,
    }));

    ctx.peers
        .write()
        .await
        .insert(peer_node_id, Arc::clone(&conn));

    spawn_reader_task(
        peer_node_id,
        reader,
        Arc::clone(&conn),
        Arc::clone(&ctx.peers),
        Arc::clone(&ctx.banned_peers),
        ctx.incoming_tx.clone(),
        ctx.control_tx.clone(),
    );

    // Notify application layer of new peer connection
    if let Err(e) = ctx
        .control_tx
        .send(ControlEvent::PeerConnected {
            peer_id: peer_node_id,
        })
        .await
    {
        warn!(peer = %peer_node_id, error = %e, "failed to send PeerConnected control event");
    }

    info!(peer = %peer_node_id, "peer connected and authenticated");
    Ok(())
}
