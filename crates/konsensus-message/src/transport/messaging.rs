//! Frame send/receive, reader task.

use std::sync::Arc;
use std::time::Instant;

use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use konsensus_core::envelope::UkmEnvelope;
use konsensus_core::traits::transport::TransportError;
use konsensus_core::types::NodeId;

use crate::wire::Frame;

use super::{
    write_noise_message, read_noise_message,
    BanMap, ControlEvent, PeerConnection, PeerMap,
    FRAME_BAN_DURATION, INVALID_FRAME_BUDGET, INVALID_FRAME_WINDOW,
    MEMORY_BUDGET_WINDOW, PEER_MEMORY_BUDGET,
};
use super::NoiseTransport;

// ─── impl NoiseTransport — send_frame ────────────────────────────────────────

impl NoiseTransport {
    /// Send an arbitrary wire protocol frame to a connected peer.
    ///
    /// Used by the session handler to send PrekeyOffer, SessionInit,
    /// SessionAck, MessageAck, and MessageReject frames.
    pub async fn send_frame(
        &self,
        peer: &NodeId,
        frame: &Frame,
    ) -> Result<(), TransportError> {
        // Clone the Arc so we can drop the RwLock read guard before doing
        // network I/O.  Holding the read guard across write_noise_message()
        // would block peer-map mutations (connect / disconnect) for the
        // duration of the TCP write.
        let conn = {
            let peers = self.peers.read().await;
            Arc::clone(
                peers
                    .get(peer)
                    .ok_or_else(|| TransportError::NotConnected(peer.to_hex()))?,
            )
        };

        let frame_bytes = frame
            .to_bytes()
            .map_err(|e| TransportError::WireProtocol(e.to_string()))?;

        let mut conn = conn.lock().await;
        let encrypted = conn
            .noise
            .encrypt(&frame_bytes)
            .map_err(|e| TransportError::NoiseError(e.to_string()))?;

        write_noise_message(&mut conn.writer, &encrypted)
            .await
            .map_err(|e| TransportError::Other(e.to_string()))?;

        Ok(())
    }

    /// Send raw bytes to a peer (for testing frame validation budget).
    ///
    /// Encrypts arbitrary bytes through the Noise channel without frame validation.
    /// This allows testing how the receiver handles garbage frames.
    #[cfg(test)]
    pub(crate) async fn send_raw_bytes(
        &self,
        peer: &NodeId,
        raw: &[u8],
    ) -> Result<(), TransportError> {
        let peers = self.peers.read().await;
        let conn = peers
            .get(peer)
            .ok_or_else(|| TransportError::NotConnected(peer.to_hex()))?;

        let mut conn = conn.lock().await;
        let encrypted = conn
            .noise
            .encrypt(raw)
            .map_err(|e| TransportError::NoiseError(e.to_string()))?;

        write_noise_message(&mut conn.writer, &encrypted)
            .await
            .map_err(|e| TransportError::Other(e.to_string()))?;

        Ok(())
    }
}

// ─── spawn_reader_task ───────────────────────────────────────────────────────

/// Spawn a background task that reads frames from a peer's TCP stream.
pub(super) fn spawn_reader_task(
    peer_id: NodeId,
    mut reader: tokio::io::ReadHalf<TcpStream>,
    conn: Arc<Mutex<PeerConnection>>,
    peers: PeerMap,
    banned_peers: BanMap,
    incoming_tx: mpsc::Sender<UkmEnvelope>,
    control_tx: mpsc::Sender<ControlEvent>,
) {
    tokio::spawn(async move {
        loop {
            // Read the next encrypted message
            let encrypted = match read_noise_message(&mut reader).await {
                Ok(data) => data,
                Err(e) => {
                    debug!(peer = %peer_id, error = %e, "peer reader error, disconnecting");
                    break;
                }
            };

            // Decrypt
            let decrypted = {
                let mut conn = conn.lock().await;
                match conn.noise.decrypt(&encrypted) {
                    Ok(data) => data,
                    Err(e) => {
                        warn!(peer = %peer_id, error = %e, "decryption failed, disconnecting");
                        break;
                    }
                }
            };

            // Track per-peer memory usage — prevents a single peer from
            // exhausting node memory by sending many large frames.
            {
                let mut conn = conn.lock().await;
                let now = Instant::now();
                if now.duration_since(conn.memory_budget_window_start) >= MEMORY_BUDGET_WINDOW {
                    conn.bytes_received = 0;
                    conn.memory_budget_window_start = now;
                }
                conn.bytes_received += encrypted.len() as u64;
                if conn.bytes_received > PEER_MEMORY_BUDGET {
                    warn!(
                        peer = %peer_id,
                        bytes = conn.bytes_received,
                        budget = PEER_MEMORY_BUDGET,
                        "per-connection memory budget exceeded — disconnecting and banning peer"
                    );
                    drop(conn);
                    banned_peers.write().await.insert(
                        peer_id,
                        Instant::now() + FRAME_BAN_DURATION,
                    );
                    break;
                }
            }

            // Parse frame — track invalid frames for validation budget
            let frame = match Frame::from_bytes(&decrypted) {
                Ok(f) => f,
                Err(e) => {
                    let should_ban = {
                        let mut conn = conn.lock().await;
                        let now = Instant::now();

                        // Reset counter if the window has expired
                        if now.duration_since(conn.invalid_frame_window_start)
                            >= INVALID_FRAME_WINDOW
                        {
                            conn.invalid_frame_count = 0;
                            conn.invalid_frame_window_start = now;
                        }

                        conn.invalid_frame_count += 1;
                        let count = conn.invalid_frame_count;

                        if count > INVALID_FRAME_BUDGET {
                            warn!(
                                peer = %peer_id,
                                invalid_count = count,
                                error = %e,
                                "frame validation budget exceeded — disconnecting and banning peer"
                            );
                            true
                        } else {
                            warn!(
                                peer = %peer_id,
                                invalid_count = count,
                                budget = INVALID_FRAME_BUDGET,
                                error = %e,
                                "invalid frame (budget warning)"
                            );
                            false
                        }
                    };

                    if should_ban {
                        // Add to ban list
                        banned_peers.write().await.insert(
                            peer_id,
                            Instant::now() + FRAME_BAN_DURATION,
                        );
                        break;
                    }
                    continue;
                }
            };

            // Valid frame received — reset invalid frame counter
            {
                let mut conn = conn.lock().await;
                conn.last_recv = Instant::now();
                conn.invalid_frame_count = 0;
                conn.invalid_frame_window_start = Instant::now();
            }

            // Handle frame
            match frame {
                Frame::Message(envelope) => {
                    debug!(peer = %peer_id, msg_id = %envelope.id, "received envelope");
                    if incoming_tx.send(*envelope).await.is_err() {
                        debug!(peer = %peer_id, "incoming channel closed, stopping reader");
                        break;
                    }
                }
                Frame::Ping { nonce } => {
                    debug!(peer = %peer_id, "received ping, sending pong");
                    let pong = Frame::Pong { nonce };
                    let mut conn = conn.lock().await;
                    if let Ok(bytes) = pong.to_bytes() {
                        if let Ok(encrypted) = conn.noise.encrypt(&bytes) {
                            if let Err(e) = write_noise_message(&mut conn.writer, &encrypted).await {
                                warn!(peer = %peer_id, error = %e, "failed to send pong reply");
                            }
                        }
                    }
                }
                Frame::Pong { nonce } => {
                    debug!(peer = %peer_id, %nonce, "received pong");
                    // Clear pending ping — keepalive supervisor will see this
                    let mut conn = conn.lock().await;
                    if conn.pending_ping == Some(nonce) {
                        conn.pending_ping = None;
                    }
                }
                Frame::Disconnect { reason } => {
                    info!(peer = %peer_id, %reason, "peer disconnected gracefully");
                    break;
                }
                Frame::MessageAck { id } => {
                    debug!(peer = %peer_id, msg_id = %id, "received message ack");
                    if let Err(e) = control_tx
                        .send(ControlEvent::MessageAcked {
                            peer_id,
                            message_id: id,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send MessageAcked control event");
                    }
                }
                Frame::MessageReject { id, reason } => {
                    warn!(peer = %peer_id, msg_id = %id, %reason, "message rejected by peer");
                    if let Err(e) = control_tx
                        .send(ControlEvent::MessageRejected {
                            peer_id,
                            message_id: id,
                            reason,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send MessageRejected control event");
                    }
                }
                Frame::PrekeyOffer { bundle } => {
                    debug!(peer = %peer_id, "received prekey offer");
                    if let Err(e) = control_tx
                        .send(ControlEvent::PrekeyOffer {
                            peer_id,
                            bundle,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send PrekeyOffer control event");
                    }
                }
                Frame::SessionInit { init_data } => {
                    debug!(peer = %peer_id, "received session init");
                    if let Err(e) = control_tx
                        .send(ControlEvent::SessionInit {
                            peer_id,
                            init_data,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send SessionInit control event");
                    }
                }
                Frame::SessionAck => {
                    debug!(peer = %peer_id, "received session ack");
                    if let Err(e) = control_tx
                        .send(ControlEvent::SessionAck { peer_id })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send SessionAck control event");
                    }
                }
                Frame::RatchetInit { payload } => {
                    debug!(peer = %peer_id, "received ratchet init");
                    if let Err(e) = control_tx
                        .send(ControlEvent::RatchetInit {
                            peer_id,
                            payload,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send RatchetInit control event");
                    }
                }
                Frame::RequestInvoice { request_id, amount_msat, purpose } => {
                    debug!(
                        peer = %peer_id,
                        %request_id,
                        amount_msat,
                        %purpose,
                        "received invoice request"
                    );
                    if let Err(e) = control_tx
                        .send(ControlEvent::InvoiceRequested {
                            peer_id,
                            request_id,
                            amount_msat,
                            purpose,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send InvoiceRequested control event");
                    }
                }
                Frame::InvoiceResponse { request_id, bolt11, payment_hash } => {
                    debug!(
                        peer = %peer_id,
                        %request_id,
                        "received invoice response"
                    );
                    if let Err(e) = control_tx
                        .send(ControlEvent::InvoiceResponseReceived {
                            peer_id,
                            request_id,
                            bolt11,
                            payment_hash,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send InvoiceResponseReceived control event");
                    }
                }
                Frame::InvoiceError { request_id, reason } => {
                    debug!(
                        peer = %peer_id,
                        %request_id,
                        %reason,
                        "received invoice error"
                    );
                    if let Err(e) = control_tx
                        .send(ControlEvent::InvoiceErrorReceived {
                            peer_id,
                            request_id,
                            reason,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send InvoiceErrorReceived control event");
                    }
                }
                Frame::LightningInfo { ln_pubkey, ln_addr } => {
                    info!(
                        peer = %peer_id,
                        ln_pubkey_prefix = &ln_pubkey[..std::cmp::min(16, ln_pubkey.len())],
                        ln_addr = ln_addr.as_deref().unwrap_or("none"),
                        "received Lightning pubkey for keysend"
                    );
                    if let Err(e) = control_tx
                        .send(ControlEvent::LightningInfoReceived {
                            peer_id,
                            ln_pubkey,
                            ln_addr,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send LightningInfoReceived control event");
                    }
                }
                Frame::PriceTable { prices, block_height, valid_blocks, trust_discount } => {
                    debug!(
                        peer = %peer_id,
                        categories = prices.len(),
                        block_height,
                        trust_discount,
                        "received price table"
                    );
                    if let Err(e) = control_tx
                        .send(ControlEvent::PriceTableReceived {
                            peer_id,
                            prices,
                            block_height,
                            valid_blocks,
                            trust_discount,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send PriceTableReceived control event");
                    }
                }
                Frame::PriceQuery { kind } => {
                    debug!(peer = %peer_id, kind, "received price query");
                    if let Err(e) = control_tx
                        .send(ControlEvent::PriceQueryReceived {
                            peer_id,
                            kind,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send PriceQueryReceived control event");
                    }
                }
                Frame::PriceResponse { kind, price_msat, block_height } => {
                    debug!(
                        peer = %peer_id,
                        kind,
                        price_msat,
                        block_height,
                        "received price response"
                    );
                    if let Err(e) = control_tx
                        .send(ControlEvent::PriceResponseReceived {
                            peer_id,
                            kind,
                            price_msat,
                            block_height,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send PriceResponseReceived control event");
                    }
                }
                Frame::PeerExchangeRequest => {
                    debug!(peer = %peer_id, "received peer exchange request");
                    if let Err(e) = control_tx
                        .send(ControlEvent::PeerExchangeRequested { peer_id })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send PeerExchangeRequested control event");
                    }
                }
                Frame::PeerExchangeResponse { peers } => {
                    let count = peers.len();
                    // Cap at 50 entries to prevent abuse
                    let peers: Vec<_> = peers.into_iter().take(50).collect();
                    debug!(peer = %peer_id, count, "received peer exchange response");
                    if let Err(e) = control_tx
                        .send(ControlEvent::PeerExchangeReceived { peer_id, peers })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send PeerExchangeReceived control event");
                    }
                }
                Frame::Gossip(envelope) => {
                    debug!(
                        peer = %peer_id,
                        sender = %envelope.sender,
                        msg_id = %envelope.id,
                        kind = envelope.kind,
                        "received gossip message"
                    );
                    if let Err(e) = control_tx
                        .send(ControlEvent::GossipReceived {
                            from_peer: peer_id,
                            envelope,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send GossipReceived control event");
                    }
                }
                Frame::CallOffer { session_id, .. } => {
                    warn!(peer = %peer_id, %session_id, "rejected legacy unpaid call offer frame; use paid UKM realtime kind");
                }
                Frame::CallAnswer { session_id, .. } => {
                    warn!(peer = %peer_id, %session_id, "rejected legacy unpaid call answer frame; use paid UKM realtime kind");
                }
                Frame::IceCandidate { session_id, .. } => {
                    warn!(peer = %peer_id, %session_id, "rejected legacy unpaid ICE candidate frame; use paid UKM realtime kind");
                }
                Frame::CallEnd { session_id, .. } => {
                    warn!(peer = %peer_id, %session_id, "rejected legacy unpaid call end frame; use paid UKM realtime kind");
                }
                _ => {
                    warn!(peer = %peer_id, "unexpected frame type in reader loop");
                }
            }
        }

        // Clean up: remove peer from connection map
        peers.write().await.remove(&peer_id);
        debug!(peer = %peer_id, "peer connection cleaned up");
    });
}
