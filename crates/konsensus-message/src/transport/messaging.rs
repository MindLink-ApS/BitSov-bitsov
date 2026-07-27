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

    /// M1b promote-on-paid: flip a connection's `privileged` flag to `true`.
    ///
    /// Called by the message-plane handler AFTER the PaymentGate accepts a PAID,
    /// M2-recipient-bound UKM from `peer`. The peer map is keyed by the
    /// AUTHENTICATED federation NodeId, so passing `envelope.sender` here promotes
    /// ONLY the connection that authenticated as that sender — a relayer that
    /// forwards someone else's payment proof cannot promote its own connection
    /// (the binding `envelope.sender == connection.peer_id`).
    ///
    /// Returns `true` if a connection keyed by `peer` existed and was flipped (or
    /// was already privileged), `false` if no such connection is live. The flip is
    /// in-memory and effective on the NEXT frame the reader stamps for that
    /// connection. Durable persistence of the promotion is a follow-up; an
    /// unprivileged reconnect simply re-runs the one-invoice admission pay-loop.
    pub async fn promote_to_privileged(&self, peer: &NodeId) -> bool {
        let conn = {
            let peers = self.peers.read().await;
            match peers.get(peer) {
                Some(c) => Arc::clone(c),
                None => return false,
            }
        };
        let mut conn = conn.lock().await;
        if !conn.privileged {
            conn.privileged = true;
            info!(peer = %peer, "promoted connection to privileged after settled payment (M1b)");
        }
        true
    }

    /// Connected peers that are currently **privileged** — whitelisted in
    /// `Whitelist` mode, or promoted by a settled, recipient-bound payment in
    /// `PriceOpen` (the same `conn.privileged` flag [`promote_to_privileged`]
    /// flips and the reader stamps onto control events).
    ///
    /// The E2EE self-heal loop iterates THIS — never `connected_peers` — so the
    /// node never proactively ships its X3DH prekey bundle to an unpaid PriceOpen
    /// stranger. The `PeerConnected` path already withholds the prekey from
    /// unprivileged peers, but the periodic self-heal would otherwise re-offer it
    /// to every connected peer regardless of privilege (P2: no free X3DH before
    /// payment — no prekey before settlement).
    ///
    /// [`promote_to_privileged`]: NoiseTransport::promote_to_privileged
    pub async fn connected_privileged_peers(&self) -> Vec<NodeId> {
        // Scoped-clone the Arcs first so the `peers` read guard is not held across
        // each `conn.lock().await` (same lock-ordering discipline as `send_frame`
        // and `promote_to_privileged`).
        let conns: Vec<(NodeId, Arc<Mutex<PeerConnection>>)> = {
            let peers = self.peers.read().await;
            peers.iter().map(|(id, c)| (*id, Arc::clone(c))).collect()
        };
        let mut privileged = Vec::with_capacity(conns.len());
        for (id, conn) in conns {
            if conn.lock().await.privileged {
                privileged.push(id);
            }
        }
        privileged
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

                        // Decay-only leaky bucket. Drain tokens for the real time
                        // elapsed since the last update, then add one for this bad
                        // frame. The level is sticky — valid frames never touch it —
                        // so interleaving cheap valid frames cannot refill the
                        // bad-frame allowance (the reset-on-valid bypass).
                        let leak_per_sec =
                            INVALID_FRAME_BUDGET as f64 / INVALID_FRAME_WINDOW.as_secs_f64();
                        let elapsed = now
                            .duration_since(conn.invalid_frame_last_leak)
                            .as_secs_f64();
                        conn.invalid_frame_level =
                            (conn.invalid_frame_level - leak_per_sec * elapsed).max(0.0);
                        conn.invalid_frame_last_leak = now;

                        conn.invalid_frame_level += 1.0;
                        let level = conn.invalid_frame_level;

                        if level > INVALID_FRAME_BUDGET as f64 {
                            warn!(
                                peer = %peer_id,
                                invalid_level = level,
                                error = %e,
                                "frame validation budget exceeded — disconnecting and banning peer"
                            );
                            true
                        } else {
                            warn!(
                                peer = %peer_id,
                                invalid_level = level,
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

            // Valid frame received — record liveness for keepalive. We deliberately
            // do NOT drain the invalid-frame leaky bucket here: that bucket is
            // decay-only and falls solely with elapsed real time. Resetting it on a
            // valid frame would let an attacker interleave one cheap valid frame
            // between bursts of garbage to keep the bad-frame allowance topped up
            // forever (the reset-on-valid bypass this fix closes).
            //
            // M1b: snapshot `privileged` under the SAME lock so the dangerous
            // ControlEvent variants below carry the connection's CURRENT privilege.
            // promote_to_privileged flips this flag; reading it per frame means a
            // promotion is honoured on the very next frame. In Whitelist mode this
            // is always `true`, so every stamped arm behaves byte-identically.
            let privileged = {
                let mut conn = conn.lock().await;
                conn.last_recv = Instant::now();
                conn.privileged
            };

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
                            privileged,
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
                            privileged,
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
                            privileged,
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
                            privileged,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send SessionInit control event");
                    }
                }
                Frame::SessionAck => {
                    debug!(peer = %peer_id, "received session ack");
                    if let Err(e) = control_tx
                        .send(ControlEvent::SessionAck { peer_id, privileged })
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
                            privileged,
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
                            privileged,
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
                            privileged,
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
                            privileged,
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
                            privileged,
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
                            privileged,
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
                            privileged,
                        })
                        .await
                    {
                        warn!(peer = %peer_id, error = %e, "failed to send PriceResponseReceived control event");
                    }
                }
                Frame::PeerExchangeRequest => {
                    debug!(peer = %peer_id, "received peer exchange request");
                    if let Err(e) = control_tx
                        .send(ControlEvent::PeerExchangeRequested { peer_id, privileged })
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
                        .send(ControlEvent::PeerExchangeReceived { peer_id, peers, privileged })
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
                            privileged,
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
