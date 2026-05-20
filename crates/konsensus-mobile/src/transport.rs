//! Noise-over-WSS transport.
//!
//! Layered encryption:
//!   Application payload
//!   └── Noise_XX_25519_ChaChaPoly_BLAKE2s (encrypted frame)
//!       └── WebSocket binary frame (RFC 6455)
//!           └── TCP / TLS (WSS in prod, plain WS for localhost tests)
//!
//! Handshake sequence (initiator left, responder right):
//!   → msg1 (e)
//!   ← msg2 (e, ee, s, es)
//!   → msg3 (s, se)
//!   ── transport phase ──

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use snow::{Builder as NoiseBuilder, TransportState};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message as WsMessage};
use tracing::{debug, trace};

use crate::error::MobileError;

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Maximum plaintext bytes per Noise message (65535 − 16 byte AEAD tag).
pub const MAX_NOISE_PAYLOAD: usize = 65_519;

type WsError = tokio_tungstenite::tungstenite::Error;
type WsSink = Box<dyn Sink<WsMessage, Error = WsError> + Send + Unpin>;
type WsSource = Box<dyn Stream<Item = Result<WsMessage, WsError>> + Send + Unpin>;

/// An authenticated, forward-secret, bidirectional Noise-over-WS channel.
///
/// Created by [`NoiseWssTransport::connect`] (initiator) or
/// [`NoiseWssTransport::accept`] (responder). The Noise_XX handshake is
/// complete by the time this type is returned to the caller.
pub struct NoiseWssTransport {
    sink: WsSink,
    stream: WsSource,
    noise: TransportState,
    remote_static: [u8; 32],
}

impl NoiseWssTransport {
    /// Connect to a `ws://` or `wss://` endpoint as the Noise initiator.
    pub async fn connect(
        endpoint: &str,
        local_static_key: &[u8; 32],
    ) -> Result<Self, MobileError> {
        debug!(endpoint, "connecting WebSocket");
        let (ws, _) = connect_async(endpoint)
            .await
            .map_err(MobileError::transport)?;
        let (sink, stream) = ws.split();
        Self::handshake_initiator(Box::new(sink), Box::new(stream), local_static_key).await
    }

    /// Accept a raw async stream as the Noise responder.
    ///
    /// Performs the WebSocket upgrade handshake, then the Noise_XX handshake.
    /// Used in integration tests; will also be used on the node side.
    pub async fn accept<S>(raw: S, local_static_key: &[u8; 32]) -> Result<Self, MobileError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("accepting WebSocket connection");
        let ws = accept_async(raw).await.map_err(MobileError::transport)?;
        let (sink, stream) = ws.split();
        Self::handshake_responder(Box::new(sink), Box::new(stream), local_static_key).await
    }

    /// Encrypt `payload` and send it as a single binary WebSocket frame.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), MobileError> {
        if payload.len() > MAX_NOISE_PAYLOAD {
            return Err(MobileError::PayloadTooLarge { size: payload.len() as u64 });
        }
        let mut buf = vec![0u8; payload.len() + 16];
        let n = self.noise.write_message(payload, &mut buf).map_err(MobileError::noise)?;
        buf.truncate(n);
        trace!(plaintext_len = payload.len(), ciphertext_len = n, "sending frame");
        self.sink.send(WsMessage::Binary(buf)).await.map_err(MobileError::transport)
    }

    /// Receive and decrypt the next binary frame from the peer.
    pub async fn recv(&mut self) -> Result<Vec<u8>, MobileError> {
        loop {
            match self.stream.next().await {
                None => return Err(MobileError::ConnectionClosed),
                Some(Err(e)) => return Err(MobileError::transport(e)),
                Some(Ok(WsMessage::Binary(frame))) => {
                    let mut plain = vec![0u8; frame.len()];
                    let n = self.noise.read_message(&frame, &mut plain).map_err(MobileError::noise)?;
                    plain.truncate(n);
                    trace!(ciphertext_len = frame.len(), plaintext_len = n, "received frame");
                    return Ok(plain);
                }
                Some(Ok(WsMessage::Close(_))) => return Err(MobileError::ConnectionClosed),
                Some(Ok(_)) => continue,
            }
        }
    }

    /// Remote peer's Noise static X25519 public key (32 bytes), verified during handshake.
    pub fn remote_static(&self) -> &[u8; 32] {
        &self.remote_static
    }

    // ── Handshake internals ───────────────────────────────────────────────────

    async fn handshake_initiator(
        mut sink: WsSink,
        mut stream: WsSource,
        local_key: &[u8; 32],
    ) -> Result<Self, MobileError> {
        let params = NOISE_PARAMS.parse().map_err(MobileError::noise)?;
        let mut hs = NoiseBuilder::new(params)
            .local_private_key(local_key)
            .build_initiator()
            .map_err(MobileError::noise)?;

        // msg1 → e
        sink.send(WsMessage::Binary(hs_write(&mut hs, &[])?))
            .await
            .map_err(MobileError::transport)?;
        debug!("noise: sent msg1 (e)");

        // msg2 ← e, ee, s, es
        hs_read(&mut hs, &recv_binary(&mut stream).await?)?;
        debug!("noise: received msg2 (e, ee, s, es)");

        // msg3 → s, se
        sink.send(WsMessage::Binary(hs_write(&mut hs, &[])?))
            .await
            .map_err(MobileError::transport)?;
        debug!("noise: sent msg3 (s, se) — handshake complete");

        into_transport(sink, stream, hs)
    }

    async fn handshake_responder(
        mut sink: WsSink,
        mut stream: WsSource,
        local_key: &[u8; 32],
    ) -> Result<Self, MobileError> {
        let params = NOISE_PARAMS.parse().map_err(MobileError::noise)?;
        let mut hs = NoiseBuilder::new(params)
            .local_private_key(local_key)
            .build_responder()
            .map_err(MobileError::noise)?;

        // msg1 ← e
        hs_read(&mut hs, &recv_binary(&mut stream).await?)?;
        debug!("noise: received msg1 (e)");

        // msg2 → e, ee, s, es
        sink.send(WsMessage::Binary(hs_write(&mut hs, &[])?))
            .await
            .map_err(MobileError::transport)?;
        debug!("noise: sent msg2 (e, ee, s, es)");

        // msg3 ← s, se
        hs_read(&mut hs, &recv_binary(&mut stream).await?)?;
        debug!("noise: received msg3 (s, se) — handshake complete");

        into_transport(sink, stream, hs)
    }
}

// ── Free helpers ──────────────────────────────────────────────────────────────

fn hs_write(hs: &mut snow::HandshakeState, payload: &[u8]) -> Result<Vec<u8>, MobileError> {
    let mut buf = vec![0u8; 65535];
    let n = hs.write_message(payload, &mut buf).map_err(MobileError::noise)?;
    buf.truncate(n);
    Ok(buf)
}

fn hs_read(hs: &mut snow::HandshakeState, msg: &[u8]) -> Result<(), MobileError> {
    let mut buf = vec![0u8; 65535];
    hs.read_message(msg, &mut buf).map_err(MobileError::noise)?;
    Ok(())
}

async fn recv_binary(stream: &mut WsSource) -> Result<Vec<u8>, MobileError> {
    loop {
        match stream.next().await {
            None => return Err(MobileError::ConnectionClosed),
            Some(Err(e)) => return Err(MobileError::transport(e)),
            Some(Ok(WsMessage::Binary(b))) => return Ok(b),
            Some(Ok(WsMessage::Close(_))) => return Err(MobileError::ConnectionClosed),
            Some(Ok(_)) => continue,
        }
    }
}

fn into_transport(
    sink: WsSink,
    stream: WsSource,
    hs: snow::HandshakeState,
) -> Result<NoiseWssTransport, MobileError> {
    let rs = hs
        .get_remote_static()
        .ok_or_else(|| MobileError::noise("remote static key unavailable after handshake"))?;
    if rs.len() != 32 {
        return Err(MobileError::noise("remote static key is not 32 bytes"));
    }
    let mut remote_static = [0u8; 32];
    remote_static.copy_from_slice(rs);

    let noise = hs.into_transport_mode().map_err(MobileError::noise)?;
    debug!(remote_static = %hex::encode(remote_static), "noise transport established");

    Ok(NoiseWssTransport { sink, stream, noise, remote_static })
}
