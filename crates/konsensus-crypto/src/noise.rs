//! Noise_XX transport encryption — wraps the `snow` crate.
//!
//! All node-to-node TCP connections are encrypted using the Noise_XX handshake pattern:
//! - Mutual authentication (both sides prove identity via static X25519 keys)
//! - Forward secrecy (ephemeral Diffie-Hellman keys per session)
//! - Identity hiding (static keys encrypted during handshake)
//!
//! The X25519 static keys come from `NodeIdentity` (in `konsensus_core`).
//!
//! # Noise_XX three-message handshake
//!
//! ```text
//! Initiator                        Responder
//! ─────────                        ─────────
//! → e                              (initiator sends ephemeral)
//! ← e, ee, s, es                   (responder ephemeral + static)
//! → s, se                          (initiator static)
//! ```
//!
//! After the handshake, both sides have an authenticated, encrypted channel
//! with forward secrecy.

use thiserror::Error;

/// Maximum plaintext payload per Noise message (65535 - 16 byte AEAD tag).
pub const MAX_NOISE_PAYLOAD: usize = 65535 - 16;

/// Maximum Noise message size on the wire (including AEAD tag).
pub const MAX_NOISE_MSG_LEN: usize = 65535;

/// The Noise protocol parameters string.
///
/// - XX: mutual authentication, identity hiding
/// - 25519: Curve25519 DH
/// - ChaChaPoly: ChaCha20-Poly1305 AEAD (faster than AES-GCM without hardware AES-NI)
/// - BLAKE2s: fast, secure hash
const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

/// Errors from Noise protocol operations.
#[derive(Debug, Error)]
pub enum NoiseError {
    /// Error from the underlying snow library.
    #[error("noise protocol error: {0}")]
    Snow(#[from] snow::Error),

    /// Attempted transport operation before handshake completed.
    #[error("handshake not complete")]
    HandshakeIncomplete,

    /// Attempted handshake operation after handshake completed.
    #[error("handshake already complete")]
    HandshakeAlreadyComplete,

    /// Remote static key not yet available (handshake not far enough).
    #[error("remote static key not available")]
    NoRemoteStatic,

    /// Session state was unexpectedly empty (internal error).
    #[error("session in invalid state")]
    InvalidState,
}

/// Internal state machine for the Noise session.
enum SessionState {
    /// Currently performing the three-message handshake.
    Handshaking(Box<snow::HandshakeState>),
    /// Handshake complete — encrypted transport ready.
    Transport(snow::TransportState),
}

/// A Noise_XX encrypted session between two nodes.
///
/// Wraps the `snow` crate to provide a clean API for the BitSov transport layer.
/// Each TCP connection gets its own `NoiseSession`.
pub struct NoiseSession {
    state: Option<SessionState>,
    is_initiator: bool,
    /// The remote peer's X25519 static public key, available after handshake.
    remote_static: Option<[u8; 32]>,
}

impl NoiseSession {
    /// Create a new session as the initiator (connecting side).
    ///
    /// `local_private_key` is the raw X25519 secret key bytes from `NodeIdentity`.
    pub fn initiator(local_private_key: &[u8; 32]) -> Result<Self, NoiseError> {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse()?;
        let handshake = snow::Builder::new(params)
            .local_private_key(local_private_key)
            .build_initiator()?;

        Ok(Self {
            state: Some(SessionState::Handshaking(Box::new(handshake))),
            is_initiator: true,
            remote_static: None,
        })
    }

    /// Create a new session as the responder (listening side).
    ///
    /// `local_private_key` is the raw X25519 secret key bytes from `NodeIdentity`.
    pub fn responder(local_private_key: &[u8; 32]) -> Result<Self, NoiseError> {
        let params: snow::params::NoiseParams = NOISE_PARAMS.parse()?;
        let handshake = snow::Builder::new(params)
            .local_private_key(local_private_key)
            .build_responder()?;

        Ok(Self {
            state: Some(SessionState::Handshaking(Box::new(handshake))),
            is_initiator: false,
            remote_static: None,
        })
    }

    /// Whether this side initiated the connection.
    pub fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Whether the handshake is complete and we're in transport mode.
    pub fn is_transport(&self) -> bool {
        matches!(self.state.as_ref(), Some(SessionState::Transport(_)))
    }

    /// Whether it's our turn to send the next handshake message.
    pub fn is_my_turn(&self) -> bool {
        match self.state.as_ref() {
            Some(SessionState::Handshaking(hs)) => hs.is_my_turn(),
            _ => false,
        }
    }

    /// Write the next handshake message.
    ///
    /// Returns the handshake message bytes to send to the peer.
    /// The optional `payload` is piggybacked in the handshake message
    /// (encrypted if the Noise pattern encrypts at this step).
    pub fn write_handshake(&mut self, payload: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let hs = match self.state.as_mut() {
            Some(SessionState::Handshaking(hs)) => hs,
            Some(SessionState::Transport(_)) => return Err(NoiseError::HandshakeAlreadyComplete),
            None => return Err(NoiseError::InvalidState),
        };

        let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];
        let len = hs.write_message(payload, &mut buf)?;
        buf.truncate(len);

        // Capture remote static key if now available
        if let Some(rs) = hs.get_remote_static() {
            let mut key = [0u8; 32];
            key.copy_from_slice(rs);
            self.remote_static = Some(key);
        }

        Ok(buf)
    }

    /// Read a handshake message from the peer.
    ///
    /// Returns any payload embedded in the handshake message.
    pub fn read_handshake(&mut self, message: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let hs = match self.state.as_mut() {
            Some(SessionState::Handshaking(hs)) => hs,
            Some(SessionState::Transport(_)) => return Err(NoiseError::HandshakeAlreadyComplete),
            None => return Err(NoiseError::InvalidState),
        };

        let mut buf = vec![0u8; MAX_NOISE_MSG_LEN];
        let len = hs.read_message(message, &mut buf)?;
        buf.truncate(len);

        // Capture remote static key if now available
        if let Some(rs) = hs.get_remote_static() {
            let mut key = [0u8; 32];
            key.copy_from_slice(rs);
            self.remote_static = Some(key);
        }

        Ok(buf)
    }

    /// Check if the handshake is finished and transition to transport mode.
    ///
    /// Returns `true` if we transitioned (or were already in transport mode).
    /// Returns `false` if the handshake is still in progress.
    pub fn try_finish_handshake(&mut self) -> Result<bool, NoiseError> {
        let is_finished = match self.state.as_ref() {
            Some(SessionState::Handshaking(hs)) => hs.is_handshake_finished(),
            Some(SessionState::Transport(_)) => return Ok(true),
            None => return Err(NoiseError::InvalidState),
        };

        if !is_finished {
            return Ok(false);
        }

        // Take ownership of the handshake state and transition
        let old_state = self.state.take().ok_or(NoiseError::InvalidState)?;
        match old_state {
            SessionState::Handshaking(hs) => {
                // Capture remote static before consuming
                if self.remote_static.is_none() {
                    if let Some(rs) = hs.get_remote_static() {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(rs);
                        self.remote_static = Some(key);
                    }
                }
                let transport = hs.into_transport_mode()?;
                self.state = Some(SessionState::Transport(transport));
                Ok(true)
            }
            SessionState::Transport(t) => {
                // Shouldn't happen due to early return, but handle gracefully
                self.state = Some(SessionState::Transport(t));
                Ok(true)
            }
        }
    }

    /// Encrypt a plaintext message for transport.
    ///
    /// Automatically chunks payloads that exceed the Noise protocol's 65,519-byte
    /// limit. Each chunk is prefixed with a `u16` BE length so the receiver can
    /// reassemble. Small messages (≤ `MAX_NOISE_PAYLOAD`) produce a single chunk.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let transport = match self.state.as_mut() {
            Some(SessionState::Transport(t)) => t,
            Some(SessionState::Handshaking(_)) => return Err(NoiseError::HandshakeIncomplete),
            None => return Err(NoiseError::InvalidState),
        };

        let mut output = Vec::new();
        for chunk in plaintext.chunks(MAX_NOISE_PAYLOAD) {
            // snow adds 16 bytes AEAD tag
            let mut buf = vec![0u8; chunk.len() + 16];
            let len = transport.write_message(chunk, &mut buf)?;
            // u16 BE length prefix per chunk
            let chunk_len = u16::try_from(len).map_err(|_| {
                NoiseError::Snow(snow::Error::Input)
            })?;
            output.extend_from_slice(&chunk_len.to_be_bytes());
            output.extend_from_slice(&buf[..len]);
        }
        Ok(output)
    }

    /// Decrypt an incoming Noise message.
    ///
    /// Parses length-prefixed chunks produced by [`Self::encrypt`], decrypts each,
    /// and reassembles the original plaintext.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let transport = match self.state.as_mut() {
            Some(SessionState::Transport(t)) => t,
            Some(SessionState::Handshaking(_)) => return Err(NoiseError::HandshakeIncomplete),
            None => return Err(NoiseError::InvalidState),
        };

        let mut output = Vec::new();
        let mut cursor = 0;
        while cursor < ciphertext.len() {
            if cursor + 2 > ciphertext.len() {
                return Err(NoiseError::Snow(snow::Error::Input));
            }
            let chunk_len =
                u16::from_be_bytes([ciphertext[cursor], ciphertext[cursor + 1]]) as usize;
            cursor += 2;
            if cursor + chunk_len > ciphertext.len() {
                return Err(NoiseError::Snow(snow::Error::Input));
            }
            let mut buf = vec![0u8; chunk_len];
            let len = transport.read_message(&ciphertext[cursor..cursor + chunk_len], &mut buf)?;
            output.extend_from_slice(&buf[..len]);
            cursor += chunk_len;
        }
        Ok(output)
    }

    /// Get the remote peer's X25519 static public key.
    ///
    /// Available after the second handshake message (for the initiator)
    /// or after the third (for the responder).
    pub fn remote_static_key(&self) -> Option<&[u8; 32]> {
        self.remote_static.as_ref()
    }
}

#[cfg(test)]
#[path = "tests/noise.rs"]
mod tests;
