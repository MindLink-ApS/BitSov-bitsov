//! Shared wire format for the node's Noise-protected remote-access tunnel.
//!
//! The public listener carries bounded, length-prefixed Noise messages, or a
//! generic plaintext retry hint when refusing a handshake before Noise.
//! HTTP and WebSocket bytes exist only inside the encrypted transport and on
//! the node's loopback connection to the ordinary Axum router.

use std::io;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use konsensus_crypto::noise::{NoiseSession, MAX_NOISE_MSG_LEN};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::auth::Scope;

pub const VERSION: u8 = 1;
pub const PAIR_LINK_PREFIX: &str = "bitsov://pair/";
pub const TRANSPORT_PROOF_DOMAIN: &str = "bitsov-remote-transport-v1";
pub const BOX_TRANSPORT_PROOF_DOMAIN: &str = "bitsov-box-transport-v1";
pub const PAIRING_PROOF_DOMAIN: &str = "bitsov-remote-pair-v1";

/// Keep tunnel records well below Noise's maximum to bound allocation and
/// make cancellation responsive even for a busy WebSocket.
pub const MAX_TUNNEL_PLAINTEXT: usize = 16 * 1024;
/// A Noise transport record contains a two-byte inner length and a 16-byte tag.
pub const MAX_TRANSPORT_FRAME: usize = MAX_TUNNEL_PLAINTEXT + 2 + 16;
pub const MAX_AUTH_PLAINTEXT: usize = 8 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairLink {
    pub v: u8,
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub node_id: String,
    // Keep the live static proof during the U1 transport migration.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transport_pubkey: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub transport_signature: String,
    #[serde(default)]
    pub box_transport_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub box_transport_signature: Option<String>,
    pub code: String,
    /// Unix seconds; zero identifies a legacy, non-durable link.
    #[serde(default)]
    pub expires_at: i64,
    #[serde(default)]
    pub hosted_by: Option<String>,
}

impl PairLink {
    pub fn to_uri(&self) -> Result<String, serde_json::Error> {
        let json = serde_json::to_vec(self)?;
        Ok(format!(
            "{PAIR_LINK_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(json)
        ))
    }

    pub fn from_uri(uri: &str) -> Result<Self, String> {
        let encoded = uri
            .strip_prefix(PAIR_LINK_PREFIX)
            .ok_or_else(|| "invalid pairing link prefix".to_string())?;
        let json = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| format!("invalid pairing link base64: {e}"))?;
        let link: Self =
            serde_json::from_slice(&json).map_err(|_| "invalid pairing link JSON".to_string())?;
        if link.v != VERSION {
            return Err(format!("unsupported pairing link version {}", link.v));
        }
        Ok(link)
    }
}

/// The exact UTF-8 string signed by the node's Ed25519 identity for a pair
/// link. The signature proves that the advertised Noise static belongs to the
/// NodeId in the same link.
pub fn transport_proof_message(node_id_hex: &str, transport_pubkey_hex: &str) -> String {
    format!("{TRANSPORT_PROOF_DOMAIN}:{node_id_hex}:{transport_pubkey_hex}")
}

/// Bind the seed-independent box Noise static to a trusted node identity.
/// Clients verify this proof during an unlocked session before saving a box pin.
/// Encoding matches transport proofs: lowercase hex keys, base64url-no-pad signature.
pub fn box_transport_proof_message(node_id_hex: &str, box_transport_pubkey_hex: &str) -> String {
    format!("{BOX_TRANSPORT_PROOF_DOMAIN}:{node_id_hex}:{box_transport_pubkey_hex}")
}

/// First encrypted message after Noise_XX. With `code`, every optional field
/// below is required. Without `code`, all of them must be absent and the Noise
/// remote static is looked up in the durable pairing store.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthRequest {
    pub v: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    /// Ed25519 pairing public key, lowercase hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_pubkey: Option<String>,
    /// Base64url-no-pad Ed25519 signature over [`pairing_proof_message`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// The exact UTF-8 string a first-pairing client signs. The client name is
/// intentionally cosmetic and is not an authority input.
pub fn pairing_proof_message(
    node_id_hex: &str,
    client_transport_pubkey_hex: &str,
    code: &str,
    client_pubkey_hex: &str,
) -> String {
    format!(
        "{PAIRING_PROOF_DOMAIN}:{node_id_hex}:{client_transport_pubkey_hex}:{code}:{client_pubkey_hex}"
    )
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AuthResponse {
    Ok {
        v: u8,
        client_id: String,
        scopes: Vec<Scope>,
        /// Lowercase hex X25519 public key; not the live responder static in U1.
        box_transport_pubkey: String,
        /// Base64url-no-pad Ed25519 proof over [`box_transport_proof_message`].
        box_transport_signature: String,
    },
    Error {
        v: u8,
        code: String,
        message: String,
    },
}

/// Optional first server frame instead of Noise message 2, followed by close.
/// This plaintext, unauthenticated hint confers no authority. It carries no
/// node/client identity, pairing status, or endpoint information. Clients may
/// defer reconnects by `retry_after_secs` (integer seconds, 1..=60), then must
/// perform the usual pinned Noise handshake and authentication on a new TCP
/// connection. Older clients fail the Noise handshake safely.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "code", rename_all = "snake_case", deny_unknown_fields)]
pub enum HandshakeRefusal {
    RateLimited { v: u8, retry_after_secs: u64 },
}

/// Write one outer record: unsigned 32-bit big-endian byte length followed by
/// exactly that many bytes.
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_NOISE_MSG_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "remote-access frame length out of bounds",
        ));
    }
    writer
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(bytes).await?;
    writer.flush().await
}

/// Read one bounded outer record.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: usize,
) -> io::Result<Vec<u8>> {
    let len = reader.read_u32().await? as usize;
    if len == 0 || len > max_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("remote-access frame length {len} exceeds limit {max_len}"),
        ));
    }
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub fn encode_transport(noise: &mut NoiseSession, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    if plaintext.is_empty() || plaintext.len() > MAX_TUNNEL_PLAINTEXT {
        return Err("remote-access plaintext length out of bounds".into());
    }
    let ciphertext = noise.encrypt(plaintext).map_err(|e| e.to_string())?;
    if ciphertext.len() > MAX_TRANSPORT_FRAME {
        return Err("remote-access ciphertext length out of bounds".into());
    }
    Ok(ciphertext)
}

pub fn decode_transport(
    noise: &mut NoiseSession,
    ciphertext: &[u8],
    max_plaintext: usize,
) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_TRANSPORT_FRAME {
        return Err("remote-access ciphertext length out of bounds".into());
    }
    let plaintext = noise
        .decrypt_sensitive(ciphertext)
        .map_err(|e| e.to_string())?;
    if plaintext.is_empty() || plaintext.len() > max_plaintext {
        return Err("remote-access decrypted length out of bounds".into());
    }
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_link_round_trips_without_padding() {
        let link = PairLink {
            v: VERSION,
            endpoint: "node.example:8443".into(),
            node_id: "11".repeat(32),
            transport_pubkey: "22".repeat(32),
            transport_signature: "sig".into(),
            code: "code".into(),
            box_transport_pubkey: "33".repeat(32),
            box_transport_signature: Some("box-sig".into()),
            expires_at: 1234567890,
            hosted_by: Some("My Pi".into()),
        };
        let uri = link.to_uri().unwrap();
        assert!(!uri.contains('='));
        assert_eq!(PairLink::from_uri(&uri).unwrap(), link);
    }
}
