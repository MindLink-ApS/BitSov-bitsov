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
/// Pair-link version is independent of the Noise/auth protocol version.
pub const PAIR_LINK_VERSION: u8 = 2;
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
    /// Compatibility projection: always the first endpoint in v2.
    pub endpoint: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// Identity signature over the versioned endpoint descriptor, absent before bootstrap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoints_signature: Option<String>,
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
        if link.v != VERSION && link.v != PAIR_LINK_VERSION {
            return Err(format!("unsupported pairing link version {}", link.v));
        }
        link.validate_descriptor()?;
        Ok(link)
    }

    /// Export the exact v1 schema for apps which reject additive JSON fields.
    /// The grant, expiry and transport pins are unchanged.
    pub fn to_legacy_uri(&self) -> Result<String, serde_json::Error> {
        let mut legacy = self.clone();
        legacy.v = VERSION;
        legacy.endpoints.clear();
        legacy.endpoints_signature = None;
        legacy.to_uri()
    }

    pub fn validate_descriptor(&self) -> Result<(), String> {
        if self.v == VERSION {
            if !self.endpoints.is_empty() || self.endpoints_signature.is_some() {
                return Err("v1 link cannot carry a v2 descriptor".into());
            }
            return Ok(());
        }
        if self.v != PAIR_LINK_VERSION
            || self.endpoints.is_empty()
            || self.endpoints.len() > 32
            || self.endpoints.first() != Some(&self.endpoint)
            || self.endpoints.iter().any(|e| validate_endpoint(e).is_err())
            || self
                .endpoints
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != self.endpoints.len()
        {
            return Err("invalid endpoint descriptor".into());
        }
        if self.node_id.is_empty() {
            if self.endpoints_signature.is_some() {
                return Err("bootstrap descriptor cannot claim an identity signature".into());
            }
            return Ok(());
        }
        self.verify_endpoints(&self.node_id)
    }

    /// A paired app MUST supply its saved node id here, and still pin the Noise
    /// responder key before sending any authentication or unlock material.
    pub fn verify_endpoints(&self, trusted_node_id: &str) -> Result<(), String> {
        let verify = || -> Option<()> {
            if self.v != PAIR_LINK_VERSION || self.node_id != trusted_node_id {
                return None;
            }
            let bytes: [u8; 32] = hex::decode(trusted_node_id).ok()?.try_into().ok()?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()?;
            let signature = ed25519_dalek::Signature::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(self.endpoints_signature.as_ref()?)
                    .ok()?,
            )
            .ok()?;
            key.verify_strict(self.endpoints_proof_message().as_bytes(), &signature)
                .ok()
        };
        verify().ok_or_else(|| "invalid endpoint descriptor signature".into())
    }

    /// Canonical JSON tuple prevents delimiter ambiguity and binds list order.
    /// This public descriptor excludes the independently rotated one-use grant.
    pub fn endpoints_proof_message(&self) -> String {
        serde_json::to_string(&(
            "bitsov-endpoints-v2",
            self.v,
            &self.node_id,
            &self.transport_pubkey,
            &self.box_transport_pubkey,
            &self.endpoint,
            &self.endpoints,
        ))
        .expect("string tuple serialization")
    }
}

/// Bare DNS name / IP and nonzero TCP port; never a URL or wildcard address.
pub fn validate_endpoint(endpoint: &str) -> Result<(), String> {
    let valid = || -> Option<()> {
        if endpoint.len() > 260 || endpoint.bytes().any(|b| b.is_ascii_whitespace()) {
            return None;
        }
        let (host, port) = endpoint.rsplit_once(':')?;
        if port.parse::<u16>().ok()? == 0 {
            return None;
        }
        let ip = if host.starts_with('[') && host.ends_with(']') {
            Some(
                host[1..host.len() - 1]
                    .parse::<std::net::Ipv6Addr>()
                    .ok()?
                    .into(),
            )
        } else if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
            Some(std::net::IpAddr::V4(ip))
        } else {
            if host.len() > 253
                || !host.split('.').all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                })
            {
                return None;
            }
            None
        };
        if ip.is_some_and(|ip| ip.is_unspecified() || ip.is_multicast()) {
            return None;
        }
        Some(())
    };
    valid().ok_or_else(|| "endpoint must be a dialable bare host:port".into())
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

/// Public, identity-signed fields of `identity/identity.json`: node id,
/// fingerprint, and both transport proofs. Locked startup and enrollment
/// tickets read only these; no seed or password material is involved.
pub fn public_identity_proofs(
    identity: &konsensus_core::NodeIdentity,
    box_transport_pubkey: &[u8; 32],
) -> serde_json::Map<String, serde_json::Value> {
    let node_id = identity.node_id().to_hex();
    let sign =
        |message: String| URL_SAFE_NO_PAD.encode(identity.sign(message.as_bytes()).to_bytes());
    let transport_pubkey = hex::encode(identity.x25519_public().as_bytes());
    let box_pubkey = hex::encode(box_transport_pubkey);
    let mut fields = serde_json::Map::new();
    fields.insert(
        "identity_fingerprint".into(),
        crate::pairing::identity_fingerprint(&node_id).into(),
    );
    fields.insert(
        "transport_signature".into(),
        sign(transport_proof_message(&node_id, &transport_pubkey)).into(),
    );
    fields.insert("transport_pubkey".into(), transport_pubkey.into());
    fields.insert(
        "box_transport_signature".into(),
        sign(box_transport_proof_message(&node_id, &box_pubkey)).into(),
    );
    fields.insert("box_transport_pubkey".into(), box_pubkey.into());
    fields.insert("node_id".into(), node_id.into());
    fields
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
    fn v2_endpoint_list_round_trips_and_v1_remains_readable() {
        let json = serde_json::json!({
            "v": 2, "endpoint": "node.example:8443",
            "endpoints": ["node.example:8443", "192.168.1.8:8443"],
            "box_transport_pubkey": "33".repeat(32), "code": "code"
        });
        let uri = format!(
            "{PAIR_LINK_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(json.to_string())
        );
        let parsed = PairLink::from_uri(&uri).expect("v2 endpoint lists must be accepted");
        assert_eq!(
            serde_json::to_value(&parsed).unwrap()["endpoints"],
            json["endpoints"]
        );
        assert_eq!(
            PairLink::from_uri(&parsed.to_uri().unwrap()).unwrap(),
            parsed
        );
    }

    #[test]
    fn descriptor_signature_covers_order_every_endpoint_and_pins() {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&[7; 32]);
        let mut link: PairLink = serde_json::from_value(serde_json::json!({
            "v": 2, "endpoint": "node.example:8443",
            "endpoints": ["node.example:8443", "192.168.1.8:8443", "100.100.1.2:8443"],
            "node_id": hex::encode(key.verifying_key().to_bytes()),
            "transport_pubkey": "22".repeat(32),
            "box_transport_pubkey": "33".repeat(32), "code": "grant"
        }))
        .unwrap();
        link.endpoints_signature = Some(
            URL_SAFE_NO_PAD.encode(
                key.sign(link.endpoints_proof_message().as_bytes())
                    .to_bytes(),
            ),
        );
        assert!(PairLink::from_uri(&link.to_uri().unwrap()).is_ok());
        assert!(link.verify_endpoints(&"00".repeat(32)).is_err());
        for field in [
            "endpoint",
            "transport_pubkey",
            "box_transport_pubkey",
            "node_id",
        ] {
            let mut value = serde_json::to_value(&link).unwrap();
            value[field] = "attacker".into();
            let changed: PairLink = serde_json::from_value(value).unwrap();
            assert!(changed.verify_endpoints(&link.node_id).is_err(), "{field}");
        }
        for index in 0..3 {
            let mut changed = link.clone();
            changed.endpoints[index] = "attacker.example:8443".into();
            assert!(changed.verify_endpoints(&link.node_id).is_err());
        }
        let mut changed = link.clone();
        changed.endpoints.swap(1, 2);
        assert!(changed.verify_endpoints(&link.node_id).is_err());
        changed = link.clone();
        changed.endpoints.pop();
        assert!(changed.verify_endpoints(&link.node_id).is_err());
        changed = link.clone();
        changed.v = 1;
        assert!(PairLink::from_uri(&changed.to_uri().unwrap()).is_err());
        let legacy = PairLink::from_uri(&link.to_legacy_uri().unwrap()).unwrap();
        assert_eq!(legacy.v, 1);
        assert_eq!(legacy.endpoint, "node.example:8443");
        assert_eq!(legacy.code, link.code);
        assert_eq!(legacy.box_transport_pubkey, link.box_transport_pubkey);
        let fields = serde_json::to_value(&legacy).unwrap();
        assert!(fields.get("endpoints").is_none());
        assert!(fields.get("endpoints_signature").is_none());
    }

    #[test]
    fn malformed_v2_and_unknown_versions_are_refused() {
        let base = serde_json::json!({"v": 2, "endpoint": "node.example:8443",
            "endpoints": ["node.example:8443"], "code": "grant"});
        for (field, value) in [
            ("v", serde_json::json!(3)),
            ("endpoints", serde_json::json!([])),
            ("endpoints", serde_json::json!(["other.example:8443"])),
            (
                "endpoints",
                serde_json::json!(["node.example:8443", "node.example:8443"]),
            ),
            (
                "endpoints",
                serde_json::json!(["node.example:8443", "0.0.0.0:8443"]),
            ),
            ("node_id", serde_json::json!("22".repeat(32))),
        ] {
            let mut input = base.clone();
            input[field] = value;
            let uri = format!(
                "{PAIR_LINK_PREFIX}{}",
                URL_SAFE_NO_PAD.encode(input.to_string())
            );
            assert!(PairLink::from_uri(&uri).is_err(), "{input}");
        }
    }

    #[test]
    fn pairing_link_round_trips_without_padding() {
        let link = PairLink {
            v: VERSION,
            endpoint: "node.example:8443".into(),
            endpoints: vec![],
            endpoints_signature: None,
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
