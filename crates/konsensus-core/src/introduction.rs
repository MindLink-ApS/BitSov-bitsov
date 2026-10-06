//! Signed node introductions (K1 "door card", slice 1).
//!
//! An introduction says: this key, reachable here, currently asks these
//! prices. It is signed by the node's Ed25519 identity key and lives for at
//! most ten minutes. Whitepaper line 1 holds: **an introduction is never
//! admission.** It carries no spending authority, no grant, no whitelist entry
//! and no session. Scanning one lets the reader dial the node unprivileged and
//! ask it for a fresh stateless quote. Every act after that is paid exactly as
//! for any stranger. The prices in the card are a signed snapshot for display;
//! they never authorize a charge.
//!
//! Nothing here is stored. There is no issued-introduction table, no replay
//! database and no registry: the random `intro_id` only distinguishes cards.
//!
//! # Wire form
//!
//! The API returns the card as JSON with lowercase hex byte fields. The link
//! (and QR) carries the signed bytes themselves, in a fragment so a landing
//! server never receives them:
//!
//! ```text
//! bitsov://introduce#<base64url-nopad(canonical_bytes without the domain tag || sig)>
//! ```
//!
//! About 270 characters for a typical endpoint. A pasted card may be the
//! link, its bare fragment, or the JSON; all are at most [`MAX_ENCODED_LEN`]
//! bytes.
//!
//! # Signature
//!
//! Ed25519 over `BLAKE3(canonical_bytes)`, where `canonical_bytes` is the
//! domain tag [`DOMAIN_V1`] followed by every field in a fixed order
//! (strings length-prefixed, integers big-endian). Each field is covered,
//! including network, endpoint, reach and prices.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::NodeIdentity;
use crate::types::NodeId;

/// Domain-separation tag: a node key signing an introduction can never be
/// replayed as an invite, envelope or federation signature.
pub const DOMAIN_V1: &[u8] = b"bitsov-introduction/v1\0";
/// The only supported format version.
pub const VERSION: u8 = 1;
/// Link prefix. The card sits in the fragment.
pub const LINK_PREFIX: &str = "bitsov://introduce#";
/// Default and maximum lifetime (K1 default: ten minutes).
pub const LIFETIME_SECS: u64 = 600;
/// Clock skew tolerated on `issued_at`.
pub const MAX_SKEW_SECS: u64 = 60;
/// Upper bound on the encoded link or pasted card (K1: 2 KiB).
pub const MAX_ENCODED_LEN: usize = 2048;
/// Upper bound on `host:port`.
pub const MAX_ENDPOINT_LEN: usize = 255;
/// Bitcoin networks a card may name.
pub const NETWORKS: [&str; 4] = ["bitcoin", "testnet", "signet", "regtest"];

/// Errors from building, decoding or verifying an introduction.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntroductionError {
    #[error("introduction is too large ({0} bytes, max {MAX_ENCODED_LEN})")]
    TooLarge(usize),
    #[error("not an introduction: {0}")]
    Malformed(String),
    #[error("unsupported introduction version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown network {0:?}")]
    UnknownNetwork(String),
    #[error("introduction is for {card}, this node runs {ours}")]
    WrongNetwork { card: String, ours: String },
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),
    #[error("endpoint is not reachable as a {0} introduction")]
    ReachMismatch(&'static str),
    #[error("introduction expired at {0}")]
    Expired(u64),
    #[error("introduction is issued in the future")]
    NotYetValid,
    #[error("introduction lives longer than {LIFETIME_SECS} s")]
    LifetimeTooLong,
    #[error("invalid node key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
}

/// Where the endpoint may be dialed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reach {
    /// Publicly routable. Never a loopback, private or link-local address.
    Public,
    /// On the introducer's local network. The reader must choose to allow it.
    Local,
}

impl Reach {
    fn tag(self) -> u8 {
        match self {
            Reach::Public => 0,
            Reach::Local => 1,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Reach::Public => "public",
            Reach::Local => "local",
        }
    }
}

/// A signed introduction. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Introduction {
    /// Format version ([`VERSION`]).
    pub v: u8,
    /// Bitcoin network the prices are payable on.
    pub network: String,
    /// The introducer's node id (its Ed25519 public key), hex.
    pub node_id: String,
    /// Canonical BitSov peer endpoint, `host:port`. Never an API URL.
    pub endpoint: String,
    /// Whether `endpoint` is public or local-network only.
    pub reach: Reach,
    /// Current first-contact (admission) price, msat. Display snapshot only.
    pub admission_msat: u64,
    /// Current price per text message, msat. Display snapshot only.
    pub message_msat: u64,
    /// Bitcoin difficulty epoch (block height / 2016) the prices were read
    /// in; 0 when the node has no chain height.
    pub price_epoch: u64,
    /// Unix seconds.
    pub issued_at: u64,
    /// Unix seconds; at most [`LIFETIME_SECS`] after `issued_at`.
    pub expires_at: u64,
    /// Random 128-bit id, hex. Distinguishes cards; grants nothing.
    pub intro_id: String,
    /// Ed25519 signature over `BLAKE3(canonical_bytes)`, hex.
    pub sig: String,
}

/// Unsigned fields, filled by the issuing node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntroductionFields {
    pub network: String,
    pub endpoint: String,
    pub admission_msat: u64,
    pub message_msat: u64,
    pub price_epoch: u64,
    pub issued_at: u64,
    pub intro_id: [u8; 16],
}

/// The first-contact (admission, message) prices a node quotes a stranger for
/// a text message, given its chat price and admission cost floor. Shared by
/// the stateless quote and the introduction so the card can never advertise a
/// different figure than the quote. Both take the gate's floor, so neither is
/// ever below one sat or `min_admission_cost_msat`.
pub fn first_contact_prices(chat_price_msat: u64, min_admission_cost_msat: u64) -> (u64, u64) {
    let price = crate::gate::price_with_floor_msat(chat_price_msat, min_admission_cost_msat);
    (price, price)
}

impl Introduction {
    /// Sign `fields` with `identity`. Refuses fields that would not verify.
    pub fn issue(identity: &NodeIdentity, fields: IntroductionFields) -> Result<Self, IntroductionError> {
        Self::issue_with_key(identity.ed25519_signing_key(), fields)
    }

    /// As [`Introduction::issue`], from a bare signing key (test vectors).
    pub fn issue_with_key(key: &SigningKey, fields: IntroductionFields) -> Result<Self, IntroductionError> {
        let endpoint = fields.endpoint.trim().to_string();
        let reach = reach_of(&endpoint)?;
        let mut card = Self {
            v: VERSION,
            network: fields.network,
            node_id: hex::encode(key.verifying_key().to_bytes()),
            endpoint,
            reach,
            admission_msat: fields.admission_msat,
            message_msat: fields.message_msat,
            price_epoch: fields.price_epoch,
            issued_at: fields.issued_at,
            expires_at: fields.issued_at.saturating_add(LIFETIME_SECS),
            intro_id: hex::encode(fields.intro_id),
            sig: String::new(),
        };
        card.check_shape()?;
        card.sig = hex::encode(key.sign(&card.digest()?).to_bytes());
        Ok(card)
    }

    /// The node id the card introduces.
    pub fn node(&self) -> Result<NodeId, IntroductionError> {
        NodeId::from_hex(&self.node_id).map_err(|_| IntroductionError::InvalidKey)
    }

    /// Domain-tagged canonical bytes of every field except `sig`.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, IntroductionError> {
        let key = decode_fixed::<32>(&self.node_id).ok_or(IntroductionError::InvalidKey)?;
        let intro_id = decode_fixed::<16>(&self.intro_id)
            .ok_or_else(|| IntroductionError::Malformed("intro_id must be 16 bytes hex".into()))?;
        if self.network.len() > u8::MAX as usize || self.endpoint.len() > MAX_ENDPOINT_LEN {
            return Err(IntroductionError::InvalidEndpoint("too long".into()));
        }
        let mut out = Vec::with_capacity(DOMAIN_V1.len() + 128 + self.endpoint.len());
        out.extend_from_slice(DOMAIN_V1);
        out.push(self.v);
        out.push(self.network.len() as u8);
        out.extend_from_slice(self.network.as_bytes());
        out.extend_from_slice(&key);
        out.push(self.endpoint.len() as u8);
        out.extend_from_slice(self.endpoint.as_bytes());
        out.push(self.reach.tag());
        for n in [self.admission_msat, self.message_msat, self.price_epoch, self.issued_at, self.expires_at] {
            out.extend_from_slice(&n.to_be_bytes());
        }
        out.extend_from_slice(&intro_id);
        Ok(out)
    }

    fn digest(&self) -> Result<[u8; 32], IntroductionError> {
        Ok(*blake3::hash(&self.canonical_bytes()?).as_bytes())
    }

    /// Version, network name, endpoint syntax, reach and lifetime. No clock.
    fn check_shape(&self) -> Result<(), IntroductionError> {
        if self.v != VERSION {
            return Err(IntroductionError::UnsupportedVersion(self.v));
        }
        if !NETWORKS.contains(&self.network.as_str()) {
            return Err(IntroductionError::UnknownNetwork(self.network.clone()));
        }
        let literal = reach_of(&self.endpoint)?;
        if self.reach == Reach::Public && literal == Reach::Local {
            return Err(IntroductionError::ReachMismatch("public"));
        }
        if self.expires_at <= self.issued_at || self.expires_at - self.issued_at > LIFETIME_SECS {
            return Err(IntroductionError::LifetimeTooLong);
        }
        Ok(())
    }

    /// Verify everything: shape, the reader's network, expiry against the
    /// caller's clock, and the signature under `node_id`.
    pub fn verify(&self, now_unix: u64, network: &str) -> Result<(), IntroductionError> {
        self.check_shape()?;
        if self.network != network {
            return Err(IntroductionError::WrongNetwork { card: self.network.clone(), ours: network.into() });
        }
        if self.issued_at > now_unix.saturating_add(MAX_SKEW_SECS) {
            return Err(IntroductionError::NotYetValid);
        }
        if self.expires_at <= now_unix {
            return Err(IntroductionError::Expired(self.expires_at));
        }
        let key = decode_fixed::<32>(&self.node_id).ok_or(IntroductionError::InvalidKey)?;
        let key = VerifyingKey::from_bytes(&key).map_err(|_| IntroductionError::InvalidKey)?;
        let sig = decode_fixed::<64>(&self.sig).ok_or(IntroductionError::InvalidSignature)?;
        key.verify_strict(&self.digest()?, &Signature::from_bytes(&sig))
            .map_err(|_| IntroductionError::InvalidSignature)
    }

    /// `bitsov://introduce#<base64url(signed bytes || sig)>`. Only for a
    /// well-formed card (as issued or parsed).
    pub fn to_link(&self) -> String {
        let mut bytes = self.canonical_bytes().expect("well-formed introduction");
        bytes.drain(..DOMAIN_V1.len());
        bytes.extend_from_slice(&decode_fixed::<64>(&self.sig).unwrap_or([0; 64]));
        format!("{LINK_PREFIX}{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Inverse of the link payload: the canonical fields then the signature.
    fn from_link_bytes(b: &[u8]) -> Result<Self, IntroductionError> {
        let short = || IntroductionError::Malformed("truncated".into());
        let mut at = 0usize;
        let mut take = |n: usize| -> Result<&[u8], IntroductionError> {
            let s = b.get(at..at + n).ok_or_else(short)?;
            at += n;
            Ok(s)
        };
        let utf8 = |s: &[u8]| String::from_utf8(s.to_vec()).map_err(|_| IntroductionError::Malformed("not UTF-8".into()));
        let u64_at = |s: &[u8]| u64::from_be_bytes(s.try_into().expect("8 bytes"));
        let v = take(1)?[0];
        let n = take(1)?[0] as usize;
        let network = utf8(take(n)?)?;
        let node_id = hex::encode(take(32)?);
        let n = take(1)?[0] as usize;
        let endpoint = utf8(take(n)?)?;
        let reach = match take(1)?[0] {
            0 => Reach::Public,
            1 => Reach::Local,
            r => return Err(IntroductionError::Malformed(format!("reach {r}"))),
        };
        let admission_msat = u64_at(take(8)?);
        let message_msat = u64_at(take(8)?);
        let price_epoch = u64_at(take(8)?);
        let issued_at = u64_at(take(8)?);
        let expires_at = u64_at(take(8)?);
        let intro_id = hex::encode(take(16)?);
        let sig = hex::encode(take(64)?);
        if at != b.len() {
            return Err(IntroductionError::Malformed("trailing bytes".into()));
        }
        Ok(Self { v, network, node_id, endpoint, reach, admission_msat, message_msat, price_epoch, issued_at, expires_at, intro_id, sig })
    }

    /// Parse a scanned or pasted introduction: the link, its bare fragment,
    /// or the JSON card. Bounded before any decoding. Does not verify.
    pub fn parse(text: &str) -> Result<Self, IntroductionError> {
        if text.len() > MAX_ENCODED_LEN {
            return Err(IntroductionError::TooLarge(text.len()));
        }
        let text = text.trim();
        if text.starts_with('{') {
            return serde_json::from_str(text).map_err(|e| IntroductionError::Malformed(e.to_string()));
        }
        let payload = match text.split_once('#') {
            Some((prefix, frag)) if format!("{prefix}#") == LINK_PREFIX => frag,
            Some(_) => return Err(IntroductionError::Malformed("not a bitsov://introduce link".into())),
            None => text,
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| IntroductionError::Malformed("bad encoding".into()))?;
        Self::from_link_bytes(&bytes)
    }
}

fn decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    hex::decode(s).ok()?.try_into().ok()
}

/// Split and validate `host:port`. A host is an IPv4 literal, a bracketed
/// IPv6 literal, or a DNS name. No scheme, credentials, path or query.
pub fn split_endpoint(endpoint: &str) -> Result<(String, u16), IntroductionError> {
    let bad = |why: &str| IntroductionError::InvalidEndpoint(why.into());
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_LEN {
        return Err(bad("empty or too long"));
    }
    if endpoint.contains(|c: char| c.is_whitespace() || "/@?#\\".contains(c)) {
        return Err(bad("must be host:port, not a URL"));
    }
    let (host, port) = endpoint.rsplit_once(':').ok_or_else(|| bad("missing port"))?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad("bad port"));
    }
    let port: u16 = port.parse().map_err(|_| bad("bad port"))?;
    if port == 0 {
        return Err(bad("bad port"));
    }
    let host = if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        v6.parse::<Ipv6Addr>().map_err(|_| bad("bad IPv6 literal"))?;
        v6.to_string()
    } else {
        if host.parse::<Ipv4Addr>().is_err() {
            let dns = host.len() <= 253
                && host.split('.').all(|l| {
                    !l.is_empty()
                        && l.len() <= 63
                        && !l.starts_with('-')
                        && !l.ends_with('-')
                        && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                });
            if !dns {
                return Err(bad("bad host"));
            }
        }
        host.to_ascii_lowercase()
    };
    Ok((host, port))
}

/// The reach implied by an endpoint's literal address: `Local` for a
/// loopback/private literal or `localhost`, `Public` otherwise (a DNS name is
/// checked again when resolved). Refuses addresses never dialable at all.
pub fn reach_of(endpoint: &str) -> Result<Reach, IntroductionError> {
    let (host, _) = split_endpoint(endpoint)?;
    if host == "localhost" || host.ends_with(".localhost") || host.ends_with(".local") {
        return Ok(Reach::Local);
    }
    match host.parse::<IpAddr>() {
        Ok(ip) => ip_reach(ip).ok_or_else(|| IntroductionError::InvalidEndpoint(format!("{ip} is never dialable"))),
        Err(_) => Ok(Reach::Public),
    }
}

/// Classify a resolved address: `None` for addresses no introduction may
/// dial (unspecified, multicast, broadcast, link-local including cloud
/// metadata, documentation, `0.0.0.0/8`), `Local` for loopback, private,
/// shared (CGNAT) and unique-local ranges, `Public` otherwise.
pub fn ip_reach(ip: IpAddr) -> Option<Reach> {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            if v4.is_unspecified() || v4.is_multicast() || v4.is_broadcast() || v4.is_link_local()
                || v4.is_documentation() || a == 0 || a >= 240
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && (b == 18 || b == 19))
            {
                None
            } else if v4.is_loopback() || v4.is_private() || (a == 100 && (64..128).contains(&b)) {
                Some(Reach::Local)
            } else {
                Some(Reach::Public)
            }
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            if v6.is_unspecified() || v6.is_multicast() || (seg[0] & 0xffc0) == 0xfe80 || seg[0] == 0x2001 && seg[1] == 0x0db8 {
                None
            } else if v6.is_loopback() || (seg[0] & 0xfe00) == 0xfc00 {
                Some(Reach::Local)
            } else if (seg[0] & 0xe000) != 0x2000
                || seg[0] == 0x2002
                || (seg[0] == 0x2001 && seg[1] <= 0x01ff)
                || seg[0] == 0x3fff
            {
                // Fail closed for special-use and transition addresses:
                // an embedded IPv4 destination must not bypass local policy.
                None
            } else {
                Some(Reach::Public)
            }
        }
    }
}

/// May an introduction with `reach` dial `ip`? Public cards only reach
/// public addresses; local cards also reach local ones. Nothing reaches the
/// never-dialable ranges.
pub fn dial_allowed(reach: Reach, ip: IpAddr) -> bool {
    match (reach, ip_reach(ip)) {
        (_, None) => false,
        (Reach::Public, Some(r)) => r == Reach::Public,
        (Reach::Local, Some(_)) => true,
    }
}

impl std::fmt::Display for Reach {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn fields(endpoint: &str) -> IntroductionFields {
        IntroductionFields {
            network: "regtest".into(),
            endpoint: endpoint.into(),
            admission_msat: 100_000,
            message_msat: 10_000,
            price_epoch: 440,
            issued_at: NOW,
            intro_id: [0xab; 16],
        }
    }

    fn card() -> Introduction {
        Introduction::issue_with_key(&key(), fields("node.example.org:9000")).unwrap()
    }

    /// Fixed vector, shared with bitsov-app's host-side verifier. If this
    /// changes, the app's copy must change in the same breath.
    #[test]
    fn test_vector_is_stable() {
        let c = card();
        assert_eq!(c.node_id, "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c");
        assert_eq!(c.reach, Reach::Public);
        assert_eq!(c.expires_at, NOW + 600);
        assert_eq!(hex::encode(c.digest().unwrap()), VECTOR_DIGEST);
        assert_eq!(c.sig, VECTOR_SIG);
        assert!(c.verify(NOW, "regtest").is_ok());
        assert_eq!(Introduction::parse(&c.to_link()).unwrap(), c);
        assert_eq!(c.to_link(), VECTOR_LINK);
    }
    const VECTOR_LINK: &str = "bitsov://introduce#AQdyZWd0ZXN06kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iwVbm9kZS5leGFtcGxlLm9yZzo5MDAwAAAAAAAAAYagAAAAAAAAJxAAAAAAAAABuAAAAABqsTuAAAAAAGqxPdirq6urq6urq6urq6urq6ur3BK7GVreWdgZElEoTou2cd8Nk2q0QYa7Jmb-SZsV3kdG52gStclWtLnYqDxfBSO0RMBFywM4DdLClJDK9TGmAA";
    const VECTOR_DIGEST: &str = "969543797148a70ad88a4047e27cc57f950fa25464aedb25a96afbbf6db1d2a6";
    const VECTOR_SIG: &str = "dc12bb195ade59d8191251284e8bb671df0d936ab44186bb2666fe499b15de4746e76812b5c956b4b9d8a83c5f0523b444c045cb03380dd2c29490caf531a600";

    #[test]
    fn every_field_is_signed() {
        let c = card();
        let tamper: Vec<fn(&mut Introduction)> = vec![
            |c| c.network = "signet".into(),
            |c| c.endpoint = "evil.example.org:9000".into(),
            |c| c.reach = Reach::Local,
            |c| c.admission_msat -= 1,
            |c| c.message_msat += 1,
            |c| c.price_epoch += 1,
            |c| c.issued_at -= 1,
            |c| c.expires_at -= 1,
            |c| c.intro_id = hex::encode([0xac; 16]),
            |c| c.node_id = hex::encode(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes()),
        ];
        for (i, t) in tamper.iter().enumerate() {
            let mut bad = c.clone();
            t(&mut bad);
            let now_net = bad.network.clone();
            assert!(bad.verify(NOW, &now_net).is_err(), "tamper {i} still verified");
        }
    }

    #[test]
    fn expiry_network_and_version_are_enforced() {
        let c = card();
        assert_eq!(c.verify(NOW + 600, "regtest"), Err(IntroductionError::Expired(NOW + 600)));
        assert!(c.verify(NOW + 599, "regtest").is_ok());
        assert!(matches!(c.verify(NOW, "bitcoin"), Err(IntroductionError::WrongNetwork { .. })));
        assert_eq!(c.verify(NOW - 61, "regtest"), Err(IntroductionError::NotYetValid));
        let mut v2 = c.clone();
        v2.v = 2;
        assert_eq!(v2.verify(NOW, "regtest"), Err(IntroductionError::UnsupportedVersion(2)));
        let mut long = c.clone();
        long.expires_at = long.issued_at + 601;
        assert_eq!(long.verify(NOW, "regtest"), Err(IntroductionError::LifetimeTooLong));
    }

    #[test]
    fn parse_is_bounded_and_strict() {
        let c = card();
        let link = c.to_link();
        assert!(link.len() < 300, "QR-sized: {}", link.len());
        let longest = Introduction::issue_with_key(&key(), fields(&format!("{}.example:9000", "a".repeat(60)))).unwrap();
        assert!(longest.to_link().len() < 400);
        let mut truncated = link.clone();
        truncated.truncate(link.len() - 4);
        assert!(Introduction::parse(&truncated).is_err());
        let frag = link.strip_prefix(LINK_PREFIX).unwrap();
        assert_eq!(Introduction::parse(frag).unwrap(), c);
        assert_eq!(Introduction::parse(&serde_json::to_string(&c).unwrap()).unwrap(), c);
        assert_eq!(Introduction::parse(&format!("  {link}\n")).unwrap(), c);
        assert!(matches!(Introduction::parse(&"A".repeat(MAX_ENCODED_LEN + 1)), Err(IntroductionError::TooLarge(_))));
        assert!(Introduction::parse(&format!("https://evil.example/#{frag}")).is_err());
        let mut extra = serde_json::to_value(&c).unwrap();
        extra["grant"] = "admin".into();
        assert!(Introduction::parse(&extra.to_string()).is_err(), "unknown fields are refused");
    }

    #[test]
    fn endpoints_are_peer_addresses_not_urls() {
        for bad in [
            "http://node.example.org:9000", "user@node.example.org:9000", "node.example.org",
            "node.example.org:0", "node.example.org:9000/admin", "[::1", "0.0.0.0:9000",
            "169.254.169.254:80", "[fe80::1]:9000", "224.0.0.1:9000", "-bad.example:1", "",
        ] {
            assert!(Introduction::issue_with_key(&key(), fields(bad)).is_err(), "{bad} accepted");
        }
        for (ok, reach) in [
            ("node.example.org:9000", Reach::Public), ("203.0.114.9:9000", Reach::Public),
            ("[2606:4700::1]:9000", Reach::Public), ("127.0.0.1:9000", Reach::Local),
            ("192.168.1.20:9000", Reach::Local), ("[fd00::2]:9000", Reach::Local),
            ("localhost:9000", Reach::Local), ("100.100.1.1:9000", Reach::Local),
        ] {
            assert_eq!(Introduction::issue_with_key(&key(), fields(ok)).unwrap().reach, reach, "{ok}");
        }
    }

    #[test]
    fn a_public_card_cannot_name_a_private_address() {
        let mut c = Introduction::issue_with_key(&key(), fields("10.0.0.5:9000")).unwrap();
        assert_eq!(c.reach, Reach::Local);
        c.reach = Reach::Public;
        c.sig = hex::encode(key().sign(&c.digest().unwrap()).to_bytes());
        assert_eq!(c.verify(NOW, "regtest"), Err(IntroductionError::ReachMismatch("public")));
    }

    #[test]
    fn a_signed_metadata_endpoint_is_still_refused() {
        let mut c = card();
        c.endpoint = "169.254.169.254:80".into();
        c.sig = hex::encode(key().sign(&c.digest().unwrap()).to_bytes());
        assert!(matches!(c.verify(NOW, "regtest"), Err(IntroductionError::InvalidEndpoint(_))));
    }

    #[test]
    fn dial_policy() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(dial_allowed(Reach::Public, ip("8.8.8.8")));
        assert!(!dial_allowed(Reach::Public, ip("127.0.0.1")));
        assert!(!dial_allowed(Reach::Public, ip("10.1.2.3")));
        assert!(!dial_allowed(Reach::Public, ip("::ffff:192.168.0.1")));
        assert!(dial_allowed(Reach::Local, ip("192.168.0.1")));
        assert!(dial_allowed(Reach::Local, ip("8.8.8.8")));
        for never in ["169.254.169.254", "0.0.0.0", "255.255.255.255", "fe80::1", "::", "::ffff:169.254.169.254"] {
            assert!(!dial_allowed(Reach::Local, ip(never)), "{never}");
        }
    }

    #[test]
    fn first_contact_prices_match_the_quote_rule() {
        assert_eq!(first_contact_prices(0, 0), (1000, 1000));
        assert_eq!(first_contact_prices(1, 0), (1000, 1000));
        assert_eq!(first_contact_prices(10_000, 0), (10_000, 10_000));
        assert_eq!(first_contact_prices(10_000, 25_000), (25_000, 25_000));
        assert_eq!(first_contact_prices(30_000, 25_000), (30_000, 30_000));
    }

    #[test]
    fn weak_key_forgery_and_tampering_are_rejected() {
        let mut c = card();
        let mut weak_key = [0u8; 32];
        weak_key[0] = 1;
        let mut forged_sig = [0u8; 64];
        forged_sig[0] = 1;
        c.node_id = hex::encode(weak_key);
        c.sig = hex::encode(forged_sig);
        for tampered in [false, true] {
            if tampered {
                c.endpoint = "other.example.org:9001".into();
                c.admission_msat = 1;
                c.message_msat = 2;
                c.expires_at = NOW + 1;
            }
            let parsed = Introduction::parse(&c.to_link()).unwrap();
            assert_eq!(parsed.verify(NOW, "regtest"), Err(IntroductionError::InvalidSignature));
        }
    }

    #[test]
    fn noncanonical_signatures_are_rejected() {
        let mut c = card();
        let mut sig = decode_fixed::<64>(&c.sig).unwrap();
        // Add the Ed25519 group order to S: the group equation is unchanged,
        // but the signature's scalar encoding is no longer canonical.
        let order = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010").unwrap();
        let mut carry = 0u16;
        for (s, l) in sig[32..].iter_mut().zip(order) {
            let sum = u16::from(*s) + u16::from(l) + carry;
            *s = sum as u8;
            carry = sum >> 8;
        }
        c.sig = hex::encode(sig);
        assert_eq!(c.verify(NOW, "regtest"), Err(IntroductionError::InvalidSignature));
        // Noncanonical encoding of the identity point (y = p + 1) as R.
        sig = decode_fixed::<64>(&card().sig).unwrap();
        sig[..32].fill(0xff);
        sig[0] = 0xee;
        sig[31] = 0x7f;
        c.sig = hex::encode(sig);
        assert_eq!(c.verify(NOW, "regtest"), Err(IntroductionError::InvalidSignature));
    }

    #[test]
    fn parse_bounds_include_surrounding_whitespace() {
        let padded = format!("{}{}", " ".repeat(MAX_ENCODED_LEN), card().to_link());
        assert!(matches!(Introduction::parse(&padded), Err(IntroductionError::TooLarge(_))));
    }

    #[test]
    fn endpoint_port_and_ipv6_transition_ranges_fail_closed() {
        for endpoint in ["node.example:0", "node.example:65536", "node.example:+9000", "node.example:-1"] {
            assert!(split_endpoint(endpoint).is_err(), "{endpoint}");
        }
        assert_eq!(split_endpoint("node.example:65535").unwrap().1, 65535);
        for ip in ["::127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::1", "fec0::1"] {
            assert!(!dial_allowed(Reach::Public, ip.parse().unwrap()), "{ip}");
        }
    }
}
