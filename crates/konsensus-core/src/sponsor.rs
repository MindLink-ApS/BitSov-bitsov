//! K1 slice 2: capped sponsor sats in an introduction kit.
//!
//! One person funds another: the inviter's node pays a small, capped gift
//! into the newcomer's own node. **The gift never buys admission.** It lands
//! as the newcomer's ordinary balance, the invoice that carries it is
//! registered funding-only on the newcomer's node (the payment gate refuses
//! it as a message proof, even from the sponsor who learns its preimage), and
//! every message after it is paid through the gate like any other. There is
//! no credit, no free lane and no platform purse.
//!
//! Two signed records, both compact binary behind base64url links:
//!
//! - [`SponsorOffer`]: the sponsor's node offers up to `gift_msat` for
//!   exactly one introduction (`intro_id`), until `expires_at`. It rides next
//!   to the introduction card: `bitsov://introduce#<card>.<offer>`.
//! - [`FundingRequest`]: the newcomer's node asks for that gift into one
//!   fixed invoice (`bolt11`, `payment_hash`) payable to its own Lightning
//!   key (`newcomer_ln`), signed by its BitSov key. It goes back to the
//!   sponsor in person, as `bitsov://sponsor-request#<request>`, with a
//!   six-digit [`comparison_code`] both screens show.
//!
//! Caps ([`MAX_GIFT_MSAT`] and friends) are the spec's hard ceilings; a node
//! may only lower them. Nothing here is stored: the sponsor's and newcomer's
//! nodes keep their own ledgers.

use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use thiserror::Error;

pub const OFFER_DOMAIN_V1: &[u8] = b"bitsov-sponsor-offer/v1\0";
pub const REQUEST_DOMAIN_V1: &[u8] = b"bitsov-sponsor-request/v1\0";
const CODE_DOMAIN_V1: &[u8] = b"bitsov-sponsor-code/v1\0";
pub const VERSION: u8 = 1;
pub const REQUEST_LINK_PREFIX: &str = "bitsov://sponsor-request#";
/// Separates the card from its offer inside an introduction link fragment.
/// Not in the base64url alphabet, so the card part parses unchanged.
pub const OFFER_SEPARATOR: char = '.';

/// Per-kit ceiling, gift plus every fee (spec: 50,000 sats).
pub const MAX_KIT_MSAT: u64 = 50_000_000;
/// Rolling 24-hour purse, including fees and unresolved reservations
/// (spec: 100,000 sats).
pub const MAX_PURSE_MSAT: u64 = 100_000_000;
/// Approved kits per rolling 24 hours (spec: two).
pub const MAX_KITS_PER_DAY: u32 = 2;
/// Kits open at once, offered or pending (spec: one).
pub const MAX_ACTIVE_KITS: u32 = 1;
/// Route-fee ceiling reserved on top of the gift (spec: 100 sats).
pub const MAX_FEE_MSAT: u64 = 100_000;
/// An offer and its dispatch authority live ten minutes (spec).
pub const OFFER_LIFETIME_SECS: u64 = 600;
pub const MAX_BOLT11_LEN: usize = 1024;
pub const MAX_ENCODED_LEN: usize = 2048;
const NETWORKS: [&str; 4] = ["bitcoin", "testnet", "signet", "regtest"];

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SponsorError {
    #[error("too large ({0} bytes)")]
    TooLarge(usize),
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("unsupported version {0}")]
    UnsupportedVersion(u8),
    #[error("wrong network: {got}, expected {want}")]
    WrongNetwork { got: String, want: String },
    #[error("expired at {0}")]
    Expired(u64),
    #[error("lives longer than {OFFER_LIFETIME_SECS} s")]
    LifetimeTooLong,
    #[error("amount outside 1..={MAX_KIT_MSAT} msat")]
    Amount,
    #[error("invalid or weak key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64(text: &str) -> Result<Vec<u8>, SponsorError> {
    if text.len() > MAX_ENCODED_LEN {
        return Err(SponsorError::TooLarge(text.len()));
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| SponsorError::Malformed("bad encoding".into()))
}

/// A full-order, canonically encoded Ed25519 key.
fn strict_key(bytes: &[u8; 32]) -> Result<VerifyingKey, SponsorError> {
    let key = VerifyingKey::from_bytes(bytes).map_err(|_| SponsorError::InvalidKey)?;
    if key.is_weak() || key.to_edwards().compress().to_bytes() != *bytes {
        return Err(SponsorError::InvalidKey);
    }
    Ok(key)
}

fn verify_sig(key: &[u8; 32], digest: &[u8; 32], sig: &[u8; 64]) -> Result<(), SponsorError> {
    strict_key(key)?
        .verify_strict(digest, &Signature::from_bytes(sig))
        .map_err(|_| SponsorError::InvalidSignature)
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], SponsorError> {
        let s = self.b.get(self.at..self.at + n).ok_or_else(|| SponsorError::Malformed("truncated".into()))?;
        self.at += n;
        Ok(s)
    }
    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], SponsorError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }
    fn u8(&mut self) -> Result<u8, SponsorError> {
        Ok(self.take(1)?[0])
    }
    fn u64(&mut self) -> Result<u64, SponsorError> {
        Ok(u64::from_be_bytes(self.fixed::<8>()?))
    }
    fn text(&mut self, n: usize) -> Result<String, SponsorError> {
        String::from_utf8(self.take(n)?.to_vec()).map_err(|_| SponsorError::Malformed("not UTF-8".into()))
    }
    fn done(&self) -> Result<(), SponsorError> {
        if self.at == self.b.len() { Ok(()) } else { Err(SponsorError::Malformed("trailing bytes".into())) }
    }
}

fn check_network(network: &str) -> Result<(), SponsorError> {
    if NETWORKS.contains(&network) { Ok(()) } else { Err(SponsorError::Malformed(format!("unknown network {network:?}"))) }
}

// ---- the offer ----------------------------------------------------------------

/// The sponsor's signed offer of up to `gift_msat` for one introduction.
/// An offer to review a request, not a bearer withdrawal authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SponsorOffer {
    pub network: String,
    pub intro_id: [u8; 16],
    /// The sponsor's node id (Ed25519).
    pub sponsor: [u8; 32],
    /// The fixed gift the newcomer may request, msat. Fees are the sponsor's.
    pub gift_msat: u64,
    pub expires_at: u64,
    pub sig: [u8; 64],
}

impl SponsorOffer {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        out.push(VERSION);
        out.push(self.network.len() as u8);
        out.extend_from_slice(self.network.as_bytes());
        out.extend_from_slice(&self.intro_id);
        out.extend_from_slice(&self.sponsor);
        out.extend_from_slice(&self.gift_msat.to_be_bytes());
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }

    fn digest(&self) -> [u8; 32] {
        let mut signed = OFFER_DOMAIN_V1.to_vec();
        signed.extend_from_slice(&self.body());
        *blake3::hash(&signed).as_bytes()
    }

    pub fn sign(key: &SigningKey, network: &str, intro_id: [u8; 16], gift_msat: u64, expires_at: u64) -> Result<Self, SponsorError> {
        check_network(network)?;
        if gift_msat == 0 || gift_msat > MAX_KIT_MSAT {
            return Err(SponsorError::Amount);
        }
        let mut offer = Self {
            network: network.into(),
            intro_id,
            sponsor: key.verifying_key().to_bytes(),
            gift_msat,
            expires_at,
            sig: [0; 64],
        };
        offer.sig = key.sign(&offer.digest()).to_bytes();
        Ok(offer)
    }

    /// Signature by `sponsor`, network, amount bound and expiry.
    pub fn verify(&self, now_unix: u64, network: &str) -> Result<(), SponsorError> {
        check_network(&self.network)?;
        if self.network != network {
            return Err(SponsorError::WrongNetwork { got: self.network.clone(), want: network.into() });
        }
        if self.gift_msat == 0 || self.gift_msat > MAX_KIT_MSAT {
            return Err(SponsorError::Amount);
        }
        if self.expires_at <= now_unix {
            return Err(SponsorError::Expired(self.expires_at));
        }
        if self.expires_at > now_unix.saturating_add(OFFER_LIFETIME_SECS + 60) {
            return Err(SponsorError::LifetimeTooLong);
        }
        verify_sig(&self.sponsor, &self.digest(), &self.sig)
    }

    pub fn encode(&self) -> String {
        let mut bytes = self.body();
        bytes.extend_from_slice(&self.sig);
        b64(&bytes)
    }

    pub fn decode(text: &str) -> Result<Self, SponsorError> {
        let bytes = unb64(text.trim())?;
        let mut r = Reader { b: &bytes, at: 0 };
        let v = r.u8()?;
        if v != VERSION {
            return Err(SponsorError::UnsupportedVersion(v));
        }
        let n = r.u8()? as usize;
        let network = r.text(n)?;
        let offer = Self {
            network,
            intro_id: r.fixed()?,
            sponsor: r.fixed()?,
            gift_msat: r.u64()?,
            expires_at: r.u64()?,
            sig: r.fixed()?,
        };
        r.done()?;
        Ok(offer)
    }
}

/// Split `bitsov://introduce#<card>.<offer>` (or a bare fragment) into the
/// card text, which [`crate::introduction::Introduction::parse`] reads
/// unchanged, and the optional offer.
pub fn split_introduction_link(text: &str) -> (String, Option<String>) {
    let text = text.trim();
    if text.starts_with('{') {
        return (text.to_string(), None);
    }
    match text.rsplit_once(OFFER_SEPARATOR) {
        // Only split inside the fragment: a card link has no '.' of its own.
        Some((card, offer)) if !offer.contains('#') && !offer.is_empty() => (card.to_string(), Some(offer.to_string())),
        _ => (text.to_string(), None),
    }
}

// ---- the funding request ------------------------------------------------------

/// The newcomer node's signed request for the offered gift, into one fixed
/// invoice payable to its own Lightning key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundingRequest {
    pub network: String,
    pub intro_id: [u8; 16],
    pub sponsor: [u8; 32],
    /// The newcomer's BitSov node id (Ed25519). Signs this request.
    pub newcomer: [u8; 32],
    /// The newcomer's Lightning node key (33-byte secp256k1): the invoice's payee.
    pub newcomer_ln: [u8; 33],
    pub amount_msat: u64,
    pub payment_hash: [u8; 32],
    pub expires_at: u64,
    pub bolt11: String,
    pub sig: [u8; 64],
}

impl FundingRequest {
    fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(200 + self.bolt11.len());
        out.push(VERSION);
        out.push(self.network.len() as u8);
        out.extend_from_slice(self.network.as_bytes());
        out.extend_from_slice(&self.intro_id);
        out.extend_from_slice(&self.sponsor);
        out.extend_from_slice(&self.newcomer);
        out.extend_from_slice(&self.newcomer_ln);
        out.extend_from_slice(&self.amount_msat.to_be_bytes());
        out.extend_from_slice(&self.payment_hash);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.extend_from_slice(&(self.bolt11.len() as u16).to_be_bytes());
        out.extend_from_slice(self.bolt11.as_bytes());
        out
    }

    fn digest(&self) -> [u8; 32] {
        let mut signed = REQUEST_DOMAIN_V1.to_vec();
        signed.extend_from_slice(&self.body());
        *blake3::hash(&signed).as_bytes()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        key: &SigningKey,
        offer: &SponsorOffer,
        newcomer_ln: [u8; 33],
        amount_msat: u64,
        payment_hash: [u8; 32],
        expires_at: u64,
        bolt11: String,
    ) -> Result<Self, SponsorError> {
        if bolt11.len() > MAX_BOLT11_LEN || !bolt11.is_ascii() {
            return Err(SponsorError::Malformed("bolt11 too long".into()));
        }
        if amount_msat == 0 || amount_msat > offer.gift_msat {
            return Err(SponsorError::Amount);
        }
        let mut req = Self {
            network: offer.network.clone(),
            intro_id: offer.intro_id,
            sponsor: offer.sponsor,
            newcomer: key.verifying_key().to_bytes(),
            newcomer_ln,
            amount_msat,
            payment_hash,
            expires_at,
            bolt11,
            sig: [0; 64],
        };
        req.sig = key.sign(&req.digest()).to_bytes();
        Ok(req)
    }

    /// Signature by `newcomer`, network, amount bound, expiry. The caller
    /// (the sponsor's node) still checks the kit, the invoice's payee, amount
    /// and hash against these fields, and its own caps.
    pub fn verify(&self, now_unix: u64, network: &str) -> Result<(), SponsorError> {
        check_network(&self.network)?;
        if self.network != network {
            return Err(SponsorError::WrongNetwork { got: self.network.clone(), want: network.into() });
        }
        if self.amount_msat == 0 || self.amount_msat > MAX_KIT_MSAT {
            return Err(SponsorError::Amount);
        }
        if self.expires_at <= now_unix {
            return Err(SponsorError::Expired(self.expires_at));
        }
        if self.newcomer == self.sponsor {
            return Err(SponsorError::Malformed("a node cannot sponsor itself".into()));
        }
        verify_sig(&self.newcomer, &self.digest(), &self.sig)
    }

    pub fn to_link(&self) -> String {
        let mut bytes = self.body();
        bytes.extend_from_slice(&self.sig);
        format!("{REQUEST_LINK_PREFIX}{}", b64(&bytes))
    }

    pub fn parse(text: &str) -> Result<Self, SponsorError> {
        if text.len() > MAX_ENCODED_LEN {
            return Err(SponsorError::TooLarge(text.len()));
        }
        let text = text.trim();
        let payload = text.strip_prefix(REQUEST_LINK_PREFIX).unwrap_or(text);
        let bytes = unb64(payload)?;
        let mut r = Reader { b: &bytes, at: 0 };
        let v = r.u8()?;
        if v != VERSION {
            return Err(SponsorError::UnsupportedVersion(v));
        }
        let n = r.u8()? as usize;
        let network = r.text(n)?;
        let intro_id = r.fixed()?;
        let sponsor = r.fixed()?;
        let newcomer = r.fixed()?;
        let newcomer_ln = r.fixed()?;
        let amount_msat = r.u64()?;
        let payment_hash = r.fixed()?;
        let expires_at = r.u64()?;
        let len = u16::from_be_bytes(r.fixed()?) as usize;
        if len > MAX_BOLT11_LEN {
            return Err(SponsorError::Malformed("bolt11 too long".into()));
        }
        let bolt11 = r.text(len)?;
        let sig = r.fixed()?;
        r.done()?;
        Ok(Self { network, intro_id, sponsor, newcomer, newcomer_ln, amount_msat, payment_hash, expires_at, bolt11, sig })
    }

    /// The six digits both people compare in person before the sponsor pays.
    pub fn comparison_code(&self) -> String {
        comparison_code(&self.intro_id, &self.sponsor, &self.newcomer, &self.payment_hash)
    }
}

/// Six digits from the kit, both keys and the invoice hash. They supplement
/// the signatures (a copied QR shows a different code); they are never the
/// only authorization.
pub fn comparison_code(intro_id: &[u8; 16], sponsor: &[u8; 32], newcomer: &[u8; 32], payment_hash: &[u8; 32]) -> String {
    let mut h = blake3::Hasher::new();
    h.update(CODE_DOMAIN_V1);
    h.update(intro_id);
    h.update(sponsor);
    h.update(newcomer);
    h.update(payment_hash);
    let d = h.finalize();
    let n = u32::from_be_bytes(d.as_bytes()[..4].try_into().expect("4 bytes")) % 1_000_000;
    format!("{n:06}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_790_000_000;

    fn sponsor() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }
    fn newcomer() -> SigningKey {
        SigningKey::from_bytes(&[4; 32])
    }
    fn offer() -> SponsorOffer {
        SponsorOffer::sign(&sponsor(), "regtest", [9; 16], 20_000_000, NOW + 600).unwrap()
    }
    fn request() -> FundingRequest {
        FundingRequest::sign(&newcomer(), &offer(), [2; 33], 20_000_000, [7; 32], NOW + 300, "lnbcrt200u1ptest".into()).unwrap()
    }

    #[test]
    fn offer_round_trips_and_every_field_is_signed() {
        let o = offer();
        assert!(o.verify(NOW, "regtest").is_ok());
        assert_eq!(SponsorOffer::decode(&o.encode()).unwrap(), o);
        let tamper: Vec<fn(&mut SponsorOffer)> = vec![
            |o| o.network = "signet".into(),
            |o| o.intro_id[0] ^= 1,
            |o| o.gift_msat += 1,
            |o| o.expires_at -= 1,
            |o| o.sponsor = SigningKey::from_bytes(&[5; 32]).verifying_key().to_bytes(),
        ];
        for (i, t) in tamper.iter().enumerate() {
            let mut bad = o.clone();
            t(&mut bad);
            let net = bad.network.clone();
            assert!(bad.verify(NOW, &net).is_err(), "offer tamper {i} verified");
        }
    }

    /// Fixed vector shared with bitsov-app's host-side reader: key `[3; 32]`,
    /// regtest, intro id `[9; 16]`, 20,000,000 msat, expires 1,790,000,600.
    #[test]
    fn offer_vector_is_stable() {
        assert_eq!(offer().encode(), OFFER_VECTOR);
        assert_eq!(SponsorOffer::decode(OFFER_VECTOR).unwrap(), offer());
    }
    const OFFER_VECTOR: &str = "AQdyZWd0ZXN0CQkJCQkJCQkJCQkJCQkJCe1JKMYo0cLG6ukDOJBZlWEpWSc6XGP5NjbBRhSshzfRAAAAAAExLQAAAAAAarE92I-FHpnHFK0Ny6W-SruDW5v3I8TMFACVAQb8HMKeYUS6U3hb8K1hLRCD783dgdDkieTVeybMhR3dKClLr-7pDQ4";

    #[test]
    fn offer_bounds() {
        assert_eq!(SponsorOffer::sign(&sponsor(), "regtest", [9; 16], MAX_KIT_MSAT + 1, NOW + 600), Err(SponsorError::Amount));
        assert_eq!(SponsorOffer::sign(&sponsor(), "regtest", [9; 16], 0, NOW + 600), Err(SponsorError::Amount));
        assert_eq!(offer().verify(NOW + 600, "regtest"), Err(SponsorError::Expired(NOW + 600)));
        assert!(matches!(offer().verify(NOW, "bitcoin"), Err(SponsorError::WrongNetwork { .. })));
        let long = SponsorOffer::sign(&sponsor(), "regtest", [9; 16], 1000, NOW + 3600).unwrap();
        assert_eq!(long.verify(NOW, "regtest"), Err(SponsorError::LifetimeTooLong));
    }

    #[test]
    fn a_weak_key_offer_is_refused() {
        let mut o = offer();
        o.sponsor = [0; 32];
        o.sponsor[0] = 1;
        o.sig = [0; 64];
        o.sig[0] = 1;
        assert_eq!(o.verify(NOW, "regtest"), Err(SponsorError::InvalidKey));
    }

    #[test]
    fn request_round_trips_and_every_field_is_signed() {
        let r = request();
        assert!(r.verify(NOW, "regtest").is_ok());
        let link = r.to_link();
        assert!(link.starts_with(REQUEST_LINK_PREFIX));
        assert_eq!(FundingRequest::parse(&link).unwrap(), r);
        let tamper: Vec<fn(&mut FundingRequest)> = vec![
            |r| r.intro_id[0] ^= 1,
            |r| r.sponsor[0] ^= 1,
            |r| r.newcomer_ln[5] ^= 1,
            |r| r.amount_msat -= 1,
            |r| r.payment_hash[0] ^= 1,
            |r| r.expires_at += 1,
            |r| r.bolt11.push('x'),
        ];
        for (i, t) in tamper.iter().enumerate() {
            let mut bad = r.clone();
            t(&mut bad);
            assert!(bad.verify(NOW, "regtest").is_err(), "request tamper {i} verified");
        }
    }

    #[test]
    fn request_bounds() {
        assert_eq!(
            FundingRequest::sign(&newcomer(), &offer(), [2; 33], 20_000_001, [7; 32], NOW + 300, "ln".into()),
            Err(SponsorError::Amount),
            "never more than the offer"
        );
        let mut own = request();
        own.newcomer = own.sponsor;
        assert!(own.verify(NOW, "regtest").is_err());
        assert!(FundingRequest::parse(&"A".repeat(MAX_ENCODED_LEN + 1)).is_err());
        assert!(FundingRequest::parse(&format!("{}AA", request().to_link())).is_err(), "trailing bytes");
    }

    #[test]
    fn comparison_code_is_six_digits_and_binds_every_input() {
        let r = request();
        let code = r.comparison_code();
        assert_eq!(code.len(), 6);
        assert!(code.bytes().all(|b| b.is_ascii_digit()));
        let mut other = r.clone();
        other.payment_hash[0] ^= 1;
        assert_ne!(other.comparison_code(), code);
        other = r.clone();
        other.newcomer[0] ^= 1;
        assert_ne!(other.comparison_code(), code);
    }

    #[test]
    fn introduction_links_split_into_card_and_offer() {
        let o = offer().encode();
        let (card, got) = split_introduction_link(&format!("bitsov://introduce#AQdy.{o}"));
        assert_eq!((card.as_str(), got.as_deref()), ("bitsov://introduce#AQdy", Some(o.as_str())));
        let (card, got) = split_introduction_link("bitsov://introduce#AQdy");
        assert_eq!((card.as_str(), got), ("bitsov://introduce#AQdy", None));
        let (card, got) = split_introduction_link("{\"v\":1}");
        assert_eq!((card.as_str(), got), ("{\"v\":1}", None));
    }
}
