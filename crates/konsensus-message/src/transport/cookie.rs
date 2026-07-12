//! Pre-Noise anti-DoS cookie (doorway hardening #2, "A-first").
//!
//! A **stateless return-routability cookie** that sits *before* the Noise_XX DH,
//! so a node can refuse to spend an X25519 Diffie–Hellman on a spoofed or
//! unproven source — the free-DH leak the per-subnet rate-limit (#300) could only
//! *rate*-bound. The node holds **no per-connection state** until the cookie
//! validates: a cookie is `HMAC(secret, src-ip ‖ epoch)`, recomputed on demand,
//! so the defense itself cannot be turned into a memory-DoS.
//!
//! Properties (per the #301 decision — "C implemented A-first"):
//! - **Default off.** [`CookieMode::Disabled`] ⇒ the handshake is byte-identical
//!   to pre-cookie. Enabling it is an operator opt-in via [`super::TransportConfig`].
//! - **Self-describing on the wire.** A cookie frame carries the [`COOKIE_MAGIC`]
//!   prefix and is a fixed 38 bytes; a Noise_XX message-1 is a bare 32-byte
//!   ephemeral key with no magic, so the two are unambiguous. The challenge is
//!   recognizable **without** any prior capability/out-of-band negotiation — which
//!   is mandatory, because this gate runs before the Noise/federation handshake
//!   where capabilities are exchanged.
//! - **Graceful, no flag-day.** A cookie-aware initiator speaks an optimistic
//!   Noise message-1 first; if the responder requires a cookie it answers with a
//!   challenge instead of a Noise reply, and the initiator retries with a fresh
//!   Noise session. A non-cookie responder never sends a challenge, so the path
//!   is unchanged for it.
//! - **No active proof-of-work.** The `difficulty` byte is reserved and fixed at
//!   `0` (a dormant hook for a future congestion-adaptive PoW); there is no
//!   standing PoW that would tax phones / low-power nodes / honest users on bad
//!   networks.
//! - **Identity/topology/price-blind.** A cookie frame carries no node id, no
//!   tier, no price, no peer data — it is pre-everything. Availability defense,
//!   never admission; it changes no payment-gate and no message-wire semantics.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use konsensus_core::traits::transport::TransportError;
use tokio::net::TcpStream;

use super::{read_bounded_message, write_noise_message};

type HmacSha256 = Hmac<Sha256>;

/// Self-describing magic prefix for a pre-Noise cookie frame. A Noise_XX
/// message-1 is a bare 32-byte ephemeral key with no structure, so this 4-byte
/// prefix (plus the fixed 38-byte length) lets either side recognize a cookie
/// frame on the wire without any prior negotiation.
pub(super) const COOKIE_MAGIC: [u8; 4] = *b"BSc1";

/// Fixed on-wire size of a cookie frame (challenge or response).
pub(super) const COOKIE_FRAME_LEN: usize = 38;

/// Hard upper bound on any frame read **before** the cookie is verified. The only
/// legitimate pre-Noise blobs are a cookie frame (38 bytes) or an optimistic
/// Noise message-1 (a bare 32-byte ephemeral); anything larger is refused without
/// allocating, so a source that has not yet proven return-routability cannot make
/// a cookie-mode node allocate/read a large buffer (the normal ~16 MiB frame cap
/// applies only *after* the cookie passes).
pub(super) const MAX_PRE_NOISE_FRAME: usize = 64;

/// Coarse-time window for cookie validity, in seconds. A cookie is bound to the
/// source IP and the epoch `unix_secs / COOKIE_EPOCH_SECS`; the verifier accepts
/// the current and immediately-previous epoch (a 2-window tolerance across a
/// boundary), so a captured cookie is replayable only from the **same source**
/// for at most `2 * COOKIE_EPOCH_SECS` — exactly the source we already decided to
/// admit to a handshake.
pub(super) const COOKIE_EPOCH_SECS: u64 = 30;

const KIND_CHALLENGE: u8 = 1;
const KIND_RESPONSE: u8 = 2;

/// Operator-selectable pre-Noise cookie posture (a field of
/// [`super::TransportConfig`]).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CookieMode {
    /// Default: no pre-Noise cookie. The handshake is byte-identical to
    /// pre-cookie; the node never issues or expects a cookie. (`konsensus.toml`:
    /// `cookie_mode = "disabled"`.)
    #[default]
    Disabled,
    /// Require every inbound initiator to echo a valid stateless cookie before
    /// this node spends a Noise DH. Operator opt-in; legacy peers that cannot
    /// answer the self-describing challenge are rejected (the operator accepted
    /// that trade by enabling the mode).
    Required,
}

/// A node's in-memory cookie secret. Random at process start; **never persisted,
/// never on the wire, never logged**.
///
/// v1 uses a single generation: a fixed secret plus epoch-based expiry is already
/// stateless and time-bounded. A rotating two-generation keyring (to bound the
/// lifetime of a compromised secret) is a documented follow-up and does not
/// change the wire format.
pub(super) struct CookieKeyring {
    secret: [u8; 32],
}

impl CookieKeyring {
    /// Generate a fresh random keyring (called once at transport start).
    pub(super) fn random() -> Self {
        let mut secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        Self { secret }
    }

    /// `HMAC-SHA256(secret, ip-octets ‖ epoch_le)`, truncated to 16 bytes.
    fn mac(&self, ip: IpAddr, epoch: u64) -> [u8; 16] {
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .expect("HMAC-SHA256 accepts a key of any length");
        match ip {
            IpAddr::V4(v4) => mac.update(&v4.octets()),
            IpAddr::V6(v6) => mac.update(&v6.octets()),
        }
        mac.update(&epoch.to_le_bytes());
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 16];
        out.copy_from_slice(&tag[..16]);
        out
    }

    /// Issue a fresh cookie for `ip` at the epoch covering `now_unix`.
    pub(super) fn issue(&self, ip: IpAddr, now_unix: u64) -> Cookie {
        let epoch = now_unix / COOKIE_EPOCH_SECS;
        Cookie {
            epoch,
            mac: self.mac(ip, epoch),
        }
    }

    /// Constant-time verify a presented cookie against `ip`, accepting only the
    /// current or immediately-previous epoch. Returns `false` for any spoofed,
    /// stale, or forged cookie.
    pub(super) fn verify(&self, ip: IpAddr, presented: &Cookie, now_unix: u64) -> bool {
        let epoch_now = now_unix / COOKIE_EPOCH_SECS;
        // Accept current or one-prior epoch only (boundary tolerance).
        if presented.epoch != epoch_now && presented.epoch.wrapping_add(1) != epoch_now {
            return false;
        }
        let expected = self.mac(ip, presented.epoch);
        ct_eq_16(&expected, &presented.mac)
    }
}

/// A parsed cookie value (the time-bound, source-bound MAC). Carries no identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Cookie {
    epoch: u64,
    mac: [u8; 16],
}

/// A decoded cookie frame (challenge or response) as it appears on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct CookieFrame {
    kind: u8,
    /// Reserved congestion-adaptive PoW difficulty. **Always 0** in v1.
    difficulty: u8,
    cookie: Cookie,
    /// Reserved PoW solution nonce. **Always 0** in v1.
    pow_nonce: u64,
}

impl CookieFrame {
    fn challenge(cookie: Cookie) -> Self {
        Self {
            kind: KIND_CHALLENGE,
            difficulty: 0,
            cookie,
            pow_nonce: 0,
        }
    }

    fn response(cookie: Cookie) -> Self {
        Self {
            kind: KIND_RESPONSE,
            difficulty: 0,
            cookie,
            pow_nonce: 0,
        }
    }

    /// Fixed-layout encode (38 bytes, all integers big-endian):
    /// `magic[4] ‖ kind ‖ difficulty ‖ epoch[8] ‖ mac[16] ‖ pow_nonce[8]`.
    fn encode(&self) -> [u8; COOKIE_FRAME_LEN] {
        let mut out = [0u8; COOKIE_FRAME_LEN];
        out[0..4].copy_from_slice(&COOKIE_MAGIC);
        out[4] = self.kind;
        out[5] = self.difficulty;
        out[6..14].copy_from_slice(&self.cookie.epoch.to_be_bytes());
        out[14..30].copy_from_slice(&self.cookie.mac);
        out[30..38].copy_from_slice(&self.pow_nonce.to_be_bytes());
        out
    }

    /// Parse a frame from raw bytes, returning `None` for anything that is not a
    /// well-formed cookie frame (wrong length, wrong magic, unknown kind). A bare
    /// Noise message never matches (no magic, wrong length), which is what makes
    /// the challenge self-describing.
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != COOKIE_FRAME_LEN || bytes[0..4] != COOKIE_MAGIC {
            return None;
        }
        let kind = bytes[4];
        if kind != KIND_CHALLENGE && kind != KIND_RESPONSE {
            return None;
        }
        let difficulty = bytes[5];
        let mut epoch_b = [0u8; 8];
        epoch_b.copy_from_slice(&bytes[6..14]);
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&bytes[14..30]);
        let mut nonce_b = [0u8; 8];
        nonce_b.copy_from_slice(&bytes[30..38]);
        Some(Self {
            kind,
            difficulty,
            cookie: Cookie {
                epoch: u64::from_be_bytes(epoch_b),
                mac,
            },
            pow_nonce: u64::from_be_bytes(nonce_b),
        })
    }

    /// v1 carries no proof-of-work, so both reserved fields MUST be zero on a
    /// response. A non-zero `difficulty` or `pow_nonce` (a forged/garbage frame,
    /// or one speaking a future PoW format this build does not implement) is
    /// rejected, keeping the v1 wire unambiguous and fail-closed.
    fn reserved_is_zero(&self) -> bool {
        self.difficulty == 0 && self.pow_nonce == 0
    }
}

/// Constant-time equality of two 16-byte tags (no early return on first mismatch).
fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// If `bytes` is a well-formed cookie **challenge**, return it. Used by the
/// initiator to recognize, without prior negotiation, that the peer requires a
/// cookie (versus a normal Noise message-2 reply).
pub(super) fn parse_challenge(bytes: &[u8]) -> Option<CookieFrame> {
    CookieFrame::decode(bytes).filter(|f| f.kind == KIND_CHALLENGE)
}

// ─── Responder gate ─────────────────────────────────────────────────────────

/// Responder side of the pre-Noise cookie gate (runs only in
/// [`CookieMode::Required`], before any Noise DH).
///
/// Reads the initiator's first framed blob:
/// - If it is already a valid cookie **response** (a future initiator that cached
///   a cookie), accept — the caller then reads the Noise message-1 next.
/// - Otherwise (the common case: an optimistic Noise message-1, or an
///   invalid/stale cookie), issue a fresh challenge bound to `ip`, read the
///   initiator's response, and verify it. On success the caller proceeds to the
///   Noise handshake (the initiator re-sends a fresh Noise message-1); on failure
///   the connection is dropped before any DH.
///
/// Holds **no per-connection state**: the cookie is recomputed from `ip` + epoch.
pub(super) async fn cookie_gate_responder(
    reader: &mut tokio::io::ReadHalf<TcpStream>,
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    ip: IpAddr,
    keyring: &CookieKeyring,
) -> Result<(), TransportError> {
    // First framed blob from the initiator. Read with a tight bound: a source
    // that has not yet proven return-routability cannot make us allocate a large
    // buffer (the normal ~16 MiB cap applies only AFTER the cookie passes).
    let first = read_bounded_message(reader, MAX_PRE_NOISE_FRAME)
        .await
        .map_err(|e| TransportError::Other(e.to_string()))?;

    // Fast path: an initiator that already holds a valid cookie may present it
    // up front (forward-compatible; the v1 initiator does not, and instead takes
    // the challenge path below). v1 reserved fields must be zero.
    if let Some(frame) = CookieFrame::decode(&first) {
        if frame.kind == KIND_RESPONSE
            && frame.reserved_is_zero()
            && keyring.verify(ip, &frame.cookie, now_unix())
        {
            return Ok(());
        }
    }

    // Challenge path: issue a fresh cookie bound to this source and require the
    // initiator to echo it. The `first` blob (an optimistic Noise message-1, or a
    // bad cookie) is discarded without a DH.
    let challenge = CookieFrame::challenge(keyring.issue(ip, now_unix()));
    write_noise_message(writer, &challenge.encode())
        .await
        .map_err(|e| TransportError::Other(e.to_string()))?;

    let answer = read_bounded_message(reader, MAX_PRE_NOISE_FRAME)
        .await
        .map_err(|e| TransportError::Other(e.to_string()))?;
    let frame = CookieFrame::decode(&answer)
        .filter(|f| f.kind == KIND_RESPONSE)
        .ok_or_else(|| TransportError::Rejected("malformed cookie response".into()))?;
    // v1 carries no PoW: a response with a non-zero reserved field is rejected.
    if !frame.reserved_is_zero() {
        return Err(TransportError::Rejected(
            "cookie response sets a reserved field (difficulty/pow_nonce) this build does not implement".into(),
        ));
    }
    if !keyring.verify(ip, &frame.cookie, now_unix()) {
        return Err(TransportError::Rejected(
            "invalid pre-Noise cookie (spoofed or stale source)".into(),
        ));
    }
    Ok(())
}

// ─── Initiator helper ───────────────────────────────────────────────────────

/// Initiator side: having recognized a `challenge` (via [`parse_challenge`]),
/// echo it back as a response. v1 carries no PoW, so a non-zero difficulty (which
/// the v1 responder never sends) is rejected rather than silently ignored.
pub(super) async fn answer_challenge(
    writer: &mut tokio::io::WriteHalf<TcpStream>,
    challenge: &CookieFrame,
) -> Result<(), TransportError> {
    if challenge.difficulty != 0 {
        return Err(TransportError::Rejected(
            "cookie challenge demands proof-of-work, which this build does not implement".into(),
        ));
    }
    let response = CookieFrame::response(challenge.cookie);
    write_noise_message(writer, &response.encode())
        .await
        .map_err(|e| TransportError::Other(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn issued_cookie_verifies_for_same_ip_and_epoch() {
        let k = CookieKeyring::random();
        let ip = ip4(203, 0, 113, 7);
        let now = 1_000_000;
        let c = k.issue(ip, now);
        assert!(k.verify(ip, &c, now), "a freshly issued cookie must verify");
    }

    #[test]
    fn cookie_for_one_ip_does_not_verify_for_another() {
        // The anti-spoofing core: a cookie is bound to the source octets, so it
        // is worthless from a different address (a spoofed-source flood never
        // receives a cookie valid for its real return path).
        let k = CookieKeyring::random();
        let now = 1_000_000;
        let c = k.issue(ip4(203, 0, 113, 7), now);
        assert!(!k.verify(ip4(198, 51, 100, 9), &c, now));
    }

    #[test]
    fn cookie_from_a_different_keyring_is_rejected() {
        // A forged cookie (attacker who never saw our secret) cannot validate.
        let a = CookieKeyring::random();
        let b = CookieKeyring::random();
        let ip = ip4(203, 0, 113, 7);
        let now = 1_000_000;
        let forged = a.issue(ip, now);
        assert!(!b.verify(ip, &forged, now));
    }

    #[test]
    fn previous_epoch_is_accepted_but_older_is_not() {
        let k = CookieKeyring::random();
        let ip = ip4(203, 0, 113, 7);
        // Issued at the start of an epoch.
        let t0 = 10 * COOKIE_EPOCH_SECS;
        let c = k.issue(ip, t0);
        // Same epoch: ok. One epoch later: still ok (boundary tolerance).
        assert!(k.verify(ip, &c, t0));
        assert!(k.verify(ip, &c, t0 + COOKIE_EPOCH_SECS));
        // Two epochs later: stale, rejected.
        assert!(!k.verify(ip, &c, t0 + 2 * COOKIE_EPOCH_SECS));
    }

    #[test]
    fn ipv6_cookies_are_bound_to_the_full_address() {
        let k = CookieKeyring::random();
        let now = 1_000_000;
        let a = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let b = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));
        let c = k.issue(a, now);
        assert!(k.verify(a, &c, now));
        assert!(!k.verify(b, &c, now));
    }

    #[test]
    fn frame_round_trips_through_the_wire_layout() {
        let k = CookieKeyring::random();
        let cookie = k.issue(ip4(203, 0, 113, 7), 1_000_000);
        for frame in [CookieFrame::challenge(cookie), CookieFrame::response(cookie)] {
            let bytes = frame.encode();
            assert_eq!(bytes.len(), COOKIE_FRAME_LEN);
            assert_eq!(&bytes[0..4], &COOKIE_MAGIC);
            let decoded = CookieFrame::decode(&bytes).expect("a valid frame must decode");
            assert_eq!(decoded, frame);
        }
    }

    #[test]
    fn a_bare_noise_message_1_is_never_mistaken_for_a_cookie() {
        // Noise_XX message-1 is a bare 32-byte ephemeral key: wrong length and no
        // magic. This is what makes the challenge self-describing.
        let noise_msg1 = [0x42u8; 32];
        assert!(CookieFrame::decode(&noise_msg1).is_none());
        assert!(parse_challenge(&noise_msg1).is_none());
        // Even a 38-byte blob without the magic must not parse.
        let not_a_cookie = [0u8; COOKIE_FRAME_LEN];
        assert!(CookieFrame::decode(&not_a_cookie).is_none());
    }

    #[test]
    fn parse_challenge_rejects_a_response_frame() {
        let k = CookieKeyring::random();
        let cookie = k.issue(ip4(203, 0, 113, 7), 1_000_000);
        let response_bytes = CookieFrame::response(cookie).encode();
        // A response is a valid frame but is NOT a challenge.
        assert!(CookieFrame::decode(&response_bytes).is_some());
        assert!(parse_challenge(&response_bytes).is_none());
        let challenge_bytes = CookieFrame::challenge(cookie).encode();
        assert!(parse_challenge(&challenge_bytes).is_some());
    }

    #[test]
    fn reserved_fields_must_be_zero_on_a_response() {
        // v1 carries no PoW — a clean response has zero reserved fields, and any
        // non-zero difficulty / pow_nonce is rejected (kept fail-closed so a
        // future PoW format cannot be smuggled past a v1 responder).
        let k = CookieKeyring::random();
        let cookie = k.issue(ip4(203, 0, 113, 7), 1_000_000);
        let clean = CookieFrame::response(cookie);
        assert!(clean.reserved_is_zero());

        let mut bad_diff = clean;
        bad_diff.difficulty = 1;
        assert!(!bad_diff.reserved_is_zero());

        let mut bad_nonce = clean;
        bad_nonce.pow_nonce = 1;
        assert!(!bad_nonce.reserved_is_zero());
    }

    #[test]
    fn tampered_mac_is_rejected() {
        let k = CookieKeyring::random();
        let ip = ip4(203, 0, 113, 7);
        let now = 1_000_000;
        let mut c = k.issue(ip, now);
        c.mac[0] ^= 0x01; // flip one bit
        assert!(!k.verify(ip, &c, now));
    }
}
