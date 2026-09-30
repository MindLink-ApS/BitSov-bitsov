//! Minimal STUN binding responder for calls across NAT (`[calls] stun_listen`).
//!
//! RFC 5389 binding request → binding success response with
//! XOR-MAPPED-ADDRESS, and nothing else: no TURN, no relay, no
//! authentication, no per-call state. It only reflects the source address of
//! the request, which the caller already knows is theirs, so the app can find
//! its public address without asking a third-party server.
//!
//! Hardening, since a UDP reflector can be abused with spoofed sources:
//! - Off by default; only the owner opens the socket.
//! - The response is at most 44 bytes and never larger than 2.2× the smallest
//!   request (20 bytes), so it is a poor amplifier.
//! - Anything that is not a well-formed binding request is dropped silently:
//!   no error responses at all (RFC 5389 §7.3.1 would answer 420 to unknown
//!   comprehension-required attributes; we drop instead, so malformed or
//!   foreign traffic never produces a packet).
//! - Responses are rate-limited per source (IPv4 address, IPv6 /64) and in
//!   total. The limiter's table is bounded and forgets a source after one
//!   window; a full table refuses new sources (fail closed).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tracing::{debug, info};

/// RFC 5389 §6 magic cookie.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const FINGERPRINT: u16 = 0x8028;
const FINGERPRINT_XOR: u32 = 0x5354_554E;
const HEADER_LEN: usize = 20;
/// Largest request we read (RFC 5389 §7.1: 548 bytes fits any path MTU).
pub const MAX_REQUEST_LEN: usize = 548;

/// The transaction id of a well-formed binding request, or `None` for anything
/// else (which gets no answer).
///
/// Accepted: a 20-byte header with the two top bits zero, method Binding,
/// class Request, the magic cookie, a length that matches the datagram and is a
/// multiple of 4, and attributes that are well-formed TLVs. Only
/// comprehension-optional attributes (type ≥ 0x8000, e.g. SOFTWARE) are
/// allowed; a FINGERPRINT, if present, must be last and correct.
pub fn parse_binding_request(buf: &[u8]) -> Option<[u8; 12]> {
    if buf.len() < HEADER_LEN || buf.len() > MAX_REQUEST_LEN {
        return None;
    }
    let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
    if msg_type != BINDING_REQUEST {
        // Also rejects the two leading bits (0b00) of every STUN message.
        return None;
    }
    let msg_len = usize::from(u16::from_be_bytes([buf[2], buf[3]]));
    if msg_len % 4 != 0 || HEADER_LEN + msg_len != buf.len() {
        return None;
    }
    if u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) != MAGIC_COOKIE {
        return None;
    }
    let mut at = HEADER_LEN;
    while at < buf.len() {
        if buf.len() - at < 4 {
            return None;
        }
        let attr_type = u16::from_be_bytes([buf[at], buf[at + 1]]);
        let attr_len = usize::from(u16::from_be_bytes([buf[at + 2], buf[at + 3]]));
        let padded = attr_len.checked_add(3)? & !3;
        let value = at + 4;
        if buf.len() - value < padded {
            return None;
        }
        if attr_type < 0x8000 {
            // Comprehension-required: we understand none (USERNAME, PRIORITY,
            // MESSAGE-INTEGRITY... belong to authenticated or ICE checks).
            return None;
        }
        if attr_type == FINGERPRINT {
            if attr_len != 4 || value + 4 != buf.len() {
                return None;
            }
            let want = u32::from_be_bytes([buf[value], buf[value + 1], buf[value + 2], buf[value + 3]]);
            if crc32(&buf[..at]) ^ FINGERPRINT_XOR != want {
                return None;
            }
        }
        at = value + padded;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..HEADER_LEN]);
    Some(txid)
}

/// The binding success response telling `source` its own address.
///
/// IPv4-mapped IPv6 sources (a dual-stack socket) are answered as IPv4.
pub fn binding_success(txid: &[u8; 12], source: SocketAddr) -> Vec<u8> {
    let ip = source.ip().to_canonical();
    let port = source.port() ^ (MAGIC_COOKIE >> 16) as u16;
    let (family, addr): (u8, Vec<u8>) = match ip {
        IpAddr::V4(v4) => (0x01, (u32::from(v4) ^ MAGIC_COOKIE).to_be_bytes().to_vec()),
        IpAddr::V6(v6) => {
            let mut key = [0u8; 16];
            key[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            key[4..].copy_from_slice(txid);
            (0x02, v6.octets().iter().zip(key).map(|(a, k)| a ^ k).collect())
        }
    };
    let attr_len = 4 + addr.len();
    let mut out = Vec::with_capacity(HEADER_LEN + 4 + attr_len);
    out.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    out.extend_from_slice(&((4 + attr_len) as u16).to_be_bytes());
    out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(txid);
    out.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&(attr_len as u16).to_be_bytes());
    out.push(0);
    out.push(family);
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(&addr);
    out
}

/// CRC-32 (ISO-HDLC), as FINGERPRINT uses (RFC 5389 §15.5).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Rate limits for the responder.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Answers per source (IPv4 address or IPv6 /64) per window.
    pub per_source: u32,
    /// Answers in total per window.
    pub total: u32,
    /// Window length.
    pub window: Duration,
    /// Sources remembered at once; a full table refuses new sources.
    pub max_sources: usize,
}

impl Default for Limits {
    /// A call gathers candidates with a handful of requests (plus
    /// retransmissions); 20 per 10 s per source leaves room for a few calls.
    fn default() -> Self {
        Self { per_source: 20, total: 2_000, window: Duration::from_secs(10), max_sources: 16_384 }
    }
}

/// Fixed-window counters per source and in total. Bounded; a source is
/// forgotten once its window has passed.
#[derive(Debug)]
pub struct RateLimiter {
    limits: Limits,
    sources: HashMap<IpAddr, (Instant, u32)>,
    total: (Instant, u32),
    last_prune: Instant,
}

impl RateLimiter {
    pub fn new(limits: Limits, now: Instant) -> Self {
        Self { limits, sources: HashMap::new(), total: (now, 0), last_prune: now }
    }

    /// Whether to answer `ip` now; counts the answer if so.
    pub fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        let window = self.limits.window;
        if now.duration_since(self.total.0) >= window {
            self.total = (now, 0);
        }
        if self.total.1 >= self.limits.total {
            return false;
        }
        let key = source_key(ip);
        if !self.sources.contains_key(&key) && self.sources.len() >= self.limits.max_sources {
            // Prune at most once per window so a flood of new sources cannot
            // make every packet scan the table.
            if now.duration_since(self.last_prune) < window {
                return false;
            }
            self.last_prune = now;
            self.sources.retain(|_, (start, _)| now.duration_since(*start) < window);
            if self.sources.len() >= self.limits.max_sources {
                return false;
            }
        }
        let entry = self.sources.entry(key).or_insert((now, 0));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0);
        }
        if entry.1 >= self.limits.per_source {
            return false;
        }
        entry.1 += 1;
        self.total.1 += 1;
        true
    }

    /// Sources currently remembered.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.sources.len()
    }
}

/// IPv4 by address; IPv6 by /64, since one host usually owns a whole /64.
fn source_key(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            let mut o = v6.octets();
            o[8..].fill(0);
            IpAddr::V6(o.into())
        }
    }
}

/// Bind the responder's UDP socket (`[calls] stun_listen`).
pub async fn bind(addr: SocketAddr) -> std::io::Result<Arc<UdpSocket>> {
    Ok(Arc::new(UdpSocket::bind(addr).await?))
}

/// Answer binding requests on `socket` until shutdown.
pub async fn serve(socket: Arc<UdpSocket>, limits: Limits, mut shutdown_rx: watch::Receiver<bool>) {
    if let Ok(addr) = socket.local_addr() {
        info!(%addr, "[calls] STUN binding responder listening (binding only, no relay)");
    }
    let mut limiter = RateLimiter::new(limits, Instant::now());
    // One byte more than we accept, so an oversized datagram is seen as such.
    let mut buf = [0u8; MAX_REQUEST_LEN + 1];
    loop {
        let (n, source) = tokio::select! {
            r = socket.recv_from(&mut buf) => match r {
                Ok(v) => v,
                Err(e) => {
                    // ICMP errors from earlier sends surface here on some platforms.
                    debug!(error = %e, "stun recv failed");
                    continue;
                }
            },
            _ = shutdown_rx.changed() => return,
        };
        let Some(txid) = parse_binding_request(&buf[..n]) else { continue };
        if !limiter.allow(source.ip(), Instant::now()) {
            continue;
        }
        if let Err(e) = socket.send_to(&binding_success(&txid, source), source).await {
            debug!(error = %e, "stun send failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn request(txid: [u8; 12], attrs: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
        b.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        b.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        b.extend_from_slice(&txid);
        b.extend_from_slice(attrs);
        b
    }

    fn with_fingerprint(mut b: Vec<u8>) -> Vec<u8> {
        let len = u16::from_be_bytes([b[2], b[3]]) + 8;
        b[2..4].copy_from_slice(&len.to_be_bytes());
        let fp = crc32(&b) ^ FINGERPRINT_XOR;
        b.extend_from_slice(&FINGERPRINT.to_be_bytes());
        b.extend_from_slice(&4u16.to_be_bytes());
        b.extend_from_slice(&fp.to_be_bytes());
        b
    }

    const TXID: [u8; 12] = [0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae];

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn bare_binding_request_is_accepted() {
        assert_eq!(parse_binding_request(&request(TXID, &[])), Some(TXID));
    }

    #[test]
    fn software_and_fingerprint_are_accepted() {
        // SOFTWARE "abc" padded to 4.
        let attrs = [0x80, 0x22, 0x00, 0x03, b'a', b'b', b'c', 0x00];
        let req = with_fingerprint(request(TXID, &attrs));
        assert_eq!(parse_binding_request(&req), Some(TXID));
    }

    #[test]
    fn malformed_packets_get_no_answer() {
        let good = request(TXID, &[]);
        // Too short, empty, oversize.
        assert_eq!(parse_binding_request(&[]), None);
        assert_eq!(parse_binding_request(&good[..19]), None);
        let mut big = request(TXID, &vec![0u8; MAX_REQUEST_LEN]);
        let body = (big.len() - 20) as u16;
        big[2..4].copy_from_slice(&body.to_be_bytes());
        assert_eq!(parse_binding_request(&big), None);
        // Wrong cookie (RFC 3489-style request).
        let mut b = good.clone();
        b[4] ^= 0xff;
        assert_eq!(parse_binding_request(&b), None);
        // Leading bits set (e.g. RTP/DTLS on the same port).
        let mut b = good.clone();
        b[0] = 0x80;
        assert_eq!(parse_binding_request(&b), None);
        // Other methods/classes: indication, success response, error, Allocate (TURN).
        for t in [0x0011u16, 0x0101, 0x0111, 0x0003] {
            let mut b = good.clone();
            b[0..2].copy_from_slice(&t.to_be_bytes());
            assert_eq!(parse_binding_request(&b), None, "type {t:#06x}");
        }
        // Length disagrees with the datagram, or is not a multiple of 4.
        let mut b = good.clone();
        b[3] = 4;
        assert_eq!(parse_binding_request(&b), None);
        let mut b = request(TXID, &[0x80, 0x22, 0x00, 0x00]);
        b.push(0);
        b[3] = 5;
        assert_eq!(parse_binding_request(&b), None);
        // Attribute running past the end.
        assert_eq!(parse_binding_request(&request(TXID, &[0x80, 0x22, 0x00, 0x08, 0, 0, 0, 0])), None);
        // Comprehension-required attributes (USERNAME, PRIORITY, MESSAGE-INTEGRITY).
        for t in [0x0006u16, 0x0024, 0x0008] {
            let mut attrs = t.to_be_bytes().to_vec();
            attrs.extend_from_slice(&[0x00, 0x04, 1, 2, 3, 4]);
            assert_eq!(parse_binding_request(&request(TXID, &attrs)), None, "attr {t:#06x}");
        }
        // Bad FINGERPRINT, and FINGERPRINT not last.
        let mut b = with_fingerprint(request(TXID, &[]));
        let last = b.len() - 1;
        b[last] ^= 1;
        assert_eq!(parse_binding_request(&b), None);
        let mut b = with_fingerprint(request(TXID, &[]));
        b.extend_from_slice(&[0x80, 0x22, 0x00, 0x00]);
        let len = u16::from_be_bytes([b[2], b[3]]) + 4;
        b[2..4].copy_from_slice(&len.to_be_bytes());
        assert_eq!(parse_binding_request(&b), None);
    }

    #[test]
    fn rfc5769_ice_check_is_not_answered() {
        // RFC 5769 §2.1: an ICE connectivity check (USERNAME, PRIORITY,
        // MESSAGE-INTEGRITY). That belongs to the peer, not a STUN server.
        let req = [
            0x00, 0x01, 0x00, 0x58, 0x21, 0x12, 0xa4, 0x42, 0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87,
            0xdf, 0xae, 0x80, 0x22, 0x00, 0x10, 0x53, 0x54, 0x55, 0x4e, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6c,
            0x69, 0x65, 0x6e, 0x74, 0x00, 0x24, 0x00, 0x04, 0x6e, 0x00, 0x01, 0xff, 0x80, 0x29, 0x00, 0x08, 0x93, 0x2f,
            0xf9, 0xb1, 0x51, 0x26, 0x3b, 0x36, 0x00, 0x06, 0x00, 0x09, 0x65, 0x76, 0x74, 0x6a, 0x3a, 0x68, 0x36, 0x76,
            0x59, 0x20, 0x20, 0x20, 0x00, 0x08, 0x00, 0x14, 0x9a, 0xea, 0xa7, 0x0c, 0xbf, 0xd8, 0xcb, 0x56, 0x78, 0x1e,
            0xf2, 0xb5, 0xb2, 0xd3, 0xf2, 0x49, 0xc1, 0xb5, 0x71, 0xa2, 0x80, 0x28, 0x00, 0x04, 0xe5, 0x7a, 0x3b, 0xcf,
        ];
        // Transcribed correctly: its FINGERPRINT checks out.
        assert_eq!(crc32(&req[..100]) ^ FINGERPRINT_XOR, 0xe57a_3bcf);
        assert_eq!(parse_binding_request(&req), None);
    }

    #[test]
    fn xor_mapped_address_matches_rfc5769_vectors() {
        // RFC 5769 §2.2: 192.0.2.1:32853 → 0001 a147 e112a643.
        let v4 = binding_success(&TXID, "192.0.2.1:32853".parse().unwrap());
        assert_eq!(&v4[..4], &[0x01, 0x01, 0x00, 0x0c]);
        assert_eq!(&v4[20..], &[0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43]);
        // RFC 5769 §2.3: [2001:db8:1234:5678:11:2233:4455:6677]:32853.
        let v6 = binding_success(&TXID, "[2001:db8:1234:5678:11:2233:4455:6677]:32853".parse().unwrap());
        assert_eq!(&v6[..4], &[0x01, 0x01, 0x00, 0x18]);
        assert_eq!(
            &v6[20..],
            &[
                0x00, 0x20, 0x00, 0x14, 0x00, 0x02, 0xa1, 0x47, 0x01, 0x13, 0xa9, 0xfa, 0xa5, 0xd3, 0xf1, 0x79, 0xbc, 0x25,
                0xf4, 0xb5, 0xbe, 0xd2, 0xb9, 0xd9,
            ]
        );
        assert_eq!(&v6[8..20], &TXID);
        // A dual-stack socket sees IPv4 as ::ffff:a.b.c.d; answer IPv4.
        let mapped = SocketAddr::new(IpAddr::V6(Ipv4Addr::new(192, 0, 2, 1).to_ipv6_mapped()), 32853);
        assert_eq!(binding_success(&TXID, mapped), v4);
    }

    #[test]
    fn response_is_small() {
        let v6 = binding_success(&TXID, SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1));
        assert_eq!(v6.len(), 44);
        assert_eq!(binding_success(&TXID, "1.2.3.4:5".parse().unwrap()).len(), 32);
    }

    fn limits() -> Limits {
        Limits { per_source: 3, total: 5, window: Duration::from_secs(10), max_sources: 2 }
    }

    #[test]
    fn per_source_limit_resets_after_the_window() {
        let t0 = Instant::now();
        let mut l = RateLimiter::new(limits(), t0);
        let a: IpAddr = "10.0.0.1".parse().unwrap();
        assert!((0..3).all(|_| l.allow(a, t0)));
        assert!(!l.allow(a, t0 + Duration::from_secs(9)));
        assert!(l.allow(a, t0 + Duration::from_secs(10)));
    }

    #[test]
    fn total_limit_caps_all_sources() {
        let t0 = Instant::now();
        let mut l = RateLimiter::new(Limits { max_sources: 100, ..limits() }, t0);
        let ips: Vec<IpAddr> = (1..=6).map(|i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i))).collect();
        let answered = ips.iter().filter(|ip| l.allow(**ip, t0)).count();
        assert_eq!(answered, 5);
        assert!(l.allow(ips[5], t0 + Duration::from_secs(10)));
    }

    #[test]
    fn ipv6_is_limited_per_64() {
        let t0 = Instant::now();
        let mut l = RateLimiter::new(limits(), t0);
        let hosts: Vec<IpAddr> = (1..=4).map(|i| format!("2001:db8::{i}").parse().unwrap()).collect();
        assert_eq!(hosts.iter().filter(|ip| l.allow(**ip, t0)).count(), 3);
        assert!(l.allow("2001:db8:0:1::1".parse().unwrap(), t0));
    }

    #[test]
    fn source_table_is_bounded_and_fails_closed() {
        let t0 = Instant::now();
        let mut l = RateLimiter::new(Limits { total: 100, ..limits() }, t0);
        let ip = |i| IpAddr::V4(Ipv4Addr::new(10, 0, 0, i));
        assert!(l.allow(ip(1), t0));
        assert!(l.allow(ip(2), t0));
        // Full: a new source is refused, known ones still count.
        assert!(!l.allow(ip(3), t0));
        assert!(l.allow(ip(1), t0));
        assert_eq!(l.tracked(), 2);
        // After the window the table is pruned and the new source fits.
        assert!(l.allow(ip(3), t0 + Duration::from_secs(10)));
        assert_eq!(l.tracked(), 1);
    }

    async fn roundtrip(client: &UdpSocket, req: &[u8]) -> Option<Vec<u8>> {
        client.send(req).await.unwrap();
        let mut buf = [0u8; 128];
        match tokio::time::timeout(Duration::from_millis(300), client.recv(&mut buf)).await {
            Ok(Ok(n)) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn udp_responder_reflects_the_caller_and_drops_junk_and_floods() {
        let socket = bind("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let server = socket.local_addr().unwrap();
        let (tx, rx) = watch::channel(false);
        let task = tokio::spawn(serve(socket, Limits { per_source: 2, ..Limits::default() }, rx));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.connect(server).await.unwrap();
        let me = client.local_addr().unwrap();

        // Junk first: no answer, and it does not use up the source's budget.
        assert_eq!(roundtrip(&client, b"hello").await, None);
        assert_eq!(roundtrip(&client, &[0u8; 20]).await, None);

        let resp = roundtrip(&client, &request(TXID, &[])).await.expect("answered");
        assert_eq!(resp, binding_success(&TXID, me));
        let mut other = TXID;
        other[0] ^= 1;
        assert!(roundtrip(&client, &request(other, &[])).await.is_some());
        // Third request from the same source in the window: dropped.
        assert_eq!(roundtrip(&client, &request(TXID, &[])).await, None);

        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), task).await.unwrap().unwrap();
    }
}
