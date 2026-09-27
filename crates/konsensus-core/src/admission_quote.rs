//! First-contact payment preparation: only chat, a short-lived attempt bound
//! to both endpoints, and no application admission authority in the quote.
use crate::types::NodeId;
pub const EXPIRY_SECS: u32 = 60;
pub const PURPOSE: &str = "konsensus:admission:0";
pub fn request_id(recipient: &NodeId, sender: &NodeId, now: u64) -> String {
    format!(
        "v1:{recipient}:{sender}:{now}:{}",
        uuid::Uuid::new_v4().simple()
    )
}
/// Reject malformed, cross-recipient, cross-sender, expired and future attempts.
/// The signed invoice description echoes the entire request ID.
pub fn expires_at(id: &str, recipient: &NodeId, sender: &NodeId, now: u64) -> Option<u64> {
    if id.len() > 190 {
        return None;
    }
    let prefix = format!("v1:{recipient}:{sender}:");
    let rest = id.strip_prefix(&prefix)?;
    let (issued, nonce) = rest.split_once(':')?;
    if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let issued: u64 = issued.parse().ok()?;
    let expiry = issued.checked_add(u64::from(EXPIRY_SECS))?;
    (issued <= now && now < expiry).then_some(expiry)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attempt_cannot_be_rebound_or_used_after_expiry() {
        let a = NodeId::from_bytes([1; 32]);
        let b = NodeId::from_bytes([2; 32]);
        let c = NodeId::from_bytes([3; 32]);
        let id = request_id(&b, &a, 100);
        assert_eq!(expires_at(&id, &b, &a, 100), Some(160));
        assert_eq!(expires_at(&id, &b, &a, 159), Some(160));
        assert_eq!(expires_at(&id, &b, &a, 160), None);
        assert_eq!(expires_at(&id, &b, &a, 99), None);
        assert_eq!(expires_at(&id, &c, &a, 100), None);
        assert_eq!(expires_at(&id, &b, &c, 100), None);
        assert_eq!(expires_at(&"x".repeat(1000), &b, &a, 100), None);
    }
}
