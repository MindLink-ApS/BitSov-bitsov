//! Web service replies (manifest / page response) are bound to the requester's
//! paid request. They must not self-mint a Lightning payment proof.
//!
//! Shape of a reply-bound envelope:
//! - `payment_proof` reuses the request's hash and preimage at `amount_msat = 0`
//! - `references` contains the request's [`MessageId`]
//! - kinds: [`KIND_PAGE_RESPONSE`] or [`KIND_WEB_MANIFEST`] (manifest is request
//!   when paid and unreplied; reply when amount is 0 and references are set)
//!
//! The requester records each paid 500/510 send as an outstanding entry keyed by
//! payment hash. Step 4.5 of the gate accepts a reply only against that entry
//! (peer, expected reply kind, request id, expiry), then consumes it.

use crate::envelope::UkmEnvelope;
use crate::kind::{KIND_PAGE_REQUEST, KIND_PAGE_RESPONSE, KIND_WEB_MANIFEST};
use crate::types::{MessageId, NodeId, PaymentProof};

/// How long a paid web request may be answered (matches gate max age window).
pub const OUTSTANDING_TTL_MS: u64 = 5 * 60 * 1000;

/// A paid outbound page/manifest request awaiting its bound reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutstandingWebRequest {
    pub request_id: MessageId,
    pub peer: NodeId,
    /// [`KIND_PAGE_RESPONSE`] or [`KIND_WEB_MANIFEST`].
    pub expected_reply_kind: u16,
    pub expires_at_ms: u64,
}

/// Expected reply kind for an outbound paid web request, if any.
pub fn expected_reply_kind(request_kind: u16) -> Option<u16> {
    match request_kind {
        KIND_PAGE_REQUEST => Some(KIND_PAGE_RESPONSE),
        KIND_WEB_MANIFEST => Some(KIND_WEB_MANIFEST),
        _ => None,
    }
}

/// Build the payment proof for a web service reply bound to `request_proof`.
///
/// Copies the requester's settled hash/preimage and sets amount to zero so the
/// reply is not a new Lightning payment and never calls `generate_valid_proof`.
pub fn reply_bound_proof(request_proof: &PaymentProof) -> PaymentProof {
    PaymentProof::new(
        request_proof.payment_hash,
        request_proof.preimage,
        0,
    )
}

/// True when this envelope is shaped as a web service reply bound to a paid request.
pub fn is_web_service_reply(envelope: &UkmEnvelope) -> bool {
    matches!(
        envelope.kind,
        KIND_PAGE_RESPONSE | KIND_WEB_MANIFEST
    ) && envelope.payment_proof.amount_msat == 0
        && !envelope.references.is_empty()
}

/// Whether `envelope` matches an outstanding paid request entry.
pub fn reply_matches_outstanding(
    envelope: &UkmEnvelope,
    outstanding: &OutstandingWebRequest,
    now_ms: u64,
) -> bool {
    if now_ms > outstanding.expires_at_ms {
        return false;
    }
    if envelope.sender != outstanding.peer {
        return false;
    }
    if envelope.kind != outstanding.expected_reply_kind {
        return false;
    }
    envelope.references.contains(&outstanding.request_id)
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::envelope::UkmEnvelopeBuilder;
    use crate::types::Recipient;

    fn proof(amount: u64) -> PaymentProof {
        let preimage = [7u8; 32];
        let hash: [u8; 32] = Sha256::digest(preimage).into();
        PaymentProof::new(hash, preimage, amount)
    }

    #[test]
    fn reply_bound_proof_reuses_hash_at_zero_amount() {
        let req = proof(50);
        let reply = reply_bound_proof(&req);
        assert_eq!(reply.payment_hash, req.payment_hash);
        assert_eq!(reply.preimage, req.preimage);
        assert_eq!(reply.amount_msat, 0);
        reply.verify_preimage().unwrap();
    }

    #[test]
    fn is_web_service_reply_requires_zero_amount_and_references() {
        let sender = NodeId::from_bytes([1u8; 32]);
        let peer = NodeId::from_bytes([2u8; 32]);
        let request = UkmEnvelopeBuilder::new(
            KIND_PAGE_REQUEST,
            sender,
            Recipient::Node(peer),
            b"req".to_vec(),
            proof(50),
        )
        .build();

        let mut reply = UkmEnvelopeBuilder::new(
            KIND_PAGE_RESPONSE,
            peer,
            Recipient::Node(sender),
            b"page".to_vec(),
            reply_bound_proof(&request.payment_proof),
        )
        .references(vec![request.id])
        .build();
        assert!(is_web_service_reply(&reply));

        reply.references.clear();
        assert!(!is_web_service_reply(&reply));

        reply.references.push(request.id);
        reply.payment_proof.amount_msat = 50;
        assert!(!is_web_service_reply(&reply));
    }

    #[test]
    fn reply_matches_outstanding_requires_peer_kind_id_and_window() {
        let peer = NodeId::from_bytes([2u8; 32]);
        let other = NodeId::from_bytes([3u8; 32]);
        let request_id = MessageId::from_bytes([9u8; 32]);
        let outstanding = OutstandingWebRequest {
            request_id,
            peer,
            expected_reply_kind: KIND_PAGE_RESPONSE,
            expires_at_ms: 1_000,
        };
        let reply = UkmEnvelopeBuilder::new(
            KIND_PAGE_RESPONSE,
            peer,
            Recipient::Node(NodeId::from_bytes([1u8; 32])),
            b"page".to_vec(),
            reply_bound_proof(&proof(50)),
        )
        .references(vec![request_id])
        .build();
        assert!(reply_matches_outstanding(&reply, &outstanding, 500));
        assert!(!reply_matches_outstanding(&reply, &outstanding, 1_001));
        let mut wrong_peer = reply.clone();
        wrong_peer.sender = other;
        assert!(!reply_matches_outstanding(&wrong_peer, &outstanding, 500));
    }
}
