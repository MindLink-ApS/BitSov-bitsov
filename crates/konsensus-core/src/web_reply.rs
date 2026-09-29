//! Web service replies (manifest / page response) are bound to the requester's
//! paid request. They must not self-mint a Lightning payment proof.
//!
//! Shape of a reply-bound envelope:
//! - `payment_proof` reuses the request's hash and preimage at `amount_msat = 0`
//! - `references` contains the request's [`MessageId`]
//! - kinds: [`KIND_PAGE_RESPONSE`] or [`KIND_WEB_MANIFEST`] (manifest is request
//!   when paid and unreplied; reply when amount is 0 and references are set)

use crate::envelope::UkmEnvelope;
use crate::kind::{KIND_PAGE_RESPONSE, KIND_WEB_MANIFEST};
use crate::types::PaymentProof;

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

/// True when this envelope is a web service reply bound to a paid request.
pub fn is_web_service_reply(envelope: &UkmEnvelope) -> bool {
    matches!(
        envelope.kind,
        KIND_PAGE_RESPONSE | KIND_WEB_MANIFEST
    ) && envelope.payment_proof.amount_msat == 0
        && !envelope.references.is_empty()
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;
    use crate::envelope::UkmEnvelopeBuilder;
    use crate::kind::KIND_PAGE_REQUEST;
    use crate::types::{NodeId, Recipient};

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
}
