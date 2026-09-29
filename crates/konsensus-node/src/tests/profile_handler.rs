use super::*;

fn pair() -> (NodeIdentity, NodeId) {
    let (_, me) = NodeIdentity::generate().unwrap();
    let (_, peer) = NodeIdentity::generate().unwrap();
    (me, *peer.node_id())
}

#[test]
fn real_backend_builds_no_mock_proof_envelope() {
    let (me, peer) = pair();
    assert!(
        profile_envelope(&me, &peer, false).unwrap().is_none(),
        "a non-Mock backend must never emit a mock-proof KIND_PROFILE"
    );
}

#[test]
fn mock_backend_still_sends_profile_with_mock_proof() {
    let (me, peer) = pair();
    let env = profile_envelope(&me, &peer, true).unwrap().expect("mock path unchanged");
    assert_eq!(env.kind, KIND_PROFILE);
    assert_eq!(env.sender, *me.node_id());
    assert_eq!(env.recipient, Recipient::Node(peer));
    assert_eq!(env.payment_proof.amount_msat, PROFILE_PAYMENT_MSAT);
    let preimage = mock_preimage(&env.nonce, me.node_id());
    let hash: [u8; 32] = Sha256::digest(preimage).into();
    assert_eq!(env.payment_proof, PaymentProof::new(hash, preimage, PROFILE_PAYMENT_MSAT));
}
