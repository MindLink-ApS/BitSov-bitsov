use super::*;
use std::time::Duration;

fn node(b: u8) -> NodeId {
    NodeId::from_bytes([b; 32])
}

fn policy() -> RelayPolicy {
    RelayPolicy {
        max_ttl_secs: 86_400,
        max_quota_bytes: 1_000_000,
        max_bindings: 2,
        min_msat_per_byte_day: 1,
        allowed_kinds: vec![0, 1, 200], // chat, longform, file_ref
        max_drain_batch: 64,
        max_bytes_per_depositor: 4 * 1024 * 1024,
    }
}

fn binding(recipient: NodeId, held: u64, root: [u8; 32]) -> RelayBindingView {
    RelayBindingView {
        recipient,
        quota_bytes: 100_000,
        held_bytes: held,
        ttl_max_secs: 3600,
        depositor_whitelist_root: root,
    }
}

/// Build a deposit proof of `amount` msat bound to `depositor` for the
/// `validate_deposit` unit tests. Settlement is the message gate's job (verified
/// before dispatch), so this uses the gate-folded mint directly.
fn verified_prepaid(amount: u64, depositor: NodeId) -> DepositProof {
    DepositProof::Prepaid(VerifiedStoragePayment::from_message_gate(
        [7u8; 32],
        amount,
        depositor,
    ))
}

#[tokio::test]
async fn deposit_prepaid_valid_is_held() {
    let r = node(1);
    let d = node(5);
    let b = binding(r, 0, [0u8; 32]);
    let proof = verified_prepaid(100_000, d);
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &d, &policy()),
        Ok(())
    );
}

#[tokio::test]
async fn deposit_no_binding_rejected() {
    let d = node(5);
    let proof = verified_prepaid(100_000, d);
    assert_eq!(
        validate_deposit(None, &node(1), 0, 500, &proof, 3600, &d, &policy()),
        Err(DepositReject::NoBinding)
    );
}

#[tokio::test]
async fn deposit_recipient_mismatch_rejected() {
    let r = node(1);
    let d = node(5);
    let b = binding(node(2), 0, [0u8; 32]); // binding belongs to a different recipient
    let proof = verified_prepaid(100_000, d);
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &d, &policy()),
        Err(DepositReject::RecipientMismatch)
    );
}

#[tokio::test]
async fn deposit_ttl_too_long_rejected() {
    let r = node(1);
    let d = node(5);
    let b = binding(r, 0, [0u8; 32]); // binding ttl_max 3600
    let proof = verified_prepaid(100_000, d);
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 7200, &d, &policy()),
        Err(DepositReject::TtlTooLong)
    );
}

#[tokio::test]
async fn deposit_ttl_exactly_at_ceiling_is_allowed() {
    // Boundary: ttl == binding.ttl_max_secs (3600) must pass (not "too long").
    let r = node(1);
    let d = node(5);
    let b = binding(r, 0, [0u8; 32]);
    let proof = verified_prepaid(100_000, d);
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &d, &policy()),
        Ok(())
    );
}

#[tokio::test]
async fn deposit_kind_not_allowed_rejected() {
    let r = node(1);
    let d = node(5);
    let b = binding(r, 0, [0u8; 32]);
    let proof = verified_prepaid(100_000, d);
    // kind 401 (call answer, real-time signalling) not in allowed_kinds
    assert_eq!(
        validate_deposit(Some(&b), &r, 401, 500, &proof, 3600, &d, &policy()),
        Err(DepositReject::KindNotAllowed)
    );
}

#[tokio::test]
async fn deposit_quota_exceeded_rejected() {
    let r = node(1);
    let d = node(5);
    let b = binding(r, 99_999, [0u8; 32]); // quota 100_000, already 99_999 held
    let proof = verified_prepaid(100_000, d);
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &d, &policy()),
        Err(DepositReject::QuotaExceeded)
    );
}

#[tokio::test]
async fn deposit_quota_exactly_full_is_allowed() {
    // Boundary: held + size == quota exactly must pass.
    let r = node(1);
    let d = node(5);
    let b = binding(r, 99_500, [0u8; 32]); // quota 100_000, 99_500 held, +500 == 100_000
    let proof = verified_prepaid(100_000, d);
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &d, &policy()),
        Ok(())
    );
}

#[tokio::test]
async fn deposit_quota_overflow_is_safe() {
    // held_bytes near u64::MAX must not wrap into a false "fits".
    let r = node(1);
    let d = node(5);
    let mut b = binding(r, u64::MAX - 10, [0u8; 32]);
    b.quota_bytes = u64::MAX; // policy cap 1_000_000 makes effective quota tiny anyway,
    let proof = verified_prepaid(100_000, d);
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &d, &policy()),
        Err(DepositReject::QuotaExceeded)
    );
}

#[tokio::test]
async fn deposit_prepaid_below_storage_floor_rejected() {
    // floor(size=500, ttl=3600, rate=1) = ceil(500*3600/86400) = 21 msat.
    // A settled payment of 20 msat is below the policy-derived floor.
    let r = node(1);
    let d = node(5);
    let b = binding(r, 0, [0u8; 32]);
    let proof = verified_prepaid(20, d);
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &d, &policy()),
        Err(DepositReject::StorageFloorNotMet)
    );
}

#[tokio::test]
async fn deposit_prepaid_depositor_mismatch_rejected() {
    // A settled payment bound to depositor A cannot be presented by peer B.
    let r = node(1);
    let b = binding(r, 0, [0u8; 32]);
    let proof = verified_prepaid(100_000, node(5)); // bound to node 5
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &node(6), &policy()),
        Err(DepositReject::DepositorMismatch)
    );
}

#[tokio::test]
async fn deposit_whitelisted_valid_inclusion_is_held() {
    // 2-leaf tree [depositor D, sibling S]; root = blake3(sorted(h(D), h(S))).
    let depositor = node(5);
    let sibling_leaf: [u8; 32] = blake3::hash(node(6).as_bytes()).into();
    let d_leaf: [u8; 32] = blake3::hash(depositor.as_bytes()).into();
    let root: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        if d_leaf <= sibling_leaf {
            h.update(&d_leaf);
            h.update(&sibling_leaf);
        } else {
            h.update(&sibling_leaf);
            h.update(&d_leaf);
        }
        h.finalize().into()
    };
    let r = node(1);
    let b = binding(r, 0, root);
    let proof = DepositProof::Whitelisted {
        depositor,
        merkle_path: vec![sibling_leaf],
        whitelist_root: root,
    };
    // authenticated depositor == the proof's depositor.
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &depositor, &policy()),
        Ok(())
    );
}

#[tokio::test]
async fn deposit_whitelisted_stolen_proof_rejected() {
    // A valid Merkle proof for depositor D, presented by peer E, is rejected —
    // sponsorship binds to the authenticated sender (not the proof's claim).
    let depositor = node(5);
    let sibling_leaf: [u8; 32] = blake3::hash(node(6).as_bytes()).into();
    let d_leaf: [u8; 32] = blake3::hash(depositor.as_bytes()).into();
    let root: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        if d_leaf <= sibling_leaf {
            h.update(&d_leaf);
            h.update(&sibling_leaf);
        } else {
            h.update(&sibling_leaf);
            h.update(&d_leaf);
        }
        h.finalize().into()
    };
    let r = node(1);
    let b = binding(r, 0, root);
    let proof = DepositProof::Whitelisted {
        depositor,
        merkle_path: vec![sibling_leaf],
        whitelist_root: root,
    };
    // authenticated sender (node 9) != the proof's depositor (node 5).
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &node(9), &policy()),
        Err(DepositReject::DepositorMismatch)
    );
}

#[tokio::test]
async fn deposit_whitelisted_wrong_root_rejected() {
    let depositor = node(5);
    let r = node(1);
    let b = binding(r, 0, [1u8; 32]); // binding's published root
    let proof = DepositProof::Whitelisted {
        depositor,
        merkle_path: vec![[2u8; 32]],
        whitelist_root: [9u8; 32], // != binding's root
    };
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &depositor, &policy()),
        Err(DepositReject::WhitelistNotProven)
    );
}

#[tokio::test]
async fn finding2_deposit_validation_is_hold_not_message_admission() {
    // FINDING 2: a verified STORAGE prepay authorizes the relay to HOLD; it
    // carries NO sender→recipient message proof. The message gate is re-checked
    // by the recipient at drain — neither consulted nor bypassable here.
    let r = node(1);
    let d = node(5);
    let b = binding(r, 0, [0u8; 32]);
    let proof = verified_prepaid(100_000, d);
    assert_eq!(
        validate_deposit(Some(&b), &r, 0, 500, &proof, 3600, &d, &policy()),
        Ok(())
    );
}

#[tokio::test]
async fn register_rate_limited_and_globally_capped() {
    let mut last = HashMap::new();
    let p = policy(); // max_bindings 2
    let peer = node(3);
    let t0 = Instant::now();

    // First registration (0 existing bindings) allowed.
    assert_eq!(register_allowed(&mut last, 0, &peer, t0, &p), Ok(()));
    // Rapid repeat within the cooldown is rejected (FINDING 1: no register spam).
    assert_eq!(
        register_allowed(&mut last, 1, &peer, t0 + Duration::from_secs(1), &p),
        Err(RegisterReject::RateLimited)
    );
    // A rejected register must NOT have updated the cooldown timestamp: the last
    // allowed time is still t0, so just-after-cooldown is allowed.
    assert_eq!(
        register_allowed(
            &mut last,
            1,
            &peer,
            t0 + RELAY_REGISTER_COOLDOWN + Duration::from_secs(1),
            &p
        ),
        Ok(())
    );
    // Global cap: at max_bindings, ANY peer is refused (bounds total binding state).
    assert_eq!(
        register_allowed(&mut last, 2, &node(99), t0, &p),
        Err(RegisterReject::GlobalCapReached)
    );
}
