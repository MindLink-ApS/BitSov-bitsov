use super::*;
use crate::relay::store::{InMemoryRelayStore, RelayBindingStore};
use crate::relay::{DepositReject, RegisterReject, RelayPolicy};
use std::sync::Arc;

fn node(b: u8) -> NodeId {
    NodeId::from_bytes([b; 32])
}

fn mid(b: u8) -> konsensus_core::types::MessageId {
    konsensus_core::types::MessageId::from_bytes([b; 32])
}

fn policy() -> RelayPolicy {
    RelayPolicy {
        max_ttl_secs: 86_400,
        max_quota_bytes: 1_000_000,
        max_bindings: 2,
        min_msat_per_byte_day: 1,
        allowed_kinds: vec![0, 1, 200],
        max_drain_batch: 64,
        max_bytes_per_depositor: 4 * 1024 * 1024,
    }
}

/// Build an engine plus the concrete store (so tests can read held state). The
/// relay engine holds no Lightning backend under D1 — settlement is the message
/// gate's job, verified before dispatch.
fn setup() -> (RelayEngine, Arc<InMemoryRelayStore>) {
    let store = Arc::new(InMemoryRelayStore::new());
    let eng = RelayEngine::new(store.clone(), policy());
    (eng, store)
}

async fn register_recipient(eng: &RelayEngine, r: NodeId, root: [u8; 32], now: Instant) {
    eng.handle_register(r, [0u8; 16], 100_000, 3600, root, 1, now)
        .await
        .expect("register ok");
}

#[tokio::test]
async fn register_then_global_cap_and_cooldown() {
    let (eng, _store) = setup();
    let t0 = Instant::now();

    // One recipient registers (count 0 -> 1, below the cap of 2).
    register_recipient(&eng, node(1), [0u8; 32], t0).await;

    // A rapid re-register by that peer is cooldown-limited (FINDING 1). This is
    // checked while still below the global cap, so the cooldown — not the cap —
    // is what fires (the cap is checked first in register_allowed).
    assert_eq!(
        eng.handle_register(
            node(1),
            [0u8; 16],
            100_000,
            3600,
            [0u8; 32],
            1,
            t0 + std::time::Duration::from_secs(1)
        )
        .await,
        Err(RelayOpError::Register(RegisterReject::RateLimited))
    );

    // A second distinct recipient registers (count -> 2, at the cap).
    register_recipient(&eng, node(2), [0u8; 32], t0).await;
    assert_eq!(eng.binding_count().await, 2);

    // A third distinct recipient now hits the global binding cap.
    assert_eq!(
        eng.handle_register(node(3), [0u8; 16], 100_000, 3600, [0u8; 32], 1, t0)
            .await,
        Err(RelayOpError::Register(RegisterReject::GlobalCapReached))
    );
}

#[tokio::test]
async fn unregister_removes_binding_and_frees_slot() {
    let (eng, _store) = setup();
    let t0 = Instant::now();
    register_recipient(&eng, node(1), [0u8; 32], t0).await;
    assert_eq!(eng.binding_count().await, 1);

    // Revoke → slot freed.
    eng.handle_unregister(node(1)).await.expect("revoke ok");
    assert_eq!(eng.binding_count().await, 0);

    // Revoking a non-existent binding surfaces the store error (never silent).
    assert!(matches!(
        eng.handle_unregister(node(1)).await,
        Err(RelayOpError::Store(_))
    ));
}

#[tokio::test]
async fn deposit_without_binding_is_rejected() {
    let (eng, _store) = setup();
    // No register for the recipient.
    assert_eq!(
        eng.handle_deposit(
            node(5),
            node(1),
            mid(0),
            vec![0xAB; 500],
            0,
            3600,
            DepositAuth::GateSettled {
                amount_msat: 100_000,
                payment_hash: [0u8; 32],
            },
            42,
        )
        .await,
        Err(RelayOpError::Deposit(DepositReject::NoBinding))
    );
}

#[tokio::test]
async fn deposit_below_floor_is_rejected() {
    let (eng, _store) = setup();
    let t0 = Instant::now();
    let recipient = node(1);
    register_recipient(&eng, recipient, [0u8; 32], t0).await;

    // floor(size=500, ttl=3600, rate=1) = 21 msat; a gate-folded 20 msat is short.
    assert_eq!(
        eng.handle_deposit(
            node(5),
            recipient,
            mid(0),
            vec![0xAB; 500],
            0,
            3600,
            DepositAuth::GateSettled {
                amount_msat: 20,
                payment_hash: [0u8; 32],
            },
            42,
        )
        .await,
        Err(RelayOpError::Deposit(DepositReject::StorageFloorNotMet))
    );
}

#[tokio::test]
async fn drain_returns_only_own_held_in_sequence_order_then_ack_deletes() {
    let (eng, _store) = setup();
    let t0 = Instant::now();
    let recipient = node(1);
    let depositor = node(5);
    register_recipient(&eng, recipient, [0u8; 32], t0).await;

    // Two gate-folded deposits for the recipient, each held under its own MessageId.
    for (amount, body, id) in [(100_000u64, 0xA1u8, mid(1)), (100_000, 0xB2, mid(2))] {
        eng.handle_deposit(
            depositor,
            recipient,
            id,
            vec![body; 100],
            0,
            3600,
            DepositAuth::GateSettled {
                amount_msat: amount,
                payment_hash: [0u8; 32],
            },
            1,
        )
        .await
        .unwrap();
    }

    // Drain returns both, oldest-first (sequence 0 then 1), each carrying its id.
    let drained = eng.handle_drain_request(recipient, 10, 2).await;
    assert_eq!(drained.len(), 2);
    assert_eq!(drained[0].sequence, 0);
    assert_eq!(drained[1].sequence, 1);
    assert_eq!(drained[0].message_id, mid(1));
    assert_eq!(drained[0].envelope_bytes, vec![0xA1; 100]);

    // A different peer drains nothing — the store is keyed by recipient, so a
    // peer can only ever fetch its OWN held mail.
    assert!(eng.handle_drain_request(node(9), 10, 2).await.is_empty());

    // Ack mid(1) → one deleted; the second remains; idempotent re-ack → 0.
    assert_eq!(eng.handle_ack(recipient, &[mid(1)]).await.unwrap(), 1);
    assert_eq!(eng.handle_drain_request(recipient, 10, 2).await.len(), 1);
    assert_eq!(eng.handle_ack(recipient, &[mid(1)]).await.unwrap(), 0);

    // Ack on an unknown recipient surfaces the store error.
    assert!(matches!(
        eng.handle_ack(node(9), &[mid(1)]).await,
        Err(RelayOpError::Store(_))
    ));
}

#[tokio::test]
async fn whitelisted_deposit_with_valid_proof_is_held() {
    let (eng, store) = setup();
    let t0 = Instant::now();
    let recipient = node(1);
    let depositor = node(5);

    // 2-leaf whitelist tree [depositor, sibling]; root anchors the binding.
    let sibling: [u8; 32] = blake3::hash(node(6).as_bytes()).into();
    let d_leaf: [u8; 32] = blake3::hash(depositor.as_bytes()).into();
    let root: [u8; 32] = {
        let mut h = blake3::Hasher::new();
        if d_leaf <= sibling {
            h.update(&d_leaf);
            h.update(&sibling);
        } else {
            h.update(&sibling);
            h.update(&d_leaf);
        }
        h.finalize().into()
    };
    register_recipient(&eng, recipient, root, t0).await;

    let seq = eng
        .handle_deposit(
            depositor,
            recipient,
            mid(0),
            vec![0xCD; 300],
            0,
            3600,
            DepositAuth::Whitelisted {
                merkle_path: vec![sibling],
                whitelist_root: root,
            },
            7,
        )
        .await
        .expect("valid whitelisted deposit is held");
    assert_eq!(seq, 0);
    assert_eq!(store.list_held(&recipient, 10, 8).await.len(), 1);
}
