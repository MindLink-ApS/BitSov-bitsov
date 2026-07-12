//! RV-RESTORE-wire (#208) — the REAL recovery seam Codex asked for: after a
//! whitelist backup is restored onto fresh storage, a *paid message from a
//! pre-kill invite-onboarded peer* must be ACCEPTED by the payment gate.
//!
//! The half-restore failure mode (memory `project_scb_restore_scope`) is silent:
//! if a backup carried peers but not accepted invites — or restore wrote neither
//! into the live whitelist — the gate would reject every invite-onboarded peer
//! with `NotWhitelisted` after a mnemonic+SCB recovery. These tests drive the
//! true seam end to end: `WhitelistBackup::collect → seal → open → restore_into`
//! into a fresh `SqliteStorage`, then `PaymentGate::verify` against the whitelist
//! rebuilt from the restored peers — not just a `restore_into` row count.

use std::collections::HashSet;
use std::sync::Arc;

use konsensus_core::gate::{GateRejection, PaymentGate};
use konsensus_core::identity::NodeIdentity;
use konsensus_core::kind::{KindCategory, KIND_CHAT};
use konsensus_core::traits::pricing::{PricingEngine, PricingError};
use konsensus_core::types::{NodeId, PaymentProof, Recipient, Signature};
use konsensus_core::UkmEnvelope;
use konsensus_core::UkmEnvelopeBuilder;
use konsensus_storage::{
    AcceptedInviteRecord, Peer, SqliteStorage, Storage, StorageNonceAdapter, WhitelistBackup,
};

/// A pricing engine that prices every kind at 1 msat, so a 100-msat proof
/// always covers it — the gate's price floor is not what these tests exercise.
struct FlatPricing;

#[async_trait::async_trait]
impl PricingEngine for FlatPricing {
    async fn get_price_msat(&self, _kind: u16) -> Result<u64, PricingError> {
        Ok(1)
    }
    async fn get_category_price_msat(&self, _c: KindCategory) -> Result<u64, PricingError> {
        Ok(1)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Build a valid, freshly-timestamped, properly-signed paid envelope from
/// `sender`. `tag` varies the ciphertext so each envelope has a distinct id and
/// nonce (no cross-test replay coupling).
fn signed_envelope(sender: &NodeIdentity, recipient: NodeId, tag: &[u8]) -> UkmEnvelope {
    let preimage = [42u8; 32];
    let hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(preimage).into()
    };
    let proof = PaymentProof::new(hash, preimage, 100);
    let mut env = UkmEnvelopeBuilder::new(
        KIND_CHAT,
        *sender.node_id(),
        Recipient::Node(recipient),
        tag.to_vec(),
        proof,
    )
    .build();
    let sig = sender.sign(&env.signable_bytes());
    env.signature = Signature::from_ed25519(&sig);
    env
}

fn ident(mnemonic: &str) -> NodeIdentity {
    NodeIdentity::from_mnemonic(mnemonic, "").expect("valid test mnemonic")
}

const PEER_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SELF_MNEMONIC: &str = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
const STRANGER_MNEMONIC: &str =
    "legal winner thank year wave sausage worth useful legal winner thank yellow";

#[tokio::test]
async fn restored_invite_peer_is_accepted_by_gate() {
    let peer = ident(PEER_MNEMONIC);
    let me = ident(SELF_MNEMONIC);
    let peer_node_id = *peer.node_id();
    // The producer seals with `identity.aes_key()`; reuse the peer's key here for
    // the round trip (any stable 32-byte key works for seal/open symmetry).
    let key = *peer.aes_key();
    let now_unix = 1_700_000_000u64;

    // SOURCE node: an invite-onboarded peer — a `peers` row (the gate whitelist)
    // AND an `accepted_invites` row (the relationship). Both must survive restore.
    let source = SqliteStorage::in_memory().await.unwrap();
    let mut peer_row = Peer::new(peer_node_id);
    peer_row.address = Some("203.0.113.7:9735".into());
    source.upsert_peer(&peer_row).await.unwrap();
    source
        .add_accepted_invite(&AcceptedInviteRecord {
            nonce: [5u8; 16],
            inviter_pubkey: [9u8; 32],
            expiry_unix: 1_900_000_000,
            accepted_at: 1_699_000_000,
        })
        .await
        .unwrap();

    // BACKUP → seal → (node dies) → open → restore into FRESH storage.
    let backup = WhitelistBackup::collect(&source, now_unix).await.unwrap();
    let sealed = backup.seal(&key).unwrap();

    let fresh = SqliteStorage::in_memory().await.unwrap();
    let restored = WhitelistBackup::open(&sealed, &key)
        .unwrap()
        .restore_into(&fresh)
        .await
        .unwrap();
    assert_eq!(restored, 1, "exactly one peer should be restored");

    // No half-restore: peer (whitelist) AND the accepted invite (relationship).
    let restored_peers = fresh.list_peers().await.unwrap();
    assert!(
        restored_peers.iter().any(|p| p.node_id == peer_node_id),
        "restored whitelist must contain the invite-onboarded peer"
    );
    assert_eq!(
        fresh
            .list_active_accepted_invites(now_unix)
            .await
            .unwrap()
            .len(),
        1,
        "the accepted invite must restore too — a half-restore breaks recovery"
    );

    // REAL SEAM: the payment gate accepts a paid message from the restored peer,
    // using the whitelist rebuilt from the restored `peers` rows.
    let whitelist: HashSet<NodeId> = restored_peers.iter().map(|p| p.node_id).collect();
    let gate = PaymentGate::new();
    let nonce_store = StorageNonceAdapter::new(Arc::new(fresh) as Arc<dyn Storage>);
    let pricing = FlatPricing;

    let env = signed_envelope(&peer, *me.node_id(), b"hello-after-restore");
    let result = gate
        .verify(&env, &nonce_store, &pricing, Some(&whitelist), None, 0.0, None)
        .await;
    assert!(
        result.is_ok(),
        "gate must ACCEPT a paid message from the restored invite-onboarded peer: {result:?}"
    );

    // Negative control: a peer absent from the restored whitelist is rejected —
    // proves the acceptance above is the restore's doing, not an open gate.
    let stranger = ident(STRANGER_MNEMONIC);
    let stranger_env = signed_envelope(&stranger, *me.node_id(), b"stranger-knock");
    let stranger_result = gate
        .verify(
            &stranger_env,
            &nonce_store,
            &pricing,
            Some(&whitelist),
            None,
            0.0,
            None,
        )
        .await;
    assert!(
        matches!(stranger_result, Err(GateRejection::NotWhitelisted(_))),
        "a peer absent from the restored whitelist must be rejected: {stranger_result:?}"
    );
}
