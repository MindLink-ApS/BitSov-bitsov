use std::sync::Arc;
use std::time::Duration;

use konsensus_core::identity::NodeIdentity;
use konsensus_core::traits::transport::MessageTransport;
use konsensus_core::types::NodeId;
use konsensus_message::wire::{Capability, SovereigntyTier};
use konsensus_message::{NoiseTransport, TransportConfig};
use konsensus_storage::sqlite::SqliteStorage;
use konsensus_storage::traits::Storage;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon abandon \
     abandon abandon abandon abandon abandon abandon abandon art";

fn make_identity(passphrase: &str) -> Arc<NodeIdentity> {
    Arc::new(NodeIdentity::from_mnemonic(MNEMONIC, passphrase).unwrap())
}

fn make_config(whitelist: Vec<NodeId>) -> TransportConfig {
    TransportConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        tier: SovereigntyTier::T1,
        capabilities: vec![Capability::X3dh],
        whitelist,
        version: 2,
    }
}

#[tokio::test]
async fn handshake_gate_with_invite_ref_invitee_initiated_connection_is_accepted() {
    let inviter = make_identity("inviter-onb4c");
    let invitee = make_identity("invitee-onb4c");

    let inviter_id = *inviter.node_id();
    let invitee_id = *invitee.node_id();

    let storage = SqliteStorage::in_memory()
        .await
        .expect("create sqlite storage");
    let invite_id = uuid::Uuid::new_v4();
    storage
        .add_whitelisted_peer_with_invite_ref(*invitee_id.as_bytes(), invite_id)
        .await
        .expect("persist invite-derived whitelist entry");

    // Build inviter whitelist strictly from storage state populated by
    // add_whitelisted_peer_with_invite_ref.
    let inviter_whitelist: Vec<NodeId> = storage
        .list_peers()
        .await
        .expect("list peers")
        .into_iter()
        .map(|p| p.node_id)
        .collect();
    assert_eq!(inviter_whitelist, vec![invitee_id]);

    let transport_inviter = Arc::new(NoiseTransport::new(
        Arc::clone(&inviter),
        make_config(inviter_whitelist),
    ));
    transport_inviter
        .start_listener()
        .await
        .expect("inviter listener bind");
    let inviter_addr = transport_inviter
        .listen_addr()
        .expect("inviter listen addr present");

    let transport_invitee = NoiseTransport::new(
        Arc::clone(&invitee),
        make_config(vec![inviter_id]),
    );

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Invitee comes online and initiates connection. Success means the
    // Noise_XX + federation handshake path accepted the peer.
    transport_invitee
        .connect(&inviter_id, &inviter_addr.to_string())
        .await
        .expect("invitee-initiated handshake should be accepted");

    assert!(
        transport_invitee.is_connected(&inviter_id).await,
        "initiator should report connected after successful handshake"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        transport_inviter.is_connected(&invitee_id).await,
        "responder should register invitee when handshake gate accepts"
    );

    transport_inviter.shutdown();
}
