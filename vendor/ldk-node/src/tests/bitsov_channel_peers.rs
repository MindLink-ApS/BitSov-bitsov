//! Channel-peer allowlist through the production event handler and open path, without
//! starting a node, network listeners, chain RPC or a funded wallet. Peers exchange real
//! `open_channel` messages in memory.
use super::*;
use crate::config::AnchorChannelsConfig;
use crate::wallet::bump::BumpWallet as LdkWallet;
use lightning::events::EventsProvider;
use lightning::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, Init, MessageSendEvent, SocketAddress};

#[derive(Default)]
struct Log(Mutex<Vec<String>>);
impl crate::logger::LogWriter for Log {
    fn log<'a>(&self, record: crate::logger::LogRecord<'a>) {
        self.0.lock().unwrap().push(record.args.to_string());
    }
}
impl Log {
    fn refused(&self) -> bool {
        self.0.lock().unwrap().iter().any(|line| line.contains("HUB_ONLY_WHILE_LOCKABLE"))
    }
}

fn node(seed: u8, allowlist: Option<Vec<PublicKey>>) -> (tempfile::TempDir, crate::Node, Arc<Log>) {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(Log::default());
    let mut builder = crate::Builder::from_config(crate::Config {
        channel_peer_allowlist: allowlist,
        // No on-chain reserve, so an unfunded node's decision rests on the allowlist alone.
        anchor_channels_config: Some(AnchorChannelsConfig { per_channel_reserve_sats: 0, ..Default::default() }),
        ..Default::default()
    });
    builder.set_custom_logger(log.clone());
    builder.set_network(bitcoin::Network::Regtest);
    builder.set_entropy_seed_bytes([seed; 64]);
    builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
    let node = builder.build_with_fs_store().unwrap();
    (dir, node, log)
}

fn handler(node: &crate::Node) -> EventHandler<Arc<Logger>> {
    EventHandler::new(
        node.event_queue.clone(), node.wallet.clone(),
        Arc::new(BumpTransactionEventHandler::new(node.tx_broadcaster.clone(),
            Arc::new(LdkWallet::new(node.wallet.clone(), node.logger.clone())),
            node.keys_manager.clone(), node.logger.clone())),
        node.channel_manager.clone(), node.connection_manager.clone(), node.output_sweeper.clone(),
        node.network_graph.clone(), None, node.payment_store.clone(), node.peer_store.clone(),
        None, node.onion_messenger.clone(), None, node.runtime.clone(), node.logger.clone(), node.config.clone(),
    )
}

/// `opener` proposes a channel; `home` handles the resulting request. Returns its temporary id.
async fn propose(opener: &crate::Node, home: &crate::Node) -> ChannelId {
    let init = |n: &crate::Node| Init {
        features: n.channel_manager.init_features(), networks: None, remote_network_address: None,
    };
    opener.channel_manager.peer_connected(home.node_id(), &init(home), false).unwrap();
    home.channel_manager.peer_connected(opener.node_id(), &init(opener), true).unwrap();
    opener.channel_manager.create_channel(home.node_id(), 100_000, 0, 7, None, None).unwrap();
    let msg = opener.channel_manager.get_and_clear_pending_msg_events().into_iter()
        .find_map(|event| match event { MessageSendEvent::SendOpenChannel { msg, .. } => Some(msg), _ => None })
        .expect("open_channel message");
    home.channel_manager.handle_open_channel(opener.node_id(), &msg);
    let events = Mutex::new(Vec::new());
    home.channel_manager.process_pending_events(&|event: LdkEvent| -> Result<(), ReplayEvent> {
        events.lock().unwrap().push(event);
        Ok(())
    });
    let events = events.into_inner().unwrap();
    assert!(matches!(events.as_slice(), [LdkEvent::OpenChannelRequest { .. }]), "{events:?}");
    let handler = handler(home);
    for event in events {
        handler.handle_event(event).await.unwrap();
    }
    msg.common_fields.temporary_channel_id
}

fn has_channel_with(home: &crate::Node, peer: &crate::Node) -> bool {
    home.channel_manager.list_channels().iter().any(|c| c.counterparty.node_id == peer.node_id())
}

#[tokio::test]
async fn allowlist_accepts_hub_and_refuses_other_inbound_requests() {
    let (_hub_dir, hub, _) = node(61, None);
    let (_stranger_dir, stranger, _) = node(62, None);
    let (_home_dir, home, log) = node(63, Some(vec![hub.node_id()]));

    propose(&hub, &home).await;
    assert!(has_channel_with(&home, &hub), "listed hub request must be accepted");
    assert!(!log.refused());

    let refused = propose(&stranger, &home).await;
    assert!(log.refused());
    assert!(!has_channel_with(&home, &stranger));
    // Rejected outright, not left waiting for a later accept.
    assert!(home.channel_manager.accept_inbound_channel(&refused, &stranger.node_id(), 8, None).is_err());
}

#[tokio::test]
async fn without_allowlist_inbound_acceptance_is_unchanged() {
    let (_stranger_dir, stranger, _) = node(62, None);
    let (_home_dir, home, log) = node(63, None);
    propose(&stranger, &home).await;
    assert!(has_channel_with(&home, &stranger));
    assert!(!log.refused());
}

#[tokio::test]
async fn allowlist_refuses_unlisted_outbound_opens_before_connecting() {
    let (_hub_dir, hub, _) = node(61, None);
    let (_stranger_dir, stranger, _) = node(62, None);
    let (_home_dir, home, log) = node(63, Some(vec![hub.node_id()]));
    let addr: SocketAddress = "127.0.0.1:9".parse().unwrap();
    for result in [
        home.open_channel(stranger.node_id(), addr.clone(), 100_000, None, None),
        home.open_channel_with_funding_policy(stranger.node_id(), addr.clone(), 100_000, false,
            crate::funding::FundingPolicy::new(crate::funding::FundingPriority::Normal,
                bitcoin::FeeRate::from_sat_per_kwu(1_000), None).unwrap()),
    ] {
        assert!(matches!(result, Err(crate::Error::ChannelCreationFailed)), "{result:?}");
    }
    assert!(log.refused());
    // A listed hub, or any peer without an allowlist, reaches the unchanged checks
    // (this node is not running).
    let (_free_dir, unrestricted, free_log) = node(64, None);
    for result in [
        home.open_channel(hub.node_id(), addr.clone(), 100_000, None, None),
        unrestricted.open_channel(stranger.node_id(), addr, 100_000, None, None),
    ] {
        assert!(matches!(result, Err(crate::Error::NotRunning)), "{result:?}");
    }
    assert!(!free_log.refused());
}
