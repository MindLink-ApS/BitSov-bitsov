//! Channel-peer allowlist through the production event handler and open path, without
//! starting a node, network listeners, chain RPC or a funded wallet. Peers exchange real
//! `open_channel` messages in memory.
use super::*;
use crate::config::AnchorChannelsConfig;
use crate::wallet::bump::BumpWallet as LdkWallet;
use lightning::events::EventsProvider;
use lightning::ln::msgs::{
	BaseMessageHandler, ChannelMessageHandler, Init, MessageSendEvent, SocketAddress,
};

#[derive(Default)]
struct Log(Mutex<Vec<String>>);
impl crate::logger::LogWriter for Log {
	fn log<'a>(&self, record: crate::logger::LogRecord<'a>) {
		self.0.lock().unwrap().push(record.args.to_string());
	}
}
impl Log {
	fn refused(&self) -> bool {
		self.0
			.lock()
			.unwrap()
			.iter()
			.any(|line| line.contains("HUB_ONLY_WHILE_LOCKABLE"))
	}
}

fn node(seed: u8, allowlist: Option<Vec<PublicKey>>) -> (tempfile::TempDir, crate::Node, Arc<Log>) {
	node_with_limits(seed, allowlist, None)
}

fn node_with_limits(
	seed: u8,
	allowlist: Option<Vec<PublicKey>>,
	limits: Option<crate::channel_limits::ChannelLimits>,
) -> (tempfile::TempDir, crate::Node, Arc<Log>) {
	let dir = tempfile::tempdir().unwrap();
	let log = Arc::new(Log::default());
	let mut builder = crate::Builder::from_config(crate::Config {
		channel_peer_allowlist: allowlist,
		channel_limits: limits,
		// No on-chain reserve, so an unfunded node's decision rests on the allowlist alone.
		anchor_channels_config: Some(AnchorChannelsConfig {
			per_channel_reserve_sats: 0,
			..Default::default()
		}),
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
		node.event_queue.clone(),
		node.wallet.clone(),
		Arc::new(BumpTransactionEventHandler::new(
			node.tx_broadcaster.clone(),
			Arc::new(LdkWallet::new(node.wallet.clone(), node.logger.clone())),
			node.keys_manager.clone(),
			node.logger.clone(),
		)),
		node.channel_manager.clone(),
		node.connection_manager.clone(),
		node.output_sweeper.clone(),
		node.network_graph.clone(),
		None,
		node.payment_store.clone(),
		node.peer_store.clone(),
		None,
		node.onion_messenger.clone(),
		None,
		node.runtime.clone(),
		node.logger.clone(),
		node.config.clone(),
	)
}

/// `opener` proposes a channel; `home` handles the resulting request. Returns its temporary id.
async fn propose(opener: &crate::Node, home: &crate::Node) -> ChannelId {
	propose_amount(opener, home, 100_000).await
}

async fn propose_amount(opener: &crate::Node, home: &crate::Node, amount: u64) -> ChannelId {
	let (id, events) = request_amount(opener, home, amount);
	let handler = handler(home);
	for event in events {
		handler.handle_event(event).await.unwrap();
	}
	id
}

fn request_amount(
	opener: &crate::Node,
	home: &crate::Node,
	amount: u64,
) -> (ChannelId, Vec<LdkEvent>) {
	let init = |n: &crate::Node| Init {
		features: n.channel_manager.init_features(),
		networks: None,
		remote_network_address: None,
	};
	opener
		.channel_manager
		.peer_connected(home.node_id(), &init(home), false)
		.unwrap();
	home.channel_manager
		.peer_connected(opener.node_id(), &init(opener), true)
		.unwrap();
	opener
		.channel_manager
		.create_channel(home.node_id(), amount, 0, 7, None, None)
		.unwrap();
	let msg = opener
		.channel_manager
		.get_and_clear_pending_msg_events()
		.into_iter()
		.find_map(|event| match event {
			MessageSendEvent::SendOpenChannel { msg, .. } => Some(msg),
			_ => None,
		})
		.expect("open_channel message");
	home.channel_manager
		.handle_open_channel(opener.node_id(), &msg);
	let events = Mutex::new(Vec::new());
	home.channel_manager
		.process_pending_events(&|event: LdkEvent| -> Result<(), ReplayEvent> {
			events.lock().unwrap().push(event);
			Ok(())
		});
	let events = events.into_inner().unwrap();
	assert!(
		matches!(events.as_slice(), [LdkEvent::OpenChannelRequest { .. }]),
		"{events:?}"
	);
	(msg.common_fields.temporary_channel_id, events)
}

fn has_channel_with(home: &crate::Node, peer: &crate::Node) -> bool {
	home.channel_manager
		.list_channels()
		.iter()
		.any(|c| c.counterparty.node_id == peer.node_id())
}

#[tokio::test]
async fn allowlist_accepts_hub_and_refuses_other_inbound_requests() {
	let (_hub_dir, hub, _) = node(61, None);
	let (_stranger_dir, stranger, _) = node(62, None);
	let (_home_dir, home, log) = node(63, Some(vec![hub.node_id()]));

	propose(&hub, &home).await;
	assert!(
		has_channel_with(&home, &hub),
		"listed hub request must be accepted"
	);
	assert!(!log.refused());

	let refused = propose(&stranger, &home).await;
	assert!(log.refused());
	assert!(!has_channel_with(&home, &stranger));
	// Rejected outright, not left waiting for a later accept.
	assert!(home
		.channel_manager
		.accept_inbound_channel(&refused, &stranger.node_id(), 8, None)
		.is_err());
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
		home.open_channel_with_funding_policy(
			stranger.node_id(),
			addr.clone(),
			100_000,
			false,
			crate::funding::FundingPolicy::new(
				crate::funding::FundingPriority::Normal,
				bitcoin::FeeRate::from_sat_per_kwu(1_000),
				None,
			)
			.unwrap(),
		),
	] {
		assert!(
			matches!(result, Err(crate::Error::ChannelCreationFailed)),
			"{result:?}"
		);
	}
	assert!(log.refused());
	// A listed hub, or any peer without an allowlist, reaches the unchanged checks
	// (this node is not running).
	let (_free_dir, unrestricted, free_log) = node(64, None);
	for result in [
		home.open_channel(hub.node_id(), addr.clone(), 100_000, None, None),
		unrestricted.open_channel(stranger.node_id(), addr, 100_000, None, None),
	] {
		assert!(
			matches!(result, Err(crate::Error::NotRunning)),
			"{result:?}"
		);
	}
	assert!(!free_log.refused());
}

#[tokio::test]
async fn capacity_edges_count_accepted_unfunded_channels_and_reject_excess() {
	let (_a, a, _) = node(71, None);
	let (_b, b, _) = node(72, None);
	let (_c, c, _) = node(73, None);
	let (_d, home, log) = node_with_limits(
		74,
		None,
		Some(crate::channel_limits::ChannelLimits::new(100_000, 150_000)),
	);
	let rejected = propose_amount(&c, &home, 100_001).await;
	assert!(!has_channel_with(&home, &c));
	assert!(home
		.channel_manager
		.accept_inbound_channel(&rejected, &c.node_id(), 8, None)
		.is_err());
	propose_amount(&a, &home, 100_000).await;
	propose_amount(&b, &home, 50_000).await;
	assert_eq!(home.channel_manager.list_channels().len(), 2);
	let (_e, excess, _) = node(77, None);
	propose_amount(&excess, &home, 20_000).await;
	assert!(!has_channel_with(&home, &excess));
	assert!(!has_channel_with(&home, &c));
	assert!(log
		.0
		.lock()
		.unwrap()
		.iter()
		.any(|s| s.contains("CHANNEL_CAPACITY_EXCEEDED")));
	assert!(log
		.0
		.lock()
		.unwrap()
		.iter()
		.any(|s| s.contains("TOTAL_CHANNEL_CAPACITY_EXCEEDED")));
	let codes: Vec<_> = home
		.channel_manager
		.get_and_clear_pending_msg_events()
		.into_iter()
		.filter_map(|event| match event {
			MessageSendEvent::HandleError {
				action: lightning::ln::msgs::ErrorAction::SendErrorMessage { msg },
				..
			} => Some(msg.data),
			_ => None,
		})
		.collect();
	assert!(codes.iter().any(|code| code == "CHANNEL_CAPACITY_EXCEEDED"));
	assert!(codes
		.iter()
		.any(|code| code == "TOTAL_CHANNEL_CAPACITY_EXCEEDED"));
	let addr: SocketAddress = "127.0.0.1:9".parse().unwrap();
	assert_eq!(
		home.open_channel(c.node_id(), addr, 20_000, None, None),
		Err(crate::Error::TotalChannelCapacityExceeded)
	);
}

#[tokio::test]
async fn capacity_refusal_precedes_outbound_connection_and_splicing() {
	let (_d, home, _) = node_with_limits(
		75,
		None,
		Some(crate::channel_limits::ChannelLimits::new(100_000, 150_000)),
	);
	let (_p, peer, _) = node(76, None);
	let addr: SocketAddress = "127.0.0.1:9".parse().unwrap();
	assert_eq!(
		home.open_channel(peer.node_id(), addr.clone(), 100_001, None, None),
		Err(crate::Error::ChannelCapacityExceeded)
	);
	assert_eq!(
		home.open_channel_with_funding_policy(
			peer.node_id(),
			addr.clone(),
			100_001,
			false,
			crate::funding::FundingPolicy::new(
				crate::funding::FundingPriority::Normal,
				bitcoin::FeeRate::from_sat_per_kwu(1_000),
				None
			)
			.unwrap()
		),
		Err(crate::Error::ChannelCapacityExceeded)
	);
	assert_eq!(
		home.open_channel(peer.node_id(), addr, 100_000, None, None),
		Err(crate::Error::NotRunning)
	);
	assert!(
		home.channel_manager
			.get_current_config()
			.reject_inbound_splices
	);
	assert_eq!(
		home.splice_in(&crate::UserChannelId(1), peer.node_id(), 1),
		Err(crate::Error::ChannelCapacityExceeded)
	);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_inbound_requests_share_one_capacity_allowance() {
	let (_a, a, _) = node(81, None);
	let (_b, b, _) = node(82, None);
	let (_h, home, _) = node_with_limits(
		83,
		None,
		Some(crate::channel_limits::ChannelLimits::new(100_000, 100_000)),
	);
	let (_, a_events) = request_amount(&a, &home, 60_000);
	let (_, b_events) = request_amount(&b, &home, 60_000);
	assert!(
		home.channel_manager.list_channels().is_empty(),
		"unaccepted requests are not reservations"
	);
	let home = Arc::new(home);
	let barrier = Arc::new(tokio::sync::Barrier::new(2));
	let mut jobs = Vec::new();
	for events in [a_events, b_events] {
		let home = home.clone();
		let barrier = barrier.clone();
		jobs.push(tokio::spawn(async move {
			let handler = handler(&home);
			barrier.wait().await;
			for event in events {
				handler.handle_event(event).await.unwrap();
			}
		}));
	}
	for job in jobs {
		job.await.unwrap();
	}
	let channels = home.channel_manager.list_channels();
	assert_eq!(channels.len(), 1);
	assert_eq!(channels[0].channel_value_satoshis, 60_000);
}

#[tokio::test]
async fn restored_funded_channel_counts_after_lowering_caps() {
	use bitcoin::{
		absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
		Witness,
	};
	use lightning::util::persist::{
		KVStoreSync, CHANNEL_MANAGER_PERSISTENCE_KEY,
		CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
		CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
	};
	use lightning::util::ser::Writeable;
	let (_a, a, _) = node(85, None);
	let (dir, home, _) = node_with_limits(
		86,
		None,
		Some(crate::channel_limits::ChannelLimits::new(100_000, 150_000)),
	);
	let temporary_id = propose_amount(&a, &home, 100_000).await;
	let accept = home
		.channel_manager
		.get_and_clear_pending_msg_events()
		.into_iter()
		.find_map(|event| match event {
			MessageSendEvent::SendAcceptChannel { msg, .. } => Some(msg),
			_ => None,
		})
		.unwrap();
	a.channel_manager
		.handle_accept_channel(home.node_id(), &accept);
	let script = Mutex::new(None);
	a.channel_manager
		.process_pending_events(&|event: LdkEvent| -> Result<(), ReplayEvent> {
			if let LdkEvent::FundingGenerationReady { output_script, .. } = event {
				*script.lock().unwrap() = Some(output_script);
			}
			Ok(())
		});
	// Synthetic SegWit funding transaction: never broadcast, no wallet funds required.
	let tx = Transaction {
		version: transaction::Version::TWO,
		lock_time: absolute::LockTime::ZERO,
		input: vec![TxIn {
			previous_output: OutPoint::null(),
			script_sig: ScriptBuf::new(),
			sequence: Sequence::MAX,
			witness: Witness::from_slice(&[vec![1]]),
		}],
		output: vec![TxOut {
			value: Amount::from_sat(100_000),
			script_pubkey: script.into_inner().unwrap().unwrap(),
		}],
	};
	a.channel_manager
		.funding_transaction_generated(temporary_id, home.node_id(), tx)
		.unwrap();
	let funding = a
		.channel_manager
		.get_and_clear_pending_msg_events()
		.into_iter()
		.find_map(|event| match event {
			MessageSendEvent::SendFundingCreated { msg, .. } => Some(msg),
			_ => None,
		})
		.unwrap();
	home.channel_manager
		.handle_funding_created(a.node_id(), &funding);
	assert!(home.channel_manager.list_channels()[0]
		.funding_txo
		.is_some());
	KVStoreSync::write(
		&*home.kv_store,
		CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
		CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
		CHANNEL_MANAGER_PERSISTENCE_KEY,
		home.channel_manager.encode(),
	)
	.unwrap();
	drop(home);
	let mut builder = crate::Builder::from_config(crate::Config {
		channel_limits: Some(crate::channel_limits::ChannelLimits::new(50_000, 90_000)),
		anchor_channels_config: Some(AnchorChannelsConfig {
			per_channel_reserve_sats: 0,
			..Default::default()
		}),
		..Default::default()
	});
	builder.set_network(bitcoin::Network::Regtest);
	builder.set_entropy_seed_bytes([86; 64]);
	builder.set_storage_dir_path(dir.path().to_str().unwrap().into());
	let restored = builder.build_with_fs_store().unwrap();
	assert_eq!(
		restored.channel_manager.list_channels()[0].channel_value_satoshis,
		100_000
	);
	assert!(
		restored
			.channel_manager
			.get_current_config()
			.reject_inbound_splices
	);
	// Restart redelivers the persisted ChannelPending event before fresh requests.
	let pending = Mutex::new(Vec::new());
	restored.channel_manager.process_pending_events(
		&|event: LdkEvent| -> Result<(), ReplayEvent> {
			pending.lock().unwrap().push(event);
			Ok(())
		},
	);
	let event_handler = handler(&restored);
	for event in pending.into_inner().unwrap() {
		event_handler.handle_event(event).await.unwrap();
	}
	let (_b, b, _) = node(87, None);
	propose_amount(&b, &restored, 20_000).await;
	assert!(!has_channel_with(&restored, &b));
	assert_eq!(
		restored.open_channel(
			b.node_id(),
			"127.0.0.1:9".parse().unwrap(),
			20_000,
			None,
			None
		),
		Err(crate::Error::TotalChannelCapacityExceeded)
	);
}
