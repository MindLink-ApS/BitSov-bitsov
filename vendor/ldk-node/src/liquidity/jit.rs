//! BITSOV-PATCH: owner-funded LSPS2 opens, durable bounded retries and exposure.
use super::*;
use crate::lsps2_open::Phase;
use std::collections::HashSet;

fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(u64::MAX)
}

impl<L: Deref> LiquiditySource<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn jit_metrics(&self) -> crate::LSPS2ServiceMetrics {
		let journal = self.jit_journal.lock().unwrap();
		let mut metrics = journal.metrics();
		let (capital, pending) = self.external_jit_exposure(&journal);
		metrics.capital_locked_sats = metrics.capital_locked_sats.saturating_add(capital);
		metrics.pending_opens = metrics.pending_opens.saturating_add(pending);
		metrics
	}

	pub(crate) fn observe_jit_channel(
		&self,
		id: u128,
		channel: ChannelId,
		ready: bool,
		closed: bool,
	) -> Result<(), Error> {
		let mut journal = self.jit_journal.lock().unwrap();
		if !journal.opens.contains_key(&id.to_string()) {
			return Ok(());
		}
		journal.update(self.kv_store.as_ref(), |j| {
			j.observe(id, channel.to_string(), ready);
			if closed {
				j.closed(id);
			}
		})
	}

	fn external_jit_exposure(&self, journal: &crate::lsps2_open::Journal) -> (u64, u64) {
		// Include pre-patch service channels conservatively, even if their tariff
		// has already changed. A zero-conf private outbound manual channel also
		// counts; never allow migration/restart to make capital disappear.
		// Unknown pre-patch closing monitors have no reliable original JIT
		// attribution/capacity. Reserve the entire configured budget until they
		// archive and sweeps finish. This may also block on a manual channel.
		let mut capital = if *self.untracked_jit_closure.lock().unwrap() {
			self.lsps2_service
				.as_ref()
				.map_or(0, |s| s.service_config.max_jit_capital_sats)
		} else {
			0u64
		};
		let mut pending = 0u64;
		for c in self.channel_manager.list_channels() {
			if c.is_outbound
				&& !c.is_announced
				&& c.confirmations_required == Some(0)
				&& !journal.opens.contains_key(&c.user_channel_id.to_string())
			{
				let overhead = self
					.lsps2_service
					.as_ref()
					.map_or(0, |s| s.service_config.max_funding_fee_sats)
					.saturating_add(
						self.config
							.anchor_channels_config
							.as_ref()
							.map_or(0, |c| c.per_channel_reserve_sats),
					);
				capital = capital
					.saturating_add(c.channel_value_satoshis)
					.saturating_add(overhead);
				if !c.is_channel_ready {
					pending += 1;
				}
			}
		}
		(capital, pending)
	}

	pub(super) fn reserve_jit_open(
		&self,
		peer: PublicKey,
		forward_msat: u64,
		fee_msat: u64,
		id: u128,
	) -> Result<(), Error> {
		let config = &self
			.lsps2_service
			.as_ref()
			.ok_or(Error::LiquiditySourceUnavailable)?
			.service_config;
		// Old, unmarked pending buys cannot silently fall back to legacy funding.
		if !crate::funding::is_jit_channel_id(id) {
			return Err(Error::ChannelCreationFailed);
		}
		let amount = forward_msat
			.checked_mul(u64::from(config.channel_over_provisioning_ppm))
			.map(|over| over / 1_000_000)
			.and_then(|over| forward_msat.checked_add(over))
			.map(|total| total / 1000)
			.filter(|amount| *amount > 0)
			.ok_or(Error::InvalidAmount)?;
		let reserve = amount
			.checked_add(config.max_funding_fee_sats)
			.and_then(|n| {
				n.checked_add(
					self.config
						.anchor_channels_config
						.as_ref()
						.map_or(0, |c| c.per_channel_reserve_sats),
				)
			})
			.ok_or(Error::InvalidAmount)?;
		let mut journal = self.jit_journal.lock().unwrap();
		if journal.opens.contains_key(&id.to_string()) {
			return Ok(());
		}
		let (external, pending) = self.external_jit_exposure(&journal);
		journal.update(self.kv_store.as_ref(), |j| {
			j.insert(
				crate::lsps2_open::OpenRequest {
					id,
					peer: peer.to_string(),
					amount_sats: amount,
					opening_fee_msat: fee_msat,
					funding_fee_cap_sats: config.max_funding_fee_sats,
					reserve,
				},
				now(),
				(config.max_concurrent_jit_opens, config.max_jit_capital_sats),
				(external, pending),
			)
		})??;
		if journal.opens[&id.to_string()].phase == Phase::Failed {
			log_error!(
				self.logger,
				"LSPS2 open {} refused: concurrent-open or capital cap",
				id
			);
		}
		Ok(())
	}

	fn try_jit_open(&self, id: u128) -> Result<ChannelId, String> {
		let service = &self
			.lsps2_service
			.as_ref()
			.ok_or("service disabled")?
			.service_config;
		let request = self.jit_journal.lock().unwrap().opens[&id.to_string()].clone();
		let peer = request
			.peer
			.parse::<PublicKey>()
			.map_err(|e| e.to_string())?;
		if self
			.peer_manager
			.read()
			.unwrap()
			.as_ref()
			.and_then(|pm| pm.peer_by_node_id(&peer))
			.is_none()
		{
			return Err("peer offline".into());
		}
		let current_reserve =
			total_anchor_channels_reserve_sats(&self.channel_manager, &self.config);
		let spendable = self
			.wallet
			.get_spendable_amount_sats(current_reserve)
			.map_err(|e| e.to_string())?;
		if spendable < request.reserved_sats {
			return Err("insufficient funds including anchors and funding fee cap".into());
		}
		if crate::funding::failure(self.kv_store.as_ref(), id)
			.map_err(|e| e.to_string())?
			.is_some()
		{
			return Err("terminal funding failure".into());
		}
		if !request.policy_saved {
			let policy = self
				.wallet
				.jit_funding_policy(
					service.funding_priority,
					request.funding_cap(service.max_funding_fee_sats),
				)
				.map_err(|e| e.to_string())?;
			crate::funding::save(self.kv_store.as_ref(), id, &policy).map_err(|e| e.to_string())?;
			self.jit_journal
				.lock()
				.unwrap()
				.update(self.kv_store.as_ref(), |j| {
					j.opens.get_mut(&id.to_string()).unwrap().policy_saved = true;
				})
				.map_err(|e| e.to_string())?;
		} else {
			crate::funding::load(self.kv_store.as_ref(), id)
				.map_err(|e| e.to_string())?
				.ok_or("missing funding policy")?;
		}
		let mut config = self.channel_manager.get_current_config().clone();
		config.channel_config.forwarding_fee_base_msat = 0;
		config.channel_config.forwarding_fee_proportional_millionths = 0;
		self.channel_manager
			.create_channel(peer, request.amount_sats, 0, id, None, Some(config))
			.map_err(|e| format!("create_channel: {:?}", e))
	}

	/// Called serially with liquidity event handling. Retain funded reservations
	/// through closure until both monitor archival and sweep completion.
	pub(crate) async fn maintain_jit_opens(&self, retained_channels: &HashSet<String>) {
		if self.lsps2_service.is_none() {
			return;
		}
		let live = self
			.channel_manager
			.list_channels()
			.into_iter()
			.map(|c| c.channel_id.to_string())
			.collect::<HashSet<_>>();
		let known = self
			.jit_journal
			.lock()
			.unwrap()
			.opens
			.values()
			.filter_map(|r| r.channel_id.clone())
			.collect::<HashSet<_>>();
		*self.untracked_jit_closure.lock().unwrap() = retained_channels
			.iter()
			.any(|id| !live.contains(id) && !known.contains(id));
		if let Err(error) = self.reconcile_jit_opens(retained_channels) {
			log_error!(
				self.logger,
				"LSPS2 journal reconciliation failed; no opens dispatched: {:?}",
				error
			);
			return;
		}
		let due = self.jit_journal.lock().unwrap().due(now());
		for id in due {
			let config = &self.lsps2_service.as_ref().unwrap().service_config;
			let exposure = self.jit_metrics();
			// A restart may lower the owner's limits. Stop undispatched work;
			// existing funded/uncertain exposure remains reserved.
			if exposure.capital_locked_sats > config.max_jit_capital_sats
				|| exposure.pending_opens > u64::from(config.max_concurrent_jit_opens)
			{
				log_error!(
					self.logger,
					"LSPS2 open {} refused after owner exposure limit changed",
					id
				);
				if self
					.jit_journal
					.lock()
					.unwrap()
					.update(self.kv_store.as_ref(), |j| {
						j.opens.get_mut(&id.to_string()).unwrap().expires_at = 0;
						j.failed(id, now());
					})
					.is_err()
				{
					return;
				}
				continue;
			}
			let begin = self
				.jit_journal
				.lock()
				.unwrap()
				.update(self.kv_store.as_ref(), |j| j.begin(id, now()));
			match begin {
				Ok(true) => {}
				Ok(false) => continue,
				Err(error) => {
					log_error!(
						self.logger,
						"LSPS2 open {} persistence failed before dispatch: {:?}",
						id,
						error
					);
					return;
				}
			}
			match self.try_jit_open(id) {
				Ok(channel_id) => {
					if let Err(error) =
						self.jit_journal
							.lock()
							.unwrap()
							.update(self.kv_store.as_ref(), |j| {
								j.observe(id, channel_id.to_string(), false);
							}) {
						log_error!(
							self.logger,
							"LSPS2 open {} outcome uncertain; reservation retained, no retry: {:?}",
							id,
							error
						);
						return;
					}
				}
				Err(error) => {
					log_error!(
						self.logger,
						"LSPS2 open {} failed (bounded retry): {}",
						id,
						error
					);
					if let Err(error) = self
						.jit_journal
						.lock()
						.unwrap()
						.update(self.kv_store.as_ref(), |j| j.failed(id, now()))
					{
						log_error!(
							self.logger,
							"LSPS2 open {} failure persistence failed; reservation retained: {:?}",
							id,
							error
						);
						return;
					}
				}
			}
		}
		// Never fail the intercepted payment during a retry: upstream failure
		// clears its HTLC queue. Only exhausted/refused requests are failed.
		let failed: Vec<_> = self
			.jit_journal
			.lock()
			.unwrap()
			.opens
			.iter()
			.filter(|(_, r)| {
				matches!(r.phase, Phase::Failed | Phase::Closed)
					&& !r.failure_notified
					&& r.cleanup_attempts < 5
			})
			.map(|(id, r)| {
				(
					id.parse::<u128>().unwrap(),
					r.peer.parse::<PublicKey>().unwrap(),
				)
			})
			.collect();
		if let Some(handler) = self.liquidity_manager.lsps2_service_handler() {
			for (id, peer) in failed {
				if self
					.jit_journal
					.lock()
					.unwrap()
					.update(self.kv_store.as_ref(), |j| {
						j.opens.get_mut(&id.to_string()).unwrap().cleanup_attempts += 1;
					})
					.is_err()
				{
					return;
				}
				if let Err(error) = handler.channel_open_failed(&peer, id).await {
					log_error!(
						self.logger,
						"LSPS2 terminal open {} HTLC cleanup: {:?}",
						id,
						error
					);
				}
				match handler.channel_open_abandoned(&peer, id).await {
					Ok(()) => {
						if let Err(error) =
							self.jit_journal
								.lock()
								.unwrap()
								.update(self.kv_store.as_ref(), |j| {
									j.opens.get_mut(&id.to_string()).unwrap().failure_notified =
										true;
								}) {
							log_error!(
								self.logger,
								"LSPS2 terminal open {} cleanup persistence: {:?}",
								id,
								error
							);
						}
					}
					Err(error) => log_error!(
						self.logger,
						"LSPS2 terminal open {} abandonment: {:?}",
						id,
						error
					),
				}
			}
		}
	}

	fn reconcile_jit_opens(&self, retained: &HashSet<String>) -> Result<(), Error> {
		let channels = self.channel_manager.list_channels();
		let mut journal = self.jit_journal.lock().unwrap();
		let mut updates = Vec::new();
		let mut releases = Vec::new();
		let mut failures = Vec::new();
		for (id, r) in &journal.opens {
			let id = id.parse::<u128>().unwrap();
			if let Some(c) = channels.iter().find(|c| c.user_channel_id == id) {
				if r.channel_id.as_deref() != Some(c.channel_id.to_string().as_str())
					|| (c.is_channel_ready && r.phase == Phase::Dispatching)
				{
					updates.push((id, c.channel_id.to_string(), c.is_channel_ready));
				}
			} else if r.closed
				&& r.reserved_sats > 0
				&& r.channel_id.as_ref().is_some_and(|c| !retained.contains(c))
			{
				releases.push(id);
			} else if r.phase == Phase::Dispatching
				&& crate::funding::failure(self.kv_store.as_ref(), id)?.is_some()
			{
				// The #190 wallet records refusal before signing/broadcast.
				failures.push(id);
			}
		}
		if updates.is_empty() && releases.is_empty() && failures.is_empty() {
			return Ok(());
		}
		journal.update(self.kv_store.as_ref(), |j| {
			for (id, channel, ready) in updates {
				j.observe(id, channel, ready);
			}
			for id in releases {
				let r = j.opens.get_mut(&id.to_string()).unwrap();
				r.phase = if r.phase == Phase::Closed {
					Phase::Failed
				} else {
					Phase::Released
				};
				r.reserved_sats = 0;
			}
			for id in failures {
				// Terminal async construction failures never re-estimate or
				// exceed the original fee ceiling by retrying with a new ID.
				j.opens.get_mut(&id.to_string()).unwrap().expires_at = 0;
				j.failed(id, now());
			}
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	fn builder(path: &std::path::Path, cap: u64) -> crate::Builder {
		let mut b = crate::Builder::new();
		b.set_storage_dir_path(path.to_str().unwrap().into());
		b.set_network(bitcoin::Network::Regtest);
		b.set_entropy_seed_bytes([45; 64]);
		b.set_liquidity_provider_lsps2(LSPS2ServiceConfig {
			require_token: Some("test".into()),
			advertise_service: false,
			channel_opening_fee_ppm: 10000,
			channel_over_provisioning_ppm: 1000000,
			min_channel_opening_fee_msat: 1000000,
			min_channel_lifetime: 144,
			max_client_to_self_delay: 2016,
			min_payment_size_msat: 10000000,
			max_payment_size_msat: 1000000000,
			client_trusts_lsp: false,
			funding_priority: crate::funding::FundingPriority::Economy,
			max_funding_fee_sats: 2000,
			max_concurrent_jit_opens: 1,
			max_jit_capital_sats: cap,
		});
		b
	}
	async fn request(source: &LiquiditySource<Arc<Logger>>, peer: PublicKey, id: u128) {
		source
			.handle_liquidity_event(LiquidityEvent::LSPS2Service(
				LSPS2ServiceEvent::OpenChannel {
					their_network_key: peer,
					amt_to_forward_msat: 99000000,
					opening_fee_msat: 1000000,
					user_channel_id: id,
					intercept_scid: 42,
				},
			))
			.await;
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn bitsov_jit_offline_failure_restarts_with_same_budget_and_caps() {
		let dir = tempfile::tempdir().unwrap();
		let node = builder(dir.path(), 250000).build_with_fs_store().unwrap();
		let peer = node.node_id();
		let id = crate::funding::new_jit_channel_id();
		let source = node.liquidity_source.as_ref().unwrap();
		request(source, peer, id).await;
		source.maintain_jit_opens(&HashSet::new()).await;
		assert_eq!(source.jit_metrics().failed_opens, 1);
		assert_eq!(source.jit_metrics().pending_opens, 1);
		assert_eq!(source.jit_metrics().capital_locked_sats, 225000);
		assert!(node.list_channels().is_empty());
		drop(node);
		let node = builder(dir.path(), 250000).build_with_fs_store().unwrap();
		let source = node.liquidity_source.as_ref().unwrap();
		request(source, peer, id).await; // replay cannot reset attempts/backoff
		assert_eq!(
			source.jit_journal.lock().unwrap().opens[&id.to_string()].attempts,
			1
		);
		let second = crate::funding::new_jit_channel_id();
		request(source, peer, second).await;
		assert_eq!(source.jit_metrics().pending_opens, 1);
		assert_eq!(source.jit_metrics().failed_opens, 2);
		assert_eq!(source.jit_metrics().capital_locked_sats, 225000);
		// Make the real scheduler due without waiting for wall-clock seconds.
		source
			.jit_journal
			.lock()
			.unwrap()
			.update(node.kv_store.as_ref(), |j| {
				j.opens.get_mut(&id.to_string()).unwrap().next_attempt = 0;
			})
			.unwrap();
		source.maintain_jit_opens(&HashSet::new()).await;
		assert_eq!(source.jit_metrics().open_retries, 1);
		assert_eq!(source.jit_metrics().failed_opens, 3);
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn bitsov_jit_lowered_cap_refuses_waiting_open_after_restart() {
		let dir = tempfile::tempdir().unwrap();
		let id = crate::funding::new_jit_channel_id();
		let node = builder(dir.path(), 250000).build_with_fs_store().unwrap();
		request(node.liquidity_source.as_ref().unwrap(), node.node_id(), id).await;
		drop(node);
		let node = builder(dir.path(), 200000).build_with_fs_store().unwrap();
		let source = node.liquidity_source.as_ref().unwrap();
		source.maintain_jit_opens(&HashSet::new()).await;
		assert_eq!(source.jit_metrics().capital_locked_sats, 0);
		assert_eq!(source.jit_metrics().failed_opens, 1);
		assert!(node.list_channels().is_empty());
	}

	#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
	async fn bitsov_jit_closed_capital_waits_for_monitor_and_sweep() {
		let dir = tempfile::tempdir().unwrap();
		let node = builder(dir.path(), 250000).build_with_fs_store().unwrap();
		let source = node.liquidity_source.as_ref().unwrap();
		let id = crate::funding::new_jit_channel_id();
		request(source, node.node_id(), id).await;
		source
			.jit_journal
			.lock()
			.unwrap()
			.update(node.kv_store.as_ref(), |j| {
				assert!(j.begin(id, now()));
			})
			.unwrap();
		let channel = ChannelId([19; 32]);
		source
			.observe_jit_channel(id, channel, true, false)
			.unwrap();
		source
			.observe_jit_channel(id, channel, true, false)
			.unwrap();
		source
			.observe_jit_channel(id, channel, false, true)
			.unwrap();
		let retained = HashSet::from([channel.to_string()]);
		source.maintain_jit_opens(&retained).await;
		assert_eq!(source.jit_metrics().opens, 1);
		assert_eq!(source.jit_metrics().capital_locked_sats, 225000);
		assert_eq!(source.jit_metrics().pending_opens, 0);
		source.maintain_jit_opens(&HashSet::new()).await;
		assert_eq!(source.jit_metrics().capital_locked_sats, 0);
		// A pre-patch closed monitor cannot disappear from cap accounting.
		source
			.maintain_jit_opens(&HashSet::from([ChannelId([20; 32]).to_string()]))
			.await;
		request(source, node.node_id(), crate::funding::new_jit_channel_id()).await;
		assert_eq!(source.jit_metrics().failed_opens, 1);
		assert_eq!(source.jit_metrics().capital_locked_sats, 250000);
	}

	#[test]
	fn bitsov_jit_marker_enforces_owner_policy_and_missing_row_fails_closed() {
		let dir = tempfile::tempdir().unwrap();
		let node = builder(dir.path(), 250000).build_with_fs_store().unwrap();
		let id = crate::funding::new_jit_channel_id();
		assert!(crate::funding::load(node.kv_store.as_ref(), id).is_err());
		let priority = crate::funding::FundingPriority::Economy;
		node.fee_estimator.set_test_fee_rate_cache(HashMap::from([
			(priority.target(), bitcoin::FeeRate::from_sat_per_kwu(777)),
			(
				crate::funding::FundingPriority::Normal.target(),
				bitcoin::FeeRate::from_sat_per_kwu(999),
			),
		]));
		let policy = node.wallet.jit_funding_policy(priority, 2000).unwrap();
		crate::funding::save(node.kv_store.as_ref(), id, &policy).unwrap();
		let stored = crate::funding::load(node.kv_store.as_ref(), id)
			.unwrap()
			.unwrap();
		assert_eq!(stored.priority(), priority);
		assert_eq!(stored.estimated_fee_rate_sat_per_kwu(), 777);
		assert_eq!(stored.max_fee_sats(), Some(2000));
	}
}
