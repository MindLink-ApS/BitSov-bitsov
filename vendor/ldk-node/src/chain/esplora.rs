// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bdk_esplora::EsploraAsyncExt;
use bitcoin::{FeeRate, Network, Script, Transaction, Txid};
use esplora_client::AsyncClient as EsploraAsyncClient;
use lightning::chain::{Confirm, Filter, WatchedOutput};
use lightning::util::ser::Writeable;
use lightning_transaction_sync::EsploraSyncClient;

use super::{periodically_archive_fully_resolved_monitors, WalletSyncStatus};
use crate::config::{
	Config, EsploraSyncConfig, BDK_CLIENT_CONCURRENCY, BDK_CLIENT_STOP_GAP,
	BDK_WALLET_SYNC_TIMEOUT_SECS, DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS,
	FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS, LDK_WALLET_SYNC_TIMEOUT_SECS, TX_BROADCAST_TIMEOUT_SECS,
};
use crate::fee_estimator::{
	apply_post_estimation_adjustments, get_all_conf_targets, get_num_block_defaults_for_target,
	OnchainFeeEstimator,
};
use crate::io::utils::write_node_metrics;
use crate::logger::{log_bytes, log_error, log_info, log_trace, LdkLogger, Logger};
use crate::types::{ChainMonitor, ChannelManager, DynStore, Sweeper, Wallet};
use crate::{BuildError, Error, NodeMetrics};

pub(super) struct EsploraChainSource {
    live_transport: Option<Arc<dyn esplora_client::r#async::HttpTransport>>,
	pub(super) sync_config: EsploraSyncConfig,
	esplora_client: EsploraAsyncClient,
	rate_limit: Arc<super::rate_limit::RateLimitedTransport>,
	onchain_wallet_sync_status: Mutex<WalletSyncStatus>,
	tx_sync: Arc<EsploraSyncClient<Arc<Logger>>>,
	lightning_wallet_sync_status: Mutex<WalletSyncStatus>,
	fee_estimator: Arc<OnchainFeeEstimator>,
	kv_store: Arc<DynStore>,
	config: Arc<Config>,
	logger: Arc<Logger>,
	node_metrics: Arc<RwLock<NodeMetrics>>,
}

// Keep a per-request deadline in addition to the aggregate wallet deadlines.
// Tests inject a resolver on this builder; production uses the default transport.
fn esplora_http_client_builder(
	headers: HashMap<String, String>,
) -> Result<reqwest::ClientBuilder, BuildError> {
	let mut default_headers = reqwest::header::HeaderMap::new();
	for (name, value) in headers {
		default_headers.insert(
			reqwest::header::HeaderName::from_bytes(name.to_ascii_lowercase().as_bytes())
				.map_err(|_| BuildError::InvalidEsploraHeaders)?,
			reqwest::header::HeaderValue::from_str(&value)
				.map_err(|_| BuildError::InvalidEsploraHeaders)?,
		);
	}
	Ok(reqwest::Client::builder()
		.timeout(Duration::from_secs(DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS))
		.default_headers(default_headers))
}

impl EsploraChainSource {
	pub(crate) fn new(
		server_url: String, headers: HashMap<String, String>, sync_config: EsploraSyncConfig,
		fee_estimator: Arc<OnchainFeeEstimator>, kv_store: Arc<DynStore>, config: Arc<Config>,
		logger: Arc<Logger>, node_metrics: Arc<RwLock<NodeMetrics>>,
	) -> Result<Self, BuildError> {
		let http_client = esplora_http_client_builder(headers)?
			.build()
			.map_err(|_| BuildError::EsploraClientSetupFailed)?;
		let rate_limit = super::rate_limit::RateLimitedTransport::shared(&server_url);
		let esplora_client = EsploraAsyncClient::from_client(server_url, http_client)
            .with_timeout(Duration::from_secs(DEFAULT_ESPLORA_CLIENT_TIMEOUT_SECS))
            .with_transport(rate_limit.clone());
		let tx_sync =
			Arc::new(EsploraSyncClient::from_client(esplora_client.clone(), Arc::clone(&logger)));

		let onchain_wallet_sync_status = Mutex::new(WalletSyncStatus::Completed);
		let lightning_wallet_sync_status = Mutex::new(WalletSyncStatus::Completed);
		Ok(Self {
            live_transport: None,
			sync_config,
			esplora_client,
			rate_limit,
			onchain_wallet_sync_status,
			tx_sync,
			lightning_wallet_sync_status,
			fee_estimator,
			kv_store,
			config,
			logger,
			node_metrics,
		})
	}

    pub(super) fn set_transport(&mut self, transport: Arc<dyn esplora_client::r#async::HttpTransport>) {
        self.live_transport = Some(transport.clone());
        self.esplora_client = self.esplora_client.clone().with_transport(transport);
        self.tx_sync = Arc::new(EsploraSyncClient::from_client(self.esplora_client.clone(), self.logger.clone()));
    }

    pub(super) fn rate_limit_failure(&self) -> Option<super::sync_health::ChainSyncFailure> {
        match &self.live_transport {
            Some(transport) => transport.rate_limit_failure(),
            None => self.rate_limit.failure(),
        }
    }
    fn classify<T>(&self, result: Result<T, Error>) -> Result<T, Error> {
        result.map_err(|error| if self.rate_limit_failure().is_some() { Error::ChainRateLimited } else { error })
    }

	pub(super) async fn sync_onchain_wallet(
		&self, onchain_wallet: Arc<Wallet>,
	) -> Result<(), Error> {
		let result = WalletSyncStatus::run(
			&self.onchain_wallet_sync_status, Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS),
			Error::WalletOperationTimeout, self.sync_onchain_wallet_inner(onchain_wallet),
        ).await;
        self.classify(result)
    }

	async fn sync_onchain_wallet_inner(&self, onchain_wallet: Arc<Wallet>) -> Result<(), Error> {
		// If this is our first sync, do a full scan with the configured gap limit.
		// Otherwise just do an incremental sync.
		let incremental_sync =
			self.node_metrics.read().unwrap().latest_onchain_wallet_sync_timestamp.is_some();

		macro_rules! get_and_apply_wallet_update {
			($sync_future: expr) => {{
				let now = Instant::now();
				match $sync_future.await {
					Ok(res) => match res {
						Ok(update) => match onchain_wallet.apply_update(update) {
							Ok(()) => {
								log_info!(
									self.logger,
									"{} of on-chain wallet finished in {}ms.",
									if incremental_sync { "Incremental sync" } else { "Sync" },
									now.elapsed().as_millis()
								);
								let unix_time_secs_opt = SystemTime::now()
									.duration_since(UNIX_EPOCH)
									.ok()
									.map(|d| d.as_secs());
									{
										let mut locked_node_metrics = self.node_metrics.write().unwrap();
										locked_node_metrics.latest_onchain_wallet_sync_timestamp = unix_time_secs_opt;
										write_node_metrics(
											&*locked_node_metrics,
											Arc::clone(&self.kv_store),
											Arc::clone(&self.logger)
										)?;
									}
									Ok(())
							},
							Err(e) => Err(e),
						},
						Err(e) => match *e {
							esplora_client::Error::Reqwest(he) => {
								if let Some(status_code) = he.status() {
									log_error!(
										self.logger,
										"{} of on-chain wallet failed due to HTTP {} error: {}",
										if incremental_sync { "Incremental sync" } else { "Sync" },
										status_code,
										he,
									);
								} else {
									log_error!(
										self.logger,
										"{} of on-chain wallet failed due to HTTP error: {}",
										if incremental_sync { "Incremental sync" } else { "Sync" },
										he,
									);
								}
								Err(Error::WalletOperationFailed)
							},
							_ => {
								log_error!(
									self.logger,
									"{} of on-chain wallet failed due to Esplora error: {}",
									if incremental_sync { "Incremental sync" } else { "Sync" },
									e
								);
								Err(Error::WalletOperationFailed)
							},
						},
					},
					Err(e) => {
						log_error!(
							self.logger,
							"{} of on-chain wallet timed out: {}",
							if incremental_sync { "Incremental sync" } else { "Sync" },
							e
						);
						Err(Error::WalletOperationTimeout)
					},
				}
			}}
		}

		if incremental_sync {
			let sync_request = onchain_wallet.get_incremental_sync_request();
			let wallet_sync_timeout_fut = tokio::time::timeout(
				Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS),
				self.esplora_client.sync(sync_request, BDK_CLIENT_CONCURRENCY),
			);
			get_and_apply_wallet_update!(wallet_sync_timeout_fut)
		} else {
			let full_scan_request = onchain_wallet.get_full_scan_request();
			let wallet_sync_timeout_fut = tokio::time::timeout(
				Duration::from_secs(BDK_WALLET_SYNC_TIMEOUT_SECS),
				self.esplora_client.full_scan(
					full_scan_request,
					BDK_CLIENT_STOP_GAP,
					BDK_CLIENT_CONCURRENCY,
				),
			);
			get_and_apply_wallet_update!(wallet_sync_timeout_fut)
		}
	}

	pub(super) async fn sync_lightning_wallet(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		let result = WalletSyncStatus::run(
			&self.lightning_wallet_sync_status, Duration::from_secs(LDK_WALLET_SYNC_TIMEOUT_SECS),
			Error::TxSyncTimeout,
			self.sync_lightning_wallet_inner(channel_manager, chain_monitor, output_sweeper),
        ).await;
        self.classify(result)
    }

	async fn sync_lightning_wallet_inner(
		&self, channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
		output_sweeper: Arc<Sweeper>,
	) -> Result<(), Error> {
		let sync_cman = Arc::clone(&channel_manager);
		let sync_cmon = Arc::clone(&chain_monitor);
		let sync_sweeper = Arc::clone(&output_sweeper);
		let confirmables = vec![
			&*sync_cman as &(dyn Confirm + Sync + Send),
			&*sync_cmon as &(dyn Confirm + Sync + Send),
			&*sync_sweeper as &(dyn Confirm + Sync + Send),
		];

		let timeout_fut = tokio::time::timeout(
			Duration::from_secs(LDK_WALLET_SYNC_TIMEOUT_SECS),
			self.tx_sync.sync(confirmables),
		);
		let now = Instant::now();
		match timeout_fut.await {
			Ok(res) => match res {
				Ok(()) => {
					log_info!(
						self.logger,
						"Sync of Lightning wallet finished in {}ms.",
						now.elapsed().as_millis()
					);

					let unix_time_secs_opt =
						SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
					{
						let mut locked_node_metrics = self.node_metrics.write().unwrap();
						locked_node_metrics.latest_lightning_wallet_sync_timestamp =
							unix_time_secs_opt;
						write_node_metrics(
							&*locked_node_metrics,
							Arc::clone(&self.kv_store),
							Arc::clone(&self.logger),
						)?;
					}

					periodically_archive_fully_resolved_monitors(
						Arc::clone(&channel_manager),
						Arc::clone(&chain_monitor),
						Arc::clone(&self.kv_store),
						Arc::clone(&self.logger),
						Arc::clone(&self.node_metrics),
					)?;
					Ok(())
				},
				Err(e) => {
					log_error!(self.logger, "Sync of Lightning wallet failed: {}", e);
					Err(e.into())
				},
			},
			Err(e) => {
				log_error!(self.logger, "Lightning wallet sync timed out: {}", e);
				Err(Error::TxSyncTimeout)
			},
		}
	}

	pub(crate) async fn update_fee_rate_estimates(&self) -> Result<(), Error> {
		let now = Instant::now();
		let estimates = tokio::time::timeout(
			Duration::from_secs(FEE_RATE_CACHE_UPDATE_TIMEOUT_SECS),
			self.esplora_client.get_fee_estimates(),
		)
		.await
		.map_err(|e| {
			log_error!(self.logger, "Updating fee rate estimates timed out: {}", e);
			Error::FeerateEstimationUpdateTimeout
		})?
		.map_err(|e| {
			log_error!(self.logger, "Failed to retrieve fee rate estimates: {}", e);
			if self.rate_limit_failure().is_some() { Error::ChainRateLimited } else { Error::FeerateEstimationUpdateFailed }
		})?;

		if estimates.is_empty() && self.config.network == Network::Bitcoin {
			// Ensure we fail if we didn't receive any estimates.
			log_error!(
						self.logger,
						"Failed to retrieve fee rate estimates: empty fee estimates are dissallowed on Mainnet.",
					);
			return Err(Error::FeerateEstimationUpdateFailed);
		}

		let confirmation_targets = get_all_conf_targets();

		let mut new_fee_rate_cache = HashMap::with_capacity(10);
		let mut funding_targets = std::collections::HashSet::new();
		for target in confirmation_targets {
			let num_blocks = get_num_block_defaults_for_target(target);

			// Convert the retrieved fee rate and fall back to 1 sat/vb if we fail or it
			// yields less than that. This is mostly necessary to continue on
			// `signet`/`regtest` where we might not get estimates (or bogus values).
			let raw_estimate = esplora_client::convert_fee_rate(num_blocks, estimates.clone());
            if crate::fee_estimator::usable_funding_estimate(raw_estimate.map(f64::from)) { funding_targets.insert(target); }
            let converted_estimate_sat_vb = raw_estimate.map_or(1.0, |converted| converted.max(1.0));

			let fee_rate = FeeRate::from_sat_per_kwu((converted_estimate_sat_vb * 250.0) as u64);

			// LDK 0.0.118 introduced changes to the `ConfirmationTarget` semantics that
			// require some post-estimation adjustments to the fee rates, which we do here.
			let adjusted_fee_rate = apply_post_estimation_adjustments(target, fee_rate);

			new_fee_rate_cache.insert(target, adjusted_fee_rate);

			log_trace!(
				self.logger,
				"Fee rate estimation updated for {:?}: {} sats/kwu",
				target,
				adjusted_fee_rate.to_sat_per_kwu(),
			);
		}

		self.fee_estimator.set_fee_rate_cache(new_fee_rate_cache, funding_targets);

		log_info!(
			self.logger,
			"Fee rate cache update finished in {}ms.",
			now.elapsed().as_millis()
		);
		let unix_time_secs_opt =
			SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs());
		{
			let mut locked_node_metrics = self.node_metrics.write().unwrap();
			locked_node_metrics.latest_fee_rate_cache_update_timestamp = unix_time_secs_opt;
			write_node_metrics(
				&*locked_node_metrics,
				Arc::clone(&self.kv_store),
				Arc::clone(&self.logger),
			)?;
		}

		Ok(())
	}

    pub(super) async fn funding_present(&self, txid: Txid) -> Result<bool, Error> {
        // /status may return 200 {"confirmed":false} for an unknown txid.
        // get_tx_info uses /tx/{txid} and maps only its explicit 404 to None.
        match self.esplora_client.get_tx_info(&txid).await {
            Ok(tx) => Ok(tx.is_some()),
            Err(_) => self.classify(Err(Error::TxSyncFailed)),
        }
    }

    async fn broadcast_with_backoff(&self, tx: &Transaction) -> Result<Result<(), esplora_client::Error>, tokio::time::error::Elapsed> {
        loop {
            // A single bounded wait, never extended by another package or GET.
            // The transport admits the following POST as its own recovery probe.
            let delay = self.live_transport.as_ref().map_or_else(|| self.rate_limit.retry_delay(), |t| t.retry_delay()).min(Duration::from_secs(300));
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let result = tokio::time::timeout(Duration::from_secs(TX_BROADCAST_TIMEOUT_SECS), self.esplora_client.broadcast(tx)).await;
            if matches!(&result, Ok(Err(esplora_client::Error::HttpResponse { status: 429, .. }))) {
                // Retain this transaction while other packages progress independently.
                continue;
            }
            return result;
        }
    }

	pub(crate) async fn process_broadcast_package(&self, package: Vec<Transaction>) {
		for tx in &package {
			let txid = tx.compute_txid();
            let timeout_fut = self.broadcast_with_backoff(tx);
			match timeout_fut.await {
				Ok(res) => match res {
					Ok(()) => {
						log_trace!(self.logger, "Successfully broadcast transaction {}", txid);
					},
					Err(e) => match e {
						esplora_client::Error::HttpResponse { status, message } => {
							if status == 400 {
								// Log 400 at lesser level, as this often just means bitcoind already knows the
								// transaction.
								// FIXME: We can further differentiate here based on the error
								// message which will be available with rust-esplora-client 0.7 and
								// later.
								log_trace!(
									self.logger,
									"Failed to broadcast due to HTTP connection error: {}",
									message
								);
							} else {
								log_error!(
									self.logger,
									"Failed to broadcast due to HTTP connection error: {} - {}",
									status,
									message
								);
							}
							log_trace!(
								self.logger,
								"Failed broadcast transaction bytes: {}",
								log_bytes!(tx.encode())
							);
						},
						_ => {
							log_error!(
								self.logger,
								"Failed to broadcast transaction {}: {}",
								txid,
								e
							);
							log_trace!(
								self.logger,
								"Failed broadcast transaction bytes: {}",
								log_bytes!(tx.encode())
							);
						},
					},
				},
				Err(e) => {
					log_error!(
						self.logger,
						"Failed to broadcast transaction due to timeout {}: {}",
						txid,
						e
					);
					log_trace!(
						self.logger,
						"Failed broadcast transaction bytes: {}",
						log_bytes!(tx.encode())
					);
				},
			}
		}
	}
}

impl Filter for EsploraChainSource {
	fn register_tx(&self, txid: &Txid, script_pubkey: &Script) {
		self.tx_sync.register_tx(txid, script_pubkey);
	}
	fn register_output(&self, output: WatchedOutput) {
		self.tx_sync.register_output(output);
	}
}

#[cfg(test)]
mod bitsov_request_tests {
	use super::*;

	fn build_with_header(name: &str, value: &str) -> Result<(), BuildError> {
		let dir = tempfile::tempdir().unwrap();
		let mut builder = crate::Builder::new();
		builder.set_storage_dir_path(dir.path().to_str().unwrap().to_owned());
		builder.set_chain_source_esplora_with_headers(
			"http://chain.invalid".into(),
			HashMap::from([(name.to_owned(), value.to_owned())]),
			None,
		);
		// Construction only: no start, resolver, listener or connection.
		builder.build().map(|_| ())
	}

	#[test]
	fn mixed_case_esplora_headers_build() {
		assert!(build_with_header("Authorization", "Bearer test-token").is_ok());
		assert!(build_with_header("X-Custom-Header", "test-value").is_ok());
	}

	#[test]
	fn invalid_esplora_header_names_return_construction_error() {
		for name in ["", "bad header", "bad:header", "bad\r\nheader", "héader"] {
			assert!(matches!(
				build_with_header(name, "test-value"),
				Err(BuildError::InvalidEsploraHeaders)
			));
		}
	}

	#[test]
	fn invalid_esplora_header_values_return_construction_error() {
		for value in ["bad\r\nvalue", "bad\0value"] {
			assert!(matches!(
				build_with_header("Authorization", value),
				Err(BuildError::InvalidEsploraHeaders)
			));
		}
	}

	struct HangingResolver;
	impl reqwest::dns::Resolve for HangingResolver {
		fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
			// Never returns an address, so no DNS query or TCP connection is possible.
			Box::pin(std::future::pending())
		}
	}

	#[tokio::test(start_paused = true)]
	async fn hanging_esplora_request_hits_production_client_deadline() {
		let http = esplora_http_client_builder(HashMap::new()).unwrap()
			.no_proxy().dns_resolver(Arc::new(HangingResolver)).build().unwrap();
		let client: EsploraAsyncClient = EsploraAsyncClient::from_client("http://chain.invalid".into(), http);
		let started = tokio::time::Instant::now();
		let result = tokio::time::timeout(Duration::from_secs(11), client.get_tip_hash()).await;
		assert!(matches!(result, Ok(Err(esplora_client::Error::Reqwest(ref error))) if error.is_timeout()));
		assert_eq!(started.elapsed(), Duration::from_secs(10));
	}
}

#[cfg(test)]
mod bitsov_http_rate_tests {
    use super::*;
    use esplora_client::r#async::HttpTransport;
    use std::collections::VecDeque;
    type Reply = (&'static str, u16, Option<&'static str>, &'static str);
    #[derive(Debug)]
    struct Fixture {
        limiter: Arc<super::super::rate_limit::RateLimitedTransport>,
        replies: Mutex<VecDeque<Reply>>,
        requests: Mutex<Vec<String>>,
        posted: Mutex<Vec<Txid>>,
        parked: Mutex<Option<Txid>>,
    }
    impl HttpTransport for Fixture {
        fn execute(&self, request: reqwest::RequestBuilder) -> std::pin::Pin<Box<dyn std::future::Future<Output=Result<reqwest::Response, esplora_client::Error>> + Send + '_>> {
            let request = request.build().unwrap();
            let broadcast = request.method() == reqwest::Method::POST;
            Box::pin(self.limiter.run(broadcast, move || async move {
                let path = request.url().path().to_owned();
                if request.method() == reqwest::Method::POST {
                    let hex = std::str::from_utf8(request.body().unwrap().as_bytes().unwrap()).unwrap();
                    let tx: Transaction = bitcoin::consensus::encode::deserialize_hex(hex).unwrap();
                    let txid = tx.compute_txid();
                    self.posted.lock().unwrap().push(txid);
                    if *self.parked.lock().unwrap() == Some(txid) {
                        return Ok(http::Response::builder().status(429).header("retry-after", "86400").body("").unwrap().into());
                    }
                }
                self.requests.lock().unwrap().push(path.clone());
                let (expected, status, retry, body) = self.replies.lock().unwrap().pop_front().expect("unexpected HTTP request");
                assert_eq!(path, expected);
                let mut response = http::Response::builder().status(status);
                if let Some(retry) = retry { response = response.header("retry-after", retry); }
                Ok(response.body(body).unwrap().into())
            }))
        }
    }
    fn fixture(replies: Vec<Reply>) -> (tempfile::TempDir, crate::Node, EsploraChainSource, Arc<Fixture>) {
        let dir = tempfile::tempdir().unwrap();
        let mut builder = crate::Builder::new();
        builder.set_storage_dir_path(dir.path().to_str().unwrap().to_owned());
        let node = builder.build().unwrap();
        let mut source = EsploraChainSource::new(format!("https://user:secret@chain.invalid/api?private={}", dir.path().display()), HashMap::new(), EsploraSyncConfig::default(),
            node.fee_estimator.clone(), node.kv_store.clone(), node.config.clone(), node.logger.clone(), node.node_metrics.clone()).unwrap();
        let fixture = Arc::new(Fixture { limiter: source.rate_limit.clone(), replies: Mutex::new(replies.into()), requests: Mutex::new(vec![]), posted: Mutex::new(vec![]), parked: Mutex::new(None) });
        source.esplora_client = EsploraAsyncClient::from_client("https://chain.invalid".into(), reqwest::Client::new()).with_transport(fixture.clone());
        source.tx_sync = Arc::new(EsploraSyncClient::from_client(source.esplora_client.clone(), node.logger.clone()));
        (dir, node, source, fixture)
    }
    #[tokio::test]
    async fn live_transport_keeps_wallet_fee_and_broadcast_request_budgets() {
        #[derive(Debug)]
        struct Budget;
        impl HttpTransport for Budget {
            fn execute(&self, request: reqwest::RequestBuilder) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>> + Send + '_>> {
                Box::pin(async move {
                    let request = request.build().unwrap();
                    assert_eq!(request.timeout(), Some(&Duration::from_secs(10)));
                    let body = match request.url().path() {
                        "/api/blocks/tip/height" => "900000",
                        "/api/fee-estimates" => "{\"6\":2.0}",
                        "/api/tx" => "",
                        _ => panic!("unexpected request"),
                    };
                    Ok(http::Response::builder().body(body).unwrap().into())
                })
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut builder = crate::Builder::new();
        builder.set_storage_dir_path(dir.path().to_str().unwrap().to_owned());
        builder.set_chain_source_esplora_with_transport("https://budget.invalid/api".into(), None, Arc::new(Budget));
        let node = builder.build().unwrap();
        let super::super::ChainSourceKind::Esplora(source) = &node.chain_source.kind else { panic!("wrong source") };
        let client = source.esplora_client.clone();
        assert_eq!(client.get_height().await.unwrap(), 900000);
        client.get_fee_estimates().await.unwrap();
        client.broadcast(&transaction(0)).await.unwrap();
    }

    #[tokio::test]
    async fn live_transport_builder_reaches_fee_client_and_redacts_decode_logs() {
        #[derive(Debug)]
        struct Live;
        impl HttpTransport for Live {
            fn redact_errors(&self) -> bool { true }
            fn execute(&self, request: reqwest::RequestBuilder) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>> + Send + '_>> {
                Box::pin(async move {
                    assert_eq!(request.build().unwrap().url().path(), "/api/fee-estimates");
                    Ok(http::Response::builder().status(200).body("{\"1\":\"credential-sentinel\"}").unwrap().into())
                })
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let mut builder = crate::Builder::new();
        builder.set_storage_dir_path(dir.path().to_str().unwrap().to_owned());
        let log_path = dir.path().join("live.log");
        builder.set_filesystem_logger(Some(log_path.to_str().unwrap().to_owned()), None);
        builder.set_chain_source_esplora_with_transport("https://live.invalid/api".into(), None, Arc::new(Live));
        let node = builder.build().unwrap();
        let super::super::ChainSourceKind::Esplora(source) = &node.chain_source.kind else { panic!("wrong source") };
        assert_eq!(source.update_fee_rate_estimates().await, Err(Error::FeerateEstimationUpdateFailed));
        let logs = std::fs::read_to_string(log_path).unwrap();
        assert!(logs.contains("InvalidResponse"));
        assert!(!logs.contains("credential-sentinel"));
    }

    #[tokio::test(start_paused = true)]
    async fn real_fee_sync_funding_and_broadcast_calls_share_cooldown_and_recover() {
        let (_dir, node, source, fixture) = fixture(vec![
            ("/fee-estimates", 429, Some("120"), "private error text"),
            ("/tx", 200, None, ""),
            ("/fee-estimates", 200, None, "{\"1\":1.0}"),
        ]);
        assert_eq!(source.update_fee_rate_estimates().await, Err(Error::ChainRateLimited));
        assert_eq!(source.sync_onchain_wallet(node.wallet.clone()).await, Err(Error::ChainRateLimited));
        assert_eq!(source.sync_lightning_wallet(node.channel_manager.clone(), node.chain_monitor.clone(), node.output_sweeper.clone()).await, Err(Error::ChainRateLimited));
        use bitcoin::hashes::Hash;
        assert_eq!(source.funding_present(Txid::all_zeros()).await, Err(Error::ChainRateLimited));
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        let source = Arc::new(source);
        let broadcast = source.clone();
        let task = tokio::spawn(async move {
            broadcast.process_broadcast_package(vec![Transaction { version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO, input: vec![], output: vec![] }]).await;
        });
        tokio::task::yield_now().await;
        let remaining = source.rate_limit.retry_delay();
        tokio::time::advance(remaining - Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
        tokio::time::advance(Duration::from_secs(1)).await;
        task.await.unwrap();
        assert!(source.rate_limit_failure().is_none());
        assert_eq!(source.update_fee_rate_estimates().await, Ok(()));
        assert_eq!(fixture.requests.lock().unwrap().len(), 3);
    }
    #[tokio::test]
    async fn funding_http_evidence_is_explicit_and_not_found_is_not_rate_limit() {
        use bitcoin::hashes::Hash;
        let path: &'static str = Box::leak(format!("/tx/{}", Txid::all_zeros()).into_boxed_str());
        let unconfirmed = tx_info(false);
        let confirmed = tx_info(true);
        let (_dir, _node, source, fixture) = fixture(vec![
            (path, 404, None, "not found"), (path, 200, None, "garbage"),
            (path, 200, None, "{}"), (path, 401, None, "unavailable"),
            (path, 200, None, unconfirmed),
            (path, 200, None, confirmed), (path, 429, None, ""),
        ]);
        assert_eq!(source.funding_present(Txid::all_zeros()).await, Ok(false));
        assert!(source.funding_present(Txid::all_zeros()).await.is_err());
        assert!(source.funding_present(Txid::all_zeros()).await.is_err());
        assert!(source.funding_present(Txid::all_zeros()).await.is_err());
        assert_eq!(source.funding_present(Txid::all_zeros()).await, Ok(true));
        assert_eq!(source.funding_present(Txid::all_zeros()).await, Ok(true));
        assert_eq!(source.funding_present(Txid::all_zeros()).await, Err(Error::ChainRateLimited));
        assert_eq!(fixture.requests.lock().unwrap().len(), 7);
    }
    fn tx_info(confirmed: bool) -> &'static str {
        use bitcoin::hashes::Hash;
        Box::leak(format!(r#"{{"txid":"{}","version":2,"locktime":0,"vin":[],"vout":[],"size":10,"weight":40,"fee":0,"status":{{"confirmed":{confirmed}}}}}"#, Txid::all_zeros()).into_boxed_str())
    }
    #[derive(Debug, Default)]
    struct AbsentTransport(std::sync::atomic::AtomicUsize);
    impl HttpTransport for AbsentTransport {
        fn execute(&self, _: reqwest::RequestBuilder) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<reqwest::Response, esplora_client::Error>> + Send + '_>> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(http::Response::builder().status(404).body("not found").unwrap().into()) })
        }
    }
    #[tokio::test]
    async fn empty_esplora_source_never_attempts_presence_request() {
        use bitcoin::hashes::Hash;
        let (_dir, _node, mut source, _) = fixture(vec![]);
        for url in ["", " ", "/"] {
            let transport = Arc::new(AbsentTransport::default());
            source.esplora_client = EsploraAsyncClient::from_client(url.into(), reqwest::Client::new())
                .with_transport(transport.clone());
            let direct = source.esplora_client.get_tx_info(&Txid::all_zeros()).await;
            let funding = source.funding_present(Txid::all_zeros()).await;
            assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 0, "unconfigured URL {url:?} reached HTTP transport");
            assert!(direct.is_err());
            assert_eq!(funding, Err(Error::TxSyncFailed));
        }
    }
    #[tokio::test]
    async fn implicit_default_source_never_attempts_funding_request() {
        use bitcoin::hashes::Hash;
        let (_dir, mut node, mut source, _) = fixture(vec![]);
        let transport = Arc::new(AbsentTransport::default());
        source.esplora_client = source.esplora_client.clone().with_transport(transport.clone());
        // Preserve the real builder's funding policy while replacing HTTP with
        // an in-memory 404. Other node components retain the original Arc.
        let verifier = node.chain_source.funding_verifier.read().unwrap().clone();
        node.chain_source = Arc::new(super::super::ChainSource {
            kind: super::super::ChainSourceKind::Esplora(source),
            sync_health: RwLock::new(super::super::SyncHealth::default()),
            funding_verifier: RwLock::new(verifier), tx_broadcaster: node.tx_broadcaster.clone(), logger: node.logger.clone(),
        });
        // All provider callers and ghost suppression share this lookup.
        let funding = node.funding_present(Txid::all_zeros()).await;
        assert_eq!(transport.0.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(funding, Err(Error::TxSyncFailed));
    }
    fn transaction(locktime: u32) -> Transaction {
        Transaction { version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::from_consensus(locktime), input: vec![], output: vec![] }
    }
    #[tokio::test]
    async fn unknown_status_is_not_presence_evidence_for_any_node_caller() {
        use bitcoin::hashes::Hash;
        let txid = Txid::all_zeros();
        let status = Box::leak(format!("/tx/{txid}/status").into_boxed_str());
        let info = Box::leak(format!("/tx/{txid}").into_boxed_str());
        let (_dir, mut node, source, _) = fixture(vec![
            (status, 200, None, r#"{"confirmed":false}"#), (info, 404, None, "not found"),
        ]);
        assert!(!source.esplora_client.get_tx_status(&txid).await.unwrap().confirmed);
        node.chain_source = Arc::new(super::super::ChainSource {
            kind: super::super::ChainSourceKind::Esplora(source),
            sync_health: RwLock::new(super::super::SyncHealth::default()),
            funding_verifier: RwLock::new(None), tx_broadcaster: node.tx_broadcaster.clone(), logger: node.logger.clone(),
        });
        // #192 balances and reservation reconciliation both use this public API.
        assert_eq!(node.funding_present(txid).await, Ok(false));
    }
    #[tokio::test(start_paused = true)]
    async fn huge_retry_after_allows_post_probe_within_300_seconds() {
        let (_dir, _node, source, fixture) = fixture(vec![
            ("/tx", 429, Some("86400"), ""), ("/tx", 200, None, ""),
        ]);
        let started = tokio::time::Instant::now();
        assert!(tokio::time::timeout(Duration::from_secs(301), source.process_broadcast_package(vec![transaction(0)])).await.is_ok());
        assert!(started.elapsed() <= Duration::from_secs(300));
        assert_eq!(fixture.posted.lock().unwrap().len(), 2);
        assert!(source.rate_limit_failure().is_none());
    }
    #[tokio::test(start_paused = true)]
    async fn newer_cooldown_cannot_extend_a_waiting_post_deadline() {
        let (_dir, _node, source, fixture) = fixture(vec![
            ("/fee-estimates", 429, Some("300"), ""), ("/tx", 200, None, ""),
        ]);
        assert_eq!(source.update_fee_rate_estimates().await, Err(Error::ChainRateLimited));
        let source = Arc::new(source);
        let broadcaster = source.clone();
        let started = tokio::time::Instant::now();
        let task = tokio::spawn(async move { broadcaster.process_broadcast_package(vec![transaction(0)]).await });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(299)).await;
        // Model a different in-flight package receiving a fresh 429 just before
        // this POST's wait expires. Its header cannot move our deadline.
        assert!(source.rate_limit.run(true, || async {
            Ok(http::Response::builder().status(429).header("retry-after", "86400").body("").unwrap().into())
        }).await.is_err());
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::time::timeout(Duration::from_secs(1), task).await.expect("POST deadline must not move").expect("broadcast task");
        assert!(started.elapsed() <= Duration::from_secs(300));
        assert_eq!(*fixture.posted.lock().unwrap(), vec![transaction(0).compute_txid()]);
        // A successful POST does not clear the newer GET cooldown.
        assert!(source.rate_limit_failure().is_some());
    }
    #[tokio::test(start_paused = true)]
    async fn parked_package_does_not_block_new_sweep_and_survives_worker_restart() {
        use lightning::chain::chaininterface::BroadcasterInterface;
        let (_dir, node, source, fixture) = fixture(vec![("/tx", 200, None, ""), ("/tx", 200, None, "")]);
        let parked = transaction(0);
        let mut sweep = transaction(1);
        // A justice/sweep input spends a commitment output, not funding.
        sweep.input.push(bitcoin::TxIn { previous_output: bitcoin::OutPoint { txid: transaction(2).compute_txid(), vout: 0 }, ..Default::default() });
        *fixture.parked.lock().unwrap() = Some(parked.compute_txid());
        let chain = Arc::new(super::super::ChainSource {
            kind: super::super::ChainSourceKind::Esplora(source),
            sync_health: RwLock::new(super::super::SyncHealth::default()),
            funding_verifier: RwLock::new(None), tx_broadcaster: node.tx_broadcaster.clone(), logger: node.logger.clone(),
        });
        let (stop, receiver) = tokio::sync::watch::channel(());
        let worker_chain = chain.clone();
        let manager = node.channel_manager.clone();
        let monitor = node.chain_monitor.clone();
        node.tx_broadcaster.broadcast_transactions(&[&parked]);
        let worker = tokio::spawn(async move { worker_chain.continuously_process_broadcast_queue(receiver, manager, monitor).await });
        for _ in 0..20 { tokio::task::yield_now().await; }
        assert_eq!(*fixture.posted.lock().unwrap(), vec![parked.compute_txid()]);
        node.tx_broadcaster.broadcast_transactions(&[&sweep]);
        for _ in 0..20 { tokio::task::yield_now().await; }
        tokio::time::advance(Duration::from_secs(300)).await;
        for _ in 0..40 { tokio::task::yield_now().await; }
        assert!(fixture.posted.lock().unwrap().contains(&sweep.compute_txid()), "a repeated 429 on one package must not withhold a new justice/sweep POST");
        stop.send(()).unwrap();
        worker.await.unwrap();
        assert_eq!(node.tx_broadcaster.interrupted_broadcasts(), vec![vec![parked.clone()]]);
        *fixture.parked.lock().unwrap() = None;
        let manager = node.channel_manager.clone();
        let monitor = node.chain_monitor.clone();
        let worker = tokio::spawn(async move { chain.continuously_process_broadcast_queue(stop.subscribe(), manager, monitor).await });
        for _ in 0..20 { tokio::task::yield_now().await; }
        tokio::time::advance(Duration::from_secs(300)).await;
        for _ in 0..40 { tokio::task::yield_now().await; }
        assert!(node.tx_broadcaster.interrupted_broadcasts().is_empty());
        assert_eq!(fixture.posted.lock().unwrap().iter().filter(|&&id| id == sweep.compute_txid()).count(), 1);
        worker.abort();
        let _ = worker.await;
    }

}
