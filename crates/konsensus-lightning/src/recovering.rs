//! Offline startup boundary. One owner retries only pre-task chain-source failures.
//! Readers never start tasks; a successfully constructed backend is never rebuilt.
use async_trait::async_trait;
use futures::stream::BoxStream;
use konsensus_core::traits::{
    lightning::*,
    liquidity::{LiquidityInfo, LiquidityQuote, LiquidityReceipt},
};
use std::{
    future::Future,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{watch, Mutex},
    task::JoinHandle,
};

struct State {
    backend: Option<Arc<dyn LightningProvider>>,
    readiness: LightningReadiness,
}

pub struct RecoveringLightning {
    state: Arc<RwLock<State>>,
    stop: watch::Sender<bool>,
    worker: Mutex<Option<JoinHandle<Result<(), LightningError>>>>,
    policy: RoutingFeePolicy,
}

fn transition(state: &mut State, phase: &str, ready: bool) {
    if state.readiness.state == phase && state.readiness.money_ready == ready {
        return;
    }
    let sequence = state.readiness.events.last().map_or(1, |e| e.sequence + 1);
    state.readiness.state = phase.into();
    state.readiness.money_ready = ready;
    state.readiness.events.push(ReadinessEvent {
        sequence,
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
        state: phase.into(),
        money_ready: ready,
    });
    if state.readiness.events.len() > 32 {
        state.readiness.events.remove(0);
    }
    tracing::info!(
        state = phase,
        money_ready = ready,
        sequence,
        "Lightning readiness changed"
    );
}

impl RecoveringLightning {
    /// Runs the bounded initial startup, then owns exactly one retry/monitor task.
    /// Permanent local errors propagate initially; after offline boot they stop
    /// retries in `failed` state. Factory cancellation drops any unstarted LDK.
    pub async fn new<F, Fut>(
        mut factory: F,
        policy: RoutingFeePolicy,
    ) -> Result<Self, LightningError>
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = Result<Arc<dyn LightningProvider>, LightningError>> + Send,
    {
        let backend = match factory().await {
            Ok(p) => Some(p),
            Err(LightningError::ChainSourceUnavailable { .. }) => None,
            Err(e) => return Err(e),
        };
        let state = Arc::new(RwLock::new(State {
            backend,
            readiness: LightningReadiness {
                money_ready: false,
                state: String::new(),
                retry_attempt: 0,
                retry_after_secs: None,
                events: Vec::new(),
            },
        }));
        {
            let mut s = state.write().unwrap();
            let phase = if s.backend.is_some() {
                "synchronizing"
            } else {
                "offline"
            };
            transition(&mut s, phase, false);
        }
        let (stop, mut stop_rx) = watch::channel(false);
        let shared = state.clone();
        let worker = tokio::spawn(async move {
            let mut factory = Some(factory);
            let mut delay = Duration::from_secs(5);
            loop {
                let backend = shared.read().unwrap().backend.clone();
                if let Some(backend) = backend {
                    drop(factory.take());
                    let ready = tokio::select! {
                        biased;
                        _ = stop_rx.changed() => break,
                        ready = backend.money_ready() => ready,
                    };
                    let mut s = shared.write().unwrap();
                    if *stop_rx.borrow() {
                        break;
                    }
                    transition(&mut s, if ready { "ready" } else { "synchronizing" }, ready);
                    s.readiness.retry_after_secs = None;
                } else {
                    shared.write().unwrap().readiness.retry_after_secs = Some(delay.as_secs());
                    tokio::select! { biased;
                        _ = stop_rx.changed() => break,
                        _ = tokio::time::sleep(delay) => {},
                    }
                    {
                        let mut s = shared.write().unwrap();
                        s.readiness.retry_attempt += 1;
                        s.readiness.retry_after_secs = None;
                        transition(&mut s, "retrying", false);
                    }
                    let result = tokio::select! { biased;
                        _ = stop_rx.changed() => break,
                        result = (factory.as_mut().expect("factory exists until startup succeeds"))() => result,
                    };
                    let mut s = shared.write().unwrap();
                    match result {
                        Ok(backend) => {
                            s.backend = Some(backend);
                            transition(&mut s, "synchronizing", false);
                        }
                        Err(LightningError::ChainSourceUnavailable { .. }) => {
                            transition(&mut s, "offline", false);
                            delay = (delay * 2).min(Duration::from_secs(60));
                        }
                        Err(_) => {
                            // Never expose arbitrary backend text (URLs/credentials).
                            transition(&mut s, "failed", false);
                            break;
                        }
                    }
                    continue;
                }
                tokio::select! { biased;
                    _ = stop_rx.changed() => break,
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {},
                }
            }
            // Cleanup belongs to the worker even if its caller cancels shutdown.
            // Never leave ChannelMonitor persistence to runtime teardown/Drop.
            let backend = shared.write().unwrap().backend.take();
            let result = if let Some(p) = backend {
                p.shutdown().await
            } else {
                Ok(())
            };
            let mut s = shared.write().unwrap();
            if *stop_rx.borrow() || stop_rx.has_changed().is_err() {
                transition(&mut s, "stopped", false);
                s.readiness.retry_after_secs = None;
            }
            result
        });
        Ok(Self {
            state,
            stop,
            worker: Mutex::new(Some(worker)),
            policy,
        })
    }

    fn backend(&self) -> Result<Arc<dyn LightningProvider>, LightningError> {
        let state = self.state.read().unwrap();
        if *self.stop.borrow() || !state.readiness.money_ready {
            return Err(LightningError::NotReady);
        }
        state.backend.clone().ok_or(LightningError::NotReady)
    }
}

impl Drop for RecoveringLightning {
    fn drop(&mut self) {
        // Sender drop also cancels the worker. It owns state, never this wrapper.
        let _ = self.stop.send(true);
    }
}

#[async_trait]
impl LightningProvider for RecoveringLightning {
    async fn readiness(&self) -> LightningReadiness {
        self.state.read().unwrap().readiness.clone()
    }
    async fn money_ready(&self) -> bool {
        !*self.stop.borrow() && self.state.read().unwrap().readiness.money_ready
    }
    async fn is_available(&self) -> bool {
        self.money_ready().await
    }
    async fn is_payment_capable(&self) -> bool {
        match self.backend() {
            Ok(p) => p.is_payment_capable().await,
            Err(_) => false,
        }
    }
    async fn wallet_sync(&self) -> WalletSync {
        match self.backend() {
            Ok(p) => p.wallet_sync().await,
            Err(_) => WalletSync::NeverSynced,
        }
    }
    fn routing_fee_policy(&self) -> RoutingFeePolicy {
        self.policy
    }
    fn liquidity_info(&self) -> LiquidityInfo {
        self.state
            .read()
            .unwrap()
            .backend
            .as_ref()
            .map(|p| p.liquidity_info())
            .unwrap_or_default()
    }
    fn inbound_keysend_stream_requires_reconciliation(&self) -> bool {
        true
    }
    async fn shutdown(&self) -> Result<(), LightningError> {
        // Serialize shutdown callers through completion, including persistence.
        let mut worker = self.worker.lock().await;
        self.stop.send_replace(true);
        {
            let mut s = self.state.write().unwrap();
            transition(&mut s, "stopped", false);
            s.readiness.retry_after_secs = None;
        }
        if let Some(task) = worker.as_mut() {
            let result = task
                .await
                .map_err(|_| LightningError::Backend("readiness worker failed".into()))?;
            worker.take();
            result?;
        }
        let mut s = self.state.write().unwrap();
        transition(&mut s, "stopped", false);
        s.readiness.retry_after_secs = None;
        Ok(())
    }
    async fn quote_liquidity(
        &self,
        owner: &str,
        gross_msat: u64,
        max_fee_msat: u64,
    ) -> Result<LiquidityQuote, LightningError> {
        let p = self.backend()?;
        p.quote_liquidity(owner, gross_msat, max_fee_msat).await
    }
    fn liquidity_quote(&self, owner: &str, id: &str) -> Result<LiquidityQuote, LightningError> {
        let p = self.backend()?;
        p.liquidity_quote(owner, id)
    }
    async fn accept_liquidity(&self, owner: &str, id: &str) -> Result<Invoice, LightningError> {
        let p = self.backend()?;
        p.accept_liquidity(owner, id).await
    }
    async fn is_funding_payment(&self, hash: &str) -> Result<bool, LightningError> {
        let p = self.backend()?;
        p.is_funding_payment(hash).await
    }
    async fn liquidity_receipt(
        &self,
        hash: &str,
    ) -> Result<Option<LiquidityReceipt>, LightningError> {
        let p = self.backend()?;
        p.liquidity_receipt(hash).await
    }
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        let p = self.backend()?;
        p.create_invoice(amount_msat, description, expiry_secs)
            .await
    }
    async fn create_stateless_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        let p = self.backend()?;
        p.create_stateless_invoice(amount_msat, description, expiry_secs)
            .await
    }
    async fn keysend_with_fee_limit(
        &self,
        dest: &str,
        amount: u64,
        memo: Option<&str>,
        max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        let p = self.backend()?;
        p.keysend_with_fee_limit(dest, amount, memo, max_fee_msat)
            .await
    }
    async fn pay_invoice(&self, bolt11: &str) -> Result<PaymentDetails, LightningError> {
        let p = self.backend()?;
        p.pay_invoice(bolt11).await
    }
    async fn pay_invoice_with_fee_limit(
        &self,
        bolt11: &str,
        max_fee_msat: u64,
    ) -> Result<PaymentDetails, LightningError> {
        let p = self.backend()?;
        p.pay_invoice_with_fee_limit(bolt11, max_fee_msat).await
    }
    async fn get_payment_status(
        &self,
        payment_hash: &str,
    ) -> Result<PaymentDetails, LightningError> {
        let p = self.backend()?;
        p.get_payment_status(payment_hash).await
    }
    async fn verify_payment(&self, payment_hash: &str) -> Result<PaymentDetails, LightningError> {
        let p = self.backend()?;
        p.verify_payment(payment_hash).await
    }
    async fn get_balance_msat(&self) -> Result<u64, LightningError> {
        let p = self.backend()?;
        p.get_balance_msat().await
    }
    async fn list_payments(&self, limit: u32) -> Result<Vec<PaymentDetails>, LightningError> {
        let p = self.backend()?;
        p.list_payments(limit).await
    }
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError> {
        let p = self.backend()?;
        p.list_channels().await
    }
    async fn keysend(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        memo: Option<&str>,
    ) -> Result<PaymentDetails, LightningError> {
        let p = self.backend()?;
        p.keysend(dest_pubkey, amount_msat, memo).await
    }
    async fn keysend_with_binding(
        &self,
        dest_pubkey: &str,
        amount_msat: u64,
        binding_tlv: &[u8],
    ) -> Result<PaymentDetails, LightningError> {
        let p = self.backend()?;
        p.keysend_with_binding(dest_pubkey, amount_msat, binding_tlv)
            .await
    }
    async fn watch_inbound_keysend(
        &self,
    ) -> Result<BoxStream<'static, InboundPayment>, LightningError> {
        let p = self.backend()?;
        p.watch_inbound_keysend().await
    }
    async fn create_hodl_invoice(
        &self,
        payment_hash: &str,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError> {
        let p = self.backend()?;
        p.create_hodl_invoice(payment_hash, amount_msat, description, expiry_secs)
            .await
    }
    async fn settle_hodl_invoice(&self, preimage: &str) -> Result<(), LightningError> {
        let p = self.backend()?;
        p.settle_hodl_invoice(preimage).await
    }
    async fn cancel_hodl_invoice(&self, payment_hash: &str) -> Result<(), LightningError> {
        let p = self.backend()?;
        p.cancel_hodl_invoice(payment_hash).await
    }
    async fn get_node_pubkey(&self) -> Option<String> {
        let backend = self.state.read().unwrap().backend.clone();
        match backend {
            Some(p) => p.get_node_pubkey().await,
            None => None,
        }
    }
    async fn get_funding_address(&self) -> Option<String> {
        match self.backend() {
            Ok(p) => p.get_funding_address().await,
            Err(_) => None,
        }
    }
    async fn send_onchain(
        &self,
        address: &str,
        amount_sats: u64,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        let p = self.backend()?;
        p.send_onchain(address, amount_sats, fee_rate_sat_per_vb)
            .await
    }
    async fn open_channel(
        &self,
        peer_pubkey: &str,
        peer_addr: &str,
        amount_sats: u64,
        announce: bool,
        fee_rate_sat_per_vb: Option<f32>,
    ) -> Result<String, LightningError> {
        let p = self.backend()?;
        p.open_channel(
            peer_pubkey,
            peer_addr,
            amount_sats,
            announce,
            fee_rate_sat_per_vb,
        )
        .await
    }
    async fn close_channel(
        &self,
        channel_id: &str,
        force: bool,
    ) -> Result<Option<String>, LightningError> {
        let p = self.backend()?;
        p.close_channel(channel_id, force).await
    }
}
