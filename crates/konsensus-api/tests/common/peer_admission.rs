//! Transport probe for admission ordering. Storage and registry remain real.
use crate::common;
use async_trait::async_trait;
use konsensus_api::state::AppState;
use konsensus_core::{
    envelope::UkmEnvelope,
    traits::{MessageTransport, TransportError},
    types::NodeId,
};
use konsensus_message::PeerRegistry;
use konsensus_storage::Storage;
use std::sync::{Arc, Mutex};

pub struct AdmissionTransport {
    pub storage: Arc<dyn Storage>,
    pub registry: Arc<tokio::sync::RwLock<PeerRegistry>>,
    pub calls: Mutex<Vec<&'static str>>,
    pub dial_started: tokio::sync::Notify,
    pub finish_dial: tokio::sync::Notify,
    pub live: Mutex<(bool, bool, bool)>, // whitelist, connection, supervision
    pub supervised_addrs: Mutex<Vec<String>>,
    pub dial: &'static str,
}
#[async_trait]
impl MessageTransport for AdmissionTransport {
    async fn send(&self, _: &NodeId, _: &UkmEnvelope) -> Result<(), TransportError> {
        unreachable!()
    }
    async fn recv(&self) -> Result<UkmEnvelope, TransportError> {
        futures::future::pending().await
    }
    async fn disconnect(&self, _: &NodeId) -> Result<(), TransportError> {
        self.live.lock().unwrap().1 = false;
        Ok(())
    }
    async fn is_connected(&self, _: &NodeId) -> bool {
        self.live.lock().unwrap().1
    }
    async fn connected_peers(&self) -> Vec<NodeId> {
        vec![]
    }
    async fn add_to_whitelist(&self, peer: &NodeId) {
        assert!(
            self.storage.get_peer(peer).await.unwrap().is_some(),
            "persist before whitelist"
        );
        assert!(
            self.registry.try_read().is_err(),
            "live changes must hold the registry write lock"
        );
        self.live.lock().unwrap().0 = true;
        self.calls.lock().unwrap().push("whitelist");
    }
    async fn connect(&self, peer: &NodeId, addr: &str) -> Result<(), TransportError> {
        assert_eq!(
            self.storage
                .get_peer(peer)
                .await
                .unwrap()
                .unwrap()
                .address
                .as_deref(),
            Some(addr)
        );
        assert_eq!(*self.calls.lock().unwrap(), ["whitelist"]);
        self.calls.lock().unwrap().push("dial");
        match self.dial {
            "gate" => {
                self.dial_started.notify_one();
                self.finish_dial.notified().await;
                // NoiseTransport::connect remembers the dial target itself,
                // before the handler's generation check runs.
                self.supervised_addrs.lock().unwrap().push(addr.to_string());
                let mut live = self.live.lock().unwrap();
                live.1 = true;
                live.2 = true;
                Ok(())
            }
            "ok" => Ok(()),
            "timeout" => futures::future::pending().await,
            _ => Err(TransportError::ConnectionFailed(
                "connection refused".into(),
            )),
        }
    }
    async fn remove_from_whitelist(&self, _: &NodeId) {
        let mut live = self.live.lock().unwrap();
        live.0 = false;
        live.2 = false;
    }
    async fn supervise_peer(&self, _: &NodeId, addr: &str) {
        self.supervised_addrs.lock().unwrap().push(addr.to_string());
        self.live.lock().unwrap().2 = true;
        self.calls.lock().unwrap().push("supervise");
    }
}

#[allow(dead_code)] // Pairing tests construct a custom state with this probe.
pub fn state(
    storage: Arc<dyn Storage>,
    dial: &'static str,
) -> (Arc<AppState>, Arc<AdmissionTransport>) {
    let base = common::test_state_with_storage(storage);
    let transport = Arc::new(AdmissionTransport {
        storage: base.storage.clone(),
        registry: base.peer_registry.clone(),
        calls: Mutex::new(vec![]),
        dial_started: Default::default(),
        finish_dial: Default::default(),
        live: Default::default(),
        dial,
        supervised_addrs: Default::default(),
    });
    (
        Arc::new(AppState {
            transport: transport.clone(),
            ..(*base).clone()
        }),
        transport,
    )
}
