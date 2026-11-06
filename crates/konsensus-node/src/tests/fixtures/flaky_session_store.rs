//! A session store whose saves can be made to fail, for failure injection in tests.
use konsensus_core::NodeId;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

#[derive(Default)]
pub(crate) struct FlakySessionStore {
    data: Mutex<HashMap<NodeId, Vec<u8>>>,
    fail: AtomicBool,
}

impl FlakySessionStore {
    pub(crate) fn fail(&self, fail: bool) {
        self.fail.store(fail, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl konsensus_crypto::SessionStore for FlakySessionStore {
    async fn save_session(&self, peer: &NodeId, state: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if self.fail.load(Ordering::SeqCst) {
            return Err("test: disk full".into());
        }
        self.data.lock().unwrap().insert(*peer, state.to_vec());
        Ok(())
    }
    async fn load_session(&self, peer: &NodeId) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.lock().unwrap().get(peer).cloned())
    }
    async fn delete_session(&self, peer: &NodeId) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.data.lock().unwrap().remove(peer);
        Ok(())
    }
    async fn list_sessions(&self) -> Result<Vec<NodeId>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.data.lock().unwrap().keys().copied().collect())
    }
}
