use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use lightning::io;
use lightning::util::persist::{
    KVStore, KVStoreSync, CHANNEL_MANAGER_PERSISTENCE_KEY,
    CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE, CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
};

use super::{BuildError, NodeBuilder};
use crate::io::test_utils::InMemoryStore;
use crate::types::DynStore;

struct ChannelManagerReadFailingStore(InMemoryStore, io::ErrorKind);

impl ChannelManagerReadFailingStore {
    fn fails_read(primary_namespace: &str, secondary_namespace: &str, key: &str) -> bool {
        primary_namespace == CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE
            && secondary_namespace == CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE
            && key == CHANNEL_MANAGER_PERSISTENCE_KEY
    }
}

impl KVStoreSync for ChannelManagerReadFailingStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> io::Result<Vec<u8>> {
        if Self::fails_read(primary_namespace, secondary_namespace, key) {
            return Err(io::Error::new(self.1, "channel manager read failed"));
        }
        KVStoreSync::read(&self.0, primary_namespace, secondary_namespace, key)
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> io::Result<()> {
        KVStoreSync::write(&self.0, primary_namespace, secondary_namespace, key, buf)
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        lazy: bool,
    ) -> io::Result<()> {
        KVStoreSync::remove(&self.0, primary_namespace, secondary_namespace, key, lazy)
    }

    fn list(&self, primary_namespace: &str, secondary_namespace: &str) -> io::Result<Vec<String>> {
        KVStoreSync::list(&self.0, primary_namespace, secondary_namespace)
    }
}

impl KVStore for ChannelManagerReadFailingStore {
    fn read(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, io::Error>> + 'static + Send>> {
        let res = KVStoreSync::read(self, primary_namespace, secondary_namespace, key);
        Box::pin(async move { res })
    }

    fn write(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        buf: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + 'static + Send>> {
        let res = KVStoreSync::write(self, primary_namespace, secondary_namespace, key, buf);
        Box::pin(async move { res })
    }

    fn remove(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
        key: &str,
        lazy: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), io::Error>> + 'static + Send>> {
        let res = KVStoreSync::remove(self, primary_namespace, secondary_namespace, key, lazy);
        Box::pin(async move { res })
    }

    fn list(
        &self,
        primary_namespace: &str,
        secondary_namespace: &str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, io::Error>> + 'static + Send>> {
        let res = KVStoreSync::list(self, primary_namespace, secondary_namespace);
        Box::pin(async move { res })
    }
}

#[test]
fn channel_manager_read_failure_fails_build() {
    for kind in [
        io::ErrorKind::Other,
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::Interrupted,
        io::ErrorKind::InvalidData,
    ] {
        let mut builder = NodeBuilder::new();
        builder.set_entropy_seed_bytes([42; 64]);
        builder.set_log_facade_logger();
        let store: Arc<DynStore> =
            Arc::new(ChannelManagerReadFailingStore(InMemoryStore::new(), kind));

        let result = builder.build_with_store(store);

        assert!(
            matches!(result, Err(BuildError::ReadFailed)),
            "must fail closed on {kind:?}"
        );
    }
}

#[test]
fn missing_manager_starts_fresh_but_corrupt_bytes_fail_and_valid_state_restores() {
    use lightning::util::ser::Writeable;
    let mut builder = NodeBuilder::new();
    builder.set_entropy_seed_bytes([42; 64]);
    builder.set_log_facade_logger();
    let store = Arc::new(InMemoryStore::new());
    let node = builder
        .build_with_store(store.clone())
        .expect("NotFound starts a fresh node");
    // A fresh manager would use height zero, so this detects silently discarding
    // valid serialized state (inbound payment secrets alone are stateless).
    let header = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Bitcoin).header;
    lightning::chain::Confirm::best_block_updated(&*node.channel_manager, &header, 42);
    KVStoreSync::write(
        &*store,
        CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
        CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
        CHANNEL_MANAGER_PERSISTENCE_KEY,
        node.channel_manager.encode(),
    )
    .unwrap();
    drop(node);
    let restored = builder.build_with_store(store.clone()).unwrap();
    assert_eq!(restored.channel_manager.current_best_block().height, 42);
    drop(restored);
    KVStoreSync::write(
        &*store,
        CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
        CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
        CHANNEL_MANAGER_PERSISTENCE_KEY,
        vec![0xff],
    )
    .unwrap();
    assert!(matches!(
        builder.build_with_store(store),
        Err(BuildError::ReadFailed)
    ));
}
