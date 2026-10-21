// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use bitcoin::secp256k1::PublicKey;
use lightning::impl_writeable_tlv_based;
use lightning::util::persist::KVStoreSync;
use lightning::util::ser::{Readable, ReadableArgs, Writeable, Writer};

use crate::io::{
	PEER_INFO_PERSISTENCE_KEY, PEER_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
	PEER_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
};
use crate::logger::{log_error, LdkLogger, LdkRecord, LogLevel};
use crate::types::DynStore;
use crate::{Error, SocketAddress};

/// Preserve normal diagnostics; only marked starter peers lower identifying
/// records. Keep a fixed ERROR signal without leaking the address or identity.
pub(crate) struct PeerLogger<'a, L: Deref> {
	logger: &'a L,
	suppressed: bool,
}
impl<L: Deref> LdkLogger for PeerLogger<'_, L> where L::Target: LdkLogger {
	fn log(&self, mut record: LdkRecord) {
		if self.suppressed && record.level >= LogLevel::Info {
			if record.level == LogLevel::Error {
				log_error!(self.logger, "Starter peer operation failed");
			}
			record.level = LogLevel::Debug;
		}
		self.logger.log(record);
	}
}

pub struct PeerStore<L: Deref>
where
	L::Target: LdkLogger,
{
	peers: RwLock<HashMap<PublicKey, PeerInfo>>,
	kv_store: Arc<DynStore>,
	logger: L,
}

impl<L: Deref> PeerStore<L>
where
	L::Target: LdkLogger,
{
	pub(crate) fn new(kv_store: Arc<DynStore>, logger: L) -> Self {
		let peers = RwLock::new(HashMap::new());
		Self { peers, kv_store, logger }
	}

	pub(crate) fn peer_logger(&self, node_id: &PublicKey) -> PeerLogger<'_, L> {
		let suppressed = match KVStoreSync::read(
			&*self.kv_store, "bitsov_starter_peers", "", &node_id.to_string(),
		) {
			Ok(_) => true,
			Err(e) => e.kind() != lightning::io::ErrorKind::NotFound,
		};
		PeerLogger { logger: &self.logger, suppressed }
	}

	pub(crate) fn add_peer(&self, peer_info: PeerInfo) -> Result<(), Error> {
		let mut locked_peers = self.peers.write().unwrap();

		// Permanent address suppression is independent of the serialized peer
		// list and survives restarts. Unknown storage errors fail closed.
		match KVStoreSync::read(
			&*self.kv_store,
			"bitsov_starter_peers",
			"",
			&peer_info.node_id.to_string(),
		) {
			Ok(_) => return Ok(()),
			Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => {}
			Err(_) => return Err(Error::PersistenceFailed),
		}

		if locked_peers.contains_key(&peer_info.node_id) {
			return Ok(());
		}

		locked_peers.insert(peer_info.node_id, peer_info);
		self.persist_peers(&*locked_peers)
	}

	/// Forget an address before opening a starter channel, and prevent the
	/// normal open/connect paths from re-persisting it, including after restart.
	pub(crate) fn suppress_address(&self, node_id: PublicKey) -> Result<(), Error> {
		let mut peers = self.peers.write().unwrap();
		peers.remove(&node_id);
		self.persist_peers(&*peers)?;
		KVStoreSync::write(
			&*self.kv_store,
			"bitsov_starter_peers",
			"",
			&node_id.to_string(),
			vec![1],
		)
		.map_err(|_| Error::PersistenceFailed)
	}

	pub(crate) fn remove_peer(&self, node_id: &PublicKey) -> Result<(), Error> {
		let mut locked_peers = self.peers.write().unwrap();

		locked_peers.remove(node_id);
		self.persist_peers(&*locked_peers)
	}

	pub(crate) fn list_peers(&self) -> Vec<PeerInfo> {
		self.peers.read().unwrap().values().cloned().collect()
	}

	pub(crate) fn get_peer(&self, node_id: &PublicKey) -> Option<PeerInfo> {
		self.peers.read().unwrap().get(node_id).cloned()
	}

	fn persist_peers(&self, locked_peers: &HashMap<PublicKey, PeerInfo>) -> Result<(), Error> {
		let data = PeerStoreSerWrapper(&*locked_peers).encode();
		KVStoreSync::write(
			&*self.kv_store,
			PEER_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_KEY,
			data,
		)
		.map_err(|e| {
			log_error!(
				self.logger,
				"Write for key {}/{}/{} failed due to: {}",
				PEER_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
				PEER_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
				PEER_INFO_PERSISTENCE_KEY,
				e
			);
			Error::PersistenceFailed
		})?;
		Ok(())
	}
}

impl<L: Deref> ReadableArgs<(Arc<DynStore>, L)> for PeerStore<L>
where
	L::Target: LdkLogger,
{
	#[inline]
	fn read<R: lightning::io::Read>(
		reader: &mut R, args: (Arc<DynStore>, L),
	) -> Result<Self, lightning::ln::msgs::DecodeError> {
		let (kv_store, logger) = args;
		let read_peers: PeerStoreDeserWrapper = Readable::read(reader)?;
		let peers: RwLock<HashMap<PublicKey, PeerInfo>> = RwLock::new(read_peers.0);
		Ok(Self { peers, kv_store, logger })
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerStoreDeserWrapper(HashMap<PublicKey, PeerInfo>);

impl Readable for PeerStoreDeserWrapper {
	fn read<R: lightning::io::Read>(
		reader: &mut R,
	) -> Result<Self, lightning::ln::msgs::DecodeError> {
		let len: u16 = Readable::read(reader)?;
		let mut peers = HashMap::with_capacity(len as usize);
		for _ in 0..len {
			let k: PublicKey = Readable::read(reader)?;
			let v: PeerInfo = Readable::read(reader)?;
			peers.insert(k, v);
		}
		Ok(Self(peers))
	}
}

pub(crate) struct PeerStoreSerWrapper<'a>(&'a HashMap<PublicKey, PeerInfo>);

impl Writeable for PeerStoreSerWrapper<'_> {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
		(self.0.len() as u16).write(writer)?;
		for (k, v) in self.0.iter() {
			k.write(writer)?;
			v.write(writer)?;
		}
		Ok(())
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerInfo {
	pub node_id: PublicKey,
	pub address: SocketAddress,
}

impl_writeable_tlv_based!(PeerInfo, {
	(0, node_id, required),
	(2, address, required),
});

#[cfg(test)]
mod tests {
	use std::str::FromStr;
	use std::sync::Arc;

	use lightning::util::test_utils::TestLogger;

	use super::*;
	use crate::io::test_utils::InMemoryStore;

	#[test]
	fn peer_info_persistence() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let logger = Arc::new(TestLogger::new());
		let peer_store = PeerStore::new(Arc::clone(&store), Arc::clone(&logger));

		let node_id = PublicKey::from_str(
			"0276607124ebe6a6c9338517b6f485825b27c2dcc0b9fc2aa6a4c0df91194e5993",
		)
		.unwrap();
		let address = SocketAddress::from_str("127.0.0.1:9738").unwrap();
		let expected_peer_info = PeerInfo { node_id, address };
		assert!(KVStoreSync::read(
			&*store,
			PEER_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_KEY,
		)
		.is_err());
		peer_store.add_peer(expected_peer_info.clone()).unwrap();

		// Check we can read back what we persisted.
		let persisted_bytes = KVStoreSync::read(
			&*store,
			PEER_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_KEY,
		)
		.unwrap();
		let deser_peer_store =
			PeerStore::read(&mut &persisted_bytes[..], (Arc::clone(&store), logger)).unwrap();

		let peers = deser_peer_store.list_peers();
		assert_eq!(peers.len(), 1);
		assert_eq!(peers[0], expected_peer_info);
		assert_eq!(deser_peer_store.get_peer(&node_id), Some(expected_peer_info));
	}
}

#[cfg(test)]
mod starter_privacy_tests {
	use super::*;
	use lightning::util::test_utils::TestLogger;
	use lightning_persister::fs_store::FilesystemStore;
	use std::str::FromStr;

	#[test]
	fn starter_peer_address_is_removed_and_cannot_be_repersisted_after_restart() {
		let dir = tempfile::tempdir().unwrap();
		let store: Arc<DynStore> = Arc::new(FilesystemStore::new(dir.path().to_path_buf()));
		let logger = Arc::new(TestLogger::new());
		let peers = PeerStore::new(store.clone(), logger.clone());
		let node_id = PublicKey::from_str(
			"0276607124ebe6a6c9338517b6f485825b27c2dcc0b9fc2aa6a4c0df91194e5993",
		)
		.unwrap();
		let peer = PeerInfo {
			node_id,
			address: SocketAddress::from_str("192.0.2.17:9735").unwrap(),
		};
		peers.add_peer(peer.clone()).unwrap();
		peers.suppress_address(node_id).unwrap();
		peers.add_peer(peer.clone()).unwrap(); // channel creation's ordinary add
		let bytes = KVStoreSync::read(
			&*store,
			PEER_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_KEY,
		)
		.unwrap();
		drop(peers);
		drop(store);
		let store: Arc<DynStore> = Arc::new(FilesystemStore::new(dir.path().to_path_buf()));
		let restarted = PeerStore::read(&mut &bytes[..], (store.clone(), logger)).unwrap();
		assert!(restarted.list_peers().is_empty());
		restarted.add_peer(peer).unwrap();
		assert!(restarted.list_peers().is_empty());
		let bytes = KVStoreSync::read(
			&*store,
			PEER_INFO_PERSISTENCE_PRIMARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_SECONDARY_NAMESPACE,
			PEER_INFO_PERSISTENCE_KEY,
		)
		.unwrap();
		assert!(!bytes.windows(4).any(|b| b == [192, 0, 2, 17]));
	}
}
