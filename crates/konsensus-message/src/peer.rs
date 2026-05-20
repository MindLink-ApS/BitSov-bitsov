//! Peer discovery and management — static peer configuration.
//!
//! In the BitSov mesh, peers are explicitly opted-in via whitelist (Principle 3:
//! Closed Mesh). This module provides the `PeerRegistry` for managing known peers
//! and their network addresses.
//!
//! # Discovery modes
//!
//! - **Static**: Peers are configured in `konsensus.toml` with their NodeId and address.
//!   This is the foundational mode — sufficient for the 3-node test network and production
//!   deployments where peers are known in advance.
//!
//! - **Future**: DNS-based discovery, mDNS for LAN, and peer exchange protocols can be
//!   added as additional discovery backends without changing the `PeerRegistry` API.
//!
//! # Integration with transport
//!
//! The `PeerRegistry` produces a list of `PeerEntry` records that the transport layer
//! uses to establish connections. It also provides the whitelist for the transport config.

use std::collections::HashMap;
use std::net::SocketAddr;

use konsensus_core::types::NodeId;
use serde::{Deserialize, Serialize};

/// A known peer with its network address and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEntry {
    /// The peer's Ed25519 public key (node identity).
    pub node_id: NodeId,
    /// The peer's network address (host:port).
    pub addr: SocketAddr,
    /// Optional human-readable label for this peer.
    pub label: Option<String>,
    /// Whether to automatically connect on node startup.
    pub auto_connect: bool,
}

/// Configuration block for static peers (parsed from `konsensus.toml`).
///
/// # Example TOML
///
/// ```toml
/// [[peers]]
/// node_id = "abc123..."
/// addr = "192.168.1.10:9735"
/// label = "Alice's node"
/// auto_connect = true
///
/// [[peers]]
/// node_id = "def456..."
/// addr = "10.0.0.5:9735"
/// auto_connect = false
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    /// Static peer entries.
    pub peers: Vec<PeerEntry>,
}

/// Registry of known peers, providing lookup, whitelist generation, and
/// auto-connect lists for the transport layer.
pub struct PeerRegistry {
    /// Known peers indexed by NodeId.
    peers: HashMap<NodeId, PeerEntry>,
}

impl PeerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Create a registry from a static peer configuration.
    pub fn from_config(config: &PeerConfig) -> Self {
        let mut registry = Self::new();
        for entry in &config.peers {
            registry.add(entry.clone());
        }
        registry
    }

    /// Add a peer to the registry.
    ///
    /// If a peer with the same NodeId already exists, it is replaced.
    pub fn add(&mut self, entry: PeerEntry) {
        self.peers.insert(entry.node_id, entry);
    }

    /// Remove a peer from the registry.
    pub fn remove(&mut self, node_id: &NodeId) -> Option<PeerEntry> {
        self.peers.remove(node_id)
    }

    /// Look up a peer by NodeId.
    pub fn get(&self, node_id: &NodeId) -> Option<&PeerEntry> {
        self.peers.get(node_id)
    }

    /// Get the network address for a peer.
    pub fn addr(&self, node_id: &NodeId) -> Option<SocketAddr> {
        self.peers.get(node_id).map(|e| e.addr)
    }

    /// Get the list of all known peer NodeIds.
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.peers.keys().copied().collect()
    }

    /// Get all peer entries.
    pub fn all(&self) -> Vec<&PeerEntry> {
        self.peers.values().collect()
    }

    /// Get the whitelist — all known peer NodeIds.
    ///
    /// Used to configure the transport's whitelist (Principle 3: Closed Mesh).
    pub fn whitelist(&self) -> Vec<NodeId> {
        self.node_ids()
    }

    /// Get the list of peers marked for auto-connect.
    ///
    /// These peers will be connected to automatically on node startup.
    pub fn auto_connect_peers(&self) -> Vec<&PeerEntry> {
        self.peers.values().filter(|e| e.auto_connect).collect()
    }

    /// Number of known peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Check if a NodeId is in the registry (i.e., whitelisted).
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.peers.contains_key(node_id)
    }

    /// Update the address for an existing peer.
    ///
    /// Returns `true` if the peer was found and updated, `false` otherwise.
    pub fn update_addr(&mut self, node_id: &NodeId, addr: SocketAddr) -> bool {
        if let Some(entry) = self.peers.get_mut(node_id) {
            entry.addr = addr;
            true
        } else {
            false
        }
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(seed: u8) -> NodeId {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        NodeId::from_verifying_key(&signing.verifying_key())
    }

    fn make_entry(seed: u8, port: u16, auto_connect: bool) -> PeerEntry {
        PeerEntry {
            node_id: make_node_id(seed),
            addr: format!("10.0.0.{seed}:{port}").parse().unwrap(),
            label: Some(format!("node-{seed}")),
            auto_connect,
        }
    }

    #[test]
    fn empty_registry() {
        let reg = PeerRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.whitelist().is_empty());
        assert!(reg.auto_connect_peers().is_empty());
    }

    #[test]
    fn add_and_lookup() {
        let mut reg = PeerRegistry::new();
        let entry = make_entry(1, 9735, true);
        let node_id = entry.node_id;

        reg.add(entry);

        assert_eq!(reg.len(), 1);
        assert!(reg.contains(&node_id));
        assert_eq!(reg.get(&node_id).unwrap().label.as_deref(), Some("node-1"));
        assert_eq!(
            reg.addr(&node_id).unwrap(),
            "10.0.0.1:9735".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn remove_peer() {
        let mut reg = PeerRegistry::new();
        let entry = make_entry(1, 9735, true);
        let node_id = entry.node_id;

        reg.add(entry);
        assert!(reg.contains(&node_id));

        let removed = reg.remove(&node_id);
        assert!(removed.is_some());
        assert!(!reg.contains(&node_id));
        assert!(reg.is_empty());
    }

    #[test]
    fn whitelist_from_peers() {
        let mut reg = PeerRegistry::new();
        reg.add(make_entry(1, 9735, true));
        reg.add(make_entry(2, 9735, false));
        reg.add(make_entry(3, 9735, true));

        let whitelist = reg.whitelist();
        assert_eq!(whitelist.len(), 3);
        assert!(whitelist.contains(&make_node_id(1)));
        assert!(whitelist.contains(&make_node_id(2)));
        assert!(whitelist.contains(&make_node_id(3)));
    }

    #[test]
    fn auto_connect_filters_correctly() {
        let mut reg = PeerRegistry::new();
        reg.add(make_entry(1, 9735, true));
        reg.add(make_entry(2, 9735, false));
        reg.add(make_entry(3, 9735, true));

        let auto = reg.auto_connect_peers();
        assert_eq!(auto.len(), 2);
        assert!(auto.iter().all(|e| e.auto_connect));
    }

    #[test]
    fn from_config() {
        let config = PeerConfig {
            peers: vec![
                make_entry(1, 9735, true),
                make_entry(2, 9736, false),
            ],
        };

        let reg = PeerRegistry::from_config(&config);
        assert_eq!(reg.len(), 2);
        assert!(reg.contains(&make_node_id(1)));
        assert!(reg.contains(&make_node_id(2)));
    }

    #[test]
    fn update_addr() {
        let mut reg = PeerRegistry::new();
        let entry = make_entry(1, 9735, true);
        let node_id = entry.node_id;
        reg.add(entry);

        let new_addr: SocketAddr = "192.168.1.100:9999".parse().unwrap();
        assert!(reg.update_addr(&node_id, new_addr));
        assert_eq!(reg.addr(&node_id).unwrap(), new_addr);

        // Non-existent peer returns false
        assert!(!reg.update_addr(&make_node_id(99), new_addr));
    }

    #[test]
    fn replace_existing_peer() {
        let mut reg = PeerRegistry::new();
        let entry1 = make_entry(1, 9735, true);
        let node_id = entry1.node_id;
        reg.add(entry1);

        // Add same node_id with different addr
        let entry2 = PeerEntry {
            node_id,
            addr: "10.0.0.1:8888".parse().unwrap(),
            label: Some("updated".into()),
            auto_connect: false,
        };
        reg.add(entry2);

        assert_eq!(reg.len(), 1); // Not duplicated
        assert_eq!(reg.get(&node_id).unwrap().label.as_deref(), Some("updated"));
        assert!(!reg.get(&node_id).unwrap().auto_connect);
    }

    #[test]
    fn node_ids_returns_all() {
        let mut reg = PeerRegistry::new();
        reg.add(make_entry(1, 9735, true));
        reg.add(make_entry(2, 9736, true));

        let ids = reg.node_ids();
        assert_eq!(ids.len(), 2);
    }

    #[test]
    fn default_config_empty() {
        let config = PeerConfig::default();
        assert!(config.peers.is_empty());

        let reg = PeerRegistry::from_config(&config);
        assert!(reg.is_empty());
    }

    #[test]
    fn serialization_roundtrip() {
        let entry = make_entry(1, 9735, true);
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: PeerEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.node_id, entry.node_id);
        assert_eq!(decoded.addr, entry.addr);
        assert_eq!(decoded.auto_connect, entry.auto_connect);
    }

    #[test]
    fn peer_entry_deny_unknown_fields() {
        let json = r#"{"node_id":"0101010101010101010101010101010101010101010101010101010101010101","addr":"127.0.0.1:9735","label":null,"auto_connect":true,"extra_field":"oops"}"#;
        let result: Result<PeerEntry, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields on PeerEntry should be rejected");
    }

    #[test]
    fn peer_config_deny_unknown_fields() {
        let json = r#"{"peers":[],"unknown_key":"value"}"#;
        let result: Result<PeerConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields on PeerConfig should be rejected");
    }
}
