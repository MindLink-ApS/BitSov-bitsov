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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

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
///
/// # Whitelist cache
///
/// The payment gate (Principle 3: closed mesh) checks every incoming message's
/// sender against the whitelist — the set of known peer NodeIds. Materializing a
/// fresh `HashSet<NodeId>` from the `peers` map on every message is O(N) per
/// message and allocates per message. To make the membership check O(1) and
/// allocation-free on the hot path, the registry keeps a `whitelist_cache`
/// `HashSet<NodeId>` in lockstep with the `peers` map: every mutation that adds
/// or removes a peer updates the cache. Callers on the hot path borrow the cached
/// set via [`PeerRegistry::whitelist_set`] and never clone it.
///
/// The cache is an internal index over `peers`, so it is always consistent with
/// the durable peers table (which the registry mirrors): the registry is the
/// single in-memory authority, all mutations flow through [`PeerRegistry::add`]
/// and [`PeerRegistry::remove`], and both keep the cache in sync.
pub struct PeerRegistry {
    /// Known peers indexed by NodeId.
    peers: HashMap<NodeId, PeerEntry>,
    /// Cached whitelist (set of known peer NodeIds), kept in sync with `peers`
    /// on every add/remove so the payment gate hot path avoids an O(N) per-message
    /// `HashSet` rebuild. Always equal to `peers.keys().copied().collect()`.
    ///
    /// Held behind `Arc` so the gate hot path can take an O(1) snapshot
    /// ([`PeerRegistry::whitelist_arc`]) and pass it *into* `PaymentGate::verify`
    /// (the gate stays the sole Principle-3 authority) without holding the
    /// registry lock across the async gate await. Mutations copy-on-write via
    /// `Arc::make_mut`, so an in-flight verification keeps its immutable snapshot
    /// even if a peer is added/revoked mid-verify.
    whitelist_cache: Arc<HashSet<NodeId>>,
    /// Peers learned via discovery (PeerExchange/gossip) that are NOT admitted.
    ///
    /// A discovered peer holds **no gate authority** and is **never** in
    /// `whitelist_cache` — it is a known endpoint only. It becomes admitted (and
    /// whitelisted) solely via [`PeerRegistry::promote_discovered_to_admitted`],
    /// driven by a settled payment (PriceOpen) or an explicit operator action.
    /// Kept strictly disjoint from `peers`: a NodeId is admitted XOR discovered,
    /// so a privileged peer can no longer inject admitted NodeIds through a
    /// PeerExchange suggestion.
    discovered: HashMap<NodeId, PeerEntry>,
}

impl PeerRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            whitelist_cache: Arc::new(HashSet::new()),
            discovered: HashMap::new(),
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
    /// If a peer with the same NodeId already exists, it is replaced. The
    /// whitelist cache is kept in sync so the gate hot path stays consistent.
    pub fn add(&mut self, entry: PeerEntry) {
        let node_id = entry.node_id;
        self.peers.insert(node_id, entry);
        Arc::make_mut(&mut self.whitelist_cache).insert(node_id);
    }

    /// Remove a peer from the registry.
    ///
    /// The whitelist cache is kept in sync so the gate hot path stays consistent.
    pub fn remove(&mut self, node_id: &NodeId) -> Option<PeerEntry> {
        let removed = self.peers.remove(node_id);
        if removed.is_some() {
            Arc::make_mut(&mut self.whitelist_cache).remove(node_id);
        }
        removed
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
    ///
    /// This allocates a fresh `Vec`; for the per-message payment-gate hot path
    /// prefer [`PeerRegistry::whitelist_set`], which borrows the cached set with
    /// no allocation.
    pub fn whitelist(&self) -> Vec<NodeId> {
        self.node_ids()
    }

    /// Borrow the cached whitelist set (Principle 3: Closed Mesh).
    ///
    /// Returns a reference to an internally maintained `HashSet<NodeId>` that is
    /// kept in sync with the peer map on every add/remove. The payment gate hot
    /// path uses this for an O(1) membership check per message with **zero
    /// allocation and no per-message clone** — unlike rebuilding a set from
    /// [`PeerRegistry::whitelist`] on every incoming message.
    pub fn whitelist_set(&self) -> &HashSet<NodeId> {
        self.whitelist_cache.as_ref()
    }

    /// Take an O(1) reference-counted snapshot of the cached whitelist set
    /// (Principle 3: Closed Mesh).
    ///
    /// The payment-gate hot path uses this to clone the `Arc` while briefly
    /// holding the registry read lock, drop the guard, then pass the snapshot
    /// **into** `PaymentGate::verify` (`whitelist = Some(&snapshot)`) so the gate
    /// remains the sole authority for the whitelist (Step 2) check — without
    /// holding the registry lock across the gate's async await, and without an
    /// O(N) per-message rebuild. Because mutations copy-on-write via
    /// `Arc::make_mut`, the snapshot an in-flight verification holds is immutable
    /// even if the registry is mutated concurrently.
    pub fn whitelist_arc(&self) -> Arc<HashSet<NodeId>> {
        Arc::clone(&self.whitelist_cache)
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

    /// Check if a NodeId is ADMITTED (i.e., in the gate whitelist).
    ///
    /// This is the admission/whitelist check — it returns `false` for a merely
    /// *discovered* peer. Use [`PeerRegistry::is_known`] /
    /// [`PeerRegistry::is_discovered`] for discovery-set membership.
    pub fn contains(&self, node_id: &NodeId) -> bool {
        self.peers.contains_key(node_id)
    }

    /// Record a peer learned via discovery (PeerExchange/gossip) WITHOUT granting
    /// it gate-admission.
    ///
    /// The peer lands in the `discovered` set, never in `whitelist_cache`. This
    /// is a no-op if the NodeId is already admitted (an admitted peer is never
    /// demoted) or already discovered (first-seen wins, so a later suggestion
    /// cannot overwrite a known endpoint).
    pub fn add_discovered(&mut self, entry: PeerEntry) {
        let node_id = entry.node_id;
        if self.peers.contains_key(&node_id) || self.discovered.contains_key(&node_id) {
            return;
        }
        self.discovered.insert(node_id, entry);
    }

    /// Promote a previously-discovered peer to admitted (whitelisted).
    ///
    /// Returns `true` if the peer was in the discovered set and is now admitted.
    /// This is the ONLY path from discovered → whitelist authority; the
    /// settled-payment promote edge and explicit operator admission call it.
    pub fn promote_discovered_to_admitted(&mut self, node_id: &NodeId) -> bool {
        match self.discovered.remove(node_id) {
            Some(entry) => {
                self.add(entry);
                true
            }
            None => false,
        }
    }

    /// True if the NodeId is known at all — ADMITTED or merely DISCOVERED.
    ///
    /// Use for discovery dedup. This is NOT an admission check
    /// (use [`PeerRegistry::contains`] for that).
    pub fn is_known(&self, node_id: &NodeId) -> bool {
        self.peers.contains_key(node_id) || self.discovered.contains_key(node_id)
    }

    /// True if the NodeId is in the discovered set (known but NOT admitted).
    pub fn is_discovered(&self, node_id: &NodeId) -> bool {
        self.discovered.contains_key(node_id)
    }

    /// Number of discovered-but-not-admitted peers.
    pub fn discovered_len(&self) -> usize {
        self.discovered.len()
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
    fn add_discovered_does_not_admit_or_whitelist() {
        // THE B2 invariant: a discovered peer holds NO gate authority.
        let mut reg = PeerRegistry::new();
        let id = make_node_id(42);
        reg.add_discovered(make_entry(42, 9735, false));

        assert!(!reg.contains(&id), "discovered peer must NOT be admitted");
        assert!(
            !reg.whitelist_set().contains(&id),
            "discovered peer must NOT be in the gate whitelist set"
        );
        assert!(
            !reg.whitelist_arc().contains(&id),
            "discovered peer must NOT be in a whitelist snapshot"
        );
        assert!(
            reg.whitelist().is_empty(),
            "whitelist reflects admitted peers only"
        );
        assert!(reg.is_known(&id));
        assert!(reg.is_discovered(&id));
        assert_eq!(reg.discovered_len(), 1);
        assert!(reg.is_empty(), "admitted peer count is still zero");
    }

    #[test]
    fn promote_discovered_moves_to_admitted_and_whitelist() {
        let mut reg = PeerRegistry::new();
        let id = make_node_id(42);
        reg.add_discovered(make_entry(42, 9735, false));

        assert!(reg.promote_discovered_to_admitted(&id));
        assert!(reg.contains(&id), "promoted peer is admitted");
        assert!(
            reg.whitelist_set().contains(&id),
            "promoted peer joins the gate whitelist"
        );
        assert!(!reg.is_discovered(&id), "no longer merely discovered");
        assert_eq!(reg.discovered_len(), 0);
        assert_eq!(reg.len(), 1);
        assert!(
            !reg.promote_discovered_to_admitted(&id),
            "promoting an already-admitted peer is a no-op"
        );
    }

    #[test]
    fn add_discovered_never_demotes_or_overwrites_admitted_peer() {
        let mut reg = PeerRegistry::new();
        let id = make_node_id(42);
        reg.add(make_entry(42, 9735, false)); // admitted at 10.0.0.42:9735

        // A later PEX suggestion for the same NodeId at a different address must
        // neither demote the peer nor overwrite its admitted endpoint.
        reg.add_discovered(PeerEntry {
            node_id: id,
            addr: "9.9.9.9:9999".parse().unwrap(),
            label: Some("attacker".to_string()),
            auto_connect: false,
        });

        assert!(reg.contains(&id), "still admitted");
        assert!(
            !reg.is_discovered(&id),
            "admitted peer is never moved to discovered"
        );
        assert_eq!(reg.discovered_len(), 0);
        assert_eq!(
            reg.addr(&id).unwrap(),
            "10.0.0.42:9735".parse::<SocketAddr>().unwrap(),
            "admitted endpoint must not be overwritten by a discovery suggestion"
        );
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

    /// HARD-11: the cached whitelist set must stay consistent with the peer map
    /// across every add/remove/replace, and must always equal the set built from
    /// `whitelist()`. The payment gate hot path borrows this cache per message.
    #[test]
    fn whitelist_set_cache_stays_consistent() {
        // Invariant helper: the cache must always equal the canonical set
        // derived from the live peer map.
        fn assert_cache_invariant(reg: &PeerRegistry) {
            let canonical: HashSet<NodeId> = reg.whitelist().into_iter().collect();
            assert_eq!(
                reg.whitelist_set(),
                &canonical,
                "cached whitelist drifted from peer map"
            );
        }

        let mut reg = PeerRegistry::new();
        assert!(reg.whitelist_set().is_empty());
        assert_cache_invariant(&reg);

        // Add three peers — cache must grow in lockstep.
        reg.add(make_entry(1, 9735, true));
        reg.add(make_entry(2, 9735, false));
        reg.add(make_entry(3, 9735, true));
        assert_eq!(reg.whitelist_set().len(), 3);
        assert!(reg.whitelist_set().contains(&make_node_id(1)));
        assert!(reg.whitelist_set().contains(&make_node_id(2)));
        assert!(reg.whitelist_set().contains(&make_node_id(3)));
        assert_cache_invariant(&reg);

        // Replacing an existing peer (same node_id, different addr) must NOT
        // duplicate or drop the cache entry.
        reg.add(PeerEntry {
            node_id: make_node_id(2),
            addr: "10.0.0.2:8888".parse().unwrap(),
            label: Some("replaced".into()),
            auto_connect: true,
        });
        assert_eq!(reg.whitelist_set().len(), 3);
        assert!(reg.whitelist_set().contains(&make_node_id(2)));
        assert_cache_invariant(&reg);

        // Remove a present peer — cache must drop exactly that entry.
        let removed = reg.remove(&make_node_id(2));
        assert!(removed.is_some());
        assert_eq!(reg.whitelist_set().len(), 2);
        assert!(!reg.whitelist_set().contains(&make_node_id(2)));
        assert_cache_invariant(&reg);

        // Removing an absent peer must leave the cache untouched.
        let absent = reg.remove(&make_node_id(99));
        assert!(absent.is_none());
        assert_eq!(reg.whitelist_set().len(), 2);
        assert_cache_invariant(&reg);

        // Drain the registry — cache must end empty.
        reg.remove(&make_node_id(1));
        reg.remove(&make_node_id(3));
        assert!(reg.whitelist_set().is_empty());
        assert_cache_invariant(&reg);
    }

    /// The cache must be populated correctly when built from config (which routes
    /// through `add`), so a node that boots from durable peers has a correct gate
    /// whitelist without any per-message rebuild.
    #[test]
    fn whitelist_set_cache_populated_from_config() {
        let config = PeerConfig {
            peers: vec![
                make_entry(1, 9735, true),
                make_entry(2, 9736, false),
                make_entry(3, 9737, true),
            ],
        };
        let reg = PeerRegistry::from_config(&config);

        let canonical: HashSet<NodeId> = reg.whitelist().into_iter().collect();
        assert_eq!(reg.whitelist_set(), &canonical);
        assert_eq!(reg.whitelist_set().len(), 3);
        assert!(reg.whitelist_set().contains(&make_node_id(1)));
        assert!(reg.whitelist_set().contains(&make_node_id(2)));
        assert!(reg.whitelist_set().contains(&make_node_id(3)));
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
