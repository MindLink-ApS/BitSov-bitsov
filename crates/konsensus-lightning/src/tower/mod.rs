//! Decision-neutral watchtower client core. No network traffic or payments.
pub mod blob;

pub mod client;
pub mod outbox;

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    io,
};

/// Named entries under `[tower.clients.NAME]`. An empty table is completely off.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TowerConfig {
    #[serde(default)]
    pub clients: BTreeMap<String, TowerEndpoint>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TowerEndpoint {
    /// Compressed Lightning pubkey; used to exclude the channel counterparty.
    pub node_id: String,
    /// Reserved for W2b. W2a never connects to this endpoint.
    pub endpoint: String,
    // TODO(W2b): prices, sessions, keysend admission and spend caps after decisions.
}

impl TowerConfig {
    pub fn validate(&self) -> io::Result<()> {
        let invalid = |msg| io::Error::new(io::ErrorKind::InvalidInput, msg);
        if self.clients.len() > 5 {
            return Err(invalid("tower.clients permits at most five towers"));
        }
        let mut peers = HashSet::new();
        for (name, client) in &self.clients {
            if name.is_empty() || name.len() > 64 {
                return Err(invalid("invalid tower client name"));
            }
            let peer = client
                .node_id
                .parse::<bitcoin::secp256k1::PublicKey>()
                .map_err(|_| invalid("tower node_id must be a compressed Lightning public key"))?;
            if client.node_id.len() != 66 || !peers.insert(peer) {
                return Err(invalid("duplicate or uncompressed tower node_id"));
            }
            let (host, port) = client
                .endpoint
                .rsplit_once(':')
                .ok_or_else(|| invalid("tower endpoint must be host:port"))?;
            if host.is_empty()
                || client.endpoint.len() > 255
                || client.endpoint.chars().any(char::is_whitespace)
                || port.parse::<u16>().ok().filter(|p| *p > 0).is_none()
                || host.contains('/')
                || host.contains('@')
                || client
                    .endpoint
                    .parse::<ldk_node::lightning::ln::msgs::SocketAddress>()
                    .is_err()
            {
                return Err(invalid(
                    "tower endpoint must be host:port (no URL or credentials)",
                ));
            }
        }
        Ok(())
    }
}
