#![forbid(unsafe_code)]
//! Synaptic Routing Protocol (SRP) — bio-inspired adaptive routing for the BitSov mesh.
//!
//! This crate implements a novel routing protocol inspired by neural plasticity.
//! Connections between nodes strengthen with successful use and weaken with disuse,
//! allowing the mesh to self-organize efficient routing paths.
//!
//! # Mechanisms
//!
//! | Mechanism | Biology | Implementation |
//! |-----------|---------|---------------|
//! | Hebbian learning | Fire together, wire together | Successful delivery → weight increase |
//! | Long-term depression | Unused synapses fade | Exponential decay over time |
//! | STDP | Fast responses strengthen more | Latency-dependent reward scaling |
//! | Dendritic growth | New connections form | Suggest direct peer after relay threshold |
//! | Synaptic pruning | Weak connections close | Deactivate below weight threshold |
//! | Homeostatic scaling | Overloaded nodes self-protect | Global weight reduction on overload |
//! | Critical period | New nodes learn fast | Boosted learning rate initially |

mod weight;
mod table;

pub use weight::SynapticWeight;
pub use table::{RoutingTable, RoutingDecision, PeerScore, RoutingConfig};
