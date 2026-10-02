//! konsensus-chain — ChainProvider implementations for Bitcoin chain data.
//!
//! Provides block height, fee estimates, and transaction confirmation data
//! from various Bitcoin chain data sources.
//!

#![forbid(unsafe_code)]
//! # Implementations
//!
//! - [`EsploraProvider`] — HTTP REST API (Esplora/mempool.space compatible)
//! - Neutrino (BIP 157/158) — planned
//! - [`ElectrumProvider`] — explicit Electrum server (server-trusting)
//! - [`BitcoindProvider`] — own Bitcoin Core RPC (pruned or full)

pub mod electrum;
pub use electrum::{ElectrumConfig, ElectrumOperator, ElectrumProvider};

pub mod bitcoind;
pub use bitcoind::{BitcoindConfig, BitcoindProvider};

pub mod esplora;
pub mod mock;

pub use esplora::{EsploraConfig, EsploraProvider};
pub use mock::{MockChainConfig, MockChainProvider};
