//! konsensus-node library — shared types for integration tests.
//!
//! The node binary lives in `main.rs`; this file exposes modules that
//! integration tests need to import (Rust binary crates cannot export
//! items from `main.rs`).

#![forbid(unsafe_code)]

pub mod content_server;
pub mod contracts;
