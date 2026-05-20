//! Incoming message processing — types and helpers for messages received from peers.
//!
//! When a remote node delivers a message to this node, the transport layer
//! (konsensus-node/src/msg_handler.rs) handles the full receive pipeline:
//! payment gate enforcement, storage, Double Ratchet decryption, plaintext
//! caching, and WebSocket broadcast.
//!
//! This module is the API-side home for any receive-path types, response
//! structures, or webhook handlers that expose the receive pipeline to
//! local clients (e.g., push-notification callbacks, delivery receipts).
//!
//! Currently no REST endpoints exist for the receive path — delivery
//! happens automatically via the transport layer and is surfaced to
//! clients through the WebSocket stream (`GET /api/v1/ws`) and the
//! query endpoints in `query.rs`.
