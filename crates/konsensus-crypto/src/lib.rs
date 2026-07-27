//! konsensus-crypto — Noise_XX transport encryption, E2EE (X3DH + Double Ratchet), and key management.
//!
//! This crate provides the cryptographic primitives for the BitSov v2 network:
//! - **Noise_XX** — transport-layer encryption for all TCP connections
//! - **X3DH** — key agreement for 1:1 E2EE sessions (forward secrecy, post-compromise security)

#![forbid(unsafe_code)]
//! - **Double Ratchet** — per-message key derivation within E2EE sessions

pub mod double_ratchet;
pub mod noise;
pub mod plaintext_cache;
pub mod sender_keys;
pub mod session;
pub mod x3dh;

pub use double_ratchet::{DoubleRatchet, MessageHeader, RatchetError, RatchetMessage, RatchetState};
pub use noise::{NoiseError, NoiseSession, MAX_NOISE_MSG_LEN, MAX_NOISE_PAYLOAD};
pub use sender_keys::{
    GroupCiphertext, GroupSession, SenderKeyDistribution, SenderKeyError, SenderKeyState,
};
pub use session::{
    SessionError, SessionManager, SessionStore, SerializablePrekeyBundle, SerializableSessionInit,
    ratchet_message_from_bytes, ratchet_message_to_bytes,
};
pub use plaintext_cache::{PlaintextCacheCipher, PlaintextCacheError};
pub use x3dh::{
    OneTimePreKey, PrekeyBundle, SignedPreKey, X3dhError, X3dhInitiation, X3dhSharedSecret,
};
