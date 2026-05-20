//! `konsensus-mobile` — BitSov mobile SDK.
//!
//! UniFFI-annotated types compiled into a native shared library exposed to
//! Swift and Kotlin via generated bindings. Cross-compiles to:
//!   - `aarch64-apple-ios-sim`
//!   - `aarch64-linux-android`

pub mod error;
pub mod keystore;
pub mod transport;

use std::sync::Arc;

use rand::rngs::OsRng;
use tracing::info;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use error::MobileError;
use transport::NoiseWssTransport;

uniffi::setup_scaffolding!();

/// Configuration needed to connect a mobile client to a BitSov node.
#[derive(Debug, Clone, uniffi::Record)]
pub struct MobileNodeConfig {
    /// WebSocket endpoint URL.
    /// Production: `wss://node.example.com/api/v1/mobile`
    /// Local dev:  `ws://127.0.0.1:9000/api/v1/mobile`
    pub endpoint: String,
    /// X25519 private key (32 bytes) for the Noise_XX handshake.
    pub static_private_key: Vec<u8>,
}

/// An X25519 key pair for use in the Noise_XX handshake.
#[derive(Debug, uniffi::Record)]
pub struct X25519KeyPair {
    /// 32-byte private key — store in the platform secure enclave / keychain.
    pub private_key: Vec<u8>,
    /// 32-byte public key — share with peers for identity verification.
    pub public_key: Vec<u8>,
}

/// Generate a fresh X25519 key pair.
///
/// Call once during onboarding and persist the private key securely.
#[uniffi::export]
pub fn generate_x25519_keypair() -> X25519KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let private_bytes = Zeroizing::new(secret.to_bytes());
    X25519KeyPair {
        private_key: private_bytes.to_vec(),
        public_key: public.as_bytes().to_vec(),
    }
}

/// Derive the X25519 public key from a private key (32 bytes).
#[uniffi::export]
pub fn derive_public_key(private_key: Vec<u8>) -> Result<Vec<u8>, MobileError> {
    let bytes: [u8; 32] = private_key.try_into().map_err(|_| MobileError::InvalidKey {
        msg: "private key must be exactly 32 bytes".to_owned(),
    })?;
    let public = PublicKey::from(&StaticSecret::from(bytes));
    Ok(public.as_bytes().to_vec())
}

/// Entry point for the mobile SDK.
///
/// Create one `MobileClient` per node endpoint, then call
/// [`MobileClient::connect`] to obtain an authenticated [`MobileSession`].
#[derive(uniffi::Object)]
pub struct MobileClient {
    config: MobileNodeConfig,
}

#[uniffi::export]
impl MobileClient {
    #[uniffi::constructor]
    pub fn new(config: MobileNodeConfig) -> Arc<Self> {
        Arc::new(Self { config })
    }

    /// Connect to the node and complete the Noise_XX handshake.
    pub async fn connect(&self) -> Result<Arc<MobileSession>, MobileError> {
        let key_bytes: [u8; 32] =
            self.config.static_private_key.clone().try_into().map_err(|_| {
                MobileError::InvalidKey {
                    msg: "static_private_key must be exactly 32 bytes".to_owned(),
                }
            })?;
        info!(endpoint = %self.config.endpoint, "mobile client connecting");
        let transport = NoiseWssTransport::connect(&self.config.endpoint, &key_bytes).await?;
        let remote_static = transport.remote_static().to_vec();
        Ok(Arc::new(MobileSession {
            transport: tokio::sync::Mutex::new(transport),
            remote_static_key: remote_static,
        }))
    }
}

/// An active, encrypted session to a BitSov node.
///
/// Obtained from [`MobileClient::connect`]. Thread-safe.
#[derive(uniffi::Object)]
pub struct MobileSession {
    transport: tokio::sync::Mutex<NoiseWssTransport>,
    remote_static_key: Vec<u8>,
}

#[uniffi::export]
impl MobileSession {
    /// Encrypt and send a binary payload to the node (max 65 519 bytes).
    pub async fn send(&self, payload: Vec<u8>) -> Result<(), MobileError> {
        self.transport.lock().await.send(&payload).await
    }

    /// Receive and decrypt the next message from the node.
    pub async fn recv(&self) -> Result<Vec<u8>, MobileError> {
        self.transport.lock().await.recv().await
    }

    /// Remote node's Noise static X25519 public key (32 bytes), verified during handshake.
    pub fn remote_static_key(&self) -> Vec<u8> {
        self.remote_static_key.clone()
    }
}
