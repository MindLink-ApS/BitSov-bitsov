# BitSov/Konsensus v2 — Core Stack Specification

> **Status:** At rest — pending v1 field testing
> **Related:** [PRD.md](PRD.md) | [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) | [CURRENT_GAPS.md](CURRENT_GAPS.md)

> **Public-core note (2026-05-20):** This is an early v2 reference document.
> The launch boundary is now governed by `CHARTER.md`,
> `RELAY_PROTOCOL.md`, `REMOTE_ACCESS_IDENTITY.md`, and
> `TIER_MIGRATION_PROTOCOL.md`. Historical "Tier 3/4" labels below refer to
> Full/Infrastructure resource profiles, not custodial hosting. Any hosted or
> relay deployment must remain non-custodial: user-held identity keys,
> encrypted storage, and ciphertext-only relay surfaces.

---

## Table of Contents

1. [Single Binary Architecture](#1-single-binary-architecture)
2. [Trait Hierarchy](#2-trait-hierarchy)
3. [Node Identity (BIP-32 Key Derivation)](#3-node-identity-bip-32-key-derivation)
4. [Message Flow](#4-message-flow)
5. [End-to-End Encryption Stack](#5-end-to-end-encryption-stack)
6. [DNS-Free Discovery](#6-dns-free-discovery)
7. [Crate and Module Structure](#7-crate-and-module-structure)
8. [Configuration](#8-configuration)
9. [Wire Compatibility with v1](#9-wire-compatibility-with-v1)
10. [Storage Architecture](#10-storage-architecture)
11. [Federation Protocol](#11-federation-protocol)

---

## 1. Single Binary Architecture

v2 compiles to a single `konsensus` binary that adapts behavior based on configuration. The binary contains all tier capabilities; the `konsensus.toml` config determines which subsystems activate.

```
┌─────────────────────────────────────────────────────────────────┐
│                     konsensus binary                             │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Chain Layer  │  │  Lightning   │  │   Messaging Layer    │  │
│  │              │  │    Layer     │  │                      │  │
│  │ Bitcoin Core │  │  LDK embed  │  │  Native P2P          │  │
│  │ Electrum     │  │  LND gRPC   │  │  Transport           │  │
│  │ Neutrino     │  │  CLN gRPC   │  │  E2EE (PQXDH + MLS) │  │
│  │              │  │  LNbits API  │  │  Room management     │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         │                 │                      │              │
│  ┌──────┴─────────────────┴──────────────────────┴───────────┐  │
│  │                    Core Engine                             │  │
│  │                                                            │  │
│  │  Payment Gate  │  Federation  │  Identity  │  Pricing     │  │
│  │  Audit Log     │  Discovery   │  Storage   │  Scheduler   │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │  Config (konsensus.toml)  →  Tier selection activates      │  │
│  │                               appropriate implementations  │  │
│  └────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Tier Activation

The binary uses Rust's trait system to select implementations at startup:

```rust
// Pseudocode — actual implementation may differ
fn build_node(config: &Config) -> Node {
    let chain: Box<dyn ChainProvider> = match config.tier {
        Tier::Light    => Box::new(NeutrinoProvider::new(&config.neutrino)),
        Tier::Standard => Box::new(ElectrumProvider::new(&config.electrum)),
        Tier::Full | Tier::Infra => Box::new(BitcoinCoreProvider::new(&config.bitcoind)),
    };

    let lightning: Box<dyn LightningProvider> = match config.lightning.backend {
        LnBackend::Ldk    => Box::new(LdkProvider::new(&config.ldk)),
        LnBackend::Lnd    => Box::new(LndProvider::new(&config.lnd)),
        LnBackend::Cln    => Box::new(ClnProvider::new(&config.cln)),
        LnBackend::Lnbits => Box::new(LnbitsProvider::new(&config.lnbits)),
    };

    let transport: Box<dyn MessagingTransport> = Box::new(
        NativeTransport::new(&config.transport)
    );

    Node::new(chain, lightning, transport, config)
}
```

### Compilation

```bash
# Full build (all features, all tiers)
cargo build --release

# Minimal build (T1 only — smaller binary)
cargo build --release --no-default-features --features tier1

# With Bitcoin Core support
cargo build --release --features bitcoind
```

---

## 2. Trait Hierarchy

Six core traits define the abstraction boundaries. Each trait has multiple implementations selected at runtime via configuration.

### 2.1 ChainProvider

Provides Bitcoin blockchain data for payment verification and chain-aware message pricing (Principle 5 · ADR-027).

```rust
/// Abstraction over Bitcoin chain data sources.
/// Implementations: Bitcoin Core RPC, Electrum client, Neutrino (BIP 157/158).
#[async_trait]
pub trait ChainProvider: Send + Sync {
    /// Returns the current best block height.
    async fn get_block_height(&self) -> Result<u64, ChainError>;

    /// Returns the block hash at the given height.
    async fn get_block_hash(&self, height: u64) -> Result<BlockHash, ChainError>;

    /// Returns the block header at the given height.
    async fn get_block_header(&self, height: u64) -> Result<BlockHeader, ChainError>;

    /// Returns the estimated fee rate in sat/vbyte for confirmation
    /// within `target_blocks` blocks.
    async fn estimate_fee(&self, target_blocks: u32) -> Result<FeeRate, ChainError>;

    /// Verifies that a transaction is confirmed at or above `min_confirmations`.
    async fn verify_tx_confirmed(
        &self,
        txid: &Txid,
        min_confirmations: u32,
    ) -> Result<bool, ChainError>;

    /// Subscribes to new block notifications.
    async fn subscribe_blocks(&self) -> Result<BlockStream, ChainError>;

    /// Returns the provider's trust level.
    fn trust_level(&self) -> TrustLevel;
}

/// Trust level of the chain data source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrustLevel {
    /// Full local validation (Bitcoin Core)
    Trustless,
    /// Server-assisted with local verification (Electrum with headers)
    ServerAssisted,
    /// Compact block filter based (Neutrino)
    FilterBased,
}
```

**Implementations:**

| Implementation | Tier | Trust Level | Notes |
|---------------|------|-------------|-------|
| `BitcoinCoreProvider` | T3-4 | `Trustless` | Full RPC interface to local `bitcoind` |
| `ElectrumProvider` | T2 | `ServerAssisted` | Electrum protocol; verifies headers locally |
| `NeutrinoProvider` | T1 | `FilterBased` | BIP 157/158 compact block filters |

### 2.2 LightningProvider

Manages Lightning Network operations — invoices, payments, channel state.

```rust
/// Abstraction over Lightning Network backends.
/// Implementations: LDK (embedded), LND (gRPC), CLN (gRPC), LNbits (HTTP API).
#[async_trait]
pub trait LightningProvider: Send + Sync {
    /// Creates a new invoice for the given amount and description.
    async fn create_invoice(
        &self,
        amount_msat: u64,
        description: &str,
        expiry_secs: u32,
    ) -> Result<Invoice, LightningError>;

    /// Pays an invoice identified by its BOLT11 payment request string.
    async fn pay_invoice(
        &self,
        bolt11: &str,
        max_fee_msat: Option<u64>,
    ) -> Result<PaymentResult, LightningError>;

    /// Checks whether a payment identified by its hash has been settled.
    async fn verify_payment(
        &self,
        payment_hash: &PaymentHash,
    ) -> Result<PaymentStatus, LightningError>;

    /// Returns the node's Lightning public key.
    async fn get_node_pubkey(&self) -> Result<PublicKey, LightningError>;

    /// Returns current channel balance (local + remote).
    async fn get_balance(&self) -> Result<Balance, LightningError>;

    /// Lists all channels with their state.
    async fn list_channels(&self) -> Result<Vec<ChannelInfo>, LightningError>;

    /// Subscribes to incoming payment notifications.
    async fn subscribe_payments(&self) -> Result<PaymentStream, LightningError>;

    /// Returns whether this provider runs in-process (LDK) or connects
    /// to an external daemon (LND, CLN, LNbits).
    fn is_embedded(&self) -> bool;
}

#[derive(Debug, Clone)]
pub enum PaymentStatus {
    Pending,
    Settled { preimage: PaymentPreimage },
    Failed { reason: String },
    Expired,
}
```

**Implementations:**

| Implementation | Tier | Embedded | Notes |
|---------------|------|----------|-------|
| `LdkProvider` | T1 | Yes | In-process Lightning node via LDK |
| `LndProvider` | T2-4 | No | gRPC connection to external `lnd` |
| `ClnProvider` | T2-4 | No | gRPC connection to external `lightningd` |
| `LnbitsProvider` | Any | No | HTTP API to LNbits (v1 compatibility) |

### 2.3 PricingEngine

Chain-aware MESSAGE pricing. Per-UKM-kind msat prices that the engine
internally adjusts to Bitcoin fee state, halving epoch, and (where
applicable) peer trust discount.

NOTE (2026-05-03 · ADR-027): an earlier draft of this section sketched
`price_message`, `price_room_join`, `current_base_rate`, plus
`verify_contract`/`anchor_contract`/`AnchorProof`/`ContractStatus`.
All were removed:
- The first three pre-dated the current `get_price_msat` trait surface.
- The contract methods conflated chain-aware MESSAGE pricing (Principle 5,
  lives in core) with timechain CONTRACT pricing (Agreements layer,
  lives in `konsensus-agreements` per ADR-028, NOT in core).

The live trait is below — straight from
`crates/konsensus-core/src/traits/pricing.rs`:

```rust
/// Kind-aware pricing engine (Principle 5).
#[async_trait]
pub trait PricingEngine: Send + Sync {
    /// Get the price in millisatoshis for a message of the given kind.
    /// Returns `Err(PricingError::NotPriceable)` for deferred kinds (400-499).
    async fn get_price_msat(&self, kind: u16) -> Result<u64, PricingError>;

    /// Get the price for a kind category (bulk pricing lookup).
    async fn get_category_price_msat(
        &self,
        category: KindCategory,
    ) -> Result<u64, PricingError>;

    /// Downcast for engine-specific operations (slated for removal —
    /// see Track L0 architectural-hygiene findings).
    fn as_any(&self) -> &dyn Any;
}
```

Two implementations live in `crates/konsensus-pricing/`:
- `StaticPricingEngine` — fixed msat prices per kind category,
  configured via `konsensus.toml` (default).
- `ChainAwarePricingEngine` — adjusts base prices using real-time
  Bitcoin fee rates and halving epoch from a `ChainProvider`.

Contract verification, anchoring, lifecycle, and status are the
Agreements layer's responsibility (see ADR-028), not the
`PricingEngine` trait's.

### 2.4 MessagingTransport

Handles message routing and delivery. Replaces v1's XMPP adapter with a native P2P transport.

```rust
/// Abstraction over messaging transport.
/// v2 primary: NativeTransport (Rust P2P over Noise protocol).
/// v1 compat: XmppTransport (Prosody adapter, for transition period).
#[async_trait]
pub trait MessagingTransport: Send + Sync {
    /// Sends an encrypted message to a recipient node.
    /// The message must already be E2E encrypted by the caller.
    async fn send_message(
        &self,
        recipient: &NodeAddress,
        message: &EncryptedMessage,
        payment_proof: &PaymentProof,
    ) -> Result<MessageId, TransportError>;

    /// Creates a room (group conversation context).
    async fn create_room(
        &self,
        room_config: &RoomConfig,
    ) -> Result<RoomId, TransportError>;

    /// Joins an existing room.
    async fn join_room(
        &self,
        room_id: &RoomId,
        payment_proof: &PaymentProof,
    ) -> Result<(), TransportError>;

    /// Leaves a room.
    async fn leave_room(&self, room_id: &RoomId) -> Result<(), TransportError>;

    /// Retrieves message history for a room or conversation.
    async fn get_history(
        &self,
        target: &ConversationTarget,
        since: Option<MessageId>,
        limit: u32,
    ) -> Result<Vec<StoredMessage>, TransportError>;

    /// Subscribes to incoming messages.
    async fn subscribe(&self) -> Result<MessageStream, TransportError>;

    /// Returns the transport's connection status.
    async fn status(&self) -> TransportStatus;
}

/// Address of a node on the network.
#[derive(Debug, Clone)]
pub struct NodeAddress {
    /// Ed25519 public key (primary identifier).
    pub public_key: Ed25519PublicKey,
    /// Optional connection hints.
    pub hints: Vec<ConnectionHint>,
}

#[derive(Debug, Clone)]
pub enum ConnectionHint {
    /// Direct TCP/IP connection.
    Tcp(SocketAddr),
    /// Tor hidden service.
    Onion(OnionAddress),
    /// DNS-based discovery.
    Dns(String),
    /// Well-known endpoint.
    WellKnown(Url),
}
```

### 2.5 FederationSigner

Handles cryptographic signing and verification for federation protocol messages.

```rust
/// Ed25519 signing and verification for federation messages.
/// Every inter-node request is signed; every response is verified.
#[async_trait]
pub trait FederationSigner: Send + Sync {
    /// Signs a federation message with the node's Ed25519 private key.
    /// Includes a nonce for replay protection.
    fn sign_message(
        &self,
        payload: &[u8],
        nonce: &Nonce,
    ) -> Result<Signature, SignerError>;

    /// Verifies a signed federation message from a peer.
    fn verify_message(
        &self,
        payload: &[u8],
        signature: &Signature,
        nonce: &Nonce,
        peer_pubkey: &Ed25519PublicKey,
    ) -> Result<bool, SignerError>;

    /// Returns this node's Ed25519 public key.
    fn public_key(&self) -> &Ed25519PublicKey;

    /// Generates a fresh nonce for outgoing messages.
    fn generate_nonce(&self) -> Nonce;

    /// Checks if a nonce has been seen before (replay protection).
    fn check_nonce(&self, nonce: &Nonce, peer: &Ed25519PublicKey) -> Result<bool, SignerError>;
}

/// Nonce for replay protection.
#[derive(Debug, Clone)]
pub struct Nonce {
    /// Random bytes.
    pub value: [u8; 32],
    /// Timestamp (used for expiration, not ordering).
    pub timestamp: u64,
}
```

### 2.6 PeerDiscovery

Locates and maintains connections to peer nodes.

```rust
/// Discovers and maintains connections to peer nodes.
/// Multiple discovery mechanisms operate concurrently.
#[async_trait]
pub trait PeerDiscovery: Send + Sync {
    /// Returns currently known peers.
    async fn known_peers(&self) -> Result<Vec<PeerInfo>, DiscoveryError>;

    /// Attempts to discover new peers using all available mechanisms.
    async fn discover(&self) -> Result<Vec<PeerInfo>, DiscoveryError>;

    /// Resolves a peer's current address from its public key.
    async fn resolve_peer(
        &self,
        pubkey: &Ed25519PublicKey,
    ) -> Result<Option<NodeAddress>, DiscoveryError>;

    /// Announces this node's presence to the network.
    async fn announce(&self, address: &NodeAddress) -> Result<(), DiscoveryError>;

    /// Adds a static peer (from configuration).
    async fn add_static_peer(&self, peer: PeerInfo) -> Result<(), DiscoveryError>;

    /// Returns which discovery mechanisms are active.
    fn active_mechanisms(&self) -> Vec<DiscoveryMechanism>;
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer's Ed25519 public key.
    pub pubkey: Ed25519PublicKey,
    /// Known addresses for this peer.
    pub addresses: Vec<NodeAddress>,
    /// Last seen timestamp.
    pub last_seen: Option<u64>,
    /// Whether this peer is in our federation whitelist.
    pub whitelisted: bool,
    /// Peer's advertised tier.
    pub tier: Option<Tier>,
}

#[derive(Debug, Clone, Copy)]
pub enum DiscoveryMechanism {
    /// Configured in konsensus.toml.
    StaticPeers,
    /// HTTP GET /.well-known/konsensus-server.json
    WellKnown,
    /// Tor hidden service directory.
    Tor,
    /// Distributed hash table.
    Dht,
}
```

---

## 3. Node Identity (BIP-32 Key Derivation)

Every Konsensus v2 node derives all cryptographic keys from a single BIP-32 seed. This provides a unified identity model where one mnemonic backup restores the entire node identity.

### Key Derivation Tree

```
BIP-32 Master Seed (24-word mnemonic)
│
├── m/84'/0'/0'          Bitcoin (BIP-84 native segwit)
│   ├── /0/*             Receiving addresses
│   └── /1/*             Change addresses
│
├── m/1017'/0'/0'        Lightning (LDK node key derivation)
│   ├── /0               Node identity key
│   ├── /1               Channel keys
│   └── /2               Onion routing keys
│
├── m/2026'/0'/0'        Konsensus application keys
│   ├── /0               Ed25519 federation signing key
│   ├── /1               X25519 key agreement (for E2EE)
│   ├── /2               secp256k1 LNURL-auth key
│   └── /3               AES-256-GCM storage encryption key
│
└── m/2026'/0'/1'        Per-peer session keys (derived per relationship)
    ├── /0               Peer 0 session
    ├── /1               Peer 1 session
    └── ...
```

### Identity Structure

```rust
/// Complete node identity derived from BIP-32 seed.
pub struct NodeIdentity {
    /// BIP-32 master key (never exposed, only used for derivation).
    master: ExtendedPrivKey,

    /// Bitcoin identity.
    pub bitcoin: BitcoinIdentity,

    /// Lightning identity.
    pub lightning: LightningIdentity,

    /// Federation identity (Ed25519).
    pub federation: FederationIdentity,

    /// Encryption identity (X25519).
    pub encryption: EncryptionIdentity,

    /// LNURL-auth identity (secp256k1).
    pub lnurl_auth: LnurlAuthIdentity,
}

impl NodeIdentity {
    /// Creates a new identity from a BIP-39 mnemonic.
    pub fn from_mnemonic(mnemonic: &str, passphrase: &str) -> Result<Self, IdentityError> {
        let seed = bip39::Seed::new(mnemonic, passphrase);
        let master = ExtendedPrivKey::new_master(Network::Bitcoin, seed.as_bytes())?;

        Ok(Self {
            bitcoin: BitcoinIdentity::derive(&master)?,
            lightning: LightningIdentity::derive(&master)?,
            federation: FederationIdentity::derive(&master)?,
            encryption: EncryptionIdentity::derive(&master)?,
            lnurl_auth: LnurlAuthIdentity::derive(&master)?,
            master,
        })
    }

    /// Returns the node's canonical identifier (Ed25519 public key fingerprint).
    pub fn node_id(&self) -> NodeId {
        NodeId::from_pubkey(&self.federation.public_key)
    }
}
```

### Key Relationships

```
┌─────────────────────────────────────────────────────────────────┐
│                      BIP-32 Seed                                 │
│                    (24-word mnemonic)                             │
│                          │                                       │
│          ┌───────────────┼───────────────┐                      │
│          │               │               │                      │
│   ┌──────┴──────┐ ┌─────┴─────┐ ┌──────┴──────┐               │
│   │  Bitcoin    │ │ Lightning │ │  Konsensus  │               │
│   │  secp256k1  │ │ secp256k1 │ │             │               │
│   │             │ │           │ │ Ed25519     │ Federation    │
│   │  Addresses  │ │ Node key  │ │ X25519      │ Encryption   │
│   │  UTXOs      │ │ Channels  │ │ secp256k1   │ LNURL-auth   │
│   │             │ │ Routing   │ │ AES-256     │ Storage enc  │
│   └─────────────┘ └───────────┘ └─────────────┘               │
│                                                                  │
│   ONE MNEMONIC → COMPLETE NODE IDENTITY RECOVERY                │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Message Flow

### Payment-Gated, Timechain-Priced, E2EE Message Flow

```
Sender Node                                              Recipient Node
─────────────                                            ──────────────
     │                                                         │
     │  1. User composes message                               │
     │  2. PricingEngine.get_price_msat(kind)                  │
     │     └── ChainProvider.get_block_height()  (engine-internal) │
     │     └── ChainProvider.estimate_fee()       (engine-internal) │
     │     └── Apply fee/halving/EMA adjustment   (engine-internal) │
     │                                                         │
     │  3. Request invoice from recipient                      │
     │  ──────────────────────────────────────────────────────→│
     │                                                         │
     │                          4. Recipient creates invoice   │
     │                             LightningProvider           │
     │                             .create_invoice(price)      │
     │  ←──────────────────────────────────────────────────────│
     │     Invoice (BOLT11)                                    │
     │                                                         │
     │  5. Pay invoice                                         │
     │     LightningProvider.pay_invoice(bolt11)               │
     │     └── Wait for settlement                             │
     │                                                         │
     │  6. E2EE encrypt message                                │
     │     └── PQXDH (1:1) or MLS (group)                     │
     │     └── Plaintext → Ciphertext                          │
     │                                                         │
     │  7. Attach payment proof                                │
     │     └── payment_hash + preimage                         │
     │                                                         │
     │  8. Sign with Ed25519 (federation layer)                │
     │     └── FederationSigner.sign_message()                 │
     │                                                         │
     │  9. Send via MessagingTransport                         │
     │  ──────────────────────────────────────────────────────→│
     │     { ciphertext, payment_proof, signature, nonce }     │
     │                                                         │
     │                         10. Verify signature            │
     │                             FederationSigner            │
     │                             .verify_message()           │
     │                                                         │
     │                         11. Check nonce (replay)        │
     │                             FederationSigner            │
     │                             .check_nonce()              │
     │                                                         │
     │                         12. Verify payment              │
     │                             LightningProvider           │
     │                             .verify_payment()           │
     │                             ⚠️  FAIL-CLOSED             │
     │                             If verification fails →     │
     │                             message REJECTED            │
     │                                                         │
     │                         13. Decrypt message             │
     │                             PQXDH/MLS decrypt           │
     │                                                         │
     │                         14. Store (encrypted at rest)   │
     │                             AES-256-GCM                 │
     │                                                         │
     │                         15. Deliver to user             │
     │  ←──────────────────────────────────────────────────────│
     │     ACK                                                 │
     │                                                         │
     │  16. Store (encrypted at rest)                          │
     │      AES-256-GCM                                        │
     │                                                         │
```

### Key Properties

- **Payment before delivery:** Message is rejected if payment verification fails (step 12). This is fail-closed — any error in payment verification results in rejection, not acceptance.
- **E2EE at composition time:** The sender encrypts before transmission (step 6). Neither node's operator can read the plaintext.
- **Double encryption at rest:** E2EE ciphertext is additionally encrypted with AES-256-GCM using the node's storage key before persistence (steps 14, 16).
- **Timechain-aware pricing:** The price is computed dynamically from chain state (step 2), not a static configuration value.
- **Federation signatures on every message:** Even between known peers, every message is signed and verified (steps 8, 10).

---

## 5. End-to-End Encryption Stack

### 1:1 Messages — PQXDH (Post-Quantum Extended Diffie-Hellman)

PQXDH extends the Signal protocol's X3DH with post-quantum key encapsulation (ML-KEM/Kyber), providing forward secrecy and post-quantum resistance.

```
┌──────────────────────────────────────────────────────────────┐
│                     PQXDH Key Agreement                       │
│                                                               │
│  Sender                              Recipient                │
│  ──────                              ─────────                │
│  Identity Key (IK_s)                 Identity Key (IK_r)      │
│  Ephemeral Key (EK)                  Signed Pre-Key (SPK)     │
│                                      One-Time Pre-Key (OPK)   │
│                                      PQ Pre-Key (PQPK)        │
│                                                               │
│  DH1 = DH(IK_s, SPK)                                        │
│  DH2 = DH(EK, IK_r)                                         │
│  DH3 = DH(EK, SPK)                                          │
│  DH4 = DH(EK, OPK)         [if available]                   │
│  PQ  = KEM.Decaps(PQPK)    [post-quantum component]         │
│                                                               │
│  SK = KDF(DH1 || DH2 || DH3 || DH4 || PQ)                  │
│                                                               │
│  → Double Ratchet initialized with SK                        │
│  → Each message: new symmetric key (forward secrecy)         │
└──────────────────────────────────────────────────────────────┘
```

### Group Messages — MLS (Messaging Layer Security)

MLS (RFC 9420) provides efficient group key agreement with forward secrecy and post-compromise security.

```
┌──────────────────────────────────────────────────────────────┐
│                     MLS Group Protocol                        │
│                                                               │
│  Tree Structure (Ratchet Tree):                              │
│                                                               │
│              [Group Key]                                      │
│              /          \                                     │
│         [Node]          [Node]                                │
│         /    \          /    \                                │
│     [Leaf]  [Leaf]  [Leaf]  [Leaf]                           │
│      Alice   Bob    Carol   Dave                             │
│                                                               │
│  Operations:                                                  │
│  • Add member    → KeyPackage + Welcome message              │
│  • Remove member → Update path, new epoch                    │
│  • Send message  → Encrypt with current epoch key            │
│  • Update keys   → Commit + UpdatePath (forward secrecy)     │
│                                                               │
│  Properties:                                                  │
│  • Forward secrecy (per epoch)                               │
│  • Post-compromise security (after update)                   │
│  • Efficient: O(log n) update cost                           │
│  • Sender authentication                                     │
└──────────────────────────────────────────────────────────────┘
```

### Transport Encryption — Noise Protocol

All node-to-node connections use the Noise_XX handshake pattern for transport-level encryption:

```
Noise_XX:
  → e                           Sender ephemeral
  ← e, ee, s, es               Responder ephemeral + static
  → s, se                      Sender static

Properties:
  • Mutual authentication
  • Forward secrecy
  • No certificates or CA infrastructure
  • Identity hiding (static keys encrypted)
```

### Encryption Layers Summary

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1: E2EE (PQXDH / MLS)                            │
│  → User-to-user encryption                               │
│  → Neither node operator can read                        │
│                                                          │
│  Layer 2: Transport (Noise_XX)                           │
│  → Node-to-node channel encryption                       │
│  → Protects metadata from network observers              │
│                                                          │
│  Layer 3: At-rest (AES-256-GCM)                          │
│  → Storage encryption with node's derived key            │
│  → Protects data if disk is compromised                  │
└─────────────────────────────────────────────────────────┘
```

---

## 6. DNS-Free Discovery

v2 supports multiple peer discovery mechanisms that operate concurrently. No single mechanism is required — nodes use whatever is available and configured.

### Discovery Mechanisms

| Mechanism | DNS Required | Censorship Resistant | Privacy | Availability |
|-----------|-------------|---------------------|---------|--------------|
| **Static peers** | No | Yes | High | Always (config) |
| **`.well-known`** | Yes (or IP) | Partial | Low | HTTP server required |
| **Tor `.onion`** | No | Yes | Very High | Tor required |
| **DHT** | No | Yes | Medium | 3+ DHT nodes required |

### Static Peers

Configured directly in `konsensus.toml`:

```toml
[[peers]]
pubkey = "ed25519:abc123..."
address = "tcp://192.168.1.100:9735"

[[peers]]
pubkey = "ed25519:def456..."
address = "onion://abcdef1234567890.onion:9735"
```

### Well-Known Endpoint

HTTP(S) endpoint serving node metadata (compatible with v1):

```
GET /.well-known/konsensus-server.json

{
  "version": 2,
  "node_id": "ed25519:abc123...",
  "lightning_pubkey": "02abc...",
  "transport": {
    "native": "tcp://example.com:9735",
    "onion": "abcdef.onion:9735"
  },
  "federation": {
    "ed25519_pubkey": "abc123...",
    "whitelist": ["ed25519:def456...", "ed25519:ghi789..."]
  },
  "tier": 3,
  "capabilities": ["pqxdh", "mls", "dht"]
}
```

### Tor Hidden Service

Nodes can expose a Tor `.onion` address for DNS-free, censorship-resistant connectivity:

```toml
[tor]
enabled = true
socks_proxy = "127.0.0.1:9050"
hidden_service = true
# .onion address is auto-generated and published via DHT or static peer exchange
```

### DHT (Distributed Hash Table)

Kademlia-based DHT for decentralized peer discovery:

```
┌──────────────────────────────────────────────────────┐
│                  DHT Lookup                           │
│                                                       │
│  1. Node wants to find peer with pubkey X            │
│  2. Hash(X) → DHT key                               │
│  3. Query closest known nodes to DHT key             │
│  4. Iterative lookup converges on responsible node   │
│  5. Retrieve NodeAddress for pubkey X                │
│  6. Connect directly to peer                         │
│                                                       │
│  Bootstrap: T4 nodes serve as initial DHT contacts   │
│  Refresh: Nodes re-announce periodically             │
│  Privacy: Lookups reveal interest in specific peers   │
│           → Tor integration mitigates this            │
└──────────────────────────────────────────────────────┘
```

---

## 7. Crate and Module Structure

### Workspace Layout

```
konsensus/
├── Cargo.toml                  # Workspace root
├── konsensus.toml.example      # Example configuration
│
├── crates/
│   ├── konsensus-core/         # Core types, traits, errors
│   │   └── src/
│   │       ├── traits/         # All 6 trait definitions
│   │       │   ├── chain.rs
│   │       │   ├── lightning.rs
│   │       │   ├── pricing.rs
│   │       │   ├── transport.rs
│   │       │   ├── signer.rs
│   │       │   └── discovery.rs
│   │       ├── identity.rs     # NodeIdentity, BIP-32 derivation
│   │       ├── types.rs        # Shared types (NodeId, RoomId, etc.)
│   │       └── error.rs        # Error types
│   │
│   ├── konsensus-chain/        # ChainProvider implementations
│   │   └── src/
│   │       ├── bitcoind.rs     # Bitcoin Core RPC
│   │       ├── electrum.rs     # Electrum client
│   │       └── neutrino.rs     # BIP 157/158
│   │
│   ├── konsensus-lightning/    # LightningProvider implementations
│   │   └── src/
│   │       ├── ldk.rs          # LDK embedded
│   │       ├── lnd.rs          # LND gRPC
│   │       ├── cln.rs          # CLN gRPC
│   │       └── lnbits.rs       # LNbits HTTP (v1 compat)
│   │
│   ├── konsensus-pricing/      # PricingEngine impl (chain-aware message pricing · ADR-027)
│   │   └── src/
│   │       ├── static_pricing.rs   # Fixed per-kind msat (config default)
│   │       ├── chain_aware.rs      # Fee-rate / halving / EMA-adjusted
│   │       └── peer_prices.rs      # Peer price cache + trust discount
│   │   # NOTE (ADR-027/028): no contracts.rs here. Contract anchoring &
│   │   # verification belong in the Agreements layer (ADR-028).
│   │
│   ├── konsensus-transport/    # MessagingTransport implementations
│   │   └── src/
│   │       ├── native.rs       # Rust P2P transport (Noise)
│   │       ├── xmpp.rs         # XMPP adapter (v1 compat)
│   │       └── protocol.rs     # Wire protocol definition
│   │
│   ├── konsensus-crypto/       # Cryptographic primitives
│   │   └── src/
│   │       ├── pqxdh.rs        # Post-Quantum X3DH
│   │       ├── mls.rs          # MLS group encryption
│   │       ├── noise.rs        # Noise protocol transport
│   │       ├── aes.rs          # AES-256-GCM storage encryption
│   │       └── keys.rs         # Key derivation helpers
│   │
│   ├── konsensus-federation/   # Federation protocol
│   │   └── src/
│   │       ├── signer.rs       # Ed25519 signing
│   │       ├── whitelist.rs    # Trust management
│   │       └── discovery.rs    # PeerDiscovery implementations
│   │
│   ├── konsensus-storage/      # Persistence layer
│   │   └── src/
│   │       ├── sqlite.rs       # T1 storage
│   │       ├── postgres.rs     # T2-4 storage
│   │       └── encrypted.rs    # Encryption wrapper
│   │
│   ├── konsensus-api/          # HTTP API (REST + WebSocket)
│   │   └── src/
│   │       ├── routes/         # Endpoint handlers
│   │       ├── middleware/      # Auth, rate limiting, logging
│   │       └── websocket.rs    # Real-time notifications
│   │
│   └── konsensus-node/         # Node orchestration (binary entry)
│       └── src/
│           ├── main.rs         # CLI entry point
│           ├── config.rs       # konsensus.toml parsing
│           ├── builder.rs      # Node assembly (trait wiring)
│           └── migrate.rs      # Tier migration logic
│
├── tests/
│   ├── unit/                   # Per-crate unit tests
│   ├── integration/            # Cross-crate integration
│   └── e2e/                    # Multi-node E2E tests
│
└── docs/                       # Architecture documentation
```

### Dependency Graph

```
konsensus-node (binary)
├── konsensus-core (traits + types)
├── konsensus-chain
│   └── konsensus-core
├── konsensus-lightning
│   └── konsensus-core
├── konsensus-pricing
│   ├── konsensus-core
│   └── konsensus-chain (for block data)
├── konsensus-transport
│   ├── konsensus-core
│   └── konsensus-crypto (for Noise)
├── konsensus-crypto
│   └── konsensus-core
├── konsensus-federation
│   └── konsensus-core
├── konsensus-storage
│   ├── konsensus-core
│   └── konsensus-crypto (for at-rest encryption)
└── konsensus-api
    ├── konsensus-core
    └── (all other crates via core traits)
```

---

## 8. Configuration

### `konsensus.toml` — Tier 1 (Light Node)

```toml
[node]
tier = "light"
data_dir = "/var/lib/konsensus"

[identity]
# BIP-39 mnemonic (24 words). Generate with: konsensus init
mnemonic_file = "/var/lib/konsensus/mnemonic.enc"

[chain]
provider = "neutrino"

[chain.neutrino]
peers = ["btcd1.example.com:8333", "btcd2.example.com:8333"]
filter_dir = "/var/lib/konsensus/filters"

[lightning]
backend = "ldk"

[lightning.ldk]
channel_dir = "/var/lib/konsensus/channels"
network = "mainnet"
# Auto-connect to well-known LSPs for initial channel
auto_channel = true

[storage]
backend = "sqlite"
path = "/var/lib/konsensus/konsensus.db"

[transport]
listen = "0.0.0.0:9735"

[federation]
whitelist = [
    "ed25519:abc123...",
    "ed25519:def456...",
]

[[peers]]
pubkey = "ed25519:abc123..."
address = "tcp://peer1.example.com:9735"

[[peers]]
pubkey = "ed25519:def456..."
address = "tcp://peer2.example.com:9735"
```

### `konsensus.toml` — Full Node

```toml
[node]
tier = "full"
data_dir = "/var/lib/konsensus"

[identity]
mnemonic_file = "/var/lib/konsensus/mnemonic.enc"

[chain]
provider = "bitcoind"

[chain.bitcoind]
rpc_url = "http://127.0.0.1:8332"
rpc_user = "konsensus"
rpc_password_file = "/var/lib/konsensus/bitcoind_rpc.pass"
network = "mainnet"

[lightning]
backend = "lnd"

[lightning.lnd]
grpc_host = "127.0.0.1:10009"
tls_cert = "/var/lib/konsensus/lnd/tls.cert"
macaroon = "/var/lib/konsensus/lnd/admin.macaroon"

[storage]
backend = "postgres"

[storage.postgres]
url = "postgresql://konsensus:password@127.0.0.1:5432/konsensus"
max_connections = 20

[transport]
listen = "0.0.0.0:9735"

[tor]
enabled = true
socks_proxy = "127.0.0.1:9050"
hidden_service = true

[federation]
whitelist = [
    "ed25519:abc123...",
    "ed25519:def456...",
    "ed25519:ghi789...",
]

[pricing]
engine = "timechain"
min_price_msat = 10
max_price_msat = 100000
fee_sensitivity = 0.5  # How much mempool fees affect pricing

[api]
listen = "127.0.0.1:3000"
cors_origins = ["http://localhost:5173"]
rate_limit_rpm = 120

[[peers]]
pubkey = "ed25519:abc123..."
address = "tcp://peer1.example.com:9735"

[[peers]]
pubkey = "ed25519:def456..."
address = "onion://abcdef1234567890.onion:9735"
```

### `konsensus.toml` — Infrastructure Node

```toml
[node]
tier = "infrastructure"
data_dir = "/var/lib/konsensus"

[identity]
mnemonic_file = "/var/lib/konsensus/mnemonic.enc"

[chain]
provider = "bitcoind"

[chain.bitcoind]
rpc_url = "http://127.0.0.1:8332"
rpc_user = "konsensus"
rpc_password_file = "/var/lib/konsensus/bitcoind_rpc.pass"
network = "mainnet"
# Archival node — no pruning
txindex = true

[lightning]
backend = "lnd"

[lightning.lnd]
grpc_host = "127.0.0.1:10009"
tls_cert = "/var/lib/konsensus/lnd/tls.cert"
macaroon = "/var/lib/konsensus/lnd/admin.macaroon"

[storage]
backend = "postgres"

[storage.postgres]
url = "postgresql://konsensus:password@127.0.0.1:5432/konsensus"
max_connections = 50

[transport]
listen = "0.0.0.0:9735"

[tor]
enabled = true
socks_proxy = "127.0.0.1:9050"
hidden_service = true
relay = true  # Act as Tor relay for the network

[federation]
whitelist = [
    "ed25519:abc123...",
    "ed25519:def456...",
    "ed25519:ghi789...",
]

[pricing]
engine = "timechain"
min_price_msat = 10
max_price_msat = 100000
fee_sensitivity = 0.5

[api]
listen = "0.0.0.0:3000"
tls_cert = "/etc/konsensus/tls/cert.pem"
tls_key = "/etc/konsensus/tls/key.pem"
rate_limit_rpm = 300

[services]
# T4-specific: network services this node provides
watchtower = true
dht_bootstrap = true
health_monitor = true
metrics_port = 9090

[[peers]]
pubkey = "ed25519:abc123..."
address = "tcp://peer1.example.com:9735"

[[peers]]
pubkey = "ed25519:def456..."
address = "onion://abcdef1234567890.onion:9735"

[[peers]]
pubkey = "ed25519:ghi789..."
address = "tcp://192.168.1.50:9735"
```

---

## 9. Wire Compatibility with v1

During the transition period, v2 nodes must federate with v1 nodes. This requires a compatibility layer.

### v1 Federation Protocol

v1 federation uses:
- **HTTP POST** with JSON body to federation endpoints
- **Ed25519 signatures** on request body with nonce
- **`.well-known/konsensus-server.json`** for discovery
- **LNbits API** for Lightning operations

### Compatibility Approach

```
v2 Node                                        v1 Node
────────                                       ────────
     │                                              │
     │  Detect peer protocol version                │
     │  (via .well-known "version" field)           │
     │                                              │
     │  If v1 peer:                                 │
     │  ├── Use HTTP federation (not native P2P)    │
     │  ├── Use LNbits-compatible invoice format    │
     │  ├── Skip E2EE (v1 doesn't support it)       │
     │  ├── Use DNS-based discovery                 │
     │  └── Downgrade gracefully                    │
     │                                              │
     │  If v2 peer:                                 │
     │  ├── Use native P2P transport                │
     │  ├── Full E2EE (PQXDH/MLS)                  │
     │  ├── Use any discovery mechanism             │
     │  └── Full feature set                        │
     │                                              │
```

### Protocol Negotiation

```rust
/// Determines the federation protocol to use with a peer.
pub enum PeerProtocol {
    /// v1 — HTTP federation, no E2EE, LNbits invoices
    V1 {
        base_url: Url,
        ed25519_pubkey: Ed25519PublicKey,
    },
    /// v2 — native P2P, full E2EE, any Lightning backend
    V2 {
        address: NodeAddress,
        capabilities: Vec<Capability>,
    },
}

impl PeerProtocol {
    /// Detect protocol version from .well-known response.
    pub async fn detect(well_known: &WellKnownResponse) -> Self {
        match well_known.version {
            1 => PeerProtocol::V1 { /* ... */ },
            2 => PeerProtocol::V2 { /* ... */ },
            _ => PeerProtocol::V1 { /* ... */ }, // Safe fallback
        }
    }
}
```

---

## 10. Storage Architecture

### Tier-Appropriate Backends

| Tier | Backend | Rationale |
|------|---------|-----------|
| T1 | SQLite | Zero-config, single-file, embedded in binary |
| T2-4 | PostgreSQL | Concurrent access, replication, mature tooling |

### Schema (Simplified)

Both backends implement the same logical schema:

```sql
-- Node identity and configuration
CREATE TABLE node_config (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL  -- AES-256-GCM encrypted
);

-- Federation peers
CREATE TABLE peers (
    pubkey TEXT PRIMARY KEY,
    addresses TEXT NOT NULL,  -- JSON array
    whitelisted BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen INTEGER,
    tier TEXT
);

-- Messages (E2EE ciphertext only)
CREATE TABLE messages (
    id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    sender_pubkey TEXT NOT NULL,
    ciphertext BLOB NOT NULL,  -- Already E2EE; additionally AES-256-GCM wrapped
    payment_hash TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    UNIQUE(payment_hash)
);

-- Payment records
CREATE TABLE payments (
    payment_hash TEXT PRIMARY KEY,
    amount_msat INTEGER NOT NULL,
    direction TEXT NOT NULL,  -- 'inbound' or 'outbound'
    status TEXT NOT NULL,
    message_id TEXT REFERENCES messages(id),
    created_at INTEGER NOT NULL,
    settled_at INTEGER
);

-- Nonce replay protection
CREATE TABLE nonces (
    nonce TEXT PRIMARY KEY,
    peer_pubkey TEXT NOT NULL,
    timestamp INTEGER NOT NULL
);

-- Audit log (immutable, append-only)
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    actor TEXT,
    details BLOB  -- AES-256-GCM encrypted
);
```

### Encryption at Rest

All sensitive data is encrypted before storage:

```rust
/// Storage wrapper that encrypts values before persistence.
pub struct EncryptedStorage<S: Storage> {
    inner: S,
    key: Aes256GcmKey,  // Derived from node's BIP-32 seed
}

impl<S: Storage> EncryptedStorage<S> {
    pub async fn store_message(&self, msg: &StoredMessage) -> Result<(), StorageError> {
        // Message is already E2EE ciphertext
        // Wrap with AES-256-GCM for at-rest protection
        let encrypted = self.key.encrypt(&msg.serialize()?)?;
        self.inner.put(&msg.id, &encrypted).await
    }
}
```

---

## 11. Federation Protocol

### v2 Federation Enhancements over v1

| Feature | v1 | v2 |
|---------|----|----|
| Transport | HTTP POST | Native P2P (Noise) |
| Signing | Ed25519 | Ed25519 (same algorithm, derived from BIP-32) |
| Replay protection | Nonce-based | Nonce-based + timestamp window |
| Discovery | `.well-known` (DNS) | Multi-mechanism (static, `.well-known`, Tor, DHT) |
| Trust model | Whitelist | Whitelist (same, proven effective) |
| Message integrity | Signature on JSON body | Signature on binary frame |
| Capability negotiation | None | Explicit capability exchange |

### Federation Handshake (v2)

```
Initiator                                  Responder
──────────                                 ─────────
     │                                          │
     │  1. Noise_XX handshake                   │
     │  ─────────────────────────────────────→  │
     │  ←─────────────────────────────────────  │
     │  ─────────────────────────────────────→  │
     │     (mutual authentication complete)     │
     │                                          │
     │  2. Capability exchange                  │
     │  ─────────────────────────────────────→  │
     │  { version: 2, tier: 3,                  │
     │    caps: [pqxdh, mls, dht],              │
     │    ed25519_pubkey: "..." }               │
     │                                          │
     │  ←─────────────────────────────────────  │
     │  { version: 2, tier: 1,                  │
     │    caps: [pqxdh, mls],                   │
     │    ed25519_pubkey: "..." }               │
     │                                          │
     │  3. Whitelist check (both sides)         │
     │     If peer not whitelisted → disconnect │
     │                                          │
     │  4. Connection established               │
     │     Bidirectional message exchange ready  │
     │                                          │
```

---

*This specification will be revised based on v1 production learnings. See [PRD.md](PRD.md) for requirements and [CURRENT_GAPS.md](CURRENT_GAPS.md) for the v1 audit that informs this architecture.*
