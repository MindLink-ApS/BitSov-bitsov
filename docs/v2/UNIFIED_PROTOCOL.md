# Konsensus v2 — The Unified Protocol

> **Status:** Architectural revelation — supersedes COMMS_STACK_ANALYSIS.md
> **Date:** 2026-03-11
> **Principle:** One protocol. Typed payloads. Payment-gated transport. Topology-driven intelligence.

---

## The Revelation

The first analysis asked: "How do we add email, calendar, voice, and collaboration to Konsensus?" That was the wrong question. It assumed legacy protocol boundaries are real.

The right question: **What IS communication, stripped to first principles?**

Answer: An authenticated, paid, encrypted message between two pubkeys. Everything else — email, calendar, SMS, chat, file sharing, collaborative editing — is just a different **shape** of that same primitive. The shape determines how the frontend renders it. The transport is invariant.

Seven out of eight communication modalities reduce to this. The sole exception is real-time media (voice/video), where the physics of latency and lossy delivery are irreducibly different.

**Result: Two transports. One message format. Zero legacy protocols in the core.**

---

## Table of Contents

1. [Why Legacy Protocols Are Baggage](#1-why-legacy-protocols-are-baggage)
2. [The Biological Proof](#2-the-biological-proof)
3. [Precedent: Six Systems Converged Here](#3-precedent-six-systems-converged-here)
4. [The Two Irreducible Transports](#4-the-two-irreducible-transports)
5. [The Unified Konsensus Message (UKM)](#5-the-unified-konsensus-message-ukm)
6. [Kind Taxonomy](#6-kind-taxonomy)
7. [Revised Trait Hierarchy](#7-revised-trait-hierarchy)
8. [Revised Crate Structure](#8-revised-crate-structure)
9. [Frontend: One Store, Many Views](#9-frontend-one-store-many-views)
10. [Payment Gating: Universal](#10-payment-gating-universal)
11. [E2EE: Uniform Across All Kinds](#11-e2ee-uniform-across-all-kinds)
12. [Legacy Bridges: Edge Concerns](#12-legacy-bridges-edge-concerns)
13. [The Acid Test](#13-the-acid-test)
14. [Revised Tier Impact](#14-revised-tier-impact)
15. [What This Changes in v2](#15-what-this-changes-in-v2)

---

## 1. Why Legacy Protocols Are Baggage

Every traditional protocol, deconstructed to its irreducible essence:

| "Protocol" | What It Actually Is | Legacy Baggage |
|-----------|-------------------|---------------|
| **Email (SMTP/IMAP)** | Async message with: sender, recipient(s), subject, body, attachments | MX records, DKIM, SPF, DMARC, relay chains, mailbox sync, spam filtering — all infrastructure for a world without cryptographic identity or payment gates |
| **Calendar (CalDAV)** | Structured message with: organizer, attendees, start/end time, location, RSVP status | WebDAV extensions, iCalendar format, VTIMEZONE complexity, free/busy queries — all infrastructure for syncing between apps that don't share a data model |
| **Contacts (CardDAV)** | Data record: name, pubkey, addresses, notes | vCard format, WebDAV sync, property extensions — all infrastructure for interop between contact apps |
| **SMS** | Short text message | SS7 signaling, carrier routing, character encoding limits — all infrastructure for 1980s cellular networks |
| **SIP (telephony signaling)** | Control messages: invite, accept, reject, hangup, with session description | SIP is essentially HTTP that was given its own transport. Could have been JSON messages over any reliable channel. |
| **File sharing** | Message with binary payload or content-addressed pointer | FTP, WebDAV, SFTP — all infrastructure for systems without native message-level encryption or P2P connectivity |
| **Collaborative editing** | Stream of CRDT operations (small messages at high frequency) | Google Docs protocol, ShareDB, OT servers — all infrastructure for centralized document storage |

**The pattern:** Every "protocol" is a message with a specific schema, wrapped in infrastructure that solves problems Konsensus has already solved (identity, trust, encryption, spam prevention, delivery).

When your transport already provides:
- Cryptographic identity (Ed25519/secp256k1 pubkeys)
- Payment-gated delivery (Lightning — eliminates spam)
- End-to-end encryption (PQXDH/MLS)
- Replay protection (nonces)
- Federation with whitelist trust
- Encrypted storage

...then SMTP's relay chain, DKIM's domain signing, CalDAV's WebDAV inheritance, and SIP's session management are **redundant infrastructure solving already-solved problems.**

---

## 2. The Biological Proof

The biological framework is not metaphor. It is prescriptive architecture.

### Biology Uses THREE Signaling Mechanisms for ALL Communication

| Biological Mechanism | Character | Konsensus Analog |
|---------------------|-----------|-----------------|
| Chemical signaling (hormones, neurotransmitters) | Async, targeted or broadcast | Reliable message channel (all UKM kinds) |
| Electrical signaling (action potentials) | Real-time, point-to-point | Real-time media channel (voice/video) |
| Contact-dependent (gap junctions) | Direct cell-to-cell | Direct node-to-node federation |

Three mechanisms for the entire kingdom of life. Not a separate protocol for immune signaling vs. endocrine signaling vs. neural signaling.

### The Nervous System Argument

Every neuron communicates using the SAME mechanism: action potentials trigger neurotransmitter release. Vision, hearing, touch, pain, memory — ALL transmitted as the same electrochemical signal. A signal on the optic nerve is physically indistinguishable from one on the auditory nerve. **The destination determines interpretation, not the transport.**

This is exactly the unified protocol model: one message format, different `kind` values, frontend interprets based on kind.

### ATP Proves Payment Unification Demands Transport Unification

ATP is the universal energy currency of all life. Every cellular process runs on ATP — not different currencies for different functions.

Konsensus already committed to this: Lightning sats power everything. But the first analysis fragmented the transport (XMPP for chat, SIP for voice, SMTP for mail, CalDAV for calendar) while unifying the payment. That is biologically incoherent — like having universal ATP but separate circulatory systems per organ.

```
INCONSISTENT (first analysis):
  Payment:   unified (Lightning sats for everything)
  Transport: fragmented (XMPP, SIP, SMTP, CalDAV, WebDAV)

CONSISTENT (this document):
  Payment:   unified (Lightning sats for everything)
  Transport: unified (one message format for everything)
  Content:   differentiated (typed payloads interpreted by frontend)
```

### The Cell Membrane

A cell membrane doesn't have a "mail slot" for hormones and a separate "phone line" for neural signals. It has a unified lipid bilayer with receptor proteins that recognize molecular **shapes**. The same membrane infrastructure. Different receptors for different molecules.

The node's cryptographic boundary (E2EE envelope, Ed25519 signatures, AES-256-GCM) is the cell membrane. One envelope format. One signing mechanism. One encryption layer. The `kind` field is the receptor that routes the decrypted payload to the correct handler.

**One protocol. Typed payloads. This is what 4 billion years of optimization converged on.**

---

## 3. Precedent: Six Systems Converged Here

Every serious attempt at unified communication arrived at the same architecture:

| System | Envelope | Type Discriminator | Economic Layer | Lesson for Konsensus |
|--------|----------|-------------------|---------------|---------------------|
| **Nostr** | Signed JSON event | `kind` integer (0-65535) | NIP-57 Lightning Zaps | Simplest and most extensible. Kind numbers + tags = infinite flexibility. |
| **Signal** | Protobuf Envelope | `Content` oneof field | MobileCoin payment field | One encrypted channel carries text, voice signaling, files, payments. Gold standard. |
| **Matrix** | Event JSON in Room DAG | `type` + `msgtype` | None | Room-based DAG works for chat, VoIP, IoT. But complexity explosion is cautionary. |
| **LXMF** (Reticulum) | 111-byte binary envelope | Fields dictionary | None | Purest expression: text, voice, files, commands, telemetry over ONE format. 111 bytes overhead. |
| **JMAP** | Method call JSON | Data type name | None | One API pattern (get/set/query/sync) works for email, contacts, calendars identically. |
| **ActivityPub** | Activity JSON-LD | `type` string | None | Universal in theory, fragmented in practice. Under-specification is the failure mode. |

### Key Lessons

1. **The type discriminator is the critical design decision.** Nostr's integer `kind` is simplest. Signal's protobuf `oneof` is most type-safe. LXMF's Fields dictionary is most flexible. Konsensus should use a numeric `kind` (like Nostr) with well-defined payload schemas (like Signal).

2. **Payment as gate, not optional tip.** Nostr makes Lightning optional (zaps). Signal makes MobileCoin optional. Konsensus makes Lightning **mandatory**. This is architecturally stronger — the gate applies uniformly to all message kinds.

3. **Envelope minimalism matters.** LXMF: 111 bytes. Nostr: ~200 bytes minimum. The leaner the envelope, the more viable it is as a universal substrate.

4. **Encryption at the envelope level, not bolted on.** Signal and LXMF get this right. Matrix bolted it on late. ActivityPub has none. Konsensus's PQXDH/MLS E2EE wrapping ALL UKM kinds uniformly is correct.

5. **LXMF is the closest precedent.** It proves that text, voice, files, commands, and telemetry work over ONE message format with a Fields dictionary. What LXMF lacks is the economic layer — which is exactly what Konsensus adds.

---

## 4. The Two Irreducible Transports

### The Hypothesis: Validated

After deep analysis, exactly TWO transport modes cannot be collapsed into one:

### Transport 1: Reliable Message Channel

- **Physics:** TCP-based. Guaranteed delivery, ordering, completeness.
- **Protocol:** Noise_XX encrypted tunnel over TCP.
- **Carries:** ALL Unified Konsensus Messages — chat, email-shaped, calendar events, contacts, file metadata, file payloads (small), CRDT operations, voice/video signaling (SDP/ICE), control messages, federation protocol, key exchange, payment proofs.
- **Principle:** Everything that is "a discrete piece of information that must arrive intact."

### Transport 2: Real-Time Media Channel

- **Physics:** UDP-based. Tolerates loss, optimizes for latency (<150ms).
- **Protocol:** WebRTC (DTLS-SRTP for media, SCTP for data channels).
- **Carries:** Voice audio streams, video streams, screen sharing streams.
- **Principle:** Everything that is "a continuous stream where timeliness matters more than completeness."

### Why Media Cannot Be Collapsed

This is not a protocol choice. It is physics:

- **Latency:** Human conversation breaks above ~150ms one-way. Text can arrive in 2 minutes.
- **Loss tolerance:** A dropped audio packet from 20ms ago is worthless. Retransmitting it is harmful. Text must arrive intact.
- **Flow:** Voice generates ~50 packets/second continuously. Chat generates messages when the human types.
- **Signal processing:** Echo cancellation, jitter buffering, noise suppression — no analogs in text delivery.

### The Critical Insight: Signaling Is NOT Media

Voice/video **signaling** (call setup, SDP offers, ICE candidates, hangup) is just messages. They ride Transport 1 like everything else. Only the actual audio/video **bitstream** requires Transport 2.

The payment gate controls Transport 1. Since no media session can be established without signaling through Transport 1, **the payment gate controls media access indirectly.** No payment → no signaling → no media session.

```
┌─────────────────────────────────────────────────────────┐
│              ALL UKM KINDS (typed payloads)              │
│                                                          │
│  chat │ email │ calendar │ file │ presence │ signaling │ │
│  CRDT │ federation │ invoice │ contact │ key-exchange │  │
│                                                          │
├─────────────────────────────────────────────────────────┤
│  TRANSPORT 1: Reliable Message Channel                   │
│  Noise_XX over TCP                                       │
│  Payment-gated. E2EE. Replay-protected.                  │
├─────────────────────────────────────────────────────────┤
│  TRANSPORT 2: Real-Time Media Channel                    │
│  WebRTC (DTLS-SRTP)                                      │
│  Established only via signaling on Transport 1.          │
│  Voice, video, screen sharing ONLY.                      │
└─────────────────────────────────────────────────────────┘
```

### What About Large File Transfer?

Large files use Transport 1 (HTTP range requests or chunked delivery) or WebRTC Data Channels (Transport 2's infrastructure configured for reliability). This is a **usage pattern**, not a third transport. The transfer initiation always flows through Transport 1 as a UKM.

### What About CRDT Sync?

High-frequency CRDT operations benefit from a dedicated WebSocket connection for performance isolation, but the underlying transport is still TCP (Transport 1). No new physics.

---

## 5. The Unified Konsensus Message (UKM)

### The Envelope

Every piece of communication in the Konsensus network is a UKM. The envelope is invariant across all kinds:

```rust
/// The Unified Konsensus Message.
/// One format for ALL communication types.
pub struct UkmEnvelope {
    /// Unique message identifier (hash of content + nonce).
    pub id: MessageId,

    /// Message kind (determines payload schema).
    pub kind: u16,

    /// Sender's Ed25519 public key.
    pub sender: Ed25519PublicKey,

    /// Recipient's Ed25519 public key (or room/group ID).
    pub recipient: Recipient,

    /// Unix timestamp (milliseconds).
    pub timestamp: u64,

    /// E2EE encrypted payload (PQXDH for 1:1, MLS for group).
    /// The plaintext payload is a kind-specific struct.
    pub ciphertext: Vec<u8>,

    /// Lightning payment proof (hash + preimage).
    /// MANDATORY for all UKMs. No payment = message rejected.
    pub payment_proof: PaymentProof,

    /// Ed25519 signature over (id, kind, sender, recipient, timestamp, ciphertext_hash).
    pub signature: Signature,

    /// Replay protection nonce.
    pub nonce: Nonce,

    /// Optional: reference to parent message (for threads, replies, reactions).
    pub references: Vec<MessageId>,
}

pub enum Recipient {
    /// Direct message to a node.
    Node(Ed25519PublicKey),
    /// Message to a room/group (MLS group ID).
    Room(RoomId),
}
```

### Design Principles

1. **Kind is a u16** — room for 65,536 message types. Core kinds (0-999) are protocol-defined. Application kinds (1000+) are extension space.
2. **Ciphertext is opaque at the transport layer** — the transport routes by kind but cannot read the payload. Only the recipient decrypts.
3. **Payment proof is mandatory** — no UKM is accepted without it. This is Principle 2, applied uniformly.
4. **References enable threading** — replies, reactions, edits, and RSVP responses reference the original message ID.
5. **The envelope is ~200-300 bytes** before ciphertext — lean enough to be a universal substrate.

---

## 6. Kind Taxonomy

### Core Kinds (0-999): Protocol-Defined

```
COMMUNICATION (0-99)
────────────────────────────────────────────────────────
  0    Chat message          { body: String, format: Option<Format> }
  1    Long-form message     { subject: String, body: String,
       (email-shaped)          attachments: Vec<FileRef>, thread_id: Option<ThreadId> }
  2    Reply                 { body: String }  // references parent
  3    Reaction              { emoji: String }  // references parent
  4    Edit                  { body: String }  // references original, replaces
  5    Delete                {}  // references original, marks tombstone
  6    Forward               { body: Option<String> }  // references forwarded msg

STRUCTURED DATA (100-199)
────────────────────────────────────────────────────────
  100  Calendar event        { title: String, start: DateTime, end: DateTime,
                               location: Option<String>, description: Option<String>,
                               recurrence: Option<Recurrence>,
                               attendees: Vec<Ed25519PublicKey> }
  101  Calendar RSVP         { status: Accept|Decline|Tentative }  // references event
  102  Calendar update       { ...partial event fields... }  // references event
  103  Calendar cancel       {}  // references event
  110  Contact card          { name: String, pubkey: Ed25519PublicKey,
                               lightning_address: Option<String>,
                               notes: Option<String>, fields: HashMap<String, String> }

FILES & MEDIA (200-299)
────────────────────────────────────────────────────────
  200  File reference        { name: String, size: u64, mime_type: String,
                               hash: Blake3Hash, chunks: Vec<ChunkRef> }
  201  Inline image          { data: Vec<u8>, mime_type: String,
                               width: u32, height: u32, thumbnail: Option<Vec<u8>> }
  202  Voice memo            { data: Vec<u8>, duration_ms: u32, codec: String }

COLLABORATION (300-399)
────────────────────────────────────────────────────────
  300  CRDT operation        { doc_id: DocId, operation: Vec<u8> }  // yrs binary delta
  301  Document snapshot     { doc_id: DocId, snapshot: Vec<u8> }
  302  Cursor position       { doc_id: DocId, position: CursorPos }

REAL-TIME SIGNALING (400-499)
────────────────────────────────────────────────────────
  400  Call invite           { session_id: SessionId, sdp_offer: String,
                               media_type: Audio|Video|ScreenShare }
  401  Call answer           { session_id: SessionId, sdp_answer: String }
  402  ICE candidate         { session_id: SessionId, candidate: String }
  403  Call hangup           { session_id: SessionId, reason: Option<String> }
  404  Call hold/resume      { session_id: SessionId, held: bool }

RELAY STORAGE (600-699)   — Tier-2 store-and-forward control (ADR-034)
────────────────────────────────────────────────────────
  600  Relay register        { quota_hint, ttl }       ; ask a relay to hold for you
  601  Relay deposit         { recipient, ciphertext }  ; hand the relay a sealed envelope
  602  Relay ack             { envelope_id }            ; recipient confirms; relay deletes
  603  Relay drain           { since }                  ; node comes online, collects
  604  Relay unregister      { }                        ; stop holding for this node
  (A relay holds only sealed ciphertext and NEVER decrypts. Relay storage is a
   paid service category — separate from the sender→recipient message payment.)

CONTROL (900-999)
────────────────────────────────────────────────────────
  900  Typing indicator      { state: Typing|Paused|Stopped }
  901  Read receipt          {}  // references the read message
  902  Delivery receipt      {}  // references the delivered message
  903  Presence update       { status: Online|Away|Busy|Offline }
  910  Room create           { name: String, members: Vec<Ed25519PublicKey>,
                               config: RoomConfig }
  911  Room invite           { room_id: RoomId }
  912  Room join             { room_id: RoomId }
  913  Room leave            { room_id: RoomId }
  914  Room config update    { room_id: RoomId, config: RoomConfig }
  950  Key bundle publish    { prekeys: Vec<PreKey>, signed_prekey: SignedPreKey,
                               pq_prekey: PqPreKey }
  951  MLS welcome           { group_id: GroupId, welcome: Vec<u8> }
  952  MLS commit            { group_id: GroupId, commit: Vec<u8> }
```

### Application Kinds (1000+): Extension Space

```
  1000  Poll                 { question: String, options: Vec<String>,
                               multi_select: bool, end_time: Option<DateTime> }
  1001  Poll vote            { option_index: u8 }  // references poll
  1002  Invoice request      { amount_msat: u64, description: String }
  1003  Payment receipt      { payment_hash: PaymentHash, amount_msat: u64 }
  1100  IoT sensor reading   { sensor_id: String, value: f64, unit: String }
  1200  Bot command          { command: String, args: Vec<String> }
  1201  Bot response         { result: String }
```

### The Power of This Design

Adding a new feature does not require a new protocol, a new crate, a new bridge, new E2EE integration, or a new audit surface. It requires:

1. Assign a kind number
2. Define the payload struct
3. Add a frontend component to render it

**Zero changes to transport, encryption, payment, federation, or storage.** The core is permanently stable. Innovation happens at the kind layer.

---

## 7. Revised Trait Hierarchy

### Before (Multi-Protocol): 8 Traits

```
ChainProvider, LightningProvider, PricingEngine,
MessagingTransport, MediaTransport, TelephonyBridge,
FederationSigner, PeerDiscovery
```

### After (Unified Protocol): 5 Core Traits

```rust
/// Bitcoin chain data.
/// Unchanged from original v2 spec.
pub trait ChainProvider: Send + Sync { /* ... */ }

/// Lightning Network operations.
/// Unchanged from original v2 spec.
pub trait LightningProvider: Send + Sync { /* ... */ }

/// Kind-aware pricing engine.
/// Prices UKMs by kind. The trait is intentionally narrow: per-kind
/// msat lookup. Chain-state effects (fee-rate adjustment, halving
/// epoch sensitivity, EMA smoothing, peer trust discount) live
/// inside the implementing engine, not on the trait.
///
/// NOTE (2026-05-03 · ADR-027): an earlier draft of this trait
/// sketched `price_ukm`, `price_session`, `current_base_rate`, and
/// `verify_contract(TimechainContract)`. All four were removed
/// because (a) they pre-dated the current `get_price_msat` surface
/// and (b) `verify_contract` conflated chain-aware MESSAGE pricing
/// with timechain CONTRACT pricing. Contract pricing is a separate
/// concern living in the Agreements layer (ADR-028), not in
/// `PricingEngine`. The live trait at
/// `crates/konsensus-core/src/traits/pricing.rs` is what's reflected
/// below.
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

    /// Downcast for engine-specific operations (EMA snapshot
    /// persistence, multi-target state). Slated for removal — see
    /// Track L0 architectural-hygiene findings.
    fn as_any(&self) -> &dyn Any;
}

/// Reliable message transport — carries ALL UKM kinds.
/// Replaces the narrow `MessagingTransport` from original spec.
#[async_trait]
pub trait MessageTransport: Send + Sync {
    /// Send any UKM to a recipient.
    async fn send(
        &self,
        ukm: &UkmEnvelope,
    ) -> Result<MessageId, TransportError>;

    /// Subscribe to incoming UKMs (all kinds).
    async fn subscribe(&self) -> Result<UkmStream, TransportError>;

    /// Query stored UKMs by kind, conversation, time range.
    async fn query(
        &self,
        filter: &UkmFilter,
    ) -> Result<Vec<UkmEnvelope>, TransportError>;

    /// Connection status.
    async fn status(&self) -> TransportStatus;
}

/// Real-time media transport — voice/video ONLY.
/// Established via signaling UKMs (kinds 400-499) on MessageTransport.
#[async_trait]
pub trait MediaTransport: Send + Sync {
    /// Create SDP offer for a media session.
    async fn create_offer(
        &self,
        config: &SessionConfig,
    ) -> Result<SdpOffer, MediaError>;

    /// Accept SDP offer, return answer.
    async fn accept_offer(
        &self,
        offer: &SdpOffer,
    ) -> Result<SdpAnswer, MediaError>;

    /// Add ICE candidate.
    async fn add_ice_candidate(
        &self,
        candidate: &IceCandidate,
    ) -> Result<(), MediaError>;

    /// Start media flow.
    async fn start_media(
        &self,
        session_id: &SessionId,
    ) -> Result<MediaStream, MediaError>;

    /// End session.
    async fn end_session(
        &self,
        session_id: &SessionId,
    ) -> Result<(), MediaError>;

    /// Supported codecs.
    fn supported_codecs(&self) -> Vec<Codec>;
}
```

### What Happened to FederationSigner and PeerDiscovery?

**Merged into `MessageTransport`.** Federation signing is an implementation detail of the transport — every UKM is signed as part of the envelope. Peer discovery is a subsystem of the transport layer, not a separate trait. The transport layer knows how to find peers (static config, `.well-known`, Tor, DHT) and sign/verify messages.

### What Happened to TelephonyBridge?

**Moved to optional bridge module.** SIP/PSTN is not a core concern — it's a translation layer at the edge. If a node wants to bridge to phone numbers, it runs an optional `konsensus-bridges` module with feature flag `sip`. The bridge converts incoming SIP INVITE to a UKM kind=400 (call invite) and outgoing kind=400 to SIP. The core protocol never touches SIP.

---

## 8. Revised Crate Structure

### Before (Multi-Protocol): 14+ Crates

```
konsensus-core, konsensus-chain, konsensus-lightning,
konsensus-pricing, konsensus-transport, konsensus-crypto,
konsensus-federation, konsensus-storage, konsensus-api,
konsensus-media, konsensus-telephony, konsensus-node,
+ Stalwart sidecar, + FreeSWITCH sidecar
```

### After (Unified Protocol): 10 Crates

```
konsensus/
├── Cargo.toml
├── konsensus.toml.example
│
├── crates/
│   ├── konsensus-core/              # UKM definition, all kinds, types, errors
│   │   └── src/
│   │       ├── ukm.rs               # UkmEnvelope, UkmKind, all payload structs
│   │       ├── identity.rs          # NodeIdentity, BIP-32 derivation
│   │       ├── traits.rs            # All 5 trait definitions
│   │       ├── types.rs             # NodeId, RoomId, MessageId, etc.
│   │       ├── federation.rs        # Signing, nonces, whitelist (merged from separate crate)
│   │       └── error.rs
│   │
│   ├── konsensus-chain/             # ChainProvider implementations
│   │   └── src/
│   │       ├── bitcoind.rs
│   │       ├── electrum.rs
│   │       └── neutrino.rs
│   │
│   ├── konsensus-lightning/         # LightningProvider implementations
│   │   └── src/
│   │       ├── ldk.rs
│   │       ├── lnd.rs
│   │       ├── cln.rs
│   │       └── lnbits.rs
│   │
│   ├── konsensus-pricing/           # Kind-aware PricingEngine (chain-aware message pricing · ADR-027)
│   │   └── src/
│   │       ├── static_pricing.rs    # Fixed per-kind msat (config-driven default)
│   │       ├── chain_aware.rs       # Fee-rate / halving / EMA-adjusted pricing
│   │       └── peer_prices.rs       # Cached peer price tables + trust discount
│   │   # NOTE (ADR-027/028): contracts.rs is intentionally absent.
│   │   # Timechain CONTRACT pricing lives in the Agreements layer
│   │   # (konsensus-agreements, ADR-028), NOT in this crate.
│   │
│   ├── konsensus-message/           # MessageTransport (the unified channel)
│   │   └── src/
│   │       ├── transport.rs         # Noise_XX TCP transport
│   │       ├── protocol.rs          # Wire protocol (binary framing for UKMs)
│   │       ├── discovery.rs         # Peer discovery (static, .well-known, Tor, DHT)
│   │       └── store.rs             # UKM query/filter engine
│   │
│   ├── konsensus-media/             # MediaTransport (WebRTC, voice/video only)
│   │   └── src/
│   │       ├── webrtc.rs            # str0m or webrtc-rs integration
│   │       ├── turn.rs              # Embedded TURN/STUN server
│   │       └── codecs.rs            # Opus, AV1, H.264 configuration
│   │
│   ├── konsensus-crypto/            # Cryptographic primitives
│   │   └── src/
│   │       ├── pqxdh.rs
│   │       ├── mls.rs
│   │       ├── noise.rs
│   │       ├── aes.rs
│   │       ├── sframe.rs            # Group call E2EE
│   │       └── keys.rs
│   │
│   ├── konsensus-storage/           # Persistence
│   │   └── src/
│   │       ├── sqlite.rs
│   │       ├── postgres.rs
│   │       └── encrypted.rs
│   │
│   ├── konsensus-api/               # HTTP API + WebSocket
│   │   └── src/
│   │       ├── routes/
│   │       ├── middleware/
│   │       └── websocket.rs
│   │
│   └── konsensus-node/              # Binary entry point
│       └── src/
│           ├── main.rs
│           ├── config.rs
│           ├── builder.rs
│           └── migrate.rs
│
├── bridges/                          # OPTIONAL — feature-gated, edge concerns
│   ├── bridge-smtp/                  # UKM ↔ SMTP/IMAP translation
│   ├── bridge-caldav/                # UKM ↔ CalDAV translation
│   ├── bridge-sip/                   # UKM ↔ SIP/PSTN translation
│   └── bridge-sms/                   # UKM ↔ SMS translation
│
└── tests/
    ├── unit/
    ├── integration/
    └── e2e/
```

### What Was Eliminated

| Eliminated | Why |
|-----------|-----|
| `konsensus-federation/` | Merged into `konsensus-core` (federation is just signing + whitelist — not a separate crate) |
| `konsensus-telephony/` | Moved to optional `bridges/bridge-sip/` |
| Stalwart dependency | Email, calendar, contacts are UKM kinds, not separate protocols |
| FreeSWITCH dependency | SIP is a bridge concern, not core |

### Dependency Graph (Simplified)

```
konsensus-node
├── konsensus-core (UKM + traits + identity + federation)
├── konsensus-chain
│   └── konsensus-core
├── konsensus-lightning
│   └── konsensus-core
├── konsensus-pricing
│   ├── konsensus-core
│   └── konsensus-chain
├── konsensus-message
│   ├── konsensus-core
│   └── konsensus-crypto
├── konsensus-media
│   ├── konsensus-core
│   └── konsensus-crypto
├── konsensus-crypto
│   └── konsensus-core
├── konsensus-storage
│   ├── konsensus-core
│   └── konsensus-crypto
└── konsensus-api
    └── konsensus-core
```

Clean. No circular dependencies. No protocol-specific crates in the core.

---

## 9. Frontend: One Store, Many Views

### The Application Layer Revelation

The reference app has multiple views, but they ALL read from the same UKM store:

```
┌─────────────────────────────────────────────────────────────┐
│                      REFERENCE APP                           │
│                                                              │
│  ┌──────┐ ┌──────┐ ┌────────┐ ┌──────┐ ┌──────┐ ┌──────┐  │
│  │ Chat │ │ Mail │ │Calendar│ │Files │ │Calls │ │ Docs │  │
│  │ View │ │ View │ │  View  │ │ View │ │ View │ │ View │  │
│  └──┬───┘ └──┬───┘ └───┬────┘ └──┬───┘ └──┬───┘ └──┬───┘  │
│     │        │         │         │        │        │        │
│     │    KIND FILTER   │         │        │        │        │
│     │   ┌──────────────┴─────────┴────────┴────────┘        │
│     │   │                                                    │
│  ┌──┴───┴────────────────────────────────────────────────┐  │
│  │                   UKM STORE                            │  │
│  │  All messages. All kinds. One table. One query API.    │  │
│  │                                                        │  │
│  │  SELECT * FROM ukm WHERE kind BETWEEN 0 AND 6         │  │  ← Chat View
│  │  SELECT * FROM ukm WHERE kind = 1                     │  │  ← Mail View
│  │  SELECT * FROM ukm WHERE kind BETWEEN 100 AND 103     │  │  ← Calendar View
│  │  SELECT * FROM ukm WHERE kind BETWEEN 200 AND 202     │  │  ← Files View
│  │  SELECT * FROM ukm WHERE kind BETWEEN 400 AND 404     │  │  ← Calls View
│  │  SELECT * FROM ukm WHERE kind BETWEEN 300 AND 302     │  │  ← Docs View
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### What Each View Renders

| View | Kinds | Presentation |
|------|-------|-------------|
| **Chat** | 0-6 (chat, reply, reaction, edit, delete, forward) | Familiar chat UI — bubbles, timestamps, read receipts |
| **Mail** | 1 (long-form with subject) | Email-like UI — inbox list, subject lines, threaded replies, attachments |
| **Calendar** | 100-103 (events, RSVPs, updates, cancellations) | Calendar grid — day/week/month views, event details, RSVP buttons |
| **Contacts** | 110 (contact cards) | Contact list — name, pubkey, Lightning address, notes |
| **Files** | 200-202 (file refs, images, voice memos) | File browser — thumbnails, download, share |
| **Calls** | 400-404 (signaling) + MediaTransport | Call UI — ringing, in-call, hangup, participants |
| **Docs** | 300-302 (CRDT ops, snapshots, cursors) | Collaborative editor — Yjs-powered, Google Docs-like |

### The Key Insight

A "mail" is just kind=1 rendered in an email-like layout. The **same UKM** could be rendered in the Chat view as a long message or in the Mail view as an email. The user can even toggle views. The data is the same. The presentation is a frontend concern.

This means:
- No IMAP server to implement
- No SMTP relay to maintain
- No CalDAV sync protocol to support
- No separate data models for each communication type
- One search index covers everything
- One sync mechanism covers everything
- One backup covers everything

---

## 10. Payment Gating: Universal

### Every UKM Kind Is Payment-Gated

The `payment_proof` field is mandatory on every UKM. The pricing varies by kind.

NOTE (2026-05-03 · ADR-027): an earlier draft of this section sketched
an `impl TimechainPricingEngine` with `price_ukm` / `price_session` /
`current_base_rate` methods that no longer exist. The live engine
implements the trait above (`get_price_msat`, `get_category_price_msat`,
`as_any`). Per-kind pricing is resolved via `KindCategory` lookups
(see `crates/konsensus-core/src/kind.rs`); chain-state effects are
applied internally by the engine, not by callers.

The live `ChainAwarePricingEngine` lives in
`crates/konsensus-pricing/src/chain_aware.rs`. Its unit tests cover
fee-rate adjustment, halving epoch sensitivity, EMA smoothing, and
volatility caps. The `StaticPricingEngine` companion in
`crates/konsensus-pricing/src/static_pricing.rs` exposes the same
trait with fixed prices configured via `konsensus.toml`.

The (separate) timechain-contract pricing concept — block-height-
anchored SaaS contracts — is **not** part of this trait. It lives
in the Agreements layer (ADR-028), not in core.

### Exceptions to Payment (Considered and Rejected)

Should control messages (typing indicators, read receipts) be free? **No.** Even at 1/100th of base rate, payment proves authenticity and prevents abuse. A presence flood attack from a compromised node would cost real sats. The payment gate is universal — no exceptions, no edge cases, no bypass paths.

The only exception: kinds 401-404 (call answer, ICE candidates, hangup) are covered by the kind=400 call invite payment. Once the caller has paid for the session, the signaling messages within that session are pre-authorized. This prevents a "pay to answer your own phone" UX problem.

---

## 11. E2EE: Uniform Across All Kinds

### One Encryption Scheme for All Content

```
┌───────────────────────────────────────────────────────────┐
│  Layer 1: E2EE — user-to-user, kind-independent           │
│  ├── 1:1 UKMs (all kinds): PQXDH → Double Ratchet         │
│  ├── Group UKMs (all kinds): MLS (RFC 9420)                │
│  └── The kind field is encrypted WITH the payload.         │
│      The transport layer sees: recipient + ciphertext.     │
│      It cannot even see what KIND of message it is routing. │
│                                                             │
│  Layer 2: Transport — node-to-node                          │
│  ├── Message channel: Noise_XX                              │
│  ├── Media channel: DTLS-SRTP                               │
│  └── Protects metadata from network observers               │
│                                                             │
│  Layer 3: At-rest — storage encryption                      │
│  ├── AES-256-GCM with BIP-32 derived key                    │
│  └── All UKMs encrypted identically before persistence      │
│                                                             │
│  Layer 4: Media E2EE (voice/video only)                     │
│  ├── 1:1 calls: DTLS-SRTP (built into WebRTC)              │
│  ├── Group calls: MLS + SFrame (RFC 9605)                   │
│  └── Signaling E2EE via Layer 1 (SDP/ICE are UKMs)         │
└───────────────────────────────────────────────────────────┘
```

### Critical Design Decision: Kind Is Encrypted

In the UKM envelope, only these fields are in plaintext (visible to the transport layer and relays):
- `sender` pubkey (needed for routing)
- `recipient` pubkey/room ID (needed for routing)
- `timestamp` (needed for ordering)
- `payment_proof` (needed for gate verification)
- `signature` (needed for authentication)
- `nonce` (needed for replay protection)

The `kind` field is **inside the ciphertext**. The transport layer does not know whether it is routing a chat message, a calendar invite, or a call setup. This provides strong metadata protection — an observer cannot distinguish communication types.

The recipient decrypts, reads the `kind`, and routes to the appropriate handler/view.

---

## 12. Legacy Bridges: Edge Concerns

### Architecture: Core + Optional Bridges

```
┌──────────────────────────────────────────────────────────┐
│                    CORE (always present)                   │
│                                                           │
│  Identity (BIP-32) → Payment Gate (Lightning) →           │
│  UKM (all kinds) → E2EE (PQXDH/MLS) →                   │
│  Transport 1 (Noise) + Transport 2 (WebRTC) →            │
│  Storage (AES-256-GCM)                                    │
│                                                           │
└──────────┬───────────┬───────────┬───────────┬───────────┘
           │           │           │           │
     ┌─────┴─────┐ ┌──┴──┐ ┌─────┴─────┐ ┌──┴──┐
     │SMTP Bridge│ │ SIP │ │CalDAV     │ │ SMS │
     │(optional) │ │Bridge│ │Bridge     │ │Bridge│
     │           │ │(opt.)│ │(optional) │ │(opt.)│
     └─────┬─────┘ └──┬──┘ └─────┬─────┘ └──┬──┘
           │           │           │           │
     Legacy Email  PSTN Phone  Apple/Google  Carrier
     (Gmail, etc.) Numbers     Calendar      SMS
```

### How Bridges Work

Each bridge is a **translator** that converts between UKMs and legacy protocols:

**SMTP Bridge** (optional, feature-gated):
- Incoming email (SMTP) → UKM kind=1 (long-form message) → delivered to recipient
- Outgoing UKM kind=1 → SMTP email (with DKIM, SPF, DMARC for deliverability)
- Requires DNS for outbound email interop (irreducible — Gmail requires MX records)

**SIP Bridge** (optional, feature-gated):
- Incoming SIP INVITE → UKM kind=400 (call invite) → signaling via Transport 1
- Outgoing UKM kind=400 → SIP INVITE → carrier
- Requires SIP trunk provider for PSTN connectivity (irreducible — phone numbers are government-regulated)

**CalDAV Bridge** (optional, feature-gated):
- Exposes UKM kind=100-103 as CalDAV resources
- Apple Calendar, Google Calendar, Thunderbird can sync via standard CalDAV protocol
- Runs as HTTP server on localhost, translating CalDAV requests to UKM queries

**SMS Bridge** (optional, feature-gated):
- Incoming SMS (via SMPP or Android gateway) → UKM kind=0 (chat message)
- Outgoing UKM kind=0 → SMS
- Requires carrier infrastructure or Android phone

### Bridges Are Not Core

Bridges live in `bridges/` directory, not `crates/`. They are feature-gated out of default builds. A T1 Light Node does not compile them. A T3/T4 node can opt into any bridge it needs.

The core protocol never touches SMTP, SIP, CalDAV, or SMS. It only speaks UKM.

---

## 13. The Acid Test

### Multi-Protocol Approach: Adding "Polls"

1. Design poll data model
2. Create new API endpoint
3. Wire into messaging transport
4. Add to E2EE encryption scope
5. Handle in federation protocol
6. Add to audit logging
7. Create storage schema
8. Build frontend component
9. **8 touch points across 5+ crates**

### Unified Protocol Approach: Adding "Polls"

1. Add `Poll = 1000` to UkmKind enum
2. Define `PollPayload { question, options, multi_select, end_time }`
3. Build frontend component

**3 touch points. Zero changes to transport, encryption, payment, federation, storage, or API.** The core is permanently stable.

### Adding "Screen Sharing"

Multi-protocol: New protocol investigation, capability negotiation, separate encryption...
Unified: Kind 400 already supports `media_type: ScreenShare`. Frontend adds a "Share Screen" button. Done.

### Adding "IoT Sensor Data"

Multi-protocol: New IoT protocol, new crate, new bridge...
Unified: Kind 1100 = sensor reading. Payload: `{ sensor_id, value, unit }`. Frontend adds a dashboard view. Done.

---

## 14. Revised Tier Impact

### Binary Size (Dramatically Reduced)

| Build Profile | Components | Estimated Size (stripped) |
|--------------|-----------|------------------------|
| **T1 Light** | Core UKM + audio + P2P | **~25-30 MB** (was 35-40 MB) |
| **T2 Standard** | T1 + video + CRDT | **~35-45 MB** (was 45-55 MB) |
| **T3 Full** | T2 + all codecs | **~45-55 MB** (was 60-75 MB) |
| **T4 Infra** | T3 + TURN/SFU | **~55-65 MB** (was 70-80 MB) |

**Stalwart sidecar eliminated** (-30-50 MB). FreeSWITCH eliminated for most deployments. The unified protocol is not just simpler — it produces smaller binaries.

### Feature Flags (Simplified)

```toml
[features]
default = ["voip-audio"]
voip-audio = ["dep:str0m", "dep:opus"]
voip-video = ["voip-audio", "dep:openh264", "dep:rav1e"]
crdt = ["dep:yrs"]
turn-relay = ["voip-audio"]
sfu = ["voip-video"]

# Optional bridges (not compiled by default)
bridge-smtp = ["dep:lettre", "dep:stalwart-smtp"]
bridge-sip = ["dep:rvoip"]
bridge-caldav = []
bridge-sms = []

# Tier presets
tier1 = ["voip-audio"]
tier2 = ["tier1", "voip-video", "crdt"]
tier3 = ["tier2"]
tier4 = ["tier3", "turn-relay", "sfu"]
```

---

## 15. What This Changes in v2

### Reduced Scope, Increased Power

| Aspect | Original v2 + COMMS Analysis | Unified Protocol |
|--------|------|------|
| Core traits | 8 | **5** |
| Core crates | 14+ | **10** |
| External daemons | 3 (Stalwart, FreeSWITCH, Prosody) | **0-1** (Prosody during transition) |
| Binary size (T4) | ~100-130 MB total | **~55-65 MB** |
| Protocols implemented | XMPP + WebRTC + SMTP + CalDAV + SIP | **UKM + WebRTC** |
| New feature effort | 8 touch points | **3 touch points** |
| E2EE audit surface | Per-protocol encryption | **One encryption path** |
| Payment gate | Per-protocol pricing | **One pricing function** |

### What the v2 Roadmap Becomes

The original v2 plan was 16 weeks. The COMMS analysis extended it to 22 weeks. The unified protocol approach:

| Phase | Duration | Focus |
|-------|----------|-------|
| 1. Foundation | 4 weeks | Core crate with UKM definitions, traits, identity, storage |
| 2. Bitcoin & Lightning | 4 weeks | ChainProvider, LightningProvider, kind-aware PricingEngine |
| 3. Message Transport & Crypto | 4 weeks | Noise transport, E2EE (PQXDH + MLS), federation |
| 4. Media Transport | 3 weeks | WebRTC (str0m), embedded TURN/STUN, SFrame |
| 5. Integration & Polish | 3 weeks | API, CLI, v1 compat, testing |
| **Total** | **18 weeks** | |

**18 weeks instead of 22** — shorter timeline for MORE capability, because we are not implementing 4 extra protocols.

---

## Conclusion: The Chemistry of Konsensus

The legacy internet evolved a separate protocol for every application category because each protocol had to reinvent identity, trust, encryption, and spam prevention from scratch. SMTP needed SPF/DKIM because it had no cryptographic identity. SIP needed its own authentication because it had no payment gate. CalDAV needed WebDAV because it had no native transport.

Konsensus has already solved all of these at the foundation layer:
- **Identity:** BIP-32 keypairs
- **Trust:** Ed25519 federation with whitelist
- **Encryption:** PQXDH/MLS E2EE
- **Spam prevention:** Lightning payment gate
- **Transport:** Noise_XX encrypted channels
- **Storage:** AES-256-GCM encrypted persistence

Building SMTP, CalDAV, SIP on top of this foundation is **rebuilding what is already built**. It is protocol accretion — the pathology of legacy systems.

The biologically correct, first-principles architecture is:

**One protocol. Typed payloads. Payment-gated transport. Topology-driven intelligence.**

The UKM is the action potential. The kind is the molecular shape. The payment is ATP. The node is the cell. The mesh is the nervous system.

This is the chemistry of Konsensus.

---

*This document supersedes the multi-protocol analysis in COMMS_STACK_ANALYSIS.md. The Rust ecosystem research (WebRTC, CRDT, iroh) remains valid — those components are needed for Transport 2 and specific UKM kind implementations. What changes is the architectural frame: those components serve the unified protocol, not separate protocol stacks.*
