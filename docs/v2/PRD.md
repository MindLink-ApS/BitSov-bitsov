# Konsensus v2 — Product Requirements Document

> **Status:** At rest — pending v1 field testing
> **Related:** [ARCHITECTURE.md](ARCHITECTURE.md) | [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md) | [CURRENT_GAPS.md](CURRENT_GAPS.md)

---

## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Vision Recap](#2-vision-recap)
3. [Sovereignty Tiers](#3-sovereignty-tiers)
4. [User Stories](#4-user-stories)
5. [Requirements Matrix](#5-requirements-matrix)
6. [Non-Goals](#6-non-goals)
7. [Success Criteria](#7-success-criteria)

---

## 1. Problem Statement

### Why v1 Is a Stepping Stone

Konsensus v1 validates the core thesis — payment-gated federated messaging — but makes deliberate architectural compromises for speed-to-market. These compromises limit how fully the Five Immutable Principles can be realized:

#### 1.1 Prosody Plaintext Storage (Principle 4 Violation)

Prosody's MAM (Message Archive Management) stores message content in plaintext in its internal database. While Konsensus enforces AES-256-GCM encryption at the API layer for its own persistence, messages flowing through Prosody are readable by anyone with access to Prosody's storage backend.

**Impact:** An operator who controls the server can read all messages. This fundamentally violates Principle 4 (Data Lives Only on Sender & Receiver Nodes) because data at rest is not protected from the infrastructure operator.

**v2 resolution:** End-to-end encryption (PQXDH for 1:1, MLS for groups) ensures messages are ciphertext at every layer. Native transport eliminates the Prosody dependency entirely.

#### 1.2 Neutrino/Electrum — Not a Full Node (Principle 1 Weakness)

v1 uses lightweight Bitcoin verification (Neutrino block filters or Electrum server queries) rather than running a full Bitcoin node. This means the node trusts external infrastructure to provide accurate chain state.

**Impact:** A compromised Electrum server or malicious Neutrino peer could feed false block data, undermining chain-aware message pricing (the live Principle 5 engine — see ADR-027) and payment verification.

**v2 resolution:** Tier 3-4 nodes run Bitcoin Core directly. Tier 1-2 nodes use Neutrino/Electrum but with configurable trust levels and multiple peer validation.

#### 1.3 Pricing surfaces unwired (Principle 5 Gap)

Two pricing surfaces are partly unwired in v1, and the conflation between
them caused the disambiguation work in ADR-027 / ADR-028:

- **Chain-aware message pricing** (the live Principle 5 surface) — message
  prices in v1 are static configuration rather than dynamically derived
  from block height and fee state.
- **Timechain contract pricing** (a separate, vision-doc concept) — the
  external `packages/timechain-pricing/` library exists with contract
  creation, anchoring, and verification logic, but is **not** wired into
  the main API and lives outside core (per ADR-028).

**Impact:** The chain-aware part of Principle 5 is architecturally
present in v2 but functionally inert in v1. The contract-pricing part
is intentionally out of scope for v2 core; it is gated behind ADR-028
and operator sign-off.

**v2 resolution:** The `PricingEngine` trait consumes `ChainProvider`
block data to dynamically price messages (chain-aware engine ships in
`crates/konsensus-pricing/`). Timechain contract pricing is deferred
to the Agreements layer (see ADR-028) and never lives in core.

#### 1.4 DNS Dependency (Principle 3 Weakness)

Federation discovery relies on DNS-resolvable domains for `.well-known/konsensus-server.json` endpoints. Prosody S2S federation also requires DNS SRV records. This creates a dependency on the DNS system — a centralized, censorable infrastructure.

**Impact:** A DNS takedown or hijack can partition the mesh. Nodes cannot federate without resolvable domain names.

**v2 resolution:** Multiple discovery mechanisms — static peer lists, `.well-known` over IP, Tor `.onion` addresses, and optional DHT-based peer discovery — ensure no single point of failure.

#### 1.5 XMPP Protocol Lock (Flexibility Constraint)

While v1's `MessagingAdapter` interface abstracts the transport, the implementation is deeply coupled to XMPP semantics (MUC, MAM, JID, stanza structure). The adapter interface itself models rooms, messages, and history in XMPP-shaped terms.

**Impact:** Swapping to a non-XMPP transport is a major migration project, not a configuration change. The abstraction leaks XMPP assumptions.

**v2 resolution:** Native P2P transport designed from scratch for Konsensus semantics. The `MessagingTransport` trait defines operations in Konsensus terms, not XMPP terms.

---

## 2. Vision Recap

### The Five Immutable Principles

These principles are the DNA of Konsensus. Every architectural decision in v2 must serve at least one:

| # | Principle | One-Line Summary |
|---|-----------|-----------------|
| 1 | **Node = Sovereign Identity & Server** | The Bitcoin keypair on the node is the user; everything else derives from it |
| 2 | **Lightning Clearance = Message Gate** | No payment, no packet — every message backed by a settled Lightning payment |
| 3 | **Closed Mesh** | Zero reliance on third-party relays; every hop is direct node-to-node |
| 4 | **Data Lives Only on Sender & Receiver** | No central storage, no cloud backup, no third-party gateways |
| 5 | **Timechain Pricing & ChainBridge Flywheel** _(see ADR-027 for terminology)_ | SaaS profit funds new nodes; subscriptions locked to Bitcoin block height. The "chain-aware message pricing" portion lives in core; the "timechain contract pricing" portion is a separate vision-layer concept (see ADR-028). |

### Biological Framework

The biological metaphor is not decoration — it is the architectural model:

| Biological Concept | Konsensus Equivalent |
|--------------------|---------------------|
| **Cell** | Node (server instance) |
| **Cell membrane** | Bitcoin keypair (defines boundary, controls what enters/exits) |
| **ATP** | BTC (energy currency that powers all operations) |
| **Nucleus** | Bitcoin timechain (shared, immutable reference) |
| **Nervous system** | The mesh network itself |
| **DNA** | The Five Immutable Principles |
| **Chemistry** | The protocol (shared rules all cells obey) |

This framework predicts architecture: cells must be self-sufficient (single binary), membranes must be cryptographically strong (BIP-32 key derivation), and the organism must be resilient to individual cell death (mesh redundancy).

---

## 3. Sovereignty Tiers

v2 introduces a tiered architecture where a single `konsensus` binary adapts its behavior based on operator resources and trust preferences. Each tier represents a different tradeoff between sovereignty and resource requirements.

### Tier 1: Light Node

**Profile:** Minimum viable sovereign node. Suitable for individuals, small teams, or resource-constrained environments.

| Attribute | Value |
|-----------|-------|
| **Bitcoin verification** | Neutrino (BIP 157/158 compact block filters) |
| **Lightning** | LDK embedded (in-process, no external daemon) |
| **Storage** | SQLite (single file, zero-config) |
| **Discovery** | Static peer list + `.well-known` |
| **E2EE** | Full (PQXDH + MLS) |
| **Disk requirement** | ~500 MB (Neutrino filter set + local data) |
| **RAM** | ~256 MB |
| **Trust model** | Trusts Neutrino peers for chain state; verifies Lightning locally |

**Key tradeoff:** Cannot independently verify full blockchain history. Trusts compact block filter providers to be honest. Suitable for most users but not for high-value or high-security deployments.

### Tier 2: Standard Node

**Profile:** Recommended for most operators. Full Lightning capabilities with lightweight chain verification.

| Attribute | Value |
|-----------|-------|
| **Bitcoin verification** | Electrum client (connects to trusted Electrum server, ideally self-hosted) |
| **Lightning** | LND or CLN (external daemon, full routing capabilities) |
| **Storage** | PostgreSQL |
| **Discovery** | Static peers + `.well-known` + optional Tor |
| **E2EE** | Full |
| **Disk requirement** | ~5 GB (Electrum index subset + PostgreSQL + Lightning) |
| **RAM** | ~1 GB |
| **Trust model** | Trusts Electrum server for chain queries; full Lightning sovereignty |

**Key tradeoff:** Electrum server dependency. Mitigated by self-hosting Electrum or connecting to multiple servers with consensus validation.

### Tier 3: Full Node

**Profile:** Maximum sovereignty. Runs Bitcoin Core for independent chain verification.

| Attribute | Value |
|-----------|-------|
| **Bitcoin verification** | Bitcoin Core (full validation, pruned or archival) |
| **Lightning** | LND or CLN with full routing |
| **Storage** | PostgreSQL with encrypted backups |
| **Discovery** | All methods including Tor `.onion` and DHT |
| **E2EE** | Full |
| **Disk requirement** | ~50 GB (pruned) or ~600 GB (archival) + PostgreSQL + Lightning |
| **RAM** | ~2 GB |
| **Trust model** | Trustless Bitcoin verification; full Lightning sovereignty |

**Key tradeoff:** Resource requirements. Requires dedicated hardware or a capable VPS. Justified for operators who need or want maximum sovereignty.

### Tier 4: Infrastructure Node

**Profile:** Network backbone operator. Runs everything in Tier 3 plus contributes to mesh infrastructure.

| Attribute | Value |
|-----------|-------|
| **Bitcoin verification** | Bitcoin Core (archival, full index) |
| **Lightning** | Multiple channel partners, routing node |
| **Storage** | PostgreSQL cluster with replication |
| **Discovery** | All methods + acts as DHT bootstrap node |
| **E2EE** | Full |
| **Additional services** | Watchtower, Tor relay, peer bootstrap, network health monitoring |
| **Disk requirement** | ~1 TB+ |
| **RAM** | ~4 GB+ |
| **Trust model** | Fully trustless; contributes trust infrastructure to the network |

**Key tradeoff:** Operational complexity and cost. These nodes are the backbone — they provide bootstrap services, Lightning routing, and Tor relay capacity for lighter nodes.

### Tier Comparison Matrix

| Capability | T1 Light | T2 Standard | T3 Full | T4 Infra |
|------------|----------|-------------|---------|----------|
| Send/receive messages | Yes | Yes | Yes | Yes |
| Payment gate enforcement | Yes | Yes | Yes | Yes |
| E2EE (PQXDH + MLS) | Yes | Yes | Yes | Yes |
| Federation | Yes | Yes | Yes | Yes |
| Independent chain verification | No | Partial | Full | Full |
| Lightning routing | No | Yes | Yes | Yes |
| Tor connectivity | Optional | Optional | Yes | Yes + relay |
| DHT participation | Client | Client | Full | Bootstrap |
| Chain-data source for pricing (ADR-027) | Via peer | Via Electrum | Direct | Direct |
| Network services | None | None | Optional | Yes |

---

## 4. User Stories

### Operator Stories

#### OS-1: Deploy a T1 Light Node

> As a new operator, I want to run a single binary on a modest VPS so that I can join the Konsensus mesh with minimal setup.

**Acceptance criteria:**
- Download single binary, create `konsensus.toml` with Lightning seed phrase and peer list
- Run `konsensus start` — node generates identity, syncs Neutrino filters, opens Lightning channels
- Node appears in peer discovery within 5 minutes
- Can send and receive payment-gated messages within 10 minutes of first start

#### OS-2: Upgrade from T1 to T3

> As an existing T1 operator, I want to upgrade to a full node without losing my identity or message history.

**Acceptance criteria:**
- Change tier configuration in `konsensus.toml`
- Run `konsensus migrate --tier 3`
- Node installs/connects Bitcoin Core, begins IBD (initial block download)
- All existing identity keys, federation trust, and message history preserved
- Node continues operating at T1 level during IBD, upgrades to T3 when sync completes

#### OS-3: Federate Across Tiers

> As a T1 operator, I want to federate with a T3 operator's node so that tier differences don't prevent communication.

**Acceptance criteria:**
- Federation handshake succeeds regardless of tier mismatch
- Payment gate works identically across tiers (Lightning is universal)
- Message E2EE works identically across tiers
- Discovery works via shared mechanism (static peers, `.well-known`)

### User Stories

#### US-1: Send a Payment-Gated Message

> As a user connected to a Konsensus node, I want to send a message that requires Lightning payment so that I know my communication is spam-free and cryptographically authorized.

**Acceptance criteria:**
- Client creates message, node generates Lightning invoice
- Sender pays invoice, payment hash attached to message
- Recipient node verifies payment settlement before accepting
- Message is E2E encrypted — neither node operator can read content
- Message stored only on sender and recipient nodes

#### US-2: Join a Group Conversation

> As a user, I want to join a group chat where all participants have paid for access so that the conversation is economically gated.

**Acceptance criteria:**
- Room creator sets per-message or per-join price
- MLS group key established among participants
- Each message requires payment from sender
- Forward secrecy maintained — compromising one epoch doesn't reveal others
- Participants can be added/removed with proper MLS group operations

#### US-3: Verify Node Identity

> As a user, I want to verify that the node I'm connecting to is the authentic node and not an impersonator.

**Acceptance criteria:**
- Node identity derived from BIP-32 seed — deterministic and verifiable
- Node publishes Ed25519 public key at `.well-known` endpoint
- Federation peers verify signatures on every request
- User can independently verify node's Bitcoin address matches expected identity

---

## 5. Requirements Matrix

### Must-Have (v2 Launch)

| ID | Requirement | Principle | Notes |
|----|-------------|-----------|-------|
| M1 | Single binary deployment for all tiers | 1 | `konsensus` binary with `--tier` flag or config |
| M2 | BIP-32 seed-based identity | 1 | All keys derived from single seed |
| M3 | Payment gate with fail-closed enforcement | 2 | No message accepted without verified payment |
| M4 | E2EE for all messages (1:1 and group) | 4 | PQXDH for 1:1, MLS for groups |
| M5 | Native P2P transport (no Prosody) | 3 | Rust-native messaging, no external server |
| M6 | Federation with Ed25519 signatures | 3 | Carried forward from v1 with enhancements |
| M7 | Chain-aware message pricing wired to chain state (Principle 5 · ADR-027) | 5 | Dynamic per-kind pricing from block height / fees. Timechain CONTRACT pricing (ADR-028) is NOT a v2 launch requirement. |
| M8 | SQLite (T1) and PostgreSQL (T2-4) storage | 1 | Tier-appropriate persistence |
| M9 | LDK embedded Lightning (T1) | 1 | No external daemon required for light nodes |
| M10 | Configuration via `konsensus.toml` | 1 | Single config file, tier-aware defaults |
| M11 | Wire compatibility with v1 federation | — | v2 nodes must federate with v1 during transition |
| M12 | Audit logging (immutable) | — | Carried forward from v1 |

### Should-Have (v2.1)

| ID | Requirement | Principle | Notes |
|----|-------------|-----------|-------|
| S1 | Tor `.onion` connectivity | 3 | DNS-free, censorship-resistant federation |
| S2 | DHT-based peer discovery | 3 | Decentralized alternative to `.well-known` |
| S3 | Bitcoin Core integration (T3-4) | 1 | Full chain verification |
| S4 | LND/CLN gRPC integration (T2-4) | 1 | External Lightning daemon support |
| S5 | Watchtower service (T4) | — | Channel security for network participants |
| S6 | Tier migration tooling | 1 | `konsensus migrate` command |
| S7 | Multi-device key synchronization | 4 | Secure key export/import between devices |

### Nice-to-Have (v2.2+)

| ID | Requirement | Principle | Notes |
|----|-------------|-----------|-------|
| N1 | Mesh networking (physical layer) | 3 | LoRa, mesh radio for true infrastructure independence |
| N2 | Hardware security module support | 1 | HSM-backed key storage |
| N3 | WASM-based plugin system | — | Extensibility without recompilation |
| N4 | Network health dashboard | — | Monitoring for T4 operators |

---

## 6. Non-Goals

v2 explicitly does **not** attempt the following. These are out of scope to maintain focus on the core sovereign stack:

| Non-Goal | Rationale |
|----------|-----------|
| **Mobile client** | Mobile platforms (iOS/Android) impose app store gatekeeping that conflicts with sovereignty. A mobile client may come later but is not a v2 deliverable. |
| **Browser wallet** | Browser-based wallets introduce custody and security concerns. The node is the wallet. |
| **Fiat payment integration** | v2 is Bitcoin-native. Fiat on-ramps are a ChainBridge concern, not a protocol concern. |
| **Smart contract platform** | Konsensus is a communication protocol, not a computation platform. Chain-aware message pricing (ADR-027) uses Bitcoin's timechain as a fee/halving signal, not as a programmable-contract platform. The Agreements layer (ADR-028) composes audited primitives (CLTV/CSV/HTLC/Miniscript/DLC) but is itself out of scope for v2. |
| **Public relay/gateway mode** | Running a Konsensus node as a public relay would violate Principle 3 (Closed Mesh). Every node is sovereign, not a service provider for anonymous users. |
| **Backwards compatibility with XMPP clients** | v2's native transport is not XMPP. XMPP clients cannot connect directly. The Electron client will be updated for v2. |
| **Multi-tenant hosting** | One node, one operator. Multi-tenant hosting violates Principle 4. Managed hosting providers run separate node instances per customer. |
| **Consensus mechanism** | Konsensus is not a blockchain. It uses Bitcoin's consensus; it does not implement its own. |

---

## 7. Success Criteria

### v2 is ready for production when:

#### Functional Criteria

1. **Single binary runs on all 4 tiers** — `konsensus start` with appropriate config produces a functional node at each tier level
2. **Payment gate enforced at all tiers** — no message passes without verified Lightning payment (fail-closed, tested with fault injection)
3. **E2EE verified** — independent audit confirms PQXDH and MLS implementations are correct; no plaintext at rest or in transit
4. **Federation works cross-tier** — T1 and T4 nodes exchange messages with identical security guarantees
5. **Chain-aware message pricing operational (Principle 5 · ADR-027)** — message prices dynamically adjust based on block height and fee environment
6. **v1 wire compatibility** — v2 nodes federate with v1 nodes during transition period

#### Performance Criteria

7. **T1 cold start < 60 seconds** — from binary execution to accepting messages (excluding Neutrino sync)
8. **Message latency < 500ms** — end-to-end (payment verification + encryption + delivery) on local network
9. **T1 memory < 256 MB** — steady-state RAM usage for light nodes
10. **Handles 100 concurrent conversations** — per node, without degradation

#### Security Criteria

11. **Zero plaintext message storage** — at any layer, at any tier
12. **Key derivation audited** — BIP-32 seed to all derived keys verified by independent review
13. **Federation replay protection** — nonce-based, tested with replay attacks
14. **Payment gate bypass impossible** — verified by adversarial testing (fuzzing, protocol manipulation)

#### Operational Criteria

15. **Tier upgrade preserves state** — identity, trust, and history survive T1→T2→T3→T4 migration
16. **Documentation complete** — operator guide, API reference, and troubleshooting for all tiers
17. **Test coverage > 80%** — unit + integration + E2E across all tiers
18. **v1 test suite passes** — all 364 existing tests pass against v2 (where applicable)

---

*This PRD will be revised based on v1 production learnings. See [CURRENT_GAPS.md](CURRENT_GAPS.md) for the v1 audit that informs these requirements.*
