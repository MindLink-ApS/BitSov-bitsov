# BitSov

A sovereign mesh network where every user is a node with Bitcoin-anchored identity, payment-gated communication, and user-held keys.

BitSov is a decentralized, privacy-respecting, Bitcoin-backed substrate where the node, not a platform account, owns the relationship. Today it carries messaging, scheduling, and collaboration; calls and file-sharing are on the roadmap.

Node IDs and public keys are the protocol identity layer. IP addresses and DNS names are reachability hints, not identity or admission authority. Nodes may learn those hints through invites, QR codes, manual entry, relays, or other out-of-band discovery, but communication remains governed by the node identity, encryption state, and payment/admission policy.

## Principles

1. **Sovereign Identity** -- Your node identity is derived from user-held key material.
2. **Bitcoin/Lightning Gate** -- Message admission and abuse resistance are tied to settled payment policy. Paid admission raises the cost of unwanted traffic.
3. **Opt-In Mesh** -- You choose who can reach you through paid-open admission policy, explicit peer policy, or closed/private operation.
4. **Data Sovereignty** -- Message content is end-to-end encrypted using audited cryptographic primitives. Data lives on sender and receiver nodes, or their authorized ciphertext relays, with metadata caveats documented in the threat model.
5. **Chain-Aware Message Pricing** -- Message costs can track Bitcoin's chain state (see `docs/v2/ADR-027`).

## Quick Start

### Developer Preview: Build the CLI from Source

The public protocol/core repository is source-first until the signed release is published. Signed binaries and desktop app packages are release artifacts; they are published only after the final launch go/no-go.

```bash
# Prerequisite: Rust 1.75+
git clone https://github.com/MindLink-ApS/BitSov-bitsov.git
cd BitSov-bitsov
cargo build --release -p konsensus-node

# Initialize a local light node (generates BIP-39 identity material)
./target/release/konsensus init --dir ./node-data --non-interactive --tier light

# Start the node from the generated config
./target/release/konsensus start --config ./node-data/konsensus.toml
```

## Configuration

`konsensus init` writes `konsensus.toml` into the selected node data directory.

Key settings:
- **Lightning backend**: LNbits (production) or Mock (development)
- **Storage**: SQLite (single node) or PostgreSQL (production)
- **Pricing**: Per-message-kind sat costs
- **Peers**: Opt-in peers. Node IDs are the protocol identity; network addresses are reachability hints obtained out-of-band.

## Sovereignty Tiers

| Tier | Setup | Identity | Lightning | Storage |
|------|-------|----------|-----------|---------|
| **Relay** | Paired remote access | User-held keys | User-authorized payments | Relay-held ciphertext |
| **Light** | Download binary | Local mnemonic | User-selected Lightning | Local SQLite |
| **Full** | Self-hosted | HSM-ready | Own LDK/LND node | Encrypted SQLite/PostgreSQL |

All tiers use node identity as the canonical endpoint identifier. Reachability hints are secondary.

> **Availability:** the **Light** and **Full** (self-host) tiers are the current shippable path. The **Relay** tier (operator-run ciphertext relay) is on the roadmap; relay/reachability remains the next major production-readiness milestone.

## Architecture

> **Sovereignty Charter:** [`CHARTER.md`](CHARTER.md) is load-bearing. Operator-held mnemonics, key escrow, custodial recovery, and Tier-3 hosted-node custody are out of scope for BitSov.

BitSov's public protocol/core export is a Rust workspace with 13 crates (internal names prefixed `konsensus-`):

| Crate | Purpose |
|-------|---------|
| `konsensus-core` | Types, traits, identity, UKM envelope, payment gate |
| `konsensus-crypto` | X3DH key agreement, Double Ratchet E2EE, Sender Keys |
| `konsensus-message` | Noise_XX transport, wire protocol, P2P mesh |
| `konsensus-lightning` | LightningProvider trait + LNbits implementation |
| `konsensus-chain` | Bitcoin chain provider + Esplora implementation |
| `konsensus-pricing` | Static and chain-aware pricing engines |
| `konsensus-storage` | SQLite/PostgreSQL with optional at-rest encryption |
| `konsensus-api` | REST + WebSocket API, JWT auth, rate limiting |
| `konsensus-routing` | Adaptive mesh routing weights and routing table |
| `konsensus-gossip` | Gossip protocol for public data propagation |
| `konsensus-node` | Binary entry point, CLI, content server |
| `konsensus-bsx` | Constrained JSON document format parser/renderer |
| `konsensus-fiat` | Fiat-rate provider traits for local display conversion |

The desktop app is packaged separately from the protocol/core export.

## Development

```bash
# Run all tests
cargo test --workspace

# Check for issues
cargo clippy --workspace -- -D warnings
```

## License

MIT
