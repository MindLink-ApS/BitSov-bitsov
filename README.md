# BitSov

A sovereign mesh network where every user is a node with Bitcoin-anchored identity, payment-gated communication, and true data sovereignty.

BitSov replaces centralized platforms with a decentralized, privacy-respecting, Bitcoin-backed network for messaging, calls, file sharing, calendar, and collaboration.

## Principles

1. **Sovereign Identity** -- Your node IS your identity, derived from a BIP-39 mnemonic
2. **Lightning Gate** -- Every message costs real sats. Spam is economically impossible
3. **Closed Mesh** -- Whitelist-only federation. You choose who can reach you
4. **Data Sovereignty** -- End-to-end encrypted. Zero plaintext at any layer
5. **Chain-Aware Message Pricing** -- Message costs track Bitcoin's chain state (see `docs/v2/ADR-027`)

## Quick Start

### Option 1: Download Binary

Download the latest release from [GitHub Releases](https://github.com/BitSov/bitsov/releases).

```bash
# Initialize a new node (generates BIP-39 identity)
./konsensus init

# Start the node
./konsensus start
```

### Option 2: Docker

```bash
# Clone and run
git clone https://github.com/BitSov/bitsov.git
cd bitsov
docker compose up -d

# With Lightning (LNbits):
docker compose --profile lightning up -d
```

### Option 3: Build from Source

```bash
# Prerequisites: Rust 1.75+, Node.js 20+
git clone https://github.com/BitSov/bitsov.git
cd bitsov

# Build the node binary
cargo build --release -p konsensus-node

# Build the desktop app (requires Tauri CLI)
cd frontend
npm install
npx tauri build
```

## Configuration

Copy and edit the example config:

```bash
cp konsensus.toml.example konsensus.toml
```

Key settings:
- **Lightning backend**: LNbits (production) or Mock (development)
- **Storage**: SQLite (single node) or PostgreSQL (production)
- **Pricing**: Per-message-kind sat costs
- **Peers**: Whitelist of known nodes to connect to

See `konsensus.toml.example` for all options.

## Sovereignty Tiers

| Tier | Setup | Identity | Lightning | Storage |
|------|-------|----------|-----------|---------|
| **Relay** | Paired remote access | User-held keys | User-authorized payments | Relay-held ciphertext |
| **Light** | Download binary | Local mnemonic | User-selected Lightning | Local SQLite |
| **Full** | Self-hosted | HSM-ready | Own LDK/LND node | Encrypted SQLite/PostgreSQL |

## Architecture

> **Sovereignty Charter:** [`CHARTER.md`](CHARTER.md) is load-bearing. Operator-held mnemonics, key escrow, custodial recovery, and Tier-3 hosted-node custody are out of scope for BitSov.

BitSov is a Rust workspace with 9 crates (internal names prefixed `konsensus-`):

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
| `konsensus-node` | Binary entry point, CLI, content server |

The desktop frontend uses Tauri + SolidJS.

## Development

```bash
# Run all tests
cargo test --workspace

# Check for issues
cargo clippy --workspace -- -D warnings

# Run the frontend dev server
cd frontend && npm run dev
```

## License

MIT
