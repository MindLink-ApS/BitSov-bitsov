# BitSov

[![CI](https://github.com/MindLink-ApS/BitSov-bitsov/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/MindLink-ApS/BitSov-bitsov/actions/workflows/ci.yml)

A sovereign mesh network where every user is a node whose identity comes from its own user-held keys, and Bitcoin/Lightning pays for communication admission.

BitSov is a decentralized, privacy-respecting, Bitcoin-backed substrate where the node, not a platform account, owns the relationship. Today it carries messaging, scheduling and collaboration, and paid audio calls are in closed beta on signet: node-routed, priced by the callee per 60-second block (M6).

**Status:** BitSov is in closed beta with signet test nodes. Paid admission follows the [2026-07-01 keystone](docs/v2/F1-CAPPED-FIRST-CONTACT.md#stranger-payment-preparation-and-the-whitepaper-floor): the target re-prices and the requester pays the target's invoice. That is the mechanism, not scale. Location privacy, the relay and scale have **not** shipped; mainnet is not supported in this beta.

Node IDs and public keys are the protocol identity layer. IP addresses and DNS names are reachability hints, not identity or admission authority. Nodes may learn those hints through invites, QR codes, manual entry, relays, or other out-of-band discovery, but communication remains governed by the node identity, encryption state, and payment/admission policy.

## Principles

1. **Sovereign Identity** -- Your node identity is derived from user-held key material.
2. **Bitcoin/Lightning Gate** -- Message admission and abuse resistance are tied to settled payment policy (settlement-gated admission): each act is admitted by a settled, recipient-bound, single-use payment that the recipient checks against its own ledger. Paid admission raises the cost of unwanted traffic.
3. **Opt-In Mesh** -- You choose who can reach you through paid-open admission policy, explicit peer policy, or closed/private operation.
4. **Data Sovereignty** -- Message content is end-to-end encrypted using audited cryptographic primitives. Data lives on sender and receiver nodes, or their authorized ciphertext relays, with metadata caveats documented in the threat model.
5. **Chain-Aware Message Pricing** -- Message costs can track Bitcoin's chain state (see `docs/v2/ADR-027`).

## Quick Start

### Developer Preview: Build the CLI from Source

The public protocol/core repository is source-first until the signed release is published. Signed binaries and desktop app packages are release artifacts; they are published only after the final launch go/no-go.

Verifying a release: artifacts are signed with the release key described under [Reporting a Vulnerability in `SECURITY.md`](SECURITY.md#reporting-a-vulnerability); the release policy has the [pinned build recipe](docs/ops/RELEASE_POLICY.md#reproducibility-inputs) and the [independent rebuild gate](docs/ops/RELEASE_POLICY.md#independent-rebuild-gate-h3), and the per-release checklists live under [`docs/releases/`](docs/releases/).

```bash
# Prerequisite: rustup. The toolchain is pinned in rust-toolchain.toml (1.99.1)
# and installed automatically on the first build.
git clone https://github.com/MindLink-ApS/BitSov-bitsov.git
cd BitSov-bitsov
cargo build --release -p konsensus-node

# Initialize a light node in your home directory, outside the source checkout.
# Shows the 24-word recovery phrase, asks you to confirm three words, and
# encrypts the stored phrase with a password you type at the prompt.
./target/release/konsensus init --dir ~/bitsov-node --tier light --encrypt

# Start the node from the generated config; it prompts for the password.
./target/release/konsensus start --config ~/bitsov-node/konsensus.toml
```

Keep the node data directory out of source checkouts: it holds the recovery
phrase, identity and databases. `init` writes a `.gitignore` ignoring everything
into the data directory and warns when that directory is inside a git working
tree. For unattended setups, pass the password on a descriptor instead of the
prompt (`init --non-interactive --password-fd 0`, then `start --password-fd 0`);
see [password input](docs/operations/password-input.md).

## Configuration

`konsensus init` writes `konsensus.toml` into the selected node data directory.

Key settings:
- **Lightning backend**: LDK (embedded) or LND (direct REST) for production; Mock for development. LNbits cannot enforce per-payment routing-fee ceilings: fee-limited payments fail closed, and selecting LNbits is rejected at configuration/startup (see [all-in fee caps](docs/v2/ALL-IN-FEE-CAPS.md)).
- **Chain view**: your own Bitcoin Core (pruned or full) or an Electrum server; public Esplora is still the default for a fresh `init` and is a third-party view of the chain (see [choose your chain source](docs/CHAIN-SOURCE.md)).
- **Storage**: SQLite (single node) or PostgreSQL (production)
- **Pricing**: Per-message-kind sat costs
- **Peers**: Opt-in peers. Node IDs are the protocol identity; network addresses are reachability hints obtained out-of-band.

### CLN (preview)

Connect to an existing Core Lightning node over pinned-CA HTTPS for invoices,
settlement lookup, balances, channels and payment history. Outgoing payments
and keysend remain disabled in this preview.
See the [CLN configuration reference](docs/CLN.md).

## Deployment profiles

| Profile | Setup | Identity | Lightning | Storage |
|------|-------|----------|-----------|---------|
| **Relay** | Paired remote access | User-held keys | User-authorized payments | Relay-held ciphertext |
| **Light** | Build from source (signed binaries after the launch go/no-go) | Local mnemonic | User-selected Lightning | Local SQLite |
| **Full** | Self-hosted | HSM-ready | Own LDK/LND node | Encrypted SQLite/PostgreSQL |

`init --tier light|full` selects the onboarding mode (see the [glossary](docs/DESIGN-REASONING.md#7-glossary-the-five-meanings-of-tier)). All profiles use node identity as the canonical endpoint identifier. Reachability hints are secondary.

> **Availability:** the **Light** and **Full** (self-host) tiers are the current closed-beta path on signet test nodes. The **Relay** tier (operator-run ciphertext relay) is on the roadmap; relay/reachability remains the next major production-readiness milestone.

## Architecture

> **Sovereignty Charter:** [`CHARTER.md`](CHARTER.md) is load-bearing. Operator-held mnemonics, key escrow, custodial recovery, and Tier-3 hosted-node custody are out of scope for BitSov.

BitSov's public protocol/core export is a Rust workspace with 14 crates (internal names prefixed `konsensus-`):

| Crate | Purpose |
|-------|---------|
| `konsensus-core` | Types, traits, identity, UKM envelope, payment gate |
| `konsensus-crypto` | X3DH key agreement, Double Ratchet E2EE, Sender Keys |
| `konsensus-message` | Noise_XX transport, wire protocol, P2P mesh |
| `konsensus-lightning` | LDK/LND providers, development mocks, and a legacy LNbits adapter (no fee-limited payments) |
| `konsensus-chain` | Bitcoin chain providers: Bitcoin Core RPC, Electrum and Esplora |
| `konsensus-pricing` | Static and chain-aware pricing engines |
| `konsensus-storage` | SQLite/PostgreSQL with optional at-rest encryption |
| `konsensus-api` | REST + WebSocket API, JWT auth, rate limiting |
| `konsensus-routing` | Adaptive mesh routing weights and routing table |
| `konsensus-gossip` | Gossip protocol for public data propagation |
| `konsensus-node` | Binary entry point, CLI, content server |
| `konsensus-bsx` | Constrained JSON document format parser/renderer |
| `konsensus-fiat` | Fiat-rate provider traits for local display conversion |
| `konsensus-recovery` | Offline recovery of LDK static `to_remote` outputs from the seed, optionally indexed by a channel backup |

The desktop app is packaged separately from the protocol/core export.

## Development

```bash
# Run all tests
cargo test --workspace

# Check for issues
cargo clippy --workspace -- -D warnings

# PostgreSQL storage tests (ignored by default; need a disposable server)
BITSOV_TEST_POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test -p konsensus-storage --locked -- --ignored postgres
```

CI runs the PostgreSQL tests in the separate, non-blocking
[`PostgreSQL Tests`](.github/workflows/postgres.yml) workflow against a
`postgres:16` service container.

## License

MIT

Hub operators can opt into the [LSPS2 provider pilot](docs/LSPS2-LIQUIDITY.md#hub-provider-pilot) for app JIT funding, with opening fees and a configurable post-open forwarding tariff. It is disabled by default; admission remains a separate stateless payment.

For long-running nodes, see [bounded file and service logging](docs/operations/LOGGING.md): `node.log` and `ldk_node.log` default to 10 MiB × 5 files each. Remove legacy stdout redirection into these managed files.
