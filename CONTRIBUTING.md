# Contributing

BitSov is a sovereign protocol project. Contributions must preserve the
load-bearing commitments in `CHARTER.md`.

## Non-Negotiable Boundary

Do not submit changes that introduce:

- operator-held user mnemonics or device signing keys
- key escrow or custodial recovery
- operator-decryptable message plaintext
- operator-issued user payment proofs
- hidden dependency on MindLink infrastructure for protocol correctness

Commercial vendor code, live infrastructure, billing, customer data, strategy,
and deploy inventories belong outside the open core.

## Community

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Security policy](SECURITY.md)
- [Issue templates](.github/ISSUE_TEMPLATE/config.yml) (blank issues are off)
- [Pull request template](.github/pull_request_template.md)

## Building and Testing

Rust 1.89 or newer. Commands below are the ones in the README and in CI.

```bash
cargo build --release -p konsensus-node
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

CI's required Rust job also runs `cargo check --workspace`, then tests the
protocol crates (the vendored LDK node is too large for that runner to test
via `--workspace`):

```bash
cargo check --workspace
cargo test -p konsensus-recovery -p konsensus-core -p konsensus-crypto \
  -p konsensus-storage -p konsensus-message -p konsensus-pricing \
  -p konsensus-chain -p konsensus-routing -p konsensus-gossip \
  -p konsensus-bsx -p konsensus-lightning -p konsensus-api -p konsensus-node
cargo clippy --workspace -- -D warnings
```

PostgreSQL storage tests are ignored by default. CI runs them in
[`.github/workflows/postgres.yml`](.github/workflows/postgres.yml) against
`postgres:16`. Locally:

```bash
BITSOV_TEST_POSTGRES_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test -p konsensus-storage --locked -- --ignored postgres
```

## Pull Requests

- Keep protocol changes small and reviewable.
- Include tests for payment-gate, storage-wrapper, and encrypted-storage paths
  when touching those boundaries.
- Prefer config-gated behavior that defaults off for relay/operator roles.
- Use the [pull request template](.github/pull_request_template.md): summary,
  testing, security impact, and a confirmation that the request has no secrets
  or private plans.
- Public issues must not contain secrets, live node IDs, customer names, channel
  balances, txids, internal IPs, or unreleased security details.
- File bugs and feature requests with the templates under
  [`.github/ISSUE_TEMPLATE`](.github/ISSUE_TEMPLATE). Blank issues are disabled.

## Security Reports

Follow [SECURITY.md](SECURITY.md). Report privately with GitHub private
vulnerability reporting: **Security** tab, then **Report a vulnerability**.
Do not open a public issue for a suspected vulnerability.

Conduct reports use the same private channel. See
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
