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

## Build and test

The toolchain is pinned in `rust-toolchain.toml` (currently `1.99.1`, with
clippy and rustfmt). `rustup` picks it up automatically; CI installs exactly
the same version. See [docs/ci/RUST-TOOLCHAIN.md](docs/ci/RUST-TOOLCHAIN.md)
for why, and for how to bump it. The minimum supported Rust (`rust-version`
in `Cargo.toml`) is a separate, lower number.

From the repository root:

```sh
cargo build --workspace
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets -- -D warnings
```

`--no-fail-fast` runs every test target, so one failure does not hide others.
A full debug build needs tens of GB of disk; `CARGO_PROFILE_DEV_DEBUG=0` and
`CARGO_PROFILE_TEST_DEBUG=0` make it much smaller. Some tests need a network
the sandbox may not have (IPv6, a private LAN interface); say so in the PR if
they fail for that reason, and show they also fail on unmodified `main`.

PostgreSQL storage tests are `#[ignore]`d. To run them, point
`BITSOV_TEST_POSTGRES_URL` at a disposable server (the tests create and drop
their own databases):

```sh
BITSOV_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:5432/postgres \
  cargo test -p konsensus-storage -- --ignored
```

### Formatting

The workspace is not `rustfmt`-clean as a whole. Format only what you change:
new or edited code must not add `rustfmt --check` differences in the files you
touch, but do not run `cargo fmt` across a crate, because that buries the real
change in unrelated reformatting.

### Test networks only

Tests, fixtures and reproductions use **regtest or signet only**, never
mainnet funds. The end-to-end harnesses live in `scripts/regress/` (for
example `three_node_paid_e2e.sh` and `two_node_paid_call_e2e.sh`) and run
against regtest. Never commit seed phrases, private keys, tokens,
credentials, payment preimages, live node IDs or internal hostnames, including
in logs or screenshots.

## Pull Requests

Open the PR with the template in `.github/pull_request_template.md`. Fill in:

- **Summary:** the problem, the change and the issue it closes.
- **Tests:** the commands you ran and their results, and any check you did
  not run and why.
- **No secrets / no mainnet:** tick each box only if it is true.


- Keep protocol changes small and reviewable.
- Include tests for payment-gate, storage-wrapper, and encrypted-storage paths
  when touching those boundaries.
- Prefer config-gated behavior that defaults off for relay/operator roles.
- Public issues must not contain secrets, live node IDs, customer names, channel
  balances, txids, internal IPs, or unreleased security details.

### Review and merge

A PR is ready to merge when:

- CI is green on its current head commit;
- two independent reviews have approved that **exact** head commit. A review
  of an earlier commit does not carry over after new pushes. A review counts
  as independent when it does not come from whoever built the change;
- a maintainer merges it. Contributors do not merge their own PRs.

Changes to payment, key-handling or other security-sensitive paths get the
closest scrutiny; expect review comments to be resolved, not just answered.

## Security Reports

Use private security disclosure channels. Do not open a public issue for a
suspected vulnerability until maintainers have triaged and published an advisory.
