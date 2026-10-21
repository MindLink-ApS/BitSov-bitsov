# BitSov Electrum root-store patch

Baseline: crates.io `electrum-client` **0.24.1**, upstream
https://github.com/bitcoindevkit/rust-electrum-client, commit
`761796c94ae29a41651914796c926bbabf8784c8`, archive SHA-256
`a5059f13888a90486e7268bbce59b175f5f76b1c55e5b9c568ceaa42d2b8507c`.
Extracted from the cached crates.io archive; original MIT license retained.

Changes from that archive:

- `Cargo.toml` and `Cargo.toml.orig`: raise optional `webpki-roots` from
  `0.25` to `1.0.10` (Cargo's compatible 1.x range, minimum 1.0.10).
  This removes the distrusted emSign root covered by RUSTSEC-2026-0381.
- `src/raw_client.rs`: remove the obsolete `Der`/`TrustAnchor` imports and
  collect cloned `TLS_SERVER_ROOTS` directly into `RootCertStore`.
  webpki-roots 1.x already exposes rustls's `TrustAnchor` type; the old
  field-by-field conversion is no longer needed. Both direct and SOCKS TLS
  connections use this construction. Domain validation and crypto-provider
  selection are unchanged.
- Omit registry metadata `.cargo_vcs_info.json` (provenance is above), the
  standalone `Cargo.lock` (the root workspace lock is authoritative), and
  upstream-only `.gitignore` and `.github/workflows/cont_integration.yml`.
  All upstream source, examples, tests, manifest features, and license remain.
- Add this patch note. The workspace excludes this directory and selects it
  through `[patch.crates-io]`, as with `vendor/esplora-client`.

Verification uses the workspace's locked graph:

```sh
cargo check --locked -p electrum-client
cargo test --locked -p konsensus-chain --test electrum
cargo test --locked -p electrum-client --lib
cargo clippy --workspace -- -D warnings
cargo test --workspace --locked
```

The upstream library suite passed: 28 passed, 17 upstream-ignored tests.
`raw_client::test` uses a live public Electrum server, so this run requires
network access. The workspace's six Electrum integration tests passed against
local fixtures. Existing upstream ignore annotations are unchanged.

The locked workspace enables `proxy,use-rustls-ring`, compiling both direct
and SOCKS rustls TLS paths. A separate AWS-LC feature check could not resolve
rustls 0.23.46's `aws-lc-rs ^1.18` requirement in the available registry; that
optional backend is not claimed verified. The upstream lifetime-style warning
in `src/batch.rs` is retained to keep the source patch minimal.
