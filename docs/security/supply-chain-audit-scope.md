# Supply-chain audit scope

This file is the scope note cited from `deny.toml`. It records what the automated dependency gate covers and which advisories that gate currently ignores. It is not a third-party audit of ldk-node, snow, or the rest of the cryptography and Lightning surface.

## What CI runs

The `Cargo Audit` job in `.github/workflows/ci.yml` is the blocking supply-chain check. It runs on pushes to `main`, on `v*` tags, in the merge queue, and on pull requests that change `Cargo.lock`, `deny.toml`, `.cargo/audit.toml`, or the other advisory inputs listed in that workflow.

Pinned in that workflow:

- `cargo deny --locked check advisories bans sources` (cargo-deny). An unignored security advisory fails the job. `bans` and `sources` are included because they pass on the current lockfile. `cargo deny check licenses` is not run.
- `cargo audit` (cargo-audit). The same cargo-audit version is pinned in `.github/workflows/security-scan.yml`, and the version is part of each job's cache key.

`deny.toml` sets `yanked` and `unused-ignored-advisory` to `warn`. Those warnings do not fail the job. A vulnerability that is not in `[advisories].ignore` does.

The daily security scan still runs cargo-audit, osv-scanner, and gitleaks. It does not run cargo-deny.

## Known debt

These IDs are listed in `deny.toml` `[advisories].ignore`. Each entry there has a `reason`. Fuller triage is in `.cargo/audit.toml`. When the pin that forces the crate is removed, `unused-ignored-advisory = "warn"` is set so a stale ignore is visible.

| Advisory | Locked crate | Why it remains |
| --- | --- | --- |
| RUSTSEC-2024-0363 | sqlx 0.8.0 | Workspace pin `=0.8.0`, forced by ldk-node 0.7 → rusqlite 0.31 → libsqlite3-sys 0.28. The fixed release is 0.8.1. |
| RUSTSEC-2026-0346 | rustls 0.21.12 | Same sqlx pin, plus test-only minreq. The patched line is 0.23, already used outside this island. |
| RUSTSEC-2026-0349 | rustls 0.21.12 | Same rustls 0.21 island as RUSTSEC-2026-0346. |
| RUSTSEC-2026-0098 | rustls-webpki 0.101.7 | Legacy rustls 0.21 via sqlx-core 0.8.0. The 0.103.x copy is already patched. |
| RUSTSEC-2026-0099 | rustls-webpki 0.101.7 | Same legacy rustls-webpki copy as RUSTSEC-2026-0098. |
| RUSTSEC-2026-0104 | rustls-webpki 0.101.7 | Same legacy rustls-webpki copy as RUSTSEC-2026-0098. |
| RUSTSEC-2026-0382 | rustls-webpki 0.101.7 | Same legacy rustls-webpki copy as RUSTSEC-2026-0098. |
| RUSTSEC-2026-0381 | webpki-roots 0.25.4 | Legacy root bundle via sqlx-core 0.8.0 and test-only minreq. The separate 1.0.x copy is already patched. |
| RUSTSEC-2026-0367 | zip 0.6.6 | Test harness only (electrsd / corepc-node download). Not in the shipped binary. No compatible harness release drops zip 0.6. |
| RUSTSEC-2026-0368 | zip 0.6.6 | Same test-harness zip copy as RUSTSEC-2026-0367. |
| RUSTSEC-2026-0369 | zip 0.6.6 | Same test-harness zip copy as RUSTSEC-2026-0367. |

cargo-audit also reports one allowed maintenance warning, `paste` 1.0.15 (`RUSTSEC-2024-0436`). That warning does not fail `cargo audit`, and it is not in the deny ignore list above.
