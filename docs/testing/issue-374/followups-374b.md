# #374 follow-ups on `test/flake-followups-374b`

Base: `eb53792ea58fc058e3612a6bc6139256c6db989b` (includes #380).

## Changes

- Bootstrap CLI waits for the expected bootstrap/live JSON state, with a
  120-second overall readiness deadline and five-second probe requests.
  Ceremony requests allow 120 seconds for debug Argon2 work under CPU load.
  Mutating requests are never retried.
- Password refusal waits at most 120 seconds, then kills and reaps the child
  before failing. A sleeping-child regression exercises timeout cleanup.
- The on-chain detached-writer Drop barrier fails after 30 seconds.
- Reconnected message delivery is bounded at 28 seconds after both transports
  report reconnection. This excludes startup/connection scheduling while still
  rejecting the historical silent 30-second invoice timeout followed by retry.
- Clock type/field are crate-private. Injection is available only through
  `IntroductionSettings::with_test_clock` with the non-default `test-support`
  feature; API integration tests enable it via a self dev-dependency.
- Enable `zeroize` for locked aes-gcm 0.10.3, aes 0.8.4 and argon2 0.5.3.
  No package versions change. aes-gcm does not forward its zeroize feature to
  aes, so the node explicitly enables the backend feature. Argon2's allocating
  helper does not wipe its working Vec, so derivation now supplies a
  `Zeroizing<Vec<Block>>` and keeps the derived key in `Zeroizing<[u8; 32]>`.
- A fixed `.enc` fixture generated with the old dependency configuration
  decrypts before and after the change. It pins the KDF parameters, password
  whitespace, v1 header, ciphertext and tag; see the fixture README.

## Production-file audit

| File | Effect |
| --- | --- |
| Root `Cargo.toml` | Enables AES-GCM, AES and Argon2 memory wiping. |
| `Cargo.lock` | Feature dependency edges and test self-dependency only; no version changes. |
| `crates/konsensus-api/Cargo.toml` | Adds non-default test-support feature and dev-only enablement. |
| `crates/konsensus-node/Cargo.toml` | Enables zeroize on aes-gcm's existing AES backend. |
| `crates/konsensus-api/src/handlers/introduction.rs` | Restricts clock access and gates injection; default still calls the identical system clock. |
| `crates/konsensus-node/src/main.rs` | Uses `fixed` then restores the configured endpoint source; network, endpoint, source, discovery and default clock values are unchanged. |
| `crates/konsensus-node/src/mnemonic_crypto.rs` | Wipes Argon2 working memory and derived keys; parameters, password bytes, format and outputs are unchanged. |

All other code changes are test-only. Production behavior is unchanged except
for memory wiping. The production dependency feature graph contains all three
crypto zeroize features and does not contain `test-support`.

## Verification

| Command | Result |
| --- | --- |
| `cargo test --workspace --no-fail-fast` | Exit 0; 4,949 passed, 0 failed, 8 ignored; 194 targets. |
| Same command with eight `yes > /dev/null` workers | Exit 0; 4,949 passed, 0 failed, 8 ignored; 194 targets. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Exit 0. |
| `cargo +1.89.0 check --workspace --locked` | Exit 0 on installed Rust 1.89.0. |

All eight CPU workers were alive when the loaded suite completed, then received
SIGTERM and were reaped (eight exit codes of -15). The first run includes
compilation; the loaded run reused the compiled targets.

Both suites passed the bootstrap/restart, refusal deadline/cleanup, on-chain
Drop barrier, reconnect latency, clock-controlled sponsor expiry, and legacy
`.enc` fixture tests. The fixture also passed against the pre-zeroization code.
Clippy and the MSRV check retain the existing sqlx-postgres 0.8.0
future-incompatibility notice. No dependency version changed.

An independent read-only code review found no blocking or important issues.
Pre-existing plaintext-buffer handling outside this patch was left unchanged.
`git diff --check` passed. Machine-readable commands, exit statuses, timings,
worker cleanup, aggregate test counts and log hashes are in
[`followups-374b.json`](followups-374b.json).
