# Offline validation

Run on macOS arm64, rustc 1.91.1 / cargo 1.91.1. All builds and test processes
(including descendants) ran under:

```sh
sandbox-exec -p '(version 1)(allow default)(deny network*)' cargo ... --offline --locked
```

No real node, RPC, chain backend, Lightning peer, daemon or live-state migration
was exercised. Even loopback and Unix-domain socket fixtures are denied.
Separate `cargo fetch --locked` operations downloaded dependencies before these
runs; downloading public source/dependencies is distinct from node runtime use.
`CARGO_BUILD_JOBS=2` or `3`, `CARGO_PROFILE_DEV_DEBUG=0` and
`CARGO_PROFILE_TEST_DEBUG=0` reduced build memory. Target directories were outside
the checkout. No ignored tests were enabled.

## Completed checks

| Command (inside network-denial sandbox) | Result |
|---|---|
| `cargo build --offline --locked` | PASS |
| `cargo test --offline --locked --manifest-path vendor/lightning/Cargo.toml --lib` | 1,220 passed, 0 failed, 9 pre-existing ignored |
| `cargo test --offline --locked --manifest-path vendor/ldk-node/Cargo.toml --lib` | 154 passed, 0 failed, 0 ignored |
| Upstream liquidity 0.2.7 `--features _test_utils --test lsps2_integration_tests` against vendored Lightning | 17 passed, 0 failed |
| Same suite plus `scripts/regress/ldk-lsps2-underfunded.patch` | 18 passed, 0 failed |
| `git diff --check` | PASS |
| `git diff 9fdb1480 -- vendor/ldk-node/src` | Empty: all node source/test patches preserved byte-for-byte |

The first build failed with background-processor 0.2.0 expecting `Result<(), Error>`
where the updated liquidity persistence API returns `Result<bool, Error>`.
Updating that unmodified registry companion to 0.2.3 resolved it; the final build
passes. The standalone Lightning suite and node suite were run against the final
production source/dependency set. Build warnings include the existing
sqlx-postgres 0.8.0 future-incompatibility warning; extracted liquidity tests emit
upstream unexpected-cfg warnings. Warnings were not represented as errors or hidden.

## Security regression sensitivity

1. **Channel reestablish:** in a temporary copy of the final Lightning tree,
   remove only `&& is_awaiting_remote_revoke` from the retransmission condition.
   Run `cargo test --offline --locked --manifest-path <copy>/Cargo.toml --lib
   test_data_loss_protect`. It fails (0 passed, 1 failed) because the old behavior
   produces four messages instead of the expected three when rejecting a rollback.
   Restore the exact final `channel.rs`: the same test passes (1 passed, 0 failed).
   The complete final Lightning suite also includes this regression and legitimate
   reconnect cases. The larger mainline theft demonstration was not backported
   into this release's test suite; no claim is made that it ran here.

2. **LSPS2:** apply the supplied regression patch to an extracted, verified
   lightning-liquidity 0.2.7 archive. It exercises the service API with a real
   pending intercepted HTLC and an injected outbound amount exceeding its recorded
   inbound amount. It does not construct a malicious onion or reproduce an
   end-to-end theft. The subsequent valid HTLC verifies SCID preservation; it was
   pending in ChannelManager, not already queued in the LSPS2 JIT state machine.
   Disable only the service's amount guard in this isolated copy: 0 passed,
   1 failed at the assertion that over-declared amounts must be rejected before
   opening. Restore the original archive service source: the full 18-test suite
   passes. An initial test-harness cleanup failure was corrected by asserting and
   draining the expected `HTLCHandlingFailed` event; no production fix was changed.

3. **Electrum:** verified the exact release-branch fix against package source and
   confirmed the build resolves it and the application constructs its client.
   No electrs/bitcoind integration or live Electrum test was run. This is source
   and build verification for that path, not runtime verification against a server.

The regressions were mutated only in `/private/tmp/ldk-security-upstream/` copies;
committed production code and the Cargo registry cache were never weakened.

## Reproduce the additional LSPS2 regression

Use the checksum in README.md to verify the downloaded archive before extraction.
The following runs only in-memory protocol fixtures; on macOS retain the OS
network sandbox shown above. `security_test_dir` must be a disposable directory
outside this workspace, and `repo_dir` is this checkout's absolute path.

```sh
tar -xzf lightning-liquidity-0.2.7.crate -C "$security_test_dir"
cd "$security_test_dir/lightning-liquidity-0.2.7"
patch -p1 < "$repo_dir/scripts/regress/ldk-lsps2-underfunded.patch"
```

Append to that copy's Cargo.toml, substituting the absolute path:

```toml
[patch.crates-io]
lightning = { path = "/absolute/repo/vendor/lightning" }
```

Copy the repo's Cargo.lock to the temporary crate, then resolve its standalone
test-only dependencies once with `cargo metadata --offline --format-version 1`.
This retains the production package pins and adds cached backtrace dependencies.
Run:

```sh
sandbox-exec -p '(version 1)(allow default)(deny network*)' \
  cargo test --offline --locked --features _test_utils --test lsps2_integration_tests
```

The nine ignored upstream Lightning tests are listed in the run logs; all nine
are pre-existing async-payments expiry/refresh tests. They remain ignored.

## Review

An independent reviewer compared every local Rust delta to its upstream baseline,
checked the sole merge-conflict resolution, authenticated inbound-amount dataflow,
reconnect safety branches, Electrum registration/reorg selection, TLV allocation
and lockfile alignment. It found no critical or important issue in this targeted
integration and approved the additional regression with its boundary clarified
above. This was not an exhaustive audit of all upstream changes or LDK Node 0.7.1.

## Full workspace result

`cargo test --workspace --locked --offline --no-fail-fast` completed all **162**
unit, integration and doc-test targets under OS network denial: **4,188 passed,
386 failed, 7 ignored**. Exit status was **101**; **37 targets failed**. This is
**not a green full-workspace run**.

Every failed test was inspected for its denial diagnostic. 385 captured failure
blocks directly contain `PermissionDenied` or `Operation not permitted` (including
subprocess stderr). The remaining `owner_token_script_error_path_and_url_guard`
only reports the child script exit status. Re-running
`bash docs/ops/test-owner-token.sh` in the same sandbox confirms `PermissionError:
[Errno 1] Operation not permitted` when Python binds a temporary loopback socket.
No failure remains unclassified. These fixtures were not rerun with networking
enabled, and no test was weakened, removed or newly ignored. This establishes
why this run failed; it does not establish that those tests would pass with sockets
permitted, nor does it claim a separate baseline run was performed.

Representative node suite counts (already included in the workspace total):

| Target | Passed | Failed | Ignored |
|---|---:|---:|---:|
| konsensus-lightning library | 189 | 77 | 0 |
| konsensus-node library | 66 | 5 | 0 |
| konsensus-node `konsensus` binary | 716 | 96 | 1 |

[workspace-results.json](workspace-results.json) records each target's counts and
**every failed test name**, panic location, and classification. The aggregate
counts are summed from the harness summaries, with failure-block counts checked
against every summary. Its SHA-256 identifies the original captured workspace
log. Vendor and LSPS2 counts are additional runs, not part of that total. The
17-test LSPS2 run is superseded by the 18-test run, so do not add both together.

## Local evidence files

Full run logs remain at these local paths (not needed to reproduce the tests):

- `/private/tmp/ldk-security-build-final.log`
- `/private/tmp/ldk-security-lightning-tests.log`
- `/private/tmp/ldk-security-node-vendor-tests.log`
- `/private/tmp/ldk-security-workspace-tests.log`
- `/private/tmp/ldk-security-lsps2-red.log`
- `/private/tmp/ldk-security-lsps2-final.log`
- `/private/tmp/ldk-security-rollback-red.log`
- `/private/tmp/ldk-security-rollback-green.log`
- `/private/tmp/ldk-security-owner-token.log`
