# ldk-node 0.7.1 security backports

Base: `26e0b7e5` on `fix/ldk-0.2.7-security`. This branch retains the patched
ldk-node **0.7.0** vendor tree and selectively backports four fixes; it does not
claim to include every change in 0.7.1. The prior Lightning 0.2.7 review is recorded
in [../ldk-0.2.7](../ldk-0.2.7/README.md).

## Verified upstream provenance

Inspected the actual upstream Git objects, original PR merge ancestry, release
backport commit messages/diffs, and membership in tag `v0.7.1`. The annotated tag
object is `3534a3d2072c0d98ff4ecb677017033003d4888d`, dated 12 October 2026;
its peeled commit is `edc8916e289d39a4135b6eda66978a9f765396bb`.
The tagged `src/builder.rs` and `src/event.rs` are byte-identical to the previously
checksum-verified 0.7.1 registry archive (SHA-256
`9a890a268dd7430d16ae5a867d73070414beab83fc744b07147aab3a33e38360`).

| Fix | Original commit | Verified 0.7.1 release commit |
|---|---|---|
| [#1032](https://github.com/lightningdevkit/ldk-node/pull/1032), manager read failure | `03dafa9c30f16e2dcc39f3eba0678347a2af136f` | [`b5fa4c2ec011887e11e2a91dc66b9fc1a2427ead`](https://github.com/lightningdevkit/ldk-node/commit/b5fa4c2ec011887e11e2a91dc66b9fc1a2427ead) |
| [#899](https://github.com/lightningdevkit/ldk-node/pull/899), unauthorized skim | `44146f9c8cb82b9f2946525736b4303195aba743` | [`73a255b79b6025e97493c991bc458d5ab39ddeab`](https://github.com/lightningdevkit/ldk-node/commit/73a255b79b6025e97493c991bc458d5ab39ddeab) |
| [#1035](https://github.com/lightningdevkit/ldk-node/pull/1035), preimage log | `8828e52b8f066a512d62f5451efef550f644eb79` | [`b92fe5fb6108451ed33d0cd19994de49282dfa23`](https://github.com/lightningdevkit/ldk-node/commit/b92fe5fb6108451ed33d0cd19994de49282dfa23) |
| [#1157](https://github.com/lightningdevkit/ldk-node/pull/1157), required custom TLVs | `8dd1c9148ab73097f5c961216418303803f222fc` | [`68d21422ddab849d761f91c6451695d8751adca5`](https://github.com/lightningdevkit/ldk-node/commit/68d21422ddab849d761f91c6451695d8751adca5) |

The original commits are ancestors of PR merges `5e4197b0`, `53268f2e`,
`0119ce3c`, and `56407547`, respectively. #899's mainline change migrates JIT
parameters to metadata; upstream's 0.7.1 backport deliberately takes only the
missing fee check, and this branch follows that narrow backport. #1157 contains
three commits; this work takes its required-TLV fix. The pre-existing local
successful-receipt duplicate protection remains unchanged; the PR's separate
outbound circular-payment status change is outside this requested backport.

[Giving possiblyrandom access to OS randomness, rust-lightning #4719](https://github.com/lightningdevkit/rust-lightning/pull/4719)
merged as `0f3916781b9a36f7f33ad296700eb020bf353be7`, with implementation
[`b7c9935be7d59290c11b27967021c486b65b046d`](https://github.com/lightningdevkit/rust-lightning/commit/b7c9935be7d59290c11b27967021c486b65b046d).
Its `possiblyrandom/src/lib.rs` matches the resolved registry 0.2.1 source.
`cargo update -p possiblyrandom --precise 0.2.1` was run for the workspace and
both standalone vendor manifests. All three locks now select checksum
`9c564dbf654befd49035528299f1208a40508f6e07efb11c163444e304e4484f`.
No other dependency version changed. The new konsensus-crypto dev dependency
exercises the default-feature path without enabling the `getrandom` feature
that masked the upstream bug.

## Before and after

| Area | Before | After |
|---|---|---|
| Manager load | Any store read error creates a new manager; decoding errors already fail | Only `NotFound` creates a new manager; other read errors return `BuildError::ReadFailed`; decoding and successful restoration are unchanged |
| Unknown receive with skim | Local check rejects only BOLT11 stateless quotes | All unregistered receives with a nonzero skim fail backwards before record insertion/claiming, including keysend and BOLT12 |
| Successful send log | INFO includes full preimage | Logs amount, fee and payment hash; receipt and application event still contain preimage |
| Unknown required TLV | A manual receive can emit `PaymentClaimable` even though LDK would refuse the claim | Reject before exposing claimability with `InvalidOnionPayload(Some((tlv_type, 0)))`; odd custom TLVs remain supported |
| Hash/jitter randomization | possiblyrandom 0.2.0 can return zeros on a supported OS without an explicit feature | 0.2.1 enables OS entropy using the target cfg as well as the explicit feature |
| Lightning patch notes | Claimed a stale `reload_tests.rs` whitespace delta | Lists only the two remaining whitespace-cleanup files |

The work-admission refusal remains first. The fixed JIT gross/net minimum,
authorized fee ceiling, zero-fee retry receipt handling, successful-payment
duplicate guard, stateless quote authentication and expiry, and all wallet,
watchtower, capacity, peer and sync patches are retained. No wire format,
persistence encoding, public API or vendor package version changes.

`local-before.json` is the prior review's complete archive-relative patch
inventory, checked against the base commit. `local-after.json` uses the same
schema against original ldk-node 0.7.0 and Lightning 0.2.7 archives, recording
additions, omissions, packaging and per-file SHA-256 hashes. `preservation.json`
compares every tracked vendor file with the reviewed base. Only the two production
files above change in ldk-node; existing JIT test code is preserved, with a new
child test-module declaration appended. All other existing source/test files
are byte-identical. The affected source diffs contain only the upstream fix
hunks and test-module wiring; there is no whole-file formatting.

## Regression coverage and CI

The new `ldk-node-security` job in `.github/workflows/ci.yml` runs
`cargo test --locked --manifest-path vendor/ldk-node/Cargo.toml --lib` on Rust-impacting
changes, including all existing local patch regressions. It uses a separate
runner/cache with two build jobs and no debug information to limit memory/disk
pressure. This is necessary because the vendor crate is excluded from both
`--workspace` and CI's `-p konsensus-*` invocation.

- `security_071_builder.rs`: ports upstream's targeted store fault injector;
  checks Other, PermissionDenied, Interrupted and InvalidData errors, plus missing,
  corrupt and valid serialized manager state.
- `security_071_events.rs`: executes the real production handler on unstarted
  disposable nodes. Covers positive/zero keysend and BOLT12-offer skim, unknown
  even/odd TLVs on manual claims, and captured send logs with/without a fee while
  retaining the preimage in the payment store and application event.
- `konsensus-crypto/tests/possiblyrandom_regression.rs`: CI's existing crate
  selection runs an entropy smoke test on Linux/macOS/Windows. It fails with
  0.2.0's default feature set; this does not claim a cryptographic RNG test or
  guarantee entropy on unsupported platforms/OS failure.

See [VALIDATION.md](VALIDATION.md) for observed results and limits.

## Verification limits

The release tag's signature identity/trust was not independently authenticated.
GitHub web/API fetches were intermittently unavailable; actual public Git objects
and registry source supplied provenance instead. No requested source fix remains
unverified. No live node state, funded network, daemon, RPC backend, deployed
migration, or hosted GitHub Actions run was tested. Event fixtures verify the
application handler's decision and effects; they are not end-to-end malicious
onion or LSPS2 channel simulations.
