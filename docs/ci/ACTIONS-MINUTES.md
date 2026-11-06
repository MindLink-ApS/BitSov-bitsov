# GitHub Actions minutes

Measured from GitHub-hosted runs on 2026-10-21 (`gh run list` and per-job
`actions/runs/.../jobs` timings). GitHub bills each job by rounding its
duration up to the next minute. Linux runners are 1×. The release matrix is
the exception: macOS is 10× and Windows is 2×, and it runs only on `v*` tags.

`BitSov-bitsov` is a public repository, so standard hosted minutes are not
deducted from the org allowance. The org spending limit still disables Actions
for every repository once private usage exceeds it. The same workflow shape is
the recipe for a private consumer such as the app repository.

## What a run costs

| Job | Observed | Billed |
| --- | ---: | ---: |
| `Rust Check & Test` (successful, registry cache hit) | 26 min, of which `cargo test` is ~22 min | 27 |
| `Rust Check & Test` (mean, including failed runs) | 20 min | 21 |
| `Vendored LDK Node Security Regressions` | 1.2 min | 2 |
| Cargo Audit | 15–20 sec | 1 |
| Semgrep | ~30 sec | 1 |
| Frontend sentinel | ~6 sec | 1 |
| Offline release signing | ~12 sec | 1 |
| Classify changes | ~6 sec | 1 |
| PostgreSQL tests, when the job runs | ~1.5 min | 2 |
| Three-node paid regtest | ~14 min | 15 |
| Security scan | under 1 min | 1 |

A code pull request therefore costs about **28 billed minutes** in `CI`, plus
**2** when PostgreSQL tests run (about 72% of recent pull requests). A push to
`main` costs about **34**. Docs-only pull requests stay near **4** (classify,
Semgrep, frontend, signing).

Volume for 1–21 October 2026, scaled by 30/21 to a 30-day month: about 633
pull-request CI runs and 189 pushes to `main`.

## Why the Rust job stays long after a cache hit

`Swatinem/rust-cache` was already in use and did hit (`Cache Size: ~554 MB`),
but with the defaults `cache-all-crates: false` and `cache-workspace-crates:
false`. Path dependencies under `vendor/` (Lightning, `ldk-node`) were
recompiled on every test. The job then deleted `libldk_node-*` before
`cargo test`, so a restored library would have been thrown away. Test
*execution* is a few minutes; the rest is codegen. `ubuntu-latest` had about
100GB free at that step, so the deletion was not buying disk.

## What changed

- Pull-request concurrency still cancels a superseded run. Pushes, tags, and
  merge-queue runs are not cancelled. Required CI does not subscribe to label
  events; adding or removing labels cannot replace a required check result.
- Docs-only and `pm/**` changes skip the Rust jobs. `Frontend Build` has no
  `if` and always runs, so a pull request still reports a completed check.
  Workflow-level `paths-ignore` is not used on `pull_request` (a skipped
  workflow never reports, and required checks stay pending).
- `Rust Check & Test` still runs `cargo check`, `cargo test`, and `cargo
  clippy` on every non-docs pull request. That required check is the merge
  gate and is not moved behind the merge queue.
- The Rust job caches path and workspace crates, wraps `rustc` with `sccache`,
  builds without debuginfo (`CARGO_PROFILE_*_DEBUG=0`, assertions unchanged),
  and deletes `ldk-node` artifacts only when free disk drops under 10GB.
- PostgreSQL tests run on storage-path pushes to `main`, the merge queue,
  `workflow_dispatch`, and when `full-ci` is added to a non-draft PR. Other
  labels cannot restart or cancel the suite. The job name is unchanged. It is
  not a required check; a skipped run is not a pass.
- The release matrix stays on `v*` tags only.
- `Cargo Audit` runs when `Cargo.lock`, `.cargo/audit.toml`, `SECURITY.md`, or
  the security-key scripts change, on every main push, on `v*` tags, in the
  merge queue, and on PR code pushes with an existing `full-ci` label. The
  daily security scan runs `cargo audit` against the default
  branch every day at 06:00 UTC. The check name is unchanged. Both path-filter
  steps are PR-only; main, tags, and the merge queue run all CI jobs without
  classifying files. The release matrix remains tag-only.
- Vendored `ldk-node` security regressions still run on Rust pull requests.

## Estimate

Guaranteed cuts are jobs that no longer start. The Rust-job cut assumes a warm
cache of the vendored crates (the 22 minute `cargo test` step falls to about
12 minutes of rebuild-plus-execution). The first run after a lockfile change
stays cold for `rust-cache`; `sccache` still covers crates whose versions did
not move. Treat the Rust column as an estimate.

| Lane | Runs / 30 days | Before min/run | After min/run | Before | After |
| --- | ---: | ---: | ---: | ---: | ---: |
| Pull-request CI | 633 | 28 | 19 | 17,700 | 12,000 |
| Push to `main` CI | 189 | 34 | 25 | 6,400 | 4,700 |
| PostgreSQL on pull requests | 456 | 2 | 0 | 900 | 0 |
| PostgreSQL on `main` | 91 | 2 | 2 | 180 | 180 |
| Three-node regtest | 58 | 15 | 15 | 870 | 870 |
| Security scan | 4 → 30 | 1 | 1 | 4 | 30 |
| **Total** |  |  |  | **~26,100** | **~17,800** |

About **8,000 billed minutes per month** (~30%), of which roughly **1,400** are
guaranteed (PostgreSQL off ordinary pull requests, Cargo Audit skipped unless
its inputs changed, minus the extra daily scans) and the rest is the smaller
Rust job.

Per ordinary code pull request (lockfile unchanged): about **28 → 19** in CI,
and **2 → 0** for PostgreSQL when that workflow used to run. About **9–11
minutes saved per pull request**. A Dependabot pull request still runs Cargo
Audit. A docs-only or `pm/`-only pull request stays near 4 minutes.

Add `full-ci` to a non-draft pull request to run PostgreSQL and the separate
`Full CI Cargo Audit (optional)` check before merge. These optional workflows
only handle PR `labeled` events and start runners only when the added label
is `full-ci`. Remove and re-add it to request another optional run. Keep both
optional checks out of branch protection. Required CI is unaffected by label
events and reads an existing `full-ci` label on its next code push.

Create the repository label once manually if it does not already exist.
CI does not create `full-ci`. No workflow grants `actions: write` or
`issues: write`; the cache actions use the Actions runtime credentials.
All sccache action references are pinned to the v0.0.11 commit SHA.
