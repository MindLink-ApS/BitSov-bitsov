# GitHub Actions minutes

Measured 2026-10-06 from recent GitHub-hosted Ubuntu runs. Estimates use
per-job whole-minute billing, so several short parallel jobs cost more than the
workflow's wall-clock time.

## Before

| Lane | Observed runtime | Estimated billed minutes |
| --- | ---: | ---: |
| `Rust Check & Test` | 23–25 min | 23–25 |
| Cargo Audit | 12–17 sec | 1 |
| Semgrep | 29–31 sec | 1 |
| Frontend sentinel | 6–7 sec | 1 |
| Offline release signing | 11–12 sec | 1 |
| PostgreSQL tests, when selected | 1 min 20 sec | 2 |
| Nightly three-node regtest | about 13 min | 14 |
| Weekly security scan | under 1 min | 1 |

Every PR, including docs-only ones, therefore consumed about 27–29 billed
minutes in the main CI workflow, of which 23–25 were the Rust workspace job.

## After

- A path-classification job runs for every PR. `dorny/paths-filter` is set to
  `predicate-quantifier: 'every'`, so a changed file counts as Rust-impacting
  unless it matches a docs-only pattern: `docs/**`, Markdown files, `LICENSE`,
  `.gitignore`, `CODEOWNERS`, or `.github/dependabot.yml`. `SECURITY.md` is
  always Rust-impacting because Cargo Audit validates it. Only a PR whose every
  changed file is docs-only skips Rust tests and Cargo Audit.
- The skipped jobs retain the exact required check names. GitHub reports
  job-level skips as successful, so branch protection still receives
  `Rust Check & Test` and `Cargo Audit`; Semgrep and Frontend continue to run.
- Classification fails closed. If the classification job fails, is skipped,
  or produces no result, `Rust Check & Test` and `Cargo Audit` run anyway.
  They are skipped only after classification succeeds and reports docs-only.
- Draft PRs run the same checks as ready PRs. A draft is never skipped, so a
  green required check on a code commit always means the check actually ran.
- A new commit cancels an older in-progress run for the same PR. Main-branch
  and tag runs are not cancelled by workflow concurrency, with one GitHub
  limitation: a group holds at most one running and one pending run, so a
  newer push to `main` replaces an older run that is still queued behind it.
  The run for the latest `main` commit always executes, so the tip of `main`
  is always validated; an intermediate commit may be skipped when pushes land
  while a run is in progress.
- Rust dependency build artifacts are restored with `Swatinem/rust-cache`,
  whose key includes `Cargo.lock`, the compiler, runner platform, and job
  settings. Cargo Audit, releases, and the weekly scan retain their existing
  lockfile-keyed caches.

A docs-only PR is estimated at about 4 billed minutes: classification,
Semgrep, Frontend, and offline release signing, instead of 27–29. The share of
PRs that qualify has not been measured against the filter, so no overall
percentage saving is claimed. A PR that touches any non-docs file still runs
every required check; warm dependency caches should reduce its dominant Rust
job, but the exact saving depends on cache population and which crates
changed. Cancellation saves the unused remainder of superseded PR runs.

Pushes to `main` and release tags retain full validation. The scheduled
three-node paid regtest is intentionally unchanged.
