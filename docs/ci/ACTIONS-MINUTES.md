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

A normal or docs-only PR therefore consumed about 27–29 minutes in the main CI
workflow. The Rust workspace job accounted for roughly 85% of that cost.

## After

- A path-classification job runs for every PR. Changes limited to `docs/**`,
  Markdown files, `LICENSE`, `.gitignore`, `CODEOWNERS`, or
  `.github/dependabot.yml` skip Rust tests and Cargo Audit.
- The skipped jobs retain the exact required check names. GitHub reports
  job-level skips as successful, so branch protection still receives
  `Rust Check & Test` and `Cargo Audit`; Semgrep and Frontend continue to run.
- Draft PRs use the same lightweight path. `ready_for_review` is explicitly
  subscribed, so moving a PR out of draft launches the full applicable checks.
- A new commit cancels an older run for the same PR. Main-branch and tag runs
  are never cancelled by workflow concurrency.
- Rust dependency build artifacts are restored with `Swatinem/rust-cache`,
  whose key includes `Cargo.lock`, the compiler, runner platform, and job
  settings. Cargo Audit, releases, and the weekly scan retain their existing
  lockfile-keyed caches.

A docs-only or draft PR is estimated at about 4 billed minutes: classification,
Semgrep, Frontend, and offline release signing. That is an approximately
23–25 minute (about 85%) reduction per run. A substantive PR still runs every
required check; warm dependency caches should reduce its dominant Rust job, but
the exact saving depends on cache population and which crates changed.
Cancellation saves the unused remainder of superseded PR runs.

Pushes to `main` and release tags retain full validation. The scheduled
three-node paid regtest is intentionally unchanged.
