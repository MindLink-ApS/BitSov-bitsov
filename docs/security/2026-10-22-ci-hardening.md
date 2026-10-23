# CI security hardening — 2026-10-22

Base commit: `84ca3fd`. Scope: the five `.github/workflows/*.yml` files and this record.

## Action pins

All 37 action uses have full 40-character commit pins (33 newly pinned; four existing sccache pins reverified). Every commit was resolved using `gh api repos/<owner>/<repo>/git/ref/tags/<tag>`; annotated tags were dereferenced with `gh api repos/<owner>/<repo>/git/tags/<sha>`. All existing major-version aliases match the selected release commits.

| Action | Upstream tag | Commit |
| --- | --- | --- |
| `dorny/paths-filter` | [v4.0.3](https://github.com/dorny/paths-filter/tree/v4.0.3) | `ceb8a2b8f2d89434be7ff52d3de7ec3738c5cc9d` |
| `dorny/paths-filter` | [v3.0.4](https://github.com/dorny/paths-filter/tree/v3.0.4) | `0e4a8c6effa4802afeda77dc8d303f8176d7dfad` |
| `actions/checkout` | [v4.4.0](https://github.com/actions/checkout/tree/v4.4.0) | `11d5960a326750d5838078e36cf38b85af677262` |
| `Swatinem/rust-cache` | [v2.9.3](https://github.com/Swatinem/rust-cache/tree/v2.9.3) | `d1527c8f67ef9af357290475d4af4b0fab8f12e0` |
| `mozilla-actions/sccache-action` | [v0.0.11](https://github.com/mozilla-actions/sccache-action/tree/v0.0.11) | `fc920bf0ec8de6ee65d409111f7ec508035751ba` |
| `actions/cache` | [v4.3.0](https://github.com/actions/cache/tree/v4.3.0) | `0057852bfaa89a56745cba8c7296529d2fc39830` |
| `anchore/sbom-action` | [v0.24.0](https://github.com/anchore/sbom-action/tree/v0.24.0) | `e22c389904149dbc22b58101806040fa8d37a610` |
| `actions/attest-build-provenance` | [v2.4.0](https://github.com/actions/attest-build-provenance/tree/v2.4.0) | `e8998f949152b193b063cb0ec769d69d929409be` |
| `softprops/action-gh-release` | [v2.6.2](https://github.com/softprops/action-gh-release/tree/v2.6.2) | `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` |
| `actions/upload-artifact` | [v4.6.2](https://github.com/actions/upload-artifact/tree/v4.6.2) | `ea165f8d65b6e75b540449e92b4886f43607fa02` |
| `dtolnay/rust-toolchain` | [v1](https://github.com/dtolnay/rust-toolchain/tree/v1) | `683b588c487a69d01f6c6ddf40f036ff682cc2c8` |

`Swatinem/rust-cache` and `mozilla-actions/sccache-action` use annotated tags; the pins above are their dereferenced commits. `anchore/sbom-action@v0` currently points to v0.24.0, so that release is retained rather than upgrading to v0.24.3.

Exception to the requested `# vX.Y.Z` comment: `dtolnay/rust-toolchain` publishes only `v1`. Its real tag is recorded instead of inventing a semver release. The `v1` commit matches upstream `master`. Former `@stable` steps now pass `toolchain: stable`; the release job keeps its existing dynamic toolchain input.

## Token permissions

Every workflow defaults to `contents: read`. Additional permissions exist only in these jobs, with inline reasons:

| Workflow / job | Scope | Reason |
| --- | --- | --- |
| `ci.yml` / `changes` | `pull-requests: read` | Read the changed-file list with paths-filter. |
| `ci.yml` / `release-cli` | `contents: write` | Upload binaries, checksums and SBOMs to the draft release. |
| `ci.yml` / `release-cli` | `id-token: write` | Obtain an OIDC token to sign build provenance. |
| `ci.yml` / `release-cli` | `attestations: write` | Publish build-provenance attestations. |
| `security-scan.yml` / `security-scan` | `issues: write` | Create the existing security-scanning repository label. |

The daily scan no longer has workflow-wide `contents: write` or `pull-requests: write`. Its scripts do not commit reports or create pull requests. Label creation accepts `issues: write`, as documented in the [GitHub REST API](https://docs.github.com/en/rest/issues/labels#create-a-label).

## Dependency scan and unresolved advisories

Dependency bumps: **none**. `Cargo.lock`, Cargo manifests, advisory exceptions and all vendor files are unchanged. Cargo Audit was already installed; no installation was needed.

- Configured Cargo Audit: exit 0, zero unignored vulnerabilities; existing `paste` maintenance warning. Advisory database commit `640bf5a9f06e66d8721e8772766531fe77c8630d`, updated 2026-10-22, 1,349 advisories.
- Configured OSV Scanner v1.8.5: exit 0, 545 packages scanned, zero unignored findings. The locally installed v2.4.0 rejects the workflow’s v1 flag, so the workflow version was downloaded to temporary storage and verified against its published SHA-256 checksum.
- `cargo deny check advisories`: exit 0 (`advisories ok`).
- Configured gitleaks history scan with redacted output: exit 0, zero findings.

A second Cargo Audit run outside the repository, against the same lockfile and database but without repository ignores, found the following existing debt. These are not treated as fixed by the configured scans.

| Advisory | Locked package | Patched version / obstacle |
| --- | --- | --- |
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) | `rsa 0.9.10` | No patched release is listed. Pulled into the lockfile by SQLx MySQL; MySQL is not an enabled storage backend. |
| [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html) | `rustls 0.21.12` | Fix requires >=0.23.46. SQLx 0.8.0 and test-only minreq require ^0.21, so a precise lockfile update cannot select the patched line. |
| [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) | `rustls 0.21.12` | Fix requires >=0.23.46. SQLx 0.8.0 and test-only minreq require ^0.21, so a precise lockfile update cannot select the patched line. |
| [RUSTSEC-2026-0104](https://rustsec.org/advisories/RUSTSEC-2026-0104.html) | `rustls-webpki 0.101.7` | Fixes are on 0.103.x (0.103.16 covers all four). Legacy rustls 0.21 and minreq require ^0.101; their patched 0.103.16 sibling is already locked. |
| [RUSTSEC-2026-0098](https://rustsec.org/advisories/RUSTSEC-2026-0098.html) | `rustls-webpki 0.101.7` | Fixes are on 0.103.x (0.103.16 covers all four). Legacy rustls 0.21 and minreq require ^0.101; their patched 0.103.16 sibling is already locked. |
| [RUSTSEC-2026-0099](https://rustsec.org/advisories/RUSTSEC-2026-0099.html) | `rustls-webpki 0.101.7` | Fixes are on 0.103.x (0.103.16 covers all four). Legacy rustls 0.21 and minreq require ^0.101; their patched 0.103.16 sibling is already locked. |
| [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382.html) | `rustls-webpki 0.101.7` | Fixes are on 0.103.x (0.103.16 covers all four). Legacy rustls 0.21 and minreq require ^0.101; their patched 0.103.16 sibling is already locked. |
| [RUSTSEC-2024-0363](https://rustsec.org/advisories/RUSTSEC-2024-0363.html) | `sqlx 0.8.0` | Fix requires >=0.8.1. The workspace pins =0.8.0 because newer SQLx SQLite needs libsqlite3-sys ^0.30, conflicting with the untouched LDK fork’s rusqlite 0.31 / libsqlite3-sys ^0.28. |
| [RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381.html) | `webpki-roots 0.25.4` | Fixed >=1.0.10; 0.26.11 is also unaffected. SQLx 0.8.0 and minreq require ^0.25. The separate runtime 1.0.10 copy is already fixed. |
| [RUSTSEC-2026-0367](https://rustsec.org/advisories/RUSTSEC-2026-0367.html) | `zip 0.6.6` | Fix requires >=9.0.0; test-harness corepc-node 0.10.1 and electrsd 0.36.1 require ^0.6. Existing policy documents fixture hash verification and the lack of a compatible harness release. |
| [RUSTSEC-2026-0368](https://rustsec.org/advisories/RUSTSEC-2026-0368.html) | `zip 0.6.6` | Fix requires >=9.0.0; test-harness corepc-node 0.10.1 and electrsd 0.36.1 require ^0.6. Existing policy documents fixture hash verification and the lack of a compatible harness release. |
| [RUSTSEC-2026-0369](https://rustsec.org/advisories/RUSTSEC-2026-0369.html) | `zip 0.6.6` | Fix requires >=9.0.0; test-harness corepc-node 0.10.1 and electrsd 0.36.1 require ^0.6. Existing policy documents fixture hash verification and the lack of a compatible harness release. |

Maintenance advisories also remain: `paste 1.0.15` (RUSTSEC-2024-0436) and `rustls-pemfile 1.0.4` (RUSTSEC-2025-0134), both from the pinned SQLx stack. Neither has an advisory-listed patched release; removing them requires migrating their parent dependencies.

These legacy TLS advisories retain residual risk for Postgres-over-TLS deployments; the SQLite default does not eliminate that risk. Existing per-advisory analysis and recheck conditions remain in `.cargo/audit.toml`, `deny.toml` and `osv-scanner.toml`. No new suppressions were added.

## Verification

Workflow YAML parses with a duplicate-key-rejecting loader. A normalized comparison against the base confirms all triggers, job conditions, scripts and inputs are unchanged apart from the authorized permission changes and explicit preservation of the Rust toolchain default. `actionlint` is not installed.

- `cargo clippy --workspace --all-targets -- -D warnings`: passed (exit 0).
- `cargo +1.89.0 check --workspace --locked`: passed (exit 0; toolchain installed).

Both checks emit the existing SQLx Postgres 0.8.0 future-compatibility notice. Local Rust commands use two build jobs, disabled incremental compilation, and disabled debug symbols to limit build resource use; debug assertions remain enabled.

The initial default-concurrency test run exposed two existing timing-sensitive sponsor tests: `expired_candidate_resubmission_persists_terminal_expiry_even_on_refusal` and `regression_signed_request_expiry_is_enforced_at_approval`. Each creates a request expiring in two wall-clock seconds; initial candidate submission was rejected as expired (HTTP 400 rather than 200). The complete sponsor test binary passed 25/25 with `RUST_TEST_THREADS=1`. No Rust source, test assertions or dependency versions were changed.

The initial run finished with 4,922 passed, 14 failed and 8 ignored (exit 101). The other 12 failures were in `session_handler::budgeted_reconnect_two_node`, with connection/admission and no-live-grant errors under default test concurrency. Running that complete group from the same compiled workspace test binary with `--test-threads=1` passed all 21 tests. These results show concurrency-sensitive failures on this host; they do not establish that default-concurrency CI is reliable.

Final full-suite verification: `RUST_TEST_THREADS=2 cargo test --workspace --no-fail-fast` passed (exit 0): **4,936 passed, 0 failed, 8 ignored**, across 194 test/doctest groups. Both previously failing groups passed in this complete run. Test concurrency was limited only in the local verification environment; workflow commands and application behavior remain unchanged.

Independent review of the workflow diff found no Critical, Important or Minor issues. YAML structural comparison and `git diff --check` passed. GitHub-hosted release execution was not performed locally.
