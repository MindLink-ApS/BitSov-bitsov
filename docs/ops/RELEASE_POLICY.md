# Release Policy

BitSov public releases must be independently verifiable.

## Required For Public Releases

- protected signed tag
- Linux binary built from the protected tag
- `SHA256SUMS`
- detached signature for `SHA256SUMS` using the release key
- SBOM
- GitHub artifact attestation or equivalent provenance
- release notes naming protocol-affecting migrations and rollback constraints

## Draft Artifact Staging

Tag-triggered CI may stage draft/prerelease GitHub releases and signed mobile
artifacts for review. Draft staging is not public-release approval. Do not
publish GitHub releases or promote TestFlight/Play builds until every public
release requirement above is verified and the operator signs off.

## Private Distribution

MindLink distribution repositories may package BitSov for App Store, Play Store,
PWA, customer installers, or hosted relay operations only after verifying the
public artifact checksum and signature.

Checksum/signature verification is a minimum artifact-integrity precondition,
not distribution approval. App-store promotion, customer installers, hosted
relay operations, or any managed customer distribution also require the
release-trust, install/migration, legal/compliance, and operator approval gates
to pass for the exact flow being shipped.

Private distribution must not become the canonical source of protocol releases.
The open-core release remains canonical.

## Operator signing (one command)

`scripts/release-sign.sh <tag> <commit-on-main>` is the operator's single step per release. It creates and pushes the GPG-signed tag (or verifies an existing one), waits for the tag's CI run, downloads every binary from the draft and checks it against its `.sha256`, writes `SHA256SUMS`, independently rebuilds the host target and requires a matching hash or an explicit reasoned host break-glass (plus explicit waivers for other targets), signs it with the release key (`B299274C200301714DC6F51A7C2D6F8AC842EF6E`, the same key as `RELEASE_KEY.asc`), verifies the signature, and attaches `SHA256SUMS` and `SHA256SUMS.asc` to the draft. The key never leaves the operator's machine, and the script never publishes.

## Independent rebuild gate (H3)

Before signing **artifact checksums**, the operator command now creates a clean,
detached worktree at the exact tagged commit and rebuilds the signing machine's
host target. It compares that binary's SHA-256 with the downloaded CI binary's
validated hash. A mismatch prints a unified `CI/<triple>` versus `local/<triple>`
hash diff and, by default, aborts before checksum signing or upload. A build error,
unsupported host, absent toolchain pin, or unaccepted target also aborts. Later
commits, uncommitted changes, and existing local build outputs are excluded.

**Host break-glass:** after investigating a mismatch, the operator may explicitly
accept the risk with `--accept-unverified-host "<reason>"`. A nonblank reason is
required; missing/empty/whitespace-only reasons, option tokens in place of a reason,
and duplicate host flags are rejected. The rebuild still runs and must produce a
binary: this flag only accepts a completed host hash mismatch. It cannot bypass
build errors, missing recipes, tag/commit checks, draft checks, download checksum
checks, or the separate non-host waivers. A matching rebuild remains `VERIFIED`;
an unused host flag is not reported as an applied waiver.

On an accepted mismatch, the signing output and retained `manifest.txt` prominently
record `WARNING: BREAK-GLASS ACCEPT UNVERIFIED HOST`, target, tag, exact commit,
**both CI and local SHA-256 hashes**, and the operator reason (shell-escaped on one
line to prevent forged log entries). Signing still covers the downloaded **CI**
binaries, not the differing local binary. This is an explicit reliance on CI
integrity, not proof of reproducibility. Keep the reason specific to the incident
and investigation; do not make this flag a routine default.

Every mismatch, including a rejected or dry-run mismatch, retains a unique
`release-sign-evidence/<tag>.<random>/` directory in the source checkout. The script
prints its absolute path as `REBUILD EVIDENCE`. It contains `<host-asset>.rebuilt`,
`host-hash.diff`, the downloaded artifacts' `SHA256SUMS`, and `manifest.txt` with
both hashes and the decision/reason. It survives EXIT cleanup and subsequent
attempts; archive it with the full signing command/output in release evidence.
These files are local evidence, not automatically uploaded or signed. The directory
is gitignored; remove it manually only after archiving. If saving evidence fails,
signing aborts and the original temporary workspace is retained with a warning
and its path, so the rebuilt binary is still available for inspection.

The current verifier rebuilds only the native host target. Every other target
requires a separate `--accept-unverified-target <triple>` on that invocation.
There is no blanket waiver; this target flag cannot waive the host (use the
separate reasoned break-glass above). Each non-host acceptance is
logged as `ACCEPT UNVERIFIED` with target, tag and commit. Retain the full command
and output in the release evidence, with the operator's reason for each waiver.
Those targets remain dependent on CI integrity even though their checksums are
signed; a waiver is not evidence of reproducibility. The five target triples are:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`

`--dry-run` performs the same download, rebuild and comparison gates but never
creates/signs/pushes a tag, accesses secret keys, signs checksums, or uploads.
It requires an existing signed tag and uses public-key verification. Normal mode
may create a signed tag first to trigger CI; that tag signature authorizes source,
not the still-unverified CI artifacts. Only the checksum signature is issued after
the independent rebuild matches or the host mismatch is explicitly accepted. The
script never publishes a release.

## Reproducibility inputs

CI and the signer use `scripts/release-build.sh` and the exact Rust version in
`scripts/release-toolchain` (initially `1.91.1`), not moving `stable`. Install that
version and its host target with rustup before signing. The pin must be present
in the release tag. Older tags lacking this recipe must not be retroactively
signed through a weaker path; prepare a new reviewed release tag.

The shared recipe preserves CI's `cargo build --locked --release -p
konsensus-node --target <triple>` and its default features. `Cargo.lock`, vendored
sources and the compiler pin are release inputs. `SOURCE_DATE_EPOCH` is the tagged
commit's committer timestamp (UTC), `TZ=UTC`, `LC_ALL=C`, and incremental compilation
is disabled. CI no longer restores compiled release artifacts; the signer starts
with a fresh worktree. Dependencies may still be downloaded, but `--locked`
forbids lockfile changes.

Rust's release profile strips symbols with `CARGO_PROFILE_RELEASE_STRIP=symbols`
and disables debug information. There is no separate platform `strip` pass after
building: both sides hash the same final Cargo output. Rust path remapping maps
the checkout, Cargo home and rustup home to `/bitsov`, `/cargo` and `/rustup`.
Unix native C/C++ compilation receives matching `-ffile-prefix-map` flags for the
checkout and Cargo home. Inherited Rust flags and compiler wrappers are removed.
CI copies the resulting `konsensus` (Windows: `konsensus.exe`) without further
binary transformation before hashing.

These settings are necessary, not a guarantee across arbitrary systems. Use a
trusted build environment and dependency cache, matching native compiler,
linker/binutils, OS libraries and SDK versions, target CPU/features and Cargo
configuration. Do not inject local Cargo config, native compiler wrappers or
profile overrides. Native tools must support the remap flags; use checkout and
Cargo-home paths without whitespace for native compiler flags. Windows MSVC path
and timestamp behavior requires matching tools/SDKs and is not normalized by the
Unix flags. Hosted `*-latest` runner images are not pinned OS/SDK environments;
changes can cause a legitimate mismatch, especially on macOS/Windows. Record
`rustc -vV`, native tool versions and CI runner image details with the release.
Fail closed by default and investigate a host mismatch. If the operator must
proceed despite an unresolved mismatch (for example, investigated macOS SDK drift
between CI and NOVA), use the reasoned host break-glass and retain its evidence.
Do not claim cross-platform reproducibility solely from a successful native-host
check.

## Release-script tests

Run `bash scripts/test-release-sign.sh`. It isolates `HOME`, `GNUPGHOME` and Git
configuration, generates a disposable signing key, uses a local Git origin and
simulates GitHub/large Rust builds. A private test copy substitutes only the
throwaway fingerprint; the production pin stays fixed. Tests must never import,
list or use real signing keys. Lint with `shellcheck scripts/release-sign.sh
scripts/release-build.sh scripts/test-release-sign.sh`.

Use the [RC checklist template](../releases/RC_CHECKLIST_TEMPLATE.md) for each new
release, including rebuild evidence and per-target waiver decisions.
