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

`scripts/release-sign.sh <tag> <reviewed-commit>` is the operator's single step per release. It creates and pushes the GPG-signed tag (or verifies an existing one), waits for the tag's CI run, downloads every binary from the draft and checks it against its `.sha256`, writes `SHA256SUMS`, independently rebuilds the host target and requires a matching hash or an explicit reasoned host break-glass (plus explicit waivers for other targets), signs it with the release key (`B299274C200301714DC6F51A7C2D6F8AC842EF6E`, the same key as `RELEASE_KEY.asc`), verifies the signature, and attaches `SHA256SUMS` and `SHA256SUMS.asc` to the draft. The key never leaves the operator's machine, and the script never publishes.

### Approved release refs

Accepted tags are `vX.Y.Z`, `vX.Y.Z-rcN` and `vX.Y.Z-rcN.M`, with numeric
components. The source gate runs before any signing or CI access:

- A dotted RC point-release tag (`vX.Y.Z-rcN.M`) requires the exact branch
  `refs/heads/release/<tag>` on `origin`. The signer fetches that branch fresh
  with tags and requires the reviewed commit to equal `FETCH_HEAD^{commit}`,
  not merely be an ancestor of the branch head. For `v0.3.0-rc19.1`, the approved
  branch is `release/v0.3.0-rc19.1`; its isolated head need not be on main.
  A missing/unfetchable branch or a different head refuses signing, even if
  the commit is on main. Cached tracking refs and same-named tags do not qualify.
- Every other accepted tag retains the existing ancestry gate: fetch `main`
  and tags from `origin`, then require the reviewed commit to be an ancestor
  of `origin/main`. A release branch cannot authorize a plain RC or stable tag.

Existing signed tags must still resolve to the exact reviewed commit, and the
CI run must build that same commit. No flag bypasses the approved-ref policy;
`--dry-run` and host/non-host waivers retain these checks.

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
toolchain preflight failures, build errors, missing recipes, tag/commit checks,
draft checks, download checksum checks, or the separate non-host waivers. A matching rebuild remains `VERIFIED`;
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
both hashes and the decision/reason. It also contains both CI Darwin
`*.toolchain.txt` files and, on a Darwin signing host, `host-toolchain.txt` from
the local rebuild. It survives EXIT cleanup and subsequent
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

On Darwin, ld64 derives the Mach-O `LC_UUID` from the link output, including the
debug map whose `N_OSO` entries carry absolute object paths (the checkout and the
rustup home); path remapping does not reach them. The recipe therefore links
Darwin targets with `-Wl,-S`, which omits the debug map. Without it, two builds
of the same commit differ only in `LC_UUID` and the linker code-signature hash
that covers it, so the H3 host rebuild (which runs in a fresh temporary
worktree) could never match CI (found on rc19.1). `scripts/release-repro-check.sh
<triple> [commit]` builds a target twice from two different worktree paths and
compares the hashes; run it on the signing host when changing the recipe.

These settings are necessary, not a guarantee across arbitrary systems. Use a
trusted build environment and dependency cache, matching native compiler,
linker/binutils, OS libraries and SDK versions, target CPU/features and Cargo
configuration. Do not inject local Cargo config, native compiler wrappers or
profile overrides. Native tools must support the remap flags; use checkout and
Cargo-home paths without whitespace for native compiler flags. Windows MSVC path
and timestamp behavior requires matching tools/SDKs and is not normalized by the
Unix flags. Hosted `*-latest` runner images are not pinned OS/SDK environments;
changes can cause a legitimate mismatch, especially on Windows. Record
`rustc -vV`, native tool versions and CI runner image details with the release.
Fail closed by default and investigate a host mismatch. If the operator must
proceed despite an unresolved binary mismatch after all toolchain checks pass,
use the reasoned host break-glass and retain its evidence.
Do not claim cross-platform reproducibility solely from a successful native-host
check.

## Pinned macOS release toolchain (NOVA)

Both Release CLI Darwin targets use GitHub's **`xcode-27` Apple Silicon runner**
and explicitly select `/Applications/Xcode_27.1.app` with `sudo xcode-select -s`.
The x86_64 Darwin target is cross-compiled on that same runner. Linux and Windows
runner/build settings are unchanged. Release CI has no Rust artifact cache or
sccache; host verification uses a fresh detached worktree.

The exact pins live in `scripts/release-macos-toolchain.sh`:

| Input | Required value |
| --- | --- |
| Xcode | 27.1 |
| Xcode build | 27A9275 |
| macOS SDK | 27.0 |
| Apple clang version line | `Apple clang version 21.0.0 (clang-2100.3.34.2)` |
| Rust | `scripts/release-toolchain` (1.91.1) |

Inventory checked 2026-10-21: the macOS 14, 15 and 26 images listed in the
[runner label inventory](https://github.com/actions/runner-images#available-images)
do not include full Xcode 27.1 (the Command Line Tools entry is not full Xcode).
The [dedicated Xcode 27 image](https://github.com/actions/runner-images/blob/main/images/macos/xcode-27-arm64-Readme.md#xcode)
(image 20261012.0260.1) lists **Xcode 27.1 build 27A9275** at
`/Applications/Xcode_27.1_Release_Candidate.app`, with symlinks
`/Applications/Xcode_27.1.app` and `/Applications/Xcode_27.1.0.app`, and macOS SDK
27.0 for Xcode 27.1. CI selects the documented `Xcode_27.1.app` symlink; the
`Release_Candidate` directory name does not change the exact version/build check.
The image README lists Clang/LLVM 21.0.0 but not its full build string. The full
Apple clang pin above comes from NOVA's reported toolchain; CI must pass that
same exact check before building. This is a versioned runner family, **not an
immutable VM snapshot**; GitHub still updates it. Exact compiler/SDK checks fail
closed if the selected toolchain changes or disappears.

NOVA already reports **Xcode 27.1 build 27A9275**, SDK **27.0**, and the Apple
clang line pinned above; no reinstall is needed when those checks pass. Do not
downgrade it to Xcode 27.0 or substitute a different build. If installation is
needed, download the matching Xcode `.xip` from
[Apple Developer Downloads](https://developer.apple.com/download/all/?q=Xcode),
expand it and place the app at `/Applications/Xcode_27.1.app`. Keep other Xcode
versions alongside it. Complete its first-launch setup and license acceptance:

```sh
unset DEVELOPER_DIR SDKROOT TOOLCHAINS
sudo xcode-select -s /Applications/Xcode_27.1.app
sudo xcodebuild -runFirstLaunch
sudo xcodebuild -license accept
xcodebuild -version
xcrun --sdk macosx --show-sdk-version
xcrun --sdk macosx clang --version
bash scripts/release-build.sh --check-toolchain aarch64-apple-darwin
```

Run the preflight from the reviewed release commit. It makes no build or signing
changes. It checks the effective Xcode (including `DEVELOPER_DIR`), exact build,
SDK version and selected clang version before any Cargo compilation. The build
uses the inspected compiler/SDK paths explicitly, rejecting a conflicting
`SDKROOT` or target-specific native compiler/flag overrides. Use a clean native
build environment as described above. The signer runs this preflight from the
release commit **before tag signing, waiting for CI or downloading artifacts**,
and the build repeats it before rebuilding. `--accept-unverified-host` cannot
bypass a toolchain failure. Tags lacking the macOS pin require a new release.

Each Darwin build writes `target/<triple>/release-toolchain.txt` containing the
SDK version/path, Xcode version/build, complete `clang --version` output, target,
and CI image identity/version. CI attaches it as `<asset>.toolchain.txt` to the
draft. The signer requires both Darwin evidence files and includes their hashes
in signed `SHA256SUMS` (17 source assets total). Archive these alongside the
signing log, which includes the local preflight output. On a host hash mismatch,
the retained evidence also includes the CI files and local toolchain record.
The signer requires nonempty CI toolchain records and hashes them; it does not
parse or compare their contents against the pins. Local preflight and CI's own
build preflight check their respective toolchains. These version records aid
diagnosis; only the H3 binary hash comparison proves
a matching host rebuild.

## Release-script tests

Run `bash scripts/test-release-sign.sh`. It isolates `HOME`, `GNUPGHOME` and Git
configuration, generates a disposable signing key, uses a local Git origin and
simulates GitHub/large Rust builds. A private test copy substitutes only the
throwaway fingerprint; the production pin stays fixed. Tests must never import,
list or use real signing keys. Lint with `shellcheck scripts/release-sign.sh
scripts/release-build.sh scripts/release-macos-toolchain.sh scripts/test-release-sign.sh`.

Use the [RC checklist template](../releases/RC_CHECKLIST_TEMPLATE.md) for each new
release, including rebuild evidence and per-target waiver decisions.
