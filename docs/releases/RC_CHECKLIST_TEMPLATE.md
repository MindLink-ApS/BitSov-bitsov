# BitSov <version> — release candidate checklist

Pre-release; not for production use. Copy this template for each new RC.

## Prepare

- [ ] Record the reviewed commit on `origin/main`, scope, migration and rollback
      constraints. Update versions, lockfile, changelog and upgrade notes.
- [ ] Review the tag's `scripts/release-toolchain`, `scripts/release-build.sh`,
      `scripts/release-macos-toolchain.sh`, lockfile and CI release matrix together.
      Install the pinned Rust toolchain.
- [ ] On NOVA, install/select **Xcode 27.1 build 27A9275**, macOS SDK **27.0**,
      Apple clang **21.0.0 (clang-2100.3.34.2)** using the
      [installation steps](../ops/RELEASE_POLICY.md#pinned-macos-release-toolchain-nova).
      From the reviewed release commit, run
      `bash scripts/release-build.sh --check-toolchain aarch64-apple-darwin`.
      A mismatch must stop before rebuilding or signing; host break-glass cannot
      waive it. Confirm both Darwin CI jobs use `xcode-27` and explicitly select
      `/Applications/Xcode_27.1.app`.
- [ ] Pass release CI and the isolated release-signing regression tests.
      Tests use only generated keys in a throwaway GnuPG home.
- [ ] Record signing host triple, `rustc -vV`, native compiler/linker/SDK versions,
      CI runner image and the tag commit's timestamp (`SOURCE_DATE_EPOCH`).
- [ ] Archive both Darwin `<asset>.toolchain.txt` release assets and the local
      preflight log: SDK version, Xcode build and full `clang --version` output.
      Verify both evidence assets are covered by `SHA256SUMS` (17 source assets).

## Rebuild and sign

- [ ] Review [reproducibility assumptions](../ops/RELEASE_POLICY.md#reproducibility-inputs).
      Use a trusted build environment matching CI and the shared recipe:
      `--locked`, stripped symbols, disabled debug/incremental output, remapped paths.
- [ ] Record a separate decision and reason for each target the host verifier
      cannot rebuild. Each accepted target needs its own
      `--accept-unverified-target <triple>`; this flag cannot waive the host.
- [ ] Run `scripts/release-sign.sh <tag> <reviewed-commit>` with those explicit
      per-target flags. Keep the command and full output in release evidence.
      For an existing signed tag, first add `--dry-run` to exercise every gate
      without signing, secret-key access or upload.
- [ ] Confirm `VERIFIED` identifies the exact tag commit, native target and matching
      local/CI SHA-256, or explicitly record a host break-glass decision below.
      Retain every non-host `ACCEPT UNVERIFIED` entry and its rationale.
- [ ] On any mismatch, inspect and archive the printed `REBUILD EVIDENCE` directory:
      rebuilt binary, hash diff, `SHA256SUMS`, `manifest.txt`, both CI Darwin
      toolchain records and (on NOVA) `host-toolchain.txt`. It survives exit
      even on rejection or dry-run; later attempts create separate directories.
- [ ] If proceeding despite an investigated host mismatch, supply
      `--accept-unverified-host "<incident-specific reason>"` explicitly. Confirm
      `WARNING: BREAK-GLASS ACCEPT UNVERIFIED HOST` in the signing log and manifest
      records the reason, exact tag/commit/target and **both** hashes. Archive them
      with the command/output; they are not automatically uploaded or signed.
      Record the host as unverified and dependent on CI integrity. This does not
      skip the rebuild or waive build failures or any other validation gate.
- [ ] Confirm the checksum signature and upload occurred only after a matching
      rebuild or the explicit, recorded host break-glass decision. Signed checksums
      describe the downloaded CI binaries, including when the local binary differs.
      The initial tag signature triggers CI; it does not approve CI binaries.

## Independently verify and publish

- [ ] In a fresh download directory, verify the tag commit/signature, checksum
      signature and all five downloaded binaries against `SHA256SUMS`.
- [ ] Check SBOM, provenance and release notes. Record unverified targets as such;
      their signed checksums do not prove they were independently rebuilt.
- [ ] Obtain operator publication sign-off. The signing script never publishes.
- [ ] Only after publication and verification, update distribution pins and follow
      the release's migration/rollback checklist.
