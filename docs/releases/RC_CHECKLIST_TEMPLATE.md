# BitSov <version> — release candidate checklist

Pre-release; not for production use. Copy this template for each new RC.

## Prepare

- [ ] Record the reviewed commit on `origin/main`, scope, migration and rollback
      constraints. Update versions, lockfile, changelog and upgrade notes.
- [ ] Review the tag's `scripts/release-toolchain`, `scripts/release-build.sh`,
      lockfile and CI release matrix together. Install the pinned Rust toolchain.
- [ ] Pass release CI and the isolated release-signing regression tests.
      Tests use only generated keys in a throwaway GnuPG home.
- [ ] Record signing host triple, `rustc -vV`, native compiler/linker/SDK versions,
      CI runner image and the tag commit's timestamp (`SOURCE_DATE_EPOCH`).

## Rebuild and sign

- [ ] Review [reproducibility assumptions](../ops/RELEASE_POLICY.md#reproducibility-inputs).
      Use a trusted build environment matching CI and the shared recipe:
      `--locked`, stripped symbols, disabled debug/incremental output, remapped paths.
- [ ] Record a separate decision and reason for each target the host verifier
      cannot rebuild. Each accepted target needs its own
      `--accept-unverified-target <triple>`; no host waiver is allowed.
- [ ] Run `scripts/release-sign.sh <tag> <reviewed-commit>` with those explicit
      per-target flags. Keep the command and full output in release evidence.
      For an existing signed tag, first add `--dry-run` to exercise every gate
      without signing, secret-key access or upload.
- [ ] Confirm `VERIFIED` identifies the exact tag commit, native target and matching
      local/CI SHA-256. Retain every `ACCEPT UNVERIFIED` entry and its rationale.
      A build failure or hash diff blocks signing: investigate, never bypass it.
- [ ] Confirm the checksum signature and upload occurred only after verification.
      The initial tag signature triggers CI; it does not approve CI binaries.

## Independently verify and publish

- [ ] In a fresh download directory, verify the tag commit/signature, checksum
      signature and all five downloaded binaries against `SHA256SUMS`.
- [ ] Check SBOM, provenance and release notes. Record unverified targets as such;
      their signed checksums do not prove they were independently rebuilt.
- [ ] Obtain operator publication sign-off. The signing script never publishes.
- [ ] Only after publication and verification, update distribution pins and follow
      the release's migration/rollback checklist.
