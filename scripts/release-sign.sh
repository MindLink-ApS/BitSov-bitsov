#!/usr/bin/env bash
# release-sign.sh: the operator's one command per release (RELEASE_POLICY.md).
#
#   scripts/release-sign.sh v0.3.0-rc10 <commit-on-main>
#
# 1. Creates and pushes a GPG-signed tag on the commit (skipped if the tag already
#    exists and is signed by the release key).
# 2. Waits for the tag's CI run, which stages the DRAFT release with the binaries
#    and per-file .sha256 and .sbom.spdx.json files.
# 3. Downloads all fifteen assets, checks each binary against its .sha256,
#    and writes SHA256SUMS covering the binaries, checksums, and SBOMs.
# 4. Rebuilds the host target from the tag and compares its hash with CI.
#    A mismatch retains evidence and requires a reasoned break-glass to proceed.
#    Every other target requires an explicit, logged waiver.
# 5. Signs SHA256SUMS with the release key, verifies the signature, and attaches
#    SHA256SUMS + SHA256SUMS.asc to the draft.
# It never publishes. The release key stays on this machine; nothing goes to CI.
set -euo pipefail

REPO=MindLink-ApS/BitSov-bitsov
KEY_FPR=B299274C200301714DC6F51A7C2D6F8AC842EF6E
DRY_RUN=false
HOST_REASON=''
ACCEPTED=()
TARGETS=(aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu x86_64-pc-windows-msvc)
ASSETS=(bitsov-darwin-aarch64 bitsov-darwin-x86_64 bitsov-linux-aarch64 bitsov-linux-x86_64 bitsov-windows-x86_64)

die() { echo "release-sign: $*" >&2; exit 1; }
# A good signature from the pinned primary key. Its fingerprint must be in
# VALIDSIG field 10: a GOODSIG user id can contain "VALIDSIG <release key>"
# without that key having signed anything. Expired/revoked/bad markers still fail.
signed_by_key() {
  local status line rest
  local -a fields
  status=$(cat)
  if grep -qE '^\[GNUPG:\] (EXPKEYSIG|REVKEYSIG|EXPSIG|BADSIG|ERRSIG) ' <<<"$status"; then
    return 1
  fi
  while IFS= read -r line; do
    case "$line" in
      '[GNUPG:] VALIDSIG '*)
        rest=${line#\[GNUPG:\] VALIDSIG }
        # fingerprint, creation date, timestamp, expiry, version, reserved,
        # public-key algorithm, hash algorithm, signature class, primary fpr.
        # Never fall back to the signing fingerprint or the last token.
        IFS=$' \t' read -r -a fields <<<"$rest"
        if [ "${#fields[@]}" -ge 10 ] && [ "${fields[9]}" = "$KEY_FPR" ]; then
          return 0
        fi
        ;;
    esac
  done <<<"$status"
  return 1
}
verify_tag() {
  # Git --raw emits its separate GPG status buffer on stderr; human GPG
  # diagnostics are excluded. Keep stdout out of the status parser as well.
  git verify-tag --raw "$TAG" >/dev/null 2>"$WORK/tag.status" &&
    signed_by_key < "$WORK/tag.status"
}
require_release_assets() {
  local expected present
  # CI attaches each binary, its checksum, and its SBOM. Anything else
  # (a DMG, a second binary, a renamed installer) is not covered by SHA256SUMS.
  expected=$(for a in "${ASSETS[@]}"; do printf '%s\n' "$a" "$a.sha256" "$a.sbom.spdx.json"; done | LC_ALL=C sort)
  # A full or partial previous upload is safe to regenerate. Only these exact
  # generated names are exempt; all fifteen source assets remain mandatory.
  present=$(gh release view "$TAG" --repo "$REPO" --json assets -q '.assets[].name' |
    awk '$0 != "SHA256SUMS" && $0 != "SHA256SUMS.asc"' | LC_ALL=C sort)
  [ "$present" = "$expected" ] || die "release $TAG assets are not exactly the five binaries, their .sha256 files, and their SBOMs"
}
POSITIONAL=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --accept-unverified-host)
      [ $# -ge 2 ] && [[ $2 != --* && $2 =~ [^[:space:]] ]] || die '--accept-unverified-host requires a nonblank reason'
      [ -z "$HOST_REASON" ] || die '--accept-unverified-host may only be supplied once'
      HOST_REASON=$2; shift 2 ;;
    --accept-unverified-target)
      [ $# -ge 2 ] || die '--accept-unverified-target requires a triple'
      found=false
      for target in "${TARGETS[@]}"; do [ "$2" != "$target" ] || found=true; done
      "$found" || die "unknown target $2"
      ACCEPTED+=("$2"); shift 2 ;;
    --*) die "unknown option $1" ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
[ "${#POSITIONAL[@]}" -eq 2 ] || die "usage: $0 [--dry-run] [--accept-unverified-host <reason>] [--accept-unverified-target <triple>]... <tag> <commit-on-main>"
set -- "${POSITIONAL[@]}"
TAG=$1 COMMIT=$2
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]] || die "tag must look like v0.3.0 or v0.3.0-rc9"
for t in git gh gpg shasum rustup diff; do command -v "$t" >/dev/null || die "$t not found"; done

SOURCE_REPO=$(git rev-parse --show-toplevel)
cd "$SOURCE_REPO"
git fetch -q origin main --tags
FULL=$(git rev-parse --verify "$COMMIT^{commit}") || die "unknown commit $COMMIT"
git merge-base --is-ancestor "$FULL" origin/main || die "$FULL is not on origin/main"

WORK=$(mktemp -d)
KEEP_WORK=false
cleanup() {
  if "$KEEP_WORK"; then
    echo "WARNING: evidence preservation incomplete; retaining rebuild workspace: $WORK" >&2
    return
  fi
  git -C "$SOURCE_REPO" worktree remove --force "$WORK/source" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
# A detached worktree excludes the operator's later commits and dirty files.
git -c core.hooksPath=/dev/null worktree add --detach "$WORK/source" "$FULL" >/dev/null
[ -f "$WORK/source/scripts/release-toolchain" ] || die 'tag lacks scripts/release-toolchain; prepare a new release with the reproducible recipe'
[ -f "$WORK/source/scripts/release-build.sh" ] || die 'tag lacks scripts/release-build.sh; prepare a new release with the reproducible recipe'
TOOLCHAIN=$(cat "$WORK/source/scripts/release-toolchain")
[[ $TOOLCHAIN =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die 'release toolchain must be an exact version'
HOST=$(rustup run "$TOOLCHAIN" rustc -vV | sed -n 's/^host: //p')
HOST_ASSET=''
for i in "${!TARGETS[@]}"; do
  [ "${TARGETS[$i]}" != "$HOST" ] || HOST_ASSET=${ASSETS[$i]}
done
[ -n "$HOST_ASSET" ] || die "unsupported signing host $HOST"
# Bash 3.2 treats an empty array as unset under nounset.
for target in ${ACCEPTED[@]+"${ACCEPTED[@]}"}; do
  [ "$target" != "$HOST" ] || die "host target cannot be waived: $HOST"
done
for target in "${TARGETS[@]}"; do
  [ "$target" != "$HOST" ] || continue
  accepted=false
  for waiver in ${ACCEPTED[@]+"${ACCEPTED[@]}"}; do [ "$waiver" != "$target" ] || accepted=true; done
  "$accepted" || die "unverified target $target; requires --accept-unverified-target $target"
done

# 1. Signed tag (this triggers CI; artifact signing is gated below).
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  [ "$(git rev-parse "$TAG^{commit}")" = "$FULL" ] || die "tag $TAG exists on a different commit"
  verify_tag || die "existing tag $TAG is not validly signed by $KEY_FPR"
  echo "tag $TAG already exists and is signed; continuing"
else
  "$DRY_RUN" && die 'dry-run requires an existing tag; no tag will be signed or pushed'
  gpg --list-secret-keys "$KEY_FPR" >/dev/null 2>&1 || die "release key $KEY_FPR is not on this machine"
  git tag -s -u "$KEY_FPR" "$TAG" "$FULL" -m "BitSov $TAG"
  verify_tag || die "fresh tag failed verification"
  git push origin "refs/tags/$TAG"
fi

# 2. Wait for the tag's CI run
echo "waiting for CI on ${TAG}..."
RUN=""
for _ in $(seq 1 60); do
  RUN=$(gh run list --repo "$REPO" --workflow ci.yml --branch "$TAG" --event push --limit 1 --json databaseId -q '.[0].databaseId' || true)
  [ -n "$RUN" ] && break
  sleep 10
done
[ -n "$RUN" ] || die "no CI run found for $TAG"
RUN_SHA=$(gh run view "$RUN" --repo "$REPO" --json headSha -q .headSha)
[ "$RUN_SHA" = "$FULL" ] || die "CI run $RUN built $RUN_SHA, not the tagged commit $FULL"
gh run watch "$RUN" --repo "$REPO" --exit-status >/dev/null || die "CI run $RUN failed; nothing signed"

# 3. Download and verify
mkdir "$WORK/artifacts"
cd "$WORK/artifacts"
gh release view "$TAG" --repo "$REPO" --json isDraft -q .isDraft | grep -qx true || die "release $TAG is not a draft; refusing to change it"
require_release_assets
for a in "${ASSETS[@]}"; do
  gh release download "$TAG" --repo "$REPO" --pattern "$a" --pattern "$a.sha256" --pattern "$a.sbom.spdx.json" --clobber
  expected=$(awk '{print $1; exit}' "$a.sha256")
  [ "$(awk '{print $2; exit}' "$a.sha256" | sed 's/^\*//')" = "$a" ] || die "$a.sha256 names a different file"
  actual=$(shasum -a 256 "$a" | awk '{print $1}')
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "$a.sha256 is malformed"
  [ "$expected" = "$actual" ] || die "$a: expected $expected, got $actual"
  printf '%s  %s\n' "$actual" "$a" >> SHA256SUMS
  shasum -a 256 "$a.sha256" "$a.sbom.spdx.json" >> SHA256SUMS
done

# 4. Rebuild independently: never execute or trust a downloaded CI binary.
echo "rebuilding $TAG ($FULL) for host $HOST"
(cd "$WORK/source" && bash "$WORK/source/scripts/release-build.sh" "$HOST") || die "local rebuild failed for $HOST; nothing signed"
BINARY="$WORK/source/target/$HOST/release/konsensus"
[ "$HOST" != x86_64-pc-windows-msvc ] || BINARY="$BINARY.exe"
[ -f "$BINARY" ] || die "local rebuild produced no binary for $HOST"
LOCAL_HASH=$(shasum -a 256 "$BINARY" | awk '{print $1}')
CI_HASH=$(awk -v asset="$HOST_ASSET" '$2 == asset {print $1}' SHA256SUMS)
if [ "$LOCAL_HASH" != "$CI_HASH" ]; then
  # Keep the original workspace if saving evidence fails (e.g. disk full).
  # The named evidence directory survives EXIT cleanup and repeated attempts.
  KEEP_WORK=true
  printf '%s  %s\n' "$CI_HASH" "$HOST_ASSET" > "$WORK/ci-hash"
  printf '%s  %s\n' "$LOCAL_HASH" "$HOST_ASSET" > "$WORK/local-hash"
  mkdir -p "$SOURCE_REPO/release-sign-evidence"
  EVIDENCE=$(mktemp -d "$SOURCE_REPO/release-sign-evidence/$TAG.XXXXXX")
  cp "$BINARY" "$EVIDENCE/$HOST_ASSET.rebuilt"
  cp SHA256SUMS "$EVIDENCE/SHA256SUMS"
  diff_status=0
  diff -u --label "CI/$HOST" --label "local/$HOST" "$WORK/ci-hash" "$WORK/local-hash" > "$EVIDENCE/host-hash.diff" || diff_status=$?
  [ "$diff_status" -eq 1 ] || die 'could not record host hash diff; refusing to sign'
  status='REJECTED HOST MISMATCH'
  [ -z "$HOST_REASON" ] || status='WARNING: BREAK-GLASS ACCEPT UNVERIFIED HOST'
  # %q keeps even multiline/control-character reasons on a single audit line.
  printf '%s target=%s tag=%s commit=%s ci_sha256=%s local_sha256=%s reason=%q\n' \
    "$status" "$HOST" "$TAG" "$FULL" "$CI_HASH" "$LOCAL_HASH" "$HOST_REASON" > "$EVIDENCE/manifest.txt"
  KEEP_WORK=false
  cat "$EVIDENCE/host-hash.diff" "$EVIDENCE/manifest.txt" >&2
  printf 'REBUILD EVIDENCE: %s\n' "$EVIDENCE" >&2
  [ -n "$HOST_REASON" ] || die "reproducibility mismatch for $HOST at $FULL; refusing to sign (investigate retained evidence; break-glass requires --accept-unverified-host <reason>)"
else
  printf 'VERIFIED target=%s tag=%s commit=%s sha256=%s\n' "$HOST" "$TAG" "$FULL" "$LOCAL_HASH"
fi
for target in ${ACCEPTED[@]+"${ACCEPTED[@]}"}; do
  printf 'ACCEPT UNVERIFIED target=%s tag=%s commit=%s (explicit operator waiver)\n' "$target" "$TAG" "$FULL" >&2
done
if "$DRY_RUN"; then
  echo 'Dry-run: gates completed (see verification/waiver status above); no signing or upload performed.'
  cat SHA256SUMS
  exit 0
fi

# 5. Sign, verify, attach only after the reproducibility gate.
gpg --list-secret-keys "$KEY_FPR" >/dev/null 2>&1 || die "release key $KEY_FPR is not on this machine"
# Re-check the draft after downloads and the rebuild, immediately before signing.
gh release view "$TAG" --repo "$REPO" --json isDraft -q .isDraft | grep -qx true || die "release $TAG is not a draft; refusing to change it"
gpg --armor --detach-sign --local-user "$KEY_FPR" --output SHA256SUMS.asc SHA256SUMS
gpg --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null | signed_by_key || die "signature check failed"
gh release upload "$TAG" SHA256SUMS SHA256SUMS.asc --repo "$REPO" --clobber

echo
echo "signed and attached: SHA256SUMS sha256 $(shasum -a 256 SHA256SUMS | awk '{print $1}')"
cat SHA256SUMS
echo
echo "Not published. After sign-off: gh release edit $TAG --repo $REPO --draft=false"
