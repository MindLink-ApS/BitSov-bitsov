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
# 4. Signs SHA256SUMS with the release key, verifies the signature, and attaches
#    SHA256SUMS + SHA256SUMS.asc to the draft.
# It never publishes. The release key stays on this machine; nothing goes to CI.
set -euo pipefail

REPO=MindLink-ApS/BitSov-bitsov
KEY_FPR=B299274C200301714DC6F51A7C2D6F8AC842EF6E
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
[ $# -eq 2 ] || die "usage: $0 <tag> <commit-on-main>"
TAG=$1 COMMIT=$2
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]] || die "tag must look like v0.3.0 or v0.3.0-rc9"
for t in git gh gpg shasum; do command -v "$t" >/dev/null || die "$t not found"; done
gpg --list-secret-keys "$KEY_FPR" >/dev/null 2>&1 || die "release key $KEY_FPR is not on this machine"

cd "$(git rev-parse --show-toplevel)"
git fetch -q origin main --tags
FULL=$(git rev-parse --verify "$COMMIT^{commit}") || die "unknown commit $COMMIT"
git merge-base --is-ancestor "$FULL" origin/main || die "$FULL is not on origin/main"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# 1. Signed tag
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  [ "$(git rev-parse "$TAG^{commit}")" = "$FULL" ] || die "tag $TAG exists on a different commit"
  verify_tag || die "existing tag $TAG is not validly signed by $KEY_FPR"
  echo "tag $TAG already exists and is signed; continuing"
else
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
cd "$WORK"
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

# 4. Sign, verify, attach. Re-check the draft after the download window so a
# publish that landed while the binaries were hashing is not then modified.
gh release view "$TAG" --repo "$REPO" --json isDraft -q .isDraft | grep -qx true || die "release $TAG is not a draft; refusing to change it"
gpg --armor --detach-sign --local-user "$KEY_FPR" --output SHA256SUMS.asc SHA256SUMS
gpg --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null | signed_by_key || die "signature check failed"
gh release upload "$TAG" SHA256SUMS SHA256SUMS.asc --repo "$REPO" --clobber

echo
echo "signed and attached: SHA256SUMS sha256 $(shasum -a 256 SHA256SUMS | awk '{print $1}')"
cat SHA256SUMS
echo
echo "Not published. After sign-off: gh release edit $TAG --repo $REPO --draft=false"
