#!/usr/bin/env bash
# release-sign.sh: the operator's one command per release (RELEASE_POLICY.md).
#
#   scripts/release-sign.sh v0.3.0-rc10 <commit-on-main>
#
# 1. Creates and pushes a GPG-signed tag on the commit (skipped if the tag already
#    exists and is signed by the release key).
# 2. Waits for the tag's CI run, which stages the DRAFT release with the binaries
#    and per-file .sha256 files.
# 3. Downloads every binary, checks it against its .sha256, and writes SHA256SUMS.
# 4. Signs SHA256SUMS with the release key, verifies the signature, and attaches
#    SHA256SUMS + SHA256SUMS.asc to the draft.
# It never publishes. The release key stays on this machine; nothing goes to CI.
set -euo pipefail

REPO=MindLink-ApS/BitSov-bitsov
KEY_FPR=B299274C200301714DC6F51A7C2D6F8AC842EF6E
ASSETS=(bitsov-darwin-aarch64 bitsov-darwin-x86_64 bitsov-linux-aarch64 bitsov-linux-x86_64 bitsov-windows-x86_64)

die() { echo "release-sign: $*" >&2; exit 1; }
[ $# -eq 2 ] || die "usage: $0 <tag> <commit-on-main>"
TAG=$1 COMMIT=$2
[[ $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc[0-9]+)?$ ]] || die "tag must look like v0.3.0 or v0.3.0-rc9"
for t in git gh gpg shasum; do command -v "$t" >/dev/null || die "$t not found"; done
gpg --list-secret-keys "$KEY_FPR" >/dev/null 2>&1 || die "release key $KEY_FPR is not on this machine"

cd "$(git rev-parse --show-toplevel)"
git fetch -q origin main --tags
FULL=$(git rev-parse --verify "$COMMIT^{commit}") || die "unknown commit $COMMIT"
git merge-base --is-ancestor "$FULL" origin/main || die "$FULL is not on origin/main"

# 1. Signed tag
if git rev-parse -q --verify "refs/tags/$TAG" >/dev/null; then
  [ "$(git rev-parse "$TAG^{commit}")" = "$FULL" ] || die "tag $TAG exists on a different commit"
  git verify-tag --raw "$TAG" 2>&1 | grep -q "VALIDSIG $KEY_FPR" || die "existing tag $TAG is not signed by $KEY_FPR"
  echo "tag $TAG already exists and is signed; continuing"
else
  git tag -s -u "$KEY_FPR" "$TAG" "$FULL" -m "BitSov $TAG"
  git verify-tag --raw "$TAG" 2>&1 | grep -q "VALIDSIG $KEY_FPR" || die "fresh tag failed verification"
  git push origin "refs/tags/$TAG"
fi

# 2. Wait for the tag's CI run
echo "waiting for CI on $TAG…"
RUN=""
for _ in $(seq 1 60); do
  RUN=$(gh run list --repo "$REPO" --workflow ci.yml --branch "$TAG" --limit 1 --json databaseId -q '.[0].databaseId' || true)
  [ -n "$RUN" ] && break
  sleep 10
done
[ -n "$RUN" ] || die "no CI run found for $TAG"
gh run watch "$RUN" --repo "$REPO" --exit-status >/dev/null || die "CI run $RUN failed; nothing signed"

# 3. Download and verify
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
gh release view "$TAG" --repo "$REPO" --json isDraft -q .isDraft | grep -qx true || die "release $TAG is not a draft; refusing to change it"
for a in "${ASSETS[@]}"; do
  gh release download "$TAG" --repo "$REPO" --pattern "$a" --pattern "$a.sha256" --clobber
  expected=$(awk '{print $1; exit}' "$a.sha256")
  actual=$(shasum -a 256 "$a" | awk '{print $1}')
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "$a.sha256 is malformed"
  [ "$expected" = "$actual" ] || die "$a: expected $expected, got $actual"
  printf '%s  %s\n' "$actual" "$a" >> SHA256SUMS
done

# 4. Sign, verify, attach
gpg --armor --detach-sign --local-user "$KEY_FPR" --output SHA256SUMS.asc SHA256SUMS
gpg --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>/dev/null | grep -q "VALIDSIG $KEY_FPR" || die "signature check failed"
gh release upload "$TAG" SHA256SUMS SHA256SUMS.asc --repo "$REPO" --clobber

echo
echo "signed and attached: SHA256SUMS sha256 $(shasum -a 256 SHA256SUMS | awk '{print $1}')"
cat SHA256SUMS
echo
echo "Not published. After sign-off: gh release edit $TAG --repo $REPO --draft=false"
