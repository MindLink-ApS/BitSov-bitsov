#!/usr/bin/env bash
# Offline tests for scripts/verify-release.sh. A throwaway key is generated in
# a private GnuPG home. The production fingerprint is never replaced in the
# script that ships; integration cases run a private copy whose pin is the
# throwaway key. No network and no real keyring.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ "${1:-}" != --isolated ]; then
  exec env -i PATH="$PATH" "$BASH" "$HERE/test-verify-release.sh" --isolated
fi

WORK=$(mktemp -d /tmp/verify-release-test.XXXXXX)
cleanup() {
  if command -v gpgconf >/dev/null && [ -d "$WORK/gnupg" ]; then
    GNUPGHOME="$WORK/gnupg" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
export HOME="$WORK/home" GNUPGHOME="$WORK/gnupg" TMPDIR="$WORK/tmp"
mkdir -m 700 "$HOME" "$GNUPGHOME" "$TMPDIR"
export LC_ALL=C

fail() { echo "FAIL: $*" >&2; exit 1; }
pass=0
ok() { pass=$((pass + 1)); echo "ok   $*"; }

gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
  'Release Test <release-test@example.invalid>' ed25519 sign 0 >"$WORK/keygen.log" 2>&1 \
  || { cat "$WORK/keygen.log" >&2; exit 1; }
TEST_KEY=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" {print $10; exit}')
[ -n "$TEST_KEY" ] || fail 'no test fingerprint'
gpg --batch --export --armor "$TEST_KEY" > "$WORK/release.asc"
gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
  "VALIDSIG $TEST_KEY <spoof@example.invalid>" ed25519 sign 0 >"$WORK/spoofgen.log" 2>&1 \
  || { cat "$WORK/spoofgen.log" >&2; exit 1; }
SPOOF_KEY=$(gpg --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" && $10 != "'"$TEST_KEY"'" {print $10; exit}')
if [ -z "$SPOOF_KEY" ] || [ "$SPOOF_KEY" = "$TEST_KEY" ]; then
  fail 'spoof key was not generated'
fi
gpg --batch --export --armor "$SPOOF_KEY" > "$WORK/spoof.asc"

# Parser: same predicate as the signer. A user id that contains the fingerprint
# is not field 10. A subkey-style VALIDSIG whose primary field matches is accepted.
# shellcheck disable=SC1091
source "$HERE/verify-release.sh"
# signed_by_key, sourced above, reads this pin. The shipped script is not edited.
# shellcheck disable=SC2034
KEY_FPR=$TEST_KEY
if printf '%s\n' \
  "[GNUPG:] GOODSIG $SPOOF_KEY VALIDSIG $TEST_KEY" \
  "[GNUPG:] VALIDSIG $SPOOF_KEY 2026-01-01 1 0 0 0 1 10 00 $SPOOF_KEY" | signed_by_key
then
  fail 'user-id spoof was accepted'
fi
ok 'user-id spoof is rejected'
if ! printf '%s\n' \
  "[GNUPG:] VALIDSIG $SPOOF_KEY 2026-01-01 1 0 0 0 1 10 00 $TEST_KEY" | signed_by_key
then
  fail 'primary-key field was rejected'
fi
ok 'primary fingerprint field is accepted'
if printf '%s\n' \
  "[GNUPG:] EXPKEYSIG $TEST_KEY Release Test" \
  "[GNUPG:] VALIDSIG $TEST_KEY 2026-01-01 1 0 0 0 1 10 00 $TEST_KEY" | signed_by_key
then
  fail 'expired signature was accepted'
fi
ok 'expired signature is rejected'

extract_fn() {
  awk 'BEGIN { p = 0 } /^signed_by_key\(\)/ { p = 1 } p { print } p && /^}$/ { exit }' "$1"
}
diff -u <(extract_fn "$HERE/release-sign.sh") <(extract_fn "$HERE/verify-release.sh") \
  || fail 'signed_by_key drifted from release-sign.sh'
ok 'signed_by_key matches release-sign.sh'
grep -q 'KEY_FPR=B299274C200301714DC6F51A7C2D6F8AC842EF6E' "$HERE/verify-release.sh" \
  || fail 'production pin was changed'
grep -q 'KEY_FPR=B299274C200301714DC6F51A7C2D6F8AC842EF6E' "$HERE/release-sign.sh" \
  || fail 'signer pin missing'
! grep -E 'curl |wget |gh release' "$HERE/verify-release.sh" >/dev/null \
  || fail 'verifier fetches something'
ok 'production pin is unchanged and the verifier does not fetch'

# Integration uses a copy pinned to the throwaway key.
sed "s/B299274C200301714DC6F51A7C2D6F8AC842EF6E/$TEST_KEY/g" "$HERE/verify-release.sh" > "$WORK/verify-release.sh"
ASSETS=(bitsov-darwin-aarch64 bitsov-darwin-x86_64 bitsov-linux-aarch64 bitsov-linux-x86_64 bitsov-windows-x86_64)

sign_tree() {
  local dir=$1 key=$2 name
  : > "$dir/SHA256SUMS"
  for name in "${ASSETS[@]}"; do
    printf 'payload %s\n' "$name" > "$dir/$name"
    shasum -a 256 -- "$name" >> "$dir/SHA256SUMS"
  done
  # One optional sibling, so the allowlist is not only the five binaries.
  printf '{"sbom":true}\n' > "$dir/bitsov-linux-x86_64.sbom.spdx.json"
  shasum -a 256 -- bitsov-linux-x86_64.sbom.spdx.json >> "$dir/SHA256SUMS"
  printf 'xcode=test\n' > "$dir/bitsov-darwin-aarch64.toolchain.txt"
  shasum -a 256 -- bitsov-darwin-aarch64.toolchain.txt >> "$dir/SHA256SUMS"
  gpg --batch --local-user "$key" --armor --detach-sign --output "$dir/SHA256SUMS.asc" "$dir/SHA256SUMS"
}

expect_fail() {
  local name=$1 dir=$2 key=$3 needle=$4 out rc
  rc=0
  out=$(bash "$WORK/verify-release.sh" "$dir" "$key" 2>&1) || rc=$?
  [ "$rc" -ne 0 ] || fail "$name: accepted"
  printf '%s\n' "$out" | grep -F "$needle" >/dev/null || fail "$name: output was: $out"
  if printf '%s\n' "$out" | grep -q 'files match a signature'; then
    fail "$name: printed success"
  fi
  ok "reject $name"
}

GOOD="$WORK/good"
mkdir -p "$GOOD"
( cd "$GOOD" && sign_tree "$GOOD" "$TEST_KEY" )
bash "$WORK/verify-release.sh" "$GOOD" "$WORK/release.asc" >"$WORK/good.out"
grep -q '7 files match a signature' "$WORK/good.out" || fail "good path: $(cat "$WORK/good.out")"
ok 'accepts five binaries plus sbom and toolchain record'

# The shipped script must refuse this throwaway key even though the sums are well formed.
rc=0
out=$(bash "$HERE/verify-release.sh" "$GOOD" "$WORK/release.asc" 2>&1) || rc=$?
[ "$rc" -ne 0 ] || fail 'production script accepted a throwaway key'
printf '%s\n' "$out" | grep -F 'not B299274C200301714DC6F51A7C2D6F8AC842EF6E' >/dev/null \
  || fail "production script output: $out"
ok 'production script keeps the real fingerprint'

TAMPER="$WORK/tamper"
mkdir -p "$TAMPER"
cp -a "$GOOD/." "$TAMPER/"
printf 'x' >> "$TAMPER/bitsov-linux-x86_64"
expect_fail 'tampered binary' "$TAMPER" "$WORK/release.asc" 'hash mismatch'

EXTRA="$WORK/extra"
mkdir -p "$EXTRA"
cp -a "$GOOD/." "$EXTRA/"
printf 'disk image\n' > "$EXTRA/BitSov.dmg"
expect_fail 'extra file' "$EXTRA" "$WORK/release.asc" 'unexpected file in download directory: BitSov.dmg'

LINK="$WORK/link"
mkdir -p "$LINK"
cp -a "$GOOD/." "$LINK/"
rm "$LINK/bitsov-linux-x86_64"
ln -s "$GOOD/bitsov-linux-x86_64" "$LINK/bitsov-linux-x86_64"
expect_fail 'symlink binary' "$LINK" "$WORK/release.asc" 'not a regular file'

NESTED="$WORK/nested"
mkdir -p "$NESTED/hidden"
cp -a "$GOOD/." "$NESTED/"
printf 'hidden\n' > "$NESTED/hidden/payload"
expect_fail 'nested path' "$NESTED" "$WORK/release.asc" 'unexpected path in download directory: hidden'

BADNAME="$WORK/badname"
mkdir -p "$BADNAME"
(
  cd "$BADNAME"
  printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  ../x\n' > SHA256SUMS
  for name in "${ASSETS[@]}"; do
    printf 'payload %s\n' "$name" > "$name"
    shasum -a 256 -- "$name" >> SHA256SUMS
  done
  gpg --batch --local-user "$TEST_KEY" --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
)
expect_fail 'path in sums' "$BADNAME" "$WORK/release.asc" 'does not publish'

SPOOF_SIG="$WORK/spoofsig"
mkdir -p "$SPOOF_SIG"
cp -a "$GOOD/." "$SPOOF_SIG/"
rm "$SPOOF_SIG/SHA256SUMS.asc"
( cd "$SPOOF_SIG" && gpg --batch --local-user "$SPOOF_KEY" --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS )
expect_fail 'signature from another key' "$SPOOF_SIG" "$WORK/release.asc" 'not a valid signature'

expect_fail 'substituted public key' "$GOOD" "$WORK/spoof.asc" 'not '"$TEST_KEY"

grep -q '^UMask=0077$' "$HERE/../docs/operations/konsensus.service" \
  || fail 'user unit lost UMask=0077'
grep -q '^UMask=0077$' "$HERE/../docs/operations/bitsov.service" \
  || fail 'system unit lost UMask=0077'
ok 'both service units set UMask=0077'

echo "verify-release: $pass checks passed"
