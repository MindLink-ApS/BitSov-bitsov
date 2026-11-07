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
found=0
while IFS= read -r cmd; do
  found=1
  case "$cmd" in
    *--no-auto-key-retrieve*) ;;
    *) fail "verifier gpg invocation lacks --no-auto-key-retrieve: $cmd" ;;
  esac
done < <(grep -E '^[[:space:]]*(if ! )?gpg ' "$HERE/verify-release.sh" || true)
[ "$found" -eq 1 ] || fail 'verifier has no gpg invocation'
grep -F -- '--status-fd 1 --no-auto-key-retrieve --verify SHA256SUMS.asc SHA256SUMS' "$HERE/release-sign.sh" >/dev/null \
  || fail 'signer verify lacks --no-auto-key-retrieve'
ok 'production pin is unchanged and GnuPG is not asked to fetch a key'

load_allowed_names
[ "${#ALLOWED[@]}" -eq 17 ] || fail 'allow-list length'
allowed_name bitsov-linux-x86_64 || fail 'exact payload name was rejected'
if allowed_name $'\nbitsov-linux-x86_64' \
  || allowed_name $'bitsov-linux-x86_64\n' \
  || allowed_name $'evil\nbitsov-linux-x86_64' \
  || allowed_name --help \
  || allowed_name '--regexp=bitsov-linux-x86_64'
then
  fail 'allow-list equality accepted a non-payload name'
fi
ok 'allow-list equality rejects newline and option-like names'

# Integration uses a copy pinned to the throwaway key.
sed "s/B299274C200301714DC6F51A7C2D6F8AC842EF6E/$TEST_KEY/g" "$HERE/verify-release.sh" > "$WORK/verify-release.sh"
ASSETS=(bitsov-darwin-aarch64 bitsov-darwin-x86_64 bitsov-linux-aarch64 bitsov-linux-x86_64 bitsov-windows-x86_64)

sign_tree() {
  local dir=$1 key=$2 name
  : > "$dir/SHA256SUMS"
  for name in "${ASSETS[@]}"; do
    printf 'payload %s\n' "$name" > "$dir/$name"
    printf '%s\n' "$name" > "$dir/$name.sha256"
    printf '{"sbom":"%s"}\n' "$name" > "$dir/$name.sbom.spdx.json"
    shasum -a 256 -- "$name" "$name.sha256" "$name.sbom.spdx.json" >> "$dir/SHA256SUMS"
    case "$name" in
      bitsov-darwin-*)
        printf 'xcode=test %s\n' "$name" > "$dir/$name.toolchain.txt"
        shasum -a 256 -- "$name.toolchain.txt" >> "$dir/SHA256SUMS"
        ;;
    esac
  done
  gpg --batch --local-user "$key" --armor --detach-sign --output "$dir/SHA256SUMS.asc" "$dir/SHA256SUMS"
}

expect_fail() {
  local name=$1 dir=$2 key=$3 needle=$4 out rc
  rc=0
  out=$(bash "$WORK/verify-release.sh" "$dir" "$key" 2>&1) || rc=$?
  [ "$rc" -ne 0 ] || fail "$name: accepted"
  printf '%s\n' "$out" | grep -F -- "$needle" >/dev/null || fail "$name: output was: $out"
  if printf '%s\n' "$out" | grep -q 'files match a signature'; then
    fail "$name: printed success"
  fi
  ok "reject $name"
}

GOOD="$WORK/good"
mkdir -p "$GOOD"
( cd "$GOOD" && sign_tree "$GOOD" "$TEST_KEY" )
bash "$WORK/verify-release.sh" "$GOOD" "$WORK/release.asc" >"$WORK/good.out"
grep -q '17 sealed files match a signature' "$WORK/good.out" || fail "good path: $(cat "$WORK/good.out")"
GOOD_SEAL=$(sed -n 's/^verify-release: sealed //p' "$WORK/good.out")
if [ -z "$GOOD_SEAL" ] || [ ! -d "$GOOD_SEAL" ] || [ -L "$GOOD_SEAL" ]; then
  fail "good path: no seal: $(cat "$WORK/good.out")"
fi
cmp -s "$GOOD/bitsov-linux-x86_64" "$GOOD_SEAL/bitsov-linux-x86_64" || fail 'good path: seal payload differs'
[ "$(find "$GOOD_SEAL" -mindepth 1 -maxdepth 1 -print | wc -l | tr -d ' ')" -eq 20 ] \
  || fail 'good path: seal file count'
if find "$GOOD_SEAL" -mindepth 1 -type l -print | grep -q .; then
  fail 'good path: symlink in seal'
fi
case "$(seal_type_mode "$GOOD_SEAL")" in
  drwx------*) ;;
  *) fail 'good path: seal is not mode 0700' ;;
esac
bash "$WORK/verify-release.sh" --cleanup "$GOOD_SEAL"
[ ! -e "$GOOD_SEAL" ] || fail 'good path: cleanup left the seal'
ok 'accepts the seventeen signer artifacts and cleans the seal'

PARTIAL="$WORK/partial"
mkdir -p "$PARTIAL"
cp -a "$GOOD/." "$PARTIAL/"
(
  cd "$PARTIAL"
  rm -f bitsov-linux-x86_64.sbom.spdx.json SHA256SUMS.asc
  grep -v -F 'bitsov-linux-x86_64.sbom.spdx.json' SHA256SUMS > SHA256SUMS.new
  mv SHA256SUMS.new SHA256SUMS
  gpg --batch --local-user "$TEST_KEY" --armor --detach-sign --output SHA256SUMS.asc SHA256SUMS
)
expect_fail 'incomplete artifact set' "$PARTIAL" "$WORK/release.asc" 'not exactly the five binaries'

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

# Names that look like grep options must still be ordinary filenames.
# Without "--", grep -Fxq --help exits 0 and grep -Fxq --regexp=<allowed>
# matches that allowed name, so the extra entry is admitted.
OPT_HELP="$WORK/opt-help"
mkdir -p "$OPT_HELP"
cp -a "$GOOD/." "$OPT_HELP/"
printf 'option-like\n' > "$OPT_HELP/--help"
expect_fail 'option-like extra file --help' "$OPT_HELP" "$WORK/release.asc" \
  'unexpected file in download directory: --help'

OPT_REGEXP="$WORK/opt-regexp"
mkdir -p "$OPT_REGEXP"
cp -a "$GOOD/." "$OPT_REGEXP/"
printf 'option-like\n' > "$OPT_REGEXP/--regexp=bitsov-linux-x86_64"
expect_fail 'option-like extra file --regexp' "$OPT_REGEXP" "$WORK/release.asc" \
  'unexpected file in download directory: --regexp=bitsov-linux-x86_64'

OPT_LINK="$WORK/opt-symlink"
mkdir -p "$OPT_LINK"
cp -a "$GOOD/." "$OPT_LINK/"
ln -s /etc/passwd "$OPT_LINK/--help"
expect_fail 'option-like symlink' "$OPT_LINK" "$WORK/release.asc" \
  'unexpected path in download directory: --help'

# A newline inside a filename is still one directory entry. It must not be
# split into grep patterns that include an allowed payload name.
NL_LEAD="$WORK/nl-lead"
mkdir -p "$NL_LEAD"
cp -a "$GOOD/." "$NL_LEAD/"
printf 'UNSIGNED-EXTRA\n' > "$NL_LEAD/$'\nbitsov-linux-x86_64'"
expect_fail 'leading newline extra file' "$NL_LEAD" "$WORK/release.asc" \
  'unexpected file in download directory:'

NL_TRAIL="$WORK/nl-trail"
mkdir -p "$NL_TRAIL"
cp -a "$GOOD/." "$NL_TRAIL/"
printf 'TWIN\n' > "$NL_TRAIL/$'bitsov-linux-x86_64\n'"
expect_fail 'trailing newline extra file' "$NL_TRAIL" "$WORK/release.asc" \
  'unexpected file in download directory:'

NL_LINK="$WORK/nl-link"
mkdir -p "$NL_LINK"
cp -a "$GOOD/." "$NL_LINK/"
printf 'outside-secret\n' > "$WORK/outside-secret"
ln -s "$WORK/outside-secret" "$NL_LINK/$'evil\nbitsov-linux-x86_64'"
expect_fail 'multiline-name symlink' "$NL_LINK" "$WORK/release.asc" \
  'unexpected path in download directory:'

assert_no_seals() {
  local leftover
  leftover=$(find "$TMPDIR" -maxdepth 1 -type d -name 'verify-release-seal.*' -print)
  [ -z "$leftover" ] || fail "seal left behind: $leftover"
}
assert_no_seals
ok 'rejected names leave no seal directory'

# Replace the live manifest while the directory walk is in progress, after
# the script has snapshotted it. Success must still be the signed bytes.
# Payload hashes are of the seal, not of the download paths.
SWAPDIR="$WORK/swap-manifest"
mkdir -p "$SWAPDIR" "$WORK/bin"
cp -a "$GOOD/." "$SWAPDIR/"
cp -P -- "$SWAPDIR/SHA256SUMS" "$WORK/signed-sums"
cp -P -- "$SWAPDIR/SHA256SUMS.asc" "$WORK/signed-sums.asc"
printf '%s\n' '0000000000000000000000000000000000000000000000000000000000000000  bitsov-linux-x86_64' \
  > "$WORK/swapped-sums"
real_find=$(command -v find)
cat > "$WORK/bin/find" << EOF
#!/bin/bash
set -euo pipefail
$(printf '%q' "$real_find") "\$@"
rc=\$?
if [ "\${1:-}" = . ] && [ -n "\${VERIFY_RELEASE_SWAP_TO:-}" ]; then
  cp -f -- "\$VERIFY_RELEASE_SWAP_TO" SHA256SUMS
fi
exit "\$rc"
EOF
chmod 755 "$WORK/bin/find"
rc=0
out=$(VERIFY_RELEASE_SWAP_TO="$WORK/swapped-sums" PATH="$WORK/bin:$PATH" \
  bash "$WORK/verify-release.sh" "$SWAPDIR" "$WORK/release.asc" 2>&1) || rc=$?
[ "$rc" -eq 0 ] || fail "manifest swap: verifier failed: $out"
printf '%s\n' "$out" | grep -F -- '17 sealed files match a signature' >/dev/null \
  || fail "manifest swap: output was: $out"
SWAP_SEAL=$(printf '%s\n' "$out" | sed -n 's/^verify-release: sealed //p')
[ -n "$SWAP_SEAL" ] || fail 'manifest swap: no seal path'
cmp -s "$WORK/signed-sums" "$SWAP_SEAL/SHA256SUMS" \
  || fail 'manifest swap: seal sums are not the signed bytes'
cmp -s "$WORK/signed-sums.asc" "$SWAP_SEAL/SHA256SUMS.asc" \
  || fail 'manifest swap: seal signature is not the signed bytes'
if cmp -s "$WORK/swapped-sums" "$SWAP_SEAL/SHA256SUMS"; then
  fail 'manifest swap: seal took the live replacement'
fi
if cmp -s "$WORK/signed-sums" "$SWAPDIR/SHA256SUMS"; then
  fail 'manifest swap: live SHA256SUMS was not replaced'
fi
cmp -s "$WORK/swapped-sums" "$SWAPDIR/SHA256SUMS" \
  || fail 'manifest swap: live SHA256SUMS is not the replacement'
if ! gpg --batch --status-fd 1 --no-auto-key-retrieve --verify \
    "$WORK/signed-sums.asc" "$WORK/signed-sums" 2>"$WORK/signed-gpg.err" \
    | signed_by_key
then
  fail 'manifest swap: signed bytes no longer verify'
fi
if gpg --batch --status-fd 1 --no-auto-key-retrieve --verify \
    "$SWAPDIR/SHA256SUMS.asc" "$SWAPDIR/SHA256SUMS" 2>"$WORK/swap-gpg.err" \
    | signed_by_key
then
  fail 'manifest swap: swapped live SHA256SUMS verified'
fi
bash "$WORK/verify-release.sh" --cleanup "$SWAP_SEAL"
[ ! -e "$SWAP_SEAL" ] || fail 'manifest swap: cleanup left the seal'
ok 'signed snapshot survives a live SHA256SUMS replacement'

# cp closes the live payload, then a writer replaces that live file before
# shasum. The hash and the bytes that remain to be installed are the seal.
RACE="$WORK/race"
mkdir -p "$RACE" "$WORK/race-bin"
cp -a "$GOOD/." "$RACE/"
cp -P -- "$RACE/bitsov-linux-x86_64" "$WORK/race-original"
REAL_CP=$(command -v cp)
REAL_SHASUM=$(command -v shasum)
cat > "$WORK/race-bin/cp" << EOF
#!/bin/bash
$(printf '%q' "$REAL_CP") "\$@"
rc=\$?
if [ "\$rc" -eq 0 ] && [ "\${1:-}" = -P ] && [ "\${3:-}" = bitsov-linux-x86_64 ]; then
  printf 'MALWARE\n' > bitsov-linux-x86_64
fi
exit "\$rc"
EOF
cat > "$WORK/race-bin/shasum" << EOF
#!/bin/bash
printf '%s\n' "\$*" >> $(printf '%q' "$WORK/shasum.log")
exec $(printf '%q' "$REAL_SHASUM") "\$@"
EOF
chmod 755 "$WORK/race-bin/cp" "$WORK/race-bin/shasum"
: > "$WORK/shasum.log"
rc=0
out=$(PATH="$WORK/race-bin:$PATH" bash "$WORK/verify-release.sh" "$RACE" "$WORK/release.asc" 2>&1) || rc=$?
[ "$rc" -eq 0 ] || fail "payload swap: verifier failed: $out"
printf '%s\n' "$out" | grep -F -- '17 sealed files match a signature' >/dev/null \
  || fail "payload swap: output was: $out"
RACE_SEAL=$(printf '%s\n' "$out" | sed -n 's/^verify-release: sealed //p')
if [ -z "$RACE_SEAL" ] || [ ! -d "$RACE_SEAL" ]; then
  fail 'payload swap: no seal'
fi
cmp -s "$WORK/race-original" "$RACE_SEAL/bitsov-linux-x86_64" \
  || fail 'payload swap: seal does not hold the signed bytes'
printf 'MALWARE\n' | cmp -s - "$RACE/bitsov-linux-x86_64" \
  || fail 'payload swap: live file was not replaced'
if cmp -s "$RACE/bitsov-linux-x86_64" "$RACE_SEAL/bitsov-linux-x86_64"; then
  fail 'payload swap: seal and the live file are the same bytes'
fi
race_hash=$(awk '$2 == "bitsov-linux-x86_64" { print $1; exit }' "$RACE_SEAL/SHA256SUMS")
race_got=$(shasum -a 256 -- "$RACE_SEAL/bitsov-linux-x86_64" | awk '{ print $1; exit }')
[ "$race_got" = "$race_hash" ] || fail 'payload swap: sealed payload does not match the signed hash'
[ "$(wc -l < "$WORK/shasum.log" | tr -d ' ')" -eq 17 ] || fail 'payload swap: shasum count'
while IFS= read -r line; do
  case "$line" in
    *"$RACE_SEAL"/*) ;;
    *) fail "payload swap: shasum read outside the seal: $line" ;;
  esac
done < "$WORK/shasum.log"
grep -F -- "$RACE_SEAL/bitsov-linux-x86_64" "$WORK/shasum.log" >/dev/null \
  || fail 'payload swap: linux payload was not hashed from the seal'
if grep -F -- "$RACE/bitsov-linux-x86_64" "$WORK/shasum.log" >/dev/null; then
  fail 'payload swap: shasum read the live payload'
fi
ok 'sealed payload survives replacement of the live file'

ln -s "$RACE_SEAL" "$WORK/seal-link"
rc=0
out=$(bash "$WORK/verify-release.sh" --cleanup "$WORK/seal-link" 2>&1) || rc=$?
[ "$rc" -ne 0 ] || fail 'cleanup followed a symlink'
[ -d "$RACE_SEAL" ] || fail 'cleanup symlink removed the seal'
rc=0
out=$(bash "$WORK/verify-release.sh" --cleanup "$GOOD" 2>&1) || rc=$?
[ "$rc" -ne 0 ] || fail 'cleanup accepted the download directory'
[ -f "$GOOD/bitsov-linux-x86_64" ] || fail 'cleanup removed a download payload'
cp -a "$RACE_SEAL" "$WORK/copied-seal"
rc=0
out=$(bash "$WORK/verify-release.sh" --cleanup "$WORK/copied-seal" 2>&1) || rc=$?
[ "$rc" -ne 0 ] || fail 'cleanup accepted a copied seal with a foreign marker'
[ -d "$RACE_SEAL" ] || fail 'foreign-marker cleanup removed the real seal'
rm -rf "$WORK/copied-seal"
chmod 755 "$RACE_SEAL"
rc=0
out=$(bash "$WORK/verify-release.sh" --cleanup "$RACE_SEAL" 2>&1) || rc=$?
[ "$rc" -ne 0 ] || fail 'cleanup accepted a seal that is not mode 0700'
chmod 700 "$RACE_SEAL"
printf 'extra\n' > "$RACE_SEAL/extra"
rc=0
out=$(bash "$WORK/verify-release.sh" --cleanup "$RACE_SEAL" 2>&1) || rc=$?
[ "$rc" -ne 0 ] || fail 'cleanup deleted a seal that contains an unexpected file'
[ -f "$RACE_SEAL/bitsov-linux-x86_64" ] || fail 'unexpected-file cleanup removed a payload'
rm -f -- "$RACE_SEAL/extra"
bash "$WORK/verify-release.sh" --cleanup "$RACE_SEAL"
[ ! -e "$RACE_SEAL" ] || fail 'cleanup left the race seal'
ok 'cleanup removes only an intact seal this script published'

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

grep -F 'does not seal the payloads' "$HERE/verify-release.sh" >/dev/null \
  || fail 'verifier omits the payload-seal limit'
grep -F 'different uid' "$HERE/verify-release.sh" >/dev/null \
  || fail 'verifier omits the different-uid limit'
grep -F 'same uid' "$HERE/verify-release.sh" >/dev/null \
  || fail 'verifier omits the same-uid limit'
# shellcheck disable=SC2016
grep -F -- 'shasum -a 256 -- "$SEAL/$name"' "$HERE/verify-release.sh" >/dev/null \
  || fail 'payload hash does not read the seal'
# shellcheck disable=SC2016
if grep -F -- 'shasum -a 256 -- "$name"' "$HERE/verify-release.sh" >/dev/null; then
  fail 'payload hash still reads the download path'
fi
if grep -n 'grep -Fxq' "$HERE/verify-release.sh" >/dev/null; then
  fail 'membership still uses grep -Fxq'
fi
# shellcheck disable=SC2016
if grep -nE 'grep .*\$rel|grep .*\$name' "$HERE/verify-release.sh" >/dev/null; then
  fail 'a filename is still a grep pattern'
fi
if grep -nE 'sudo[[:space:]]' "$HERE/verify-release.sh" >/dev/null; then
  fail 'verifier runs sudo'
fi
grep -F 'does not seal the payloads' "$HERE/../docs/operations/home-node.md" >/dev/null \
  || fail 'home-node omits the payload-seal limit'
grep -F 'same user' "$HERE/../docs/operations/home-node.md" >/dev/null \
  || fail 'home-node omits the same-user limit'
# shellcheck disable=SC2016
grep -F 'sudo install -m 0755 "$seal/bitsov-linux-x86_64"' "$HERE/../docs/operations/home-node.md" >/dev/null \
  || fail 'home-node does not install from the seal'
if grep -F 'sudo install -m 0755 /path/to/download/bitsov-linux-x86_64' "$HERE/../docs/operations/home-node.md" >/dev/null; then
  fail 'home-node still installs the live download path'
fi
grep -F 'does not seal the payloads' "$HERE/../docs/ops/RELEASE_POLICY.md" >/dev/null \
  || fail 'release policy omits the payload-seal limit'
grep -F 'same uid' "$HERE/../docs/ops/RELEASE_POLICY.md" >/dev/null \
  || fail 'release policy omits the same-uid limit'
ok 'threat model says the seal, not the manifest snapshot, is what gets installed'

assert_no_seals
ok 'no seal directory remains'

echo "verify-release: $pass checks passed"
