#!/usr/bin/env bash
# Offline end-to-end regression tests; bash 3.2+, git, shasum and core utilities.
# Real Git uses a throwaway file:// origin. Only gh and GPG are faked: no
# credentials, real keyring, network, or release publishing are involved.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Drop inherited Git configuration/environment (including signing and hooks).
if [ "${1:-}" != --isolated ]; then
  exec env -i PATH="$PATH" "$BASH" "$HERE/test-release-sign.sh" --isolated
fi

WORK=$(mktemp -d /tmp/release-sign-test.XXXXXX)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/bin" "$WORK/home" "$WORK/tmp" "$WORK/fixtures"
export HOME="$WORK/home" GNUPGHOME="$WORK/home/gnupg" TMPDIR="$WORK/tmp"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ALLOW_PROTOCOL=file
export PATH="$WORK/bin:$PATH"
export TEST_ROOT="$WORK" TEST_TAG=v0.0.0-rc1
export TEST_REPO=MindLink-ApS/BitSov-bitsov
export TEST_KEY=B299274C200301714DC6F51A7C2D6F8AC842EF6E

cat > "$WORK/bin/common" <<'STUB'
set -euo pipefail
bad_call() {
  printf '%s: unexpected arguments: %s\n' "$0" "$*" >> "$CASE_DIR/unexpected"
  exit 97
}
expect_args() {
  local expected=$1; shift
  [ "$(printf '%s\n' "$@")" = "$expected" ] || bad_call "$@"
}
STUB

cat > "$WORK/bin/gh" <<'STUB'
#!/usr/bin/env bash
source "$TEST_ROOT/bin/common"
printf '%s\n' "$*" >> "$CASE_DIR/gh.log"
case "${1:-} ${2:-}" in
  'run list')
    expect_args "$(printf '%s\n' run list --repo "$TEST_REPO" --workflow ci.yml --branch "$TEST_TAG" --event push --limit 1 --json databaseId -q '.[0].databaseId')" "$@"
    echo 123
    ;;
  'run view')
    expect_args "$(printf '%s\n' run view 123 --repo "$TEST_REPO" --json headSha -q .headSha)" "$@"
    if [ "$TEST_CASE" = ci-sha ]; then echo "$OTHER_COMMIT"; else echo "$COMMIT"; fi
    ;;
  'run watch')
    expect_args "$(printf '%s\n' run watch 123 --repo "$TEST_REPO" --exit-status)" "$@"
    ;;
  'release view')
    expect_args "$(printf '%s\n' release view "$TEST_TAG" --repo "$TEST_REPO" --json isDraft -q .isDraft)" "$@"
    if [ "$TEST_CASE" = non-draft ]; then echo false; else echo true; fi
    ;;
  'release download')
    asset=${7:-}
    case "$asset" in
      bitsov-darwin-aarch64|bitsov-darwin-x86_64|bitsov-linux-aarch64|bitsov-linux-x86_64|bitsov-windows-x86_64) ;;
      *) bad_call "$@" ;;
    esac
    expect_args "$(printf '%s\n' release download "$TEST_TAG" --repo "$TEST_REPO" --pattern "$asset" --pattern "$asset.sha256" --clobber)" "$@"
    cp "$TEST_ROOT/fixtures/$asset" "$TEST_ROOT/fixtures/$asset.sha256" .
    # Corrupt the LAST asset: the script must validate all five before signing.
    if [ "$asset" = bitsov-windows-x86_64 ]; then
      case "$TEST_CASE" in
        checksum) printf 'corrupt\n' >> "$asset" ;;
        filename) sed "s/$asset/another-file/" "$asset.sha256" > altered; mv altered "$asset.sha256" ;;
      esac
    fi
    ;;
  'release upload')
    printf '%s\n' "$@" > "$CASE_DIR/upload.args"
    expect_args "$(printf '%s\n' release upload "$TEST_TAG" SHA256SUMS SHA256SUMS.asc --repo "$TEST_REPO" --clobber)" "$@"
    mkdir "$CASE_DIR/upload"
    cp SHA256SUMS SHA256SUMS.asc "$CASE_DIR/upload/"
    ;;
  *) bad_call "$@" ;; # Includes release edit/create: publishing always fails.
esac
STUB

cat > "$WORK/bin/gpg" <<'STUB'
#!/usr/bin/env bash
source "$TEST_ROOT/bin/common"
printf '%s\n' "$*" >> "$CASE_DIR/gpg.log"
signature() {
  printf '%s\n' '-----BEGIN PGP SIGNATURE-----' '' 'offline-test-signature' '-----END PGP SIGNATURE-----'
}
status() {
  local marker=GOODSIG
  if [ "$TEST_CASE" = "expired-$1" ]; then marker=EXPKEYSIG; fi
  printf '[GNUPG:] NEWSIG\n'
  printf '[GNUPG:] %s %s Test Release Key\n' "$marker" "${TEST_KEY:24}"
  # GPG emits VALIDSIG even with EXPKEYSIG; exit zero deliberately tests the
  # status filter rather than relying on GPG's process exit code.
  printf '[GNUPG:] VALIDSIG %s 2026-01-01 1767225600 0 4 0 1 10 00 %s\n' "$TEST_KEY" "$TEST_KEY"
  printf '[GNUPG:] TRUST_ULTIMATE 0 pgp\n'
}
case "${1:-}" in
  --list-secret-keys)
    expect_args "$(printf '%s\n' --list-secret-keys "$TEST_KEY")" "$@"
    ;;
  --armor)
    expect_args "$(printf '%s\n' --armor --detach-sign --local-user "$TEST_KEY" --output SHA256SUMS.asc SHA256SUMS)" "$@"
    cp SHA256SUMS "$CASE_DIR/signed-sums"
    signature > SHA256SUMS.asc
    ;;
  --status-fd)
    expect_args "$(printf '%s\n' --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS)" "$@"
    cmp SHA256SUMS "$CASE_DIR/signed-sums"
    signature | cmp - SHA256SUMS.asc
    status sums
    ;;
  --status-fd=2)
    # Git's tag -s invokes gpg with this signing protocol.
    expect_args "$(printf '%s\n' --status-fd=2 -bsau "$TEST_KEY")" "$@"
    cat > "$CASE_DIR/signed-tag"
    signature
    printf '[GNUPG:] SIG_CREATED D 1 10 00 1767225600 %s\n' "$TEST_KEY" >&2
    ;;
  --keyid-format=long)
    # Git passes the detached signature file and the tag payload on stdin.
    expect_args "$(printf '%s\n' --keyid-format=long --status-fd=1 --verify "${4:-}" -)" "$@"
    signature | cmp - "$4"
    cat > "$CASE_DIR/verified-tag"
    status tag
    ;;
  *) bad_call "$@" ;;
esac
STUB

# A broken run-list stub must fail promptly rather than spend ten minutes
# polling. Record it even if the production script ignores the exit status.
cat > "$WORK/bin/sleep" <<'STUB'
#!/usr/bin/env bash
source "$TEST_ROOT/bin/common"
bad_call "$@"
STUB
chmod +x "$WORK/bin/gh" "$WORK/bin/gpg" "$WORK/bin/sleep"

# Fixture checksums are computed before running release-sign, independently
# of its manifest assembly, then compared byte-for-byte with the upload.
for asset in bitsov-darwin-aarch64 bitsov-darwin-x86_64 bitsov-linux-aarch64 bitsov-linux-x86_64 bitsov-windows-x86_64; do
  printf 'offline binary: %s\n' "$asset" > "$WORK/fixtures/$asset"
  (cd "$WORK/fixtures" && shasum -a 256 "$asset" > "$asset.sha256")
  cat "$WORK/fixtures/$asset.sha256" >> "$WORK/expected-sums"
done

run_case() (
  export LC_ALL=$1 TEST_CASE=$2 CASE_DIR="$WORK/$1-$2"
  mkdir -p "$CASE_DIR"
  fail() { echo "$*" >&2; exit 1; }
  git init -q --bare "$CASE_DIR/origin.git"
  git init -q "$CASE_DIR/repo"
  cd "$CASE_DIR/repo"
  git config user.name 'Release Test'
  git config user.email release-test@example.invalid
  git config gpg.program "$WORK/bin/gpg"
  git config commit.gpgsign false
  git checkout -q -b main
  git commit -q --allow-empty -m base
  OTHER_COMMIT=$(git rev-parse HEAD)
  git commit -q --allow-empty -m release
  COMMIT=$(git rev-parse HEAD)
  export COMMIT OTHER_COMMIT
  git remote add origin "file://$CASE_DIR/origin.git"
  git push -q -u origin main
  if [ "$TEST_CASE" != fresh ]; then
    target=$COMMIT
    [ "$TEST_CASE" != wrong-tag ] || target=$OTHER_COMMIT
    git tag -s -u "$TEST_KEY" "$TEST_TAG" "$target" -m "BitSov $TEST_TAG"
    git push -q origin "refs/tags/$TEST_TAG"
    old_tag=$(git rev-parse "refs/tags/$TEST_TAG")
  fi
  # Exclude fixture setup from side-effect assertions.
  rm -f "$CASE_DIR/signed-tag"
  : > "$CASE_DIR/gpg.log"
  : > "$CASE_DIR/gh.log"
  rc=0
  bash "$HERE/release-sign.sh" "$TEST_TAG" "$COMMIT" > "$CASE_DIR/output" 2>&1 || rc=$?
  [ ! -f "$CASE_DIR/unexpected" ] || { cat "$CASE_DIR/unexpected"; fail 'unexpected stub call'; }

  reason=''
  case "$TEST_CASE" in
    existing|fresh) ;;
    wrong-tag) reason="tag $TEST_TAG exists on a different commit" ;;
    ci-sha) reason="CI run 123 built $OTHER_COMMIT, not the tagged commit $COMMIT" ;;
    non-draft) reason="release $TEST_TAG is not a draft; refusing to change it" ;;
    checksum) reason='bitsov-windows-x86_64: expected' ;;
    filename) reason='bitsov-windows-x86_64.sha256 names a different file' ;;
    expired-tag) reason="existing tag $TEST_TAG is not validly signed" ;;
    expired-sums) reason='signature check failed' ;;
    *) fail "unknown case $TEST_CASE" ;;
  esac
  if [ -z "$reason" ]; then
    [ "$rc" -eq 0 ] || fail "expected success, got exit $rc"
    cmp "$WORK/expected-sums" "$CASE_DIR/upload/SHA256SUMS"
    cmp "$CASE_DIR/signed-sums" "$CASE_DIR/upload/SHA256SUMS"
    printf '%s\n' release upload "$TEST_TAG" SHA256SUMS SHA256SUMS.asc --repo "$TEST_REPO" --clobber > "$CASE_DIR/expected.args"
    cmp "$CASE_DIR/expected.args" "$CASE_DIR/upload.args"
    [ "$(grep -c '^release download ' "$CASE_DIR/gh.log")" -eq 5 ]
    [ "$(grep -c '^release upload ' "$CASE_DIR/gh.log")" -eq 1 ]
    grep -qx "run watch 123 --repo $TEST_REPO --exit-status" "$CASE_DIR/gh.log"
    grep -qx -- '--status-fd 1 --verify SHA256SUMS.asc SHA256SUMS' "$CASE_DIR/gpg.log"
    grep -q '^Not published\.' "$CASE_DIR/output"
    [ -s "$CASE_DIR/verified-tag" ]
  else
    [ "$rc" -ne 0 ] || fail 'expected rejection, got success'
    grep -F "release-sign: $reason" "$CASE_DIR/output" >/dev/null || fail "missing rejection: $reason"
    [ ! -e "$CASE_DIR/upload.args" ] || fail 'uploaded after rejection'
    if [ "$TEST_CASE" != expired-sums ]; then
      [ ! -e "$CASE_DIR/signed-sums" ] || fail 'signed before validation finished'
    fi
  fi
  if [ "$TEST_CASE" = fresh ]; then
    [ -s "$CASE_DIR/signed-tag" ] || fail 'fresh tag was not signed'
    [ "$(git --git-dir="$CASE_DIR/origin.git" rev-parse "$TEST_TAG^{commit}")" = "$COMMIT" ] || fail 'fresh tag was not pushed'
  else
    [ ! -e "$CASE_DIR/signed-tag" ] || fail 'existing tag was signed again'
    [ "$(git rev-parse "refs/tags/$TEST_TAG")" = "$old_tag" ] || fail 'existing tag changed'
    [ "$(git --git-dir="$CASE_DIR/origin.git" rev-parse "refs/tags/$TEST_TAG")" = "$old_tag" ] || fail 'remote tag changed'
  fi
)

# Discover real installed encodings; Bash may merely warn and keep going for
# an unavailable locale, which would give false confidence in this regression.
locales=(C)
legacy=''
utf8=''
available=$(LC_ALL=C locale -a)
for candidate in da_DK.ISO8859-1 en_US.UTF-8 $available; do
  [ "$candidate" != C ] && [ "$candidate" != POSIX ] || continue
  printf '%s\n' "$available" | grep -Fxi "$candidate" >/dev/null || continue
  encoding=$(LC_ALL="$candidate" locale charmap 2>/dev/null) || continue
  case "$encoding" in
    UTF-8|UTF8|utf8|utf-8)
      case "$candidate" in en_US.*) [ -n "$utf8" ] || utf8=$candidate ;; esac
      ;;
    *) [ -n "$legacy" ] || legacy=$candidate ;;
  esac
  [ -z "$legacy" ] || [ -z "$utf8" ] || break
done
if [ -n "$legacy" ]; then locales+=("$legacy"); else echo 'SKIP: no non-UTF-8 locale besides C/POSIX installed'; fi
# en_US.UTF-8 is mandatory; CI generates it explicitly.
[ -n "$utf8" ] || { echo 'ERROR: en_US.UTF-8 is required (install/generate it first)' >&2; exit 1; }
locales+=("$utf8")

passed=0 failed=0
for test_locale in "${locales[@]}"; do
  for test_case in existing fresh wrong-tag ci-sha non-draft checksum filename expired-tag expired-sums; do
    # Launch a separate process so errexit remains active inside run_case.
    # Calling a function in an if condition would silently disable it.
    set +e
    (set -e; run_case "$test_locale" "$test_case") > "$WORK/case.log" 2>&1
    result=$?
    set -e
    if [ "$result" -eq 0 ]; then
      echo "PASS [$test_locale] $test_case"
      passed=$((passed + 1))
    else
      echo "FAIL [$test_locale] $test_case"
      cat "$WORK/case.log"
      cat "$WORK/$test_locale-$test_case/output" 2>/dev/null || true
      failed=$((failed + 1))
    fi
  done
done
echo "RELEASE-SIGN-TESTS: $passed passed, $failed failed"
[ "$failed" -eq 0 ]
