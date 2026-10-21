#!/usr/bin/env bash
# Offline end-to-end regression tests; bash 3.2+, git, shasum and core utilities.
# Real Git and GPG use a throwaway origin and generated test key. gh and
# Rust compilation are simulated; no real keyring, network or publishing.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Drop inherited Git configuration/environment (including signing and hooks).
if [ "${1:-}" != --isolated ]; then
  exec env -i PATH="$PATH" "$BASH" "$HERE/test-release-sign.sh" --isolated
fi

WORK=$(mktemp -d /tmp/release-sign-test.XXXXXX)
cleanup() {
  if command -v gpgconf >/dev/null && [ -d "$WORK/home/gnupg" ]; then
    GNUPGHOME="$WORK/home/gnupg" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$WORK/bin" "$WORK/home" "$WORK/tmp" "$WORK/fixtures"
export HOME="$WORK/home" GNUPGHOME="$WORK/home/gnupg" TMPDIR="$WORK/tmp"
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_ALLOW_PROTOCOL=file
export PATH="$WORK/bin:$PATH"
export TEST_ROOT="$WORK" TEST_TAG=v0.0.0-rc1
export TEST_REPO=MindLink-ApS/BitSov-bitsov
export REAL_GPG
REAL_GPG=$(command -v gpg)
mkdir -m 700 "$GNUPGHOME"
"$REAL_GPG" --batch --pinentry-mode loopback --passphrase '' --quick-generate-key \
  'Release Test <release-test@example.invalid>' ed25519 sign 0 >"$WORK/keygen.log" 2>&1 || { cat "$WORK/keygen.log" >&2; exit 1; }
TEST_KEY=$("$REAL_GPG" --batch --with-colons --list-secret-keys | awk -F: '$1 == "fpr" {print $10; exit}')
export TEST_KEY
# Change only a private test copy, never the production key pin or a real keyring.
sed "s/B299274C200301714DC6F51A7C2D6F8AC842EF6E/$TEST_KEY/g" "$HERE/release-sign.sh" > "$WORK/release-sign.sh"

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
    if [ "${7:-}" = assets ]; then
      expect_args "$(printf '%s\n' release view "$TEST_TAG" --repo "$TEST_REPO" --json assets -q '.assets[].name')" "$@"
      case "$TEST_CASE" in
        extra-asset|retry-extra) printf '%s\n' BitSov.dmg ;;
        retry-lookalike) printf '%s\n' SHA256SUMS.asc.bak ;;
      esac
      case "$TEST_CASE" in
        retry-sums) printf '%s\n' SHA256SUMS ;;
        retry-signature) printf '%s\n' SHA256SUMS.asc ;;
        retry-extra|retry-lookalike) printf '%s\n' SHA256SUMS SHA256SUMS.asc ;;
      esac
      # A second invocation sees exactly the output uploaded by the first.
      if [ -d "$CASE_DIR/upload" ]; then printf '%s\n' SHA256SUMS SHA256SUMS.asc; fi
      for name in bitsov-darwin-aarch64 bitsov-darwin-x86_64 bitsov-linux-aarch64 bitsov-linux-x86_64 bitsov-windows-x86_64; do
        printf '%s\n' "$name" "$name.sha256" "$name.sbom.spdx.json"
      done
      exit 0
    fi
    expect_args "$(printf '%s\n' release view "$TEST_TAG" --repo "$TEST_REPO" --json isDraft -q .isDraft)" "$@"
    n=0
    if [ -f "$CASE_DIR/draft-checks" ]; then n=$(cat "$CASE_DIR/draft-checks"); fi
    n=$((n + 1))
    if [ "$TEST_CASE" = published-late ] && [ "$n" -eq 2 ]; then
      [ -s "$CASE_DIR/build.log" ] || bad_call draft-check-before-rebuild
    fi
    printf '%s\n' "$n" > "$CASE_DIR/draft-checks"
    if [ "$TEST_CASE" = non-draft ] || { [ "$TEST_CASE" = published-late ] && [ "$n" -ge 2 ]; }; then
      echo false
    else
      echo true
    fi
    ;;
  'release download')
    asset=${7:-}
    case "$asset" in
      bitsov-darwin-aarch64|bitsov-darwin-x86_64|bitsov-linux-aarch64|bitsov-linux-x86_64|bitsov-windows-x86_64) ;;
      *) bad_call "$@" ;;
    esac
    if [ "${10:-}" = --clobber ]; then
      expect_args "$(printf '%s\n' release download "$TEST_TAG" --repo "$TEST_REPO" --pattern "$asset" --pattern "$asset.sha256" --clobber)" "$@"
    else
      expect_args "$(printf '%s\n' release download "$TEST_TAG" --repo "$TEST_REPO" --pattern "$asset" --pattern "$asset.sha256" --pattern "$asset.sbom.spdx.json" --clobber)" "$@"
      cp "$TEST_ROOT/fixtures/$asset.sbom.spdx.json" .
    fi
    cp "$TEST_ROOT/fixtures/$asset" "$TEST_ROOT/fixtures/$asset.sha256" .
    # A compromised CI can replace BOTH the host binary and its checksum.
    if [ "$asset" = bitsov-linux-x86_64 ] && [ "$TEST_CASE" = compromised-ci ]; then
      echo injected >> "$asset"
      shasum -a 256 "$asset" > "$asset.sha256"
    fi
    # Corrupt the LAST asset: the script must validate all five before signing.
    if [ "$asset" = bitsov-windows-x86_64 ]; then
      case "$TEST_CASE" in
        checksum|accept-checksum) printf 'corrupt\n' >> "$asset" ;;
        filename) sed "s/$asset/another-file/" "$asset.sha256" > altered; mv altered "$asset.sha256" ;;
      esac
    fi
    ;;
  'release upload')
    printf '%s\n' "$@" > "$CASE_DIR/upload.args"
    expect_args "$(printf '%s\n' release upload "$TEST_TAG" SHA256SUMS SHA256SUMS.asc --repo "$TEST_REPO" --clobber)" "$@"
    mkdir -p "$CASE_DIR/upload"
    cp SHA256SUMS SHA256SUMS.asc "$CASE_DIR/upload/"
    ;;
  *) bad_call "$@" ;; # Includes release edit/create: publishing always fails.
esac
STUB

cat > "$WORK/bin/gpg" <<'STUB'
#!/usr/bin/env bash
source "$TEST_ROOT/bin/common"
printf '%s\n' "$*" >> "$CASE_DIR/gpg.log"
case "$*" in
  *--detach-sign*) cp SHA256SUMS "$CASE_DIR/signed-sums" ;;
  *-bsau*) touch "$CASE_DIR/signed-tag" ;;
  *--verify*) touch "$CASE_DIR/verified-tag" ;;
esac
# Always verify real signatures first. Rewrite only status records to exercise
# the malformed/forged-status cases from the signature-hardening suite.
verify_kind=''
case "${1:-}" in
  --keyid-format=long) verify_kind=tag ;;
  --status-fd) verify_kind=sums ;;
esac
if [ -z "$verify_kind" ]; then exec "$REAL_GPG" "$@"; fi
output=$("$REAL_GPG" "$@")
if [ "$TEST_CASE" = stderr-noise ]; then
  printf '[GNUPG:] BADSIG %s diagnostic, not status\n' "${TEST_KEY:24}" >&2
fi
while IFS= read -r line; do
  case "$line" in
    '[GNUPG:] GOODSIG '*)
      case "$TEST_CASE" in
        "expired-$verify_kind") line=${line/GOODSIG/EXPKEYSIG} ;;
        notation)
          if [ "$verify_kind" = tag ]; then
            line="[GNUPG:] GOODSIG ${TEST_KEY:24} VALIDSIG $TEST_KEY"
          fi
          ;;
      esac
      ;;
    '[GNUPG:] VALIDSIG '*)
      rest=${line#\[GNUPG:\] VALIDSIG }
      IFS=$' \t' read -r -a fields <<<"$rest"
      case "$TEST_CASE" in
        subkey) fields[0]=0123456789ABCDEF0123456789ABCDEF01234567 ;;
        notation)
          if [ "$verify_kind" = tag ]; then
            fields[0]=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
            fields[9]=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
          fi
          ;;
        "wrong-primary-$verify_kind") fields[9]=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ;;
        "missing-primary-$verify_kind") unset 'fields[9]' ;;
        "truncated-$verify_kind") fields=("$TEST_KEY") ;;
        "trailing-key-$verify_kind")
          fields[0]=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
          fields[9]=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
          fields+=("$TEST_KEY")
          ;;
        "stderr-only-$verify_kind") printf '%s\n' "$line" >&2; continue ;;
      esac
      line="[GNUPG:] VALIDSIG ${fields[*]}"
      ;;
  esac
  printf '%s\n' "$line"
done <<<"$output"
STUB

cat > "$WORK/bin/rustup" <<'STUB'
#!/usr/bin/env bash
source "$TEST_ROOT/bin/common"
case "$*" in
  'run 1.91.1 rustc -vV')
    if [ "$TEST_CASE" = unsupported-host ]; then
      printf 'rustc 1.91.1\nhost: riscv64gc-unknown-linux-gnu\n'
    else
      printf 'rustc 1.91.1\nhost: %s\n' "$TEST_HOST"
    fi
    ;;
  "run 1.91.1 cargo build --locked --release -p konsensus-node --target $TEST_HOST")
    [ "$(git rev-parse HEAD)" = "$COMMIT" ] || bad_call wrong-commit
    [ "$(cat tagged-content)" = tagged ] || bad_call dirty-source
    [ "$SOURCE_DATE_EPOCH" = "$(git show -s --format=%ct HEAD)" ] || bad_call epoch
    [ "$CARGO_PROFILE_RELEASE_STRIP" = symbols ] || bad_call strip
    [ "$CARGO_INCREMENTAL" = 0 ] || bad_call incremental
    [[ "$CARGO_ENCODED_RUSTFLAGS" == *--remap-path-prefix* ]] || bad_call remap
    printf '%s\n' "$PWD" >> "$CASE_DIR/build.log"
    case "$TEST_CASE" in *build-failure) exit 1 ;; esac
    mkdir -p "$CARGO_TARGET_DIR/$TEST_HOST/release"
    cp "$TEST_ROOT/fixtures/$TEST_HOST_ASSET" "$CARGO_TARGET_DIR/$TEST_HOST/release/konsensus"
    if [[ "$TEST_CASE" == *mismatch ]]; then
      echo different >> "$CARGO_TARGET_DIR/$TEST_HOST/release/konsensus"
    fi
    ;;
  *) bad_call "$@" ;;
esac
STUB
chmod +x "$WORK/bin/rustup"

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
  printf '{"spdxVersion":"SPDX-2.3","name":"%s"}\n' "$asset" > "$WORK/fixtures/$asset.sbom.spdx.json"
  (cd "$WORK/fixtures" && shasum -a 256 "$asset" "$asset.sha256" "$asset.sbom.spdx.json") >> "$WORK/expected-sums"
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
  mkdir scripts
  printf '1.91.1\n' > scripts/release-toolchain
  cp "$HERE/release-build.sh" scripts/release-build.sh
  printf 'tagged\n' > tagged-content
  git add scripts/release-toolchain scripts/release-build.sh tagged-content
  git commit -q -m release
  COMMIT=$(git rev-parse HEAD)
  export COMMIT OTHER_COMMIT
  export TEST_HOST=x86_64-unknown-linux-gnu TEST_HOST_ASSET=bitsov-linux-x86_64
  if [ "$TEST_CASE" = accept-darwin-mismatch ]; then
    TEST_HOST=aarch64-apple-darwin TEST_HOST_ASSET=bitsov-darwin-aarch64
  fi
  git remote add origin "file://$CASE_DIR/origin.git"
  git push -q -u origin main
  if [ "$TEST_CASE" != fresh ] && [ "$TEST_CASE" != dry-fresh ]; then
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
  # A dirty checkout and later commit must never become the build input.
  printf 'exit 89\n' > scripts/release-build.sh
  printf 'later\n' > tagged-content
  git commit -qam later
  printf 'exit 90\n' > scripts/release-build.sh
  printf 'dirty\n' > tagged-content
  args=()
  if [ "$TEST_CASE" != no-waivers ]; then
    for target in aarch64-apple-darwin x86_64-apple-darwin aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu x86_64-pc-windows-msvc; do
      [ "$target" != "$TEST_HOST" ] || continue
      if [[ "$TEST_CASE" != *missing-waiver ]] || [ "$target" != x86_64-pc-windows-msvc ]; then
        args+=(--accept-unverified-target "$target")
      fi
    done
  fi
  case "$TEST_CASE" in
    dry-*) args+=(--dry-run) ;;
    waive-host) args+=(--accept-unverified-target x86_64-unknown-linux-gnu) ;;
    unknown-waiver) args+=(--accept-unverified-target imaginary-triple) ;;
  esac
  host_reason=$'Investigated SDK drift; operator accepts risk "rc"\nVERIFIED forged'
  case "$TEST_CASE" in
    accept-*|dry-accept-*) args+=(--accept-unverified-host "$host_reason") ;;
    reason-empty) args+=(--accept-unverified-host '') ;;
    reason-blank) args+=(--accept-unverified-host $' \t\n') ;;
    reason-option) args+=(--accept-unverified-host --dry-run) ;;
    reason-duplicate) args+=(--accept-unverified-host first --accept-unverified-host second) ;;
  esac
  # Put the valueless option last so positionals cannot become its reason.
  tail_args=()
  [ "$TEST_CASE" != reason-missing ] || tail_args+=(--accept-unverified-host)
  # Force a real filesystem failure without relying on permissions/root behavior.
  [ "$TEST_CASE" != accept-evidence-failure-mismatch ] || touch release-sign-evidence
  rc=0
  bash "$WORK/release-sign.sh" ${args[@]+"${args[@]}"} "$TEST_TAG" "$COMMIT" ${tail_args[@]+"${tail_args[@]}"} > "$CASE_DIR/output" 2>&1 || rc=$?
  if [ "$TEST_CASE" = retry ]; then
    [ "$rc" -eq 0 ] || fail "initial signing failed: $rc"
    cmp "$WORK/expected-sums" "$CASE_DIR/upload/SHA256SUMS"
    # Stale uploaded output must be replaced, not downloaded into the new sums.
    printf 'stale manifest\n' > "$CASE_DIR/upload/SHA256SUMS"
    printf 'stale signature\n' > "$CASE_DIR/upload/SHA256SUMS.asc"
    bash "$WORK/release-sign.sh" "${args[@]}" "$TEST_TAG" "$COMMIT" >> "$CASE_DIR/output" 2>&1 || rc=$?
  fi
  [ ! -f "$CASE_DIR/unexpected" ] || { cat "$CASE_DIR/unexpected"; fail 'unexpected stub call'; }

  if [ "$TEST_CASE" = accept-evidence-failure-mismatch ]; then
    [ "$rc" -ne 0 ] || fail 'accepted mismatch despite failing to save evidence'
    retained=$(sed -n 's/^WARNING: evidence preservation incomplete; retaining rebuild workspace: //p' "$CASE_DIR/output")
    [ -d "$retained" ] || fail 'fallback workspace was deleted'
    cp "$WORK/fixtures/$TEST_HOST_ASSET" "$CASE_DIR/expected-rebuilt"
    echo different >> "$CASE_DIR/expected-rebuilt"
    cmp "$CASE_DIR/expected-rebuilt" "$retained/source/target/$TEST_HOST/release/konsensus"
    [ -s "$retained/ci-hash" ] && [ -s "$retained/local-hash" ] || fail 'fallback lost hashes'
    [ ! -e "$CASE_DIR/signed-sums" ] || fail 'signed after evidence failure'
    [ ! -e "$CASE_DIR/upload.args" ] || fail 'uploaded after evidence failure'
    ! grep -q -- '--list-secret-keys' "$CASE_DIR/gpg.log" || fail 'evidence failure accessed private keys'
    exit 0
  fi
  reason=''
  case "$TEST_CASE" in
    existing|fresh|subkey|stderr-noise|retry|retry-sums|retry-signature|dry-existing|accept-mismatch|dry-accept-mismatch|accept-darwin-mismatch|accept-match) ;;
    mismatch|dry-mismatch|compromised-ci) reason='reproducibility mismatch for x86_64-unknown-linux-gnu' ;;
    build-failure|accept-build-failure) reason='local rebuild failed' ;;
    no-waivers|missing-waiver|accept-missing-waiver) reason='unverified target' ;;
    waive-host) reason='host target cannot be waived' ;;
    unknown-waiver) reason='unknown target' ;;
    unsupported-host) reason='unsupported signing host' ;;
    dry-fresh) reason='dry-run requires an existing tag' ;;
    wrong-tag) reason="tag $TEST_TAG exists on a different commit" ;;
    ci-sha) reason="CI run 123 built $OTHER_COMMIT, not the tagged commit $COMMIT" ;;
    non-draft|published-late) reason="release $TEST_TAG is not a draft; refusing to change it" ;;
    checksum|accept-checksum) reason='bitsov-windows-x86_64: expected' ;;
    filename) reason='bitsov-windows-x86_64.sha256 names a different file' ;;
    expired-tag|notation|wrong-primary-tag|missing-primary-tag|truncated-tag|trailing-key-tag|stderr-only-tag) reason="existing tag $TEST_TAG is not validly signed" ;;
    expired-sums|wrong-primary-sums|missing-primary-sums|truncated-sums|trailing-key-sums|stderr-only-sums) reason='signature check failed' ;;
    reason-empty|reason-blank|reason-option|reason-missing) reason='--accept-unverified-host requires a nonblank reason' ;;
    reason-duplicate) reason='--accept-unverified-host may only be supplied once' ;;
    extra-asset|retry-extra|retry-lookalike) reason="release $TEST_TAG assets are not exactly the five binaries" ;;
    *) fail "unknown case $TEST_CASE" ;;
  esac
  # Inspect evidence AFTER the signer has exited and its EXIT trap has run.
  case "$TEST_CASE" in
    *mismatch|compromised-ci)
      evidence=$(sed -n 's/^REBUILD EVIDENCE: //p' "$CASE_DIR/output")
      [ -d "$evidence" ] || fail 'mismatch evidence was not retained'
      [ -f "$evidence/$TEST_HOST_ASSET.rebuilt" ] || fail 'rebuilt binary was deleted'
      cp "$WORK/fixtures/$TEST_HOST_ASSET" "$CASE_DIR/expected-rebuilt"
      [ "$TEST_CASE" = compromised-ci ] || echo different >> "$CASE_DIR/expected-rebuilt"
      cmp "$CASE_DIR/expected-rebuilt" "$evidence/$TEST_HOST_ASSET.rebuilt"
      local_hash=$(shasum -a 256 "$CASE_DIR/expected-rebuilt" | awk '{print $1}')
      cp "$WORK/fixtures/$TEST_HOST_ASSET" "$CASE_DIR/expected-ci"
      [ "$TEST_CASE" != compromised-ci ] || echo injected >> "$CASE_DIR/expected-ci"
      ci_hash=$(shasum -a 256 "$CASE_DIR/expected-ci" | awk '{print $1}')
      grep -qx "$ci_hash  $TEST_HOST_ASSET" "$evidence/SHA256SUMS" || fail 'retained CI hash is wrong'
      grep -F "$local_hash" "$evidence/host-hash.diff" >/dev/null || fail 'diff lost local hash'
      grep -F "$ci_hash" "$evidence/host-hash.diff" >/dev/null || fail 'diff lost CI hash'
      grep -q '^--- CI/' "$evidence/host-hash.diff" || fail 'missing retained CI diff'
      grep -q '^+++ local/' "$evidence/host-hash.diff" || fail 'missing retained local diff'
      for record in "target=$TEST_HOST" "tag=$TEST_TAG" "commit=$COMMIT" "ci_sha256=$ci_hash" "local_sha256=$local_hash"; do
        grep -F "$record" "$evidence/manifest.txt" >/dev/null || fail "missing evidence: $record"
        grep -F "$record" "$CASE_DIR/output" >/dev/null || fail "missing log: $record"
      done
      case "$TEST_CASE" in
        *accept-*)
          printf -v escaped_reason '%q' "$host_reason"
          grep -F "reason=$escaped_reason" "$evidence/manifest.txt" >/dev/null || fail 'reason missing from manifest'
          grep -F "reason=$escaped_reason" "$CASE_DIR/output" >/dev/null || fail 'reason missing from log'
          grep -q '^WARNING: BREAK-GLASS ACCEPT UNVERIFIED HOST ' "$CASE_DIR/output" || fail 'host waiver not prominent'
          ;;
        *)
          ! grep -q -- '--list-secret-keys' "$CASE_DIR/gpg.log" || fail 'rejected mismatch accessed private keys'
          ;;
      esac
      ! grep -q '^VERIFIED ' "$CASE_DIR/output" || fail 'mismatch falsely marked verified'
      ! grep -q 'verification passed' "$CASE_DIR/output" || fail 'mismatch falsely marked passed'
      build_dir=$(cat "$CASE_DIR/build.log")
      [ ! -d "$build_dir" ] || fail 'temporary worktree leaked after evidence saved'
      if [ "$TEST_CASE" = mismatch ]; then
        retry_rc=0
        bash "$WORK/release-sign.sh" "${args[@]}" "$TEST_TAG" "$COMMIT" > "$CASE_DIR/retry-output" 2>&1 || retry_rc=$?
        [ "$retry_rc" -ne 0 ] || fail 'retry unexpectedly accepted mismatch'
        retry_evidence=$(sed -n 's/^REBUILD EVIDENCE: //p' "$CASE_DIR/retry-output")
        [ -d "$retry_evidence" ] && [ "$retry_evidence" != "$evidence" ] || fail 'retry reused evidence directory'
        cmp "$CASE_DIR/expected-rebuilt" "$evidence/$TEST_HOST_ASSET.rebuilt"
        cmp "$CASE_DIR/expected-rebuilt" "$retry_evidence/$TEST_HOST_ASSET.rebuilt"
      fi
      ;;
  esac
  if [ -z "$reason" ]; then
    [ "$rc" -eq 0 ] || fail "expected success, got exit $rc"
    [ -s "$CASE_DIR/build.log" ] || fail 'host was not rebuilt'
    grep -q 'ACCEPT UNVERIFIED target=' "$CASE_DIR/output" || fail 'waivers not logged'
    if [[ "$TEST_CASE" == dry-* ]]; then
      [ ! -e "$CASE_DIR/signed-sums" ] || fail 'dry-run signed'
      [ ! -e "$CASE_DIR/upload.args" ] || fail 'dry-run uploaded'
      ! grep -q -- '--list-secret-keys' "$CASE_DIR/gpg.log" || fail 'dry-run accessed private keys'
      exit 0
    fi
    if [ "$TEST_CASE" = accept-match ]; then
      grep -q '^VERIFIED ' "$CASE_DIR/output" || fail 'matching rebuild not verified'
      ! grep -q '^WARNING: BREAK-GLASS' "$CASE_DIR/output" || fail 'unused waiver reported as applied'
    fi
    cmp "$WORK/expected-sums" "$CASE_DIR/upload/SHA256SUMS"
    cmp "$CASE_DIR/signed-sums" "$CASE_DIR/upload/SHA256SUMS"
    printf '%s\n' release upload "$TEST_TAG" SHA256SUMS SHA256SUMS.asc --repo "$TEST_REPO" --clobber > "$CASE_DIR/expected.args"
    cmp "$CASE_DIR/expected.args" "$CASE_DIR/upload.args"
    runs=1
    [ "$TEST_CASE" != retry ] || runs=2
    [ "$(grep -c '^release download ' "$CASE_DIR/gh.log")" -eq $((5 * runs)) ]
    [ "$(grep -c '^release upload ' "$CASE_DIR/gh.log")" -eq "$runs" ]
    [ "$(wc -l < "$CASE_DIR/upload/SHA256SUMS")" -eq 15 ]
    grep -qx "run watch 123 --repo $TEST_REPO --exit-status" "$CASE_DIR/gh.log"
    grep -qx -- '--status-fd 1 --verify SHA256SUMS.asc SHA256SUMS' "$CASE_DIR/gpg.log"
    grep -q '^Not published\.' "$CASE_DIR/output"
    [ -e "$CASE_DIR/verified-tag" ]
  else
    [ "$rc" -ne 0 ] || fail 'expected rejection, got success'
    grep -F "release-sign: $reason" "$CASE_DIR/output" >/dev/null || fail "missing rejection: $reason"
    [ ! -e "$CASE_DIR/upload.args" ] || fail 'uploaded after rejection'
    if [ "$reason" != 'signature check failed' ]; then
      [ ! -e "$CASE_DIR/signed-sums" ] || fail 'signed before validation finished'
    fi
  fi
  if [ "$TEST_CASE" = published-late ]; then
    [ -s "$CASE_DIR/build.log" ] || fail 'late publication rejected before rebuild'
    [ "$(cat "$CASE_DIR/draft-checks")" -eq 2 ] || fail 'missing second draft check'
  fi
  if [ "$TEST_CASE" = mismatch ] || [ "$TEST_CASE" = dry-mismatch ]; then
    grep -q '^--- CI/' "$CASE_DIR/output" || fail 'missing CI diff'
    grep -q '^+++ local/' "$CASE_DIR/output" || fail 'missing local diff'
  fi
  if [ "$TEST_CASE" = dry-fresh ]; then
    [ ! -e "$CASE_DIR/signed-tag" ] || fail 'dry-run signed a tag'
  elif [ "$TEST_CASE" = fresh ]; then
    [ -e "$CASE_DIR/signed-tag" ] || fail 'fresh tag was not signed'
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
  if [ "$candidate" = C ] || [ "$candidate" = POSIX ]; then continue; fi
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
  for test_case in existing fresh wrong-tag ci-sha non-draft checksum filename expired-tag \
    expired-sums mismatch compromised-ci unsupported-host build-failure no-waivers missing-waiver waive-host \
    unknown-waiver dry-existing dry-mismatch dry-fresh accept-mismatch dry-accept-mismatch accept-darwin-mismatch accept-evidence-failure-mismatch \
    accept-match accept-build-failure accept-checksum accept-missing-waiver reason-empty reason-blank reason-option reason-missing \
    reason-duplicate subkey published-late extra-asset notation wrong-primary-tag missing-primary-tag truncated-tag \
    trailing-key-tag wrong-primary-sums missing-primary-sums truncated-sums trailing-key-sums stderr-only-tag stderr-only-sums stderr-noise \
    retry retry-sums retry-signature retry-extra retry-lookalike; do
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
