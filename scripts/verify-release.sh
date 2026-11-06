#!/usr/bin/env bash
# verify-release.sh — check a downloaded release directory offline.
#
#   scripts/verify-release.sh <download-dir> <release-public-key.asc>
#
# The key file must be the reviewed RELEASE_KEY.asc (or a byte-for-byte copy).
# The script checks that file's primary fingerprint itself. It does not fetch
# the key, the tag, or the binaries, and it does not import into the caller's
# GnuPG home.
#
# A signature counts only when gpg reports a [GNUPG:] VALIDSIG line whose
# field 10 (primary-key fingerprint) is the release key. A GOODSIG user id
# that contains the fingerprint text is not that field. This is the same
# predicate as scripts/release-sign.sh; keep the two copies identical.
#
# SHA256SUMS must name exactly the seventeen assets release-sign.sh publishes:
# the five CLI binaries, their .sha256 files, their SBOMs, and the two Darwin
# toolchain records. Every named file must be a regular non-symlink and match
# its hash. A shorter list, or any other file in the directory, is refused.
# GnuPG is invoked with --no-auto-key-retrieve inside a temporary GNUPGHOME.
set -euo pipefail

KEY_FPR=B299274C200301714DC6F51A7C2D6F8AC842EF6E
ASSETS=(bitsov-darwin-aarch64 bitsov-darwin-x86_64 bitsov-linux-aarch64 bitsov-linux-x86_64 bitsov-windows-x86_64)

die() { echo "verify-release: $*" >&2; exit 1; }

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

# Same seventeen names as require_release_assets in scripts/release-sign.sh.
expected_release_names() {
  local asset
  for asset in "${ASSETS[@]}"; do
    printf '%s\n' "$asset" "$asset.sha256" "$asset.sbom.spdx.json"
    case "$asset" in
      bitsov-darwin-*) printf '%s\n' "$asset.toolchain.txt" ;;
    esac
  done
}

allowed_name() {
  expected_release_names | grep -Fxq -- "$1"
}

# The temporary home holds only the pinned key. Do not retrieve another one.
gpg_offline() {
  gpg --no-auto-key-retrieve "$@"
}

main() {
  local dir key line hash name rest got listed pub_count primary rel expected present
  [ $# -eq 2 ] || die "usage: $0 <download-dir> <release-public-key.asc>"
  dir=$1
  key=$2
  [ -d "$dir" ] || die "download directory not found: $dir"
  [ -f "$key" ] || die "release public key not found: $key"

  umask 077
  WORK=$(mktemp -d)
  # Private temp even if the caller umask is loose. The keyring is discarded.
  chmod 700 "$WORK"
  export GNUPGHOME="$WORK/gnupg"
  mkdir -m 700 "$GNUPGHOME"
  cleanup() {
    if command -v gpgconf >/dev/null 2>&1; then
      gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
  }
  trap cleanup EXIT

  # Count primary keys and read the first primary fingerprint from gpg, not
  # from text in the file. A second key in the armor is refused. --show-keys
  # does not import.
  if ! gpg_offline --batch --with-colons --show-keys "$key" >"$WORK/key.colon" 2>"$WORK/show-keys.err"; then
    cat "$WORK/show-keys.err" >&2
    die "release public key could not be read"
  fi
  pub_count=$(grep -c '^pub:' "$WORK/key.colon" || true)
  [ "$pub_count" -eq 1 ] || die "release public key file must contain exactly one primary key"
  primary=$(awk -F: '$1 == "pub" { seen = 1; next } seen && $1 == "fpr" { print $10; exit }' "$WORK/key.colon")
  [ "$primary" = "$KEY_FPR" ] || die "release public key fingerprint is $primary, not $KEY_FPR"
  gpg_offline --batch --import "$key" >/dev/null 2>&1

  cd "$dir"
  if [ ! -f SHA256SUMS ] || [ -L SHA256SUMS ]; then
    die "SHA256SUMS is not a regular file"
  fi
  if [ ! -f SHA256SUMS.asc ] || [ -L SHA256SUMS.asc ]; then
    die "SHA256SUMS.asc is not a regular file"
  fi
  : > "$WORK/names"
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || die "SHA256SUMS contains a blank line"
    [[ $line != \\* ]] || die "SHA256SUMS contains an escaped filename"
    hash=${line%% *}
    rest=${line#* }
    [[ $hash =~ ^[0-9a-f]{64}$ ]] || die "SHA256SUMS has a malformed hash"
    case "$rest" in
      ' '*) name=${rest# } ;;
      '*'*) name=${rest#\*} ;;
      *) die "SHA256SUMS line is not hash, two spaces, filename" ;;
    esac
    case "$name" in
      *[!A-Za-z0-9._-]*|.*|'') die "SHA256SUMS names a file the release does not publish: $name" ;;
    esac
    allowed_name "$name" || die "SHA256SUMS names a file the release does not publish: $name"
    grep -Fxq "$name" "$WORK/names" && die "SHA256SUMS lists $name more than once"
    printf '%s\n' "$name" >> "$WORK/names"
    printf '%s %s\n' "$hash" "$name" >> "$WORK/expected"
  done < SHA256SUMS
  [ -s "$WORK/names" ] || die "SHA256SUMS is empty"
  expected=$(expected_release_names | LC_ALL=C sort)
  present=$(LC_ALL=C sort "$WORK/names")
  [ "$present" = "$expected" ] || die "SHA256SUMS is not exactly the five binaries, their .sha256 files, their SBOMs, and Darwin toolchain evidence"

  find . -mindepth 1 -print0 > "$WORK/entries"
  while IFS= read -r -d '' rel; do
    rel=${rel#./}
    case "$rel" in
      SHA256SUMS|SHA256SUMS.asc) ;;
      */*) die "unexpected path in download directory: $rel" ;;
      *)
        if [ -d "$rel" ]; then
          die "unexpected path in download directory: $rel"
        fi
        if [ -L "$rel" ]; then
          grep -Fxq "$rel" "$WORK/names" || die "unexpected path in download directory: $rel"
        else
          grep -Fxq "$rel" "$WORK/names" || die "unexpected file in download directory: $rel"
        fi
        ;;
    esac
  done < "$WORK/entries"

  gpg_offline --status-fd 1 --verify SHA256SUMS.asc SHA256SUMS 2>"$WORK/gpg.err" | signed_by_key \
    || die "signature is not a valid signature by release key $KEY_FPR"

  while read -r hash name; do
    if [ -L "$name" ] || [ ! -f "$name" ]; then
      die "$name is not a regular file"
    fi
    got=$(shasum -a 256 -- "$name" | awk '{print $1; exit}')
    [ "$got" = "$hash" ] || die "$name: hash mismatch"
  done < "$WORK/expected"

  listed=$(wc -l < "$WORK/names" | tr -d ' ')
  echo "verify-release: $listed files match a signature by $KEY_FPR"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
