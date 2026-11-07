#!/usr/bin/env bash
# verify-release.sh — check a downloaded release directory offline.
#
#   scripts/verify-release.sh <download-dir> <release-public-key.asc>
#   scripts/verify-release.sh --cleanup <seal-dir>
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
# toolchain records. Every directory entry must be exactly SHA256SUMS,
# SHA256SUMS.asc, or one of those seventeen names. The comparison is shell
# string equality. A directory entry is never a grep pattern: a newline inside
# a filename would split a grep pattern into a list and can admit another file.
# A shorter list, another name, a nested path, or a symlink is refused.
#
# On success the script leaves a mode-0700 seal directory and prints
# "verify-release: sealed <path>". SHA256SUMS, SHA256SUMS.asc, and all seventeen
# payloads are copied there as regular files first. Parsing, the signature
# check, and every hash read those copies.
# Copying SHA256SUMS does not seal the payloads; each payload is copied on its
# own. Install from the printed seal path, then run --cleanup. This script does
# not install.
#
# Mode 0700 stops a different uid from writing the seal.
# It does not stop the same uid. The verifying user, root, or another process
# running as that user can still change the seal after this script exits.
# GnuPG is invoked with --no-auto-key-retrieve inside a temporary GNUPGHOME
# under a work directory that is removed on exit. The seal is not that work
# directory, and it holds no keyring.
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

load_allowed_names() {
  local name
  ALLOWED=()
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    ALLOWED+=("$name")
  done < <(expected_release_names)
}

# Exact match against the seventeen payload names. Not a grep pattern.
allowed_name() {
  local candidate=$1 name
  [ -n "$candidate" ] || return 1
  for name in "${ALLOWED[@]}"; do
    [ "$candidate" = "$name" ] && return 0
  done
  return 1
}

sidecar_name() {
  [ "$1" = SHA256SUMS ] || [ "$1" = SHA256SUMS.asc ]
}

# True when $1 is already recorded in the sums snapshot. Shell equality only.
seen_name() {
  local candidate=$1 existing
  [ -f "$WORK/names" ] || return 1
  while IFS= read -r existing || [ -n "$existing" ]; do
    [ "$candidate" = "$existing" ] && return 0
  done < "$WORK/names"
  return 1
}

# Copy one path as a regular file. cp -P keeps a symlink as a symlink so the
# check below refuses it instead of reading the target. chmod runs only after
# that check. Used for the sums and for every payload.
snapshot_regular() {
  local src=$1 dest=$2 label=$3
  if [ -L "$src" ] || [ ! -f "$src" ]; then
    die "$label is not a regular file"
  fi
  cp -P -- "$src" "$dest"
  if [ -L "$dest" ] || [ ! -f "$dest" ]; then
    die "$label is not a regular file"
  fi
  chmod 600 -- "$dest"
}

# ls -nd is used because the mode and owner must be read without GNU stat.
# shellcheck disable=SC2012
seal_owner_uid() {
  LC_ALL=C ls -nd "$1" | awk '{ print $3; exit }'
}

# shellcheck disable=SC2012
seal_type_mode() {
  LC_ALL=C ls -ld "$1" | awk '{ print $1; exit }'
}

# Remove a seal this script published. Refuse a symlink, a directory that is
# not mode 0700 and owned by this user, a missing or mismatched marker, or any
# entry that is not a regular file with an allowed name. Delete those files
# by name, then rmdir. Never rm -rf an unvalidated path.
remove_seal() {
  local dir=$1 canonical magic marker_dir mode owner entry name
  [ -n "$dir" ] || die "usage: $0 --cleanup <seal-dir>"
  [ "$dir" != / ] || die "refusing to clean $dir"
  if [ ! -d "$dir" ] || [ -L "$dir" ]; then
    die "seal directory is not a directory: $dir"
  fi
  mode=$(seal_type_mode "$dir")
  owner=$(seal_owner_uid "$dir")
  [ "$owner" = "$(id -u)" ] || die "seal directory is not owned by this user"
  case "$mode" in
    drwx------|drwx------.|drwx------+) ;;
    *) die "seal directory is not mode 0700" ;;
  esac
  if [ ! -f "$dir/.verify-release-seal" ] || [ -L "$dir/.verify-release-seal" ]; then
    die "not a verify-release seal: $dir"
  fi
  canonical=$(cd -- "$dir" && pwd -P) || die "seal directory is not a directory: $dir"
  magic=""
  marker_dir=""
  {
    IFS= read -r magic || true
    IFS= read -r marker_dir || true
  } < "$dir/.verify-release-seal"
  [ "$magic" = verify-release-seal-v1 ] || die "not a verify-release seal: $dir"
  if [ -z "$marker_dir" ] || [ "$marker_dir" != "$canonical" ]; then
    die "seal marker does not match $dir"
  fi
  : > "$CLEAN_LIST"
  find "$dir" -mindepth 1 -print0 > "$CLEAN_LIST"
  while IFS= read -r -d '' entry; do
    name=${entry#"$dir"/}
    case "$name" in
      */*) die "seal directory contains an unexpected path: $name" ;;
    esac
    if [ -L "$entry" ] || [ ! -f "$entry" ]; then
      die "seal entry is not a regular file: $name"
    fi
    if [ "$name" = .verify-release-seal ] || sidecar_name "$name" || allowed_name "$name"; then
      continue
    fi
    die "seal directory contains an unexpected file: $name"
  done < "$CLEAN_LIST"
  while IFS= read -r -d '' entry; do
    rm -f -- "$entry"
  done < "$CLEAN_LIST"
  rmdir -- "$dir" || die "seal directory was not removed: $dir"
}

# The temporary home holds only the pinned key. Do not retrieve another one.
gpg_offline() {
  gpg --no-auto-key-retrieve "$@"
}

main() {
  local dir key line hash name rest got listed pub_count primary rel expected present canonical
  load_allowed_names
  [ "${#ALLOWED[@]}" -eq 17 ] || die "internal allow-list is not the seventeen release assets"
  if [ "${1:-}" = --cleanup ]; then
    [ $# -eq 2 ] || die "usage: $0 --cleanup <seal-dir>"
    CLEAN_LIST=$(mktemp)
    trap 'rm -f -- "$CLEAN_LIST"' EXIT
    remove_seal "$2"
    return 0
  fi
  [ $# -eq 2 ] || die "usage: $0 <download-dir> <release-public-key.asc>"
  dir=$1
  key=$2
  [ -d "$dir" ] || die "download directory not found: $dir"
  [ -f "$key" ] || die "release public key not found: $key"

  umask 077
  WORK=$(mktemp -d)
  SEAL=""
  SEAL_KEEP=0
  # Private temp even if the caller umask is loose. The keyring is discarded.
  # The seal is a different directory and is kept only after every payload hash
  # matches. Copying the manifest into it does not seal the payloads.
  chmod 700 "$WORK"
  export GNUPGHOME="$WORK/gnupg"
  mkdir -m 700 "$GNUPGHOME"
  cleanup() {
    if command -v gpgconf >/dev/null 2>&1; then
      gpgconf --kill gpg-agent >/dev/null 2>&1 || true
    fi
    if [ -n "${WORK:-}" ]; then
      rm -rf -- "$WORK"
    fi
    if [ "${SEAL_KEEP:-0}" != 1 ] && [ -n "${SEAL:-}" ]; then
      case "$SEAL" in
        */verify-release-seal.*) rm -rf -- "$SEAL" ;;
        *) echo "verify-release: refusing to remove unexpected seal path" >&2 ;;
      esac
    fi
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

  SEAL=$(mktemp -d "${TMPDIR:-/tmp}/verify-release-seal.XXXXXX")
  chmod 700 "$SEAL"
  cd -- "$dir" || die "download directory not found: $dir"
  # Freeze the sums before they are parsed. Each payload is copied into this
  # same directory after the membership walk. Hashes read those copies.
  # Copying SHA256SUMS does not seal the payloads. The download paths are not hashed.
  snapshot_regular SHA256SUMS "$SEAL/SHA256SUMS" SHA256SUMS
  snapshot_regular SHA256SUMS.asc "$SEAL/SHA256SUMS.asc" SHA256SUMS.asc
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
    seen_name "$name" && die "SHA256SUMS lists $name more than once"
    printf '%s\n' "$name" >> "$WORK/names"
    printf '%s %s\n' "$hash" "$name" >> "$WORK/expected"
  done < "$SEAL/SHA256SUMS"
  [ -s "$WORK/names" ] || die "SHA256SUMS is empty"
  expected=$(expected_release_names | LC_ALL=C sort)
  present=$(LC_ALL=C sort "$WORK/names")
  [ "$present" = "$expected" ] || die "SHA256SUMS is not exactly the five binaries, their .sha256 files, their SBOMs, and Darwin toolchain evidence"

  find . -mindepth 1 -print0 > "$WORK/entries"
  while IFS= read -r -d '' rel; do
    rel=${rel#./}
    if sidecar_name "$rel"; then
      continue
    fi
    case "$rel" in
      */*) die "unexpected path in download directory: $rel" ;;
    esac
    # -d follows a symlink to a directory. Those are unexpected either way.
    if [ -d "$rel" ]; then
      die "unexpected path in download directory: $rel"
    fi
    if allowed_name "$rel"; then
      continue
    fi
    if [ -L "$rel" ]; then
      die "unexpected path in download directory: $rel"
    fi
    die "unexpected file in download directory: $rel"
  done < "$WORK/entries"

  while IFS= read -r name; do
    snapshot_regular "$name" "$SEAL/$name" "$name"
  done < <(expected_release_names)

  gpg_offline --status-fd 1 --verify "$SEAL/SHA256SUMS.asc" "$SEAL/SHA256SUMS" 2>"$WORK/gpg.err" | signed_by_key \
    || die "signature is not a valid signature by release key $KEY_FPR"

  while read -r hash name; do
    if [ -L "$SEAL/$name" ] || [ ! -f "$SEAL/$name" ]; then
      die "$name is not a regular file"
    fi
    got=$(shasum -a 256 -- "$SEAL/$name" | awk '{print $1; exit}')
    [ "$got" = "$hash" ] || die "$name: hash mismatch"
  done < "$WORK/expected"

  canonical=$(cd -- "$SEAL" && pwd -P)
  printf 'verify-release-seal-v1\n%s\n' "$canonical" > "$SEAL/.verify-release-seal"
  chmod 600 -- "$SEAL/.verify-release-seal"
  chmod 700 -- "$SEAL"
  SEAL_KEEP=1
  listed=$(wc -l < "$WORK/names" | tr -d ' ')
  echo "verify-release: $listed sealed files match a signature by $KEY_FPR"
  echo "verify-release: sealed $canonical"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
