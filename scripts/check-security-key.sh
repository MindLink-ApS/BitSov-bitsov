#!/usr/bin/env bash
# check-security-key.sh — guard that SECURITY_KEY.asc and SECURITY.md agree.
#
# Why: the 2026-09-10 disclosure-key rotation (PR #63) needed a second commit
# because the hand-edited SECURITY.md kept the OLD key's `Expires:` line.
# Nothing verified that the policy text matched the published key. This does.
#
# Checks (each printed as it runs):
#   a. SECURITY_KEY.asc holds exactly one PUBLIC KEY BLOCK and no PRIVATE KEY BLOCK
#   b. primary fingerprint == the `gpg --fingerprint <40hex>` line in SECURITY.md,
#      and its spaced form (as `gpg --fingerprint` prints it) is on exactly the
#      two `Fingerprint:` lines (contact block + "PGP Key" section)
#   c. the encryption subkey's spaced fingerprint is on the single
#      `Encryption:      subkey …` line
#   d. primary expiry (UTC, %Y-%m-%d) == the `Expires:` line; the primary and
#      the encryption subkey are not expired and not within 90 days of expiry
#   e. the primary key is neither revoked nor expired
#
# Exit 0 prints  "SECURITY-KEY: OK <fpr> expires <date>";
# any failure prints "SECURITY-KEY: FAIL <reason>" and exits non-zero.
#
# Dependencies: bash 3.2+, awk, grep, date, gpg (>= 2.1.23 for --show-keys).
# gpg is preinstalled on GitHub ubuntu runners; macOS: MacGPG or `brew install gnupg`.
# The key is parsed in a throwaway GNUPGHOME — the user's keyring is never touched.
#
# Usage: scripts/check-security-key.sh [repo-root]   (default: parent of scripts/)
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
KEY_FILE="$ROOT/SECURITY_KEY.asc"
POLICY="$ROOT/SECURITY.md"
WARN_DAYS=90

fail() { echo "SECURITY-KEY: FAIL $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

# 40-hex -> "XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX" (double space
# after the 5th group, exactly like `gpg --fingerprint`). Pure bash on purpose:
# a sed backreference beyond \9 produced a wrong fingerprint during PR #63.
spaced() {
  local f="$1" out="" i
  for i in 0 4 8 12 16 20 24 28 32 36; do
    out="${out}${f:$i:4}"
    case "$i" in
      16) out="${out}  " ;;
      36) ;;
      *)  out="${out} " ;;
    esac
  done
  printf '%s' "$out"
}

# epoch -> YYYY-MM-DD in UTC. GNU date first, BSD/macOS date as fallback.
utc_date() {
  date -u -d "@$1" +%Y-%m-%d 2>/dev/null || date -u -r "$1" +%Y-%m-%d
}

[ -f "$KEY_FILE" ] || fail "missing $KEY_FILE"
[ -f "$POLICY" ]   || fail "missing $POLICY"

GPG="$(command -v gpg || command -v gpg2 || true)"
[ -n "$GPG" ] || fail "gpg not found on PATH"

echo "check-security-key: $KEY_FILE <-> $POLICY (gpg: $GPG)"

# --- a. armor sanity ---------------------------------------------------------
pub_blocks="$(grep -c -- '-----BEGIN PGP PUBLIC KEY BLOCK-----' "$KEY_FILE" || true)"
priv_blocks="$(grep -c -- 'PRIVATE KEY BLOCK' "$KEY_FILE" || true)"
[ "$pub_blocks" -eq 1 ] || fail "expected exactly 1 PUBLIC KEY BLOCK in SECURITY_KEY.asc, found $pub_blocks"
[ "$priv_blocks" -eq 0 ] || fail "SECURITY_KEY.asc contains a PRIVATE KEY BLOCK marker ($priv_blocks)"
ok "(a) SECURITY_KEY.asc: 1 public key block, 0 private key blocks"

# --- parse the key (isolated keyring) ---------------------------------------
GNUPGHOME_TMP="$(mktemp -d)"
trap 'rm -rf "$GNUPGHOME_TMP"' EXIT
COLONS="$(GNUPGHOME="$GNUPGHOME_TMP" "$GPG" --batch --no-tty --with-colons --show-keys "$KEY_FILE" 2>/dev/null)" \
  || fail "gpg could not parse SECURITY_KEY.asc"

NOW="$(date -u +%s)"

# --with-colons fields: 1 type, 2 validity, 7 expiry epoch, 10 fingerprint, 12 capabilities.
# An `fpr` record belongs to the `pub`/`sub` record immediately before it.
# Output: npub|pub_validity|pub_expiry|pub_fpr|n_enc_subs|enc_fpr|enc_validity|enc_expiry
parsed="$(printf '%s\n' "$COLONS" | awk -F: -v now="$NOW" '
  $1 == "pub" { npub++; pv = $2; pe = $7; last = "pub"; next }
  $1 == "sub" {
    sv = $2; se = $7
    # usable encryption subkey: has "e" capability, not revoked/expired by
    # validity flag, and expiry (if any) still in the future
    if ($12 ~ /e/ && sv != "r" && sv != "e" && (se == "" || se + 0 > now)) last = "esub"
    else last = "sub"
    next
  }
  $1 == "fpr" && last == "pub"  { pf = $10; last = ""; next }
  $1 == "fpr" && last == "esub" { nenc++; ef = $10; ev = sv; ee = se; last = ""; next }
  { last = "" }
  END { printf "%d|%s|%s|%s|%d|%s|%s|%s\n", npub, pv, pe, pf, nenc, ef, ev, ee }
')"
IFS='|' read -r npub pub_valid pub_exp pub_fpr nenc enc_fpr enc_valid enc_exp <<< "$parsed"

[ "$npub" -eq 1 ] || fail "expected exactly 1 primary key in SECURITY_KEY.asc, found $npub"
printf '%s' "$pub_fpr" | grep -Eq '^[0-9A-F]{40}$' || fail "could not read a 40-hex primary fingerprint (got '$pub_fpr')"

# --- e. primary validity -----------------------------------------------------
case "$pub_valid" in
  r) fail "primary key $pub_fpr is REVOKED" ;;
  e) fail "primary key $pub_fpr is EXPIRED" ;;
esac
ok "(e) primary key not revoked, not expired (validity '$pub_valid')"

# --- b. primary fingerprint <-> SECURITY.md -----------------------------------
pub_spaced="$(spaced "$pub_fpr")"

n_cli="$(grep -Ec 'gpg --fingerprint [0-9A-Fa-f]{40}([^0-9A-Fa-f]|$)' "$POLICY" || true)"
[ "$n_cli" -eq 1 ] || fail "expected exactly 1 'gpg --fingerprint <40hex>' line in SECURITY.md, found $n_cli"
cli_fpr="$(grep -E 'gpg --fingerprint [0-9A-Fa-f]{40}([^0-9A-Fa-f]|$)' "$POLICY" \
  | awk '{ for (i = 1; i < NF; i++) if ($i == "--fingerprint") print toupper($(i + 1)) }')"
[ "$cli_fpr" = "$pub_fpr" ] || fail "SECURITY.md 'gpg --fingerprint' says $cli_fpr but key is $pub_fpr"
ok "(b) 'gpg --fingerprint' line matches primary $pub_fpr"

n_fpr_lines="$(grep -Ec '^Fingerprint:' "$POLICY" || true)"
n_fpr_match="$(grep -Ec "^Fingerprint:[[:space:]]+${pub_spaced}[[:space:]]*$" "$POLICY" || true)"
[ "$n_fpr_lines" -eq 2 ] || fail "expected exactly 2 'Fingerprint:' lines in SECURITY.md, found $n_fpr_lines"
[ "$n_fpr_match" -eq 2 ] || fail "expected both 'Fingerprint:' lines to read '$pub_spaced', only $n_fpr_match match"
ok "(b) both 'Fingerprint:' lines read '$pub_spaced'"

# --- c. encryption subkey <-> SECURITY.md -------------------------------------
[ "$nenc" -eq 1 ] || fail "expected exactly 1 usable encryption subkey in SECURITY_KEY.asc, found $nenc"
printf '%s' "$enc_fpr" | grep -Eq '^[0-9A-F]{40}$' || fail "could not read a 40-hex encryption subkey fingerprint (got '$enc_fpr')"
enc_spaced="$(spaced "$enc_fpr")"

n_enc_lines="$(grep -Ec '^Encryption:' "$POLICY" || true)"
n_enc_match="$(grep -Ec "^Encryption:[[:space:]]+subkey[[:space:]]+${enc_spaced}[[:space:]]*$" "$POLICY" || true)"
[ "$n_enc_lines" -eq 1 ] || fail "expected exactly 1 'Encryption:' line in SECURITY.md, found $n_enc_lines"
[ "$n_enc_match" -eq 1 ] || fail "'Encryption:' line does not read 'subkey $enc_spaced'"
ok "(c) 'Encryption:' line reads 'subkey $enc_spaced'"

# --- d. expiry <-> SECURITY.md, and not (nearly) expired ----------------------
[ -n "$pub_exp" ] || fail "primary key $pub_fpr has no expiry date (a disclosure key must expire)"
key_expires="$(utc_date "$pub_exp")"

n_exp_lines="$(grep -Ec '^Expires:' "$POLICY" || true)"
[ "$n_exp_lines" -eq 1 ] || fail "expected exactly 1 'Expires:' line in SECURITY.md, found $n_exp_lines"
doc_expires="$(grep -E '^Expires:' "$POLICY" | awk '{ print $2 }')"
[ "$doc_expires" = "$key_expires" ] || fail "SECURITY.md 'Expires:' says $doc_expires but primary key expires $key_expires"
ok "(d) 'Expires:' line matches primary key expiry $key_expires"

days_left=$(( (pub_exp - NOW) / 86400 ))
[ "$pub_exp" -gt "$NOW" ] || fail "primary key expired on $key_expires"
[ "$days_left" -ge "$WARN_DAYS" ] || fail "primary key expires on $key_expires — only $days_left days left (< $WARN_DAYS); rotate or extend now"

if [ -n "$enc_exp" ]; then
  enc_days_left=$(( (enc_exp - NOW) / 86400 ))
  [ "$enc_days_left" -ge "$WARN_DAYS" ] \
    || fail "encryption subkey expires on $(utc_date "$enc_exp") — only $enc_days_left days left (< $WARN_DAYS)"
fi
ok "(d) primary ($days_left days) and encryption subkey not within $WARN_DAYS days of expiry"

echo "SECURITY-KEY: OK $pub_fpr expires $key_expires"
