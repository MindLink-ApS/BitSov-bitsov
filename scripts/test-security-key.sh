#!/usr/bin/env bash
# test-security-key.sh — regression tests for scripts/check-security-key.sh
#
# Generates throwaway OpenPGP keys in short-lived GNUPGHOMEs (the user's
# ~/.gnupg is never touched, no network) and drives the guard through its
# accept path and every rejection path using fixture SECURITY_KEY.asc /
# SECURITY.md files built from the generated values. Every case asserts the
# exit code AND the "SECURITY-KEY: OK" / "SECURITY-KEY: FAIL <reason>" text.
#
# Cases:
#   positive     well-formed ed25519 cert,sign primary + cv25519 encr subkey
#   policy       Expires: mismatch; hex flipped on a spaced Fingerprint: line;
#                hex flipped on the `gpg --fingerprint` line; Encryption: subkey
#                mismatch; a Fingerprint: line missing
#   armor        PRIVATE KEY BLOCK marker; two PUBLIC KEY BLOCKs; missing file
#   expiry       primary 89d -> FAIL, 91d -> PASS (the 90-day boundary);
#                encryption subkey 89d under a 2y primary -> FAIL;
#                primary already expired (generated with --faked-system-time)
#   validity     primary revoked (auto-generated revocation cert imported)
#   subkeys      no encryption subkey; expired encryption subkey under a valid
#                primary; sign+auth+encr subkeys -> the encr one is selected;
#                two usable encryption subkeys
#
# Dependencies: bash 3.2+, gpg >= 2.1.23, gpgconf, awk, sed, grep, date — the
# same toolchain the guard needs. Runs on macOS (MacGPG/brew) and ubuntu.
#
# Usage: scripts/test-security-key.sh      (exit 0 iff every case passes)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD="$HERE/check-security-key.sh"

GPG="$(command -v gpg || command -v gpg2 || true)"
[ -n "$GPG" ]   || { echo "SECURITY-KEY-TESTS: gpg not found on PATH" >&2; exit 2; }
[ -f "$GUARD" ] || { echo "SECURITY-KEY-TESTS: missing $GUARD" >&2; exit 2; }

export LC_ALL=C   # untranslated gpg output

# /tmp on purpose, not $TMPDIR: gpg-agent's unix socket lives under the
# homedir and its path is limited to ~100 bytes.
WORK="$(mktemp -d /tmp/skt.XXXX)"
chmod 700 "$WORK"
GPG_LOG="$WORK/gpg.log"
DONE=0
cleanup() {
  local rc=$? h
  if [ "$DONE" -eq 0 ]; then
    echo "SECURITY-KEY-TESTS: aborted before the summary (exit $rc); gpg log follows" >&2
    [ -f "$GPG_LOG" ] && cat "$GPG_LOG" >&2 || true
  fi
  for h in "$WORK"/h*; do
    [ -d "$h" ] && gpgconf --homedir "$h" --kill all >/dev/null 2>&1 || true
  done
  rm -rf "$WORK"
}
trap cleanup EXIT

PASSED=0
FAILED=0
OUT=""
RC=0
PUB_FPR=""
PUB_EXP=""
ENC_FPR=""
KEY=""
POLICY=""

# --- gpg helpers -------------------------------------------------------------

gpg_in() {  # gpg_in <homedir> [gpg args...]   (batch, no passphrase, stderr -> log)
  local h="$1"; shift
  "$GPG" --homedir "$h" --batch --yes --no-tty --pinentry-mode loopback --passphrase '' "$@" 2>>"$GPG_LOG"
}

new_home() {  # -> path of a fresh, empty GNUPGHOME (mktemp: safe inside $(...) subshells)
  local h
  h="$(mktemp -d "$WORK/hXXXX")"
  chmod 700 "$h"
  printf '%s' "$h"
}

gen_primary() {  # gen_primary <home> <expiry> [faked-system-time] -> primary fpr
  local h="$1" exp="$2" ft=""
  [ -n "${3:-}" ] && ft="--faked-system-time $3"
  # shellcheck disable=SC2086
  gpg_in "$h" $ft --quick-gen-key 'BitSov guard test <security-test@example.invalid>' ed25519 cert,sign "$exp"
  gpg_in "$h" --with-colons --list-keys | awk -F: '$1 == "fpr" { print $10; exit }'
}

add_subkey() {  # add_subkey <home> <primary-fpr> <algo> <usage> <expiry> [faked-system-time]
  local ft=""
  [ -n "${6:-}" ] && ft="--faked-system-time $6"
  # shellcheck disable=SC2086
  gpg_in "$1" $ft --quick-add-key "$2" "$3" "$4" "$5"
}

revoke_primary() {  # revoke_primary <home> <primary-fpr>
  # --quick-gen-key writes a ready-made revocation certificate with a ':'
  # in front of the armor header so it cannot be imported by accident.
  sed 's/^:-----BEGIN/-----BEGIN/' "$1/openpgp-revocs.d/$2.rev" > "$1/revoke.asc"
  gpg_in "$1" --import "$1/revoke.asc"
}

key_info() {  # key_info <home> -> sets PUB_FPR, PUB_EXP (epoch), ENC_FPR (first e-capable subkey, may be empty)
  local parsed
  parsed="$(gpg_in "$1" --with-colons --list-keys | awk -F: '
    $1 == "pub" { pe = $7; last = "pub"; next }
    $1 == "sub" { last = ($12 ~ /e/ && ef == "") ? "esub" : "sub"; next }
    $1 == "fpr" && last == "pub"  { pf = $10; last = ""; next }
    $1 == "fpr" && last == "esub" { ef = $10; last = ""; next }
    { last = "" }
    END { printf "%s|%s|%s\n", pf, pe, ef }')"
  IFS='|' read -r PUB_FPR PUB_EXP ENC_FPR <<< "$parsed"
}

# --- fixture helpers ---------------------------------------------------------

spaced() {  # 40-hex -> "XXXX XXXX XXXX XXXX XXXX  XXXX XXXX XXXX XXXX XXXX" (as gpg prints it)
  local f="$1"
  printf '%s %s %s %s %s  %s %s %s %s %s' \
    "${f:0:4}" "${f:4:4}" "${f:8:4}" "${f:12:4}" "${f:16:4}" \
    "${f:20:4}" "${f:24:4}" "${f:28:4}" "${f:32:4}" "${f:36:4}"
}

flip_hex() {  # flip_hex <string> -> same string with its first character changed to another hex digit
  local n="0"
  [ "${1:0:1}" = "0" ] && n="1"
  printf '%s%s' "$n" "${1:1}"
}

utc_date() {  # epoch -> YYYY-MM-DD (UTC); GNU date, then BSD/macOS date
  date -u -d "@$1" +%Y-%m-%d 2>/dev/null || date -u -r "$1" +%Y-%m-%d
}

write_policy() {  # write_policy <out> <primary-fpr> <enc-fpr> <expires YYYY-MM-DD>
  # Mirrors every line of the real SECURITY.md the guard reads: the contact
  # block (Fingerprint / Encryption / Expires), the `gpg --fingerprint <40hex>`
  # line, the second `Fingerprint:` line in the "PGP Key" section — plus the
  # release-key decoy that must NOT be counted.
  local ps es
  ps="$(spaced "$2")"
  es="$(spaced "$3")"
  cat > "$1" <<EOF
# Security Policy (generated test fixture)

## Reporting a Vulnerability

Report privately to: **security-test@example.invalid**

\`\`\`
Contact:         security-test@example.invalid
Fingerprint:     $ps
Encryption:      subkey $es
Expires:         $4
\`\`\`

This key encrypts inbound reports only. Release artifacts are signed with a
**separate** release key (fingerprint
\`0123 4567 89AB CDEF 0123  4567 89AB CDEF 0123 4567\`).

Import and verify by **fingerprint** before encrypting:

\`\`\`bash
gpg --import SECURITY_KEY.asc
gpg --fingerprint $2
# Confirm the printed fingerprint matches the one above before encrypting.
\`\`\`

## PGP Key

\`\`\`
-----BEGIN PGP PUBLIC KEY BLOCK-----
(see SECURITY_KEY.asc)
-----END PGP PUBLIC KEY BLOCK-----

Fingerprint: $ps
\`\`\`
EOF
}

fixture() {  # fixture <home> -> sets KEY + POLICY (fresh fixture pair) and PUB_FPR/PUB_EXP/ENC_FPR
  local d
  d="$(mktemp -d "$WORK/cXXXX")"
  key_info "$1"
  gpg_in "$1" --armor --export > "$d/SECURITY_KEY.asc"
  write_policy "$d/SECURITY.md" "$PUB_FPR" \
    "${ENC_FPR:-0000000000000000000000000000000000000000}" "$(utc_date "$PUB_EXP")"
  KEY="$d/SECURITY_KEY.asc"
  POLICY="$d/SECURITY.md"
}

variant() {  # variant <src-file> <sed-script> -> path of a mutated copy
  local out
  out="$(mktemp "$WORK/vXXXX")"
  sed -e "$2" "$1" > "$out"
  printf '%s' "$out"
}

# --- assertions --------------------------------------------------------------

run_guard() {  # run_guard <key-file> <policy-file> -> sets OUT, RC
  if OUT="$(SECURITY_KEY_FILE="$1" SECURITY_MD_FILE="$2" bash "$GUARD" 2>&1)"; then
    RC=0
  else
    RC=$?
  fi
}

expect_pass() {  # expect_pass <name> <key-file> <policy-file>
  run_guard "$2" "$3"
  if [ "$RC" -eq 0 ] && printf '%s\n' "$OUT" | grep -q '^SECURITY-KEY: OK '; then
    PASSED=$((PASSED + 1))
    echo "  PASS  $1"
    echo "        $(printf '%s\n' "$OUT" | grep '^SECURITY-KEY: OK ')"
  else
    FAILED=$((FAILED + 1))
    echo "  FAIL  $1 — expected exit 0 + 'SECURITY-KEY: OK', got exit $RC:"
    printf '%s\n' "$OUT" | sed 's/^/        | /'
  fi
}

expect_fail() {  # expect_fail <name> <key-file> <policy-file> <reason-substring>
  run_guard "$2" "$3"
  if [ "$RC" -ne 0 ] \
     && printf '%s\n' "$OUT" | grep -F -- 'SECURITY-KEY: FAIL ' | grep -qF -- "$4"; then
    PASSED=$((PASSED + 1))
    echo "  PASS  $1"
    echo "        $(printf '%s\n' "$OUT" | grep -F -- 'SECURITY-KEY: FAIL ')"
  else
    FAILED=$((FAILED + 1))
    echo "  FAIL  $1 — expected non-zero exit + 'SECURITY-KEY: FAIL …$4…', got exit $RC:"
    printf '%s\n' "$OUT" | sed 's/^/        | /'
  fi
}

# =============================================================================
echo "test-security-key: guard=$GUARD"
echo "test-security-key: gpg=$GPG ($("$GPG" --version | head -1))"

# --- reference key: ed25519 cert,sign primary (2y) + cv25519 encr subkey (2y)
H="$(new_home)"
F="$(gen_primary "$H" 2y)"
add_subkey "$H" "$F" cv25519 encr 2y
fixture "$H"
KEY_OK="$KEY"; POLICY_OK="$POLICY"
PS="$(spaced "$PUB_FPR")"; ES="$(spaced "$ENC_FPR")"

# self-check of the fixture builder: spaced() must equal what `gpg --fingerprint` prints
gpg_in "$H" --fingerprint | grep -qF -- "$PS" \
  || { echo "SECURITY-KEY-TESTS: test bug — spaced() does not match gpg --fingerprint output" >&2; exit 2; }

echo "-- positive"
expect_pass "well-formed key with matching policy" "$KEY_OK" "$POLICY_OK"

echo "-- policy text"
expect_fail "Expires: line disagrees with the key" \
  "$KEY_OK" "$(variant "$POLICY_OK" 's/^Expires:.*/Expires:         2019-01-01/')" \
  "'Expires:' says 2019-01-01 but primary key expires"

expect_fail "one hex char flipped on a spaced Fingerprint: line" \
  "$KEY_OK" "$(variant "$POLICY_OK" "s/^Fingerprint:     $PS/Fingerprint:     $(flip_hex "$PS")/")" \
  "expected both 'Fingerprint:' lines to read '$PS', only 1 match"

expect_fail "one hex char flipped on the 'gpg --fingerprint' line" \
  "$KEY_OK" "$(variant "$POLICY_OK" "s/^gpg --fingerprint $PUB_FPR/gpg --fingerprint $(flip_hex "$PUB_FPR")/")" \
  "'gpg --fingerprint' says $(flip_hex "$PUB_FPR") but key is $PUB_FPR"

expect_fail "Encryption: subkey fingerprint mismatch" \
  "$KEY_OK" "$(variant "$POLICY_OK" "s/^Encryption:      subkey $ES/Encryption:      subkey $(flip_hex "$ES")/")" \
  "'Encryption:' line does not read 'subkey $ES'"

expect_fail "second Fingerprint: line missing" \
  "$KEY_OK" "$(variant "$POLICY_OK" '/^Fingerprint: [0-9A-F]/d')" \
  "expected exactly 2 'Fingerprint:' lines in SECURITY.md, found 1"

echo "-- armor"
KEY_PRIV="$(mktemp "$WORK/vXXXX")"
{ cat "$KEY_OK"; echo '-----BEGIN PGP PRIVATE KEY BLOCK-----'; } > "$KEY_PRIV"
expect_fail "PRIVATE KEY BLOCK marker present" "$KEY_PRIV" "$POLICY_OK" \
  "SECURITY_KEY.asc contains a PRIVATE KEY BLOCK marker (1)"

KEY_TWO="$(mktemp "$WORK/vXXXX")"
cat "$KEY_OK" "$KEY_OK" > "$KEY_TWO"
expect_fail "two PUBLIC KEY BLOCKs in one file" "$KEY_TWO" "$POLICY_OK" \
  "expected exactly 1 PUBLIC KEY BLOCK in SECURITY_KEY.asc, found 2"

expect_fail "key file missing" "$WORK/does-not-exist.asc" "$POLICY_OK" "missing"

echo "-- expiry (90-day boundary)"
H="$(new_home)"; F="$(gen_primary "$H" 89d)"; add_subkey "$H" "$F" cv25519 encr 89d; fixture "$H"
expect_fail "primary expires in 89 days" "$KEY" "$POLICY" "days left (< 90); rotate or extend now"

H="$(new_home)"; F="$(gen_primary "$H" 91d)"; add_subkey "$H" "$F" cv25519 encr 91d; fixture "$H"
expect_pass "primary expires in 91 days" "$KEY" "$POLICY"

H="$(new_home)"; F="$(gen_primary "$H" 2y)"; add_subkey "$H" "$F" cv25519 encr 89d; fixture "$H"
expect_fail "encryption subkey expires in 89 days under a 2y primary" "$KEY" "$POLICY" \
  "encryption subkey expires on"

# generated at a faked 2020-01-01 with a 1y lifetime -> expired at real time
H="$(new_home)"; F="$(gen_primary "$H" 1y 20200101T000000)"
add_subkey "$H" "$F" cv25519 encr 1y 20200101T000000; fixture "$H"
expect_fail "primary key already expired" "$KEY" "$POLICY" "primary key $PUB_FPR is EXPIRED"

echo "-- validity"
H="$(new_home)"; F="$(gen_primary "$H" 2y)"; add_subkey "$H" "$F" cv25519 encr 2y
revoke_primary "$H" "$F"; fixture "$H"
expect_fail "primary key revoked" "$KEY" "$POLICY" "primary key $PUB_FPR is REVOKED"

echo "-- subkey selection"
H="$(new_home)"; F="$(gen_primary "$H" 2y)"; fixture "$H"
expect_fail "no encryption subkey at all" "$KEY" "$POLICY" \
  "expected exactly 1 usable encryption subkey in SECURITY_KEY.asc, found 0"

# valid primary (faked 2020-01-01, 30y) whose only encryption subkey expired in 2021
H="$(new_home)"; F="$(gen_primary "$H" 30y 20200101T000000)"
add_subkey "$H" "$F" cv25519 encr 1y 20200101T000000; fixture "$H"
expect_fail "encryption subkey expired under a valid primary" "$KEY" "$POLICY" \
  "expected exactly 1 usable encryption subkey in SECURITY_KEY.asc, found 0"

# sign + auth subkeys first, encr last: the guard must pick the encr one
H="$(new_home)"; F="$(gen_primary "$H" 2y)"
add_subkey "$H" "$F" ed25519 sign 2y
add_subkey "$H" "$F" ed25519 auth 2y
add_subkey "$H" "$F" cv25519 encr 2y
fixture "$H"
expect_pass "sign + auth + encr subkeys: the encr subkey is selected" "$KEY" "$POLICY"

H="$(new_home)"; F="$(gen_primary "$H" 2y)"
add_subkey "$H" "$F" cv25519 encr 2y
add_subkey "$H" "$F" cv25519 encr 2y
fixture "$H"
expect_fail "two usable encryption subkeys" "$KEY" "$POLICY" \
  "expected exactly 1 usable encryption subkey in SECURITY_KEY.asc, found 2"

# =============================================================================
DONE=1
echo "SECURITY-KEY-TESTS: $PASSED passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
