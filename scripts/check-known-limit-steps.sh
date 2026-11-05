#!/usr/bin/env bash
# check-known-limit-steps.sh — the dropped-link recovery steps say the same thing
# in the release notes and in UPGRADING, and name the app's real controls.
#
# Both files carry the list after "If messages stop being read after a dropped
# link:". The two copies must match, and the call step must name the buttons the
# app shows ("End call" while a call is closing, "Hang up" while it is live),
# never a bare "End".
#
# Usage: scripts/check-known-limit-steps.sh [repo-root]
# Test hooks: KNOWN_LIMIT_NOTES and KNOWN_LIMIT_UPGRADING override the two paths.
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
NOTES="${KNOWN_LIMIT_NOTES:-$ROOT/docs/releases/v0.3.0-rc22.md}"
UPGRADING="${KNOWN_LIMIT_UPGRADING:-$ROOT/docs/UPGRADING.md}"
START='If messages stop being read after a dropped link:'
END='Amounts already paid for messages or minutes that were not read are not refunded.'

fail() { echo "KNOWN-LIMIT-STEPS: FAIL $*" >&2; exit 1; }

steps() {
  [ -f "$1" ] || fail "missing $1"
  awk -v s="$START" -v e="$END" '
    $0 == s { on = 1; n++; next }
    on && $0 == e { on = 0; next }
    on { print }
    END { if (n != 1) exit 3 }
  ' "$1" || fail "expected exactly one steps list in $1"
}

a="$(steps "$NOTES")"
b="$(steps "$UPGRADING")"
[ -n "$a" ] || fail "empty steps list in $NOTES"
[ "$a" = "$b" ] || fail "steps differ between $NOTES and $UPGRADING"
if printf '%s\n' "$a" | grep -Eq '(^|[^A-Za-z])End\.'; then
  fail "a step names a bare End; the app's buttons are End call and Hang up"
fi
printf '%s\n' "$a" | tr '\n' ' ' | grep -q 'End call' || fail "no step names End call"
printf '%s\n' "$a" | tr '\n' ' ' | grep -q 'Hang up' || fail "no step names Hang up"
echo "KNOWN-LIMIT-STEPS: OK"
