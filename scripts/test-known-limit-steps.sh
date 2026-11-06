#!/usr/bin/env bash
# test-known-limit-steps.sh — exercises check-known-limit-steps.sh on the repo
# files and on fixtures that must be refused.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$HERE/check-known-limit-steps.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
pass=0

write() { # file, step-4 text, extra
  {
    echo "# fixture"
    echo
    echo "If messages stop being read after a dropped link:"
    echo
    echo "1. Stop sending."
    echo "$2"
    echo
    echo "Amounts already paid for messages or minutes that were not read are not refunded."
    [ -z "${3:-}" ] || printf '%s\n' "$3"
  } > "$1"
}

expect() { # want(ok|fail), label, notes, upgrading
  local out rc=0
  out="$(KNOWN_LIMIT_NOTES="$3" KNOWN_LIMIT_UPGRADING="$4" bash "$CHECK" 2>&1)" || rc=$?
  if [ "$1" = ok ] && [ "$rc" -ne 0 ]; then echo "FAIL $2: $out"; exit 1; fi
  if [ "$1" = fail ] && [ "$rc" -eq 0 ]; then echo "FAIL $2: accepted"; exit 1; fi
  echo "ok: $2"; pass=$((pass + 1))
}

good='4. In any app that still shows the call, use End call, or Hang up while the
   call still shows as live.'
write "$TMP/good.md" "$good"
write "$TMP/nohang.md" '4. In any app that still shows the call, use End call.'
write "$TMP/other.md" '4. In any app that still shows the call, use End call, or Hang up.'
write "$TMP/twice.md" "$good" "If messages stop being read after a dropped link:"
sed '$d' "$TMP/good.md" > "$TMP/unterminated.md"

out="$(bash "$CHECK")" || { echo "FAIL repo files: $out"; exit 1; }
echo "ok: repo files"; pass=$((pass + 1))
expect ok   "matching fixtures"            "$TMP/good.md"   "$TMP/good.md"
for ending in '.' ',' ';' ':' '!' '?' '"' ')' '' ' and wait.' ' caller.' ' calls.' ' End call call.' $'\n6. Wait.' $'\r\n6. Wait.'; do
  write "$TMP/bare.md" "$good"$'\n'"5. Then use End$ending"
  label="$(printf '%q' "End$ending")"
  expect fail "bare $label with both labels" "$TMP/bare.md" "$TMP/bare.md"
done
for labels in $'End \t call, or Hang \t up' $'End\n   call, or Hang\n   up' $'End\r\n   call, or Hang\r\n   up' 'End call End call, or Hang up'; do
  write "$TMP/spaced.md" "4. Use $labels."
  expect ok "complete labels with normalized whitespace" "$TMP/spaced.md" "$TMP/spaced.md"
done
write "$TMP/words.md" "$good"$'\n''5. Ending and End_call are not button labels.'
expect ok "End within larger words"      "$TMP/words.md"  "$TMP/words.md"
expect fail "End call without Hang up"     "$TMP/nohang.md" "$TMP/nohang.md"
expect fail "copies differ"                "$TMP/good.md"   "$TMP/other.md"
expect fail "two lists in one file"        "$TMP/twice.md"  "$TMP/good.md"
expect fail "unterminated section"         "$TMP/unterminated.md" "$TMP/unterminated.md"
expect fail "missing file"                 "$TMP/none.md"   "$TMP/good.md"
echo "known-limit steps: $pass passed"
