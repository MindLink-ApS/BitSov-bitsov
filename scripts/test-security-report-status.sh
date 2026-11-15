#!/usr/bin/env bash
# test-security-report-status.sh — the report never says ALL CLEAR unless every
# scanner is clean and the waiver-deadline check succeeded. No network.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOW="$HERE/../.github/workflows/security-scan.yml"
pass=0

case_() { # label, want overall (prefix), want waiver_status, then VAR=value...
  local label="$1" want="$2" want_waiver="$3"; shift 3
  local out
  out="$(env -i PATH="$PATH" "$@" bash -c 'source "$0"; security_overall; printf "%s|%s|%s" "$overall" "$waiver_status" "${SCAN_ERROR:-false}"' "$HERE/security-report-status.sh")"
  local overall="${out%%|*}" rest="${out#*|}"; local waiver="${rest%%|*}"
  case "$overall" in "$want"*) ;; *) echo "FAIL $label: overall '$overall', want '$want'"; exit 1;; esac
  [ "$waiver" = "$want_waiver" ] || { echo "FAIL $label: waiver '$waiver', want '$want_waiver'"; exit 1; }
  echo "ok: $label"; pass=$((pass + 1))
}

clean=(CARGO_VULN_COUNT=0 OSV_COUNT=0 LEAK_COUNT=0)
case_ "all clean and deadlines passed" "ALL CLEAR" clean "${clean[@]}" WAIVER_DEADLINES_OUTCOME=success
case_ "only the deadline check failed" "WAIVER DEADLINES FAILED" "FAILED (failure)" "${clean[@]}" WAIVER_DEADLINES_OUTCOME=failure
case_ "deadline check cancelled" "WAIVER DEADLINES FAILED" "FAILED (cancelled)" "${clean[@]}" WAIVER_DEADLINES_OUTCOME=cancelled
case_ "deadline check did not run" "WAIVER DEADLINES FAILED" "FAILED (not run)" "${clean[@]}"
case_ "findings and a failed deadline check" "REQUIRES REVIEW" "FAILED (failure)" CARGO_VULN_COUNT=0 OSV_COUNT=2 LEAK_COUNT=0 WAIVER_DEADLINES_OUTCOME=failure
case_ "findings, deadlines passed" "REQUIRES REVIEW" clean CARGO_VULN_COUNT=1 OSV_COUNT=0 LEAK_COUNT=0 WAIVER_DEADLINES_OUTCOME=success
case_ "a scan error wins" "SCAN ERROR" "FAILED (failure)" "${clean[@]}" OSV_ERROR=true WAIVER_DEADLINES_OUTCOME=failure

# The workflow must use this logic, pass the deadline outcome in, and show the row.
grep -q 'WAIVER_DEADLINES_OUTCOME: ${{ steps.waiver_deadlines.outcome }}' "$WORKFLOW" \
  || { echo "FAIL workflow does not pass the waiver-deadline outcome to the report"; exit 1; }
grep -q 'source scripts/security-report-status.sh' "$WORKFLOW" \
  || { echo "FAIL workflow does not use security-report-status.sh"; exit 1; }
grep -q "printf '| waiver deadlines | %s |" "$WORKFLOW" \
  || { echo "FAIL the report summary has no waiver-deadline row"; exit 1; }
if grep -q 'echo "ALL CLEAR")' "$WORKFLOW"; then echo "FAIL workflow still computes ALL CLEAR inline"; exit 1; fi
echo "ok: workflow wiring"; pass=$((pass + 1))

echo "test-security-report-status: $pass passed"
