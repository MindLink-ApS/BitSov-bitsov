#!/usr/bin/env bash
# test-security-report-status.sh — the report never says ALL CLEAR unless every
# scanner is clean and the waiver-deadline check succeeded. No network.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKFLOW="$HERE/../.github/workflows/security-scan.yml"
pass=0

case_() { # label, want overall (prefix), want waiver_status, want SCAN_ERROR, want HAS_FINDINGS, then VAR=value...
  local label="$1" want="$2" want_waiver="$3" want_err="$4" want_find="$5"; shift 5
  local out
  # Same shell options as the workflow step (bash -eo pipefail); SCAN_ERROR starts
  # false there, as in the workflow.
  out="$(env -i PATH="$PATH" SCAN_ERROR=false "$@" bash -eo pipefail -c 'source "$0"; security_overall; printf "%s|%s|%s|%s" "$overall" "$waiver_status" "$SCAN_ERROR" "$HAS_FINDINGS"' "$HERE/security-report-status.sh" 2>/dev/null)" \
    || { echo "FAIL $label: security_overall exited non-zero"; exit 1; }
  local overall waiver err find
  IFS='|' read -r overall waiver err find <<<"$out"
  case "$overall" in "$want"*) ;; *) echo "FAIL $label: overall '$overall', want '$want'"; exit 1;; esac
  [ "$waiver" = "$want_waiver" ] || { echo "FAIL $label: waiver '$waiver', want '$want_waiver'"; exit 1; }
  [ "$err" = "$want_err" ] || { echo "FAIL $label: SCAN_ERROR '$err', want '$want_err'"; exit 1; }
  [ "$find" = "$want_find" ] || { echo "FAIL $label: HAS_FINDINGS '$find', want '$want_find'"; exit 1; }
  echo "ok: $label"; pass=$((pass + 1))
}

clean=(CARGO_VULN_COUNT=0 OSV_COUNT=0 LEAK_COUNT=0)
case_ "all clean and deadlines passed" "ALL CLEAR" clean false false "${clean[@]}" WAIVER_DEADLINES_OUTCOME=success
case_ "only the deadline check failed" "WAIVER DEADLINES FAILED" "FAILED (failure)" false false "${clean[@]}" WAIVER_DEADLINES_OUTCOME=failure
case_ "deadline check cancelled" "WAIVER DEADLINES FAILED" "FAILED (cancelled)" false false "${clean[@]}" WAIVER_DEADLINES_OUTCOME=cancelled
case_ "deadline check skipped" "WAIVER DEADLINES FAILED" "FAILED (skipped)" false false "${clean[@]}" WAIVER_DEADLINES_OUTCOME=skipped
case_ "deadline check did not run" "WAIVER DEADLINES FAILED" "FAILED (not run)" false false "${clean[@]}"
case_ "findings and a failed deadline check" "REQUIRES REVIEW" "FAILED (failure)" false true CARGO_VULN_COUNT=0 OSV_COUNT=2 LEAK_COUNT=0 WAIVER_DEADLINES_OUTCOME=failure
case_ "findings, deadlines passed" "REQUIRES REVIEW" clean false true CARGO_VULN_COUNT=1 OSV_COUNT=0 LEAK_COUNT=0 WAIVER_DEADLINES_OUTCOME=success
case_ "a scan error wins" "SCAN ERROR" "FAILED (failure)" true false "${clean[@]}" OSV_ERROR=true WAIVER_DEADLINES_OUTCOME=failure
case_ "a scan error wins over findings" "SCAN ERROR" clean true true CARGO_VULN_COUNT=0 OSV_COUNT=0 LEAK_COUNT=3 CARGO_ERROR=true WAIVER_DEADLINES_OUTCOME=success
# A count that is missing, empty or not a whole number is a scan error, never clean.
case_ "missing cargo count" "SCAN ERROR" clean true false OSV_COUNT=0 LEAK_COUNT=0 WAIVER_DEADLINES_OUTCOME=success
case_ "empty osv count" "SCAN ERROR" clean true false CARGO_VULN_COUNT=0 OSV_COUNT= LEAK_COUNT=0 WAIVER_DEADLINES_OUTCOME=success
case_ "null leak count" "SCAN ERROR" clean true false CARGO_VULN_COUNT=0 OSV_COUNT=0 LEAK_COUNT=null WAIVER_DEADLINES_OUTCOME=success
case_ "negative cargo count" "SCAN ERROR" clean true false CARGO_VULN_COUNT=-1 OSV_COUNT=0 LEAK_COUNT=0 WAIVER_DEADLINES_OUTCOME=success
case_ "bad count next to findings" "SCAN ERROR" clean true true CARGO_VULN_COUNT=2 OSV_COUNT=x LEAK_COUNT=0 WAIVER_DEADLINES_OUTCOME=success

# The workflow must use this logic, pass the deadline outcome in, and show the row.
grep -q 'WAIVER_DEADLINES_OUTCOME: ${{ steps.waiver_deadlines.outcome }}' "$WORKFLOW" \
  || { echo "FAIL workflow does not pass the waiver-deadline outcome to the report"; exit 1; }
grep -q 'source scripts/security-report-status.sh' "$WORKFLOW" \
  || { echo "FAIL workflow does not use security-report-status.sh"; exit 1; }
grep -Eq '^[[:space:]]*security_overall[[:space:]]*$' "$WORKFLOW" \
  || { echo "FAIL workflow sources security-report-status.sh but never calls security_overall"; exit 1; }
grep -q "printf '| waiver deadlines | %s |" "$WORKFLOW" \
  || { echo "FAIL the report summary has no waiver-deadline row"; exit 1; }
if grep -q 'echo "ALL CLEAR")' "$WORKFLOW"; then echo "FAIL workflow still computes ALL CLEAR inline"; exit 1; fi
echo "ok: workflow wiring"; pass=$((pass + 1))

echo "test-security-report-status: $pass passed"
