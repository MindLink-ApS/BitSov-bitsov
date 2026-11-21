#!/usr/bin/env bash
# security-report-status.sh — the security report's overall status and summary rows.
# Sourced by the "Generate security report" step of security-scan.yml, and by
# test-security-report-status.sh. Reads the scanner counts and error flags and the
# waiver-deadline step's outcome; sets HAS_FINDINGS, SCAN_ERROR, overall and the
# per-check status words. The report says ALL CLEAR only when every scanner is
# clean and the waiver-deadline check succeeded. A count that is missing, empty or
# not a whole number is that scanner's scan error, never clean.
_security_count_ok() { case "$1" in ''|*[!0-9]*) return 1;; esac; }
_security_count_status() { # count, error flag
  if [ "$2" = true ]; then echo "SCAN ERROR"
  elif [ "$1" -gt 0 ]; then echo "FINDINGS ($1)"
  else echo "clean"; fi
}
security_overall() {
  _security_count_ok "${CARGO_VULN_COUNT-}" || CARGO_ERROR=true
  _security_count_ok "${OSV_COUNT-}"        || OSV_ERROR=true
  _security_count_ok "${LEAK_COUNT-}"       || LEAK_ERROR=true

  HAS_FINDINGS=false
  _security_count_ok "${CARGO_VULN_COUNT-}" && [ "$CARGO_VULN_COUNT" -gt 0 ] && HAS_FINDINGS=true
  _security_count_ok "${OSV_COUNT-}"        && [ "$OSV_COUNT" -gt 0 ]        && HAS_FINDINGS=true
  _security_count_ok "${LEAK_COUNT-}"       && [ "$LEAK_COUNT" -gt 0 ]       && HAS_FINDINGS=true

  cargo_status=$(_security_count_status "${CARGO_VULN_COUNT-}" "${CARGO_ERROR:-false}")
  osv_status=$(_security_count_status "${OSV_COUNT-}" "${OSV_ERROR:-false}")
  leak_status=$(_security_count_status "${LEAK_COUNT-}" "${LEAK_ERROR:-false}")
  # Any outcome other than success (failure, cancelled, skipped, or none) is not clean.
  if [ "${WAIVER_DEADLINES_OUTCOME:-}" = success ]; then
    waiver_status="clean"
  else
    waiver_status="FAILED (${WAIVER_DEADLINES_OUTCOME:-not run})"
  fi

  if [ "${HAS_FINDINGS}" = true ]; then
    overall="REQUIRES REVIEW"
  elif [ "${waiver_status}" != clean ]; then
    overall="WAIVER DEADLINES FAILED — see the \"Check advisory waiver deadlines\" step"
  else
    overall="ALL CLEAR"
  fi
  if [ "${CARGO_ERROR:-false}" = true ] || [ "${OSV_ERROR:-false}" = true ] || [ "${LEAK_ERROR:-false}" = true ]; then
    SCAN_ERROR=true
    overall="SCAN ERROR — triage privately"
  fi
  return 0
}
