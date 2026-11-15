#!/usr/bin/env bash
# security-report-status.sh — the security report's overall status and summary rows.
# Sourced by the "Generate security report" step of security-scan.yml, and by
# test-security-report-status.sh. Reads the scanner counts and error flags and the
# waiver-deadline step's outcome; sets HAS_FINDINGS, SCAN_ERROR, overall and the
# per-check status words. The report says ALL CLEAR only when every scanner is
# clean and the waiver-deadline check succeeded.
security_overall() {
  HAS_FINDINGS=false
  [ "${CARGO_VULN_COUNT:-0}" -gt 0 ] && HAS_FINDINGS=true
  [ "${OSV_COUNT:-0}"        -gt 0 ] && HAS_FINDINGS=true
  [ "${LEAK_COUNT:-0}"       -gt 0 ] && HAS_FINDINGS=true

  cargo_status=$([ "${CARGO_VULN_COUNT:-0}" -gt 0 ] && echo "FINDINGS (${CARGO_VULN_COUNT})" || echo "clean")
  osv_status=$([ "${OSV_COUNT:-0}"           -gt 0 ] && echo "FINDINGS (${OSV_COUNT})"        || echo "clean")
  leak_status=$([ "${LEAK_COUNT:-0}"         -gt 0 ] && echo "FINDINGS (${LEAK_COUNT})"       || echo "clean")
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
  [ "${CARGO_ERROR:-false}" = true ] && cargo_status="SCAN ERROR"
  [ "${OSV_ERROR:-false}" = true ] && osv_status="SCAN ERROR"
  [ "${LEAK_ERROR:-false}" = true ] && leak_status="SCAN ERROR"
  return 0
}
