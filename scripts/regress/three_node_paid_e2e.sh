#!/usr/bin/env bash
# Atlas runs 1–4: one offline, CI-runnable entry point; no downloads.
set -euo pipefail
export REGTEST_TEST=regtest_e2e::three_node::three_node_paid_e2e
export REGTEST_ALLOW_MISSING=1
export REGTEST_TIMEOUT_SECONDS="${REGTEST_TIMEOUT_SECONDS:-1800}"
exec bash "$(dirname "$0")/regtest_e2e.sh"
