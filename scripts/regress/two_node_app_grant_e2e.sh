#!/usr/bin/env bash
# Ordinary app approvals on two production nodes with real regtest settlement.
set -euo pipefail
export REGTEST_TEST=regtest_e2e::app_grant::
export REGTEST_ALLOW_MISSING=1
export REGTEST_TIMEOUT_SECONDS="${REGTEST_TIMEOUT_SECONDS:-1200}"
exec bash "$(dirname "$0")/regtest_e2e.sh"
