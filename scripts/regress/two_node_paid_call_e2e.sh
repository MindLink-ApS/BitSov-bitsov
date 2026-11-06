#!/usr/bin/env bash
# M6 P1: reuse the paid-regtest supervisor, fixtures and process cleanup.
set -euo pipefail
export REGTEST_TEST=regtest_e2e::paid_call::
export REGTEST_ALLOW_MISSING=1
export REGTEST_TIMEOUT_SECONDS="${REGTEST_TIMEOUT_SECONDS:-1200}"
exec bash "$(dirname "$0")/regtest_e2e.sh"
