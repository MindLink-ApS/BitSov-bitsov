#!/usr/bin/env bash
# Nightly 1:1 call proof (#411): run the real-LDK calls regtest
# (`regtest_e2e::real_ldk_regtest_calls`, A--C--B on regtest) through the
# offline runner and fail unless the log proves the test executed and
# completed offer, answer, ICE and hangup. Regtest only; no downloads.
#
# Exit codes: the runner's own on failure/timeout; 1 when fixtures are
# missing, when the test was skipped or filtered out, or when a phase marker
# is absent. A skip is never a pass in this lane.
set -euo pipefail
export REGTEST_TEST=regtest_e2e::real_ldk_regtest_calls
export REGTEST_TIMEOUT_SECONDS="${REGTEST_TIMEOUT_SECONDS:-1800}"
# Missing fixtures must fail, never SKIP (77): the lane requires execution.
unset REGTEST_ALLOW_MISSING
log="${REGTEST_CALLS_LOG:-calls.log}"

set +e
bash "$(dirname "$0")/regtest_e2e.sh" 2>&1 | tee "$log"
result=${PIPESTATUS[0]}
set -e
if [[ "$result" == 77 ]]; then
  echo "::error::real_ldk_regtest_calls SKIPPED (77); this lane requires execution."
  exit 1
fi
if [[ "$result" != 0 ]]; then
  echo "::error::real_ldk_regtest_calls runner exited $result"
  exit "$result"
fi

# Exactly one test ran and passed (a renamed or de-ignored test would be
# "0 passed", which Cargo still reports as success).
if ! grep -qE '^test result: ok\. 1 passed; 0 failed;' "$log"; then
  echo "::error::real_ldk_regtest_calls did not run (expected exactly one passing test)"
  exit 1
fi
required=(
  "STEP PASS call offer paid at call_msat and forwarded to B's WS"
  'STEP PASS answer, ICE and hangup paid and delivered both ways'
  'STEP PASS ICE after hangup refused before paying'
  'REGTEST-CALLS PASS;'
)
for marker in "${required[@]}"; do
  if ! grep -qF -- "$marker" "$log"; then
    echo "::error::real_ldk_regtest_calls incomplete; missing: $marker"
    exit 1
  fi
done
echo "REAL-LDK CALLS LANE PASS: offer, answer, ICE and hangup proven in $log"
