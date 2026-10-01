#!/usr/bin/env bash
# Safety: tests must never use 3141; it may belong to the owner's live pilot.
# Regression tests for docs/ops/owner-token.sh (sourced usage).
#
# Covers:
#   - error path does not enable errexit/nounset in the caller, and does not
#     kill an interactive-style shell (next command still runs)
#   - success leaves caller shell options ($-) unchanged and does not export
#   - URL guard rejects userinfo (@) and non-loopback hosts; accepts strict
#     http://127.0.0.1:PORT[/api/v1] and http://[::1]:PORT[/api/v1]
#
# Usage: bash docs/ops/test-owner-token.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$HERE/owner-token.sh"
ROOT="$(cd "$HERE/../.." && pwd)"

# Ask the OS for unused loopback ports, then close the sockets before probing.
TEST_PORTS="$(python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET) as ipv4, socket.socket(socket.AF_INET6) as ipv6:
    ipv4.bind(("127.0.0.1", 0))
    ipv6.bind(("::1", 0))
    print(ipv4.getsockname()[1], ipv6.getsockname()[1])
PY
)"
read -r PORT_V4 PORT_V6 <<<"$TEST_PORTS"
if [[ ! "$PORT_V4" =~ ^[0-9]+$ || ! "$PORT_V6" =~ ^[0-9]+$ \
      || "$PORT_V4" == 3141 || "$PORT_V6" == 3141 ]]; then
  echo "owner-token tests: invalid test ports" >&2
  exit 1
fi
TEST_API_BASE="http://127.0.0.1:$PORT_V4"

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); echo "ok - $*"; }
bad() { FAIL=$((FAIL + 1)); echo "not ok - $*" >&2; }

# --- 1) Error path: missing env must not leave set -e/-u and must not kill ---
probe="$(
  BITSOV_API_BASE="$TEST_API_BASE" bash --norc -c '
    set +eu
    unset KONSENSUS_CONFIG KONSENSUS_MNEMONIC
    before=$-
    # shellcheck disable=SC1090
    source "'"$SCRIPT"'"
    rc=$?
    after=$-
    printf "rc=%s before=%s after=%s\n" "$rc" "$before" "$after"
    echo SURVIVED
    # With no errexit, a subsequent false must not terminate either.
    false
    echo AFTER_FALSE
  '
)" || true

echo "$probe" | grep -q 'rc=1' && ok "missing-env returns 1" || bad "missing-env return code: $probe"
echo "$probe" | grep -q 'SURVIVED' && ok "missing-env does not kill shell" || bad "missing-env killed shell: $probe"
echo "$probe" | grep -q 'AFTER_FALSE' && ok "caller without -e survives false after source" || bad "false after source aborted: $probe"
# before/after must match (script must not add e or u)
before="$(echo "$probe" | sed -n 's/.*before=\([^ ]*\).*/\1/p' | head -1)"
after="$(echo "$probe" | sed -n 's/.*after=\([^ ]*\).*/\1/p' | head -1)"
if [[ "$before" == "$after" ]]; then
  ok "missing-env leaves \$- unchanged ($before)"
else
  bad "missing-env changed \$- from [$before] to [$after]"
fi
case "$after" in
  *e*|*u*) bad "missing-env left errexit/nounset in caller ($-=$after)" ;;
  *) ok "missing-env did not enable e/u" ;;
esac

# --- 2) URL guard ---
url_probe() {
  local base="$1" expect_ok="$2"
  local out
  out="$(
    BITSOV_API_BASE="$base" KONSENSUS_MNEMONIC=/dev/null \
      bash --norc -c '
        set +eu
        # Keep URL validation real, but never connect even if a port is reused.
        curl() { return 7; }
        # shellcheck disable=SC1090
        source "'"$SCRIPT"'"
        echo rc=$?
      ' 2>&1
  )" || true
  if [[ "$expect_ok" == "reject" ]]; then
    if echo "$out" | grep -qi 'BITSOV_API_BASE\|loopback\|must be http'; then
      ok "reject URL $base"
    else
      bad "expected URL reject for $base, got: $out"
    fi
  else
    # Accept means we got past the URL guard (may fail later on curl/sign).
    if echo "$out" | grep -qi 'BITSOV_API_BASE\|loopback\|must be http'; then
      bad "URL wrongly rejected $base: $out"
    else
      ok "accept URL past guard $base"
    fi
  fi
}

url_probe "$TEST_API_BASE@evil.example/" reject
url_probe "$TEST_API_BASE@evil.example" reject
url_probe "http://localhost:$PORT_V4" reject
url_probe "http://evil.example:$PORT_V4" reject
url_probe "$TEST_API_BASE/extra" reject
url_probe "$TEST_API_BASE?x=1" reject
url_probe "$TEST_API_BASE" accept
url_probe "$TEST_API_BASE/" accept
url_probe "$TEST_API_BASE/api/v1" accept
url_probe "$TEST_API_BASE/api/v1/" accept
url_probe "http://[::1]:$PORT_V6" accept
url_probe "http://[::1]:$PORT_V6/api/v1" accept

# --- 3) Success path: options unchanged, token not exported ---
WORK="$(mktemp -d /tmp/owner-token-test.XXXX)"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# Stub curl + konsensus on PATH
cat >"$WORK/curl" <<'EOF'
#!/usr/bin/env bash
# Emit challenge or token based on argv.
args="$*"
if [[ "$args" == *auth/challenge* ]]; then
  printf '%s\n' '{"challenge":"bitsov-auth-v1:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff:1700000000","expires_at":1700000000}'
  exit 0
fi
if [[ "$args" == *auth/token* ]]; then
  printf '%s\n' '{"token":"eyJtest.owner.token"}'
  exit 0
fi
echo "stub-curl: unexpected $args" >&2
exit 1
EOF
cat >"$WORK/konsensus" <<'EOF'
#!/usr/bin/env bash
# Print a fake 64-byte hex signature; never touch a mnemonic.
printf '%s\n' "$(printf 'ab%.0s' {1..64})"
EOF
chmod +x "$WORK/curl" "$WORK/konsensus"

success="$(
  PATH="$WORK:$PATH" \
  BITSOV_API_BASE="$TEST_API_BASE" \
  KONSENSUS_MNEMONIC="$WORK/unused-mnemonic.txt" \
  KONSENSUS_BIN="$WORK/konsensus" \
  bash --norc -c '
    set +eu
    before=$-
    # shellcheck disable=SC1090
    source "'"$SCRIPT"'"
    rc=$?
    after=$-
    printf "rc=%s before=%s after=%s token=%s\n" "$rc" "$before" "$after" "${OWNER_TOKEN:-}"
    if declare -p OWNER_TOKEN 2>/dev/null | grep -q "declare -x"; then
      echo EXPORTED=1
    else
      echo EXPORTED=0
    fi
    # Token must not have been printed by default.
    echo SURVIVED
  ' 2>"$WORK/stderr"
)"

stderr="$(cat "$WORK/stderr")"
echo "$success" | grep -q 'rc=0' && ok "success returns 0" || bad "success rc: $success / stderr=$stderr"
echo "$success" | grep -q 'token=eyJtest.owner.token' && ok "success sets OWNER_TOKEN" || bad "token missing: $success"
echo "$success" | grep -q 'EXPORTED=0' && ok "OWNER_TOKEN not exported" || bad "OWNER_TOKEN was exported: $success"
sb="$(echo "$success" | sed -n 's/.*before=\([^ ]*\).*/\1/p' | head -1)"
sa="$(echo "$success" | sed -n 's/.*after=\([^ ]*\).*/\1/p' | head -1)"
if [[ "$sb" == "$sa" ]]; then
  ok "success leaves \$- unchanged ($sb)"
else
  bad "success changed \$- from [$sb] to [$sa]"
fi
# Token must not appear in stderr traces under default (no -x) run
if echo "$stderr" | grep -q 'eyJtest.owner.token'; then
  bad "token leaked on stderr: $stderr"
else
  ok "token not printed on stderr by default"
fi

# --- 4) xtrace restore: with set -x, token must not appear in traces ---
xtrace_out="$(
  PATH="$WORK:$PATH" \
  BITSOV_API_BASE="$TEST_API_BASE" \
  KONSENSUS_MNEMONIC="$WORK/unused-mnemonic.txt" \
  KONSENSUS_BIN="$WORK/konsensus" \
  bash --norc -c '
    set +eu
    set -x
    # shellcheck disable=SC1090
    source "'"$SCRIPT"'"
    set +x
    echo DONE_TOKEN="${OWNER_TOKEN:-}"
  ' 2>&1
)"
if echo "$xtrace_out" | grep -q 'DONE_TOKEN=eyJtest.owner.token'; then
  ok "xtrace run still sets OWNER_TOKEN"
else
  bad "xtrace run failed to set token: $xtrace_out"
fi
# Traces of the assignment itself are suppressed while +x inside the mint.
# Allow DONE_TOKEN= line which is after restore; reject bare token in +x lines.
trace_leaks="$(echo "$xtrace_out" | grep '^\+' | grep -F 'eyJtest.owner.token' || true)"
if [[ -z "$trace_leaks" ]]; then
  ok "xtrace does not leak token on + lines"
else
  bad "xtrace leaked token: $trace_leaks"
fi

echo
echo "owner-token tests: $PASS passed, $FAIL failed (root=$ROOT)"
[[ "$FAIL" -eq 0 ]]
