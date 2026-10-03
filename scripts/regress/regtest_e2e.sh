#!/usr/bin/env bash
# No automatic downloads. Reuse installed binaries or the existing harness cache.
set -euo pipefail
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/bitsov-target-a22}"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export BITCOIND_SKIP_DOWNLOAD=1 ELECTRS_SKIP_DOWNLOAD=1
find_binary() {
  local name="$1" candidate
  if candidate="$(command -v "$name")"; then printf '%s\n' "$candidate"; return; fi
  for candidate in /tmp/bitsov-target-*/debug/build/*/out/bitcoin/bitcoin-*/bin/"$name" /tmp/bitsov-target-*/debug/build/*/out/electrs/*/"$name"; do
    if [[ -x "$candidate" ]]; then printf '%s\n' "$candidate"; return; fi
  done
  echo "Missing $name: set its *_EXE environment variable to a local executable (see docs/regtest-e2e.md)." >&2
  return 1
}
export BITCOIND_EXE="${BITCOIND_EXE:-$(find_binary bitcoind || true)}"
export ELECTRS_EXE="${ELECTRS_EXE:-$(find_binary electrs || true)}"
export REGTEST_BUILD_ONLY=0
if [[ ! -x "$BITCOIND_EXE" || ! -x "$ELECTRS_EXE" ]]; then
  if [[ "${REGTEST_ALLOW_MISSING:-0}" != 1 ]]; then exit 1; fi
  echo "Local regtest fixtures unavailable; compiling the scenario before reporting SKIP."
  export REGTEST_BUILD_ONLY=1
fi
echo "Bitcoin Core: $BITCOIND_EXE"
echo "electrs: $ELECTRS_EXE"
# Own the whole process group: Rust RAII handles normal exits and panics;
# exec keeps the runner PID: signals reach the supervisor's cleanup handlers.
# They cover timeout, SIGINT, SIGTERM and SIGHUP (including daemons).
exec python3 - <<'PYTHON'
import os
import shutil
import signal
import subprocess
import tempfile

root = None
child = None
pending_signal = None

def interrupted(signum, _frame):
    global pending_signal
    # Popen may already have spawned Cargo before returning its handle. Defer
    # cancellation until assignment so finally can always kill that group.
    if pending_signal is None:
        pending_signal = signum
    if child is not None:
        raise SystemExit(128 + pending_signal)

signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
for sig in signals:
    signal.signal(sig, interrupted)
try:
    root = tempfile.mkdtemp(prefix="bitsov-regtest-")
    print(f"Disposable regtest data: {root}", flush=True)
    env = {k: v for k, v in os.environ.items() if k.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
    env.update(TMPDIR=root, TEMPDIR_ROOT=root, NO_PROXY="*", no_proxy="*")
    command = [
        "cargo", "test", "--offline", "--locked", "-p", "konsensus-node",
        "--features", "regtest-e2e", "--bin", "konsensus",
    ]
    build_only = env.get("REGTEST_BUILD_ONLY") == "1"
    if build_only:
        command += ["--no-run"]
    else:
        command += [os.environ.get("REGTEST_TEST", "regtest_e2e::"),
                    "--", "--ignored", "--nocapture", "--test-threads=1"]
    child = subprocess.Popen(command, env=env, start_new_session=True)
    if pending_signal is not None:
        raise SystemExit(128 + pending_signal)
    try:
        result = child.wait(timeout=int(os.environ.get("REGTEST_TIMEOUT_SECONDS", "900")))
        if result == 0 and build_only:
            print("SKIP three-node paid E2E: compiled; BITCOIND_EXE and/or ELECTRS_EXE unavailable offline. No daemons started.", flush=True)
        raise SystemExit(result)
    except subprocess.TimeoutExpired:
        print("REGTEST-E2E timeout; terminating the test and its daemons", flush=True)
        raise SystemExit(124)
finally:
    # A repeated cancellation must not interrupt process-group/data cleanup.
    for sig in signals:
        signal.signal(sig, signal.SIG_IGN)
    if child is not None:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()
    if root is not None:
        shutil.rmtree(root)
PYTHON
