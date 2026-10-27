#!/usr/bin/env bash
# Seed-only channel recovery on local regtest (bitcoind only). No downloads.
set -euo pipefail
cd "$(dirname "$0")/../.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/bitsov-target-recover-regtest}"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export BITCOIND_SKIP_DOWNLOAD=1

find_binary() {
  local name="$1" candidate
  if candidate="$(command -v "$name" 2>/dev/null)"; then
    printf '%s\n' "$candidate"
    return
  fi
  for candidate in /tmp/bitsov-target-*/debug/build/*/out/bitcoin/bitcoin-*/bin/"$name"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "Missing $name: set BITCOIND_EXE to a local executable." >&2
  return 1
}

export BITCOIND_EXE="${BITCOIND_EXE:-$(find_binary bitcoind || true)}"
export REGTEST_BUILD_ONLY=0
if [[ ! -x "$BITCOIND_EXE" ]]; then
  if [[ "${REGTEST_ALLOW_MISSING:-0}" != 1 ]]; then
    exit 1
  fi
  echo "Local bitcoind unavailable; compiling recover_regtest before reporting SKIP."
  export REGTEST_BUILD_ONLY=1
fi

echo "Bitcoin Core: $BITCOIND_EXE"
# Same process-group timeout supervisor as regtest_e2e.sh. exec keeps this
# runner's PID, so timeout and cancellation reach the cleanup handlers.
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
    root = tempfile.mkdtemp(prefix="bitsov-recover-regtest-")
    print(f"Disposable regtest data: {root}", flush=True)
    env = {k: v for k, v in os.environ.items() if k.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
    env.update(TMPDIR=root, TEMPDIR_ROOT=root, NO_PROXY="*", no_proxy="*")
    command = [
        "cargo", "test", "--offline", "--locked", "-p", "konsensus-lightning",
        "--test", "recover_regtest",
    ]
    build_only = env.get("REGTEST_BUILD_ONLY") == "1"
    if build_only:
        command += ["--no-run"]
    else:
        command += [
            "recover_force_closed_channel_from_seed_after_data_loss",
            "--", "--ignored", "--nocapture", "--test-threads=1",
        ]
    child = subprocess.Popen(command, env=env, start_new_session=True)
    if pending_signal is not None:
        raise SystemExit(128 + pending_signal)
    try:
        result = child.wait(timeout=int(os.environ.get("REGTEST_TIMEOUT_SECONDS", "900")))
        if result == 0 and build_only:
            print("SKIP recover regtest: compiled; BITCOIND_EXE unavailable. No daemons started.", flush=True)
            raise SystemExit(77)
        if result == 0:
            print("RECOVER REGTEST PASS; seed-only force-close recovery", flush=True)
        raise SystemExit(result)
    except subprocess.TimeoutExpired:
        print("RECOVER-REGTEST timeout; terminating the test and its daemons", flush=True)
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
