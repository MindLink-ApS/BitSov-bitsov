#!/usr/bin/env bash
# One-command Mexico demo rehearsal on local regtest.
# Talk-track beats: first contact with owner approval, paid message, paid reply,
# refusal over cap at 0 msat, exact msat reconciliation.
# Cached binaries only (no downloads). 127.0.0.1 listeners; ephemeral ports if
# busy. Tears down only the process group this script owns.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/bitsov-target-demo-rehearsal}"
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 CARGO_INCREMENTAL=0
export BITCOIND_SKIP_DOWNLOAD=1 ELECTRS_SKIP_DOWNLOAD=1
export REGTEST_TEST="${REGTEST_TEST:-regtest_e2e::mexico_demo_rehearsal}"

find_binary() {
  local name="$1" candidate
  if candidate="$(command -v "$name" 2>/dev/null)"; then
    printf '%s\n' "$candidate"
    return
  fi
  # Existing harness / prior REAL-UI scratchpad caches only — never download.
  while IFS= read -r candidate; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done < <(
    # shellcheck disable=SC2086
    compgen -G "/tmp/bitsov-target-*/debug/build/*/out/bitcoin/bitcoin-*/bin/${name}" || true
    compgen -G "/tmp/bitsov-target-*/debug/build/*/out/electrs/*/${name}" || true
    compgen -G "/tmp/claude-501/*/scratchpad/bin/${name}" || true
    compgen -G "/tmp/claude-501/*/*/scratchpad/bin/${name}" || true
    compgen -G "/tmp/claude-501/*/*/*/scratchpad/bin/${name}" || true
  )
  echo "Missing $name: set BITCOIND_EXE / ELECTRS_EXE to a local cached executable (no downloads)." >&2
  return 1
}

export BITCOIND_EXE="${BITCOIND_EXE:-$(find_binary bitcoind)}"
export ELECTRS_EXE="${ELECTRS_EXE:-$(find_binary electrs)}"
[[ -x "$BITCOIND_EXE" && -x "$ELECTRS_EXE" ]]
echo "Bitcoin Core: $BITCOIND_EXE"
echo "electrs: $ELECTRS_EXE"
echo "Demo rehearsal target: $REGTEST_TEST"

# Own the whole process group. Only this group's children are stopped on exit.
exec python3 - <<'PYTHON'
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

REQUIRED = [
    "first contact with owner approval",
    "paid message",
    "paid reply",
    "refusal over cap at 0 msat",
    "exact msat reconciliation",
]
BEAT_RE = re.compile(r"^BEAT (PASS|FAIL) (.+): ([0-9.]+)s\s*$")

root = None
child = None
pending_signal = None
beats = []

def interrupted(signum, _frame):
    global pending_signal
    if pending_signal is None:
        pending_signal = signum
    if child is not None:
        raise SystemExit(128 + pending_signal)

signals = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
for sig in signals:
    signal.signal(sig, interrupted)

started = time.monotonic()
try:
    root = tempfile.mkdtemp(prefix="bitsov-demo-rehearsal-")
    print(f"Disposable regtest data: {root}", flush=True)
    env = {
        k: v
        for k, v in os.environ.items()
        if k.lower() not in {"http_proxy", "https_proxy", "all_proxy"}
    }
    env.update(TMPDIR=root, TEMPDIR_ROOT=root, NO_PROXY="*", no_proxy="*")
    child = subprocess.Popen(
        [
            "cargo",
            "test",
            "--offline",
            "--locked",
            "-p",
            "konsensus-node",
            "--features",
            "regtest-e2e",
            "--bin",
            "konsensus",
            os.environ.get("REGTEST_TEST", "regtest_e2e::mexico_demo_rehearsal"),
            "--",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ],
        env=env,
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    if pending_signal is not None:
        raise SystemExit(128 + pending_signal)
    assert child.stdout is not None
    for line in child.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        match = BEAT_RE.match(line.rstrip("\n"))
        if match:
            beats.append((match.group(1), match.group(2), match.group(3)))
    try:
        code = child.wait(timeout=int(os.environ.get("REGTEST_TIMEOUT_SECONDS", "900")))
    except subprocess.TimeoutExpired:
        print("DEMO-REHEARSAL timeout; terminating owned process group", flush=True)
        raise SystemExit(124)

    print("---", flush=True)
    ok = True
    names = [name for _status, name, _secs in beats]
    for expected in REQUIRED:
        found = next((b for b in beats if b[1] == expected), None)
        if found is None:
            print(f"BEAT FAIL {expected}: missing", flush=True)
            ok = False
        elif found[0] != "PASS":
            print(f"BEAT FAIL {expected}: {found[2]}s", flush=True)
            ok = False
        else:
            print(f"BEAT PASS {expected}: {found[2]}s", flush=True)
    if names != REQUIRED:
        print(
            f"BEAT ORDER FAIL: got {names!r}, expected {REQUIRED!r}",
            flush=True,
        )
        ok = False
    elapsed = time.monotonic() - started
    if code != 0:
        print(f"DEMO-REHEARSAL FAIL cargo exit {code} in {elapsed:.1f}s", flush=True)
        raise SystemExit(code if code else 1)
    if not ok:
        print(f"DEMO-REHEARSAL FAIL beats incomplete in {elapsed:.1f}s", flush=True)
        raise SystemExit(1)
    print(f"DEMO-REHEARSAL PASS 5/5 beats in {elapsed:.1f}s", flush=True)
    raise SystemExit(0)
finally:
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
        try:
            child.wait(timeout=5)
        except Exception:
            pass
    if root is not None:
        shutil.rmtree(root, ignore_errors=True)
PYTHON
