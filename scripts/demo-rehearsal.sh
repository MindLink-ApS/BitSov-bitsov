#!/usr/bin/env bash
# One-command end-user demo rehearsal on local regtest (A -- C -- B, real LDK).
# Talk-track beats: front-door card created and exported as link, verified,
# knocked (first contact with owner approval, admission paid once), paid
# message, paid reply, voice note sent as a paid file and received, 1:1 call
# offer paid once at call_msat with answer and hangup, refusal over cap at
# 0 msat, exact msat reconciliation. Every money beat also prints its own
# "MSAT <beat>:" line after reconciling channels and budgets to the msat.
#
# The call beat needs paid 1:1 calls (#131). It runs when this checkout has
# them (crates/konsensus-core/src/payloads/call.rs); otherwise it prints
# "BEAT SKIP ..." and the rehearsal still passes. DEMO_CALLS=0 skips it on
# purpose; DEMO_CALLS=1 insists (SKIP, clearly labelled, if calls are absent).
#
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

case "${DEMO_CALLS:-auto}" in
  0 | off | no)
    DEMO_REHEARSAL_CALLS=skip
    DEMO_REHEARSAL_CALLS_SKIP="disabled by DEMO_CALLS=${DEMO_CALLS}" ;;
  *)
    if [[ -f crates/konsensus-core/src/payloads/call.rs ]]; then
      DEMO_REHEARSAL_CALLS=run
      DEMO_REHEARSAL_CALLS_SKIP=
    else
      DEMO_REHEARSAL_CALLS=skip
      DEMO_REHEARSAL_CALLS_SKIP="paid 1:1 calls (PR #131) are not merged into this checkout"
    fi ;;
esac
export DEMO_REHEARSAL_CALLS DEMO_REHEARSAL_CALLS_SKIP
echo "Call beat: ${DEMO_REHEARSAL_CALLS}${DEMO_REHEARSAL_CALLS_SKIP:+ ($DEMO_REHEARSAL_CALLS_SKIP)}"

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

CALL_BEAT = "1:1 call offer paid once at call_msat, answered and hung up"
REQUIRED = [
    "front-door card created and exported as link",
    "front-door card verified",
    "first contact with owner approval (front-door knock, paid once)",
    "paid message",
    "paid reply",
    "voice note sent as paid file and received",
    CALL_BEAT,
    "refusal over cap at 0 msat",
    "exact msat reconciliation",
]
# The only beat allowed to SKIP, and only when this script decided so.
SKIPPABLE = {CALL_BEAT} if os.environ.get("DEMO_REHEARSAL_CALLS") != "run" else set()
BEAT_RE = re.compile(r"^BEAT (PASS|FAIL) (.+): ([0-9.]+)s\s*$")
SKIP_RE = re.compile(r"^BEAT (SKIP) (.+?): (.+)$")

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
        match = BEAT_RE.match(line.rstrip("\n")) or SKIP_RE.match(line.rstrip("\n"))
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
        elif found[0] == "SKIP" and expected in SKIPPABLE:
            print(f"BEAT SKIP {expected}: {found[2]}", flush=True)
        elif found[0] != "PASS":
            print(f"BEAT FAIL {expected}: {found[0]} {found[2]}", flush=True)
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
    passed = sum(1 for b in beats if b[0] == "PASS")
    skipped = [b[1] for b in beats if b[0] == "SKIP"]
    note = f", {len(skipped)} SKIP ({'; '.join(skipped)})" if skipped else ""
    print(
        f"DEMO-REHEARSAL PASS {passed}/{len(REQUIRED)} beats{note} in {elapsed:.1f}s",
        flush=True,
    )
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
