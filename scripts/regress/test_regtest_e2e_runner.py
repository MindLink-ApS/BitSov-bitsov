#!/usr/bin/env python3
"""Exercise the real runner's cleanup without Cargo, Bitcoin Core or electrs."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


RUNNER = Path(__file__).with_name("regtest_e2e.sh")
# Stand in for Cargo and its node/daemon descendants. The descendants ignore
# SIGTERM deliberately, so cleaning up just Cargo cannot satisfy the test.
FAKE_CARGO = '''#!/usr/bin/env python3
import json, os, pathlib, signal, subprocess, sys
daemon = """import signal
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print('ready', flush=True)
while True:
    signal.pause()
"""
children = [subprocess.Popen([sys.executable, '-c', daemon],
                            stdout=subprocess.PIPE, text=True) for _ in range(3)]
for child in children:
    assert child.stdout.readline() == 'ready\\n'
root = pathlib.Path(os.environ['TMPDIR'])
for name in ('bitcoind', 'electrs', 'nodes'):
    (root / name).mkdir()
probe = pathlib.Path(os.environ['PROBE'])
pending = probe.with_suffix('.tmp')
pending.write_text(json.dumps(dict(cargo=os.getpid(), supervisor=os.getppid(),
    descendants=[child.pid for child in children], root=str(root))))
pending.rename(probe)
mode = os.environ['PROBE_MODE']
if mode == 'success':
    sys.exit(0)
if mode == 'failure':
    sys.exit(17)
while True:
    signal.pause()
'''

# Deliver cancellation after the OS child exists but before the supervisor's
# Popen call returns. This makes the otherwise tiny launch race deterministic.
INTERRUPT_LAUNCH = '''import os, signal, subprocess, time
original = subprocess.Popen
def popen(*args, **kwargs):
    child = original(*args, **kwargs)
    if args[0][0] == 'cargo':
        deadline = time.monotonic() + 10
        while not os.path.exists(os.environ['PROBE']):
            if time.monotonic() >= deadline:
                raise RuntimeError('fake Cargo did not start')
            time.sleep(0.02)
        os.kill(os.getpid(), signal.SIGTERM)
    return child
subprocess.Popen = popen
'''


def alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def kill(pid, sig, group=False):
    try:
        (os.killpg if group else os.kill)(pid, sig)
    except ProcessLookupError:
        pass


def wait_until(check, timeout=10):
    deadline = time.monotonic() + timeout
    while not check():
        if time.monotonic() >= deadline:
            raise AssertionError("timed out waiting for runner lifecycle condition")
        time.sleep(0.02)


class RunnerCleanup(unittest.TestCase):
    def check_cleanup(self, mode, expected, sig=None, group=False, launch=False):
        with tempfile.TemporaryDirectory(prefix="bitsov-runner-check-") as temporary:
            directory = Path(temporary)
            cargo = directory / "cargo"
            cargo.write_text(FAKE_CARGO)
            cargo.chmod(0o755)
            probe = directory / "probe.json"
            env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}",
                       BITCOIND_EXE=shutil.which("true"),
                       ELECTRS_EXE=shutil.which("true"),
                       PROBE=str(probe), PROBE_MODE=mode,
                       REGTEST_TIMEOUT_SECONDS="2" if mode == "timeout" else "60")
            if launch:
                (directory / "sitecustomize.py").write_text(INTERRUPT_LAUNCH)
                env["PYTHONPATH"] = str(directory)
            data = None
            with (directory / "runner.log").open("w+") as log:
                runner = subprocess.Popen(["bash", str(RUNNER)], env=env,
                                          stdout=log, stderr=log,
                                          start_new_session=True)
                try:
                    wait_until(probe.exists)
                    data = json.loads(probe.read_text())
                    if sig is not None:
                        kill(runner.pid, sig, group=group)
                    result = runner.wait(timeout=15)
                    log.seek(0)
                    self.assertEqual(result, expected, log.read())
                    self.assertFalse(Path(data["root"]).exists(), "data root leaked")
                    pids = [data["supervisor"], data["cargo"], *data["descendants"]]
                    wait_until(lambda: not any(alive(pid) for pid in pids))
                finally:
                    # Also clean up when probing a broken runner.
                    if data is not None:
                        kill(data["supervisor"], signal.SIGTERM)
                        kill(data["cargo"], signal.SIGKILL, group=True)
                    kill(runner.pid, signal.SIGKILL, group=True)
                    runner.wait(timeout=10)
                    if data is not None:
                        wait_until(lambda: not alive(data["supervisor"]))
                        shutil.rmtree(data["root"], ignore_errors=True)

    def test_normal_exit_failure_and_timeout(self):
        for mode, expected in (("success", 0), ("failure", 17), ("timeout", 124)):
            with self.subTest(mode=mode):
                self.check_cleanup(mode, expected)

    def test_signals_to_runner_pid_and_group(self):
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            for group in (False, True):
                with self.subTest(signal=sig.name, group=group):
                    self.check_cleanup("signal", 128 + sig, sig, group)

    def test_signal_during_child_launch(self):
        self.check_cleanup("signal", 143, launch=True)


class MissingFixtures(unittest.TestCase):
    def test_missing_binary_still_builds_and_reports_skip(self):
        for build_exit in (0, 17):
            with self.subTest(build_exit=build_exit), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                cargo = directory / "cargo"
                cargo.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PROBE\"\nexit " + str(build_exit) + "\n")
                cargo.chmod(0o755)
                probe = directory / "args"
                env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}",
                           BITCOIND_EXE=str(directory / "missing-bitcoind"),
                           ELECTRS_EXE=str(directory / "missing-electrs"), PROBE=str(probe))
                result = subprocess.run(["bash", str(RUNNER.with_name("three_node_paid_e2e.sh"))],
                                        env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 77 if build_exit == 0 else build_exit, result.stdout + result.stderr)
                args = probe.read_text().splitlines()
                for required in ("--offline", "--locked", "--no-run", "regtest-e2e"):
                    self.assertIn(required, args)
                self.assertNotIn("--ignored", args)
                self.assertEqual("SKIP three-node paid E2E" in result.stdout, build_exit == 0)


class GhostGate(unittest.TestCase):
    def test_full_suite_excludes_pending_ghost_scenario(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                cargo = directory / "cargo"
                cargo.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PROBE\"\n")
                cargo.chmod(0o755)
                probe = directory / "args"
                env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}",
                           BITCOIND_EXE=shutil.which("true"), ELECTRS_EXE=shutil.which("true"),
                           PROBE=str(probe), REGTEST_GHOST_AFTER_PR200="1" if enabled else "0")
                env.pop("REGTEST_TEST", None)
                result = subprocess.run(["bash", str(RUNNER)], env=env,
                                        capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                args = probe.read_text().splitlines()
                self.assertIn("regtest_e2e::", args)
                self.assertEqual("--skip" in args, not enabled)
                if not enabled:
                    self.assertEqual(args[args.index("--skip") + 1],
                                     "regtest_e2e::three_node::ghost_unfunded_channel_requires_pr200")
                self.assertEqual("SKIP ghost/unfunded-channel" in result.stdout, not enabled)

    def test_named_gate_and_failures_propagate(self):
        for enabled, main_exit, ghost_exit in ((False, 0, 0), (True, 0, 0),
                                              (True, 17, 0), (True, 0, 19)):
            with self.subTest(enabled=enabled, main_exit=main_exit, ghost_exit=ghost_exit), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                cargo = directory / "cargo"
                cargo.write_text("""#!/usr/bin/env python3
import json, os, sys
with open(os.environ['PROBE'], 'a') as probe:
    probe.write(json.dumps(sys.argv[1:]) + '\\n')
main_exit = int(os.environ['MAIN_EXIT'])
sys.exit(main_exit or (int(os.environ['GHOST_EXIT']) if '--skip' not in sys.argv else 0))
""")
                cargo.chmod(0o755)
                probe = directory / "args"
                env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}",
                           BITCOIND_EXE=shutil.which("true"), ELECTRS_EXE=shutil.which("true"),
                           PROBE=str(probe), REGTEST_GHOST_AFTER_PR200="1" if enabled else "0",
                           MAIN_EXIT=str(main_exit), GHOST_EXIT=str(ghost_exit))
                result = subprocess.run(["bash", str(RUNNER.with_name("three_node_paid_e2e.sh"))],
                                        env=env, capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, main_exit or (ghost_exit if enabled else 0),
                                 result.stdout + result.stderr)
                calls = [json.loads(line) for line in probe.read_text().splitlines()]
                self.assertIn("regtest_e2e::three_node::", calls[0])
                self.assertEqual(len(calls), 1, "both scenarios share one supervised process group")
                self.assertEqual("--skip" in calls[0], not enabled)
                self.assertEqual("SKIP ghost/unfunded-channel" in result.stdout,
                                 not enabled)


# Stand in for Cargo under the nightly 1:1 call lane (#411). Prints what
# libtest prints for `--ignored --nocapture` runs, minus whatever CALLS_MODE
# withholds, so the gate's log checks are exercised without LDK or bitcoind.
FAKE_CALLS_CARGO = """#!/usr/bin/env python3
import json, os, sys
with open(os.environ['PROBE'], 'a') as probe:
    probe.write(json.dumps(sys.argv[1:]) + '\\n')
mode = os.environ['CALLS_MODE']
steps = [
    'STEP PASS chain + 3 real LDK nodes started: 4.0s (elapsed 4.0s)',
    "STEP PASS call offer paid at call_msat and forwarded to B's WS: 1.0s (elapsed 30.0s)",
    'STEP PASS answer, ICE and hangup paid and delivered both ways: 1.1s (elapsed 31.1s)',
    'STEP PASS ICE after hangup refused before paying: 0.1s (elapsed 31.2s)',
    'STEP PASS msat reconciliation: channels and budgets: 0.2s (elapsed 31.4s)',
    'REGTEST-CALLS PASS; offer, answer, ICE and hangup paid and delivered; complete in 40.1s',
]
if mode == 'filtered':
    print('running 0 tests')
    print()
    print('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 212 filtered out; finished in 0.00s')
    sys.exit(0)
print('running 1 test')
print('test regtest_e2e::real_ldk_regtest_calls ... ', end='')
if mode == 'fail':
    print(steps[0])
    print('thread panicked at offer: assertion failed')
    print('FAILED')
    print()
    print('test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 211 filtered out; finished in 9.00s')
    sys.exit(101)
withheld = {'no-hangup': 'STEP PASS answer, ICE and hangup', 'no-verdict': 'REGTEST-CALLS PASS;'}.get(mode)
for line in steps:
    if withheld is None or withheld not in line:
        print(line)
print('ok')
print()
print('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 211 filtered out; finished in 40.10s')
sys.exit(0)
"""


class CallsLaneGate(unittest.TestCase):
    """scripts/regress/calls_e2e.sh fails unless the calls regtest ran to the end."""

    def run_lane(self, mode, fixtures=True, extra_env=None):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            cargo = directory / "cargo"
            cargo.write_text(FAKE_CALLS_CARGO)
            cargo.chmod(0o755)
            probe = directory / "args"
            log = directory / "calls.log"
            fixture = shutil.which("true") if fixtures else str(directory / "missing")
            env = dict(os.environ, PATH=f"{directory}:{os.environ['PATH']}",
                       BITCOIND_EXE=fixture, ELECTRS_EXE=fixture, PROBE=str(probe),
                       CALLS_MODE=mode, REGTEST_CALLS_LOG=str(log))
            env.pop("REGTEST_TEST", None)
            env.update(extra_env or {})
            result = subprocess.run(["bash", str(RUNNER.with_name("calls_e2e.sh"))],
                                    env=env, capture_output=True, text=True, timeout=15, cwd=temporary)
            calls = [json.loads(line) for line in probe.read_text().splitlines()] if probe.exists() else []
            return result, calls, log.read_text() if log.exists() else ""

    def test_complete_run_passes_and_selects_only_the_calls_test(self):
        result, calls, log = self.run_lane("full")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(calls), 1, "one supervised Cargo invocation")
        args = calls[0]
        self.assertIn("regtest_e2e::real_ldk_regtest_calls", args)
        self.assertIn("--ignored", args)
        self.assertIn("regtest-e2e", args)
        self.assertNotIn("--no-run", args)
        self.assertNotIn("regtest_e2e::", args, "the lane runs one proof, not the whole suite")
        self.assertIn("REGTEST-CALLS PASS;", log, "the log is retained for evidence")
        self.assertIn("REAL-LDK CALLS LANE PASS", result.stdout)

    def test_zero_tests_is_a_failure_even_though_cargo_exits_zero(self):
        result, calls, _ = self.run_lane("filtered")
        self.assertEqual(len(calls), 1)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("did not run", result.stdout)
        self.assertNotIn("REAL-LDK CALLS LANE PASS", result.stdout)

    def test_missing_phase_or_verdict_fails(self):
        for mode, marker in (("no-hangup", "STEP PASS answer, ICE and hangup"), ("no-verdict", "REGTEST-CALLS PASS;")):
            with self.subTest(mode=mode):
                result, calls, _ = self.run_lane(mode)
                self.assertEqual(len(calls), 1)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("incomplete; missing: " + marker, result.stdout)

    def test_cargo_failure_code_propagates(self):
        result, calls, _ = self.run_lane("fail")
        self.assertEqual(len(calls), 1)
        self.assertEqual(result.returncode, 101, result.stdout + result.stderr)
        self.assertNotIn("REAL-LDK CALLS LANE PASS", result.stdout)

    def test_gate_markers_are_printed_by_the_rust_test(self):
        # The gate greps for prose the Rust test prints; a renamed step must
        # fail here, offline, rather than silently turn the nightly red.
        import re
        gate = RUNNER.with_name("calls_e2e.sh").read_text()
        block = re.search(r"required=\((.*?)\)", gate, re.S).group(1)
        markers = [m[0] or m[1] for m in re.findall(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'', block)]
        markers = [m for m in markers if m]
        self.assertEqual(len(markers), 4, markers)
        source = (RUNNER.parents[2] / "crates/konsensus-node/src/tests/regtest_e2e.rs").read_text()
        calls = source[source.index("async fn real_ldk_regtest_calls()"):source.index("async fn real_ldk_regtest_meeting()")]
        for marker in markers:
            text = marker.removeprefix("STEP PASS ")
            with self.subTest(marker=marker):
                self.assertTrue(text in calls, f"gate marker not printed by real_ldk_regtest_calls: {marker}")

    def test_missing_fixtures_fail_instead_of_skipping(self):
        # REGTEST_ALLOW_MISSING=1 would let the shared runner compile and SKIP (77);
        # the calls lane ignores it: no fixtures means no Cargo run and exit 1.
        result, calls, _ = self.run_lane("full", fixtures=False, extra_env={"REGTEST_ALLOW_MISSING": "1"})
        self.assertEqual(calls, [], "Cargo must not run without fixtures")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("SKIP", result.stdout)
        self.assertNotIn("REAL-LDK CALLS LANE PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
