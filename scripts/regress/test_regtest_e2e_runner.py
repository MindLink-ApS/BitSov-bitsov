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


if __name__ == "__main__":
    unittest.main()
