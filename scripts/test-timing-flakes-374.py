#!/usr/bin/env python3
"""Reproduce #374's serial full-workspace stress proof (mock/regtest only)."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time


FOCUS = {
    "regression_signed_request_expiry_is_enforced_at_approval",
    "expired_candidate_resubmission_persists_terminal_expiry_even_on_refusal",
    "reconciliation_cannot_release_a_live_dispatch_from_an_older_failed_record",
    "sponsor::cancelled_owner_dispatch_retains_its_purse_reservation_for_restart",
    "node::tests::offline_fee_barrier_preserves_local_identity_and_storage",
    "local_owner_unavailable_verifier_refuses_start_without_writing_files",
    "disconnected_client_does_not_cancel_outcome_recording",
}
RECONNECT = "session_handler::budgeted_reconnect_two_node::"
COMMAND = ["cargo", "test", "--workspace", "--no-fail-fast"]


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=30)
    parser.add_argument("--load-runs", type=int, default=10)
    args = parser.parse_args()
    if not 0 <= args.load_runs <= args.runs or args.runs < 1:
        parser.error("require runs >= 1 and 0 <= load-runs <= runs")
    args.log_dir.mkdir(parents=True, exist_ok=False)
    # Never accidentally inherit serial libtest execution from a developer shell.
    env = os.environ.copy()
    env.pop("RUST_TEST_THREADS", None)
    source_diff = subprocess.check_output(["git", "diff", "--binary", "--", "crates"])
    report = {
        "command": COMMAND,
        "base_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "source_diff_sha256": hashlib.sha256(source_diff).hexdigest(),
        "concurrency": "libtest default; RUST_TEST_THREADS unset; no --test-threads",
        "cpu_workers_per_loaded_run": 8,
        "requested_runs": args.runs,
        "requested_loaded_runs": args.load_runs,
        "suite_watchdog_seconds": 1800,
        "started_utc": utc_now(),
        "runs": [],
        "pass_counts": {},
    }
    # Keep the exact tested patch alongside raw logs, before later documentation edits.
    (args.log_dir / "source.diff").write_bytes(source_diff)
    for number in range(1, args.runs + 1):
        loaded = number <= args.load_runs
        workers = []
        child = None
        logfile = args.log_dir / f"run-{number:02}.log"
        entry = {"run": number, "loaded": loaded, "started_utc": utc_now()}
        started = time.monotonic()
        try:
            if loaded:
                workers = [subprocess.Popen(["yes"], stdout=subprocess.DEVNULL) for _ in range(8)]
            print(f"Run {number}/{args.runs}: starting ({'8 CPU workers' if loaded else 'no added CPU load'})", flush=True)
            with logfile.open("w") as log:
                child = subprocess.Popen(COMMAND, stdout=log, stderr=subprocess.STDOUT,
                                         env=env, start_new_session=True)
                try:
                    entry["exit_code"] = child.wait(timeout=1800)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGTERM)
                    try:
                        child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait()
                    entry["exit_code"] = "suite_watchdog"
            entry["cpu_workers_alive_at_finish"] = sum(p.poll() is None for p in workers)
        finally:
            if child is not None and child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                child.wait()
            for worker in workers:
                if worker.poll() is None:
                    worker.terminate()
            for worker in workers:
                worker.wait()
        entry["elapsed_seconds"] = round(time.monotonic() - started, 3)
        raw = logfile.read_bytes()
        output = raw.decode(errors="replace")
        entry["log_sha256"] = hashlib.sha256(raw).hexdigest()
        passed = re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE)
        focus = sorted(name for name in passed if name in FOCUS or name.startswith(RECONNECT))
        entry["focus_passes"] = focus
        entry["test_summaries"] = re.findall(r"^test result: .*$", output, re.MULTILINE)
        entry["failures"] = re.findall(r"^test (\S+) \.\.\. FAILED$", output, re.MULTILINE)
        missing = sorted(FOCUS - set(focus))
        reconnect_count = sum(name.startswith(RECONNECT) for name in focus)
        entry["missing_focus_tests"] = missing
        entry["reconnect_passes"] = reconnect_count
        entry["passed"] = (entry["exit_code"] == 0 and not missing and reconnect_count == 21
                           and not entry["failures"] and bool(entry["test_summaries"])
                           and (not loaded or entry["cpu_workers_alive_at_finish"] == 8))
        for name in focus:
            report["pass_counts"][name] = report["pass_counts"].get(name, 0) + 1
        report["runs"].append(entry)
        report["consecutive_full_passes"] = sum(run["passed"] for run in report["runs"])
        report["finished_utc"] = utc_now()
        (args.log_dir / "results.json").write_text(json.dumps(report, indent=2) + "\n")
        print(f"Run {number}: {'PASS' if entry['passed'] else 'FAIL'} in {entry['elapsed_seconds']}s; "
              f"{len(focus)} focused tests; log {logfile}", flush=True)
        if not entry["passed"]:
            raise SystemExit("Stopped at first failed run; fix before starting a new consecutive series.")
    print(f"Verified {args.runs} consecutive full passes, {args.load_runs} under CPU load.", flush=True)


if __name__ == "__main__":
    main()
