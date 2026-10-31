"""Regression tests for the nightly flaky-test report (no network required)."""

from pathlib import Path
import unittest

from scripts.ci.flaky_report import (
    collect, failed_tests, is_flaky_signal, issue_title, report,
)

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/flaky-report.yml"
LOG = """2026-10-30T21:40:45.4316470Z test owner_added_peer_survives_restart_and_config_still_wins ... FAILED
2026-10-30T21:40:45.4316917Z failures:
2026-10-30T21:40:45.4317267Z ---- owner_added_peer_survives_restart_and_config_still_wins stdout ----
2026-10-30T21:40:45.4318011Z thread 'x' panicked at crates/konsensus-node/tests/peer_add_restart.rs:137:14:
2026-10-30T21:40:46.0000000Z test other::passing_test ... ok
"""


def run(run_id, attempt, conclusion, head="a" * 40):
    return {"id": run_id, "run_attempt": attempt, "conclusion": conclusion, "head_sha": head,
            "name": "CI", "html_url": f"https://example.invalid/runs/{run_id}",
            "created_at": "2026-10-30T21:17:00Z", "head_branch": "harden/x"}


class ParseTests(unittest.TestCase):
    def test_failed_tests_from_a_timestamped_cargo_log(self):
        self.assertEqual(failed_tests(LOG),
                         ["owner_added_peer_survives_restart_and_config_still_wins"])

    def test_no_failures_and_empty_logs(self):
        self.assertEqual(failed_tests("test a ... ok\n"), [])
        self.assertEqual(failed_tests(None), [])

    def test_flaky_signal_needs_same_commit_failure_then_success(self):
        self.assertTrue(is_flaky_signal(run(1, 1, "failure"), run(1, 2, "success")))
        self.assertFalse(is_flaky_signal(run(1, 1, "failure"), run(1, 1, "success")))
        self.assertFalse(is_flaky_signal(run(1, 1, "success"), run(1, 2, "success")))
        self.assertFalse(is_flaky_signal(run(1, 1, "failure"), run(1, 2, "failure")))
        self.assertFalse(is_flaky_signal(run(1, 1, "failure", head="b" * 40), run(1, 2, "success")))


class FlowTests(unittest.TestCase):
    def test_collect_reads_attempt_one_failed_jobs_only(self):
        calls = []

        def api(endpoint, *, method="GET", payload=None, paginate=False, raw=False, key=None):
            calls.append(endpoint)
            if "/actions/runs?" in endpoint:
                self.assertEqual(key, "workflow_runs")
                return [run(7, 2, "success"), run(8, 1, "success"), run(9, 2, "failure")]
            if endpoint.endswith("/attempts/1"):
                return run(7, 1, "failure")
            if endpoint.endswith("/attempts/1/jobs?per_page=100"):
                return {"jobs": [{"id": 70, "conclusion": "failure"}, {"id": 71, "conclusion": "success"}]}
            if endpoint.endswith("/jobs/70/logs"):
                self.assertTrue(raw)
                return LOG
            raise AssertionError(endpoint)

        found = collect("o/r", "2026-10-30T00:00:00Z", api=api)
        self.assertEqual(list(found), ["owner_added_peer_survives_restart_and_config_still_wins"])
        self.assertFalse(any("/runs/8/" in c or "/runs/9/" in c or "/jobs/71/" in c for c in calls))

    def test_report_opens_new_issues_and_comments_on_existing_ones(self):
        posted = []
        existing = {"number": 12, "title": issue_title("old_test")}

        def api(endpoint, *, method="GET", payload=None, paginate=False, raw=False, key=None):
            if method == "POST":
                posted.append((endpoint, payload))
                return {}
            return [existing, {"number": 13, "title": issue_title("new_test"), "pull_request": {}}]

        report("o/r", {"old_test": ["- line a"], "new_test": ["- line b", "- line b"]}, api=api)
        self.assertEqual(posted[0][0], "repos/o/r/issues")
        self.assertEqual(posted[0][1]["title"], "flaky: new_test")
        self.assertEqual(posted[0][1]["labels"], ["flaky"])
        self.assertEqual(posted[0][1]["body"].count("- line b"), 1)
        self.assertEqual(posted[1][0], "repos/o/r/issues/12/comments")

    def test_workflow_is_scheduled_read_mostly_and_never_skips_tests(self):
        text = WORKFLOW.read_text()
        self.assertIn("schedule:", text)
        self.assertIn("issues: write", text)
        self.assertIn("actions: read", text)
        self.assertNotIn("pull_request", text)
        self.assertNotIn("actions/checkout", text)
        self.assertNotIn("--skip", Path(__file__).resolve().with_name("flaky_report.py").read_text())


if __name__ == "__main__":
    unittest.main()
