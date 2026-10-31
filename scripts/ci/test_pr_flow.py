"""Regression tests for the PR flow gates (no network required)."""

from pathlib import Path
import unittest

from scripts.ci.pr_flow import (
    has_design_note, is_counted, positive_int, run_pr_size, run_wip_cap, size_status,
    wip_statuses,
)

WORKFLOW = Path(__file__).resolve().parents[2] / ".github/workflows/pr-flow.yml"


def pr(number, created, labels=(), draft=False, state="open"):
    return {"number": number, "created_at": created, "draft": draft, "state": state,
            "labels": [{"name": name} for name in labels],
            "head": {"sha": f"{number:040x}"}}


def sha(number):
    return f"{number:040x}"


class WipCapTests(unittest.TestCase):
    def test_first_cap_prs_get_slots_and_the_rest_queue(self):
        prs = [pr(n, f"2026-10-{n:02d}") for n in range(1, 7)]
        statuses = wip_statuses(prs, 4)
        self.assertEqual([statuses[sha(n)][0] for n in range(1, 7)],
                         ["success"] * 4 + ["pending"] * 2)
        self.assertIn("1 beyond WIP cap 4", statuses[sha(5)][1])
        self.assertIn("2 beyond WIP cap 4", statuses[sha(6)][1])

    def test_priority_label_beats_age(self):
        prs = [pr(1, "2026-10-01"), pr(2, "2026-10-02"), pr(3, "2026-10-30", ["m6"])]
        statuses = wip_statuses(prs, 1)
        self.assertEqual(statuses[sha(3)][0], "success")
        self.assertEqual(statuses[sha(1)][0], "pending")

    def test_security_ranks_after_m6_and_before_unlabelled(self):
        prs = [pr(1, "2026-10-01"), pr(2, "2026-10-29", ["security"]),
               pr(3, "2026-10-30", ["M6"])]
        statuses = wip_statuses(prs, 2)
        self.assertEqual(statuses[sha(3)][0], "success")  # labels are case-insensitive
        self.assertEqual(statuses[sha(2)][0], "success")
        self.assertEqual(statuses[sha(1)][0], "pending")

    def test_drafts_and_closed_prs_take_no_slot_and_get_no_status(self):
        prs = [pr(1, "2026-10-01", draft=True), pr(2, "2026-10-02", state="closed"),
               pr(3, "2026-10-03")]
        statuses = wip_statuses(prs, 1)
        self.assertEqual(set(statuses), {sha(3)})
        self.assertEqual(statuses[sha(3)][0], "success")

    def test_run_wip_cap_posts_one_status_per_open_pr(self):
        posted = []

        def api(endpoint, *, method="GET", payload=None, paginate=False):
            if method == "POST":
                posted.append((endpoint, payload))
                return {}
            self.assertTrue(paginate)
            return [pr(1, "2026-10-01"), pr(2, "2026-10-02"), pr(3, "2026-10-03", draft=True)]

        run_wip_cap("o/r", 1, api=api)
        self.assertEqual([(e.rsplit("/", 1)[1], p["state"]) for e, p in posted],
                         [(sha(1), "success"), (sha(2), "pending")])
        self.assertTrue(all(p["context"] == "wip-cap" for _, p in posted))


class SizeTests(unittest.TestCase):
    def files(self, *pairs):
        return [{"filename": name, "additions": lines, "deletions": 0} for name, lines in pairs]

    def test_tests_lockfiles_vendor_and_evidence_are_not_counted(self):
        for path in ("Cargo.lock", "vendor/ldk-node/src/lib.rs", "crates/a/tests/x.rs",
                     "crates/a/src/foo_tests.rs", "crates/a/src/tests.rs",
                     "scripts/ci/test_pr_flow.py", "crates/a/tests/fixtures/x.json",
                     "docs/testing/issue-1/run.log.gz", "CHANGELOG.md"):
            self.assertFalse(is_counted(path), path)
        for path in ("crates/a/src/lib.rs", "scripts/latest_report.py", ".github/workflows/ci.yml",
                     "docs/ops/RUNBOOK.md"):
            self.assertTrue(is_counted(path), path)

    def test_small_pr_passes(self):
        state, description = size_status(self.files(("src/a.rs", 300), ("tests/b.rs", 900)), [], "", 500)
        self.assertEqual(state, "success")
        self.assertIn("300 counted lines", description)

    def test_deletions_count(self):
        files = [{"filename": "src/a.rs", "additions": 300, "deletions": 250}]
        self.assertEqual(size_status(files, [], "", 500)[0], "failure")

    def test_large_pr_fails_without_label_and_note(self):
        files = self.files(("src/a.rs", 501))
        self.assertEqual(size_status(files, [], "", 500)[0], "failure")
        self.assertEqual(size_status(files, ["large-ok"], "", 500)[0], "failure")
        self.assertEqual(size_status(files, [], "## Design note\nwhy\n", 500)[0], "failure")

    def test_large_pr_passes_with_label_and_note(self):
        body = "Summary\n\n## Design note\n\nOne owner decision, one migration.\n"
        self.assertEqual(size_status(self.files(("src/a.rs", 2000)), ["Large-OK"], body, 500)[0],
                         "success")

    def test_design_note_needs_text_before_the_next_heading(self):
        self.assertFalse(has_design_note("## Design note\n\n## Tests\nok"))
        self.assertFalse(has_design_note("## Design notes are optional\ntext"))
        self.assertTrue(has_design_note("### design note\n- the why"))

    def test_partial_file_list_stays_pending(self):
        posted = []

        def api(endpoint, *, method="GET", payload=None, paginate=False):
            if method == "POST":
                posted.append(payload)
                return {}
            if paginate:
                return [{"filename": "src/a.rs", "additions": 1, "deletions": 0}]
            return {"head": {"sha": "a" * 40}, "changed_files": 2, "labels": [], "body": ""}

        run_pr_size("o/r", 7, 500, api=api)
        self.assertEqual(posted[0]["state"], "pending")
        self.assertEqual(posted[0]["context"], "pr-size")


class ConfigTests(unittest.TestCase):
    def test_positive_int_falls_back_on_blank_or_invalid(self):
        self.assertEqual(positive_int("", 4), 4)
        self.assertEqual(positive_int(None, 4), 4)
        self.assertEqual(positive_int("0", 4), 4)
        self.assertEqual(positive_int("x", 4), 4)
        self.assertEqual(positive_int(" 6 ", 4), 6)

    def test_workflow_loads_trusted_scripts_and_runs_tests(self):
        text = WORKFLOW.read_text()
        self.assertIn("scripts/ci/pr_flow.py scripts/ci/test_pr_flow.py", text)
        self.assertIn("python3 -m unittest scripts/ci/test_pr_flow.py", text)
        self.assertNotIn("actions/checkout", text)


if __name__ == "__main__":
    unittest.main()
