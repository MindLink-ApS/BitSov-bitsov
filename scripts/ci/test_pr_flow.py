"""Regression tests for the PR flow gates (no network required)."""

from pathlib import Path
import unittest

from scripts.ci.pr_flow import (
    file_is_counted, has_design_note, is_counted, positive_int, publish, run_all,
    size_status, wip_statuses,
)

WORKFLOWS = Path(__file__).resolve().parents[2] / ".github/workflows"


def pr(number, created, labels=(), draft=False, state="open", sha=None):
    return {"number": number, "created_at": created, "draft": draft, "state": state,
            "labels": [{"name": name} for name in labels],
            "head": {"sha": sha or f"{number:040x}"}}


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

    def test_priority_order_is_m6_deadline_then_security_money_then_merge_ready(self):
        prs = [pr(1, "2026-10-01"), pr(2, "2026-10-02", ["merge-ready"]),
               pr(3, "2026-10-03", ["money"]), pr(4, "2026-10-04", ["security"]),
               pr(5, "2026-10-05", ["deadline"]), pr(6, "2026-10-06", ["M6"])]
        statuses = wip_statuses(prs, 6)
        order = sorted(range(1, 7), key=lambda n: int(statuses[sha(n)][1].split()[3]))
        # m6/deadline share rank 0 (older first), then security/money (older first),
        # then merge-ready, then unlabelled.
        self.assertEqual(order, [5, 6, 3, 4, 2, 1])

    def test_drafts_get_a_neutral_success_and_take_no_slot(self):
        prs = [pr(1, "2026-10-01", draft=True), pr(2, "2026-10-02", state="closed"),
               pr(3, "2026-10-03")]
        statuses = wip_statuses(prs, 1)
        self.assertEqual(statuses[sha(3)], ("success", "in WIP slot 1 of 1"))
        self.assertEqual(statuses[sha(1)], ("success", "draft: not in the WIP queue"))
        self.assertNotIn(sha(2), statuses)

    def test_shared_head_sha_is_in_review_if_any_pr_holds_a_slot(self):
        shared = "c" * 40
        prs = [pr(1, "2026-10-01", sha=shared), pr(2, "2026-10-02"),
               pr(3, "2026-10-03", sha=shared)]
        statuses = wip_statuses(prs, 1)
        self.assertEqual(statuses[shared][0], "success")
        self.assertEqual(statuses[sha(2)][0], "pending")


class SizeTests(unittest.TestCase):
    def files(self, *pairs):
        return [{"filename": name, "additions": lines, "deletions": 0} for name, lines in pairs]

    def test_tests_lockfiles_vendor_fixtures_and_evidence_are_not_counted(self):
        for path in ("Cargo.lock", "vendor/ldk-node/src/lib.rs", "crates/a/tests/x.rs",
                     "crates/a/src/foo_tests.rs", "crates/a/src/tests.rs",
                     "scripts/ci/test_pr_flow.py", "crates/a/tests/fixtures/x.json",
                     "fixtures/contract.json", "docs/testing/issue-1/run.log.gz", "CHANGELOG.md"):
            self.assertFalse(is_counted(path), path)
        for path in ("crates/a/src/lib.rs", "scripts/latest_report.py", ".github/workflows/ci.yml",
                     "docs/ops/RUNBOOK.md"):
            self.assertTrue(is_counted(path), path)

    def test_a_rename_into_tests_still_counts(self):
        moved = {"filename": "crates/a/tests/gate.rs", "previous_filename": "crates/a/src/gate.rs",
                 "additions": 400, "deletions": 400}
        self.assertTrue(file_is_counted(moved))
        self.assertEqual(size_status([moved], [], "", 500)[0], "failure")

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

    def test_design_note_needs_text_and_accepts_crlf(self):
        self.assertFalse(has_design_note("## Design note\n\n## Tests\nok"))
        self.assertFalse(has_design_note("## Design notes are optional\ntext"))
        self.assertTrue(has_design_note("### design note\n- the why"))
        self.assertTrue(has_design_note("Summary\r\n\r\n## Design note\r\nThe why.\r\n"))


class RunAllTests(unittest.TestCase):
    def make_api(self, prs, details, files, existing=None):
        posted = []
        existing = existing or {}

        def api(endpoint, *, method="GET", payload=None, paginate=False):
            if method == "POST":
                posted.append((endpoint.rsplit("/", 1)[1], payload["context"], payload["state"]))
                return {}
            if endpoint.endswith("/status"):
                head = endpoint.split("/")[-2]
                return {"statuses": existing.get(head, [])}
            if "/files" in endpoint:
                return files[int(endpoint.split("/pulls/")[1].split("/")[0])]
            if "/pulls/" in endpoint:
                return details[int(endpoint.rsplit("/", 1)[1])]
            return prs
        return api, posted

    def detail(self, number, changed, labels=(), body="", head=None):
        return {"head": {"sha": head or sha(number)}, "changed_files": changed,
                "labels": [{"name": n} for n in labels], "body": body}

    def test_publishes_both_contexts_for_every_open_pr(self):
        prs = [pr(1, "2026-10-01"), pr(2, "2026-10-02", draft=True)]
        details = {1: self.detail(1, 1), 2: self.detail(2, 1)}
        files = {1: [{"filename": "src/a.rs", "additions": 10, "deletions": 0}],
                 2: [{"filename": "src/b.rs", "additions": 900, "deletions": 0}]}
        api, posted = self.make_api(prs, details, files)
        run_all("o/r", 1, 500, api=api)
        self.assertIn((sha(1), "wip-cap", "success"), posted)
        self.assertIn((sha(2), "wip-cap", "success"), posted)
        self.assertIn((sha(1), "pr-size", "success"), posted)
        self.assertIn((sha(2), "pr-size", "failure"), posted)

    def test_partial_file_list_stays_pending_and_shared_sha_keeps_the_worst_size(self):
        shared = "d" * 40
        prs = [pr(1, "2026-10-01", sha=shared), pr(2, "2026-10-02", sha=shared)]
        details = {1: self.detail(1, 1, head=shared), 2: self.detail(2, 2, head=shared)}
        files = {1: [{"filename": "src/a.rs", "additions": 900, "deletions": 0}],
                 2: [{"filename": "src/a.rs", "additions": 1, "deletions": 0}]}
        api, posted = self.make_api(prs, details, files)
        run_all("o/r", 4, 500, api=api)
        self.assertEqual([p for p in posted if p[1] == "pr-size"], [(shared, "pr-size", "failure")])

    def test_head_pushed_during_the_run_is_left_for_the_next_run(self):
        prs = [pr(1, "2026-10-01")]
        details = {1: self.detail(1, 1, head="e" * 40)}
        api, posted = self.make_api(prs, details, {1: []})
        run_all("o/r", 4, 500, api=api)
        self.assertEqual([p for p in posted if p[1] == "pr-size"], [])

    def test_unchanged_status_is_not_posted_again(self):
        posted = []
        status = {"context": "wip-cap", "state": "success", "description": "in WIP slot 1 of 4"}

        def api(endpoint, *, method="GET", payload=None, paginate=False):
            if method == "POST":
                posted.append(payload)
                return {}
            return {"statuses": [status]}

        self.assertFalse(publish(api, "repos/o/r", "a" * 40, "wip-cap", "success", "in WIP slot 1 of 4"))
        self.assertTrue(publish(api, "repos/o/r", "a" * 40, "wip-cap", "pending", "queued"))
        self.assertEqual(len(posted), 1)


class ConfigTests(unittest.TestCase):
    def test_positive_int_falls_back_on_blank_or_invalid(self):
        self.assertEqual(positive_int("", 4), 4)
        self.assertEqual(positive_int(None, 4), 4)
        self.assertEqual(positive_int("0", 4), 4)
        self.assertEqual(positive_int("x", 4), 4)
        self.assertEqual(positive_int(" 6 ", 4), 6)

    def test_publisher_runs_from_trusted_code_and_never_on_pull_request(self):
        text = (WORKFLOWS / "pr-flow.yml").read_text()
        self.assertIn("workflow_run:", text)
        self.assertNotIn("pull_request", text.split("jobs:")[0])
        self.assertIn("scripts/ci/pr_flow.py scripts/ci/test_pr_flow.py", text)
        self.assertIn('== *"HTTP 404"*', text)
        self.assertIn("python3 -m unittest scripts/ci/test_pr_flow.py", text)
        self.assertNotIn("actions/checkout", text)

    def test_trigger_has_no_permissions_and_runs_nothing_from_the_pr(self):
        text = (WORKFLOWS / "pr-flow-trigger.yml").read_text()
        self.assertIn("permissions: {}", text)
        self.assertNotIn("actions/checkout", text)
        self.assertNotIn("${{ github.event.pull_request", text)


if __name__ == "__main__":
    unittest.main()
