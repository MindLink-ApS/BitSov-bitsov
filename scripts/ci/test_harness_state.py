"""Offline regression tests; fixtures mirror GitHub REST responses."""
from datetime import datetime, timezone
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import subprocess

import harness_state as hs


FIXTURE = Path(__file__).with_name("fixtures") / "harness_state.json"


class FixtureCase(unittest.TestCase):
    def setUp(self):
        self.data = json.loads(FIXTURE.read_text())
        self.now = datetime(2026, 10, 25, 12, tzinfo=timezone.utc)

    def state(self):
        return hs.compute_state(self.data, self.now)


class ComputationTests(FixtureCase):
    def test_open_pr_fields_and_vendor_aliases_only_on_current_head(self):
        pr = self.state()["open_prs"][0]
        self.assertEqual(pr["number"], 10)
        self.assertEqual(pr["title"], self.data["pulls"][0]["title"])
        self.assertEqual(pr["head_sha"], "a" * 40)
        self.assertEqual(pr["age_hours"], 36.0)
        self.assertFalse(pr["draft"])
        self.assertEqual(pr["labels"], ["builder:claude", "security"])
        self.assertEqual(pr["builder_label"], "builder:claude")
        self.assertEqual(set(pr["verdicts"]), {"openai", "anthropic"})
        self.assertEqual(pr["verdicts"]["openai"]["result"], "PASS")
        self.assertEqual(pr["verdicts"]["anthropic"]["vendor"], "FABLE")
        self.assertEqual(pr["verdicts"]["anthropic"]["result"], "PASS")

    def test_rerun_checks_gate_and_mergeability(self):
        first, second = self.state()["open_prs"]
        self.assertEqual((first["review_gate"], first["ci"]), ("success", "success"))
        self.assertEqual(first["mergeable_state"], "BEHIND")
        self.assertTrue(first["behind"])
        self.assertFalse(first["dirty"])
        self.assertEqual((second["review_gate"], second["ci"]), ("missing", "pending"))
        self.assertEqual(second["mergeable_state"], "DIRTY")
        self.assertTrue(second["dirty"])
        self.assertTrue(second["draft"])
        self.assertIsNone(second["builder_label"])

    def test_merge_windows_and_median_include_boundaries(self):
        state = self.state()
        self.assertEqual(state["merges"], {"last_24h": 1, "last_7d": 2})
        self.assertEqual(state["median_open_pr_age_hours"], 24.0)

    def test_first_verdict_rate_counts_prs_once_including_closed_and_stale_heads(self):
        rate = self.state()["first_verdict_7d"]
        self.assertEqual(rate, {"passed": 2, "total": 3, "pass_rate": 0.6667})

    def test_last_completed_main_e2e_result_survives_new_in_progress_run(self):
        result = self.state()["three_node_paid_e2e"]
        self.assertEqual(result["id"], 1)
        self.assertEqual(result["conclusion"], "failure")
        self.assertEqual(result["head_sha"], "d" * 40)

    def test_checklist_counts_actual_tasks_outside_code_fences(self):
        self.assertEqual(self.state()["checklist_428"], {"checked": 4, "total": 5})

    def test_empty_repository_has_no_invented_success_or_age(self):
        self.data.update(pulls=[], e2e_runs=[], checklist_body="")
        state = self.state()
        self.assertEqual(state["open_prs"], [])
        self.assertIsNone(state["median_open_pr_age_hours"])
        self.assertEqual(state["first_verdict_7d"], {"passed": 0, "total": 0, "pass_rate": None})
        self.assertIsNone(state["three_node_paid_e2e"])

    def test_unknown_merge_state_and_missing_ci_remain_explicit(self):
        pr = self.data["pulls"][0]
        pr.update(mergeable_state="unknown", check_runs=[], statuses=[])
        computed = self.state()["open_prs"][0]
        self.assertEqual(computed["mergeable_state"], "UNKNOWN")
        self.assertIsNone(computed["behind"])
        self.assertIsNone(computed["dirty"])
        self.assertEqual(computed["ci"], "missing")

    def test_new_gate_check_is_separate_from_ci_and_failed_ci_is_not_hidden(self):
        pr = self.data["pulls"][0]
        pr["statuses"] = []
        pr["check_runs"] += [
            {"id": 4, "name": "review-gate", "status": "completed", "conclusion": "failure"},
            {"id": 5, "name": "Test", "status": "completed", "conclusion": "timed_out"},
        ]
        computed = self.state()["open_prs"][0]
        self.assertEqual(computed["review_gate"], "failure")
        self.assertEqual(computed["ci"], "failure")

    def test_stale_or_short_sha_and_quoted_examples_cannot_supply_verdict(self):
        pr = self.data["pulls"][0]
        pr["reviews"] = []
        pr["comments"] = [{"created_at": "2026-10-25T10:00:00Z", "body": body} for body in [
            "CODEX-VERDICT PASS bbbbbbb", "CODEX-VERDICT PASS aaaaaa",
            "> CODEX-VERDICT PASS aaaaaaa", "~~~\nCODEX-VERDICT PASS aaaaaaa\n~~~",
            "CODEX-VERDICT PASS aaaaaaaZ", "text CODEX-VERDICT PASS aaaaaaa",
        ]]
        self.assertEqual(self.state()["open_prs"][0]["verdicts"], {})

    def comment(self, body, number=100, *, created="2026-10-25T10:00:00Z", updated=None,
                login="reviewer", association="MEMBER"):
        entry = {"id": number, "created_at": created, "body": body,
                 "user": {"login": login}, "author_association": association}
        if updated:
            entry["updated_at"] = updated
        return entry

    def head_only(self, comments, authors=""):
        pr = self.data["pulls"][0]
        pr["reviews"] = []
        pr["comments"] = comments
        return hs.compute_state(self.data, self.now, authors)

    def isolated_first(self, comments, authors=""):
        self.data["pulls"] = [self.data["pulls"][0]]
        return self.head_only(comments, authors)["first_verdict_7d"]

    def test_drive_by_accounts_cannot_set_first_or_head_verdicts(self):
        # Red team: association NONE, invented vendor and short SHA used to count.
        head = "a" * 40
        for association in ["NONE", "CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", None]:
            with self.subTest(association=association):
                comments = [self.comment(f"CODEX-VERDICT PASS {head}", 1,
                                         created="2026-10-25T01:00:00Z",
                                         login="drive-by", association=association),
                            self.comment(f"CODEX-VERDICT FAIL {head}", 2,
                                         created="2026-10-25T02:00:00Z")]
                state = self.head_only(comments)
                self.assertEqual(state["open_prs"][0]["verdicts"]["openai"]["result"], "FAIL")
                self.assertEqual(self.isolated_first(comments),
                                 {"passed": 0, "total": 1, "pass_rate": 0.0})
                self.setUp()

    def test_spammed_closed_prs_from_outsiders_do_not_move_the_rate(self):
        spam = [{"number": 1000 + n, "title": "spam", "state": "closed", "merged_at": None,
                 "comments": [self.comment("CODEX-VERDICT PASS " + "1" * 40, n,
                                           login="drive-by", association="NONE")],
                 "reviews": []} for n in range(50)]
        self.data["pulls"] += spam
        self.assertEqual(self.state()["first_verdict_7d"],
                         {"passed": 2, "total": 3, "pass_rate": 0.6667})

    def test_unknown_vendors_and_short_shas_never_count(self):
        head = "a" * 40
        for body in [f"LGTM-VERDICT PASS {head}", f"CUSTOM-VERDICT PASS {head}",
                     "CODEX-VERDICT PASS 0000000", "CODEX-VERDICT PASS " + "a" * 39,
                     "CODEX-VERDICT PASS " + "a" * 12, f"CODEX-VERDICT PASS {head}0",
                     f"CODEX-VERDICT PASS {head} extra", f"CODEX-VERDICT  PASS {head}",
                     f"**CODEX-VERDICT PASS {head}**", f"    CODEX-VERDICT PASS {head}",
                     f"CODEX-VERDICT PASS {head}\u2028junk"]:
            with self.subTest(body=body):
                self.setUp()
                self.assertEqual(self.head_only([self.comment(body)])["open_prs"][0]["verdicts"], {})
                self.setUp()
                self.assertEqual(self.isolated_first([self.comment(body)])["total"], 0)

    def test_verdict_line_anywhere_with_trailing_space_counts(self):
        body = "_Relayed by Atlas from the NOVA Codex terminal_\n\nCODEX-VERDICT PASS " + "a" * 40 + " "
        self.assertEqual(self.head_only([self.comment(body)])["open_prs"][0]["verdicts"]
                         ["openai"]["result"], "PASS")

    def test_allowlist_matches_review_gate_rule(self):
        head = "a" * 40
        bot = self.comment(f"GROK-VERDICT FAIL {head}", 1, login="cursor[bot]",
                           association="NONE")
        member = self.comment(f"CODEX-VERDICT PASS {head}", 2, login="member",
                              association="MEMBER")
        # Allowlisted bot counts despite NONE; unlisted MEMBER does not.
        verdicts = self.head_only([bot, member], "owner, Cursor[bot]")["open_prs"][0]["verdicts"]
        self.assertEqual(set(verdicts), {"cursor"})
        self.assertEqual(verdicts["cursor"]["result"], "FAIL")
        # Unset, or no non-blank entries: OWNER/MEMBER/COLLABORATOR only.
        for authors in ["", ",", " , "]:
            with self.subTest(authors=authors):
                verdicts = self.head_only([bot, member], authors)["open_prs"][0]["verdicts"]
                self.assertEqual(set(verdicts), {"openai"})

    def test_comments_without_user_are_skipped(self):
        for user in [None, {}, {"login": None}, "ghost"]:
            for authors in ["", "reviewer"]:
                with self.subTest(user=user, authors=authors):
                    entry = self.comment("CODEX-VERDICT PASS " + "a" * 40)
                    entry["user"] = user
                    self.assertEqual(self.head_only([entry], authors)["open_prs"][0]["verdicts"], {})

    def test_cursor_family_matches_review_gate(self):
        for vendor in ["GROK", "COMPOSER", "CURSOR"]:
            with self.subTest(vendor=vendor):
                comment = self.comment(f"{vendor}-VERDICT PASS " + "a" * 40)
                self.assertEqual(set(self.head_only([comment])["open_prs"][0]["verdicts"]),
                                 {"cursor"})

    def test_edited_comments_are_ignored_for_first_verdict_only(self):
        # Red team: editing a first FAIL into PASS used to count as a PASS.
        head = "a" * 40
        edited = self.comment(f"CODEX-VERDICT PASS {head}", 1, created="2026-10-25T00:00:00Z",
                              updated="2026-10-25T11:00:00Z")
        self.assertEqual(self.isolated_first([edited]), {"passed": 0, "total": 0, "pass_rate": None})
        self.setUp()
        later = self.comment(f"CLAUDE-VERDICT FAIL {head}", 2, created="2026-10-25T01:00:00Z",
                             updated="2026-10-25T01:00:00Z")
        self.assertEqual(self.isolated_first([edited, later]),
                         {"passed": 0, "total": 1, "pass_rate": 0.0})
        self.setUp()
        # The head verdict still reflects the current body, ordered by posting time.
        verdicts = self.head_only([edited])["open_prs"][0]["verdicts"]
        self.assertEqual(verdicts["openai"]["result"], "PASS")
        self.assertNotIn("edited", verdicts["openai"])

    def test_builder_slash_and_hyphen_conventions(self):
        for label in ["builder/codex", "builder-fable"]:
            with self.subTest(label=label):
                self.data["pulls"][0]["labels"] = [{"name": label}]
                self.assertEqual(self.state()["open_prs"][0]["builder_label"], label)


class RenderingTests(FixtureCase):
    def test_markdown_contains_summary_table_and_identical_json(self):
        state = self.state()
        body = hs.render_markdown(state)
        markdown, block = body.split("```json\n", 1)
        self.assertEqual(json.loads(block.rsplit("```", 1)[0]), state)
        self.assertIn("Open: 2", markdown)
        self.assertIn("Median age: 24.0 h", markdown)
        self.assertIn("2/3", markdown)
        self.assertIn("failure", markdown)
        self.assertIn("4/5", markdown)
        self.assertIn("| PR |", markdown)
        self.assertIn("BEHIND", markdown)
        self.assertIn("anthropic: PASS", markdown)
        self.assertIn("Fix \\| table &lt;tag&gt; &#64;\u200bsomeone", markdown)
        self.assertNotIn("@someone", body)
        self.assertNotIn("<tag>", body)

    def test_rendering_empty_state(self):
        self.data.update(pulls=[], e2e_runs=[])
        body = hs.render_markdown(self.state())
        self.assertIn("Open: 0", body)
        self.assertIn("n/a", body)

    def test_long_titles_are_truncated_not_fatal(self):
        state = self.state()
        state["open_prs"][0]["title"] = "x" * 66000
        body = hs.render_markdown(state)
        self.assertLessEqual(len(body), hs.BODY_LIMIT)
        self.assertIn("x" * 119 + "\u2026", body)
        self.assertNotIn("x" * 121, body)
        self.data["pulls"][0]["title"] = "y" * 256
        self.assertEqual(len(self.state()["open_prs"][0]["title"]), 120)

    def many_open_prs(self, count, title):
        template = self.data["pulls"][1]
        self.data["pulls"] = [dict(template, number=n, title=title) for n in range(1, count + 1)]
        return self.state()

    def test_many_open_prs_drop_oldest_rows_instead_of_failing(self):
        # Red team: 60 open fork PRs with 256-character titles stopped the job.
        for title in ["_" * 256, "a" * 256, "@" * 256]:
            with self.subTest(title=title[:3]):
                state = self.many_open_prs(400, title)
                body = hs.render_markdown(state)
                self.assertLessEqual(len(body), hs.BODY_LIMIT)
                data = json.loads(body.split("```json\n", 1)[1].rsplit("```", 1)[0])
                omitted = data["open_prs_omitted"]
                self.assertGreater(omitted, 0)
                self.assertIn(f"\u2026 {omitted} more open PRs", body)
                self.assertIn("Open: 400", body)
                shown = [pr["number"] for pr in data["open_prs"]]
                self.assertEqual(shown, list(range(omitted + 1, 401)))
                self.assertNotIn(f"| #{omitted} |", body)
                self.assertIn(f"| #{omitted + 1} |", body)
                # Only as many rows as needed are dropped (one row is < 2,000 chars).
                self.assertGreater(len(body), hs.BODY_LIMIT - 2000)

    def test_report_that_fits_has_no_more_line(self):
        state = self.many_open_prs(50, "_" * 256)
        body = hs.render_markdown(state)
        self.assertNotIn("more open PRs", body)
        self.assertNotIn("open_prs_omitted", body)

    def test_issue_references_links_and_bidi_controls_are_neutralized(self):
        title = ("@octocat #1 MindLink-ApS/other#5 GH-7 gh-8 https://evil.example/login "
                 "www.evil.example \u202e\u2066\u2067\u2068\u2069\u202a\u200f end")
        self.data["pulls"] = [dict(self.data["pulls"][1], number=7, title=title)]
        body = hs.render_markdown(self.state())
        row = next(line for line in body.splitlines() if line.startswith("| #7 |"))
        for raw in ["#1", "#5", "GH-7", "gh-8", "https://", "www.", "@octocat",
                    "\u202e", "\u2066", "\u2067", "\u2068", "\u2069", "\u202a", "\u200f"]:
            with self.subTest(raw=raw):
                self.assertNotIn(raw, row)
        self.assertIn("#\u200b1", row)
        self.assertIn("other#\u200b5", row)
        self.assertIn("end", row)
        for char in "\u202e\u2066\u2069":
            self.assertNotIn(char, body)


class GitHubBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.repo = "MindLink-ApS/BitSov-bitsov"
        self.responses = {}
        self.writes = []
        self.reads = []
        self.transport = patch.object(hs.subprocess, "run", side_effect=self.run_gh)
        self.transport.start()
        self.addCleanup(self.transport.stop)
        self.api = hs.GitHub(self.repo)

    def run_gh(self, command, **kwargs):
        self.assertEqual(command[:2], ["gh", "api"])
        self.assertNotIn("shell", kwargs)
        endpoint = command[2]
        method = command[command.index("--method") + 1]
        if method == "GET":
            self.reads.append(endpoint)
            result = self.responses[endpoint]
        else:
            payload = json.loads(kwargs["input"])
            self.writes.append((endpoint, method, payload))
            result = self.responses[(endpoint, method)]
        return subprocess.CompletedProcess(command, 0, json.dumps(result), "")

    def endpoint(self, path):
        return f"repos/{self.repo}" + (f"/{path}" if path else "")

    def response(self, path, data):
        self.responses[self.endpoint(path)] = data

    def test_pagination_reads_array_and_nested_check_pages_past_first_100(self):
        for path, key in [("issues/10/comments", None), ("commits/abc/check-runs", "check_runs")]:
            with self.subTest(path=path):
                first = [{"id": n} for n in range(100)]
                last = [{"id": 101}]
                self.response(f"{path}?per_page=100&page=1", {key: first} if key else first)
                self.response(f"{path}?per_page=100&page=2", {key: last} if key else last)
                self.assertEqual(self.api.list_all(path, key=key), first + last)

    def publication_setup(self, issues, pins):
        self.response("issues?state=open&labels=harness-state&per_page=100&page=1", issues)
        self.responses[("graphql", "POST")] = {"data": {"repository": {"pinnedIssues": {
            "nodes": [{"issue": {"number": number}} for number in pins]
        }}}}

    def test_existing_pinned_issue_only_receives_body_patch(self):
        self.publication_setup([{"number": 500, "node_id": "I_500", "body": "old"}], [500])
        self.responses[(self.endpoint("issues/500"), "PATCH")] = {"number": 500}
        hs.publish(self.api, "new")
        mutations = [w for w in self.writes if w[0] != "graphql"]
        self.assertEqual(mutations, [(self.endpoint("issues/500"), "PATCH", {"body": "new"})])
        self.assertTrue(all("mutation" not in w[2].get("query", "") for w in self.writes))

    def test_unchanged_body_needs_no_patch_or_comment(self):
        self.publication_setup([{"number": 500, "node_id": "I_500", "body": "same"}], [500])
        hs.publish(self.api, "same")
        self.assertEqual([w for w in self.writes if w[0] != "graphql"], [])

    def test_missing_issue_creates_label_and_issue_then_pins_without_comments(self):
        self.publication_setup([], [])
        self.response("labels?per_page=100&page=1", [])
        self.responses[(self.endpoint("labels"), "POST")] = {"name": "harness-state"}
        self.responses[(self.endpoint("issues"), "POST")] = {"number": 501, "node_id": "I_501"}
        # A GraphQL query and pin mutation share this transport response;
        # the publisher validates the query and mutation independently.
        self.responses[("graphql", "POST")]["data"]["pinIssue"] = {"issue": {"number": 501}}
        hs.publish(self.api, "report")
        writes = [w for w in self.writes if w[0] != "graphql"]
        self.assertEqual([w[0] for w in writes], [self.endpoint("labels"), self.endpoint("issues")])
        self.assertEqual(writes[1][2], {"title": "Factory state (auto)", "labels": ["harness-state"], "body": "report"})
        pin = self.writes[-1][2]
        self.assertIn("pinIssue", pin["query"])
        self.assertEqual(pin["variables"]["issueId"], "I_501")

    def test_duplicate_labelled_issues_fail_before_mutation(self):
        self.publication_setup([{"number": 500}, {"number": 501}], [])
        with self.assertRaisesRegex(ValueError, "multiple open"):
            hs.publish(self.api, "new")
        self.assertEqual(self.writes, [])

    def test_labelled_pr_is_not_the_dashboard_issue(self):
        self.publication_setup([{"number": 1, "pull_request": {}},
                                {"number": 500, "node_id": "I_500", "body": "same"}], [500])
        hs.publish(self.api, "same")
        self.assertEqual([w for w in self.writes if w[0] != "graphql"], [])

    def test_graphql_errors_abort_before_issue_write(self):
        self.publication_setup([{"number": 500, "node_id": "I_500", "body": "old"}], [])
        self.responses[("graphql", "POST")] = {"errors": [{"message": "permission denied"}]}
        with self.assertRaisesRegex(RuntimeError, "GraphQL"):
            hs.publish(self.api, "new")
        self.assertEqual([w for w in self.writes if w[0] != "graphql"], [])

    def test_collect_rejects_nonpublic_repository_before_reading_other_data(self):
        self.response("", {"visibility": "private"})
        with self.assertRaisesRegex(ValueError, "public"):
            hs.collect(self.api, datetime(2026, 10, 25, 12, tzinfo=timezone.utc))
        self.assertEqual(self.reads, [self.endpoint("")])

    def test_collection_uses_head_sha_and_reads_closed_prs_at_cutoff(self):
        fixture = json.loads(FIXTURE.read_text())
        open_pr = fixture["pulls"][0]
        closed = fixture["pulls"][2] | {"updated_at": "2026-10-18T12:00:00Z"}
        old = fixture["pulls"][5] | {"updated_at": "2026-10-18T11:59:59Z"}
        self.response("", {"visibility": "public"})
        self.response("pulls?state=open&per_page=100&page=1", [{"number": 10}])
        self.response("pulls/10", open_pr)
        self.response("pulls?state=closed&sort=updated&direction=desc&per_page=100&page=1", [closed, old])
        for pr in [open_pr, closed]:
            self.response(f'issues/{pr["number"]}/comments?per_page=100&page=1', pr["comments"])
            self.response(f'pulls/{pr["number"]}/reviews?per_page=100&page=1', pr["reviews"])
        sha = "a" * 40
        self.response(f"commits/{sha}/statuses?per_page=100&page=1", open_pr["statuses"])
        self.response(f"commits/{sha}/check-runs?per_page=100&page=1", {"check_runs": open_pr["check_runs"]})
        self.response("issues/428", {"body": fixture["checklist_body"]})
        self.response("actions/workflows/three-node-paid-e2e.yml/runs?branch=main&status=completed&per_page=1",
                      {"workflow_runs": [fixture["e2e_runs"][1]]})
        data = hs.collect(self.api, datetime(2026, 10, 25, 12, tzinfo=timezone.utc))
        self.assertEqual([p["number"] for p in data["pulls"]], [10, 12])
        state = hs.compute_state(data, datetime(2026, 10, 25, 12, tzinfo=timezone.utc))
        self.assertEqual(state["open_prs"][0]["ci"], "success")
        self.assertEqual(state["merges"]["last_24h"], 1)
        self.assertEqual(state["checklist_428"]["checked"], 4)
        self.assertEqual(state["three_node_paid_e2e"]["id"], 1)


if __name__ == "__main__":
    unittest.main()
