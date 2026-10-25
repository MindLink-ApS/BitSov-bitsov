"""Regression tests for the model-free review gate (no network required)."""

import json
import subprocess
import unittest
from unittest.mock import patch

from scripts.ci.review_gate import evaluate, github_api, run_gate


HEAD = "a" * 40
STALE = "b" * 40


def verdict(vendor, outcome="PASS", sha=HEAD, *, number=1, author="reviewer",
            association="MEMBER", updated=None):
    return {
        "id": number,
        "body": f"{vendor}-VERDICT {outcome} {sha}\nReview details follow.",
        "user": {"login": author},
        "author_association": association,
        "created_at": f"2026-10-25T00:00:{number:02d}Z",
        "updated_at": updated or f"2026-10-25T00:00:{number:02d}Z",
    }


class EvaluationTests(unittest.TestCase):
    def check_gate(self, comments, *, builder="claude", labels=(),
                   files=("src/lib.rs",), branch="feature/example", authors=""):
        labels = list(labels)
        if builder:
            labels.append(f"builder:{builder}")
        return evaluate(HEAD, branch, labels, list(files), comments, authors)

    def test_two_non_builder_passes_succeed(self):
        state, _ = self.check_gate([verdict("CODEX"), verdict("CURSOR")])
        self.assertEqual(state, "success")

    def test_builders_own_pass_does_not_count(self):
        state, description = self.check_gate([verdict("CLAUDE"), verdict("CODEX")])
        self.assertEqual(state, "pending")
        self.assertIn("CURSOR PASS", description)

    def test_grok_and_composer_are_one_family(self):
        state, description = self.check_gate([verdict("GROK"), verdict("COMPOSER")])
        self.assertEqual(state, "pending")
        self.assertIn("CODEX PASS", description)

    def test_money_without_codex_is_pending(self):
        state, description = self.check_gate([verdict("CURSOR")], labels=["money"])
        self.assertEqual(state, "pending")
        self.assertIn("needs CODEX PASS on aaaaaaa", description)

    def test_codex_built_money_passes_with_claude_and_cursor(self):
        state, _ = self.check_gate([verdict("CLAUDE"), verdict("CURSOR")],
                                   builder="codex", labels=["money"])
        self.assertEqual(state, "success")

    def test_codex_built_money_requires_claude(self):
        state, description = self.check_gate([verdict("CURSOR")], builder="codex",
                                             labels=["security"])
        self.assertEqual(state, "pending")
        self.assertIn("CLAUDE PASS", description)

    def test_stale_sha_is_ignored(self):
        state, description = self.check_gate([verdict("CODEX", sha=STALE),
                                             verdict("CURSOR")])
        self.assertEqual(state, "pending")
        self.assertIn("CODEX PASS", description)

    def test_non_builder_fail_blocks_even_docs(self):
        state, description = self.check_gate([verdict("CODEX", "FAIL"),
                                             verdict("CURSOR")], files=["README.md"])
        self.assertEqual(state, "failure")
        self.assertIn("CODEX FAIL", description)

    def test_builder_fail_is_ignored(self):
        state, _ = self.check_gate([verdict("CLAUDE", "FAIL"), verdict("CODEX"),
                                   verdict("CURSOR")])
        self.assertEqual(state, "success")

    def test_docs_only_needs_one_pass(self):
        state, _ = self.check_gate([verdict("CODEX")],
                                   files=["README.md", "docs/diagram.svg"])
        self.assertEqual(state, "success")

    def test_docs_only_without_pass_is_pending(self):
        state, description = self.check_gate([], files=["docs/guide.txt"])
        self.assertEqual(state, "pending")
        self.assertIn("1 non-builder PASS", description)

    def test_docs_only_exception_precedes_money_classification(self):
        state, _ = self.check_gate([verdict("CURSOR")], labels=["security"],
                                   files=["docs/security.md"])
        self.assertEqual(state, "success")

    def test_unknown_builder_is_pending(self):
        state, description = self.check_gate([verdict("CODEX"), verdict("CURSOR")],
                                             builder=None)
        self.assertEqual(state, "pending")
        self.assertIn("builder unknown", description)

    def test_branch_fallbacks(self):
        for branch, comments in [
            ("cursor/topic", [verdict("CLAUDE"), verdict("CODEX")]),
            ("cloud/topic", [verdict("CODEX"), verdict("CURSOR")]),
        ]:
            with self.subTest(branch=branch):
                self.assertEqual(self.check_gate(comments, builder=None,
                                                 branch=branch)[0], "success")

    def test_label_overrides_branch_fallback(self):
        state, _ = self.check_gate([verdict("CLAUDE"), verdict("CODEX")],
                                   branch="cursor/topic")
        self.assertEqual(state, "pending")

    def test_conflicting_builder_labels_fail_closed(self):
        state, description = self.check_gate([verdict("CLAUDE"), verdict("CODEX")],
                                             labels=["builder:cursor"],
                                             branch="cursor/topic")
        self.assertEqual(state, "pending")
        self.assertIn("builder unknown", description)

    def test_all_vendor_aliases_count(self):
        for vendor in ["CLAUDE", "FABLE", "OPUS"]:
            with self.subTest(vendor=vendor):
                self.assertEqual(self.check_gate([verdict(vendor), verdict("CODEX")],
                                                 builder="cursor")[0], "success")

    def test_newest_verdict_per_family_wins_independent_of_api_order(self):
        for old, new, expected in [("FAIL", "PASS", "success"),
                                   ("PASS", "FAIL", "failure")]:
            with self.subTest(new=new):
                comments = [verdict("COMPOSER", new, number=3), verdict("CODEX"),
                            verdict("GROK", old, number=2)]
                self.assertEqual(self.check_gate(comments)[0], expected)

    def test_edited_comment_is_the_newest_verdict(self):
        comments = [verdict("GROK", "FAIL", number=1,
                            updated="2026-10-25T01:00:00Z"),
                    verdict("COMPOSER", number=2), verdict("CODEX")]
        self.assertEqual(self.check_gate(comments)[0], "failure")

    def test_newer_stale_fail_does_not_replace_current_pass(self):
        comments = [verdict("CODEX"), verdict("CODEX", "FAIL", STALE, number=2),
                    verdict("CURSOR")]
        self.assertEqual(self.check_gate(comments)[0], "success")

    def test_author_allowlist_is_case_insensitive_and_trims_whitespace(self):
        comments = [verdict("CODEX", author="Alice"),
                    verdict("CURSOR", author="bob"),
                    verdict("CODEX", "FAIL", author="mallory", number=3)]
        self.assertEqual(self.check_gate(comments, authors=" alice, BOB ")[0], "success")
        self.assertEqual(self.check_gate(comments, authors="bob")[0], "pending")
        self.assertEqual(self.check_gate(comments)[0], "failure")

    def test_trusted_author_associations_count_with_or_without_allowlist(self):
        for association in ["OWNER", "MEMBER", "COLLABORATOR"]:
            for authors in ["", "reviewer"]:
                with self.subTest(association=association, authors=authors):
                    comments = [verdict("CODEX", association=association),
                                verdict("CURSOR", association=association)]
                    self.assertEqual(self.check_gate(comments, authors=authors)[0], "success")

    def test_outsider_pass_is_ignored_with_or_without_allowlist(self):
        for association in ["NONE", "CONTRIBUTOR", "FIRST_TIMER",
                            "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", None, "UNKNOWN"]:
            for authors in ["", "reviewer, outsider"]:
                with self.subTest(association=association, authors=authors):
                    comments = [verdict("CURSOR"),
                                verdict("CODEX", author="outsider", association=association)]
                    self.assertEqual(self.check_gate(comments, authors=authors)[0], "pending")

    def test_outsider_fail_does_not_block_with_or_without_allowlist(self):
        for association in ["NONE", "CONTRIBUTOR", "FIRST_TIMER",
                            "FIRST_TIME_CONTRIBUTOR", "MANNEQUIN", None, "UNKNOWN"]:
            for authors in ["", "reviewer, outsider"]:
                with self.subTest(association=association, authors=authors):
                    comments = [verdict("CODEX"), verdict("CURSOR"),
                                verdict("CODEX", "FAIL", number=2, author="outsider",
                                        association=association)]
                    self.assertEqual(self.check_gate(comments, authors=authors)[0], "success")

    def test_missing_author_association_is_ignored(self):
        for authors in ["", "reviewer"]:
            with self.subTest(authors=authors):
                comment = verdict("CODEX")
                del comment["author_association"]
                self.assertEqual(self.check_gate([comment, verdict("CURSOR")],
                                                 authors=authors)[0], "pending")

    def test_only_exact_first_line_verdicts_count(self):
        for body in [f"Preface\nCODEX-VERDICT PASS {HEAD}",
                     f"CODEX-VERDICT PASS {HEAD[:7]}",
                     f"CODEX-VERDICT PASS {HEAD} extra", "",
                     f"OTHER-VERDICT PASS {HEAD}",
                     f"> CODEX-VERDICT PASS {HEAD}"]:
            with self.subTest(body=body):
                comment = verdict("CODEX")
                comment["body"] = body
                self.assertEqual(self.check_gate([comment, verdict("CURSOR")])[0], "pending")

    def test_uppercase_hex_sha_counts(self):
        self.assertEqual(self.check_gate([verdict("CODEX", sha=HEAD.upper()),
                                          verdict("CURSOR")])[0], "success")

    def test_money_and_security_paths_require_codex(self):
        # CURSOR is the only non-builder pass: each path must ask for CODEX.
        for path in ["crates/konsensus-lightning/src/lib.rs",
                     "crates/konsensus-crypto/src/lib.rs", "src/spend_budget.rs",
                     "src/pairing.rs", "src/invoice.rs", "src/session.rs"]:
            with self.subTest(path=path):
                state, description = self.check_gate([verdict("CURSOR")], files=[path])
                self.assertEqual(state, "pending")
                self.assertIn("needs CODEX PASS on aaaaaaa", description)

    def test_empty_file_list_does_not_get_docs_exception(self):
        self.assertEqual(self.check_gate([verdict("CODEX")], files=[])[0], "pending")


class FakeAPI:
    """Small API boundary double; all gate decisions use the real evaluator."""

    def __init__(self, *, second_head=HEAD, changed_files=1, files=None):
        self.second_head = second_head
        self.changed_files = changed_files
        self.files = files if files is not None else [{"filename": "src/lib.rs"}]
        self.statuses = []
        self.reads = []
        self.pr_reads = 0

    def __call__(self, endpoint, *, method="GET", payload=None, paginate=False):
        if method == "POST":
            self.statuses.append((endpoint, payload))
            return {}
        self.reads.append((endpoint, paginate))
        if endpoint == "repos/owner/repo/pulls/7":
            self.pr_reads += 1
            return {"head": {"sha": HEAD if self.pr_reads == 1 else self.second_head,
                             "ref": "feature/topic"},
                    "labels": [{"name": "builder:claude"}],
                    "changed_files": self.changed_files}
        if endpoint == "repos/owner/repo/pulls/7/files?per_page=100":
            return self.files
        if endpoint == "repos/owner/repo/issues/7/comments?per_page=100":
            return [verdict("CODEX"), verdict("CURSOR")]
        raise AssertionError(f"Unexpected API request: {endpoint}")


class APITests(unittest.TestCase):
    def test_comment_author_association_survives_pagination(self):
        pages = [[verdict("CURSOR", association="COLLABORATOR")],
                 [verdict("CODEX", author="outsider", association="NONE")]]
        response = subprocess.CompletedProcess([], 0, stdout=json.dumps(pages))
        with patch("scripts.ci.review_gate.subprocess.run", return_value=response):
            comments = github_api("repos/o/r/issues/7/comments?per_page=100", paginate=True)
        state, _ = evaluate(HEAD, "feature/topic", ["builder:claude"], ["src/lib.rs"],
                            comments)
        self.assertEqual(state, "pending")
        state, _ = evaluate(HEAD, "feature/topic", ["builder:claude"], ["README.md"],
                            comments)
        self.assertEqual(state, "success")

    def test_github_api_reads_all_pages(self):
        def gh(command, **kwargs):
            self.assertEqual(command, ["gh", "api", "--method", "GET", "repos/o/r/files",
                                       "--paginate", "--slurp"])
            self.assertTrue(kwargs["check"])
            return subprocess.CompletedProcess(command, 0, stdout='[[{"id": 1}], [{"id": 2}]]')
        with patch("scripts.ci.review_gate.subprocess.run", side_effect=gh):
            self.assertEqual(github_api("repos/o/r/files", paginate=True), [{"id": 1}, {"id": 2}])

    def test_github_api_posts_json_via_stdin(self):
        payload = {"context": "review-gate", "state": "pending", "description": "needs review"}
        def gh(command, **kwargs):
            self.assertEqual(command, ["gh", "api", "--method", "POST", "repos/o/r/statuses/sha",
                                       "--input", "-"])
            self.assertEqual(json.loads(kwargs["input"]), payload)
            return subprocess.CompletedProcess(command, 0, stdout='{"id": 3}')
        with patch("scripts.ci.review_gate.subprocess.run", side_effect=gh):
            self.assertEqual(github_api("repos/o/r/statuses/sha", method="POST", payload=payload),
                             {"id": 3})

    def test_api_error_leaves_existing_success_cleared(self):
        api = FakeAPI()
        def broken_api(endpoint, **kwargs):
            if endpoint.endswith("/comments?per_page=100"):
                raise subprocess.CalledProcessError(1, ["gh", "api"])
            return api(endpoint, **kwargs)
        with self.assertRaises(subprocess.CalledProcessError):
            run_gate("pull_request", {"number": 7}, "owner/repo", api=broken_api)
        self.assertEqual([payload["state"] for _, payload in api.statuses], ["pending"])

    def test_pr_event_reads_current_head_and_posts_commit_status(self):
        api = FakeAPI()
        run_gate("pull_request", {"number": 7, "pull_request": {"head": {"sha": STALE}}},
                 "owner/repo", api=api)
        endpoint, payload = api.statuses[-1]
        self.assertEqual(endpoint, f"repos/owner/repo/statuses/{HEAD}")
        self.assertEqual(payload["context"], "review-gate")
        self.assertEqual(payload["state"], "success")
        self.assertEqual(api.statuses[0][1]["state"], "pending")
        self.assertTrue(all(paginate for endpoint, paginate in api.reads
                            if "?per_page=100" in endpoint))

    def test_pr_comment_resolves_pr_number(self):
        api = FakeAPI()
        run_gate("issue_comment", {"issue": {"number": 7, "pull_request": {}}},
                 "owner/repo", api=api)
        self.assertEqual(api.statuses[-1][1]["state"], "success")

    def test_regular_issue_comment_is_ignored(self):
        api = FakeAPI()
        run_gate("issue_comment", {"issue": {"number": 7}}, "owner/repo", api=api)
        self.assertEqual(api.reads, [])
        self.assertEqual(api.statuses, [])

    def test_merge_group_posts_success_on_group_sha_without_pr_reads(self):
        api = FakeAPI()
        run_gate("merge_group", {"merge_group": {"head_sha": STALE}}, "owner/repo", api=api)
        self.assertEqual(api.reads, [])
        self.assertEqual(api.statuses[-1][0], f"repos/owner/repo/statuses/{STALE}")
        self.assertEqual(api.statuses[-1][1]["state"], "success")

    def test_truncated_file_list_fails_closed(self):
        api = FakeAPI(changed_files=3001)
        run_gate("pull_request", {"number": 7}, "owner/repo", api=api)
        self.assertEqual(api.statuses[-1][1]["state"], "pending")
        self.assertIn("file list incomplete", api.statuses[-1][1]["description"])

    def test_head_change_during_api_reads_cannot_publish_success(self):
        api = FakeAPI(second_head=STALE)
        run_gate("pull_request", {"number": 7}, "owner/repo", api=api)
        self.assertTrue(all(payload["state"] == "pending" for _, payload in api.statuses))
        self.assertEqual(api.statuses[-1][0], f"repos/owner/repo/statuses/{STALE}")

    def test_unrelated_head_repository_metadata_changes_do_not_block(self):
        api = FakeAPI()
        def metadata_changes(endpoint, **kwargs):
            result = api(endpoint, **kwargs)
            if endpoint == "repos/owner/repo/pulls/7" and api.pr_reads > 1:
                result["head"]["repo"] = {"updated_at": "2026-10-25T01:00:00Z"}
            return result
        run_gate("pull_request", {"number": 7}, "owner/repo", api=metadata_changes)
        self.assertEqual(api.statuses[-1][1]["state"], "success")

    def test_label_change_during_api_reads_cannot_publish_success(self):
        api = FakeAPI()
        def label_changes(endpoint, **kwargs):
            result = api(endpoint, **kwargs)
            if endpoint == "repos/owner/repo/pulls/7" and api.pr_reads > 1:
                result["labels"] = [{"name": "builder:codex"}]
            return result
        run_gate("pull_request", {"number": 7}, "owner/repo", api=label_changes)
        self.assertTrue(all(payload["state"] == "pending" for _, payload in api.statuses))

    def test_rename_out_of_security_path_keeps_security_classification(self):
        # A docs-looking destination must not hide the old code path.
        api = FakeAPI(files=[{"filename": "docs/archive.md",
                              "previous_filename": "src/session.rs"}])
        def only_cursor(endpoint, **kwargs):
            if endpoint.endswith("/comments?per_page=100"):
                return [verdict("CURSOR")]
            return api(endpoint, **kwargs)
        run_gate("pull_request", {"number": 7}, "owner/repo", api=only_cursor)
        self.assertEqual(api.statuses[-1][1]["state"], "pending")
        self.assertIn("CODEX PASS", api.statuses[-1][1]["description"])


if __name__ == "__main__":
    unittest.main()
