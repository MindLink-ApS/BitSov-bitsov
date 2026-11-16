#!/usr/bin/env python3
"""Regression tests for scripts/check-waiver-deadlines.py. No network."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CHECK = REPO / "scripts" / "check-waiver-deadlines.py"
TOOLS = ("cargo-audit", "cargo-deny", "osv-scanner")

AUDIT = '[advisories]\nignore = ["RUSTSEC-1"]\n'
DENY = '[advisories]\nignore = [{ id = "RUSTSEC-2", reason = "r" }]\n'
OSV = """
[[IgnoredVulns]]
id = "RUSTSEC-3"
ignoreUntil = 2027-02-03
reason = "r"

[[IgnoredVulns]]
id = "GHSA-3"
ignoreUntil = 2027-02-03
reason = "alias"
"""
DEADLINES = """
[[waiver]]
ids = ["RUSTSEC-1"]
deadline = 2027-02-03

[[waiver]]
ids = ["RUSTSEC-2"]
deadline = 2027-02-03

[[waiver]]
ids = ["RUSTSEC-3", "GHSA-3"]
deadline = 2027-02-03
"""


def run(root, *args):
    return subprocess.run(
        [sys.executable, str(CHECK), "--root", str(root), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class Fixture(unittest.TestCase):
    def write(self, audit=AUDIT, deny=DENY, osv=OSV, deadlines=DEADLINES):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        (root / ".cargo").mkdir()
        (root / ".cargo/audit.toml").write_text(audit)
        (root / "deny.toml").write_text(deny)
        (root / "osv-scanner.toml").write_text(osv)
        (root / ".cargo/waiver-deadlines.toml").write_text(deadlines)
        return root

    def assert_error(self, result, text):
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn("WAIVER-DEADLINES: ERROR", result.stdout)
        self.assertIn(text, result.stdout)


class Deadlines(Fixture):
    def test_day_before_deadline_is_ok(self):
        result = run(self.write(), "--today", "2027-02-02")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("WAIVER-DEADLINES: OK", result.stdout)

    def test_each_tool_fails_on_the_deadline_day(self):
        root = self.write()
        expected = {"cargo-audit": "RUSTSEC-1", "cargo-deny": "RUSTSEC-2", "osv-scanner": "GHSA-3"}
        for tool, advisory in expected.items():
            with self.subTest(tool=tool):
                result = run(root, "--tool", tool, "--today", "2027-02-03")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f"EXPIRED {tool}: {advisory} deadline 2027-02-03", result.stdout)

    def test_warns_before_deadline_without_failing(self):
        result = run(self.write(), "--today", "2027-01-20")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("WARNING cargo-audit: RUSTSEC-1 expires on 2027-02-03", result.stdout)

    def test_no_warning_outside_the_window(self):
        result = run(self.write(), "--today", "2026-11-04")
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("WARNING", result.stdout)

    def test_repo_configs_pass_now_and_fail_for_each_tool_once_past_deadline(self):
        result = run(REPO, "--today", "2026-11-04")
        self.assertEqual(result.returncode, 0, result.stdout)
        for tool in TOOLS:
            with self.subTest(tool=tool):
                result = run(REPO, "--tool", tool, "--today", "2999-01-01")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f"EXPIRED {tool}: ", result.stdout)


class Consistency(Fixture):
    def test_waiver_without_deadline(self):
        cases = {
            "cargo-audit": {"audit": '[advisories]\nignore = ["RUSTSEC-1", "RUSTSEC-9"]\n'},
            "cargo-deny": {"deny": DENY.replace(" }]", ' }, { id = "RUSTSEC-9", reason = "r" }]')},
            "osv-scanner": {
                "osv": OSV + '\n[[IgnoredVulns]]\nid = "RUSTSEC-9"\nignoreUntil = 2027-02-03\n'
            },
        }
        for tool, change in cases.items():
            with self.subTest(tool=tool):
                result = run(self.write(**change), "--today", "2026-11-04")
                self.assert_error(result, f"{tool}: RUSTSEC-9 has no deadline")

    def test_osv_date_must_match(self):
        changed = OSV.replace("ignoreUntil = 2027-02-03", "ignoreUntil = 2027-03-01", 1)
        result = run(self.write(osv=changed), "--today", "2026-11-04")
        self.assert_error(result, "RUSTSEC-3 ignoreUntil is 2027-03-01, expected 2027-02-03")

    def test_alias_date_must_match(self):
        changed = OSV.replace('id = "GHSA-3"\nignoreUntil = 2027-02-03', 'id = "GHSA-3"\nignoreUntil = 2099-01-01')
        result = run(self.write(osv=changed), "--today", "2026-11-04")
        self.assert_error(result, "GHSA-3 ignoreUntil is 2099-01-01, expected 2027-02-03")

    def test_osv_entry_must_have_a_date(self):
        changed = OSV.replace('id = "GHSA-3"\nignoreUntil = 2027-02-03\n', 'id = "GHSA-3"\n')
        result = run(self.write(osv=changed), "--today", "2026-11-04")
        self.assert_error(result, "GHSA-3 ignoreUntil is None")

    def test_unused_deadline(self):
        extra = DEADLINES + '\n[[waiver]]\nids = ["RUSTSEC-8"]\ndeadline = 2027-02-03\n'
        result = run(self.write(deadlines=extra), "--today", "2026-11-04")
        self.assert_error(result, "RUSTSEC-8 is not waived anywhere")

    def test_id_listed_twice(self):
        extra = DEADLINES + '\n[[waiver]]\nids = ["RUSTSEC-1"]\ndeadline = 2099-01-01\n'
        result = run(self.write(deadlines=extra), "--today", "2026-11-04")
        self.assert_error(result, "RUSTSEC-1 is listed twice")

    def test_deadline_must_be_a_date(self):
        changed = DEADLINES.replace("deadline = 2027-02-03", 'deadline = "2027-02-03"', 1)
        result = run(self.write(deadlines=changed), "--today", "2026-11-04")
        self.assert_error(result, "needs a plain date deadline")

    def test_missing_file_fails_closed(self):
        root = self.write()
        (root / "deny.toml").unlink()
        result = run(root, "--today", "2026-11-04")
        self.assert_error(result, "cannot read waivers")

    def test_bad_toml_fails_closed(self):
        result = run(self.write(audit="[advisories\n"), "--today", "2026-11-04")
        self.assert_error(result, "cannot read waivers")


if __name__ == "__main__":
    unittest.main()
