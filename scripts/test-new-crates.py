#!/usr/bin/env python3
"""Exercise crate-name comparisons through the command-line interface."""

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("check-new-crates.py")
FIXTURES = Path(__file__).parent / "fixtures" / "new-crates"


class NewCratesTests(unittest.TestCase):
    def check_crates(self, head="base.lock", allowlist="", base="base.lock"):
        with tempfile.TemporaryDirectory() as temporary:
            allowed = Path(temporary) / "allowlist.txt"
            allowed.write_text(allowlist, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT),
                 "--base-lock", str(FIXTURES / base),
                 "--head-lock", str(FIXTURES / head),
                 "--allowlist", str(allowed)],
                capture_output=True, text=True, check=False,
            )

    def test_no_change(self):
        result = self.check_crates()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No new crate names.", result.stdout)

    def test_version_bump(self):
        result = self.check_crates(head="version-bump.lock")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No new crate names.", result.stdout)

    def test_new_crates_are_listed_and_require_allowlist_entries(self):
        result = self.check_crates(head="new-crates.lock")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("- another-crate (not allowlisted)", result.stdout)
        self.assertIn("- new-crate (not allowlisted)", result.stdout)
        self.assertLess(result.stdout.index("- another-crate"),
                        result.stdout.index("- new-crate"))

    def test_new_allowlisted_crates(self):
        result = self.check_crates(
            head="new-crates.lock",
            allowlist="# Crate names\nnew-crate\nanother-crate\n\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("- another-crate (allowlisted)", result.stdout)
        self.assertIn("- new-crate (allowlisted)", result.stdout)

    def test_one_allowlisted_crate_does_not_cover_another(self):
        result = self.check_crates(head="new-crates.lock", allowlist="new-crate\n")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("- another-crate (not allowlisted)", result.stdout)
        self.assertIn("- new-crate (allowlisted)", result.stdout)

    def test_removals(self):
        result = self.check_crates(base="new-crates.lock")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("No new crate names.", result.stdout)

    def test_missing_lockfile_is_an_input_error(self):
        result = self.check_crates(base="missing.lock")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Cannot read crate inputs:", result.stderr)
        self.assertNotIn("No new crate names.", result.stdout)

    def test_malformed_lockfile_is_an_input_error(self):
        result = self.check_crates(head="malformed.lock")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("Cannot read crate inputs:", result.stderr)
        self.assertNotIn("No new crate names.", result.stdout)


if __name__ == "__main__":
    unittest.main()
